//! Search filters, checked against an entry.
//!
//! Text compares case-insensitively (what directories do for names and addresses), DNs as DNs,
//! numbers as numbers. Two of Active Directory's matching rules are there because apps set to
//! "Active Directory" use them all the time:
//!
//! - `1.2.840.113556.1.4.1941` (LDAP_MATCHING_RULE_IN_CHAIN): `memberOf` and `member` through
//!   groups inside groups;
//! - `1.2.840.113556.1.4.803` / `…804` (bitwise AND / OR): `userAccountControl` flags, as in
//!   `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` for "not disabled".

use crate::directory::{Entry, Snapshot};
use crate::dn::Dn;
use ldap3_proto::proto::{LdapFilter, LdapSubstringFilter};

pub const IN_CHAIN: &str = "1.2.840.113556.1.4.1941";
pub const BIT_AND: &str = "1.2.840.113556.1.4.803";
pub const BIT_OR: &str = "1.2.840.113556.1.4.804";

const DN_VALUED: &[&str] = &["member", "uniquemember", "memberof"];
const BINARY: &[&str] = &["objectguid", "objectsid", "jpegphoto", "thumbnailphoto"];

fn normalize_dn(value: &[u8]) -> Option<String> {
    Dn::parse(std::str::from_utf8(value).ok()?).map(|dn| dn.normalized())
}

fn equal(attribute: &str, stored: &[u8], asked: &str) -> bool {
    let attribute = attribute.to_lowercase();
    if DN_VALUED.contains(&attribute.as_str()) {
        return match (normalize_dn(stored), Dn::parse(asked)) {
            (Some(stored), Some(asked)) => stored == asked.normalized(),
            _ => false,
        };
    }
    if BINARY.contains(&attribute.as_str()) {
        return stored == asked.as_bytes() || std::str::from_utf8(stored).is_ok_and(|text| text == asked);
    }
    std::str::from_utf8(stored)
        .is_ok_and(|text| text.eq_ignore_ascii_case(asked) || text.to_lowercase() == asked.to_lowercase())
}

fn substring(stored: &[u8], filter: &LdapSubstringFilter) -> bool {
    let Ok(text) = std::str::from_utf8(stored) else { return false };
    let text = text.to_lowercase();
    let mut rest = text.as_str();
    if let Some(initial) = &filter.initial {
        let initial = initial.to_lowercase();
        let Some(after) = rest.strip_prefix(initial.as_str()) else { return false };
        rest = after;
    }
    for any in &filter.any {
        let any = any.to_lowercase();
        let Some(at) = rest.find(any.as_str()) else { return false };
        rest = &rest[at + any.len()..];
    }
    filter.final_.as_ref().is_none_or(|last| rest.ends_with(last.to_lowercase().as_str()))
}

fn compare(stored: &[u8], asked: &str) -> Option<std::cmp::Ordering> {
    let text = std::str::from_utf8(stored).ok()?;
    match (text.trim().parse::<i64>(), asked.trim().parse::<i64>()) {
        (Ok(stored), Ok(asked)) => Some(stored.cmp(&asked)),
        _ => Some(text.to_lowercase().cmp(&asked.to_lowercase())),
    }
}

/// Whether `entry` matches `filter`.
pub fn matches(filter: &LdapFilter, entry: &Entry, snapshot: &Snapshot) -> bool {
    let values = |name: &str| entry.get(name).map(Vec::as_slice).unwrap_or_default();
    match filter {
        LdapFilter::And(all) => all.iter().all(|filter| matches(filter, entry, snapshot)),
        LdapFilter::Or(any) => any.iter().any(|filter| matches(filter, entry, snapshot)),
        LdapFilter::Not(inner) => !matches(inner, entry, snapshot),
        LdapFilter::Equality(name, value) | LdapFilter::Approx(name, value) => {
            values(name).iter().any(|stored| equal(name, stored, value))
        }
        LdapFilter::Substring(name, filter) => values(name).iter().any(|stored| substring(stored, filter)),
        LdapFilter::GreaterOrEqual(name, value) => {
            values(name).iter().any(|stored| compare(stored, value).is_some_and(|order| order.is_ge()))
        }
        LdapFilter::LessOrEqual(name, value) => {
            values(name).iter().any(|stored| compare(stored, value).is_some_and(|order| order.is_le()))
        }
        LdapFilter::Present(name) => name.eq_ignore_ascii_case("objectclass") || entry.get(name).is_some(),
        LdapFilter::Extensible(assertion) => {
            let name = assertion.type_.as_deref().unwrap_or_default();
            match assertion.matching_rule.as_deref() {
                Some(IN_CHAIN) => {
                    let Some(asked) = Dn::parse(&assertion.match_value).map(|dn| dn.normalized()) else { return false };
                    match name.to_lowercase().as_str() {
                        "memberof" => snapshot.nested_groups_of(entry).contains(&asked),
                        "member" | "uniquemember" => snapshot.nested_members_of(entry).contains(&asked),
                        _ => values(name).iter().any(|stored| equal(name, stored, &assertion.match_value)),
                    }
                }
                Some(rule @ (BIT_AND | BIT_OR)) => {
                    let Ok(mask) = assertion.match_value.trim().parse::<i64>() else { return false };
                    values(name).iter().any(|stored| {
                        std::str::from_utf8(stored).ok().and_then(|text| text.trim().parse::<i64>().ok()).is_some_and(
                            |flags| {
                                if rule == BIT_AND { flags & mask == mask } else { flags & mask != 0 }
                            },
                        )
                    })
                }
                // Without a rule, or one of the usual string rules: equality.
                _ => values(name).iter().any(|stored| equal(name, stored, &assertion.match_value)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrings_find_their_pieces_in_order() {
        let filter = LdapSubstringFilter::from("ny*ne*o");
        assert!(substring(b"Nyu Neko", &filter));
        assert!(!substring(b"Neko Nyu", &filter));
        assert!(substring(b"nyu", &LdapSubstringFilter::from("*y*")));
    }

    #[test]
    fn numbers_compare_as_numbers() {
        assert_eq!(compare(b"10001", "9999"), Some(std::cmp::Ordering::Greater));
        assert_eq!(compare(b"abc", "ABD"), Some(std::cmp::Ordering::Less));
    }
}
