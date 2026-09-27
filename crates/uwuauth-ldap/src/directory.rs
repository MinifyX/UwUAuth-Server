//! The directory as LDAP shows it: built from the store, kept in memory until something changes.
//!
//! ```text
//! dc=example,dc=com                         the base
//! ├── ou=people   uid=<name>,ou=people,…    everybody but the trash
//! ├── ou=groups   cn=<name>,ou=groups,…     every group, `everyone` included
//! └── ou=services cn=<name>,ou=services,…   LDAP accounts of apps (for binding only)
//! ```
//!
//! Every entry speaks two dialects at once, so an app set to "OpenLDAP" and one set to "Active
//! Directory" both find what they look for: people are `inetOrgPerson` and `posixAccount` *and*
//! `user` (with `sAMAccountName`, `userPrincipalName`, `objectGUID`, `objectSid`,
//! `userAccountControl`, `memberOf`), groups are `groupOfNames`, `groupOfUniqueNames` and
//! `posixGroup` *and* `group`.

use crate::dn::{Dn, escape};
use std::collections::{BTreeMap, BTreeSet};
use uwuauth_store::{EVERYONE_ID, Group, Membership, Person};

/// What an entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Base,
    Container,
    Person(String),
    Group(String),
}

/// One entry: its DN and attributes. Attribute names are kept as written; looking them up is
/// case-insensitive.
#[derive(Debug, Clone)]
pub struct Entry {
    pub dn: String,
    pub parsed: Dn,
    pub normalized: String,
    pub kind: Kind,
    /// Lower-case name → (name as written, values).
    pub attributes: BTreeMap<String, (String, Vec<Vec<u8>>)>,
}

/// Attributes only given when asked for by name ("operational", or large).
pub const ON_REQUEST: &[&str] = &[
    "entryuuid",
    "createtimestamp",
    "modifytimestamp",
    "entrydn",
    "subschemasubentry",
    "hassubordinates",
    "jpegphoto",
    "thumbnailphoto",
];

impl Entry {
    fn new(dn: String, kind: Kind) -> Entry {
        let parsed = Dn::parse(&dn).expect("the server writes DNs it can read");
        let normalized = parsed.normalized();
        Entry { dn, parsed, normalized, kind, attributes: BTreeMap::new() }
    }

    fn set(&mut self, name: &str, values: Vec<Vec<u8>>) {
        if !values.is_empty() {
            self.attributes.insert(name.to_lowercase(), (name.to_string(), values));
        }
    }

    fn text(&mut self, name: &str, values: &[&str]) {
        self.set(name, values.iter().map(|value| value.as_bytes().to_vec()).collect());
    }

    fn one(&mut self, name: &str, value: impl AsRef<str>) {
        self.set(name, vec![value.as_ref().as_bytes().to_vec()]);
    }

    pub fn get(&self, name: &str) -> Option<&Vec<Vec<u8>>> {
        self.attributes.get(&name.to_lowercase()).map(|(_, values)| values)
    }
}

/// Everything the directory is built from.
pub struct Source<'a> {
    pub base: &'a Dn,
    /// For `userPrincipalName`: `example.com`.
    pub domain: &'a str,
    /// The domain's SID parts, for `objectSid`.
    pub sid: [u32; 3],
    pub people: &'a [Person],
    pub groups: &'a [Group],
    pub membership: &'a Membership,
    pub attributes: &'a BTreeMap<String, BTreeMap<String, String>>,
    pub avatars: &'a BTreeMap<String, Vec<u8>>,
    pub services: &'a [String],
}

/// The directory, built once per change.
pub struct Snapshot {
    pub entries: Vec<Entry>,
    pub base: Dn,
    pub domain: String,
    /// Person id → index into `entries`.
    pub people: BTreeMap<String, usize>,
    /// Lower-case user name → person id.
    pub usernames: BTreeMap<String, String>,
    /// Group id → normalized DN.
    pub group_dns: BTreeMap<String, String>,
    /// Normalized group DN → group id.
    pub group_ids: BTreeMap<String, String>,
    pub membership: Membership,
}

pub fn person_dn(base: &str, username: &str) -> String {
    format!("uid={},ou=people,{base}", escape(username))
}

pub fn group_dn(base: &str, name: &str) -> String {
    format!("cn={},ou=groups,{base}", escape(name))
}

pub fn service_dn(base: &str, name: &str) -> String {
    format!("cn={},ou=services,{base}", escape(name))
}

/// `objectGUID`: the id's bytes in the order Windows keeps a GUID in.
pub fn object_guid(id: &str) -> Vec<u8> {
    uuid::Uuid::parse_str(id).map(|id| id.to_bytes_le().to_vec()).unwrap_or_default()
}

/// `objectSid`: S-1-5-21-a-b-c-rid, in its binary form.
pub fn object_sid(domain: [u32; 3], rid: u32) -> Vec<u8> {
    let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
    for part in [21, domain[0], domain[1], domain[2], rid] {
        sid.extend_from_slice(&part.to_le_bytes());
    }
    sid
}

/// `S-1-5-21-…` for people to read.
pub fn sid_text(domain: [u32; 3], rid: u32) -> String {
    format!("S-1-5-21-{}-{}-{}-{rid}", domain[0], domain[1], domain[2])
}

/// A time as LDAP writes it (GeneralizedTime): `20260927120000Z`.
pub fn generalized(time: &str) -> String {
    uwuauth_store::clock::parse(time)
        .map(|at| {
            let at = at.to_offset(time::UtcOffset::UTC);
            format!(
                "{:04}{:02}{:02}{:02}{:02}{:02}Z",
                at.year(),
                u8::from(at.month()),
                at.day(),
                at.hour(),
                at.minute(),
                at.second()
            )
        })
        .unwrap_or_default()
}

/// Active Directory's "normal account", and with the "disabled" bit.
pub const UAC_NORMAL: u32 = 512;
pub const UAC_DISABLED: u32 = 2;

impl Snapshot {
    pub fn build(source: Source<'_>) -> Snapshot {
        let base = source.base.clone();
        let base_text =
            base.0.iter().map(|rdn| format!("{}={}", rdn.name, escape(&rdn.value))).collect::<Vec<_>>().join(",");
        let mut entries = Vec::new();

        let mut root = Entry::new(base_text.clone(), Kind::Base);
        root.text("objectClass", &["top", "domain", "dcObject"]);
        if let Some(first) = base.first() {
            root.one(&first.name, &first.value);
        }
        entries.push(root);
        for (ou, what) in [("people", "People"), ("groups", "Groups"), ("services", "Services")] {
            let mut container = Entry::new(format!("ou={ou},{base_text}"), Kind::Container);
            container.text("objectClass", &["top", "organizationalUnit"]);
            container.one("ou", ou);
            container.one("description", what);
            entries.push(container);
        }

        let alive: Vec<&Person> = source.people.iter().filter(|person| person.deleted.is_none()).collect();
        let everybody: Vec<String> = alive.iter().map(|person| person.id.clone()).collect();
        let username_of: BTreeMap<&str, &str> =
            alive.iter().map(|person| (person.id.as_str(), person.username.as_str())).collect();
        let group_dns: BTreeMap<String, String> =
            source.groups.iter().map(|group| (group.id.clone(), group_dn(&base_text, &group.name))).collect();
        let everyone_gid =
            source.groups.iter().find(|group| group.id == EVERYONE_ID).map_or(10001, |group| group.gid_number);

        let mut people = BTreeMap::new();
        let mut usernames = BTreeMap::new();
        for person in &alive {
            let mut entry = Entry::new(person_dn(&base_text, &person.username), Kind::Person(person.id.clone()));
            let family = person.family_name.clone().unwrap_or_else(|| person.display_name.clone());
            entry.text(
                "objectClass",
                &["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "user"],
            );
            entry.one("uid", &person.username);
            entry.one("cn", &person.display_name);
            entry.one("displayName", &person.display_name);
            entry.one("sn", &family);
            entry.one("gecos", &person.display_name);
            if let Some(given) = &person.given_name {
                entry.one("givenName", given);
            }
            if let Some(email) = &person.email {
                entry.one("mail", email);
            }
            entry.one("uidNumber", person.uid_number.to_string());
            entry.one("gidNumber", everyone_gid.to_string());
            entry.one(
                "homeDirectory",
                person.home_directory.clone().unwrap_or_else(|| format!("/home/{}", person.username)),
            );
            entry.one("loginShell", person.login_shell.clone().unwrap_or_else(|| "/bin/bash".into()));
            entry.one("preferredLanguage", &person.language);
            entry.one("sAMAccountName", &person.username);
            entry.one("userPrincipalName", format!("{}@{}", person.username, source.domain));
            entry.set("objectGUID", vec![object_guid(&person.id)]);
            entry.set("objectSid", vec![object_sid(source.sid, person.uid_number as u32)]);
            let disabled = !person.active();
            entry.one("userAccountControl", (UAC_NORMAL | if disabled { UAC_DISABLED } else { 0 }).to_string());
            entry.one("primaryGroupID", "513");
            let member_of: Vec<String> = source
                .membership
                .direct_groups_of(&person.id)
                .iter()
                .chain([EVERYONE_ID.to_string()].iter())
                .filter_map(|id| group_dns.get(id).cloned())
                .collect();
            entry.set("memberOf", member_of.into_iter().map(String::into_bytes).collect());
            entry.one("entryUUID", &person.id);
            entry.one("createTimestamp", generalized(&person.created));
            entry.one("modifyTimestamp", generalized(&person.updated));
            entry.one("whenCreated", generalized(&person.created));
            entry.one("whenChanged", generalized(&person.updated));
            if let Some(photo) = source.avatars.get(&person.id) {
                entry.set("jpegPhoto", vec![photo.clone()]);
                entry.set("thumbnailPhoto", vec![photo.clone()]);
            }
            if let Some(values) = source.attributes.get(&person.id) {
                for (name, value) in values {
                    if !entry.attributes.contains_key(&name.to_lowercase()) {
                        entry.one(name, value);
                    }
                }
            }
            usernames.insert(person.username.to_lowercase(), person.id.clone());
            people.insert(person.id.clone(), entries.len());
            entries.push(entry);
        }

        for group in source.groups {
            let mut entry = Entry::new(group_dns[&group.id].clone(), Kind::Group(group.id.clone()));
            entry.text("objectClass", &["top", "groupOfNames", "groupOfUniqueNames", "posixGroup", "group"]);
            entry.one("cn", &group.name);
            entry.one("sAMAccountName", &group.name);
            if !group.description.is_empty() {
                entry.one("description", &group.description);
            }
            entry.one("gidNumber", group.gid_number.to_string());
            // Security group, global scope.
            entry.one("groupType", "-2147483646");
            let direct_people: Vec<String> = if group.id == EVERYONE_ID {
                everybody.clone()
            } else {
                source
                    .membership
                    .people
                    .get(&group.id)
                    .map(|people| people.iter().filter(|id| username_of.contains_key(id.as_str())).cloned().collect())
                    .unwrap_or_default()
            };
            let mut members: Vec<String> = direct_people
                .iter()
                .filter_map(|id| username_of.get(id.as_str()).map(|name| person_dn(&base_text, name)))
                .collect();
            members.extend(
                source
                    .membership
                    .groups
                    .get(&group.id)
                    .into_iter()
                    .flatten()
                    .filter_map(|id| group_dns.get(id).cloned()),
            );
            entry.set("member", members.iter().map(|dn| dn.clone().into_bytes()).collect());
            entry.set("uniqueMember", members.into_iter().map(String::into_bytes).collect());
            entry.set(
                "memberUid",
                direct_people
                    .iter()
                    .filter_map(|id| username_of.get(id.as_str()).map(|name| name.as_bytes().to_vec()))
                    .collect(),
            );
            let outer: Vec<String> = source
                .membership
                .groups
                .iter()
                .filter(|(_, inner)| inner.contains(&group.id))
                .filter_map(|(outer, _)| group_dns.get(outer).cloned())
                .collect();
            entry.set("memberOf", outer.into_iter().map(String::into_bytes).collect());
            entry.set("objectGUID", vec![object_guid(&group.id)]);
            entry.set("objectSid", vec![object_sid(source.sid, group.gid_number as u32)]);
            entry.one("entryUUID", &group.id);
            entry.one("createTimestamp", generalized(&group.created));
            entry.one("modifyTimestamp", generalized(&group.updated));
            entry.one("whenCreated", generalized(&group.created));
            entry.one("whenChanged", generalized(&group.updated));
            entries.push(entry);
        }

        for name in source.services {
            let mut entry = Entry::new(service_dn(&base_text, name), Kind::Container);
            entry.text("objectClass", &["top", "applicationProcess"]);
            entry.one("cn", name);
            entries.push(entry);
        }

        let group_ids = group_dns
            .iter()
            .map(|(id, dn)| (Dn::parse(dn).map(|dn| dn.normalized()).unwrap_or_default(), id.clone()))
            .collect();
        let group_dns = group_dns
            .into_iter()
            .map(|(id, dn)| (id, Dn::parse(&dn).map(|dn| dn.normalized()).unwrap_or_default()))
            .collect();
        Snapshot {
            entries,
            base,
            domain: source.domain.to_string(),
            people,
            usernames,
            group_dns,
            group_ids,
            membership: source.membership.clone(),
        }
    }

    /// The groups (normalized DNs) `entry` is in, through groups inside groups too: for
    /// `memberOf:1.2.840.113556.1.4.1941:=`.
    pub fn nested_groups_of(&self, entry: &Entry) -> BTreeSet<String> {
        let ids: BTreeSet<String> = match &entry.kind {
            Kind::Person(id) => self.membership.groups_of(id),
            Kind::Group(id) => {
                let mut found = BTreeSet::new();
                let mut queue = vec![id.clone()];
                while let Some(inner) = queue.pop() {
                    for (outer, members) in &self.membership.groups {
                        if members.contains(&inner) && found.insert(outer.clone()) {
                            queue.push(outer.clone());
                        }
                    }
                }
                found
            }
            _ => BTreeSet::new(),
        };
        ids.iter().filter_map(|id| self.group_dns.get(id).cloned()).collect()
    }

    /// The members (normalized DNs) of group `entry`, through groups inside groups too: for
    /// `member:1.2.840.113556.1.4.1941:=`.
    pub fn nested_members_of(&self, entry: &Entry) -> BTreeSet<String> {
        let Kind::Group(id) = &entry.kind else { return BTreeSet::new() };
        let everybody: Vec<String> = self.people.keys().cloned().collect();
        let mut found: BTreeSet<String> = self
            .membership
            .people_in(id, &everybody)
            .into_iter()
            .filter_map(|person| self.people.get(&person).map(|index| self.entries[*index].normalized.clone()))
            .collect();
        let mut queue = vec![id.clone()];
        let mut seen = BTreeSet::new();
        while let Some(group) = queue.pop() {
            if !seen.insert(group.clone()) {
                continue;
            }
            for inner in self.membership.groups.get(&group).into_iter().flatten() {
                if let Some(dn) = self.group_dns.get(inner) {
                    found.insert(dn.clone());
                }
                queue.push(inner.clone());
            }
        }
        found
    }

    /// The person a bind name means: a DN under `ou=people`, `name`, `name@domain`,
    /// `DOMAIN\name`, or an address.
    pub fn find_person<'a>(&'a self, name: &str, people: &'a [Person]) -> Option<&'a Person> {
        let name = name.trim();
        let by_username = |username: &str| {
            let id = self.usernames.get(&username.to_lowercase())?;
            people.iter().find(|person| &person.id == id)
        };
        if let Some(dn) = Dn::parse(name).filter(|dn| dn.0.len() > 1) {
            let first = dn.first()?;
            if !matches!(first.name.as_str(), "uid" | "cn")
                || dn.parent().normalized() != format!("ou=people,{}", self.base.normalized())
            {
                return None;
            }
            return by_username(&first.value);
        }
        if let Some((_, user)) = name.split_once('\\') {
            return by_username(user);
        }
        if let Some((user, domain)) = name.split_once('@') {
            if domain.eq_ignore_ascii_case(&self.domain)
                && let Some(person) = by_username(user)
            {
                return Some(person);
            }
            return people.iter().find(|person| {
                person.deleted.is_none()
                    && person.email.as_deref().is_some_and(|email| email.eq_ignore_ascii_case(name))
            });
        }
        by_username(name)
    }
}

/// The base DN for a server at `host`: `auth.example.com` → `dc=example,dc=com`; a name of one
/// or two labels stays whole.
pub fn default_base(host: &str) -> String {
    let host = host.split(':').next().unwrap_or(host);
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    let labels = if labels.len() > 2 { &labels[1..] } else { &labels[..] };
    if labels.is_empty() || labels.iter().all(|label| label.chars().all(|c| c.is_ascii_digit())) {
        return "dc=uwuauth,dc=local".into();
    }
    labels.iter().map(|label| format!("dc={}", label.to_lowercase())).collect::<Vec<_>>().join(",")
}

/// `example.com` from `dc=example,dc=com`.
pub fn domain_of(base: &Dn) -> String {
    base.0.iter().filter(|rdn| rdn.name == "dc").map(|rdn| rdn.value.to_lowercase()).collect::<Vec<_>>().join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base_comes_from_the_server_s_name() {
        assert_eq!(default_base("auth.example.com"), "dc=example,dc=com");
        assert_eq!(default_base("example.com:8443"), "dc=example,dc=com");
        assert_eq!(default_base("auth.home.arpa"), "dc=home,dc=arpa");
        assert_eq!(default_base("127.0.0.1"), "dc=uwuauth,dc=local");
        assert_eq!(domain_of(&Dn::parse("dc=example,dc=com").unwrap()), "example.com");
    }

    #[test]
    fn a_sid_and_a_guid_in_windows_order() {
        let sid = object_sid([1, 2, 3], 10000);
        assert_eq!(sid.len(), 8 + 5 * 4);
        assert_eq!(&sid[..8], &[1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&sid[8..12], &21u32.to_le_bytes());
        let guid = object_guid("00112233-4455-6677-8899-aabbccddeeff");
        assert_eq!(
            guid,
            vec![0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(generalized("2026-09-27T12:34:56.000000Z"), "20260927123456Z");
    }
}
