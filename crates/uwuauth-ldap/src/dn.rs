//! Distinguished names (RFC 4514): taking them apart, comparing them, and escaping values.
//!
//! Two DNs are the same when their attribute names match case-insensitively and their values
//! match after unescaping, case-insensitively and with spaces around the separators ignored —
//! which is how apps write them, and how directories compare them.

/// One `name=value` part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    /// Lower case.
    pub name: String,
    /// Unescaped.
    pub value: String,
}

/// A DN, taken apart: the leftmost part first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dn(pub Vec<Rdn>);

impl Dn {
    /// Parse `text`; nothing when it is not a DN. Multi-valued RDNs (`a=1+b=2`) are refused: no
    /// entry here has one.
    pub fn parse(text: &str) -> Option<Dn> {
        let text = text.trim();
        if text.is_empty() {
            return Some(Dn::default());
        }
        let mut parts = Vec::new();
        let mut chars = text.chars().peekable();
        loop {
            let mut name = String::new();
            for c in chars.by_ref() {
                if c == '=' {
                    break;
                }
                name.push(c);
            }
            let name = name.trim().to_lowercase();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
                return None;
            }
            let mut value = String::new();
            let mut pending_space = String::new();
            let mut ended = false;
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        let next = chars.next()?;
                        // Spaces before the value are not part of it; spaces inside it are.
                        if !value.is_empty() {
                            value.push_str(&pending_space);
                        }
                        pending_space.clear();
                        if next.is_ascii_hexdigit() {
                            let low = chars.next()?;
                            let byte = u8::from_str_radix(&format!("{next}{low}"), 16).ok()?;
                            // Hex escapes may spell UTF-8 over several bytes.
                            let mut bytes = vec![byte];
                            while byte >= 0x80 && chars.peek() == Some(&'\\') {
                                let mut ahead = chars.clone();
                                ahead.next();
                                let (Some(h), Some(l)) = (ahead.next(), ahead.next()) else { break };
                                let Ok(more) = u8::from_str_radix(&format!("{h}{l}"), 16) else { break };
                                if more & 0xC0 != 0x80 {
                                    break;
                                }
                                chars = ahead;
                                bytes.push(more);
                            }
                            value.push_str(&String::from_utf8(bytes).ok()?);
                        } else {
                            value.push(next);
                        }
                    }
                    ',' | ';' => {
                        ended = true;
                        break;
                    }
                    '+' => return None,
                    ' ' => pending_space.push(' '),
                    c => {
                        if !value.is_empty() {
                            value.push_str(&pending_space);
                        }
                        pending_space.clear();
                        value.push(c);
                    }
                }
            }
            parts.push(Rdn { name, value });
            if !ended {
                break;
            }
        }
        Some(Dn(parts))
    }

    /// The comparable form: names and values lower case, values escaped, no spaces between parts.
    pub fn normalized(&self) -> String {
        self.0
            .iter()
            .map(|rdn| format!("{}={}", rdn.name, escape(&rdn.value.to_lowercase())))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Whether `self` is `base` or below it.
    pub fn is_under(&self, base: &Dn) -> bool {
        self.0.len() >= base.0.len() && self.normalized().ends_with(&base.normalized()) && {
            let tail = &self.0[self.0.len() - base.0.len()..];
            Dn(tail.to_vec()).normalized() == base.normalized()
        }
    }

    /// The parent: the DN without its leftmost part.
    pub fn parent(&self) -> Dn {
        Dn(self.0.iter().skip(1).cloned().collect())
    }

    pub fn first(&self) -> Option<&Rdn> {
        self.0.first()
    }
}

/// A value escaped for a DN (RFC 4514 section 2.4).
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (index, c) in value.chars().enumerate() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '#' if index == 0 => out.push_str("\\#"),
            ' ' if index == 0 || index == last => out.push_str("\\ "),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_compare_the_way_directories_do() {
        let a = Dn::parse("UID=Nyu, OU=people ,dc=Example,DC=com").unwrap();
        let b = Dn::parse("uid=nyu,ou=people,dc=example,dc=com").unwrap();
        assert_eq!(a.normalized(), b.normalized());
        assert!(b.is_under(&Dn::parse("dc=example,dc=com").unwrap()));
        assert!(!b.is_under(&Dn::parse("dc=other,dc=com").unwrap()));
        assert!(!Dn::parse("dc=com").unwrap().is_under(&b));
        assert_eq!(b.parent().normalized(), "ou=people,dc=example,dc=com");
    }

    #[test]
    fn escaped_values_come_back() {
        let dn = Dn::parse(r"cn=B\C3\BCro\2C Team \2B 2,ou=groups,dc=example,dc=com").unwrap();
        assert_eq!(dn.0[0].value, "Büro, Team + 2");
        let written = format!("cn={},ou=groups,dc=example,dc=com", escape("Büro, Team + 2"));
        assert_eq!(Dn::parse(&written).unwrap().0[0].value, "Büro, Team + 2");
        assert_eq!(escape(" x "), r"\ x\ ");
        assert!(Dn::parse("cn=a+sn=b,dc=example").is_none());
        assert!(Dn::parse("no equals").is_none());
        assert_eq!(Dn::parse("").unwrap(), Dn::default());
    }
}
