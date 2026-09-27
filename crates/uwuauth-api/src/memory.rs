//! What the server only needs for a few minutes, in memory: WebAuthn challenges waiting for their
//! answer, sign-ins waiting for their second step, an authenticator app being set up.
//!
//! A restart forgets them, which costs somebody one more try at most.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// At most this many live values per map: past that, new ones are refused rather than let an
/// attacker fill the memory.
pub const MOST: usize = 10_000;

/// Values by key that are taken once and run out after `ttl`.
pub struct Expiring<V> {
    ttl: Duration,
    entries: Mutex<HashMap<String, (V, Instant)>>,
}

impl<V> Expiring<V> {
    pub fn new(ttl: Duration) -> Self {
        Expiring { ttl, entries: Mutex::new(HashMap::new()) }
    }

    /// Keep `value` under `key`. False when the map is full of live values and this is a new key.
    pub fn put(&self, key: String, value: V) -> bool {
        let mut entries = self.entries.lock();
        let now = Instant::now();
        if entries.len() >= MOST && !entries.contains_key(&key) {
            entries.retain(|_, (_, at)| now.duration_since(*at) < self.ttl);
            if entries.len() >= MOST {
                return false;
            }
        }
        entries.insert(key, (value, now));
        true
    }

    /// The value under `key`, once: whatever happens next, it is gone.
    pub fn take(&self, key: &str) -> Option<V> {
        let (value, at) = self.entries.lock().remove(key)?;
        (at.elapsed() < self.ttl).then_some(value)
    }
}

impl<V: Clone> Expiring<V> {
    /// The first value `matches` takes, with its key, left where it is.
    pub fn find(&self, matches: impl Fn(&V) -> bool) -> Option<(String, V)> {
        let entries = self.entries.lock();
        entries
            .iter()
            .find(|(_, (value, at))| at.elapsed() < self.ttl && matches(value))
            .map(|(key, (value, _))| (key.clone(), value.clone()))
    }

    /// The value under `key`, left where it is.
    pub fn peek(&self, key: &str) -> Option<V> {
        let entries = self.entries.lock();
        entries.get(key).filter(|(_, at)| at.elapsed() < self.ttl).map(|(value, _)| value.clone())
    }
}

/// A sign-in that got past the password and waits for its second step.
#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub person_id: String,
    pub remember: bool,
    /// Wrong second steps so far; after five, the sign-in starts over.
    pub tries: u32,
}

/// What the server keeps in memory.
pub struct Memory {
    /// WebAuthn challenges, by what they are for (`login:<nonce>`, `register:<person>`, …).
    pub challenges: Expiring<Vec<u8>>,
    /// Sign-ins waiting for their second step, by the token the browser got.
    pub pending: Expiring<PendingLogin>,
    /// Authenticator app secrets being set up, by person, until the first code confirms them.
    pub totp_setup: Expiring<Vec<u8>>,
    /// Sign-ins to apps in progress: codes, consent, devices, sign-outs.
    pub oidc: crate::oidc::Pending,
}

impl Default for Memory {
    fn default() -> Self {
        Memory {
            challenges: Expiring::new(Duration::from_secs(crate::webauthn::CHALLENGE_SECONDS)),
            pending: Expiring::new(Duration::from_secs(5 * 60)),
            totp_setup: Expiring::new(Duration::from_secs(15 * 60)),
            oidc: crate::oidc::Pending::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_taken_once_and_runs_out() {
        let map = Expiring::new(Duration::from_secs(60));
        map.put("a".into(), 1);
        assert_eq!(map.peek("a"), Some(1));
        assert_eq!(map.take("a"), Some(1));
        assert_eq!(map.take("a"), None);
        let gone = Expiring::new(Duration::ZERO);
        gone.put("b".into(), 2);
        assert_eq!(gone.take("b"), None);
    }

    #[test]
    fn a_full_map_refuses_newcomers() {
        let map = Expiring::new(Duration::from_secs(60));
        for n in 0..MOST {
            assert!(map.put(n.to_string(), n));
        }
        assert!(!map.put("one more".into(), 0));
        assert!(map.put("1".into(), 1), "an existing key may still change");
    }
}
