//! Randomness, hashes, sealed secrets and password hashing.
//!
//! - **Passwords** are hashed with Argon2id (OWASP's parameters by default, cheap ones in tests),
//!   a few at a time, off the async threads.
//! - **Tokens** — session cookies, links, app passwords, API tokens — are random and long, so the
//!   database keeps only their SHA-256.
//! - **Secrets the server has to read again** — the authenticator app's secret, the mail server's
//!   password — are sealed with AES-256-GCM under a key in `secret.key` next to the database, not
//!   in it: a copy of the database alone does not give them away.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::path::Path;

/// `bytes` random bytes, from the operating system.
pub fn random_bytes(bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];
    SystemRandom::new().fill(&mut out).expect("the system has randomness");
    out
}

/// A random token for a URL, a cookie or a header: base64url of `bytes` random bytes.
pub fn random_token(bytes: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(bytes))
}

/// Random text from an alphabet without letters that look alike, in groups of four: what people
/// type or read out, like app passwords and recovery codes.
pub fn readable_secret(groups: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut out = String::with_capacity(groups * 5);
    let limit = 256 - 256 % ALPHABET.len();
    while out.len() < groups * 5 - 1 {
        for byte in random_bytes(32) {
            if usize::from(byte) >= limit {
                continue;
            }
            if out.len() % 5 == 4 {
                out.push('-');
            }
            out.push(ALPHABET[usize::from(byte) % ALPHABET.len()] as char);
            if out.len() == groups * 5 - 1 {
                break;
            }
        }
    }
    out
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

/// SHA-256 of what a person types, without the dashes and spaces they may or may not type.
pub fn secret_hash(typed: &str) -> Vec<u8> {
    let normalized: String =
        typed.chars().filter(|c| !c.is_whitespace() && *c != '-').flat_map(char::to_lowercase).collect();
    sha256(normalized.as_bytes())
}

/// Compare without telling by the time it takes where the first difference is.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url with or without padding, or plain base64: clients differ.
pub fn unb64(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed).ok())
}

// ── Sealing ───────────────────────────────────────────────

/// Seals and opens secrets with the server's key.
pub struct Sealer {
    key: LessSafeKey,
}

impl Sealer {
    /// The key from `path`, made there (readable by the server only) if there is none yet.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let fresh = random_bytes(32);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
                }
                write_private(path, &fresh).map_err(|error| format!("{}: {error}", path.display()))?;
                fresh
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if bytes.len() != 32 {
            return Err(format!("{} is not a key of this server: it should be 32 bytes", path.display()));
        }
        Ok(Self::from_key(&bytes))
    }

    pub fn from_key(key: &[u8]) -> Self {
        Sealer { key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte key")) }
    }

    /// `v1.` and base64 of a random nonce and the sealed bytes.
    pub fn seal(&self, plain: &[u8]) -> String {
        let nonce: [u8; 12] = random_bytes(12).try_into().expect("12 bytes");
        let mut sealed = plain.to_vec();
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(b"uwuauth"), &mut sealed)
            .expect("sealing never fails for short input");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        format!("v1.{}", STANDARD.encode(out))
    }

    /// What [`Sealer::seal`] sealed; nothing when it was sealed with another key or is damaged.
    pub fn open(&self, sealed: &str) -> Option<Vec<u8>> {
        let bytes = STANDARD.decode(sealed.strip_prefix("v1.")?).ok()?;
        if bytes.len() < 12 + 16 {
            return None;
        }
        let (nonce, rest) = bytes.split_at(12);
        let mut rest = rest.to_vec();
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let plain = self.key.open_in_place(nonce, Aad::from(b"uwuauth"), &mut rest).ok()?;
        Some(plain.to_vec())
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

// ── Passwords ─────────────────────────────────────────────

/// How hard Argon2id works. OWASP's recommendation for a server by default; tests use less.
#[derive(Debug, Clone, Copy)]
pub struct HashCost {
    pub memory_kib: u32,
    pub iterations: u32,
}

impl Default for HashCost {
    fn default() -> Self {
        HashCost { memory_kib: 19 * 1024, iterations: 2 }
    }
}

impl HashCost {
    /// Cheap, for tests, where nobody attacks the hash.
    pub fn cheap() -> Self {
        HashCost { memory_kib: 64, iterations: 1 }
    }

    fn argon2(self) -> argon2::Argon2<'static> {
        let params = argon2::Params::new(self.memory_kib, self.iterations, 1, None).expect("valid Argon2 parameters");
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    }
}

/// How many hashes run at once. Each takes its memory (19 MiB by default) for as long as it
/// runs; without a bound, many sign-ins at the same moment — from many addresses, which the rate
/// limits do not stop — would take as much memory as they like. The rest wait their turn.
fn hashing() -> &'static tokio::sync::Semaphore {
    static HASHING: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    HASHING.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        tokio::sync::Semaphore::new((cores * 2).clamp(2, 32))
    })
}

/// Hash a password. Off the async threads: it takes a few dozen milliseconds on purpose.
pub async fn hash_password(cost: HashCost, password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let password = password.to_string();
    let turn = hashing().acquire().await.map_err(|error| error.to_string())?;
    tokio::task::spawn_blocking(move || {
        let _turn = turn;
        let salt = SaltString::encode_b64(&random_bytes(16)).map_err(|error| error.to_string())?;
        cost.argon2().hash_password(password.as_bytes(), &salt).map(|hash| hash.to_string()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Whether `password` is what `hash` was made from. For somebody who does not exist or has no
/// password, pass `None`: the same work is done anyway, so the time taken does not tell which
/// names have an account.
pub async fn verify_password(cost: HashCost, hash: Option<&str>, password: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let hash = hash.map(str::to_string);
    let password = password.to_string();
    let Ok(turn) = hashing().acquire().await else { return false };
    tokio::task::spawn_blocking(move || {
        let _turn = turn;
        match hash {
            Some(hash) => PasswordHash::new(&hash)
                .is_ok_and(|parsed| argon2::Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()),
            None => {
                use argon2::password_hash::{PasswordHasher, SaltString};
                let salt = SaltString::encode_b64(&[0u8; 16]).expect("a fixed salt");
                let _ = cost.argon2().hash_password(password.as_bytes(), &salt);
                false
            }
        }
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_secret_opens_only_with_its_key() {
        let sealer = Sealer::from_key(&[1; 32]);
        let sealed = sealer.seal(b"totp secret");
        assert_ne!(sealer.seal(b"totp secret"), sealed, "a new nonce every time");
        assert_eq!(sealer.open(&sealed).unwrap(), b"totp secret");
        assert!(Sealer::from_key(&[2; 32]).open(&sealed).is_none());
        assert!(sealer.open("v1.AAAA").is_none());
        assert!(sealer.open("plain").is_none());
    }

    #[test]
    fn the_key_is_made_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        let sealed = Sealer::load(&path).unwrap().seal(b"x");
        assert_eq!(Sealer::load(&path).unwrap().open(&sealed).unwrap(), b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(&path, b"short").unwrap();
        assert!(Sealer::load(&path).is_err());
    }

    #[test]
    fn readable_secrets_are_readable() {
        let secret = readable_secret(6);
        assert_eq!(secret.len(), 29);
        assert_eq!(secret.split('-').count(), 6);
        assert!(secret.chars().all(|c| c == '-' || (c.is_ascii_alphanumeric() && !"ilo01".contains(c))));
        assert_eq!(secret_hash(&secret), secret_hash(&secret.replace('-', " ").to_uppercase()));
    }

    #[tokio::test]
    async fn a_password_hash_takes_only_the_right_password() {
        let hash = hash_password(HashCost::cheap(), "correct horse").await.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(HashCost::cheap(), Some(&hash), "correct horse").await);
        assert!(!verify_password(HashCost::cheap(), Some(&hash), "wrong").await);
        assert!(!verify_password(HashCost::cheap(), None, "correct horse").await);
        assert!(!verify_password(HashCost::cheap(), Some("garbage"), "correct horse").await);
    }
}
