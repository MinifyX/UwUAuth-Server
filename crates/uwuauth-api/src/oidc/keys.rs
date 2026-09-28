//! The keys UwUAuth signs tokens with, and JWTs (RFC 7519) signed and checked with them.
//!
//! Two keys: RSA (RS256), which OpenID Connect assumes when an app says nothing, and P-256
//! (ES256), smaller and faster, for apps that take it. Both are made on first use and kept in the
//! database, sealed with the server's key. `ring` signs with both; the RSA key is only *made* with
//! the `rsa` crate, because `ring` cannot make one.
//!
//! Tokens are only ever checked against these keys, with the algorithm the key is for: `none`,
//! HMAC and anything else never pass.

use crate::crypto::{Sealer, b64, sha256, unb64};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair, UnparsedPublicKey};
use serde_json::{Map, Value, json};
use uwuauth_store::Store;

const RSA_KEY: &str = "oidc_rsa";
const EC_KEY: &str = "oidc_ec";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Es256,
}

impl Alg {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "RS256" => Some(Alg::Rs256),
            "ES256" => Some(Alg::Es256),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Es256 => "ES256",
        }
    }
}

pub struct Keys {
    rsa: RsaKeyPair,
    rsa_kid: String,
    ec: EcdsaKeyPair,
    ec_kid: String,
}

/// A key's id: the start of its public key's hash, stable for as long as the key is.
fn kid(public: &[u8]) -> String {
    b64(&sha256(public)[..12])
}

impl Keys {
    /// The keys from the database, made there first if there are none. `fixed_rsa` stands in for
    /// making an RSA key (tests, where that would take long).
    pub async fn load(store: &Store, sealer: &Sealer, fixed_rsa: Option<&[u8]>) -> Result<Self, String> {
        let rsa_pkcs8 = match stored(store, sealer, RSA_KEY).await? {
            Some(pkcs8) => pkcs8,
            None => {
                let fresh = match fixed_rsa {
                    Some(key) => key.to_vec(),
                    None => tokio::task::spawn_blocking(make_rsa).await.map_err(|error| error.to_string())??,
                };
                keep(store, sealer, RSA_KEY, &fresh).await?
            }
        };
        let ec_pkcs8 = match stored(store, sealer, EC_KEY).await? {
            Some(pkcs8) => pkcs8,
            None => {
                let fresh =
                    EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                        .map_err(|_| "no randomness for a key")?;
                keep(store, sealer, EC_KEY, fresh.as_ref()).await?
            }
        };
        let rsa =
            RsaKeyPair::from_pkcs8(&rsa_pkcs8).map_err(|error| format!("the RSA signing key is damaged: {error}"))?;
        let ec = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &ec_pkcs8, &SystemRandom::new())
            .map_err(|error| format!("the P-256 signing key is damaged: {error}"))?;
        let rsa_kid = kid(rsa.public().as_ref());
        let ec_kid = kid(ec.public_key().as_ref());
        Ok(Keys { rsa, rsa_kid, ec, ec_kid })
    }

    /// Both public keys, as a JWK set (RFC 7517).
    pub fn jwks(&self) -> Value {
        let rsa = signature::RsaPublicKeyComponents::<Vec<u8>>::from(self.rsa.public());
        let point = self.ec.public_key().as_ref();
        json!({ "keys": [
            {
                "kty": "RSA",
                "n": b64(&rsa.n),
                "e": b64(&rsa.e),
                "use": "sig",
                "alg": "RS256",
                "kid": self.rsa_kid,
            },
            {
                "kty": "EC",
                "crv": "P-256",
                "x": b64(&point[1..33]),
                "y": b64(&point[33..65]),
                "use": "sig",
                "alg": "ES256",
                "kid": self.ec_kid,
            },
        ]})
    }

    /// A signed JWT: `typ` in the header (`JWT`, or `at+jwt` for access tokens, RFC 9068).
    pub fn sign(&self, alg: Alg, typ: &str, claims: &Value) -> String {
        let kid = match alg {
            Alg::Rs256 => &self.rsa_kid,
            Alg::Es256 => &self.ec_kid,
        };
        let header = json!({ "alg": alg.name(), "typ": typ, "kid": kid });
        let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let rng = SystemRandom::new();
        let signature = match alg {
            Alg::Rs256 => {
                let mut out = vec![0; self.rsa.public().modulus_len()];
                self.rsa
                    .sign(&signature::RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut out)
                    .expect("RSA signing works");
                out
            }
            Alg::Es256 => self.ec.sign(&rng, input.as_bytes()).expect("ECDSA signing works").as_ref().to_vec(),
        };
        format!("{input}.{}", b64(&signature))
    }

    /// The header and claims of a JWT one of these keys signed, if it is one. Nothing is said
    /// about the claims: whoever calls checks issuer, audience and time.
    pub fn verify(&self, token: &str) -> Option<(Map<String, Value>, Map<String, Value>)> {
        let mut parts = token.trim().split('.');
        let (Some(header), Some(claims), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let object = |part: &str| -> Option<Map<String, Value>> {
            match serde_json::from_slice(&unb64(part)?) {
                Ok(Value::Object(map)) => Some(map),
                _ => None,
            }
        };
        let (head, body) = (object(header)?, object(claims)?);
        let signature = unb64(signature)?;
        let message = format!("{header}.{claims}");
        let kid = head.get("kid").and_then(Value::as_str);
        let valid = match head.get("alg").and_then(Value::as_str) {
            Some("RS256") if kid.is_none_or(|kid| kid == self.rsa_kid) => {
                signature::RsaPublicKeyComponents::<Vec<u8>>::from(self.rsa.public())
                    .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &signature)
                    .is_ok()
            }
            Some("ES256") if kid.is_none_or(|kid| kid == self.ec_kid) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, self.ec.public_key().as_ref())
                    .verify(message.as_bytes(), &signature)
                    .is_ok()
            }
            _ => false,
        };
        valid.then_some((head, body))
    }
}

/// The left half of the SHA-256 of `token`, base64url: `at_hash` and `c_hash` for both algorithms
/// (RS256 and ES256 both hash with SHA-256).
pub fn half_hash(token: &str) -> String {
    let hash = sha256(token.as_bytes());
    b64(&hash[..16])
}

async fn stored(store: &Store, sealer: &Sealer, key: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(sealed) = store.setting(key).await.map_err(|error| error.to_string())? else { return Ok(None) };
    sealer
        .open(&sealed)
        .map(Some)
        .ok_or_else(|| format!("the signing key {key} does not open with secret.key — was secret.key replaced?"))
}

/// Keep a new key — unless another start kept one first, which then wins.
async fn keep(store: &Store, sealer: &Sealer, key: &str, pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    let sealed = store.setting_or_insert(key, &sealer.seal(pkcs8)).await.map_err(|error| error.to_string())?;
    sealer.open(&sealed).ok_or_else(|| format!("the signing key {key} does not open"))
}

fn make_rsa() -> Result<Vec<u8>, String> {
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).map_err(|error| error.to_string())?;
    key.to_pkcs8_der().map(|der| der.as_bytes().to_vec()).map_err(|error| error.to_string())
}

/// A fixed RSA key for tests, so no test waits for one to be made. Made for this and nothing
/// else: it signs nothing outside the tests.
#[cfg(test)]
pub(crate) fn test_rsa_key() -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(include_str!("test-rsa.b64").trim())
        .expect("the test key is base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn keys() -> (Keys, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &uwuauth_store::Options { readers: 1 }).unwrap();
        let sealer = Sealer::from_key(&[3; 32]);
        (Keys::load(&store, &sealer, Some(&test_rsa_key())).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn both_algorithms_sign_and_verify() {
        let (keys, _dir) = keys().await;
        for alg in [Alg::Rs256, Alg::Es256] {
            let token = keys.sign(alg, "JWT", &json!({ "sub": "nyu" }));
            let (header, claims) = keys.verify(&token).expect("our own token");
            assert_eq!(header["alg"], alg.name());
            assert_eq!(claims["sub"], "nyu");
            let mut tampered = token.clone();
            tampered.insert(token.find('.').unwrap() + 2, 'x');
            assert!(keys.verify(&tampered).is_none());
        }
        assert_eq!(keys.jwks()["keys"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn none_and_hmac_never_pass() {
        let (keys, _dir) = keys().await;
        let claims = b64(json!({ "sub": "admin" }).to_string().as_bytes());
        for alg in ["none", "HS256"] {
            let header = b64(json!({ "alg": alg }).to_string().as_bytes());
            assert!(keys.verify(&format!("{header}.{claims}.")).is_none(), "{alg}");
            assert!(keys.verify(&format!("{header}.{claims}.c2lnbmF0dXJl")).is_none(), "{alg}");
        }
    }

    #[tokio::test]
    async fn the_keys_are_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &uwuauth_store::Options { readers: 1 }).unwrap();
        let sealer = Sealer::from_key(&[3; 32]);
        let first = Keys::load(&store, &sealer, Some(&test_rsa_key())).await.unwrap();
        let second = Keys::load(&store, &sealer, None).await.unwrap();
        assert_eq!(first.jwks(), second.jwks());
        let token = first.sign(Alg::Es256, "JWT", &json!({}));
        assert!(second.verify(&token).is_some());
    }
}
