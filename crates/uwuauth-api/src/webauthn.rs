//! WebAuthn, checked by hand: passkeys that sign in on their own, and security keys as the second
//! step after a password.
//!
//! Only what that needs, with the crypto `ring` brings anyway: attestation `none` (the server
//! does not care which make of key it is, only that it is the same one later), ES256, EdDSA and
//! RS256 signatures, and the checks WebAuthn asks for — the challenge, the origin, the relying
//! party, user presence (and verification, where asked), and a signature counter that only goes
//! up.

use ciborium::Value as Cbor;
use parking_lot::Mutex;
use ring::signature::{self, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a challenge waits for its answer.
pub const CHALLENGE_SECONDS: u64 = 5 * 60;

/// What a new credential is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub credential_id: Vec<u8>,
    /// The COSE public key, as the authenticator sent it.
    pub public_key: Vec<u8>,
    pub counter: u32,
}

/// Where WebAuthn happens: the relying party id (the host) and the origin pages come from.
#[derive(Debug, Clone)]
pub struct Party {
    pub id: String,
    pub origin: String,
}

impl Party {
    /// From the server's public address: `https://auth.example.com:8443` has the id
    /// `auth.example.com` and itself as the origin.
    pub fn from_public(public: &str) -> Self {
        let origin = public.trim_end_matches('/').to_string();
        let host = origin.split_once("://").map_or(origin.as_str(), |(_, rest)| rest);
        let host = host.split('/').next().unwrap_or(host);
        let id = match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) && !name.ends_with(']') => name,
            _ => host,
        };
        Party { id: id.to_string(), origin }
    }
}

pub use crate::crypto::{b64, unb64};

// ── What clients send ─────────────────────────────────────

/// `navigator.credentials.create()`'s answer, as JSON (`PublicKeyCredential.toJSON()`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    #[serde(alias = "rawId")]
    pub raw_id: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    pub response: AttestationResponse,
}

#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    #[serde(alias = "AttestationObject", rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(alias = "clientDataJSON", rename = "clientDataJson")]
    pub client_data_json: String,
}

/// `navigator.credentials.get()`'s answer.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    #[serde(default)]
    pub raw_id: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    pub response: AssertionResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    pub authenticator_data: String,
    #[serde(alias = "clientDataJSON", rename = "clientDataJson")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

impl Assertion {
    /// The credential it is from.
    pub fn credential_id(&self) -> Option<Vec<u8>> {
        self.raw_id.as_deref().or(self.id.as_deref()).and_then(unb64)
    }
}

impl Attestation {
    pub fn credential_id(&self) -> Option<Vec<u8>> {
        self.raw_id.as_deref().or(self.id.as_deref()).and_then(unb64)
    }
}

// ── Checking ──────────────────────────────────────────────

fn check_client_data(raw: &[u8], kind: &str, challenge: &[u8], party: &Party) -> Result<(), String> {
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
    }
    let data: ClientData = serde_json::from_slice(raw).map_err(|_| "the client data is not readable")?;
    if data.kind != kind {
        return Err("the client data is for something else".into());
    }
    if unb64(&data.challenge).as_deref() != Some(challenge) {
        return Err("the challenge does not match".into());
    }
    if data.origin.trim_end_matches('/') != party.origin {
        return Err(format!("the origin {} is not this server", data.origin));
    }
    Ok(())
}

/// The fixed start of authenticator data: rp id hash, flags, counter.
struct AuthData<'a> {
    flags: u8,
    counter: u32,
    rest: &'a [u8],
}

const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const ATTESTED: u8 = 0x40;

fn parse_auth_data<'a>(data: &'a [u8], party: &Party, verified: bool) -> Result<AuthData<'a>, String> {
    if data.len() < 37 {
        return Err("the authenticator data is too short".into());
    }
    let rp_hash = ring::digest::digest(&ring::digest::SHA256, party.id.as_bytes());
    if data[..32] != *rp_hash.as_ref() {
        return Err("the key is for another server".into());
    }
    let flags = data[32];
    if flags & USER_PRESENT == 0 {
        return Err("nobody touched the key".into());
    }
    if verified && flags & USER_VERIFIED == 0 {
        return Err("the key did not verify who is there".into());
    }
    let counter = u32::from_be_bytes(data[33..37].try_into().expect("four bytes"));
    Ok(AuthData { flags, counter, rest: &data[37..] })
}

fn cbor_get(map: &[(Cbor, Cbor)], key: i64) -> Option<&Cbor> {
    map.iter().find(|(k, _)| k.as_integer().is_some_and(|k| i128::from(k) == i128::from(key))).map(|(_, v)| v)
}

fn cbor_bytes(map: &[(Cbor, Cbor)], key: i64) -> Option<&[u8]> {
    cbor_get(map, key)?.as_bytes().map(Vec::as_slice)
}

fn cbor_int(map: &[(Cbor, Cbor)], key: i64) -> Option<i128> {
    cbor_get(map, key)?.as_integer().map(i128::from)
}

/// Whether a COSE key is one this server checks signatures of.
fn check_key(cose: &[u8]) -> Result<(), String> {
    let key: Cbor = ciborium::from_reader(cose).map_err(|_| "the key is not readable")?;
    let map = key.as_map().ok_or("the key is not readable")?;
    match (cbor_int(map, 1), cbor_int(map, 3)) {
        (Some(2), Some(-7))
            if cbor_bytes(map, -2).is_some_and(|x| x.len() == 32)
                && cbor_bytes(map, -3).is_some_and(|y| y.len() == 32) =>
        {
            Ok(())
        }
        (Some(1), Some(-8)) if cbor_bytes(map, -2).is_some_and(|x| x.len() == 32) => Ok(()),
        (Some(3), Some(-257)) if cbor_bytes(map, -1).is_some() && cbor_bytes(map, -2).is_some() => Ok(()),
        _ => Err("this kind of key is not supported: use one with ES256, EdDSA or RS256".into()),
    }
}

fn verify_signature(cose: &[u8], message: &[u8], signed: &[u8]) -> Result<(), String> {
    let key: Cbor = ciborium::from_reader(cose).map_err(|_| "the stored key is not readable")?;
    let map = key.as_map().ok_or("the stored key is not readable")?;
    let bad = |_| "the signature is wrong".to_string();
    match cbor_int(map, 3) {
        Some(-7) => {
            let (x, y) = (cbor_bytes(map, -2).unwrap_or_default(), cbor_bytes(map, -3).unwrap_or_default());
            let mut point = Vec::with_capacity(65);
            point.push(4);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point).verify(message, signed).map_err(bad)
        }
        Some(-8) => UnparsedPublicKey::new(&signature::ED25519, cbor_bytes(map, -2).unwrap_or_default())
            .verify(message, signed)
            .map_err(bad),
        Some(-257) => signature::RsaPublicKeyComponents {
            n: cbor_bytes(map, -1).unwrap_or_default(),
            e: cbor_bytes(map, -2).unwrap_or_default(),
        }
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signed)
        .map_err(bad),
        _ => Err("the stored key is not supported".into()),
    }
}

/// Check a new credential against the challenge that was handed out for it.
pub fn register(
    attestation: &Attestation,
    challenge: &[u8],
    party: &Party,
    verified: bool,
) -> Result<Registered, String> {
    let client_data = unb64(&attestation.response.client_data_json).ok_or("the client data is not readable")?;
    check_client_data(&client_data, "webauthn.create", challenge, party)?;
    let object = unb64(&attestation.response.attestation_object).ok_or("the attestation is not readable")?;
    let object: Cbor = ciborium::from_reader(object.as_slice()).map_err(|_| "the attestation is not readable")?;
    let auth_data = object
        .as_map()
        .and_then(|map| map.iter().find(|(key, _)| key.as_text() == Some("authData")))
        .and_then(|(_, value)| value.as_bytes())
        .ok_or("the attestation has no authenticator data")?;
    let parsed = parse_auth_data(auth_data, party, verified)?;
    if parsed.flags & ATTESTED == 0 || parsed.rest.len() < 18 {
        return Err("the attestation has no credential".into());
    }
    let length = usize::from(u16::from_be_bytes([parsed.rest[16], parsed.rest[17]]));
    let rest = &parsed.rest[18..];
    if rest.len() < length || length == 0 || length > 1023 {
        return Err("the credential id is not readable".into());
    }
    let (credential_id, rest) = rest.split_at(length);
    // The key is the next CBOR item; extensions may follow it.
    let mut reader = std::io::Cursor::new(rest);
    let _: Cbor = ciborium::from_reader(&mut reader).map_err(|_| "the key is not readable")?;
    let public_key = rest[..reader.position() as usize].to_vec();
    check_key(&public_key)?;
    if attestation.credential_id().is_some_and(|given| given != credential_id) {
        return Err("the credential id does not match".into());
    }
    Ok(Registered { credential_id: credential_id.to_vec(), public_key, counter: parsed.counter })
}

/// Check an assertion by a credential with the key `public_key`, whose counter was at `counter`.
/// The counter it is at now.
pub fn assert(
    assertion: &Assertion,
    challenge: &[u8],
    party: &Party,
    public_key: &[u8],
    counter: u32,
    verified: bool,
) -> Result<u32, String> {
    let client_data = unb64(&assertion.response.client_data_json).ok_or("the client data is not readable")?;
    check_client_data(&client_data, "webauthn.get", challenge, party)?;
    let auth_data = unb64(&assertion.response.authenticator_data).ok_or("the authenticator data is not readable")?;
    let parsed = parse_auth_data(&auth_data, party, verified)?;
    let signed = unb64(&assertion.response.signature).ok_or("the signature is not readable")?;
    let mut message = auth_data.clone();
    message.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client_data).as_ref());
    verify_signature(public_key, &message, &signed)?;
    // Keys that count count up; one that went back is a copy.
    if (parsed.counter != 0 || counter != 0) && parsed.counter <= counter {
        return Err("the key's counter went backwards: it may have been copied".into());
    }
    Ok(parsed.counter)
}

// ── What goes out ─────────────────────────────────────────

/// A fresh challenge.
pub fn challenge() -> Vec<u8> {
    crate::crypto::random_bytes(32)
}

/// The user handle a passkey carries for a person: their id's 16 bytes.
pub fn user_handle(person_id: &str) -> Vec<u8> {
    uuid::Uuid::parse_str(person_id).map(|id| id.as_bytes().to_vec()).unwrap_or_else(|_| person_id.as_bytes().to_vec())
}

/// The person id in a user handle.
pub fn person_of_handle(handle: &[u8]) -> Option<String> {
    uuid::Uuid::from_slice(handle).ok().map(|id| id.to_string())
}

/// Options for `navigator.credentials.create()`. A passkey (`resident`) is found by the browser
/// without a name and verifies who is there; a security key for the second step does neither.
pub fn creation_options(
    party: &Party,
    person_id: &str,
    username: &str,
    display_name: &str,
    challenge: &[u8],
    exclude: &[Vec<u8>],
    resident: bool,
) -> Value {
    json!({
        "rp": { "id": party.id, "name": "UwUAuth" },
        "user": { "id": b64(&user_handle(person_id)), "name": username, "displayName": display_name },
        "challenge": b64(challenge),
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 },
            { "type": "public-key", "alg": -257 },
        ],
        "timeout": CHALLENGE_SECONDS * 1000,
        "attestation": "none",
        "authenticatorSelection": if resident {
            json!({ "requireResidentKey": true, "residentKey": "required", "userVerification": "required" })
        } else {
            json!({ "requireResidentKey": false, "residentKey": "discouraged", "userVerification": "discouraged" })
        },
        "excludeCredentials": exclude.iter().map(|id| json!({ "type": "public-key", "id": b64(id) })).collect::<Vec<_>>(),
        "extensions": { "credProps": true },
    })
}

/// Options for `navigator.credentials.get()`: for the second step with these keys, or — none
/// given — for a passkey the browser picks.
pub fn request_options(party: &Party, challenge: &[u8], allow: &[Vec<u8>]) -> Value {
    json!({
        "challenge": b64(challenge),
        "timeout": CHALLENGE_SECONDS * 1000,
        "rpId": party.id,
        "allowCredentials": allow.iter().map(|id| json!({ "type": "public-key", "id": b64(id) })).collect::<Vec<_>>(),
        "userVerification": if allow.is_empty() { "required" } else { "discouraged" },
    })
}

// ── Challenges waiting for their answer ───────────────────

/// Challenges by what they are for, in memory: an answer comes within minutes or not at all.
#[derive(Default)]
pub struct Challenges {
    waiting: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
}

impl Challenges {
    pub fn put(&self, key: String, challenge: Vec<u8>) {
        let mut waiting = self.waiting.lock();
        let now = Instant::now();
        if waiting.len() > 10_000 {
            waiting.retain(|_, (_, at)| now.duration_since(*at) < Duration::from_secs(CHALLENGE_SECONDS));
        }
        waiting.insert(key, (challenge, now));
    }

    /// The challenge for `key`, once: whatever the answer, it is gone afterwards.
    pub fn take(&self, key: &str) -> Option<Vec<u8>> {
        let (challenge, at) = self.waiting.lock().remove(key)?;
        (at.elapsed() < Duration::from_secs(CHALLENGE_SECONDS)).then_some(challenge)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    /// A security key in software: one P-256 key, a counter, and the flags it sets.
    pub(crate) struct SoftKey {
        pub key: EcdsaKeyPair,
        pub id: Vec<u8>,
        pub counter: u32,
        pub verified: bool,
    }

    impl SoftKey {
        pub(crate) fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            SoftKey { key, id: crate::crypto::random_bytes(16), counter: 0, verified: true }
        }

        fn cose(&self) -> Vec<u8> {
            let point = self.key.public_key().as_ref();
            let map = Cbor::Map(vec![
                (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
                (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
                (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
                (Cbor::Integer((-2).into()), Cbor::Bytes(point[1..33].to_vec())),
                (Cbor::Integer((-3).into()), Cbor::Bytes(point[33..65].to_vec())),
            ]);
            let mut out = Vec::new();
            ciborium::into_writer(&map, &mut out).unwrap();
            out
        }

        fn auth_data(&self, rp: &str, attested: bool) -> Vec<u8> {
            let mut data = ring::digest::digest(&ring::digest::SHA256, rp.as_bytes()).as_ref().to_vec();
            let mut flags = USER_PRESENT;
            if self.verified {
                flags |= USER_VERIFIED;
            }
            if attested {
                flags |= ATTESTED;
            }
            data.push(flags);
            data.extend_from_slice(&self.counter.to_be_bytes());
            if attested {
                data.extend_from_slice(&[0; 16]);
                data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.id);
                data.extend_from_slice(&self.cose());
            }
            data
        }

        fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
            json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })
                .to_string()
                .into_bytes()
        }

        /// The answer to creation options, as JSON the way the clients send it.
        pub(crate) fn create(&self, options: &Value, origin: &str) -> Value {
            let rp = options["rp"]["id"].as_str().unwrap();
            let object = Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(self.auth_data(rp, true))),
            ]);
            let mut attestation = Vec::new();
            ciborium::into_writer(&object, &mut attestation).unwrap();
            json!({
                "id": b64(&self.id),
                "rawId": b64(&self.id),
                "type": "public-key",
                "extensions": {},
                "response": {
                    "attestationObject": b64(&attestation),
                    "clientDataJson": b64(&Self::client_data("webauthn.create", options["challenge"].as_str().unwrap(), origin)),
                },
            })
        }

        /// The answer to request options.
        pub(crate) fn get(&mut self, options: &Value, origin: &str, user_handle: Option<&str>) -> Value {
            self.counter += 1;
            let rp = options["rpId"].as_str().unwrap();
            let auth_data = self.auth_data(rp, false);
            let client_data = Self::client_data("webauthn.get", options["challenge"].as_str().unwrap(), origin);
            let mut message = auth_data.clone();
            message.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client_data).as_ref());
            let signature = self.key.sign(&SystemRandom::new(), &message).unwrap();
            json!({
                "id": b64(&self.id),
                "rawId": b64(&self.id),
                "type": "public-key",
                "extensions": {},
                "response": {
                    "authenticatorData": b64(&auth_data),
                    "clientDataJson": b64(&client_data),
                    "signature": b64(signature.as_ref()),
                    "userHandle": user_handle,
                },
            })
        }
    }

    fn party() -> Party {
        Party::from_public("https://auth.example.com")
    }

    #[test]
    fn a_handle_is_the_person_s_id() {
        let id = "5f7c2a1e-0000-4000-8000-000000000000";
        assert_eq!(user_handle(id).len(), 16);
        assert_eq!(person_of_handle(&user_handle(id)).as_deref(), Some(id));
        assert!(person_of_handle(b"short").is_none());
    }

    #[test]
    fn the_party_comes_from_the_public_address() {
        let party = Party::from_public("https://auth.example.com:8443/");
        assert_eq!((party.id.as_str(), party.origin.as_str()), ("auth.example.com", "https://auth.example.com:8443"));
        assert_eq!(Party::from_public("http://localhost").id, "localhost");
    }

    #[test]
    fn a_key_registers_and_signs_in() {
        let mut key = SoftKey::new();
        let challenge = challenge();
        let options =
            creation_options(&party(), "5f7c2a1e-0000-4000-8000-000000000000", "nyu", "Nyu", &challenge, &[], false);
        let answer: Attestation = serde_json::from_value(key.create(&options, "https://auth.example.com")).unwrap();
        let registered = register(&answer, &challenge, &party(), false).unwrap();
        assert_eq!(registered.credential_id, key.id);

        let challenge = super::challenge();
        let options = request_options(&party(), &challenge, &[key.id.clone()]);
        let answer: Assertion = serde_json::from_value(key.get(&options, "https://auth.example.com", None)).unwrap();
        assert_eq!(assert(&answer, &challenge, &party(), &registered.public_key, 0, false), Ok(1));
        assert!(assert(&answer, &challenge, &party(), &registered.public_key, 1, false).is_err(), "the counter");
        assert!(
            assert(&answer, &super::challenge(), &party(), &registered.public_key, 0, false).is_err(),
            "the challenge"
        );
        let other = SoftKey::new();
        let answer_again: Assertion =
            serde_json::from_value(key.get(&options, "https://auth.example.com", None)).unwrap();
        let other_key = register(
            &serde_json::from_value(other.create(
                &creation_options(&party(), "u", "e", "E", &challenge, &[], false),
                "https://auth.example.com",
            ))
            .unwrap(),
            &challenge,
            &party(),
            false,
        )
        .unwrap();
        assert!(assert(&answer_again, &challenge, &party(), &other_key.public_key, 0, false).is_err(), "another key");
    }

    #[test]
    fn another_origin_or_server_is_refused() {
        let key = SoftKey::new();
        let challenge = challenge();
        let options = creation_options(&party(), "u", "nyu", "Nyu", &challenge, &[], false);
        let phished: Attestation = serde_json::from_value(key.create(&options, "https://auth.example.net")).unwrap();
        assert!(register(&phished, &challenge, &party(), false).is_err());
        let mut elsewhere = options.clone();
        elsewhere["rp"]["id"] = json!("example.net");
        let answer: Attestation = serde_json::from_value(key.create(&elsewhere, "https://auth.example.com")).unwrap();
        assert!(register(&answer, &challenge, &party(), false).is_err());
    }

    #[test]
    fn a_passkey_has_to_verify_who_is_there() {
        let mut key = SoftKey::new();
        key.verified = false;
        let challenge = challenge();
        let options = creation_options(&party(), "u", "nyu", "Nyu", &challenge, &[], true);
        let answer: Attestation = serde_json::from_value(key.create(&options, "https://auth.example.com")).unwrap();
        assert!(register(&answer, &challenge, &party(), true).is_err());
        assert!(register(&answer, &challenge, &party(), false).is_ok());
    }

    #[test]
    fn a_challenge_is_taken_once() {
        let challenges = Challenges::default();
        challenges.put("a".into(), vec![1]);
        assert_eq!(challenges.take("a"), Some(vec![1]));
        assert_eq!(challenges.take("a"), None);
    }
}
