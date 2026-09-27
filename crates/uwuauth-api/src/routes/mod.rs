//! UwUAuth's own API under `/uwu/v1`.
//!
//! - `login` — signing in and out, a second step, confirming again, "forgot password".
//! - `links` — what the links in invitations and mails lead to.
//! - `me` — the self-service portal: one's own profile and how one signs in.
//! - `people`, `groups`, `invitations` — managing the directory, for admins and (for the people
//!   they look after) managers and (for their groups) group owners.
//! - `admin` — the rest of the admin portal: overview, events, log, backups, attributes, import
//!   and export.

pub mod admin;
pub mod apps;
pub mod groups;
pub mod invitations;
pub mod ldap;
pub mod links;
pub mod login;
pub mod me;
pub mod people;

use crate::errors::{ApiError, ApiResult};
use crate::session::SignIn;
use crate::{AppState, crypto, webauthn};
use axum::Router;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uwuauth_store::{Passkey, Person, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .merge(login::routes())
        .merge(links::routes())
        .merge(me::routes())
        .merge(people::routes())
        .merge(groups::routes())
        .merge(invitations::routes())
        .merge(admin::routes())
        .merge(apps::routes())
        .merge(ldap::routes())
        .merge(crate::tokens::routes())
}

/// A person as the portals show them. `groups` are the ids of the groups they are directly in.
pub fn person_view(
    state: &AppState,
    person: &Person,
    groups: &BTreeSet<String>,
    admin: bool,
    has_avatar: bool,
) -> Value {
    json!({
        "id": person.id,
        "username": person.username,
        "displayName": person.display_name,
        "givenName": person.given_name,
        "familyName": person.family_name,
        "email": person.email,
        "emailVerified": person.email_verified,
        "language": person.language,
        "disabled": person.disabled,
        "managed": person.managed,
        "hasPassword": person.password_hash.is_some(),
        "hasTotp": person.totp_secret.is_some(),
        "expires": person.expires,
        "uidNumber": person.uid_number,
        "loginShell": person.login_shell,
        "homeDirectory": person.home_directory,
        "created": person.created,
        "updated": person.updated,
        "lastLogin": person.last_login,
        "deleted": person.deleted,
        "admin": admin,
        "groups": groups,
        "avatar": has_avatar.then(|| avatar_url(state, person)),
    })
}

/// Where a person's picture is, with the time it changed so a browser fetches a new one.
pub fn avatar_url(state: &AppState, person: &Person) -> String {
    format!("{}/uwu/v1/avatars/{}?v={}", state.config.public, person.id, person.updated.replace([':', '.'], ""))
}

pub fn passkey_view(passkey: &Passkey) -> Value {
    json!({ "id": passkey.id, "name": passkey.name, "created": passkey.created, "lastUsed": passkey.last_used })
}

/// A new password or a new passkey: what the links and "add a passkey" take.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewPasskey {
    pub credential: webauthn::Attestation,
    #[serde(default)]
    pub name: Option<String>,
}

/// Start registering a passkey for `person_id`: the options for the browser, with the challenge
/// kept under `key`.
pub fn passkey_options(
    state: &AppState,
    key: &str,
    person_id: &str,
    username: &str,
    display: &str,
    exclude: &[Passkey],
) -> Value {
    let challenge = webauthn::challenge();
    state.memory.challenges.put(key.to_string(), challenge.clone());
    let exclude: Vec<Vec<u8>> = exclude.iter().map(|passkey| passkey.credential_id.clone()).collect();
    webauthn::creation_options(&state.party, person_id, username, display, &challenge, &exclude, true)
}

/// Check a new passkey against the challenge under `key` and keep it for `person_id`.
pub async fn register_passkey(state: &AppState, key: &str, person_id: &str, new: &NewPasskey) -> ApiResult<Passkey> {
    let challenge = state
        .memory
        .challenges
        .take(key)
        .ok_or_else(|| ApiError::bad("challenge", "Start again: the request ran out."))?;
    let registered = webauthn::register(&new.credential, &challenge, &state.party, true)
        .map_err(|message| ApiError::bad("passkey", message))?;
    let passkey = Passkey {
        id: uuid::Uuid::new_v4().to_string(),
        person_id: person_id.to_string(),
        credential_id: registered.credential_id,
        public_key: registered.public_key,
        counter: registered.counter,
        name: crate::policy::optional(new.name.as_deref(), 60).unwrap_or_else(|| "Passkey".into()),
        created: clock::now(),
        last_used: None,
    };
    if !state.store.add_passkey(passkey.clone()).await? {
        return Err(ApiError::bad("too_many", "That is as many passkeys as an account can have."));
    }
    Ok(passkey)
}

/// Check a passkey assertion against the challenge under `key`: the passkey and its person, with
/// the counter moved on.
pub async fn check_assertion(
    state: &AppState,
    key: &str,
    assertion: &webauthn::Assertion,
    person: Option<&str>,
) -> ApiResult<Passkey> {
    let wrong = || ApiError::bad("passkey", "That passkey did not work.");
    let challenge = state
        .memory
        .challenges
        .take(key)
        .ok_or_else(|| ApiError::bad("challenge", "Start again: the request ran out."))?;
    let credential = assertion.credential_id().ok_or_else(wrong)?;
    let passkey = state.store.passkey_by_credential(&credential).await?.ok_or_else(wrong)?;
    if person.is_some_and(|person| person != passkey.person_id) {
        return Err(wrong());
    }
    // A passkey found by the browser says whose it is; it has to be the one it belongs to.
    if let Some(handle) = assertion.response.user_handle.as_deref().filter(|handle| !handle.is_empty())
        && crypto::unb64(handle).and_then(|bytes| webauthn::person_of_handle(&bytes)).as_deref()
            != Some(passkey.person_id.as_str())
    {
        return Err(wrong());
    }
    let counter = webauthn::assert(assertion, &challenge, &state.party, &passkey.public_key, passkey.counter, true)
        .map_err(|message| ApiError::bad("passkey", message))?;
    state.store.used_passkey(&passkey.id, counter).await?;
    Ok(passkey)
}

/// Set a password for `person`: checked against the rules, hashed, and a new security stamp, so
/// every session but the one that did it ends. The new hash is returned.
pub async fn new_password(state: &AppState, person: &Person, password: &str) -> ApiResult<String> {
    crate::policy::password(state, password, Some((&person.username, person.email.as_deref()))).await?;
    crypto::hash_password(state.config.hash_cost, password).await.map_err(ApiError::internal)
}

/// The methods a sign-in used, for events.
pub fn methods_json(methods: &[SignIn]) -> Value {
    json!(methods.iter().map(|method| method.amr()).collect::<Vec<_>>())
}
