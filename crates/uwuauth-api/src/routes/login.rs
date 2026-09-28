//! Signing in and out.
//!
//! - **With a passkey**: one step. The browser picks the passkey; it verifies who is there, so it
//!   counts as two factors.
//! - **With a password**: then, for somebody with an authenticator app or a passkey, a second
//!   step with either (or a recovery code). Somebody in a group that asks for a second factor
//!   and who has none gets a restricted session that only reaches their security settings.
//! - **Confirming again**: before changing how one signs in, with the password or a passkey.
//! - **Forgot password**: a link by mail, for accounts with an address that nobody else looks
//!   after (a kid asks a parent instead).
//!
//! Every attempt goes to the event log. A name that does not exist takes as long as one that
//! does, and gets the same answer.

use super::{check_assertion, methods_json};
use crate::crypto::{random_token, secret_hash, sha256, verify_password};
use crate::errors::{ApiError, ApiResult};
use crate::memory::PendingLogin;
use crate::session::{ClientIp, MeSetup, SESSION_COOKIE, SignIn, set_cookie, start, with_cookies};
use crate::{AppState, audit, policy, totp, webauthn};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use uwuauth_mail::{Language, Mail};
use uwuauth_store::{Person, Purpose, clock};

/// How long a link to set a new password works.
pub const RESET_MINUTES: i64 = 60;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/login", post(login))
        .route("/uwu/v1/login/second", post(second))
        .route("/uwu/v1/login/second/options", post(second_options))
        .route("/uwu/v1/login/passkey/options", post(passkey_options))
        .route("/uwu/v1/login/passkey", post(passkey))
        .route("/uwu/v1/logout", post(logout))
        .route("/uwu/v1/reauth", post(reauth))
        .route("/uwu/v1/reauth/options", post(reauth_options))
        .route("/uwu/v1/forgot", post(forgot))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    login: String,
    password: String,
    #[serde(default)]
    remember: bool,
}

fn wrong() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "wrong", "The name or the password is wrong.")
}

fn refused(reason: &'static str) -> ApiError {
    let message = match reason {
        "locked" => "Too many wrong passwords. Wait a quarter of an hour.",
        "expired" => "This account has run out.",
        _ => "This account is disabled.",
    };
    ApiError::new(StatusCode::FORBIDDEN, reason, message)
}

/// Whether `person` has anything for a second step: an authenticator app or a passkey.
async fn second_factors(state: &AppState, person: &Person) -> ApiResult<Vec<&'static str>> {
    let mut methods = Vec::new();
    if person.totp_secret.is_some() {
        methods.push("totp");
    }
    if !state.store.passkeys(&person.id).await?.is_empty() {
        methods.push("passkey");
    }
    if !methods.is_empty() && state.store.recovery_codes_left(&person.id).await? > 0 {
        methods.push("recovery");
    }
    Ok(methods)
}

async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> ApiResult<Response> {
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many());
    }
    let name: String = login.login.trim().chars().take(254).collect();
    let person = state.store.person_by_login(&name).await?;
    if let Some(person) = &person
        && let Some(reason) = policy::refusal(&state, person).await?
    {
        audit(&state, "login_refused", None, Some(&person.id), None, &ip, json!({ "reason": reason })).await;
        return Err(refused(reason));
    }
    let hash = person.as_ref().and_then(|person| person.password_hash.as_deref());
    let right = verify_password(state.config.hash_cost, hash, &login.password).await;
    let Some(person) = person.filter(|_| right) else {
        if let Some(person) = state.store.person_by_login(&name).await? {
            state.limits.account.take(person.id.clone());
            audit(&state, "login_failed", None, Some(&person.id), None, &ip, json!({ "method": "pwd" })).await;
        } else {
            audit(&state, "login_failed", None, None, None, &ip, json!({ "login": name })).await;
        }
        return Err(wrong());
    };
    if !state.limits.account.allows(&person.id) {
        return Err(ApiError::too_many());
    }
    let factors = second_factors(&state, &person).await?;
    if factors.is_empty() {
        return finish(&state, &person, &[SignIn::Password], login.remember, ip, &headers).await;
    }
    let token = random_token(24);
    state
        .memory
        .pending
        .put(token.clone(), PendingLogin { person_id: person.id.clone(), remember: login.remember, tries: 0 });
    Ok(Json(json!({ "status": "second_factor", "pending": token, "methods": factors })).into_response())
}

/// A session for `person`, who proved who they are with `methods`: the answer with its cookies.
pub(crate) async fn finish(
    state: &AppState,
    person: &Person,
    methods: &[SignIn],
    remember: bool,
    ip: IpAddr,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let second = methods.iter().any(|method| *method != SignIn::Password);
    let restricted = !second && {
        let membership = state.store.membership().await?;
        let groups = state.store.groups().await?;
        policy::needs_mfa(&groups, &membership.groups_of(&person.id))
    };
    let started = start(state, person, methods, remember, restricted, ip, headers).await?;
    state.store.touch_login(&person.id).await?;
    audit(state, "login", Some(&person.id), Some(&person.id), None, &ip, json!({ "methods": methods_json(methods) }))
        .await;
    new_device(state, person, &started.device_id, ip, headers).await;
    let cookies = started.cookies;
    let body = json!({ "status": "signed_in", "restricted": restricted });
    Ok(with_cookies(Json(body).into_response(), cookies))
}

/// Tell `person` about a device they never signed in on — unless it is their first sign-in
/// anywhere, or the admin turned it off.
async fn new_device(state: &AppState, person: &Person, device: &str, ip: IpAddr, headers: &HeaderMap) {
    let agent = crate::session::user_agent(headers);
    let had_any = state.store.has_devices(&person.id).await.unwrap_or(true);
    let new = state.store.saw_device(&person.id, device, agent.as_deref()).await.unwrap_or(false);
    if new && had_any {
        mail_new_device(state, person, ip, agent).await;
    }
}

async fn mail_new_device(state: &AppState, person: &Person, ip: IpAddr, agent: Option<String>) {
    let settings = state.settings();
    let Some(to) = person.email.clone().filter(|_| settings.new_device_mail && state.mailer.enabled()) else {
        return;
    };
    let now = jiff::Timestamp::now().to_zoned(settings.tz()).strftime("%Y-%m-%d %H:%M").to_string();
    let mail = Mail::NewDevice { device: describe(agent.as_deref()), ip: ip.to_string(), time: now };
    let mailer = state.mailer.clone();
    let language = Language::from_code(&person.language);
    tokio::spawn(async move {
        if let Err(error) = mailer.send(&to, &mail, language).await {
            tracing::warn!(%error, "the note about a new device did not go out");
        }
    });
}

/// "Firefox on Linux", from a user agent, as well as a guess goes.
pub fn describe(agent: Option<&str>) -> String {
    let agent = agent.unwrap_or_default();
    let browser = [("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")]
        .into_iter()
        .find(|(needle, _)| agent.contains(needle))
        .map_or("a browser", |(_, name)| name);
    let system = [
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iPadOS"),
        ("Windows", "Windows"),
        ("Mac OS", "macOS"),
        ("Linux", "Linux"),
    ]
    .into_iter()
    .find(|(needle, _)| agent.contains(needle))
    .map_or("a device", |(_, name)| name);
    format!("{browser} / {system}")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Second {
    pending: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery: Option<String>,
    #[serde(default)]
    passkey: Option<webauthn::Assertion>,
}

async fn second(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(second): Json<Second>,
) -> ApiResult<Response> {
    let gone = || ApiError::new(StatusCode::UNAUTHORIZED, "expired", "Start again: the sign-in ran out.");
    let mut pending = state.memory.pending.take(&second.pending).ok_or_else(gone)?;
    if !state.limits.second_factor.take(pending.person_id.clone()) {
        return Err(ApiError::too_many());
    }
    let person = state.store.person(&pending.person_id).await?.ok_or_else(gone)?;
    if let Some(reason) = policy::refusal(&state, &person).await? {
        return Err(refused(reason));
    }
    let method = if let Some(code) = &second.code {
        check_totp(&state, &person, code).await?.then_some(SignIn::Totp)
    } else if let Some(recovery) = &second.recovery {
        state.store.take_recovery_code(&person.id, secret_hash(recovery)).await?.then_some(SignIn::Recovery)
    } else if let Some(assertion) = &second.passkey {
        check_assertion(&state, &format!("second:{}", second.pending), assertion, Some(&person.id))
            .await
            .ok()
            .map(|_| SignIn::Passkey)
    } else {
        None
    };
    let Some(method) = method else {
        audit(&state, "login_failed", None, Some(&person.id), None, &ip, json!({ "method": "second" })).await;
        pending.tries += 1;
        if pending.tries < 5 {
            state.memory.pending.put(second.pending, pending);
        }
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong_code", "That did not work. Try again."));
    };
    if method == SignIn::Recovery {
        audit(&state, "recovery_code_used", Some(&person.id), Some(&person.id), None, &ip, json!({})).await;
    }
    finish(&state, &person, &[SignIn::Password, method], pending.remember, ip, &headers).await
}

/// Whether `code` is the authenticator app's code for now, not used before.
pub(crate) async fn check_totp(state: &AppState, person: &Person, code: &str) -> ApiResult<bool> {
    let Some(secret) = person.totp_secret.as_deref().and_then(|sealed| state.sealer.open(sealed)) else {
        return Ok(false);
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let Some(step) = totp::matching_step(&secret, code, now) else { return Ok(false) };
    Ok(state.store.take_totp_step(&person.id, step).await?)
}

#[derive(Deserialize)]
struct PendingOnly {
    pending: String,
}

/// Options for a passkey as the second step: one of the person's passkeys.
async fn second_options(State(state): State<AppState>, Json(body): Json<PendingOnly>) -> ApiResult<Json<Value>> {
    let pending = state
        .memory
        .pending
        .peek(&body.pending)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "expired", "Start again: the sign-in ran out."))?;
    let passkeys = state.store.passkeys(&pending.person_id).await?;
    let challenge = webauthn::challenge();
    state.memory.challenges.put(format!("second:{}", body.pending), challenge.clone());
    let allow: Vec<Vec<u8>> = passkeys.into_iter().map(|passkey| passkey.credential_id).collect();
    Ok(Json(webauthn::request_options(&state.party, &challenge, &allow)))
}

/// Options for signing in with a passkey the browser picks.
async fn passkey_options(State(state): State<AppState>, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many());
    }
    let id = random_token(16);
    let challenge = webauthn::challenge();
    state.memory.challenges.put(format!("login:{id}"), challenge.clone());
    Ok(Json(json!({ "id": id, "options": webauthn::request_options(&state.party, &challenge, &[]) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyLogin {
    id: String,
    credential: webauthn::Assertion,
    #[serde(default)]
    remember: bool,
}

async fn passkey(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<PasskeyLogin>,
) -> ApiResult<Response> {
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many());
    }
    let passkey = match check_assertion(&state, &format!("login:{}", body.id), &body.credential, None).await {
        Ok(passkey) => passkey,
        Err(error) => {
            audit(&state, "login_failed", None, None, None, &ip, json!({ "method": "hwk" })).await;
            return Err(error);
        }
    };
    let person = state.store.person(&passkey.person_id).await?.ok_or_else(ApiError::unauthorized)?;
    if let Some(reason) = policy::refusal(&state, &person).await? {
        audit(&state, "login_refused", None, Some(&person.id), None, &ip, json!({ "reason": reason })).await;
        return Err(refused(reason));
    }
    finish(&state, &person, &[SignIn::Passkey], body.remember, ip, &headers).await
}

async fn logout(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap) -> ApiResult<Response> {
    // The apps that signed in with this session hear about it (back-channel logout).
    crate::oidc::logout::end_from_headers(&state, &headers, ip).await?;
    let clear = set_cookie(&state, SESSION_COOKIE, "", Some(0));
    Ok(with_cookies(StatusCode::NO_CONTENT.into_response(), vec![clear]))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reauth {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    passkey: Option<webauthn::Assertion>,
}

/// Options for confirming with a passkey: one of the person's own.
async fn reauth_options(State(state): State<AppState>, MeSetup(me): MeSetup) -> ApiResult<Json<Value>> {
    let passkeys = state.store.passkeys(&me.person.id).await?;
    let challenge = webauthn::challenge();
    state.memory.challenges.put(format!("reauth:{}", me.person.id), challenge.clone());
    let allow: Vec<Vec<u8>> = passkeys.into_iter().map(|passkey| passkey.credential_id).collect();
    Ok(Json(webauthn::request_options(&state.party, &challenge, &allow)))
}

/// Prove again who one is: with the password (and the app's code, for somebody who has the app
/// and no passkey), or with a passkey.
async fn reauth(
    State(state): State<AppState>,
    MeSetup(me): MeSetup,
    ClientIp(ip): ClientIp,
    Json(body): Json<Reauth>,
) -> ApiResult<StatusCode> {
    if !state.limits.second_factor.take(me.person.id.clone()) {
        return Err(ApiError::too_many());
    }
    let person = &me.person;
    let methods: Vec<SignIn> = if let Some(assertion) = &body.passkey {
        check_assertion(&state, &format!("reauth:{}", person.id), assertion, Some(&person.id)).await?;
        vec![SignIn::Passkey]
    } else if let Some(password) = &body.password {
        if !verify_password(state.config.hash_cost, person.password_hash.as_deref(), password).await {
            audit(&state, "reauth_failed", Some(&person.id), Some(&person.id), None, &ip, json!({})).await;
            return Err(wrong());
        }
        if person.totp_secret.is_some() {
            let code = body.code.as_deref().unwrap_or_default();
            if !check_totp(&state, person, code).await? {
                return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong_code", "The code is wrong."));
            }
            vec![SignIn::Password, SignIn::Totp]
        } else {
            vec![SignIn::Password]
        }
    } else {
        return Err(ApiError::bad("missing", "A password or a passkey is needed."));
    };
    let mut amr: Vec<&str> = methods.iter().map(|method| method.amr()).collect();
    if methods.len() > 1 || methods.contains(&SignIn::Passkey) {
        amr.push("mfa");
    }
    // Confirming does not lift a restriction: only setting up a second factor does.
    state.store.reauthenticated(&me.session.id, &json!(amr).to_string()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Forgot {
    login: String,
}

/// A link to set a new password, by mail. The answer is the same whether there was anybody to
/// send it to or not.
async fn forgot(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(body): Json<Forgot>,
) -> ApiResult<StatusCode> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many());
    }
    let person = state.store.person_by_login(&body.login).await?;
    let Some(person) = person.filter(|person| person.active() && !person.managed) else {
        return Ok(StatusCode::ACCEPTED);
    };
    let Some(to) = person.email.clone() else { return Ok(StatusCode::ACCEPTED) };
    if !state.limits.mail.take(to.to_lowercase()) || !state.mailer.enabled() {
        return Ok(StatusCode::ACCEPTED);
    }
    let token = random_token(32);
    state
        .store
        .create_link(
            sha256(token.as_bytes()),
            Purpose::Reset,
            Some(&person.id),
            "{}",
            None,
            &clock::in_seconds(RESET_MINUTES * 60),
        )
        .await?;
    let mail = Mail::PasswordReset { link: state.link(&format!("/reset?token={token}")), minutes: RESET_MINUTES };
    if let Err(error) = state.mailer.send(&to, &mail, Language::from_code(&person.language)).await {
        tracing::warn!(%error, "the mail with a new password link did not go out");
    }
    audit(&state, "reset_requested", None, Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    #[test]
    fn devices_are_described_plainly() {
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0";
        assert_eq!(super::describe(Some(firefox)), "Firefox / Linux");
        assert_eq!(super::describe(None), "a browser / a device");
    }
}
