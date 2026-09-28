//! The self-service portal: one's own profile, and every way one signs in.
//!
//! Changing how one signs in — password, passkeys, the authenticator app, recovery codes, app
//! passwords, the address — needs a recent proof of who one is ([`Me::require_fresh`]); the web
//! app asks for it when the server says `reauth`. A restricted session (a group asks for a second
//! factor the person does not have yet) reaches exactly what it takes to set one up.

use super::{NewPasskey, new_password, passkey_options, passkey_view, person_view, register_passkey};
use crate::crypto::{random_token, readable_secret, secret_hash, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::session::{ClientIp, Me, MeSetup};
use crate::{AppState, audit, policy, totp};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use uwuauth_mail::{Language, Mail};
use uwuauth_store::{EventFilter, Person, Purpose, clock, people};

/// Recovery codes per set.
pub const RECOVERY_CODES: usize = 10;
/// The largest picture the browser may send: it makes them 256 pixels square.
pub const AVATAR_MAX: usize = 256 * 1024;
/// How long a link to confirm an address works.
pub const VERIFY_MINUTES: i64 = 60;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/me", get(show).patch(change))
        .route("/uwu/v1/me/avatar", put(set_avatar).delete(remove_avatar))
        .route("/uwu/v1/avatars/{id}", get(avatar))
        .route("/uwu/v1/me/email", post(change_email))
        .route("/uwu/v1/me/password", post(set_password).delete(remove_password))
        .route("/uwu/v1/me/passkeys/options", post(new_passkey_options))
        .route("/uwu/v1/me/passkeys", post(add_passkey))
        .route("/uwu/v1/me/passkeys/{id}", delete(remove_passkey).patch(rename_passkey))
        .route("/uwu/v1/me/totp/start", post(totp_start))
        .route("/uwu/v1/me/totp", post(totp_confirm).delete(totp_remove))
        .route("/uwu/v1/me/recovery", post(recovery))
        .route("/uwu/v1/me/app-passwords", post(add_app_password))
        .route("/uwu/v1/me/app-passwords/{id}", delete(remove_app_password))
        .route("/uwu/v1/me/sessions", get(sessions))
        .route("/uwu/v1/me/sessions/{id}", delete(end_session))
        .route("/uwu/v1/me/sessions/end-others", post(end_others))
        .route("/uwu/v1/me/events", get(events))
}

async fn show(State(state): State<AppState>, MeSetup(me): MeSetup) -> ApiResult<Json<Value>> {
    let person = &me.person;
    let membership = state.store.membership().await?;
    let all_groups = state.store.groups().await?;
    let of_person = membership.groups_of(&person.id);
    let direct = membership.direct_groups_of(&person.id);
    let has_avatar = state.store.avatar(&person.id).await?.is_some();
    let mut body = person_view(&state, person, &direct, me.admin, has_avatar);
    let passkeys = state.store.passkeys(&person.id).await?;
    let app_passwords = state.store.app_passwords(&person.id).await?;
    let defs = state.store.attribute_defs().await?;
    let values = state.store.attributes_of(&person.id).await?;
    let settings = state.settings();
    body["passkeys"] = json!(passkeys.iter().map(passkey_view).collect::<Vec<_>>());
    body["recoveryCodesLeft"] = json!(state.store.recovery_codes_left(&person.id).await?);
    body["appPasswords"] = json!(app_passwords
        .iter()
        .map(|app| json!({ "id": app.id, "name": app.name, "created": app.created, "lastUsed": app.last_used, "lastIp": app.last_ip }))
        .collect::<Vec<_>>());
    body["memberOf"] = json!(all_groups
        .iter()
        .filter(|group| of_person.contains(&group.id))
        .map(|group| json!({ "id": group.id, "name": group.name, "builtin": group.builtin, "direct": direct.contains(&group.id) }))
        .collect::<Vec<_>>());
    body["attributes"] = json!(defs
        .iter()
        .map(|def| json!({ "name": def.name, "label": def.label, "kind": def.kind, "choices": serde_json::from_str::<Value>(&def.choices).unwrap_or_default(), "selfEditable": def.self_editable, "value": values.get(&def.name) }))
        .collect::<Vec<_>>());
    body["needsMfa"] = json!(policy::needs_mfa(&all_groups, &of_person));
    body["restricted"] = json!(me.session.restricted);
    body["fresh"] = json!(me.fresh());
    body["manager"] = json!(state.store.managers().await?.contains(&person.id));
    body["ownsGroups"] = json!(
        membership
            .owners
            .iter()
            .filter(|(_, owners)| owners.contains(&person.id))
            .map(|(group, _)| group.clone())
            .collect::<Vec<_>>()
    );
    body["server"] = json!({
        "organization": settings.organization,
        "mode": settings.mode,
        "setupDone": settings.setup_done,
        "mail": state.mailer.enabled(),
        "passwordMinLength": settings.password_min_length,
        "version": state.version,
    });
    Ok(Json(body))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Profile {
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    language: Option<String>,
    attributes: BTreeMap<String, String>,
}

async fn change(State(state): State<AppState>, me: Me, Json(profile): Json<Profile>) -> ApiResult<Json<Value>> {
    let display = profile.display_name.as_deref().map(policy::display_name).transpose()?;
    let defs = state.store.attribute_defs().await?;
    let mut attributes = BTreeMap::new();
    for (name, value) in profile.attributes {
        let def = defs
            .iter()
            .find(|def| def.name == name && def.self_editable)
            .ok_or_else(|| ApiError::field(&name, "not_editable", "This attribute is not yours to change."))?;
        attributes.insert(name, super::people::check_attribute(def, &value)?);
    }
    let person = state
        .store
        .update_person(&me.person.id, move |person| {
            if let Some(display) = display {
                person.display_name = display;
            }
            if let Some(given) = profile.given_name {
                person.given_name = policy::optional(Some(&given), 100);
            }
            if let Some(family) = profile.family_name {
                person.family_name = policy::optional(Some(&family), 100);
            }
            if let Some(language) = profile.language {
                person.language = policy::language(&language);
            }
        })
        .await?;
    state.store.set_attributes(&person.id, attributes).await?;
    Ok(Json(json!({ "displayName": person.display_name, "language": person.language })))
}

/// A picture: a JPEG the browser made small.
pub(crate) fn check_jpeg(bytes: &[u8]) -> ApiResult<()> {
    if bytes.len() > AVATAR_MAX {
        return Err(ApiError::bad("too_large", "The picture is too large."));
    }
    if !bytes.starts_with(&[0xFF, 0xD8, 0xFF]) || !bytes.ends_with(&[0xFF, 0xD9]) {
        return Err(ApiError::bad("not_jpeg", "The picture has to be a JPEG."));
    }
    Ok(())
}

async fn set_avatar(State(state): State<AppState>, me: Me, body: Bytes) -> ApiResult<StatusCode> {
    check_jpeg(&body)?;
    state.store.set_avatar(&me.person.id, Some(body.to_vec())).await?;
    state.store.update_person(&me.person.id, |_| {}).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_avatar(State(state): State<AppState>, me: Me) -> ApiResult<StatusCode> {
    state.store.set_avatar(&me.person.id, None).await?;
    state.store.update_person(&me.person.id, |_| {}).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A person's picture, for the portals and for apps (OpenID Connect's `picture`). Found by the
/// person's id, which nobody guesses.
async fn avatar(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let (jpeg, updated) = state.store.avatar(&id).await?.ok_or_else(ApiError::not_found)?;
    let mut response = jpeg.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'"));
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", updated.replace(['"', ':', '.'], ""))) {
        headers.insert(header::ETAG, value);
    }
    Ok(response)
}

#[derive(Deserialize)]
struct NewEmail {
    email: String,
}

/// A new address: a link goes there, and the address counts once it is opened.
async fn change_email(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewEmail>,
) -> ApiResult<Json<Value>> {
    me.require_fresh()?;
    let email = policy::email(&body.email)?;
    if let Some(other) = state.store.person_by_login(&email).await?
        && other.id != me.person.id
    {
        return Err(ApiError::field("email", "exists", "That address has an account already."));
    }
    if !state.mailer.enabled() {
        return Err(ApiError::bad("no_mail", "This server cannot send mail. Ask an admin to change your address."));
    }
    if !state.limits.mail.take(email.to_lowercase()) {
        return Err(ApiError::too_many());
    }
    let token = random_token(32);
    let data = json!({ "email": email }).to_string();
    state
        .store
        .create_link(
            sha256(token.as_bytes()),
            Purpose::Verify,
            Some(&me.person.id),
            &data,
            Some(&me.person.id),
            &clock::in_seconds(VERIFY_MINUTES * 60),
        )
        .await?;
    let mail = Mail::EmailVerify { link: state.link(&format!("/verify?token={token}")), minutes: VERIFY_MINUTES };
    state
        .mailer
        .send(&email, &mail, Language::from_code(&me.person.language))
        .await
        .map_err(|error| ApiError::bad("mail_failed", error.to_string()))?;
    audit(
        &state,
        "email_change_requested",
        Some(&me.person.id),
        Some(&me.person.id),
        None,
        &ip,
        json!({ "email": email }),
    )
    .await;
    Ok(Json(json!({ "sent": email })))
}

/// Tell `person` that how they sign in changed, when there is an address and mail.
pub(crate) fn notify(state: &AppState, person: &Person, mail: Mail) {
    let Some(to) = person.email.clone().filter(|_| state.mailer.enabled()) else { return };
    let mailer = state.mailer.clone();
    let language = Language::from_code(&person.language);
    tokio::spawn(async move {
        if let Err(error) = mailer.send(&to, &mail, language).await {
            tracing::warn!(%error, "a note about a change did not go out");
        }
    });
}

pub(crate) fn now_text(state: &AppState) -> String {
    jiff::Timestamp::now().to_zoned(state.settings().tz()).strftime("%Y-%m-%d %H:%M").to_string()
}

#[derive(Deserialize)]
struct NewPassword {
    password: String,
}

async fn set_password(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewPassword>,
) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    let hash = new_password(&state, &me.person, &body.password).await?;
    let stamp = people::stamp();
    let new_stamp = stamp.clone();
    let person = state
        .store
        .update_person(&me.person.id, move |person| {
            person.password_hash = Some(hash);
            person.password_changed = Some(clock::now());
            person.security_stamp = new_stamp;
        })
        .await?;
    // Every other browser signs in again; this one stays.
    state.store.restamp_session(&me.session.id, &stamp).await?;
    state.store.end_sessions(&person.id, Some(&me.session.id)).await?;
    audit(&state, "password_changed", Some(&person.id), Some(&person.id), None, &ip, json!({})).await;
    notify(&state, &person, Mail::PasswordChanged { time: now_text(&state) });
    Ok(StatusCode::NO_CONTENT)
}

/// Sign in with passkeys only: the password goes, if there is a passkey to sign in with.
async fn remove_password(State(state): State<AppState>, me: Me, ClientIp(ip): ClientIp) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    if state.store.passkeys(&me.person.id).await?.is_empty() {
        return Err(ApiError::bad("last_credential", "Add a passkey first: without a password you sign in with it."));
    }
    let person = state
        .store
        .update_person(&me.person.id, |person| {
            person.password_hash = None;
            person.password_changed = Some(clock::now());
        })
        .await?;
    audit(&state, "password_removed", Some(&person.id), Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn new_passkey_options(State(state): State<AppState>, MeSetup(me): MeSetup) -> ApiResult<Json<Value>> {
    me.require_fresh()?;
    let existing = state.store.passkeys(&me.person.id).await?;
    let key = format!("register:{}", me.person.id);
    Ok(Json(passkey_options(&state, &key, &me.person.id, &me.person.username, &me.person.display_name, &existing)))
}

async fn add_passkey(
    State(state): State<AppState>,
    MeSetup(me): MeSetup,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewPasskey>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    me.require_fresh()?;
    let passkey = register_passkey(&state, &format!("register:{}", me.person.id), &me.person.id, &body).await?;
    if me.session.restricted {
        state.store.unrestrict(&me.session.id).await?;
    }
    audit(
        &state,
        "passkey_added",
        Some(&me.person.id),
        Some(&me.person.id),
        Some(&passkey.id),
        &ip,
        json!({ "name": passkey.name }),
    )
    .await;
    notify(&state, &me.person, Mail::SignInChanged { what: added(&me.person, "passkey"), time: now_text(&state) });
    Ok((StatusCode::CREATED, Json(passkey_view(&passkey))))
}

/// What changed, in the reader's language.
fn added(person: &Person, what: &str) -> String {
    let de = person.language == "de";
    match (what, de) {
        ("passkey", true) => "Ein Passkey wurde hinzugefügt",
        ("passkey", false) => "A passkey was added",
        ("passkey-", true) => "Ein Passkey wurde entfernt",
        ("passkey-", false) => "A passkey was removed",
        ("totp", true) => "Die Authenticator-App wurde eingerichtet",
        ("totp", false) => "The authenticator app was set up",
        ("totp-", true) => "Die Authenticator-App wurde entfernt",
        ("totp-", false) => "The authenticator app was removed",
        (_, true) => "Neue Wiederherstellungscodes wurden erstellt",
        (_, false) => "New recovery codes were made",
    }
    .to_string()
}

#[derive(Deserialize)]
struct Rename {
    name: String,
}

async fn rename_passkey(
    State(state): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Json(body): Json<Rename>,
) -> ApiResult<StatusCode> {
    let name = policy::optional(Some(&body.name), 60)
        .ok_or_else(|| ApiError::field("name", "required", "A name is needed."))?;
    if !state.store.rename_passkey(&me.person.id, &id, &name).await? {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Whether taking away one of `person`'s ways to sign in leaves them one, and leaves them a
/// second factor if a group asks for one.
async fn can_lose(state: &AppState, person: &Person, passkey: Option<&str>, totp: bool) -> ApiResult<()> {
    let passkeys = state.store.passkeys(&person.id).await?;
    let left_passkeys = passkeys.iter().filter(|p| Some(p.id.as_str()) != passkey).count();
    if person.password_hash.is_none() && left_passkeys == 0 {
        return Err(ApiError::bad(
            "last_credential",
            "That is your only way to sign in. Set a password or add another passkey first.",
        ));
    }
    let membership = state.store.membership().await?;
    let groups = state.store.groups().await?;
    let has_totp = person.totp_secret.is_some() && !totp;
    if policy::needs_mfa(&groups, &membership.groups_of(&person.id)) && left_passkeys == 0 && !has_totp {
        return Err(ApiError::bad("mfa_required", "A group you are in asks for a second factor. Keep one."));
    }
    Ok(())
}

async fn remove_passkey(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    can_lose(&state, &me.person, Some(&id), false).await?;
    if !state.store.remove_passkey(&me.person.id, &id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "passkey_removed", Some(&me.person.id), Some(&me.person.id), Some(&id), &ip, json!({})).await;
    notify(&state, &me.person, Mail::SignInChanged { what: added(&me.person, "passkey-"), time: now_text(&state) });
    Ok(StatusCode::NO_CONTENT)
}

/// A new secret for the authenticator app, kept in memory until a first code confirms it.
async fn totp_start(State(state): State<AppState>, MeSetup(me): MeSetup) -> ApiResult<Json<Value>> {
    me.require_fresh()?;
    let secret = crate::crypto::random_bytes(20);
    let text = totp::base32_encode(&secret);
    state.memory.totp_setup.put(me.person.id.clone(), secret);
    let issuer = state.settings().organization;
    let label = format!("{issuer}:{}", me.person.username);
    let uri = format!(
        "otpauth://totp/{}?secret={text}&issuer={}&algorithm=SHA1&digits=6&period=30",
        percent(&label),
        percent(&issuer)
    );
    Ok(Json(json!({ "secret": text, "uri": uri })))
}

/// Percent-encoding for a URI component.
fn percent(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

async fn new_recovery_codes(state: &AppState, person: &str) -> ApiResult<Vec<String>> {
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| readable_secret(3)).collect();
    state.store.set_recovery_codes(person, codes.iter().map(|code| secret_hash(code)).collect()).await?;
    Ok(codes)
}

async fn totp_confirm(
    State(state): State<AppState>,
    MeSetup(me): MeSetup,
    ClientIp(ip): ClientIp,
    Json(body): Json<Code>,
) -> ApiResult<Json<Value>> {
    me.require_fresh()?;
    let secret = state
        .memory
        .totp_setup
        .peek(&me.person.id)
        .ok_or_else(|| ApiError::bad("expired", "Start the setup again: it ran out."))?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let step = totp::matching_step(&secret, &body.code, now)
        .ok_or_else(|| ApiError::field("code", "wrong_code", "The code is wrong. Check the time on your phone."))?;
    state.memory.totp_setup.take(&me.person.id);
    let sealed = state.sealer.seal(&secret);
    let person = state
        .store
        .update_person(&me.person.id, move |person| {
            person.totp_secret = Some(sealed);
            person.totp_step = step;
        })
        .await?;
    let codes = if state.store.recovery_codes_left(&person.id).await? == 0 {
        Some(new_recovery_codes(&state, &person.id).await?)
    } else {
        None
    };
    if me.session.restricted {
        state.store.unrestrict(&me.session.id).await?;
    }
    audit(&state, "totp_added", Some(&person.id), Some(&person.id), None, &ip, json!({})).await;
    notify(&state, &person, Mail::SignInChanged { what: added(&person, "totp"), time: now_text(&state) });
    Ok(Json(json!({ "recoveryCodes": codes })))
}

async fn totp_remove(State(state): State<AppState>, me: Me, ClientIp(ip): ClientIp) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    can_lose(&state, &me.person, None, true).await?;
    let person = state.store.update_person(&me.person.id, |person| person.totp_secret = None).await?;
    if state.store.passkeys(&person.id).await?.is_empty() {
        state.store.set_recovery_codes(&person.id, Vec::new()).await?;
    }
    audit(&state, "totp_removed", Some(&person.id), Some(&person.id), None, &ip, json!({})).await;
    notify(&state, &person, Mail::SignInChanged { what: added(&person, "totp-"), time: now_text(&state) });
    Ok(StatusCode::NO_CONTENT)
}

async fn recovery(
    State(state): State<AppState>,
    MeSetup(me): MeSetup,
    ClientIp(ip): ClientIp,
) -> ApiResult<Json<Value>> {
    me.require_fresh()?;
    let codes = new_recovery_codes(&state, &me.person.id).await?;
    audit(&state, "recovery_codes_made", Some(&me.person.id), Some(&me.person.id), None, &ip, json!({})).await;
    notify(&state, &me.person, Mail::SignInChanged { what: added(&me.person, "recovery"), time: now_text(&state) });
    Ok(Json(json!({ "recoveryCodes": codes })))
}

#[derive(Deserialize)]
struct NewApp {
    name: String,
}

async fn add_app_password(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewApp>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    me.require_fresh()?;
    let name = policy::optional(Some(&body.name), 60)
        .ok_or_else(|| ApiError::field("name", "required", "A name is needed."))?;
    let secret = readable_secret(6);
    let added = state
        .store
        .add_app_password(&me.person.id, &name, secret_hash(&secret))
        .await?
        .ok_or_else(|| ApiError::bad("too_many", "That is as many app passwords as an account can have."))?;
    audit(
        &state,
        "app_password_added",
        Some(&me.person.id),
        Some(&me.person.id),
        Some(&added.id),
        &ip,
        json!({ "name": name }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": added.id, "name": added.name, "created": added.created, "secret": secret })),
    ))
}

async fn remove_app_password(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.remove_app_password(&me.person.id, &id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "app_password_removed", Some(&me.person.id), Some(&me.person.id), Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Sessions as the portals show them: the first 8 bytes of the id, hex, identify one.
pub(crate) fn session_view(session: &uwuauth_store::Session, current: Option<&[u8]>) -> Value {
    json!({
        "id": hex(&session.id[..8]),
        "created": session.created,
        "lastSeen": session.last_seen,
        "expires": session.expires,
        "ip": session.ip,
        "device": super::login::describe(session.user_agent.as_deref()),
        "userAgent": session.user_agent,
        "methods": serde_json::from_str::<Value>(&session.methods).unwrap_or_default(),
        "current": current == Some(session.id.as_slice()),
    })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn sessions(State(state): State<AppState>, me: Me) -> ApiResult<Json<Value>> {
    let sessions = state.store.sessions_of(&me.person.id).await?;
    Ok(Json(json!(sessions.iter().map(|session| session_view(session, Some(&me.session.id))).collect::<Vec<_>>())))
}

/// End one session, by the short id the list shows.
pub(crate) async fn end_by_short_id(state: &AppState, person: &str, short: &str) -> ApiResult<()> {
    let sessions = state.store.sessions_of(person).await?;
    let session = sessions.iter().find(|session| hex(&session.id[..8]) == short).ok_or_else(ApiError::not_found)?;
    state.store.end_session_of(person, &session.id).await?;
    Ok(())
}

async fn end_session(State(state): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult<StatusCode> {
    end_by_short_id(&state, &me.person.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn end_others(State(state): State<AppState>, me: Me, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    let ended = state.store.end_sessions(&me.person.id, Some(&me.session.id)).await?;
    audit(&state, "sessions_ended", Some(&me.person.id), Some(&me.person.id), None, &ip, json!({ "count": ended }))
        .await;
    Ok(Json(json!({ "ended": ended })))
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct Page {
    pub before: Option<i64>,
    pub kind: Option<String>,
}

pub(crate) fn event_view(event: &uwuauth_store::Event) -> Value {
    json!({
        "id": event.id,
        "time": event.time,
        "kind": event.kind,
        "actor": event.actor_id,
        "person": event.person_id,
        "target": event.target,
        "ip": event.ip,
        "detail": serde_json::from_str::<Value>(&event.detail).unwrap_or_default(),
    })
}

async fn events(
    State(state): State<AppState>,
    me: Me,
    axum::extract::Query(page): axum::extract::Query<Page>,
) -> ApiResult<Json<Value>> {
    let events = state
        .store
        .events(EventFilter {
            people: Some(vec![me.person.id.clone()]),
            kind: page.kind,
            before: page.before,
            limit: 100,
        })
        .await?;
    Ok(Json(json!(events.iter().map(event_view).collect::<Vec<_>>())))
}

#[allow(dead_code)]
fn _unused(_: HeaderMap, _: IpAddr) {}
