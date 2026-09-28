//! `/oauth/token` and what checks its tokens: `/oauth/userinfo`, `/oauth/introspect`,
//! `/oauth/revoke`.
//!
//! - An **access token** is a JWT (RFC 9068), signed like the app's ID tokens, a quarter of an
//!   hour by default. It carries a short hash of the person's security stamp: a new password,
//!   "sign out everywhere" or a disabled account ends it at the next check here, and apps that
//!   only read its signature find out at their next refresh.
//! - A **refresh token** is random; the database keeps its hash. Each works once and comes with
//!   a new one. One used a second time was copied: its whole family ends, and the app has to
//!   sign the person in again. Every refresh checks again that the person may use the app — a
//!   kid's time window that closed ends the app's access within a quarter of an hour.

use super::authorize::{Code, refusal};
use super::claims;
use super::device::DeviceState;
use super::keys::{Alg, half_hash};
use super::{Client, client, form, issuer, oauth_error, open_to_all, scopes};
use crate::crypto::{b64, random_token, sha256};
use crate::{ApiResult, AppState, audit};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use uwuauth_store::{App, Person, Refresh, RefreshToken, clock};

pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    open_to_all(response)
}

fn invalid_grant(description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

/// A short hash of the person's security stamp, carried in access tokens.
pub fn stamp_hash(person: &Person) -> String {
    b64(&sha256(person.security_stamp.as_bytes())[..8])
}

pub async fn token(
    State(state): State<AppState>,
    crate::session::ClientIp(ip): crate::session::ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.limits.oauth.check(ip) {
        return oauth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "too many requests, wait a moment",
        );
    }
    let form = form(&body);
    let client = match client(&state, &headers, &form).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let field = |name: &str| form.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());
    let grant_type = field("grant_type").unwrap_or_default();
    if !client.app.grant_types.iter().any(|allowed| allowed == grant_type) && !grant_type.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "unauthorized_client", "this app may not use that grant type");
    }
    let result = match grant_type {
        "authorization_code" => {
            code_grant(&state, &client, field("code"), field("redirect_uri"), field("code_verifier")).await
        }
        "refresh_token" => refresh_grant(&state, &client, field("refresh_token"), field("scope")).await,
        "client_credentials" => client_credentials(&state, &client, field("scope")).await,
        DEVICE_GRANT => device_grant(&state, &client, field("device_code")).await,
        "" => Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "grant_type is missing")),
        _ => Ok(oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "that grant type is not offered")),
    };
    match result {
        Ok(response) => no_store(response),
        Err(error) => {
            tracing::warn!(error = %error.message, "the token endpoint failed");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "something went wrong on the server")
        }
    }
}

/// What a sign-in gives an app, however it came.
pub struct Issue<'a> {
    pub app: &'a App,
    pub person: &'a Person,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub sid: Option<String>,
    /// The refresh token this one replaces (its hash) and its family, for a refresh.
    pub replaces: Option<(Vec<u8>, String)>,
    /// Include an ID token.
    pub id_token: bool,
}

/// What was issued: the token endpoint's answer, and the refresh token's family if there is one.
pub struct Issued {
    pub body: Value,
    pub family: Option<String>,
}

/// Tokens for `issue`, as the token endpoint answers them. Nothing when the refresh token being
/// replaced lost its family in the meantime (it was used twice at the same moment).
pub async fn tokens(state: &AppState, issue: Issue<'_>) -> ApiResult<Option<Issued>> {
    let keys = state.keys().await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let alg = Alg::parse(&issue.app.id_token_alg).unwrap_or(Alg::Rs256);
    let lasts = issue.app.access_token_minutes.clamp(1, 24 * 60) * 60;
    let scope = issue.scopes.join(" ");
    let mut access_claims = json!({
        "iss": issuer(state),
        "sub": issue.person.id,
        "aud": issue.app.client_id,
        "client_id": issue.app.client_id,
        "exp": now + lasts,
        "iat": now,
        "jti": random_token(16),
        "scope": scope,
        "auth_time": issue.auth_time,
        "uwu_s": stamp_hash(issue.person),
    });
    if let Some(sid) = &issue.sid {
        access_claims["sid"] = json!(sid);
    }
    let access = keys.sign(alg, "at+jwt", &access_claims);
    let mut body = json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": lasts,
        "scope": scope,
    });
    if issue.id_token && issue.scopes.iter().any(|scope| scope == "openid") {
        let mut claims = claims::about(state, issue.app, issue.person, &issue.scopes).await?;
        claims.insert("iss".into(), json!(issuer(state)));
        claims.insert("aud".into(), json!(issue.app.client_id));
        claims.insert("azp".into(), json!(issue.app.client_id));
        claims.insert("exp".into(), json!(now + lasts.max(300)));
        claims.insert("iat".into(), json!(now));
        claims.insert("auth_time".into(), json!(issue.auth_time));
        claims.insert("amr".into(), json!(issue.amr));
        claims.insert("at_hash".into(), json!(half_hash(&access)));
        if let Some(nonce) = &issue.nonce {
            claims.insert("nonce".into(), json!(nonce));
        }
        if let Some(sid) = &issue.sid {
            claims.insert("sid".into(), json!(sid));
        }
        body["id_token"] = json!(keys.sign(alg, "JWT", &Value::Object(claims)));
    }
    // Every token belongs to a grant: userinfo and introspection look for it.
    let grant = state.store.touch_grant(&issue.app.id, &issue.person.id, &scope, false).await?;
    let mut family = None;
    if issue.app.grant_types.iter().any(|grant| grant == "refresh_token") {
        let refresh = random_token(32);
        let token = RefreshToken {
            hash: sha256(refresh.as_bytes()),
            grant_id: grant.id,
            family: issue
                .replaces
                .as_ref()
                .map_or_else(|| uuid::Uuid::new_v4().to_string(), |(_, family)| family.clone()),
            scope,
            stamp: issue.person.security_stamp.clone(),
            auth_time: issue.auth_time,
            amr: json!(issue.amr).to_string(),
            sid: issue.sid.clone(),
            nonce: issue.nonce.clone(),
            created: clock::now(),
            expires: clock::in_seconds(issue.app.refresh_token_days.clamp(1, 3650) * 86_400),
            used: None,
        };
        family = Some(token.family.clone());
        match &issue.replaces {
            Some((parent, _)) => {
                if !state.store.add_refresh_token_after(parent, token).await? {
                    return Ok(None);
                }
            }
            None => state.store.add_refresh_token(token).await?,
        }
        body["refresh_token"] = json!(refresh);
    }
    Ok(Some(Issued { body, family }))
}

async fn code_grant(
    state: &AppState,
    client: &Client,
    code: Option<&str>,
    redirect_uri: Option<&str>,
    verifier: Option<&str>,
) -> ApiResult<Response> {
    let Some(code) = code else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "code is missing"));
    };
    let key = b64(&sha256(code.as_bytes()));
    let Some(found): Option<Code> = state.oidc().codes.take(&key) else {
        // A code that comes a second time was stolen: what it gave the first time ends.
        if let Some(Some(family)) = state.oidc().used_codes.take(&key) {
            state.store.revoke_family(&family).await?;
            tracing::warn!(app = client.app.name, "a code came a second time; the tokens it gave are revoked");
        }
        return Ok(invalid_grant("the code is unknown, used or ran out"));
    };
    if found.app_id != client.app.id {
        return Ok(invalid_grant("the code is for another app"));
    }
    // An app that sent redirect_uri with the request sends the same one now (RFC 6749 4.1.3).
    let redirect_fits = match redirect_uri {
        Some(uri) => uri == found.redirect_uri,
        None => !found.redirect_given,
    };
    if !redirect_fits {
        return Ok(invalid_grant("redirect_uri is not the one the code was made for"));
    }
    match (&found.code_challenge, verifier) {
        (Some(challenge), Some(verifier)) => {
            let valid = (43..=128).contains(&verifier.len())
                && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
            if !valid || b64(&sha256(verifier.as_bytes())) != *challenge {
                return Ok(invalid_grant("the code verifier does not fit the challenge"));
            }
        }
        (Some(_), None) => return Ok(invalid_grant("the code verifier is missing")),
        (None, Some(_)) => return Ok(invalid_grant("there was no code challenge")),
        (None, None) if !client.authenticated => return Ok(invalid_grant("an app without a secret needs PKCE")),
        (None, None) => {}
    }
    let Some(person) = state.store.person(&found.person_id).await? else {
        return Ok(invalid_grant("the person is gone"));
    };
    if refusal(state, &client.app, &person).await?.is_some() {
        return Ok(invalid_grant("the person may not use this app now"));
    }
    let issued = tokens(
        state,
        Issue {
            app: &client.app,
            person: &person,
            scopes: found.scopes,
            nonce: found.nonce,
            auth_time: found.auth_time,
            amr: found.amr,
            sid: Some(found.sid),
            replaces: None,
            id_token: true,
        },
    )
    .await?;
    let Some(issued) = issued else { return Ok(invalid_grant("the grant ended")) };
    state.oidc().used_codes.put(key, issued.family);
    Ok(Json(issued.body).into_response())
}

async fn refresh_grant(
    state: &AppState,
    client: &Client,
    token: Option<&str>,
    scope: Option<&str>,
) -> ApiResult<Response> {
    let Some(token) = token else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "refresh_token is missing"));
    };
    let hash = sha256(token.as_bytes());
    // Whose it is first, so a refresh token of another app is not used up by asking.
    let Some(stored) = state.store.refresh_token(&hash).await? else {
        return Ok(invalid_grant("the refresh token is unknown"));
    };
    let Some(grant) = state.store.grant_by_id(&stored.grant_id).await? else {
        return Ok(invalid_grant("the grant was taken back"));
    };
    if grant.app_id != client.app.id {
        return Ok(invalid_grant("the refresh token is for another app"));
    }
    // A refresh may ask for less than before, never for more — checked before the token is used
    // up, so a wrong request costs nothing.
    let before: Vec<String> = stored.scope.split_whitespace().map(str::to_string).collect();
    let asked = match scope {
        Some(scope) => scopes(scope),
        None => before.clone(),
    };
    if asked.iter().any(|scope| !before.contains(scope)) {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", "a refresh cannot widen the scope"));
    }
    let found = match state.store.use_refresh_token(&hash).await? {
        Refresh::Fresh(found) => *found,
        Refresh::Reused => {
            let ip: std::net::IpAddr = [0, 0, 0, 0].into();
            audit(
                state,
                "refresh_token_reused",
                None,
                Some(&grant.person_id),
                Some(&client.app.id),
                &ip,
                json!({ "app": client.app.name }),
            )
            .await;
            return Ok(invalid_grant("the refresh token was used before; the app has to sign in again"));
        }
        Refresh::Unknown => return Ok(invalid_grant("the refresh token ran out")),
    };
    let Some(person) = state.store.person(&grant.person_id).await? else {
        return Ok(invalid_grant("the person is gone"));
    };
    if person.security_stamp != found.stamp {
        state.store.revoke_family(&found.family).await?;
        return Ok(invalid_grant("the person signed out everywhere or changed their password"));
    }
    if refusal(state, &client.app, &person).await?.is_some() {
        state.store.revoke_family(&found.family).await?;
        return Ok(invalid_grant("the person may not use this app now"));
    }
    let issued = tokens(
        state,
        Issue {
            app: &client.app,
            person: &person,
            scopes: asked,
            nonce: None,
            auth_time: found.auth_time,
            amr: serde_json::from_str(&found.amr).unwrap_or_default(),
            sid: found.sid,
            replaces: Some((hash, found.family)),
            id_token: true,
        },
    )
    .await?;
    match issued {
        Some(issued) => Ok(Json(issued.body).into_response()),
        None => Ok(invalid_grant("the refresh token was used twice at once; the app has to sign in again")),
    }
}

/// A token for the app itself, not for a person: for a service that calls UwUAuth.
async fn client_credentials(state: &AppState, client: &Client, scope: Option<&str>) -> ApiResult<Response> {
    if !client.authenticated {
        return Ok(oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "client credentials need the app's secret"));
    }
    let keys = state.keys().await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let lasts = client.app.access_token_minutes.clamp(1, 24 * 60) * 60;
    let scope: Vec<String> = scopes(scope.unwrap_or_default())
        .into_iter()
        .filter(|scope| scope != "openid" && scope != "offline_access")
        .collect();
    let alg = Alg::parse(&client.app.id_token_alg).unwrap_or(Alg::Rs256);
    let access = keys.sign(
        alg,
        "at+jwt",
        &json!({
            "iss": issuer(state),
            "sub": client.app.client_id,
            "aud": client.app.client_id,
            "client_id": client.app.client_id,
            "exp": now + lasts,
            "iat": now,
            "jti": random_token(16),
            "scope": scope.join(" "),
        }),
    );
    Ok(Json(json!({ "access_token": access, "token_type": "Bearer", "expires_in": lasts, "scope": scope.join(" ") }))
        .into_response())
}

async fn device_grant(state: &AppState, client: &Client, device_code: Option<&str>) -> ApiResult<Response> {
    let Some(device_code) = device_code else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "device_code is missing"));
    };
    let key = b64(&sha256(device_code.as_bytes()));
    let Some(mut grant) = state.oidc().devices.peek(&key) else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "expired_token", "the device code ran out"));
    };
    if grant.app_id != client.app.id {
        return Ok(invalid_grant("the device code is for another app"));
    }
    let now = std::time::Instant::now();
    if grant.last_poll.is_some_and(|last| now.duration_since(last).as_secs() < super::device::INTERVAL_SECONDS) {
        grant.last_poll = Some(now);
        state.oidc().devices.put(key, grant);
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "slow_down", "ask less often"));
    }
    grant.last_poll = Some(now);
    match grant.state.clone() {
        DeviceState::Waiting => {
            state.oidc().devices.put(key, grant);
            Ok(oauth_error(StatusCode::BAD_REQUEST, "authorization_pending", "the person has not confirmed yet"))
        }
        DeviceState::Refused => {
            state.oidc().devices.take(&key);
            Ok(oauth_error(StatusCode::BAD_REQUEST, "access_denied", "the person said no"))
        }
        DeviceState::Confirmed { person_id, auth_time, amr } => {
            // Taken once: of two polls at the same moment, only one gets the tokens.
            if state.oidc().devices.take(&key).is_none() {
                return Ok(oauth_error(StatusCode::BAD_REQUEST, "expired_token", "the device code was used"));
            }
            let Some(person) = state.store.person(&person_id).await? else {
                return Ok(invalid_grant("the person is gone"));
            };
            if refusal(state, &client.app, &person).await?.is_some() {
                return Ok(invalid_grant("the person may not use this app now"));
            }
            let issued = tokens(
                state,
                Issue {
                    app: &client.app,
                    person: &person,
                    scopes: grant.scopes,
                    nonce: None,
                    auth_time,
                    amr,
                    sid: None,
                    replaces: None,
                    id_token: true,
                },
            )
            .await?;
            match issued {
                Some(issued) => Ok(Json(issued.body).into_response()),
                None => Ok(invalid_grant("the grant ended")),
            }
        }
    }
}

/// An access token of this server that has not run out, its person still who it was issued to:
/// the token's claims, the app and the person.
pub async fn check_access_token(
    state: &AppState,
    token: &str,
) -> ApiResult<Option<(Map<String, Value>, App, Option<Person>)>> {
    let keys = state.keys().await?;
    let Some((header, claims)) = keys.verify(token) else { return Ok(None) };
    if header.get("typ").and_then(Value::as_str) != Some("at+jwt") {
        return Ok(None);
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if claims.get("iss").and_then(Value::as_str) != Some(issuer(state).as_str()) || exp <= now {
        return Ok(None);
    }
    let client_id = claims.get("client_id").and_then(Value::as_str).unwrap_or_default();
    let Some(app) = state.store.app_by_client_id(client_id).await?.filter(|app| !app.disabled) else { return Ok(None) };
    let sub = claims.get("sub").and_then(Value::as_str).unwrap_or_default();
    if sub == app.client_id {
        return Ok(Some((claims, app, None)));
    }
    let Some(person) = state.store.person(sub).await? else { return Ok(None) };
    if !person.active() || claims.get("uwu_s").and_then(Value::as_str) != Some(stamp_hash(&person).as_str()) {
        return Ok(None);
    }
    if state.store.grant(&app.id, &person.id).await?.is_none() {
        return Ok(None);
    }
    Ok(Some((claims, app, Some(person))))
}

/// `/oauth/userinfo`: the claims about the person, by the scopes of the token.
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let from_header = crate::session::bearer(&headers).map(str::to_string);
    let token =
        from_header.or_else(|| form(&body).into_iter().find(|(key, _)| key == "access_token").map(|(_, value)| value));
    let invalid = || {
        let mut response = (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_token" }))).into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer error=\"invalid_token\""));
        open_to_all(response)
    };
    let Some(token) = token else { return invalid() };
    let found = match check_access_token(&state, &token).await {
        Ok(Some(found)) => found,
        Ok(None) => return invalid(),
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "something went wrong"),
    };
    let (claims, app, Some(person)) = found else { return invalid() };
    let scopes = scopes(claims.get("scope").and_then(Value::as_str).unwrap_or_default());
    if !scopes.iter().any(|scope| scope == "openid") {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "insufficient_scope" }))).into_response();
    }
    match claims::about(&state, &app, &person, &scopes).await {
        Ok(claims) => no_store(Json(Value::Object(claims)).into_response()),
        Err(_) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "something went wrong"),
    }
}

/// `/oauth/introspect` (RFC 7662): for an app with a secret, about its own tokens.
pub async fn introspect(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let form = form(&body);
    let client = match client(&state, &headers, &form).await {
        Ok(client) if client.authenticated => client,
        Ok(_) => {
            return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "introspection needs the app's secret");
        }
        Err(response) => return *response,
    };
    let token = form.iter().find(|(key, _)| key == "token").map(|(_, value)| value.clone()).unwrap_or_default();
    let inactive = || no_store(Json(json!({ "active": false })).into_response());
    if let Ok(Some((claims, app, person))) = check_access_token(&state, &token).await {
        if app.id != client.app.id {
            return inactive();
        }
        let mut body = json!({
            "active": true,
            "token_type": "Bearer",
            "scope": claims.get("scope"),
            "client_id": app.client_id,
            "sub": claims.get("sub"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "iss": claims.get("iss"),
            "aud": claims.get("aud"),
        });
        if let Some(person) = person {
            body["username"] = json!(person.username);
        }
        return no_store(Json(body).into_response());
    }
    let hash = sha256(token.as_bytes());
    if let Ok(Some(stored)) = state.store.refresh_token(&hash).await
        && stored.used.is_none()
        && stored.expires.as_str() > clock::now().as_str()
        && let Ok(Some(grant)) = state.store.grant_by_id(&stored.grant_id).await
        && grant.app_id == client.app.id
        // Active means a refresh would work: the person as they were, and still allowed in.
        && let Ok(Some(person)) = state.store.person(&grant.person_id).await
        && person.security_stamp == stored.stamp
        && matches!(refusal(&state, &client.app, &person).await, Ok(None))
    {
        return no_store(
            Json(json!({
                "active": true,
                "token_type": "refresh_token",
                "scope": stored.scope,
                "client_id": client.app.client_id,
                "sub": grant.person_id,
                "exp": clock::parse(&stored.expires).map(|at| at.unix_timestamp()),
            }))
            .into_response(),
        );
    }
    inactive()
}

/// `/oauth/revoke` (RFC 7009): a refresh token ends with its family. Access tokens end on their
/// own within minutes; the answer is the same either way.
pub async fn revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let form = form(&body);
    let client = match client(&state, &headers, &form).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let token = form.iter().find(|(key, _)| key == "token").map(|(_, value)| value.clone()).unwrap_or_default();
    if let Ok(Some(stored)) = state.store.refresh_token(&sha256(token.as_bytes())).await
        && let Ok(Some(grant)) = state.store.grant_by_id(&stored.grant_id).await
        && grant.app_id == client.app.id
        && let Err(error) = state.store.revoke_family(&stored.family).await
    {
        tracing::warn!(%error, "revoking a refresh token failed");
    }
    no_store(StatusCode::OK.into_response())
}
