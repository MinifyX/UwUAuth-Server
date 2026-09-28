//! Devices without a proper browser — a TV, a command line (RFC 8628): the device shows a short
//! code, the person types it on their phone at `/#/device`, confirms, and the device gets its
//! tokens by asking `/oauth/token` every few seconds.

use super::authorize::{refusal, strong};
use super::{client, form, issuer, oauth_error, open_to_all, scopes};
use crate::crypto::{b64, random_bytes, random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::session::{ClientIp, Me};
use crate::{AppState, audit};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

/// How long a device code works.
pub const DEVICE_SECONDS: u64 = 10 * 60;
/// How often a device may ask.
pub const INTERVAL_SECONDS: u64 = 5;

/// Letters that are hard to mix up, and no vowels, so no code spells a word.
const USER_CODE_LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

#[derive(Debug, Clone)]
pub enum DeviceState {
    Waiting,
    Refused,
    Confirmed { person_id: String, auth_time: i64, amr: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct DeviceGrant {
    pub app_id: String,
    pub scopes: Vec<String>,
    pub user_code: String,
    pub state: DeviceState,
    pub last_poll: Option<std::time::Instant>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/device/{code}", get(show).post(decide))
}

/// `XXXX-XXXX` from the letters above: about 34 bits, and the device codes run out in minutes.
fn user_code() -> String {
    let mut code = String::with_capacity(9);
    let limit = 256 - 256 % USER_CODE_LETTERS.len();
    while code.len() < 9 {
        for byte in random_bytes(16) {
            if usize::from(byte) >= limit || code.len() == 9 {
                continue;
            }
            if code.len() == 4 {
                code.push('-');
            }
            code.push(USER_CODE_LETTERS[usize::from(byte) % USER_CODE_LETTERS.len()] as char);
        }
    }
    code
}

/// What a person types, as the code is written: upper case, the dash where it belongs.
fn normalize(typed: &str) -> String {
    let letters: String = typed.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect();
    if letters.len() == 8 { format!("{}-{}", &letters[..4], &letters[4..]) } else { letters }
}

/// `/oauth/device_authorization`.
pub async fn start(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let form = form(&body);
    let client = match client(&state, &headers, &form).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    if !client.app.grant_types.iter().any(|grant| grant == super::token::DEVICE_GRANT) {
        return oauth_error(StatusCode::BAD_REQUEST, "unauthorized_client", "this app may not use the device flow");
    }
    let scope = form.iter().find(|(key, _)| key == "scope").map(|(_, value)| value.as_str()).unwrap_or_default();
    let device_code = random_token(32);
    let user_code = user_code();
    state.oidc().devices.put(
        b64(&sha256(device_code.as_bytes())),
        DeviceGrant {
            app_id: client.app.id.clone(),
            scopes: scopes(scope),
            user_code: user_code.clone(),
            state: DeviceState::Waiting,
            last_poll: None,
        },
    );
    let page = format!("{}/#/device", issuer(&state));
    open_to_all(
        Json(json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": page,
            "verification_uri_complete": format!("{page}?code={user_code}"),
            "expires_in": DEVICE_SECONDS,
            "interval": INTERVAL_SECONDS,
        }))
        .into_response(),
    )
}

/// The device grant a person's code belongs to: its key and itself.
fn find(state: &AppState, code: &str) -> Option<(String, DeviceGrant)> {
    let code = normalize(code);
    state.oidc().devices.find(|grant| grant.user_code == code && matches!(grant.state, DeviceState::Waiting))
}

async fn show(
    State(state): State<AppState>,
    _me: Me,
    ClientIp(ip): ClientIp,
    Path(code): Path<String>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many());
    }
    let (_, grant) = find(&state, &code).ok_or_else(ApiError::not_found)?;
    let app = state.store.app(&grant.app_id).await?.ok_or_else(ApiError::not_found)?;
    Ok(Json(
        json!({ "app": { "name": app.name, "description": app.description }, "scopes": grant.scopes, "code": grant.user_code }),
    ))
}

#[derive(Deserialize)]
struct Decision {
    approve: bool,
}

async fn decide(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(code): Path<String>,
    Json(decision): Json<Decision>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many());
    }
    let (key, mut grant) = find(&state, &code).ok_or_else(ApiError::not_found)?;
    let app = state.store.app(&grant.app_id).await?.ok_or_else(ApiError::not_found)?;
    if !decision.approve {
        grant.state = DeviceState::Refused;
        state.oidc().devices.put(key, grant);
        return Ok(Json(json!({ "approved": false })));
    }
    if let Some(reason) = refusal(&state, &app, &me.person).await? {
        return Err(ApiError::forbidden("You may not use this app now.").with_detail(json!({ "reason": reason })));
    }
    let amr = me.methods();
    if app.require_mfa && !strong(&amr) {
        return Err(ApiError::reauth().with_detail(json!({ "reason": "mfa" })));
    }
    let auth_time = uwuauth_store::clock::parse(&me.session.auth_time).map_or(0, |at| at.unix_timestamp());
    grant.state = DeviceState::Confirmed { person_id: me.person.id.clone(), auth_time, amr };
    state.oidc().devices.put(key, grant);
    audit(
        &state,
        "device_confirmed",
        Some(&me.person.id),
        Some(&me.person.id),
        Some(&app.id),
        &ip,
        json!({ "app": app.name }),
    )
    .await;
    Ok(Json(json!({ "approved": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_are_easy_to_type() {
        let code = user_code();
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
        assert!(code.chars().filter(|c| *c != '-').all(|c| USER_CODE_LETTERS.contains(&(c as u8))));
        assert_eq!(normalize(&code.to_lowercase().replace('-', " ")), code);
    }
}
