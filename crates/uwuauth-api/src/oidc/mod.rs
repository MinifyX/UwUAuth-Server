//! OpenID Connect and OAuth 2: UwUAuth as the place apps send people to sign in.
//!
//! - `authorize` — `/oauth/authorize`: who is signing in, whether they may use the app (its
//!   groups, their time windows, a second factor if the app asks for one), whether they agree
//!   (for apps that ask), and a code for the app.
//! - `token` — `/oauth/token`: codes (with PKCE), refresh tokens (each used once, a family ends
//!   when one comes back), client credentials, and devices without a browser (RFC 8628).
//! - `userinfo`, `introspect`, `revoke`, `logout` (RP-initiated, and back-channel to apps).
//! - `register` — apps registering themselves with a token an admin made (RFC 7591).
//!
//! Access tokens are JWTs (RFC 9068) that live a quarter of an hour by default, so a changed
//! group or a closed time window counts at the next refresh at the latest. The ID token's
//! algorithm is the app's: RS256 unless it says ES256.

pub mod authorize;
pub mod claims;
pub mod device;
#[cfg(test)]
mod flows;
pub mod keys;
pub mod logout;
pub mod register;
pub mod templates;
pub mod token;

use crate::crypto::{constant_time_eq, sha256};
use crate::memory::Expiring;
use crate::{ApiError, ApiResult, AppState};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;
use std::time::Duration;
use uwuauth_store::App;

/// Scopes UwUAuth knows. Others an app asks for are left out, not refused.
pub const SCOPES: &[&str] = &["openid", "profile", "email", "groups", "roles", "attributes", "offline_access"];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery).options(preflight))
        .route("/.well-known/oauth-authorization-server", get(discovery).options(preflight))
        .route("/oauth/jwks", get(jwks).options(preflight))
        .route("/oauth/authorize", get(authorize::authorize_get).post(authorize::authorize_post))
        .route("/oauth/token", post(token::token).options(preflight))
        .route("/oauth/userinfo", get(token::userinfo).post(token::userinfo).options(preflight))
        .route("/oauth/introspect", post(token::introspect).options(preflight))
        .route("/oauth/revoke", post(token::revoke).options(preflight))
        .route("/oauth/device_authorization", post(device::start).options(preflight))
        .route("/oauth/register", post(register::register).options(preflight))
        .route("/oauth/logout", get(logout::logout_get).post(logout::logout_post))
        .merge(authorize::consent_routes())
        .merge(device::routes())
        .merge(logout::routes())
}

/// What the server remembers about sign-ins to apps for a few minutes.
pub struct Pending {
    /// Codes waiting for the app to fetch its tokens, by the code's hash.
    pub codes: Expiring<authorize::Code>,
    /// Requests waiting for a person to agree, by id.
    pub consents: Expiring<authorize::Request>,
    /// Devices waiting for a person to confirm them, by the device code's hash.
    pub devices: Expiring<device::DeviceGrant>,
    /// Sign-outs an app asked for that wait for the person to confirm them.
    pub logouts: Expiring<logout::LogoutRequest>,
    /// Answers for apps that want them posted, waiting for the browser to fetch the page.
    pub answers: Expiring<authorize::FormAnswer>,
}

impl Default for Pending {
    fn default() -> Self {
        Pending {
            codes: Expiring::new(Duration::from_secs(60)),
            consents: Expiring::new(Duration::from_secs(10 * 60)),
            devices: Expiring::new(Duration::from_secs(device::DEVICE_SECONDS)),
            logouts: Expiring::new(Duration::from_secs(10 * 60)),
            answers: Expiring::new(Duration::from_secs(60)),
        }
    }
}

pub fn issuer(state: &AppState) -> String {
    state.config.public.clone()
}

/// The document apps read first (OpenID Connect Discovery 1.0, RFC 8414).
async fn discovery(State(state): State<AppState>) -> Response {
    let issuer = issuer(&state);
    let body = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "jwks_uri": format!("{issuer}/oauth/jwks"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "end_session_endpoint": format!("{issuer}/oauth/logout"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth/introspect"),
        "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
        "scopes_supported": SCOPES,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "userinfo_signing_alg_values_supported": ["none"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": claims::SUPPORTED,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "ui_locales_supported": ["de", "en"],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "frontchannel_logout_supported": false,
        "authorization_response_iss_parameter_supported": true,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false,
    });
    open_to_all(Json(body).into_response())
}

async fn jwks(State(state): State<AppState>) -> ApiResult<Response> {
    let keys = state.keys().await?;
    let mut response = Json(keys.jwks()).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    Ok(open_to_all(response))
}

/// Endpoints any web page may call: they hold nothing a cookie would unlock, so `*` is safe.
pub fn open_to_all(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("authorization, content-type"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
    response
}

async fn preflight() -> Response {
    let mut response = open_to_all(StatusCode::NO_CONTENT.into_response());
    response.headers_mut().insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    response
}

/// An OAuth error (RFC 6749 section 5.2): `{"error", "error_description"}`.
pub fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut response = (status, Json(json!({ "error": error, "error_description": description }))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"UwUAuth\""));
    }
    open_to_all(response)
}

/// The client asking at the token endpoint and its friends, and how it proved it is that client.
pub struct Client {
    pub app: App,
    /// It showed its secret (a confidential client), rather than only its id.
    pub authenticated: bool,
}

/// Percent-decoding for `application/x-www-form-urlencoded` (and Basic credentials, RFC 6749
/// section 2.3.1).
pub fn form_decode(text: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", text.replace('&', "%26")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

/// Who the client is, from `Authorization: Basic` or `client_id`/`client_secret` in the form.
/// A client with a secret has to show it; one without (public) only says its id.
pub async fn client(state: &AppState, headers: &HeaderMap, form: &[(String, String)]) -> Result<Client, Box<Response>> {
    let field = |name: &str| form.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone());
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")))
        .and_then(|encoded| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|pair| pair.split_once(':').map(|(id, secret)| (form_decode(id), form_decode(secret))));
    let (client_id, secret, used_basic) = match basic {
        Some((id, secret)) => (id, Some(secret), true),
        None => (field("client_id").unwrap_or_default(), field("client_secret"), false),
    };
    let unknown = || {
        let status = if used_basic { StatusCode::UNAUTHORIZED } else { StatusCode::BAD_REQUEST };
        Box::new(oauth_error(status, "invalid_client", "the client is unknown or its secret is wrong"))
    };
    let app = state
        .store
        .app_by_client_id(client_id.trim())
        .await
        .ok()
        .flatten()
        .filter(|app| !app.disabled)
        .ok_or_else(unknown)?;
    match (&app.secret_hash, secret.filter(|secret| !secret.is_empty())) {
        (Some(hash), Some(secret)) if constant_time_eq(hash, &sha256(secret.as_bytes())) => {
            Ok(Client { app, authenticated: true })
        }
        (Some(_), _) => Err(unknown()),
        (None, None) => Ok(Client { app, authenticated: false }),
        // A public client that sends a secret has none to send: refused, rather than believed.
        (None, Some(_)) => Err(unknown()),
    }
}

/// Parse a form body into pairs.
pub fn form(body: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

impl AppState {
    /// The signing keys, made on first use.
    pub async fn keys(&self) -> ApiResult<&keys::Keys> {
        self.keys
            .get_or_try_init(|| keys::Keys::load(&self.store, &self.sealer, self.config.fixed_rsa_key.as_deref()))
            .await
            .map_err(ApiError::internal)
    }
}

/// Everything in `SCOPES` that `asked` names, `openid` first, each once.
pub fn scopes(asked: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for scope in asked.split_whitespace() {
        if SCOPES.contains(&scope) && !out.iter().any(|known| known == scope) {
            out.push(scope.to_string());
        }
    }
    out.sort_by_key(|scope| scope != "openid");
    out
}

/// The OpenID Connect session id of a browser session: derived from the session, never the
/// session's own secret.
pub fn sid(session_id: &[u8]) -> String {
    crate::crypto::b64(&sha256(&[b"sid:".as_slice(), session_id].concat())[..16])
}

#[cfg(test)]
mod tests {
    #[test]
    fn scopes_are_known_ones_openid_first() {
        assert_eq!(super::scopes("email openid email nonsense profile"), ["openid", "email", "profile"]);
        assert!(super::scopes("").is_empty());
    }

    #[test]
    fn basic_credentials_are_form_decoded() {
        assert_eq!(super::form_decode("a%3Ab+c"), "a:b c");
    }
}
