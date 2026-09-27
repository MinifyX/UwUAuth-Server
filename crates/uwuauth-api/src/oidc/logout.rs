//! Signing out: from an app (RP-initiated logout, `/oauth/logout`), and telling apps when a
//! session ends (back-channel logout).
//!
//! An app that sends a valid `id_token_hint` for the person who is signed in signs them out at
//! once. Without one, anybody could make a link that signs somebody out, so the person confirms
//! on UwUAuth's page first. Afterwards the browser goes to the app's `post_logout_redirect_uri`
//! — only one the app registered.
//!
//! Every app that got tokens in the session and has a `backchannel_logout_uri` gets a logout
//! token (a signed JWT) posted there, so it can end its own session too.

use super::keys::Alg;
use super::{issuer, sid};
use crate::crypto::{random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::session::{ClientIp, SESSION_COOKIE, cookie, from_headers, set_cookie, with_cookies};
use crate::{AppState, audit};
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use uwuauth_store::App;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Params {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// A sign-out an app asked for, waiting for the person to confirm it.
#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub redirect: Option<String>,
    pub app: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/logout-request/{id}", post(confirm).get(info))
}

pub async fn logout_get(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Response {
    run(&state, ip, &headers, params).await.unwrap_or_else(IntoResponse::into_response)
}

pub async fn logout_post(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(params): Form<Params>,
) -> Response {
    run(&state, ip, &headers, params).await.unwrap_or_else(IntoResponse::into_response)
}

async fn run(state: &AppState, ip: IpAddr, headers: &HeaderMap, params: Params) -> ApiResult<Response> {
    // The hint says who and which app; it may have run out, it only has to be ours.
    let keys = state.keys().await?;
    let hint = params.id_token_hint.as_deref().and_then(|token| keys.verify(token)).map(|(_, claims)| claims);
    let hint_app = hint.as_ref().and_then(|claims| claims.get("aud")).and_then(Value::as_str).map(str::to_string);
    let client_id = hint_app.or(params.client_id.clone());
    let app = match &client_id {
        Some(id) => state.store.app_by_client_id(id).await?,
        None => None,
    };
    let redirect = params.post_logout_redirect_uri.as_deref().and_then(|uri| {
        let app = app.as_ref()?;
        app.post_logout_redirect_uris.iter().any(|known| known == uri).then(|| with_state(uri, params.state.as_deref()))
    });
    let me = from_headers(state, headers, ip).await?;
    let Some(me) = me else {
        // Nobody signed in here: nothing to end, straight on.
        return Ok(
            Redirect::to(&redirect.unwrap_or_else(|| format!("{}/#/signed-out", state.config.public))).into_response()
        );
    };
    let hint_matches = hint.as_ref().is_some_and(|claims| {
        claims.get("iss").and_then(Value::as_str) == Some(issuer(state).as_str())
            && claims.get("sub").and_then(Value::as_str) == Some(me.person.id.as_str())
    });
    if hint_matches {
        end(state, &me.session.id, &me.person.id, ip).await?;
        let clear = set_cookie(state, SESSION_COOKIE, "", Some(0));
        let to = redirect.unwrap_or_else(|| format!("{}/#/signed-out", state.config.public));
        return Ok(with_cookies(Redirect::to(&to).into_response(), vec![clear]));
    }
    let id = random_token(18);
    state.oidc().logouts.put(id.clone(), LogoutRequest { redirect, app: app.map(|app| app.name) });
    Ok(Redirect::to(&format!("{}/#/logout?request={id}", state.config.public)).into_response())
}

fn with_state(uri: &str, app_state: Option<&str>) -> String {
    match (url::Url::parse(uri), app_state) {
        (Ok(mut url), Some(value)) => {
            url.query_pairs_mut().append_pair("state", value);
            url.to_string()
        }
        _ => uri.to_string(),
    }
}

async fn info(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let request = state.oidc().logouts.peek(&id).ok_or_else(ApiError::not_found)?;
    Ok(Json(json!({ "app": request.app })))
}

#[derive(Deserialize)]
struct Decision {
    confirm: bool,
}

/// The person confirmed (or not) a sign-out an app asked for: where the browser goes next.
async fn confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(decision): Json<Decision>,
) -> ApiResult<Response> {
    let request = state.oidc().logouts.take(&id).ok_or_else(ApiError::not_found)?;
    let mut cookies = Vec::new();
    if decision.confirm
        && let Some(me) = from_headers(&state, &headers, ip).await?
    {
        end(&state, &me.session.id, &me.person.id, ip).await?;
        cookies.push(set_cookie(&state, SESSION_COOKIE, "", Some(0)));
    }
    let to = request.redirect.filter(|_| decision.confirm).unwrap_or_else(|| format!("{}/#/", state.config.public));
    Ok(with_cookies(Json(json!({ "redirect": to })).into_response(), cookies))
}

/// End a browser session and tell the apps that signed in with it.
pub async fn end(state: &AppState, session_id: &[u8], person: &str, ip: IpAddr) -> ApiResult<()> {
    state.store.end_session(session_id).await?;
    audit(state, "logout", Some(person), Some(person), None, &ip, json!({})).await;
    backchannel(state, &sid(session_id), person).await
}

/// End the session in `headers`' cookie, if there is one: `/uwu/v1/logout` goes through here.
pub async fn end_from_headers(state: &AppState, headers: &HeaderMap, ip: IpAddr) -> ApiResult<()> {
    let Some(token) = cookie(headers, SESSION_COOKIE) else { return Ok(()) };
    let id = sha256(token.as_bytes());
    let Some(session) = state.store.session(&id).await? else { return Ok(()) };
    end(state, &id, &session.person_id, ip).await
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring speaks the versions rustls asks for")
            .with_root_certificates(roots)
            .with_no_client_auth();
        reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .user_agent("UwUAuth-Server")
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("an HTTP client")
    })
}

/// Post a logout token (OpenID Connect Back-Channel Logout 1.0) to every app session `sid`
/// signed in to. In the background: a slow app does not hold up the sign-out.
pub async fn backchannel(state: &AppState, sid: &str, person: &str) -> ApiResult<()> {
    let apps = state.store.take_session_apps(sid).await?;
    let keys = state.keys().await?;
    for (app_id, _) in apps {
        let Some(app) = state.store.app(&app_id).await? else { continue };
        let Some(uri) = app.backchannel_logout_uri.clone() else { continue };
        let token = logout_token(state, keys, &app, person, sid);
        let name = app.name.clone();
        tokio::spawn(async move {
            let body =
                url::form_urlencoded::Serializer::new(String::new()).append_pair("logout_token", &token).finish();
            let sent = client()
                .post(&uri)
                .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await;
            match sent {
                Ok(response) if response.status().is_success() => {
                    tracing::debug!(app = name, "back-channel logout sent")
                }
                Ok(response) => {
                    tracing::info!(app = name, status = %response.status(), "the app did not take the back-channel logout")
                }
                Err(error) => tracing::info!(app = name, %error, "the back-channel logout did not reach the app"),
            }
        });
    }
    Ok(())
}

fn logout_token(state: &AppState, keys: &super::keys::Keys, app: &App, person: &str, sid: &str) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let alg = Alg::parse(&app.id_token_alg).unwrap_or(Alg::Rs256);
    keys.sign(
        alg,
        "logout+jwt",
        &json!({
            "iss": issuer(state),
            "aud": app.client_id,
            "iat": now,
            "exp": now + 120,
            "jti": random_token(16),
            "sub": person,
            "sid": sid,
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }),
    )
}
