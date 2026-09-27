//! Apps registering themselves (RFC 7591), with a token an admin made for that: the UwUSuite's
//! pairing builds on it (stage 4). Without a token, nothing registers: this is not a public
//! server where anybody's app may come along.

use super::{oauth_error, open_to_all};
use crate::crypto::sha256;
use crate::routes::apps::{NewApp, check_new, check_uri, make};
use crate::{AppState, audit};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Registration {
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    backchannel_logout_uri: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
    id_token_signed_response_alg: Option<String>,
    client_uri: Option<String>,
    scope: Option<String>,
}

/// What marks an app that registered itself: it asks people before it gets their data, it is not
/// in anybody's "My apps", and its back-channel address has to be a public one.
pub const REGISTERED: &str = "registered";

pub async fn register(
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
    let Some(token) = crate::session::bearer(&headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token", "registering needs a token from an admin");
    };
    let Ok(request) = serde_json::from_slice::<Registration>(&body) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", "the registration is not JSON");
    };
    let allowed = ["authorization_code", "refresh_token", "client_credentials", super::token::DEVICE_GRANT];
    let grants =
        request.grant_types.clone().unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    if grants.iter().any(|grant| !allowed.contains(&grant.as_str()))
        || request.response_types.as_ref().is_some_and(|types| types.iter().any(|t| t != "code"))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only code, refresh, client credentials and device grants are offered",
        );
    }
    for uri in request.redirect_uris.iter().chain(&request.post_logout_redirect_uris) {
        if let Err(message) = check_uri(uri) {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", &message);
        }
    }
    if let Some(uri) = request.backchannel_logout_uri.as_deref().filter(|uri| !uri.is_empty()) {
        let literal_private = url::Url::parse(uri)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.trim_start_matches('[').trim_end_matches(']').to_string()))
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| !super::logout::public_ip(ip));
        if !uri.starts_with("https://") || check_uri(uri).is_err() || literal_private {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "backchannel_logout_uri has to be a public https address",
            );
        }
    }
    if grants.iter().any(|grant| grant == "authorization_code") && request.redirect_uris.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", "at least one redirect_uri is needed");
    }
    let public = request.token_endpoint_auth_method.as_deref() == Some("none");
    let method = match request.token_endpoint_auth_method.as_deref() {
        Some("client_secret_post") => "client_secret_post",
        Some("none") => "none",
        _ => "client_secret_basic",
    };
    let mut new = NewApp {
        name: request.client_name.clone().unwrap_or_default(),
        template: Some(REGISTERED.into()),
        redirect_uris: request.redirect_uris.clone(),
        post_logout_redirect_uris: request.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: request.backchannel_logout_uri.clone(),
        grant_types: Some(grants.clone()),
        public,
        token_auth_method: Some(method.into()),
        id_token_alg: request.id_token_signed_response_alg.clone(),
        // Whoever has a registration token is not somebody everybody trusts: people agree
        // before such an app gets their data, and it is not in their "My apps".
        consent: true,
        launch_url: None,
        ..NewApp::default()
    };
    if let Err(error) = check_new(&state, &new).await {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", &error.message);
    }
    // The token counts only now that the request is good: a bad request does not use it up.
    let Ok(Some(used)) = state.store.use_registration_token(&sha256(token.as_bytes())).await else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "the registration token is unknown, used up or ran out",
        );
    };
    if new.name.trim().is_empty() {
        new.name = used.name.clone();
    }
    let (app, secret) = match make(&state, new, used.created_by.as_deref()).await {
        Ok(made) => made,
        Err(error) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", &error.message),
    };
    audit(
        &state,
        "app_registered",
        used.created_by.as_deref(),
        None,
        Some(&app.id),
        &ip,
        json!({ "name": app.name, "token": used.name }),
    )
    .await;
    let mut body = json!({
        "client_id": app.client_id,
        "client_id_issued_at": uwuauth_store::clock::parse(&app.created).map(|at| at.unix_timestamp()),
        "client_name": app.name,
        "redirect_uris": app.redirect_uris,
        "post_logout_redirect_uris": app.post_logout_redirect_uris,
        "backchannel_logout_uri": app.backchannel_logout_uri,
        "grant_types": app.grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": app.token_auth_method,
        "id_token_signed_response_alg": app.id_token_alg,
        "scope": request.scope,
    });
    if let Some(secret) = secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    open_to_all((StatusCode::CREATED, Json(body)).into_response())
}
