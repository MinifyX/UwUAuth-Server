//! `/uwu/v1/server`: what this server is and what it speaks, and `/.well-known/uwusuite`.
//!
//! The first thing another UwUSuite program asks when somebody types this server's address into
//! it — before pairing (stage 4), it has to know that a UwUAuth answers there and which of the
//! protocols it may use. The list grows with every stage; an app looks for what it needs in it
//! and never assumes.
//!
//! `/.well-known/uwusuite` is the same for finding servers: a suite app that knows only a domain
//! asks there (a reverse proxy can hand the path of the domain itself to UwUAuth), and learns
//! where the suite's servers are.

use crate::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/server", get(server)).route("/.well-known/uwusuite", get(suite))
}

async fn server(State(state): State<AppState>) -> Json<Value> {
    let public = &state.config.public;
    Json(json!({
        "product": "UwUAuth",
        "version": state.version,
        "name": state.settings.read().organization.clone(),
        "issuer": public,
        "protocols": if state.config.ldap.is_some() { json!(["oidc", "ldap", "scim"]) } else { json!(["oidc", "scim"]) },
        "openidConfiguration": format!("{public}/.well-known/openid-configuration"),
        "pairing": crate::suite::PAIRING_VERSION,
        "pair": format!("{public}/uwu/v1/pair"),
        "scim": true,
    }))
}

async fn suite(State(state): State<AppState>) -> Json<Value> {
    let public = &state.config.public;
    Json(json!({
        "uwusuite": 1,
        "servers": [{ "product": "UwUAuth", "url": public, "info": format!("{public}/uwu/v1/server") }],
    }))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestServer, json};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn the_server_says_what_it_is() {
        let server = TestServer::new().await;
        let response = server.get("/uwu/v1/server").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["product"], "UwUAuth");
        assert_eq!(body["version"], "0.0.0-test");
        assert_eq!(body["issuer"], "https://auth.example.com");
        assert!(body["protocols"].is_array());
        assert_eq!(body["pairing"], 1);
        assert_eq!(body["scim"], true);
        assert_eq!(body["pair"], "https://auth.example.com/uwu/v1/pair");
        let suite = json(server.get("/.well-known/uwusuite").await).await;
        assert_eq!(suite["servers"][0]["product"], "UwUAuth");
        assert_eq!(suite["servers"][0]["info"], "https://auth.example.com/uwu/v1/server");
    }
}
