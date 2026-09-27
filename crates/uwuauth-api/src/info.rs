//! `/uwu/v1/server`: what this server is and what it speaks.
//!
//! The first thing another UwUSuite program asks when somebody types this server's address into
//! it — before pairing (stage 4), it has to know that a UwUAuth answers there and which of the
//! protocols it may use. The list grows with every stage; an app looks for what it needs in it
//! and never assumes.

use crate::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/server", get(server))
}

/// The protocols this build speaks. Empty until stage 2 brings OpenID Connect.
const PROTOCOLS: &[&str] = &[];

async fn server(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "product": "UwUAuth Server",
        "version": state.version,
        "issuer": state.config.public,
        "protocols": PROTOCOLS,
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
        assert_eq!(body["product"], "UwUAuth Server");
        assert_eq!(body["version"], "0.0.0-test");
        assert_eq!(body["issuer"], "https://auth.example.com");
        assert!(body["protocols"].is_array());
    }
}
