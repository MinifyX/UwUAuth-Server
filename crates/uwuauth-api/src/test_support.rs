//! A whole API in memory, for tests: a database in a temporary directory of its own, and
//! requests straight into the router, without a socket.

use crate::{ApiConfig, AppState, LogBuffer, router};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response};
use serde_json::Value;
use tower::ServiceExt;
use uwuauth_store::Store;

pub(crate) struct TestServer {
    pub router: Router,
    _dir: tempfile::TempDir,
}

impl TestServer {
    pub(crate) async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("uwuauth.db"), &uwuauth_store::Options { readers: 2 }).unwrap();
        let config = ApiConfig {
            public: "https://auth.example.com".into(),
            trust_forwarded: false,
            backups: dir.path().join("backups"),
            data: dir.path().to_path_buf(),
        };
        let state = AppState::new(store, config, "0.0.0-test", LogBuffer::new(100)).await.unwrap();
        Self { router: router(state), _dir: dir }
    }

    pub(crate) async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(request).await.unwrap()
    }

    pub(crate) async fn get(&self, path: &str) -> Response<Body> {
        self.send(Request::get(path).body(Body::empty()).unwrap()).await
    }
}

/// The body of a response, as JSON.
pub(crate) async fn json(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
