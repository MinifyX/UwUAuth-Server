//! A whole API in memory, for tests: a database in a temporary directory of its own, a mailer
//! that keeps what it sends, cheap hashing and limits nobody runs into. Requests go straight
//! into the router, without a socket; a [`Browser`] keeps its cookies like a real one.

use crate::routes::invitations::{InviteFields, invite};
use crate::webauthn::tests::SoftKey;
use crate::{ApiConfig, AppState, HashCost, Limits, LogBuffer, Settings, router};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;
use uwuauth_mail::Mailer;
use uwuauth_store::Store;

pub(crate) const PUBLIC: &str = "https://auth.example.com";

pub(crate) struct TestServer {
    pub router: Router,
    pub state: AppState,
    _dir: tempfile::TempDir,
}

impl TestServer {
    pub(crate) async fn new() -> Self {
        Self::with(|_| {}).await
    }

    /// With the configuration changed first: another HIBP, other settings.
    pub(crate) async fn with(change: impl FnOnce(&mut ApiConfig)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("uwuauth.db"), &uwuauth_store::Options { readers: 2 }).unwrap();
        let mut config = ApiConfig::new(PUBLIC, dir.path().to_path_buf());
        config.hash_cost = HashCost::cheap();
        config.hibp_url = "http://127.0.0.1:9".into();
        config.start_settings = Settings { setup_done: true, ..Settings::default() };
        change(&mut config);
        let mut state = AppState::new(store, config, "0.0.0-test", LogBuffer::new(100)).await.unwrap();
        state.mailer = Mailer::capturing();
        state.limits = Arc::new(Limits::generous());
        Self { router: router(state.clone()), state, _dir: dir }
    }

    pub(crate) async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(request).await.unwrap()
    }

    pub(crate) async fn get(&self, path: &str) -> Response<Body> {
        self.send(Request::get(path).body(Body::empty()).unwrap()).await
    }

    pub(crate) fn browser(&self) -> Browser<'_> {
        Browser { server: self, cookies: Mutex::new(BTreeMap::new()) }
    }

    /// An invitation link's token, made the way the portal makes one.
    pub(crate) async fn invitation(&self, fields: InviteFields) -> String {
        let body = invite(&self.state, None, fields).await.unwrap();
        token_of(body["link"].as_str().unwrap())
    }

    /// A signed-in browser of a new person with a password, made through an invitation.
    pub(crate) async fn person(&self, username: &str, admin: bool) -> Browser<'_> {
        let token = self.invitation(InviteFields { admin, ..InviteFields::default() }).await;
        let browser = self.browser();
        let response = browser
            .post(
                &format!("/uwu/v1/links/invite/{token}"),
                json!({ "username": username, "displayName": username, "password": PASSWORD }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        browser
    }

    /// The last mail sent to `to`.
    pub(crate) fn mail_to(&self, to: &str) -> Option<uwuauth_mail::Sent> {
        self.state.mailer.sent().into_iter().rev().find(|mail| mail.to == to)
    }
}

pub(crate) const PASSWORD: &str = "correct horse battery";

/// The token in a link like `https://…/#/invite?token=…`.
pub(crate) fn token_of(link: &str) -> String {
    link.split("token=").nth(1).unwrap().split('&').next().unwrap().to_string()
}

/// Something that talks to the server like a browser: keeps cookies, sends its origin.
pub(crate) struct Browser<'a> {
    pub server: &'a TestServer,
    cookies: Mutex<BTreeMap<String, String>>,
}

impl Browser<'_> {
    pub(crate) async fn request(&self, method: &str, path: &str, body: Option<Value>) -> Response<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", PUBLIC)
            .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0");
        let cookies =
            self.cookies.lock().iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("; ");
        if !cookies.is_empty() {
            request = request.header("cookie", cookies);
        }
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = self.server.send(request.body(body).unwrap()).await;
        for value in response.headers().get_all("set-cookie") {
            let text = value.to_str().unwrap();
            let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if value.is_empty() || attributes.contains("Max-Age=0") {
                self.cookies.lock().remove(name);
            } else {
                self.cookies.lock().insert(name.to_string(), value.to_string());
            }
        }
        response
    }

    pub(crate) async fn get(&self, path: &str) -> Response<Body> {
        self.request("GET", path, None).await
    }

    pub(crate) async fn post(&self, path: &str, body: Value) -> Response<Body> {
        self.request("POST", path, Some(body)).await
    }

    /// GET, expecting 200, as JSON.
    pub(crate) async fn json(&self, path: &str) -> Value {
        let response = self.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        json(response).await
    }

    /// `method` with a JSON body, expecting a success, the answer as JSON (null for none).
    pub(crate) async fn ok(&self, method: &str, path: &str, body: Value) -> Value {
        let response = self.request(method, path, Some(body)).await;
        let status = response.status();
        let text = text(response).await;
        assert!(status.is_success(), "{method} {path}: {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    pub(crate) fn cookie(&self, name: &str) -> Option<String> {
        self.cookies.lock().get(name).cloned()
    }

    pub(crate) fn forget_cookies(&self) {
        self.cookies.lock().clear();
    }

    /// Add a passkey (made in software) to the signed-in person.
    pub(crate) async fn add_passkey(&self) -> SoftKey {
        let key = SoftKey::new();
        let options = self.ok("POST", "/uwu/v1/me/passkeys/options", json!({})).await;
        let credential = key.create(&options, PUBLIC);
        self.ok("POST", "/uwu/v1/me/passkeys", json!({ "credential": credential, "name": "Laptop" })).await;
        key
    }
}

pub(crate) async fn json(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub(crate) async fn text(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}
