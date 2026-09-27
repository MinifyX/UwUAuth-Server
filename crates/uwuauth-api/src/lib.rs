//! UwUAuth Server's HTTP side.
//!
//! Everything that speaks HTTP shares one router:
//!
//! - **UwUAuth's own API** under `/uwu/v1`: what the web app, scripts and the other UwUSuite
//!   programs use. In stage 0 it only says what this server is.
//! - **The protocols that speak HTTP**, as they come: OpenID Connect and OAuth 2 (stage 2),
//!   the UwUSuite pairing (stage 4), forward auth for reverse proxies (stage 5), SAML (stage 6),
//!   SCIM (stage 7). LDAP and RADIUS are not HTTP and get listeners of their own.
//! - **The web app** at `/`: sign-in pages, the self-service portal and the admin portal, from
//!   the files built into the binary.

mod errors;
mod health;
mod info;
mod logs;
mod web;

pub use logs::{LogBuffer, LogLine};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use uwuauth_store::Store;

/// What the API is told by the program around it.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// How people and apps reach this server: `https://auth.example.com`. The issuer of every
    /// token later on, so it has to be right from the start.
    pub public: String,
    /// Trust `X-Forwarded-For` for the address a request comes from.
    pub trust_forwarded: bool,
    /// Where backups go.
    pub backups: PathBuf,
    /// The data directory.
    pub data: PathBuf,
}

/// What the last look for a newer release found, for the admin portal.
#[derive(Debug, Clone, Default)]
pub struct UpdateInfo {
    /// When it was looked last, in the database's time format.
    pub checked: Option<String>,
    /// A newer release on this machine's channel.
    pub newer: Option<String>,
    pub url: Option<String>,
    /// For a build of main: how many commits main is ahead.
    pub commits: Option<u32>,
    pub error: Option<String>,
    /// What this machine follows: `latest`, `beta`, `edge` or a version.
    pub channel: Option<String>,
    pub commit: Option<String>,
}

/// What every request handler can reach. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub version: &'static str,
    pub config: Arc<ApiConfig>,
    pub logs: Arc<LogBuffer>,
    pub update: Arc<RwLock<UpdateInfo>>,
    pub started: std::time::Instant,
}

impl AppState {
    pub async fn new(
        store: Store,
        config: ApiConfig,
        version: &'static str,
        logs: Arc<LogBuffer>,
    ) -> Result<Self, String> {
        Ok(AppState {
            store,
            version,
            config: Arc::new(config),
            logs,
            update: Arc::default(),
            started: std::time::Instant::now(),
        })
    }
}

/// The largest request body anything takes so far.
const BODY_LIMIT: usize = 2 * 1024 * 1024;

/// A request that has not been answered after this long is answered with 408, rather than
/// holding its connection for ever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn router(state: AppState) -> Router {
    // Served over https (by this server or a proxy in front), the browser is told to never try
    // plain http for it again: a first visit by http is where a network could slip in a sign-in
    // page of its own.
    let https = state.config.public.starts_with("https://");
    let router = Router::new()
        .merge(health::routes())
        .merge(info::routes())
        .merge(web::routes())
        .fallback(web::fallback)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        .with_state(state)
        // JSON shrinks to a fraction of itself; the web app's files come compressed already.
        .layer(CompressionLayer::new().gzip(true).br(true))
        .layer(header("x-content-type-options", "nosniff"))
        .layer(header("referrer-policy", "same-origin"))
        .layer(header("x-robots-tag", "noindex, nofollow"))
        .layer(header("x-frame-options", "DENY"))
        .layer(header("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"))
        .layer(header("cache-control", "no-store"));
    if https { router.layer(header("strict-transport-security", "max-age=63072000")) } else { router }
}

fn header(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(HeaderName::from_static(name), HeaderValue::from_static(value))
}

#[cfg(test)]
pub(crate) mod test_support;
