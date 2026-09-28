//! UwUAuth Server's HTTP side.
//!
//! Everything that speaks HTTP shares one router:
//!
//! - **UwUAuth's own API** under `/uwu/v1`: signing in, the self-service portal (`/uwu/v1/me`),
//!   the admin portal (people, groups, invitations, settings, …) and scripts with API tokens.
//! - **The protocols that speak HTTP**, as they come: OpenID Connect and OAuth 2 (stage 2),
//!   the UwUSuite pairing (stage 4), forward auth for reverse proxies (stage 5), SAML (stage 6),
//!   SCIM (stage 7). LDAP and RADIUS are not HTTP and get listeners of their own.
//! - **The web app** at `/`: sign-in pages, the self-service portal and the admin portal, from
//!   the files built into the binary.

pub mod crypto;
mod errors;
mod health;
pub mod hibp;
mod info;
pub mod limits;
mod logs;
pub mod memory;
pub mod oidc;
pub mod policy;
pub mod routes;
pub mod session;
pub mod settings;
pub mod tokens;
pub mod totp;
mod web;
pub mod webauthn;

pub use crypto::HashCost;
pub use errors::{ApiError, ApiResult};
pub use limits::Limits;
pub use logs::{LogBuffer, LogLine};
pub use settings::Settings;

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
use uwuauth_mail::Mailer;
use uwuauth_store::Store;

/// What the API is told by the program around it.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// How people and apps reach this server: `https://auth.example.com`. The issuer of every
    /// token, the origin of every passkey, and what links in mails point to.
    pub public: String,
    /// Trust `X-Forwarded-For` for the address a request comes from.
    pub trust_forwarded: bool,
    /// Where backups go.
    pub backups: PathBuf,
    /// The data directory.
    pub data: PathBuf,
    pub hash_cost: HashCost,
    /// Have I Been Pwned's range API.
    pub hibp_url: String,
    /// Sign-ins one address may try at once.
    pub login_attempts: u32,
    /// Where a new server starts, until an admin saves settings.
    pub start_settings: Settings,
    /// An RSA key to sign with instead of making one (tests: making one takes a while).
    pub fixed_rsa_key: Option<Vec<u8>>,
    pub ldap: Option<LdapInfo>,
}

impl ApiConfig {
    /// For tests and tools: sensible values for a server at `public` with data in `data`.
    pub fn new(public: &str, data: PathBuf) -> Self {
        ApiConfig {
            public: public.trim_end_matches('/').to_string(),
            trust_forwarded: false,
            backups: data.join("backups"),
            data,
            hash_cost: HashCost::default(),
            hibp_url: "https://api.pwnedpasswords.com".into(),
            login_attempts: 10,
            start_settings: Settings::default(),
            fixed_rsa_key: None,
            ldap: None,
        }
    }
}

/// How LDAP is set up, for the admin portal. None when it is off.
#[derive(Debug, Clone)]
pub struct LdapInfo {
    pub base: String,
    pub domain: String,
    pub ldap: Option<std::net::SocketAddr>,
    pub ldaps: Option<std::net::SocketAddr>,
    pub plain_bind: bool,
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
    pub settings: Arc<RwLock<Settings>>,
    pub mailer: Mailer,
    pub sealer: Arc<crypto::Sealer>,
    pub limits: Arc<Limits>,
    /// Who WebAuthn is for: this server's host and origin.
    pub party: webauthn::Party,
    pub memory: Arc<memory::Memory>,
    /// The keys tokens are signed with, made on first use.
    pub keys: Arc<tokio::sync::OnceCell<oidc::keys::Keys>>,
}

impl AppState {
    /// Everything the API needs, with the settings from the database and the sealing key from
    /// the data directory.
    pub async fn new(
        store: Store,
        config: ApiConfig,
        version: &'static str,
        logs: Arc<LogBuffer>,
    ) -> Result<Self, String> {
        let sealer = crypto::Sealer::load(&config.data.join("secret.key"))?;
        let settings = Settings::load(&store, &sealer, &config.start_settings).await?;
        let mailer = Mailer::new(settings.smtp.as_ref()).map_err(|error| format!("mail: {error}"))?;
        let party = webauthn::Party::from_public(&config.public);
        let limits = Arc::new(Limits::with_login_attempts(config.login_attempts));
        Ok(AppState {
            store,
            version,
            config: Arc::new(config),
            logs,
            update: Arc::default(),
            started: std::time::Instant::now(),
            settings: Arc::new(RwLock::new(settings)),
            mailer,
            sealer: Arc::new(sealer),
            limits,
            party,
            memory: Arc::default(),
            keys: Arc::default(),
        })
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().clone()
    }

    /// A link into the web app: `/#/reset?token=…`.
    pub fn link(&self, path: &str) -> String {
        format!("{}/#{path}", self.config.public)
    }
}

/// Write an event down. A failure only goes to the log: nothing a person did should fail
/// because its note could not be written.
pub async fn audit(
    state: &AppState,
    kind: &str,
    actor: Option<&str>,
    person: Option<&str>,
    target: Option<&str>,
    ip: &std::net::IpAddr,
    detail: serde_json::Value,
) {
    let ip = ip.to_string();
    if let Err(error) = state.store.record(kind, actor, person, target, Some(&ip), &detail.to_string()).await {
        tracing::warn!(%error, kind, "an event could not be written down");
    }
}

/// The largest request body almost everything takes.
const BODY_LIMIT: usize = 512 * 1024;

/// An import brings a whole directory at once.
const IMPORT_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// A request that has not been answered after this long is answered with 408, rather than
/// holding its connection for ever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn router(state: AppState) -> Router {
    // Served over https (by this server or a proxy in front), the browser is told to never try
    // plain http for it again: a first visit by http is where a network could slip in a sign-in
    // page of its own.
    let https = state.config.public.starts_with("https://");
    let imports = routes::admin::import_routes().layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT));
    let router = Router::new()
        .merge(health::routes())
        .merge(info::routes())
        .merge(settings::routes())
        .merge(routes::routes())
        .merge(oidc::routes())
        .merge(web::routes())
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .merge(imports)
        .fallback(web::fallback)
        .layer(axum::middleware::from_fn_with_state(state.clone(), session::csrf))
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

#[cfg(test)]
mod flows;
