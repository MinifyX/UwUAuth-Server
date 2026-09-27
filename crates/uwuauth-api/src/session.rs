//! Who is asking: the session cookie of a signed-in browser, an API token of a script, and where
//! the request comes from.
//!
//! - The **session cookie** holds 32 random bytes; the database keeps their SHA-256. It is
//!   `HttpOnly`, `SameSite=Lax` and, over https, `Secure`. Without "stay signed in" it lasts as
//!   long as the browser and runs out on the server after `sessionHours` without use; with it,
//!   `rememberDays`.
//! - A session carries the person's **security stamp** from when it began: a new password, a
//!   disabled account or "sign out everywhere" changes the stamp, and every older session stops.
//! - A **restricted** session belongs to somebody who has to set up a second factor first (a
//!   group they are in asks for one). It reaches their own security settings and nothing else.
//! - Changing how one signs in asks for a **recent** proof of who one is: within the last ten
//!   minutes, or again.
//! - Requests that change something and come with the cookie have to come from this server's
//!   own pages: their `Origin` is checked (see [`csrf`]). Scripts use an API token instead and
//!   send no cookie.

use crate::AppState;
use crate::crypto::{random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};
use uwuauth_store::{ApiToken, Person, Session, clock};

pub const SESSION_COOKIE: &str = "uwuauth_session";
pub const DEVICE_COOKIE: &str = "uwuauth_device";

/// How long a proof of who one is counts as recent.
pub const FRESH_SECONDS: i64 = 10 * 60;

// ── Where a request comes from ────────────────────────────

/// The address a request comes from: the peer's, or behind a trusted proxy the last one in
/// `X-Forwarded-For` (or `X-Real-IP`).
///
/// The last, not the first: a proxy like nginx with `$proxy_add_x_forwarded_for` appends the
/// address it sees to whatever the client sent, so everything before that is the client's to
/// make up — and with it, a fresh rate limit on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts, state.config.trust_forwarded)))
    }
}

pub(crate) fn client_ip(parts: &Parts, trust_forwarded: bool) -> IpAddr {
    if trust_forwarded {
        let forwarded_for = parts.headers.get_all("x-forwarded-for").into_iter().next_back();
        let forwarded = forwarded_for
            .and_then(|value| value.to_str().ok())
            .and_then(|list| list.rsplit(',').next())
            .or_else(|| parts.headers.get("x-real-ip").and_then(|value| value.to_str().ok()))
            .and_then(|value| value.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return canonical(ip);
        }
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| canonical(info.0.ip()))
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The browser's `User-Agent`, cut short.
pub fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers.get("user-agent").and_then(|value| value.to_str().ok()).map(|agent| agent.chars().take(300).collect())
}

// ── Cookies ───────────────────────────────────────────────

/// The value of cookie `name`.
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
}

/// A `Set-Cookie` value: `max_age` in seconds, none for a cookie that ends with the browser.
pub fn set_cookie(state: &AppState, name: &str, value: &str, max_age: Option<i64>) -> HeaderValue {
    let secure = if state.config.public.starts_with("https://") { "; Secure" } else { "" };
    let age = max_age.map(|seconds| format!("; Max-Age={seconds}")).unwrap_or_default();
    HeaderValue::from_str(&format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax{secure}{age}"))
        .expect("cookie values are base64url")
}

/// The browser's device id, made now if it has none: `(id, Set-Cookie if new)`.
pub fn device(state: &AppState, headers: &HeaderMap) -> (String, Option<HeaderValue>) {
    match cookie(headers, DEVICE_COOKIE).filter(|id| id.len() <= 64) {
        Some(id) => (id.to_string(), None),
        None => {
            let id = random_token(16);
            let header = set_cookie(state, DEVICE_COOKIE, &id, Some(400 * 86_400));
            (id, Some(header))
        }
    }
}

// ── Starting a session ────────────────────────────────────

/// How somebody signed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignIn {
    Password,
    Totp,
    Recovery,
    Passkey,
}

impl SignIn {
    /// As OpenID Connect's `amr` spells it (RFC 8176).
    pub fn amr(self) -> &'static str {
        match self {
            SignIn::Password => "pwd",
            SignIn::Totp => "otp",
            SignIn::Recovery => "kba",
            SignIn::Passkey => "hwk",
        }
    }
}

/// A session that was just started.
pub struct Started {
    /// For the answer: the session cookie, and the device cookie for a browser that had none.
    pub cookies: Vec<HeaderValue>,
    /// The browser's device id.
    pub device_id: String,
}

/// Start a session for `person`: the row in the database, and the cookies for the answer.
pub async fn start(
    state: &AppState,
    person: &Person,
    methods: &[SignIn],
    remember: bool,
    restricted: bool,
    ip: IpAddr,
    headers: &HeaderMap,
) -> ApiResult<Started> {
    let settings = state.settings();
    let token = random_token(32);
    let lasts =
        if remember { i64::from(settings.remember_days) * 86_400 } else { i64::from(settings.session_hours) * 3600 };
    let now = clock::now();
    let (device_id, device_cookie) = device(state, headers);
    let mut amr: Vec<&str> = methods.iter().map(|method| method.amr()).collect();
    if methods.len() > 1 || methods.contains(&SignIn::Passkey) {
        amr.push("mfa");
    }
    state
        .store
        .create_session(Session {
            id: sha256(token.as_bytes()),
            person_id: person.id.clone(),
            created: now.clone(),
            last_seen: now.clone(),
            expires: clock::in_seconds(lasts),
            auth_time: now,
            methods: serde_json::to_string(&amr).unwrap_or_else(|_| "[]".into()),
            restricted,
            remember,
            stamp: person.security_stamp.clone(),
            device_id: Some(device_id.clone()),
            ip: Some(ip.to_string()),
            user_agent: user_agent(headers),
        })
        .await?;
    let mut cookies = vec![set_cookie(state, SESSION_COOKIE, &token, remember.then_some(lasts))];
    cookies.extend(device_cookie);
    Ok(Started { cookies, device_id })
}

/// A response with these cookies set.
pub fn with_cookies(mut response: Response, cookies: Vec<HeaderValue>) -> Response {
    for cookie in cookies {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    response
}

// ── The session of a request ──────────────────────────────

/// A signed-in person, their session, and whether they are an admin.
#[derive(Debug, Clone)]
pub struct Me {
    pub person: Person,
    pub session: Session,
    pub admin: bool,
}

impl Me {
    /// The methods of this session, as `amr`.
    pub fn methods(&self) -> Vec<String> {
        serde_json::from_str(&self.session.methods).unwrap_or_default()
    }

    /// Whether they proved who they are within the last ten minutes.
    pub fn fresh(&self) -> bool {
        clock::parse(&self.session.auth_time)
            .is_some_and(|at| (time::OffsetDateTime::now_utc() - at).whole_seconds() < FRESH_SECONDS)
    }

    /// For what needs a recent proof: an error that makes the web app ask for one.
    pub fn require_fresh(&self) -> ApiResult<()> {
        if self.fresh() { Ok(()) } else { Err(ApiError::reauth()) }
    }
}

async fn signed_in(parts: &Parts, state: &AppState) -> ApiResult<Me> {
    let token = cookie(&parts.headers, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
    let id = sha256(token.as_bytes());
    let session = state.store.session(&id).await?.ok_or_else(ApiError::unauthorized)?;
    let person = state.store.person(&session.person_id).await?.ok_or_else(ApiError::unauthorized)?;
    if !person.active() || person.security_stamp != session.stamp {
        state.store.end_session(&id).await?;
        return Err(ApiError::unauthorized());
    }
    // Seen again: at most once a minute, the row is written.
    let stale =
        clock::parse(&session.last_seen).is_none_or(|at| (time::OffsetDateTime::now_utc() - at).whole_seconds() > 60);
    if stale {
        let settings = state.settings();
        let lasts = if session.remember {
            i64::from(settings.remember_days) * 86_400
        } else {
            i64::from(settings.session_hours) * 3600
        };
        let ip = client_ip(parts, state.config.trust_forwarded).to_string();
        state.store.touch_session(&id, &ip, &clock::in_seconds(lasts)).await?;
    }
    let admin = state.store.admin_ids().await?.contains(&person.id);
    Ok(Me { person, session, admin })
}

impl FromRequestParts<AppState> for Me {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let me = signed_in(parts, state).await?;
        if me.session.restricted {
            return Err(ApiError::forbidden("Set up a second way to sign in first.")
                .with_detail(serde_json::json!({ "restricted": true })));
        }
        Ok(me)
    }
}

/// A signed-in person whose session may still be restricted: for their own security settings,
/// where they set up what they need.
#[derive(Debug, Clone)]
pub struct MeSetup(pub Me);

impl FromRequestParts<AppState> for MeSetup {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        signed_in(parts, state).await.map(MeSetup)
    }
}

/// Who runs the server: a signed-in admin, or a script with an API token (a read-only token only
/// for reading).
#[derive(Debug, Clone)]
pub enum AdminOnly {
    Person(Box<Me>),
    Token(ApiToken),
}

impl AdminOnly {
    /// For the event log: the person's id, or `token:<id>`.
    pub fn actor_id(&self) -> String {
        match self {
            AdminOnly::Person(me) => me.person.id.clone(),
            AdminOnly::Token(token) => format!("token:{}", token.id),
        }
    }

    pub fn person(&self) -> Option<&Person> {
        match self {
            AdminOnly::Person(me) => Some(&me.person),
            AdminOnly::Token(_) => None,
        }
    }
}

/// The bearer token of a request, if it has one.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token.trim()).filter(|token| !token.is_empty())
}

impl FromRequestParts<AppState> for AdminOnly {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if let Some(token) = bearer(&parts.headers).filter(|token| token.starts_with(crate::tokens::PREFIX)) {
            let found =
                state.store.use_api_token(sha256(token.as_bytes())).await?.ok_or_else(ApiError::unauthorized)?;
            if found.read_only && parts.method != Method::GET && parts.method != Method::HEAD {
                return Err(ApiError::forbidden("This token may only read."));
            }
            return Ok(AdminOnly::Token(found));
        }
        let me = Me::from_request_parts(parts, state).await?;
        if !me.admin {
            return Err(ApiError::forbidden("Only admins can do this."));
        }
        Ok(AdminOnly::Person(Box::new(me)))
    }
}

// ── Cross-site requests ───────────────────────────────────

/// Requests that change something and carry the session cookie have to come from this server's
/// own pages. `SameSite=Lax` keeps the cookie off cross-site POSTs already; this is the second
/// lock, for browsers and paths where that is not enough.
pub(crate) async fn csrf(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let unsafe_method = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let headers = request.headers();
    if unsafe_method && cookie(headers, SESSION_COOKIE).is_some() && bearer(headers).is_none() {
        let origin = headers.get("origin").and_then(|value| value.to_str().ok());
        let same_site = headers.get("sec-fetch-site").and_then(|value| value.to_str().ok()) == Some("same-origin");
        let ours = match origin {
            Some(origin) => origin.trim_end_matches('/') == state.config.public,
            None => same_site,
        };
        if !ours {
            return ApiError::forbidden("This request did not come from this server's pages.").into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_are_found_by_name() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "a=1; uwuauth_session=abc; b=2".parse().unwrap());
        assert_eq!(cookie(&headers, SESSION_COOKIE), Some("abc"));
        assert_eq!(cookie(&headers, "b"), Some("2"));
        assert_eq!(cookie(&headers, "c"), None);
        headers.insert(COOKIE, "uwuauth_session=".parse().unwrap());
        assert_eq!(cookie(&headers, SESSION_COOKIE), None);
    }

    #[test]
    fn a_bearer_token_is_read_whatever_the_case() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "bearer uwu_abc".parse().unwrap());
        assert_eq!(bearer(&headers), Some("uwu_abc"));
        headers.insert("authorization", "Basic abc".parse().unwrap());
        assert_eq!(bearer(&headers), None);
    }

    #[test]
    fn behind_a_proxy_the_address_it_added_counts() {
        let parts = |headers: &[(&str, &str)]| {
            let mut request = axum::http::Request::get("/");
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let mut parts = request.body(()).unwrap().into_parts().0;
            parts.extensions.insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
            parts
        };
        let spoofed = parts(&[("x-forwarded-for", "203.0.113.9, 198.51.100.7")]);
        assert_eq!(client_ip(&spoofed, true), IpAddr::from([198, 51, 100, 7]));
        assert_eq!(client_ip(&spoofed, false), IpAddr::from([127, 0, 0, 1]), "not believed unless trusted");
        let real = parts(&[("x-real-ip", "198.51.100.8")]);
        assert_eq!(client_ip(&real, true), IpAddr::from([198, 51, 100, 8]));
    }
}
