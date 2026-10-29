//! Forward auth: a reverse proxy (Caddy's `forward_auth`, Traefik's `ForwardAuth`, nginx's
//! `auth_request`, Nginx Proxy Manager) asks UwUAuth for every request whether it may through,
//! for apps that know nothing of OpenID Connect.
//!
//! - `/uwu/v1/forward-auth` — the question. The proxy sends where the request goes
//!   (`X-Forwarded-Proto/Host/Uri/Method`, or nginx's `X-Original-URL/Method`) and the browser's
//!   cookies. 2xx with `Remote-User`, `Remote-Groups`, `Remote-Email` and `Remote-Name`: through.
//!   Not signed in: 302 to UwUAuth (303 for anything but GET and HEAD), and back afterwards.
//!   Not allowed: 403, and an event.
//! - `/uwu/v1/forward-auth/nginx` — the same, but 401 (with `Location`) instead of a redirect:
//!   `auth_request` only understands 2xx, 401 and 403.
//! - `/oauth/forward-auth?rd=<address>` — where the browser comes to sign in. It sets the
//!   forward-auth cookie and sends the browser back to `rd`, if `rd` is the address of a
//!   forward-auth app the cookie reaches.
//!
//! Which app a request is for: the app whose address (`host` or `host/path`) matches it most
//! closely; a longer path wins. A host no app names is refused.
//!
//! The forward-auth cookie is not the session cookie. With a cookie domain set it goes to every
//! host below that domain, and so to every app there: it only says "this session" (signed with the
//! server's key) and opens nothing but forward auth. The session cookie, which opens the portal
//! and the admin API, stays on this server's own host.

#[cfg(test)]
mod flows;

use crate::errors::ApiResult;
use crate::memory::Expiring;
use crate::oidc::authorize::{refusal, strong};
use crate::session::{ClientIp, Me, from_headers, from_session_id, set_cookie, with_cookies};
use crate::{AppState, audit};
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{any, get};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uwuauth_store::App;

/// The cookie forward auth reads.
pub const COOKIE: &str = "uwuauth_fa";

/// The template key of a forward-auth app.
pub const TEMPLATE: &str = "forward-auth";

/// How long an answer for a session and an app is kept: a changed group or a closed time window
/// counts after this long at the latest. Signing out counts at once.
const ANSWER_SECONDS: u64 = 10;

/// How long the list of forward-auth apps is kept (a change in the portal counts at once).
const RULES_SECONDS: u64 = 10;

/// One "not allowed" event per session (or address), app and reason in this time, not one for
/// every picture on the page.
const DENIED_EVENT_SECONDS: u64 = 5 * 60;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/forward-auth", any(check_redirect))
        .route("/uwu/v1/forward-auth/nginx", any(check_nginx))
        .route("/oauth/forward-auth", get(back))
}

// ── Addresses ─────────────────────────────────────────────

/// Whether `host` (without a port) is `domain` or below it.
pub fn within(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.');
    host == domain || host.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// A host without its port: `app.example.com:8443` → `app.example.com`, `[2001:db8::1]:443` →
/// `[2001:db8::1]`.
fn without_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(at) if !host[at..].contains(']') && host[at + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..at],
        _ => host,
    }
}

/// An app's address as it is kept: `host[:port]` in lower case, then the path prefix without a
/// trailing slash (nothing for the whole host). A scheme in front is dropped.
pub fn parse_address(text: &str) -> Result<(String, String), String> {
    let bad = || format!("{} is not an address like app.example.com or example.com/wiki.", text.trim());
    let text = text.trim();
    let rest = text.strip_prefix("https://").or_else(|| text.strip_prefix("http://")).unwrap_or(text);
    if rest.is_empty()
        || rest.len() > 300
        || rest.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#' | '@' | '*' | '\\'))
    {
        return Err(bad());
    }
    let (host, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };
    let host = host.to_ascii_lowercase();
    let name = without_port(&host);
    let port = &host[name.len()..];
    if !port.is_empty() && port[1..].parse::<u16>().is_err() {
        return Err(bad());
    }
    let label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    let ipv6 = name.strip_prefix('[').and_then(|inner| inner.strip_suffix(']'));
    let fine = match ipv6 {
        Some(inner) => inner.parse::<std::net::Ipv6Addr>().is_ok(),
        None => name.len() <= 253 && name.split('.').all(label),
    };
    if !fine {
        return Err(bad());
    }
    Ok((host, normalize_path(path).ok_or_else(bad)?))
}

/// The address as one string: `host[:port][/path]`.
pub fn address(text: &str) -> Result<String, String> {
    parse_address(text).map(|(host, path)| format!("{host}{path}"))
}

/// A request path the way the app behind the proxy will see it, for comparing: no query, `%xx`
/// decoded, no empty segments, no trailing slash. `/` is empty.
///
/// Nothing for a path apps read in different ways: an encoded `/`, `\`, `.`, `%` or `;`, a raw
/// `\` or `;` (path parameters), a `.` or `..` segment, a broken `%`. Which address such a path
/// falls under would be a guess, and a wrong guess lets a request past a stricter rule; it is
/// refused instead. Browsers never send these by themselves.
fn normalize_path(raw: &str) -> Option<String> {
    let raw = raw.split(['?', '#']).next().unwrap_or_default();
    if raw.contains(['\\', ';']) {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = |byte: Option<&u8>| byte.and_then(|byte| (*byte as char).to_digit(16));
            let (Some(high), Some(low)) = (hex(bytes.get(at + 1)), hex(bytes.get(at + 2))) else {
                return None;
            };
            let byte = (high * 16 + low) as u8;
            if matches!(byte, b'/' | b'\\' | b'.' | b'%' | b';' | b'?' | b'#') || byte.is_ascii_control() {
                return None;
            }
            decoded.push(byte);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    let mut path = String::new();
    for segment in decoded.split('/') {
        match segment {
            "" => {}
            "." | ".." => return None,
            segment => {
                path.push('/');
                path.push_str(segment);
            }
        }
    }
    Some(path)
}

/// Whether `path` is `prefix` or below it, by whole segments.
fn path_within(path: &str, prefix: &str) -> bool {
    prefix.is_empty() || path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// An address of a forward-auth app.
#[derive(Debug, Clone)]
struct Rule {
    app: Arc<App>,
    /// With the port, if the address names one.
    host: String,
    port: bool,
    path: String,
}

/// The app for a request to `host` (as the browser sent it, maybe with a port) and `path`
/// (normalized): the closest address, a longer path first, an address with a port before one
/// without.
fn closest<'a>(rules: &'a [Rule], host: &str, path: &str) -> Option<&'a Rule> {
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    let name = without_port(host);
    rules
        .iter()
        .filter(|rule| if rule.port { rule.host == host } else { rule.host == name })
        .filter(|rule| path_within(path, &rule.path))
        .max_by_key(|rule| (rule.path.len(), rule.port))
}

fn rules_of(apps: Vec<App>) -> Vec<Rule> {
    let mut rules = Vec::new();
    for app in apps.into_iter().filter(|app| !app.forward_auth.is_empty()) {
        let app = Arc::new(app);
        for entry in &app.forward_auth {
            if let Ok((host, path)) = parse_address(entry) {
                let port = without_port(&host).len() != host.len();
                rules.push(Rule { app: app.clone(), host, port, path });
            }
        }
    }
    rules
}

// ── What is kept in memory ────────────────────────────────

/// Answers and the list of apps, for a short while: a proxy asks for every request.
pub struct Cache {
    /// By `<session id>|<app id>`.
    answers: Expiring<Answer>,
    rules: Mutex<Option<(Instant, Arc<Vec<Rule>>)>>,
    /// Sessions and apps noted as signed in, by `<session id>|<app id>`.
    noted: Expiring<()>,
    /// "Not allowed" events written lately.
    denied: Expiring<()>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            answers: Expiring::new(Duration::from_secs(ANSWER_SECONDS)),
            rules: Mutex::new(None),
            noted: Expiring::new(Duration::from_secs(12 * 3600)),
            denied: Expiring::new(Duration::from_secs(DENIED_EVENT_SECONDS)),
        }
    }
}

impl Cache {
    /// An app changed: the list is read again at the next question.
    pub fn apps_changed(&self) {
        *self.rules.lock() = None;
        self.answers.forget(|_| true);
    }

    /// Sessions ended elsewhere (signing out everywhere, an admin, a new password): every answer
    /// is asked again. Rare enough that keeping track of whose answers they were is not worth it.
    pub fn sessions_ended(&self) {
        self.answers.forget(|_| true);
    }

    /// A session ended or signed in again: its answers are asked again.
    pub fn forget_session(&self, session_id: &[u8]) {
        let prefix = format!("{}|", crate::crypto::b64(session_id));
        self.answers.forget(|key| key.starts_with(&prefix));
    }
}

async fn rules(state: &AppState) -> ApiResult<Arc<Vec<Rule>>> {
    let cache = &state.memory.forward_auth;
    if let Some((at, rules)) = cache.rules.lock().as_ref()
        && at.elapsed() < Duration::from_secs(RULES_SECONDS)
    {
        return Ok(rules.clone());
    }
    let rules = Arc::new(rules_of(state.store.apps().await?));
    *cache.rules.lock() = Some((Instant::now(), rules.clone()));
    Ok(rules)
}

// ── The cookie ────────────────────────────────────────────

fn cookie_value(state: &AppState, session_id: &[u8]) -> String {
    let tag = state.sealer.sign(&[b"forward-auth:".as_slice(), session_id].concat());
    format!("{}.{}", crate::crypto::b64(session_id), crate::crypto::b64(&tag))
}

/// The session id in a forward-auth cookie, if the server signed it.
fn session_of(state: &AppState, value: &str) -> Option<Vec<u8>> {
    let (id, tag) = value.split_once('.')?;
    let (id, tag) = (crate::crypto::unb64(id)?, crate::crypto::unb64(tag)?);
    state.sealer.verify(&[b"forward-auth:".as_slice(), &id].concat(), &tag).then_some(id)
}

/// The cookie `name`, if the browser sent exactly one. Two mean another host below the cookie
/// domain set its own next to UwUAuth's ("cookie tossing"): neither is trusted.
fn only_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| value);
    let first = found.next()?;
    (found.next().is_none() && !first.is_empty()).then_some(first)
}

/// `; Domain=…` with a cookie domain set.
fn domain_attribute(state: &AppState) -> String {
    let domain = state.settings().cookie_domain;
    if domain.is_empty() { String::new() } else { format!("; Domain={domain}") }
}

fn set(state: &AppState, me: &Me) -> HeaderValue {
    let max_age = me.session.remember.then(|| i64::from(state.settings().remember_days) * 86_400);
    let plain = set_cookie(state, COOKIE, &cookie_value(state, &me.session.id), max_age);
    let text = format!("{}{}", plain.to_str().unwrap_or_default(), domain_attribute(state));
    HeaderValue::from_str(&text).unwrap_or(plain)
}

/// The `Set-Cookie` that takes the forward-auth cookie away again, for signing out.
pub fn clear(state: &AppState) -> HeaderValue {
    let plain = set_cookie(state, COOKIE, "", Some(0));
    let text = format!("{}{}", plain.to_str().unwrap_or_default(), domain_attribute(state));
    HeaderValue::from_str(&text).unwrap_or(plain)
}

// ── Where the request goes ────────────────────────────────

/// The request the proxy asks about.
#[derive(Debug, Clone)]
struct Target {
    method: Method,
    /// As the browser sent it, maybe with a port.
    host: String,
    /// The whole address, to come back to after signing in.
    url: String,
}

/// The last of a header's comma-separated values: the one the proxy closest to UwUAuth added.
fn last<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Where the request goes, from the headers of the one kind the endpoint is for: the other kind
/// may come straight from the browser (Caddy and Traefik pass headers on), so it is never read.
/// `path` is `None` for a path [`normalize_path`] refuses.
fn target(headers: &HeaderMap, style: Style) -> Option<(Target, Option<String>)> {
    let method_header = match style {
        Style::Redirect => "x-forwarded-method",
        Style::Nginx => "x-original-method",
    };
    let method = last(headers, method_header)
        .and_then(|method| Method::from_bytes(method.to_ascii_uppercase().as_bytes()).ok())
        .unwrap_or(Method::GET);
    if style == Style::Nginx {
        let original = headers.get("x-original-url").and_then(|value| value.to_str().ok())?.trim();
        let url = url::Url::parse(original).ok()?;
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str()?),
            None => url.host_str()?.to_string(),
        };
        let path = normalize_path(&original_path(original));
        return Some((Target { method, host, url: url.to_string() }, path));
    }
    let proto = last(headers, "x-forwarded-proto").unwrap_or("https").to_ascii_lowercase();
    let host = last(headers, "x-forwarded-host")
        .or_else(|| headers.get(header::HOST).and_then(|value| value.to_str().ok()))?
        .to_string();
    if host.len() > 300 || host.contains(['/', '\\', '@', '?', '#']) {
        return None;
    }
    let uri = headers.get("x-forwarded-uri").and_then(|value| value.to_str().ok()).unwrap_or("/");
    let uri = if uri.starts_with('/') { uri.to_string() } else { format!("/{uri}") };
    let proto = if proto == "http" { "http" } else { "https" };
    Some((Target { method, url: format!("{proto}://{host}{uri}"), host }, normalize_path(&uri)))
}

/// The path of an absolute address as it was written: `url` would resolve `..` and `%2e` its own
/// way, and the app behind the proxy might not.
fn original_path(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    after_scheme.find('/').map_or_else(|| "/".to_string(), |at| after_scheme[at..].to_string())
}

// ── The question ──────────────────────────────────────────

/// What UwUAuth says about a session and an app.
#[derive(Debug, Clone)]
enum Answer {
    /// Through, with these headers for the app.
    Allow(Vec<(&'static str, Vec<u8>)>),
    /// Not this app: why.
    Deny(&'static str),
    /// Signed in, but the app wants a second factor.
    Mfa,
}

/// How the proxy wants "sign in first" said.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Redirect,
    Nginx,
}

async fn check_redirect(state: State<AppState>, ip: ClientIp, headers: HeaderMap) -> Response {
    check(state, ip, headers, Style::Redirect).await
}

async fn check_nginx(state: State<AppState>, ip: ClientIp, headers: HeaderMap) -> Response {
    check(state, ip, headers, Style::Nginx).await
}

async fn check(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap, style: Style) -> Response {
    match decide(&state, ip, &headers, style).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn decide(state: &AppState, ip: IpAddr, headers: &HeaderMap, style: Style) -> ApiResult<Response> {
    let Some((target, path)) = target(headers, style) else {
        return Ok(forbidden(state, None, "unknown"));
    };
    // Keyed by the address asking, not by anything in the request: nobody fills the event log by
    // making up hosts or paths.
    let Some(path) = path else {
        denied_event(state, &format!("ip:{ip}"), None, None, "path", ip, &target, "").await;
        return Ok(forbidden(state, None, "unknown"));
    };
    let rules = rules(state).await?;
    let Some(rule) = closest(&rules, &target.host, &path) else {
        denied_event(state, &format!("ip:{ip}"), None, None, "unknown_host", ip, &target, &path).await;
        return Ok(forbidden(state, None, "unknown"));
    };
    let app = rule.app.clone();
    let session_id = only_cookie(headers, COOKIE).and_then(|value| session_of(state, value));
    let key = session_id.as_ref().map(|id| format!("{}|{}", crate::crypto::b64(id), app.id));
    let cached = key.as_deref().and_then(|key| state.memory.forward_auth.answers.peek(key));
    let answer = match cached {
        Some(answer) => answer,
        None => {
            let me = match &session_id {
                Some(id) => from_session_id(state, id, ip).await?.filter(|me| !me.session.restricted),
                None => None,
            };
            let Some(me) = me else { return Ok(sign_in_first(state, &target, style)) };
            let answer = answer_for(state, &app, &me, ip).await?;
            if let Some(key) = key.clone() {
                state.memory.forward_auth.answers.put(key, answer.clone());
            }
            if let Answer::Deny(reason) = &answer {
                let person = me.person.id.clone();
                let key = key.as_deref().unwrap_or_default();
                denied_event(state, key, Some(&person), Some(&app), reason, ip, &target, &path).await;
            }
            answer
        }
    };
    Ok(match answer {
        Answer::Allow(headers) => {
            let mut response = StatusCode::OK.into_response();
            for (name, value) in headers {
                if let Ok(value) = HeaderValue::from_bytes(&value) {
                    response.headers_mut().insert(HeaderName::from_static(name), value);
                }
            }
            response
        }
        Answer::Deny(reason) => forbidden(state, Some(&app), reason),
        Answer::Mfa => {
            let continue_to = back_path(&target.url);
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("reason", "mfa").append_pair("app", &app.name).append_pair("continue", &continue_to);
            go(&format!("{}/#/denied?{}", state.config.public, query.finish()), &target, style)
        }
    })
}

/// Whether `me` may use `app`, and what the app is told about them. The first time a session
/// gets through to an app, it is noted (for signing out, and "My apps") with an event.
async fn answer_for(state: &AppState, app: &App, me: &Me, ip: IpAddr) -> ApiResult<Answer> {
    if let Some(reason) = refusal(state, app, &me.person).await? {
        return Ok(Answer::Deny(reason));
    }
    if app.require_mfa && !strong(&me.methods()) {
        return Ok(Answer::Mfa);
    }
    let membership = state.store.membership().await?;
    let mine = membership.groups_of(&me.person.id);
    let mut names: Vec<String> = state
        .store
        .groups()
        .await?
        .into_iter()
        .filter(|group| mine.contains(&group.id))
        .map(|group| group.name)
        .collect();
    names.sort();
    let clean = |text: &str| -> Vec<u8> { text.chars().filter(|c| !c.is_control()).collect::<String>().into_bytes() };
    let headers = vec![
        ("remote-user", clean(&me.person.username)),
        ("remote-groups", clean(&names.join(","))),
        ("remote-email", clean(me.person.email.as_deref().unwrap_or_default())),
        ("remote-name", clean(&me.person.display_name)),
    ];
    let noted = format!("{}|{}", crate::crypto::b64(&me.session.id), app.id);
    if state.memory.forward_auth.noted.peek(&noted).is_none() {
        state.memory.forward_auth.noted.put(noted, ());
        let sid = crate::oidc::sid(&me.session.id);
        state.store.note_session_app(&sid, &app.id, &me.person.id).await?;
        audit(
            state,
            "app_login",
            Some(&me.person.id),
            Some(&me.person.id),
            Some(&app.id),
            &ip,
            json!({ "app": app.name, "via": "forward_auth" }),
        )
        .await;
    }
    Ok(Answer::Allow(headers))
}

/// "Not allowed" goes down as an event, once in a while per session (or address asking), app and
/// reason, and not too often per address at all. When the memory for that is full, nothing is
/// written: better a missing event than a flooded log.
#[allow(clippy::too_many_arguments)]
async fn denied_event(
    state: &AppState,
    key: &str,
    person: Option<&str>,
    app: Option<&App>,
    reason: &str,
    ip: IpAddr,
    target: &Target,
    path: &str,
) {
    let key = format!("{key}|{reason}");
    let denied = &state.memory.forward_auth.denied;
    if denied.peek(&key).is_some() || !denied.put(key, ()) || !state.limits.forward_auth.check(ip) {
        return;
    }
    let short = |text: &str, most: usize| text.chars().take(most).collect::<String>();
    audit(
        state,
        "forward_auth_denied",
        person,
        person,
        app.map(|app| app.id.as_str()),
        &ip,
        json!({
            "reason": reason,
            "app": app.map(|app| app.name.as_str()),
            "host": short(&target.host, 100),
            "path": if path.is_empty() { "/".to_string() } else { short(path, 200) },
            "method": target.method.as_str(),
        }),
    )
    .await;
}

/// `/oauth/forward-auth?rd=<url>`, as a path on this server.
fn back_path(url: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new()).append_pair("rd", url).finish();
    format!("/oauth/forward-auth?{query}")
}

fn sign_in_first(state: &AppState, target: &Target, style: Style) -> Response {
    go(&format!("{}{}", state.config.public, back_path(&target.url)), target, style)
}

/// Off to `location`: a redirect the browser follows, or for nginx a 401 that says where.
fn go(location: &str, target: &Target, style: Style) -> Response {
    let status = match style {
        Style::Nginx => StatusCode::UNAUTHORIZED,
        Style::Redirect if matches!(target.method, Method::GET | Method::HEAD) => StatusCode::FOUND,
        Style::Redirect => StatusCode::SEE_OTHER,
    };
    let mut response = status.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// 403, with a small page for a person who sees it.
fn forbidden(state: &AppState, app: Option<&App>, reason: &str) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("reason", reason);
    if let Some(app) = app {
        query.append_pair("app", &app.name);
    }
    let link = format!("{}/#/denied?{}", state.config.public, query.finish());
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
         <title>403</title><p>Not allowed here. · Hier geht es nicht weiter.</p>\
         <p><a href=\"{}\">UwUAuth</a></p>",
        escape(&link)
    );
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}

// ── Coming back from signing in ───────────────────────────

#[derive(Deserialize)]
struct Back {
    rd: Option<String>,
}

/// Why `rd` cannot be gone back to, or nothing. Only addresses of forward-auth apps that the
/// cookie reaches: no open redirect, and no loop between a proxy and a cookie it never gets.
fn check_return(state: &AppState, rules: &[Rule], rd: &str) -> Result<url::Url, &'static str> {
    if rd.len() > 4000 {
        return Err("bad");
    }
    let url = url::Url::parse(rd).map_err(|_| "bad")?;
    let https = state.config.public.starts_with("https://");
    match url.scheme() {
        "https" => {}
        "http" if !https => {}
        "http" => return Err("insecure"),
        _ => return Err("bad"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("bad");
    }
    let Some(name) = url.host_str() else { return Err("bad") };
    let name = name.to_ascii_lowercase();
    let host = match url.port() {
        Some(port) => format!("{name}:{port}"),
        None => name.clone(),
    };
    let path = normalize_path(&original_path(rd)).ok_or("bad")?;
    if closest(rules, &host, &path).is_none() {
        return Err("unknown");
    }
    let own = url::Url::parse(&state.config.public).ok().and_then(|public| public.host_str().map(str::to_string));
    let domain = state.settings().cookie_domain;
    let reached = own.as_deref() == Some(name.as_str()) || (!domain.is_empty() && within(&name, &domain));
    if !reached {
        return Err("cookie_domain");
    }
    Ok(url)
}

async fn back(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<Back>,
) -> ApiResult<Response> {
    let rd = query.rd.unwrap_or_default();
    let rules = rules(&state).await?;
    let url = match check_return(&state, &rules, &rd) {
        Ok(url) => url,
        Err(problem) => {
            let text = match problem {
                "cookie_domain" => {
                    "This app is outside the cookie domain set in UwUAuth's settings, so the browser would never \
                 show it the sign-in. · Diese App liegt außerhalb der Cookie-Domain in den Einstellungen von \
                 UwUAuth."
                }
                "insecure" => {
                    "UwUAuth runs on https, so its cookie never reaches an app on plain http. · UwUAuth läuft mit \
                 https, sein Cookie erreicht keine App über http."
                }
                "unknown" => "No forward-auth app has this address. · Keine Forward-Auth-App hat diese Adresse.",
                _ => return Ok(Redirect::to(&format!("{}/#/", state.config.public)).into_response()),
            };
            let body = format!(
                "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
             <title>UwUAuth</title><p>{}</p><p><a href=\"{}/#/\">UwUAuth</a></p>",
                escape(text),
                escape(&state.config.public)
            );
            return Ok((StatusCode::BAD_REQUEST, Html(body)).into_response());
        }
    };
    let me = from_headers(&state, &headers, ip).await?.filter(|me| !me.session.restricted);
    let Some(me) = me else {
        let mut login = url::form_urlencoded::Serializer::new(String::new());
        login.append_pair("continue", &back_path(&rd));
        return Ok(Redirect::to(&format!("{}/#/login?{}", state.config.public, login.finish())).into_response());
    };
    // Maybe just signed in again with a second factor: ask again.
    state.memory.forward_auth.forget_session(&me.session.id);
    // The address as parsed, not as written: what was checked is what the browser gets.
    Ok(with_cookies(Redirect::to(url.as_str()).into_response(), vec![set(&state, &me)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_addresses_are_kept_in_one_spelling() {
        assert_eq!(address("App.Example.COM").unwrap(), "app.example.com");
        assert_eq!(address("https://example.com/wiki/").unwrap(), "example.com/wiki");
        assert_eq!(address("app.example.com:8443/").unwrap(), "app.example.com:8443");
        assert_eq!(address("[2001:db8::1]/x").unwrap(), "[2001:db8::1]/x");
        for bad in
            ["", "user@app.example.com", "*.example.com", "app.example.com?x=1", "app .example.com", "-a.example"]
        {
            assert!(address(bad).is_err(), "{bad}");
        }
        assert!(address("app.example.com:99999").is_err());
    }

    #[test]
    fn forward_paths_are_compared_the_way_the_app_reads_them() {
        let norm = |path: &str| normalize_path(path);
        assert_eq!(norm("/").as_deref(), Some(""));
        assert_eq!(norm("/wiki/?q=1").as_deref(), Some("/wiki"));
        assert_eq!(norm("//wiki//page/").as_deref(), Some("/wiki/page"));
        assert_eq!(norm("/caf%C3%A9/a%20b").as_deref(), Some("/café/a b"));
        assert_eq!(norm("/wiki?next=/../admin").as_deref(), Some("/wiki"), "the query is not the path");
    }

    #[test]
    fn forward_paths_apps_read_in_different_ways_are_refused() {
        for path in [
            // Up from a stricter rule to a looser one …
            "/admin/../public",
            "/admin/..%2fpublic",
            "/admin/..%2Fpublic",
            "/admin/..\\public",
            "/admin/..%5cpublic",
            "/admin/%2e%2e/public",
            "/admin/%2E./public",
            // … and down into it.
            "/public/../admin",
            "/public/..%2fadmin",
            "/public/%2e%2e/admin",
            "/public%2fadmin",
            "/public\\admin",
            // Everything else apps disagree about.
            "/./admin",
            "/admin;x=1",
            "/admin%3bx",
            "/%252e%252e/admin",
            "/admin%",
            "/admin%zz",
            "/admin%00",
            "/admin%ff",
        ] {
            assert_eq!(normalize_path(path), None, "{path}");
        }
    }

    #[test]
    fn forward_hosts_lie_within_a_domain_by_whole_labels() {
        assert!(within("example.com", "example.com"));
        assert!(within("app.example.com", "example.com"));
        assert!(!within("badexample.com", "example.com"));
        assert!(!within("example.com.invalid", "example.com"));
        assert_eq!(without_port("app.example.com:8443"), "app.example.com");
        assert_eq!(without_port("[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(without_port("[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn forward_the_closest_address_wins() {
        let app = |id: &str, addresses: &[&str]| App {
            id: id.into(),
            forward_auth: addresses.iter().map(|a| a.to_string()).collect(),
            ..App::default()
        };
        let rules = rules_of(vec![
            app("site", &["example.com"]),
            app("wiki", &["example.com/wiki"]),
            app("admin", &["example.com/wiki/admin"]),
            app("alt", &["example.com:8443"]),
        ]);
        let found = |host: &str, path: &str| {
            closest(&rules, host, &normalize_path(path).unwrap()).map(|rule| rule.app.id.clone())
        };
        assert_eq!(found("example.com", "/"), Some("site".into()));
        assert_eq!(found("EXAMPLE.com:443", "/wiki/page"), Some("wiki".into()));
        assert_eq!(found("example.com", "/wiki/admin/x"), Some("admin".into()));
        assert_eq!(found("example.com", "/wikipedia"), Some("site".into()));
        assert_eq!(found("example.com:8443", "/wiki"), Some("wiki".into()));
        assert_eq!(found("example.com:8443", "/"), Some("alt".into()));
        assert_eq!(found("other.example.com", "/"), None);
    }

    #[test]
    fn forward_target_comes_only_from_the_endpoints_own_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "http, https".parse().unwrap());
        headers.insert("x-forwarded-host", "spoofed.example.net, app.example.com".parse().unwrap());
        headers.insert("x-forwarded-uri", "/b?x=1".parse().unwrap());
        headers.insert("x-forwarded-method", "post".parse().unwrap());
        // From the browser, passed on by Caddy or Traefik: never read on this endpoint.
        headers.insert("x-original-url", "https://open.example.com/".parse().unwrap());
        headers.insert("x-original-method", "GET".parse().unwrap());
        let (found, path) = target(&headers, Style::Redirect).unwrap();
        assert_eq!((found.host.as_str(), path.as_deref()), ("app.example.com", Some("/b")));
        assert_eq!(found.url, "https://app.example.com/b?x=1");
        assert_eq!(found.method, Method::POST);

        // nginx's endpoint reads only nginx's headers, and without them says no.
        let (found, path) = target(&headers, Style::Nginx).unwrap();
        assert_eq!((found.host.as_str(), path.as_deref()), ("open.example.com", Some("")));
        assert_eq!(found.method, Method::GET);
        headers.remove("x-original-url");
        assert!(target(&headers, Style::Nginx).is_none());

        let mut nginx = HeaderMap::new();
        nginx.insert("x-original-url", "https://app.example.com:8443/%2e%2e/c?y".parse().unwrap());
        let (found, path) = target(&nginx, Style::Nginx).unwrap();
        assert_eq!((found.host.as_str(), path), ("app.example.com:8443", None));
    }

    #[test]
    fn forward_cookie_counts_only_when_there_is_one() {
        let with = |cookies: &[&str]| {
            let mut headers = HeaderMap::new();
            for cookie in cookies {
                headers.append(header::COOKIE, cookie.parse().unwrap());
            }
            only_cookie(&headers, COOKIE).map(str::to_string)
        };
        assert_eq!(with(&["a=1; uwuauth_fa=x; b=2"]), Some("x".into()));
        assert_eq!(with(&["uwuauth_fa=x; uwuauth_fa=y"]), None);
        assert_eq!(with(&["uwuauth_fa=x", "uwuauth_fa=y"]), None);
        assert_eq!(with(&["uwuauth_fa="]), None);
        assert_eq!(with(&["a=1"]), None);
    }
}
