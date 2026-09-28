//! `/oauth/authorize`: an app sends somebody here to sign in.
//!
//! In this order:
//!
//! 1. The app and where to send the answer. When either is wrong, nothing goes back to the app —
//!    it could be anybody's address — and the person sees why on UwUAuth's own page.
//! 2. The request itself (`response_type=code`, PKCE for apps without a secret). What is wrong
//!    from here on goes back to the app as an OAuth error.
//! 3. Who is signed in. Nobody, or `prompt=login`, or a sign-in older than `max_age`: off to the
//!    sign-in page, which comes back here afterwards.
//! 4. Whether they may use this app: the app's groups, their time windows, a second factor if the
//!    app asks for one.
//! 5. Whether they agreed, for apps that ask ("consent").
//! 6. A code for the app, good for one minute and once.

use super::{Pending, SCOPES, issuer, scopes, sid};
use crate::errors::{ApiError, ApiResult};
use crate::session::{ClientIp, Me, from_headers};
use crate::{AppState, audit, policy};
use axum::extract::{Form, Path, Query, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use uwuauth_store::{App, Person};

/// Codes are fetched within a minute or not at all.
pub const CODE_SECONDS: i64 = 60;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Params {
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub response_mode: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    /// Set by this server when it sent somebody to sign in again: the id of what it remembers
    /// about that. Only a sign-in after the time it remembers counts. A made-up id is nothing.
    pub uwu_login: Option<String>,
}

/// A request that waits for somebody to agree.
#[derive(Debug, Clone)]
pub struct Request {
    pub app_id: String,
    pub person_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub form_post: bool,
    /// The app sent `redirect_uri` (it may leave it out with one registered); then the token
    /// request has to send the same one.
    pub redirect_given: bool,
    pub sid: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

/// A code, waiting for the app to fetch its tokens.
#[derive(Debug, Clone)]
pub struct Code {
    pub app_id: String,
    pub person_id: String,
    pub redirect_uri: String,
    pub redirect_given: bool,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub sid: String,
}

pub async fn authorize_get(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(params): Query<Params>,
    RawQuery(query): RawQuery,
) -> Response {
    authorize(&state, ip, &headers, params, query.unwrap_or_default()).await
}

pub async fn authorize_post(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(params): Form<Params>,
) -> Response {
    // Sent as a form, it comes back here as a GET after signing in.
    let query = serde_urlencoded(&params);
    authorize(&state, ip, &headers, params, query).await
}

fn serde_urlencoded(params: &Params) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    let mut add = |name: &str, value: &Option<String>| {
        if let Some(value) = value {
            out.append_pair(name, value);
        }
    };
    add("response_type", &Some(params.response_type.clone()));
    add("client_id", &Some(params.client_id.clone()));
    add("redirect_uri", &params.redirect_uri);
    add("scope", &params.scope);
    add("state", &params.state);
    add("nonce", &params.nonce);
    add("code_challenge", &params.code_challenge);
    add("code_challenge_method", &params.code_challenge_method);
    add("prompt", &params.prompt);
    add("max_age", &params.max_age);
    add("response_mode", &params.response_mode);
    out.finish()
}

/// A page of the web app: `/#/<path>?<pairs>`.
fn page(state: &AppState, path: &str, pairs: &[(&str, &str)]) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        query.append_pair(name, value);
    }
    Redirect::to(&format!("{}/#/{path}?{}", state.config.public, query.finish())).into_response()
}

/// Whether `given` is one of the app's redirect addresses. For an app on the same device
/// (`http://127.0.0.1`, `[::1]`, `localhost`), any port counts (RFC 8252 section 7.3).
pub fn redirect_matches(registered: &[String], given: &str) -> bool {
    if registered.iter().any(|uri| uri == given) {
        return true;
    }
    let Ok(given) = url::Url::parse(given) else { return false };
    let loopback =
        |url: &url::Url| url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    loopback(&given)
        && registered.iter().filter_map(|uri| url::Url::parse(uri).ok()).any(|uri| {
            loopback(&uri)
                && uri.host_str() == given.host_str()
                && uri.path() == given.path()
                && uri.query() == given.query()
        })
}

/// The app's redirect address with the answer added (and `iss`, RFC 9207), or a page that posts
/// it (`response_mode=form_post`).
fn answer(
    state: &AppState,
    redirect_uri: &str,
    form_post: bool,
    pairs: &[(&str, &str)],
    app_state: Option<&str>,
) -> Response {
    let mut all: Vec<(&str, &str)> = pairs.to_vec();
    if let Some(app_state) = app_state {
        all.push(("state", app_state));
    }
    let iss = issuer(state);
    all.push(("iss", &iss));
    if form_post {
        return form_post_page(redirect_uri, &all);
    }
    let Ok(mut url) = url::Url::parse(redirect_uri) else { return Redirect::to(redirect_uri).into_response() };
    url.query_pairs_mut().extend_pairs(all);
    Redirect::to(url.as_str()).into_response()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// The OAuth 2.0 Form Post Response Mode: a page that sends the answer on by itself. Its one
/// script is allowed by its hash, nothing else.
fn form_post_page(redirect_uri: &str, pairs: &[(&str, &str)]) -> Response {
    const SCRIPT: &str = "document.forms[0].submit()";
    let fields: String = pairs
        .iter()
        .map(|(name, value)| format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", escape(name), escape(value)))
        .collect();
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>UwUAuth</title></head><body>\
         <form method=\"post\" action=\"{}\">{fields}<noscript><button type=\"submit\">Continue</button></noscript></form>\
         <script>{SCRIPT}</script></body></html>",
        escape(redirect_uri)
    );
    use base64::Engine as _;
    let hash = base64::engine::general_purpose::STANDARD.encode(crate::crypto::sha256(SCRIPT.as_bytes()));
    let mut response = Html(html).into_response();
    let policy = format!("default-src 'none'; script-src 'sha256-{hash}'; form-action *; frame-ancestors 'none'");
    if let Ok(value) = HeaderValue::from_str(&policy) {
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

/// Why somebody may not use an app, or nothing: disabled or run out, not in the app's groups,
/// outside their time window.
pub async fn refusal(state: &AppState, app: &App, person: &Person) -> ApiResult<Option<&'static str>> {
    if app.disabled {
        return Ok(Some("app_disabled"));
    }
    if let Some(reason) = policy::refusal(state, person).await? {
        return Ok(Some(reason));
    }
    let membership = state.store.membership().await?;
    let groups = membership.groups_of(&person.id);
    if !app.allowed_groups.is_empty() && !app.allowed_groups.iter().any(|group| groups.contains(group)) {
        return Ok(Some("groups"));
    }
    let windows = state.store.windows_for(&person.id, &groups).await?;
    if !policy::within_windows(state, &windows, Some(&app.id)) {
        return Ok(Some("time"));
    }
    Ok(None)
}

/// Whether a session's sign-in counts as two factors.
pub fn strong(amr: &[String]) -> bool {
    amr.iter().any(|method| method == "mfa" || method == "hwk")
}

async fn authorize(state: &AppState, ip: IpAddr, headers: &HeaderMap, params: Params, query: String) -> Response {
    match run(state, ip, headers, params, query).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn run(state: &AppState, ip: IpAddr, headers: &HeaderMap, params: Params, query: String) -> ApiResult<Response> {
    // 1. The app, and where the answer goes.
    let Some(app) = state.store.app_by_client_id(params.client_id.trim()).await?.filter(|app| !app.disabled) else {
        return Ok(page(state, "oauth-error", &[("reason", "unknown_app")]));
    };
    let redirect_given = params.redirect_uri.as_deref().is_some_and(|uri| !uri.is_empty());
    let redirect_uri = match params.redirect_uri.as_deref().filter(|uri| !uri.is_empty()) {
        Some(uri) if redirect_matches(&app.redirect_uris, uri) => uri.to_string(),
        Some(_) => return Ok(page(state, "oauth-error", &[("reason", "redirect"), ("app", &app.name)])),
        None if app.redirect_uris.len() == 1 => app.redirect_uris[0].clone(),
        None => return Ok(page(state, "oauth-error", &[("reason", "redirect"), ("app", &app.name)])),
    };
    let form_post = params.response_mode.as_deref() == Some("form_post");
    let app_state = params.state.as_deref();
    let refuse = |error: &str, description: &str| {
        Ok(answer(state, &redirect_uri, form_post, &[("error", error), ("error_description", description)], app_state))
    };

    // 2. The request.
    if params.request.is_some() {
        return refuse("request_not_supported", "request objects are not supported");
    }
    if params.request_uri.is_some() {
        return refuse("request_uri_not_supported", "request_uri is not supported");
    }
    if params.response_type != "code" {
        return refuse("unsupported_response_type", "only the authorization code flow is offered");
    }
    if !app.grant_types.iter().any(|grant| grant == "authorization_code") {
        return refuse("unauthorized_client", "this app may not use the authorization code flow");
    }
    let public = app.secret_hash.is_none();
    let challenge = params.code_challenge.clone().filter(|challenge| !challenge.is_empty());
    match (&challenge, params.code_challenge_method.as_deref()) {
        (Some(challenge), Some("S256"))
            if challenge.len() == 43
                && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => {}
        (Some(_), _) => return refuse("invalid_request", "PKCE needs S256 and a challenge of 43 characters"),
        (None, _) if public || app.require_pkce => {
            return refuse("invalid_request", "this app has to use PKCE with S256");
        }
        (None, _) => {}
    }
    if params.nonce.as_ref().is_some_and(|nonce| nonce.len() > 512) || app_state.is_some_and(|value| value.len() > 2048)
    {
        return refuse("invalid_request", "the nonce or state is too long");
    }
    let asked = params.scope.clone().unwrap_or_default();
    let scopes = scopes(&asked);
    if scopes.is_empty() && !asked.trim().is_empty() {
        return refuse("invalid_scope", &format!("none of these scopes are known; known are: {}", SCOPES.join(" ")));
    }
    let prompts: Vec<&str> = params.prompt.as_deref().unwrap_or_default().split_whitespace().collect();
    if prompts.contains(&"none") && prompts.len() > 1 {
        return refuse("invalid_request", "prompt=none goes with nothing else");
    }

    // 3. Who is signed in.
    let me = from_headers(state, headers, ip).await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let max_age: Option<i64> = params.max_age.as_deref().and_then(|age| age.trim().parse().ok());
    // Back from signing in again: when this server sent the browser off, and that only once.
    let after = params.uwu_login.as_deref().and_then(|id| state.oidc().logins.take(id));
    let signed_in = me.as_ref().filter(|me| {
        let auth_time = uwuauth_store::clock::parse(&me.session.auth_time).map_or(0, |at| at.unix_timestamp());
        // The new sign-in is what counts; `max_age` and `prompt=login` are answered by it.
        let recent = match after {
            Some(after) => auth_time >= after,
            // `max_age=0` means now: always again.
            None => max_age.is_none_or(|age| now - auth_time < age) && !prompts.contains(&"login"),
        };
        !me.session.restricted && recent
    });
    let Some(me) = signed_in else {
        if prompts.contains(&"none") {
            return refuse("login_required", "nobody is signed in");
        }
        return Ok(to_login(
            state,
            &query,
            prompts.contains(&"login") || max_age.is_some() || me.is_some_and(|me| !me.session.restricted),
            now,
        ));
    };
    let auth_time = uwuauth_store::clock::parse(&me.session.auth_time).map_or(now, |at| at.unix_timestamp());
    let amr = me.methods();

    // 4. Whether they may.
    if let Some(reason) = refusal(state, &app, &me.person).await? {
        audit(
            state,
            "app_refused",
            Some(&me.person.id),
            Some(&me.person.id),
            Some(&app.id),
            &ip,
            json!({ "reason": reason, "app": app.name }),
        )
        .await;
        if prompts.contains(&"none") {
            return refuse("access_denied", "this person may not use this app now");
        }
        return Ok(page(state, "denied", &[("reason", reason), ("app", &app.name)]));
    }
    if app.require_mfa && !strong(&amr) {
        if prompts.contains(&"none") {
            return refuse("interaction_required", "this app needs a second factor");
        }
        let continue_to = format!("/oauth/authorize?{}", without(&query, &["uwu_login"]));
        return Ok(page(state, "denied", &[("reason", "mfa"), ("app", &app.name), ("continue", &continue_to)]));
    }

    // 5. Agreement, for apps that ask.
    let sid = sid(&me.session.id);
    let request = Request {
        app_id: app.id.clone(),
        person_id: me.person.id.clone(),
        redirect_uri: redirect_uri.clone(),
        scopes: scopes.clone(),
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        code_challenge: challenge,
        form_post,
        redirect_given,
        sid,
        auth_time,
        amr,
    };
    if app.consent {
        let grant = state.store.grant(&app.id, &me.person.id).await?;
        let covered = grant.as_ref().is_some_and(|grant| {
            grant.consented && scopes.iter().all(|scope| grant.scope.split_whitespace().any(|known| known == scope))
        });
        if !covered || prompts.contains(&"consent") {
            if prompts.contains(&"none") {
                return refuse("consent_required", "the person has not agreed yet");
            }
            let id = crate::crypto::random_token(18);
            state.oidc().consents.put(id.clone(), request);
            return Ok(page(state, "consent", &[("request", &id)]));
        }
    }

    // 6. The code.
    issue(state, &app, request, false, ip).await
}

/// The query without the named parameters.
fn without(query: &str, names: &[&str]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(url::form_urlencoded::parse(query.as_bytes()).filter(|(name, _)| !names.contains(&name.as_ref())))
        .finish()
}

/// Off to the sign-in page, which sends the browser back here afterwards. `again`: a sign-in that
/// happened before now does not count (for `prompt=login`, `max_age`, or a sign-in that is too
/// old). The sign-in page then asks even somebody who is signed in (`fresh=1`).
fn to_login(state: &AppState, query: &str, again: bool, now: i64) -> Response {
    let mut back = without(query, &["prompt", "uwu_login"]);
    if again {
        let id = crate::crypto::random_token(18);
        if state.oidc().logins.put(id.clone(), now) {
            back.push_str(&format!("&uwu_login={id}"));
        }
        return page(state, "login", &[("continue", &format!("/oauth/authorize?{back}")), ("fresh", "1")]);
    }
    page(state, "login", &[("continue", &format!("/oauth/authorize?{back}"))])
}

/// Make the code, note the grant, send the answer.
async fn issue(state: &AppState, app: &App, request: Request, consented: bool, ip: IpAddr) -> ApiResult<Response> {
    let code = make_code(state, app, &request, consented, ip).await?;
    Ok(answer(state, &request.redirect_uri, request.form_post, &[("code", &code)], request.state.as_deref()))
}

/// Make the code and note the grant.
async fn make_code(state: &AppState, app: &App, request: &Request, consented: bool, ip: IpAddr) -> ApiResult<String> {
    let code = crate::crypto::random_token(32);
    let scope = request.scopes.join(" ");
    state.store.touch_grant(&app.id, &request.person_id, &scope, consented).await?;
    state.store.note_session_app(&request.sid, &app.id, &request.person_id).await?;
    audit(
        state,
        "app_login",
        Some(&request.person_id),
        Some(&request.person_id),
        Some(&app.id),
        &ip,
        json!({ "app": app.name }),
    )
    .await;
    state.oidc().codes.put(
        crate::crypto::b64(&crate::crypto::sha256(code.as_bytes())),
        Code {
            app_id: app.id.clone(),
            person_id: request.person_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            redirect_given: request.redirect_given,
            scopes: request.scopes.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            auth_time: request.auth_time,
            amr: request.amr.clone(),
            sid: request.sid.clone(),
        },
    );
    Ok(code)
}

impl AppState {
    pub fn oidc(&self) -> &Pending {
        &self.memory.oidc
    }
}

// ── Consent ───────────────────────────────────────────────

pub fn consent_routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/consent/{id}", get(consent_info).post(consent_decide))
        .route("/oauth/answer/{id}", get(form_answer))
}

/// An answer for an app that wants it posted (`response_mode=form_post`), after the person agreed
/// in the web app: the web app cannot post to another site itself, so the browser comes here for
/// the page that does.
#[derive(Debug, Clone)]
pub struct FormAnswer {
    pub redirect_uri: String,
    pub pairs: Vec<(String, String)>,
}

async fn form_answer(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let answer = state.oidc().answers.take(&id).ok_or_else(ApiError::not_found)?;
    let pairs: Vec<(&str, &str)> = answer.pairs.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    Ok(form_post_page(&answer.redirect_uri, &pairs))
}

/// Where the browser goes with the answer for the app: the app's address with it added, or, for
/// `form_post`, the page that posts it.
fn answer_address(state: &AppState, request: &Request, pairs: &[(&str, &str)]) -> String {
    let mut all: Vec<(String, String)> =
        pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect();
    if let Some(app_state) = &request.state {
        all.push(("state".into(), app_state.clone()));
    }
    all.push(("iss".into(), issuer(state)));
    if request.form_post {
        let id = crate::crypto::random_token(18);
        state.oidc().answers.put(id.clone(), FormAnswer { redirect_uri: request.redirect_uri.clone(), pairs: all });
        return format!("{}/oauth/answer/{id}", state.config.public);
    }
    match url::Url::parse(&request.redirect_uri) {
        Ok(mut url) => {
            url.query_pairs_mut().extend_pairs(all);
            url.to_string()
        }
        Err(_) => request.redirect_uri.clone(),
    }
}

async fn consent_info(State(state): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let request = state
        .oidc()
        .consents
        .peek(&id)
        .filter(|request| request.person_id == me.person.id)
        .ok_or_else(ApiError::not_found)?;
    let app = state.store.app(&request.app_id).await?.ok_or_else(ApiError::not_found)?;
    let host = url::Url::parse(&request.redirect_uri)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    Ok(Json(json!({
        "app": { "name": app.name, "description": app.description, "launchUrl": app.launch_url, "template": app.template },
        "scopes": request.scopes,
        "redirectHost": host,
    })))
}

#[derive(Deserialize)]
struct Decision {
    approve: bool,
}

/// The person agreed or not: the answer for the app, as the address the browser goes to next.
async fn consent_decide(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(decision): Json<Decision>,
) -> ApiResult<Json<Value>> {
    let request = state
        .oidc()
        .consents
        .take(&id)
        .filter(|request| request.person_id == me.person.id)
        .ok_or_else(ApiError::not_found)?;
    let app = state.store.app(&request.app_id).await?.ok_or_else(ApiError::not_found)?;
    let redirect = if decision.approve {
        let code = make_code(&state, &app, &request, true, ip).await?;
        answer_address(&state, &request, &[("code", &code)])
    } else {
        audit(
            &state,
            "app_consent_refused",
            Some(&me.person.id),
            Some(&me.person.id),
            Some(&app.id),
            &ip,
            json!({ "app": app.name }),
        )
        .await;
        answer_address(&state, &request, &[("error", "access_denied"), ("error_description", "the person said no")])
    };
    Ok(Json(json!({ "redirect": redirect })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_redirects_take_any_port() {
        let registered = vec!["http://127.0.0.1/callback".to_string(), "https://app.example.com/cb".to_string()];
        assert!(redirect_matches(&registered, "http://127.0.0.1:49152/callback"));
        assert!(redirect_matches(&registered, "https://app.example.com/cb"));
        assert!(!redirect_matches(&registered, "https://app.example.com/cb/"));
        assert!(!redirect_matches(&registered, "https://app.example.com:8443/cb"), "only loopback may change the port");
        assert!(!redirect_matches(&registered, "http://127.0.0.1:49152/other"));
        assert!(!redirect_matches(&registered, "https://evil.example.net/cb"));
    }

    #[test]
    fn a_form_post_escapes_what_it_carries() {
        let response = form_post_page("https://app.example.com/cb", &[("state", "\"><script>x</script>")]);
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
        assert!(policy.starts_with("default-src 'none'; script-src 'sha256-"));
    }

    #[test]
    fn a_query_loses_what_is_named() {
        assert_eq!(without("a=1&prompt=login&b=2", &["prompt"]), "a=1&b=2");
    }
}
