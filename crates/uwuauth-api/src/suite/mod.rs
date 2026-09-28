//! Pairing with the UwUSuite (stage 4), and pushing people and groups to apps over SCIM.
//!
//! Pairing saves typing, nothing more: afterwards a suite app speaks OpenID Connect and SCIM
//! like any other app, and would work the same with another provider.
//!
//! 1. An admin makes a **pairing code** in the admin portal (`POST /uwu/v1/pairing-codes`): 12
//!    characters of Crockford's base32 (60 bits), once, for 15 minutes, also as a QR code of
//!    `<this server>/#pair=<code>`. With it go the groups that may use the app and which groups
//!    get which of its roles.
//! 2. The suite app asks `GET /uwu/v1/server` (is this a UwUAuth, does it pair?) and sends
//!    `POST /uwu/v1/pair` with the code and what it is: name, icon, redirect addresses, roles,
//!    where its SCIM is.
//! 3. UwUAuth makes a confidential OpenID Connect client for it (PKCE, no consent screen: it is
//!    the admin's own app), answers with issuer, client id and secret, and a token it will send
//!    with every SCIM request — and starts pushing the people who may use the app ([`scim`]).
//!
//! The code is the only thing that proves the request is wanted, so `/uwu/v1/pair` is guarded:
//! ten tries per address and sixty in all per fifteen minutes, every code compared in constant
//! time, and the code used up in the same transaction that keeps the app.

pub mod scim;

use crate::crypto::{constant_time_eq, random_bytes, random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::oidc::SCOPES;
use crate::routes::apps::{NewApp, RoleIn, prepare};
use crate::session::{AdminOnly, ClientIp};
use crate::{AppState, audit, policy};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use uwuauth_store::{EVERYONE_ID, Group, PairingCode, ScimTarget, SuiteApp, clock};

/// The template of an app made by pairing.
pub const TEMPLATE: &str = "uwusuite";

/// Which version of the pairing this server speaks, for `/uwu/v1/server`.
pub const PAIRING_VERSION: u32 = 1;

/// How long a code lasts.
const CODE_SECONDS: i64 = 15 * 60;

/// Crockford's base32: no I, L, O or U, so nothing looks like something else.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A suite app's icon, at most.
const ICON_BYTES: usize = 64 * 1024;

/// Roles a suite app may name, at most.
const ROLES: usize = 20;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/pair", post(pair))
        .route("/uwu/v1/pairing-codes", get(codes).post(create_code))
        .route("/uwu/v1/pairing-codes/{id}", get(code).delete(delete_code))
        .route("/uwu/v1/apps/{id}/icon", get(icon))
        .route("/uwu/v1/apps/{id}/scim", put(scim::set_up).delete(scim::remove))
        .route("/uwu/v1/apps/{id}/scim/sync", post(scim::sync_now))
}

// ── Codes ─────────────────────────────────────────────────

/// A fresh code: `7KQ4-M2XD-9HFT`.
fn new_code() -> String {
    let characters: String = random_bytes(12).iter().map(|byte| CROCKFORD[usize::from(byte & 31)] as char).collect();
    format!("{}-{}-{}", &characters[..4], &characters[4..8], &characters[8..])
}

/// A code as somebody typed or scanned it, the way it is hashed: the 12 characters in capitals,
/// without dashes and spaces, with what Crockford reads as digits (`I`, `L` → `1`, `O` → `0`).
/// The whole QR text (`https://…/#pair=…`) works too.
pub fn normalize(typed: &str) -> Option<String> {
    let typed = typed.rsplit_once("pair=").map_or(typed, |(_, code)| code);
    let mut out = String::with_capacity(12);
    for c in typed.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        if !CROCKFORD.contains(&(c as u8)) || !c.is_ascii() || out.len() == 12 {
            return None;
        }
        out.push(c);
    }
    (out.len() == 12).then_some(out)
}

/// The open code `typed` is, compared against every open code in constant time.
async fn find_code(state: &AppState, typed: &str) -> ApiResult<Option<PairingCode>> {
    // Hashed even when it cannot be a code, so a malformed one takes the same path.
    let hash = sha256(normalize(typed).unwrap_or_default().as_bytes());
    let mut found = None;
    for code in state.store.open_pairing_codes().await? {
        let matches = code.hash.as_deref().is_some_and(|known| constant_time_eq(known, &hash));
        if matches && found.is_none() {
            found = Some(code);
        }
    }
    Ok(found)
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NewCode {
    allowed_groups: Vec<String>,
    role_groups: BTreeMap<String, Vec<String>>,
}

/// Group ids for what the admin picked: ids or names. `everyone` in a list of who may means
/// everybody, which is the empty list.
fn resolve(groups: &[Group], picked: &[String], field: &str) -> ApiResult<Vec<String>> {
    let mut ids = Vec::new();
    for pick in picked {
        let group = groups
            .iter()
            .find(|group| group.id == *pick || group.name.eq_ignore_ascii_case(pick))
            .ok_or_else(|| ApiError::field(field, "unknown_group", format!("There is no group {pick}.")))?;
        if !ids.contains(&group.id) {
            ids.push(group.id.clone());
        }
    }
    Ok(ids)
}

fn role_id_ok(id: &str) -> bool {
    (1..=40).contains(&id.len())
        && id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'))
}

async fn create_code(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(new): Json<NewCode>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let groups = state.store.groups().await?;
    let mut allowed = resolve(&groups, &new.allowed_groups, "allowedGroups")?;
    if allowed.iter().any(|id| id == EVERYONE_ID) {
        allowed.clear();
    }
    let mut roles = BTreeMap::new();
    for (role, picked) in &new.role_groups {
        if !role_id_ok(role) {
            return Err(ApiError::field("roleGroups", "role", format!("{role} cannot be a role.")));
        }
        let ids = resolve(&groups, picked, "roleGroups")?;
        if !ids.is_empty() {
            roles.insert(role.clone(), ids);
        }
    }
    let code = new_code();
    let made = state
        .store
        .create_pairing_code(PairingCode {
            hash: Some(sha256(normalize(&code).unwrap_or_default().as_bytes())),
            allowed_groups: allowed,
            role_groups: serde_json::to_string(&roles).unwrap_or_else(|_| "{}".into()),
            created_by: admin.person().map(|person| person.id.clone()),
            expires: clock::in_seconds(CODE_SECONDS),
            ..PairingCode::default()
        })
        .await?
        .ok_or_else(|| ApiError::bad("too_many", "That many codes are open already. Withdraw one first."))?;
    audit(&state, "pairing_code_created", Some(&admin.actor_id()), None, Some(&made.id), &ip, json!({})).await;
    let mut body = code_view(&made);
    body["code"] = json!(code);
    body["link"] = json!(format!("{}/#pair={code}", state.config.public));
    Ok((StatusCode::CREATED, Json(body)))
}

fn code_view(code: &PairingCode) -> Value {
    json!({
        "id": code.id,
        "created": code.created,
        "createdBy": code.created_by,
        "expires": code.expires,
        "allowedGroups": code.allowed_groups,
        "roleGroups": serde_json::from_str::<Value>(&code.role_groups).unwrap_or_else(|_| json!({})),
        "open": code.open(),
        "used": code.used,
        "appId": code.app_id,
    })
}

async fn codes(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let codes = state.store.open_pairing_codes().await?;
    Ok(Json(json!(codes.iter().map(code_view).collect::<Vec<_>>())))
}

/// One code: whether it is still open, and which app took it. The portal asks while it shows it.
async fn code(State(state): State<AppState>, _admin: AdminOnly, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let code = state.store.pairing_code(&id).await?.ok_or_else(ApiError::not_found)?;
    let mut body = code_view(&code);
    if let Some(app_id) = &code.app_id
        && let Some(app) = state.store.app(app_id).await?
    {
        body["app"] = json!({ "id": app.id, "name": app.name });
    }
    Ok(Json(body))
}

async fn delete_code(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_pairing_code(&id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "pairing_code_deleted", Some(&admin.actor_id()), None, Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Pairing ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PairRequest {
    code: String,
    app: SuiteAppIn,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuiteAppIn {
    product: String,
    #[serde(default)]
    version: String,
    name: String,
    url: String,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    backchannel_logout_uri: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    roles: Vec<Role>,
    #[serde(default)]
    scim: Option<ScimIn>,
}

/// A role a suite app knows.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Role {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimIn {
    base_url: String,
    #[serde(default)]
    resources: Option<Vec<String>>,
    /// `email` (what the suite apps key accounts by) or `username`.
    #[serde(default)]
    user_name: Option<String>,
}

fn loopback(url: &url::Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
}

/// An address without a fragment or a login in it.
fn parse_uri(uri: &str, field: &str) -> ApiResult<url::Url> {
    let bad = || ApiError::field(field, "uri", format!("{uri} cannot be used here."));
    if uri.len() > 500 {
        return Err(bad());
    }
    let url = url::Url::parse(uri).map_err(|_| bad())?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        return Err(bad());
    }
    Ok(url)
}

/// The suite app's own address: `https`, or plain `http` to this machine (tests, a first try).
fn app_url(uri: &str) -> ApiResult<url::Url> {
    let url = parse_uri(uri, "app.url")?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback(&url) => Ok(url),
        _ => Err(ApiError::field("app.url", "uri", "The app's address has to be https.")),
    }
}

/// An address of the suite app: `https` on the app's own host — or, for a redirect, one on this
/// machine (RFC 8252), which only the device itself can receive.
fn on_host(uri: &str, app: &url::Url, field: &str, loopback_ok: bool) -> ApiResult<()> {
    let url = parse_uri(uri, field)?;
    let ok = match url.scheme() {
        "https" => url.host_str() == app.host_str() || (loopback_ok && loopback(&url)),
        "http" => loopback(&url) && (loopback_ok || loopback(app)),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::field(
            field,
            "uri",
            format!("{uri} is not on the app's own host ({}).", app.host_str().unwrap_or("")),
        ))
    }
}

/// A PNG from a `data:` address, 64 KiB at most.
fn icon_of(data: &str) -> ApiResult<Vec<u8>> {
    let bad = || ApiError::field("app.icon", "icon", "The icon has to be a PNG of 64 KiB at most, as a data: address.");
    let encoded = data.strip_prefix("data:image/png;base64,").ok_or_else(bad)?;
    if encoded.len() > ICON_BYTES * 4 / 3 + 8 {
        return Err(bad());
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).map_err(|_| bad())?;
    if bytes.len() > ICON_BYTES || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(bad());
    }
    Ok(bytes)
}

fn product_ok(product: &str) -> bool {
    (1..=40).contains(&product.len())
        && product.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'))
}

/// What a checked pairing request makes.
struct Checked {
    new: NewApp,
    suite: SuiteApp,
    scim: Option<(String, Vec<String>, String)>,
    scopes: Vec<String>,
}

/// Everything the suite app sent, checked; the code's groups and roles put onto the app.
fn check(request: SuiteAppIn, code: &PairingCode) -> ApiResult<Checked> {
    if !product_ok(&request.product) {
        return Err(ApiError::field("app.product", "invalid", "The product is a short name like UwULock."));
    }
    let version = request.version.trim();
    if version.len() > 40 || version.chars().any(char::is_control) {
        return Err(ApiError::field("app.version", "invalid", "The version is a short text like 0.6.0."));
    }
    let name = policy::optional(Some(&request.name), 80)
        .ok_or_else(|| ApiError::field("app.name", "required", "A name is needed."))?;
    let url = app_url(&request.url)?;
    if request.redirect_uris.is_empty() || request.redirect_uris.len() > 20 {
        return Err(ApiError::field("app.redirectUris", "required", "Between one and 20 redirect addresses."));
    }
    for uri in &request.redirect_uris {
        on_host(uri, &url, "app.redirectUris", true)?;
    }
    if request.post_logout_redirect_uris.len() > 20 {
        return Err(ApiError::field("app.postLogoutRedirectUris", "invalid", "At most 20 addresses."));
    }
    for uri in &request.post_logout_redirect_uris {
        on_host(uri, &url, "app.postLogoutRedirectUris", true)?;
    }
    let backchannel = request.backchannel_logout_uri.filter(|uri| !uri.is_empty());
    if let Some(uri) = &backchannel {
        on_host(uri, &url, "app.backchannelLogoutUri", false)?;
    }
    let icon = request.icon.as_deref().filter(|icon| !icon.is_empty()).map(icon_of).transpose()?;
    let asked = request
        .scopes
        .unwrap_or_else(|| ["openid", "email", "profile", "groups", "roles"].into_iter().map(String::from).collect());
    let mut scopes: Vec<String> = vec!["openid".into()];
    for scope in asked {
        if SCOPES.contains(&scope.as_str()) && !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if request.roles.len() > ROLES {
        return Err(ApiError::field("app.roles", "invalid", "At most 20 roles."));
    }
    let mut roles: Vec<Role> = Vec::new();
    for role in request.roles {
        if !role_id_ok(&role.id) || roles.iter().any(|known| known.id == role.id) {
            return Err(ApiError::field("app.roles", "role", format!("{} cannot be a role's id.", role.id)));
        }
        roles.push(Role {
            name: policy::optional(Some(&role.name), 60).unwrap_or_else(|| role.id.clone()),
            description: policy::optional(Some(&role.description), 200).unwrap_or_default(),
            id: role.id,
        });
    }
    let scim = match request.scim {
        None => None,
        Some(scim) => {
            on_host(&scim.base_url, &url, "app.scim.baseUrl", false)?;
            let resources = scim.resources.unwrap_or_else(|| vec!["User".into(), "Group".into()]);
            if !resources.iter().any(|resource| resource == "User")
                || resources.iter().any(|resource| resource != "User" && resource != "Group")
            {
                return Err(ApiError::field("app.scim.resources", "invalid", "SCIM resources are User and Group."));
            }
            let user_name = match scim.user_name.as_deref() {
                None | Some("email") => "email",
                Some("username") => "username",
                Some(_) => {
                    return Err(ApiError::field("app.scim.userName", "invalid", "userName is email or username."));
                }
            };
            Some((scim.base_url.trim_end_matches('/').to_string(), resources, user_name.to_string()))
        }
    };
    let new = NewApp {
        name,
        template: Some(TEMPLATE.into()),
        redirect_uris: request.redirect_uris,
        post_logout_redirect_uris: request.post_logout_redirect_uris,
        backchannel_logout_uri: backchannel,
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        public: false,
        token_auth_method: Some("client_secret_basic".into()),
        consent: false,
        require_pkce: true,
        allowed_groups: code.allowed_groups.clone(),
        roles: role_mapping(code, &roles),
        launch_url: Some(url.as_str().to_string()),
        ..NewApp::default()
    };
    let suite = SuiteApp {
        product: request.product,
        version: version.to_string(),
        url: url.as_str().trim_end_matches('/').to_string(),
        icon,
        roles: serde_json::to_string(&roles).unwrap_or_else(|_| "[]".into()),
        paired_by: code.created_by.clone(),
        ..SuiteApp::default()
    };
    Ok(Checked { new, suite, scim, scopes })
}

/// Which groups get which role: what the admin picked with the code, for the roles the app
/// knows (all of them when it named none). A `user` role nobody picked groups for goes to
/// whoever may use the app — for UwULock, that is who may make a vault without an invitation.
fn role_mapping(code: &PairingCode, roles: &[Role]) -> Vec<RoleIn> {
    let picked: BTreeMap<String, Vec<String>> = serde_json::from_str(&code.role_groups).unwrap_or_default();
    let known = |role: &str| roles.is_empty() || roles.iter().any(|known| known.id == role);
    let mut mapping: Vec<RoleIn> = picked
        .iter()
        .filter(|(role, _)| known(role))
        .flat_map(|(role, groups)| groups.iter().map(|group| RoleIn { group: group.clone(), role: role.clone() }))
        .collect();
    if roles.iter().any(|role| role.id == "user") && !picked.contains_key("user") {
        let users =
            if code.allowed_groups.is_empty() { vec![EVERYONE_ID.to_string()] } else { code.allowed_groups.clone() };
        mapping.extend(users.into_iter().map(|group| RoleIn { group, role: "user".into() }));
    }
    mapping
}

fn invalid_code() -> ApiError {
    ApiError::bad("invalid_code", "The pairing code is unknown, used or ran out.")
}

/// `POST /uwu/v1/pair`: a suite app with a code becomes an app here.
async fn pair(State(state): State<AppState>, ClientIp(ip): ClientIp, body: Bytes) -> ApiResult<Json<Value>> {
    // Per address first: somebody who ran out of tries does not use up everybody else's.
    if !state.limits.pairing.check(ip) || !state.limits.pairing_all.take(()) {
        return Err(ApiError::too_many());
    }
    let request: PairRequest = serde_json::from_slice(&body)
        .map_err(|error| ApiError::bad("invalid", format!("The request is not what pairing takes: {error}")))?;
    let product: String = request.app.product.chars().filter(|c| !c.is_control()).take(40).collect();
    let Some(code) = find_code(&state, &request.code).await? else {
        audit(&state, "app_pairing_refused", None, None, None, &ip, json!({ "product": product, "reason": "code" }))
            .await;
        return Err(invalid_code());
    };
    let checked = check(request.app, &code)?;
    let (app, secret) = prepare(&state, checked.new, code.created_by.as_deref()).await?;
    let scim_token = checked.scim.as_ref().map(|_| random_token(32));
    let target =
        checked.scim.clone().zip(scim_token.clone()).map(|((base_url, resources, user_name), token)| ScimTarget {
            base_url,
            token: state.sealer.seal(token.as_bytes()),
            resources,
            user_name,
            ..ScimTarget::default()
        });
    let suite = checked.suite.clone();
    let app = state.store.pair(&code.id, app, checked.suite, target).await?.ok_or_else(invalid_code)?;
    audit(
        &state,
        "app_paired",
        code.created_by.as_deref(),
        None,
        Some(&app.id),
        &ip,
        json!({ "name": app.name, "product": suite.product, "version": suite.version, "url": suite.url }),
    )
    .await;
    state.scim.wake();
    Ok(Json(json!({
        "issuer": state.config.public,
        "clientId": app.client_id,
        "clientSecret": secret,
        "tokenEndpointAuthMethod": app.token_auth_method,
        "scopes": checked.scopes,
        "groupsClaim": "groups",
        "rolesClaim": "roles",
        "scimToken": scim_token,
        "appId": app.id,
        "manageUrl": format!("{}/admin#/apps/{}", state.config.public, app.id),
    })))
}

// ── For the app pages ─────────────────────────────────────

/// A paired app's icon. Not secret: anybody may see it, like people's pictures.
async fn icon(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let png = state.store.suite_app(&id).await?.and_then(|suite| suite.icon).ok_or_else(ApiError::not_found)?;
    let mut response = png.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'"));
    Ok(response)
}

/// What the app pages show beyond the app itself: for paired apps what they said about
/// themselves, and for apps with SCIM how pushing goes.
#[derive(Default)]
pub struct Extras {
    suite: HashMap<String, SuiteApp>,
    scim: HashMap<String, ScimTarget>,
    counts: HashMap<String, (i64, i64)>,
}

impl Extras {
    pub async fn load(state: &AppState) -> ApiResult<Self> {
        Ok(Extras {
            suite: state.store.suite_apps().await?.into_iter().map(|suite| (suite.app_id.clone(), suite)).collect(),
            scim: state.store.scim_targets().await?.into_iter().map(|target| (target.app_id.clone(), target)).collect(),
            counts: state
                .store
                .scim_counts()
                .await?
                .into_iter()
                .map(|(app, users, groups)| (app, (users, groups)))
                .collect(),
        })
    }

    /// `suite` and `scim` put onto an app as the portal shows it.
    pub fn add(&self, state: &AppState, id: &str, body: &mut Value) {
        body["suite"] = self.suite.get(id).map_or(Value::Null, |suite| suite_view(state, suite));
        body["scim"] = self.scim.get(id).map_or(Value::Null, |target| {
            let (users, groups) = self.counts.get(id).copied().unwrap_or_default();
            scim_view(target, users, groups)
        });
    }

    pub fn icon(&self, state: &AppState, id: &str) -> Option<String> {
        self.suite
            .get(id)
            .filter(|suite| suite.has_icon)
            .map(|_| format!("{}/uwu/v1/apps/{id}/icon", state.config.public))
    }
}

fn suite_view(state: &AppState, suite: &SuiteApp) -> Value {
    json!({
        "product": suite.product,
        "version": suite.version,
        "url": suite.url,
        "roles": serde_json::from_str::<Value>(&suite.roles).unwrap_or_else(|_| json!([])),
        "pairedBy": suite.paired_by,
        "paired": suite.paired,
        "icon": suite.has_icon.then(|| format!("{}/uwu/v1/apps/{}/icon", state.config.public, suite.app_id)),
    })
}

pub(crate) fn scim_view(target: &ScimTarget, users: i64, groups: i64) -> Value {
    let mut view = Map::new();
    view.insert("baseUrl".into(), json!(target.base_url));
    view.insert("resources".into(), json!(target.resources));
    view.insert("userName".into(), json!(target.user_name));
    view.insert("synced".into(), json!(target.synced));
    view.insert("tried".into(), json!(target.tried));
    view.insert("error".into(), json!(target.error));
    view.insert("users".into(), json!(users));
    view.insert("groups".into(), json!(groups));
    Value::Object(view)
}

#[cfg(test)]
mod tests;
