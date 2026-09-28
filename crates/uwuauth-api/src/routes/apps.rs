//! Apps in the admin portal — made by hand or from a template, their secret shown once — the
//! tokens apps register themselves with, and "My apps" in the self-service portal.

use crate::crypto::{random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::oidc::templates;
use crate::session::{AdminOnly, ClientIp, Me};
use crate::suite::Extras;
use crate::{AppState, audit, policy};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwuauth_store::{App, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/apps", get(list).post(create))
        .route("/uwu/v1/apps/{id}", get(show).patch(change).delete(remove))
        .route("/uwu/v1/apps/{id}/secret", post(new_secret))
        .route("/uwu/v1/app-templates", get(app_templates))
        .route("/uwu/v1/registration-tokens", get(registration_tokens).post(create_registration_token))
        .route("/uwu/v1/registration-tokens/{id}", delete(delete_registration_token))
        .route("/uwu/v1/me/apps", get(my_apps))
        .route("/uwu/v1/me/grants/{id}", delete(revoke_grant))
}

/// Whether an app may send people back to `uri`: `https`, `http` to this device (RFC 8252), or
/// an app's own scheme (`com.example.app:/cb`, RFC 8252 section 7.1). Never a fragment, a login
/// in the address, or `javascript:` and friends.
pub fn check_uri(uri: &str) -> Result<(), String> {
    check(uri, false)
}

/// The same, and plain `http` anywhere: an admin may point at an app in the home network that has
/// no certificate. Their call.
fn check_admin_uri(uri: &str) -> Result<(), String> {
    check(uri, true)
}

fn check(uri: &str, http: bool) -> Result<(), String> {
    let bad = || format!("{uri} cannot be a redirect address");
    if uri.len() > 500 {
        return Err(bad());
    }
    let url = url::Url::parse(uri).map_err(|_| bad())?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(bad());
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback || http => Ok(()),
        "javascript" | "data" | "file" | "vbscript" | "blob" | "about" | "ftp" | "ws" | "wss" | "http" => Err(bad()),
        // An app's own scheme: letters, digits, dots, pluses and dashes (RFC 3986).
        scheme if scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')) => Ok(()),
        _ => Err(bad()),
    }
}

/// What the portal (or a registration) says about a new app.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NewApp {
    pub name: String,
    pub description: Option<String>,
    pub template: Option<String>,
    /// The app's own address, for a template's `{url}`.
    pub url: Option<String>,
    /// For a template's `{slug}`: what the app calls UwUAuth in its callback.
    pub slug: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub grant_types: Option<Vec<String>>,
    /// No secret: an app on a phone or a single-page app.
    pub public: bool,
    pub token_auth_method: Option<String>,
    pub id_token_alg: Option<String>,
    pub consent: bool,
    pub require_pkce: bool,
    pub allowed_groups: Vec<String>,
    pub require_mfa: bool,
    pub roles: Vec<RoleIn>,
    pub access_token_minutes: Option<i64>,
    pub refresh_token_days: Option<i64>,
    pub launch_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct RoleIn {
    pub group: String,
    pub role: String,
}

const GRANTS: &[&str] =
    &["authorization_code", "refresh_token", "client_credentials", crate::oidc::token::DEVICE_GRANT];

/// A client id people can read: the app's name made small, and a bit of randomness.
fn client_id(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug: String = slug.chars().take(24).collect();
    let suffix: String = random_token(6).to_lowercase().chars().filter(char::is_ascii_alphanumeric).take(6).collect();
    if slug.is_empty() { format!("app-{suffix}") } else { format!("{slug}-{suffix}") }
}

/// Check what a new app is made of, without keeping it.
pub async fn check_new(state: &AppState, new: &NewApp) -> ApiResult<()> {
    fields(state, App::default(), new.clone()).await.map(drop)
}

/// Check what an app is made of and keep it. Its secret, if it has one, comes back once.
pub async fn make(state: &AppState, new: NewApp, created_by: Option<&str>) -> ApiResult<(App, Option<String>)> {
    let (app, secret) = prepare(state, new, created_by).await?;
    Ok((state.store.create_app(app).await?, secret))
}

/// Check what an app is made of, without keeping it: the app, and its secret if it has one.
pub async fn prepare(state: &AppState, new: NewApp, created_by: Option<&str>) -> ApiResult<(App, Option<String>)> {
    let template = new.template.as_deref().and_then(templates::find);
    let url = new.url.as_deref().map(str::trim).filter(|url| !url.is_empty()).unwrap_or_default();
    let slug = new.slug.as_deref().filter(|slug| !slug.is_empty()).unwrap_or("uwuauth");
    let mut redirect_uris = new.redirect_uris.clone();
    let mut post_logout = new.post_logout_redirect_uris.clone();
    let mut launch_url = new.launch_url.clone().filter(|url| !url.is_empty());
    if let Some(template) = template
        && !url.is_empty()
    {
        if redirect_uris.is_empty() {
            redirect_uris = template.redirect_uris.iter().map(|pattern| templates::fill(pattern, url, slug)).collect();
        }
        if post_logout.is_empty() {
            post_logout =
                template.post_logout_redirect_uris.iter().map(|pattern| templates::fill(pattern, url, slug)).collect();
        }
        if launch_url.is_none() && !template.launch_url.is_empty() {
            launch_url = Some(templates::fill(template.launch_url, url, slug));
        }
    }
    let name = policy::optional(Some(&new.name), 80)
        .or_else(|| template.map(|template| template.name.to_string()))
        .ok_or_else(|| ApiError::field("name", "required", "A name is needed."))?;
    let app = fields(
        state,
        App::default(),
        NewApp { redirect_uris, post_logout_redirect_uris: post_logout, launch_url, ..new.clone() },
    )
    .await?;
    let secret = (!new.public).then(|| random_token(32));
    let app = App {
        client_id: client_id(&name),
        name,
        template: template.map(|template| template.key.to_string()).or_else(|| {
            new.template.clone().filter(|key| key == crate::oidc::register::REGISTERED || key == crate::suite::TEMPLATE)
        }),
        secret_hash: secret.as_ref().map(|secret| sha256(secret.as_bytes())),
        token_auth_method: if new.public { "none".into() } else { app.token_auth_method },
        created_by: created_by.map(str::to_string),
        ..app
    };
    Ok((app, secret))
}

/// Everything but the name, the id and the secret, checked and put onto `app`.
async fn fields(state: &AppState, mut app: App, new: NewApp) -> ApiResult<App> {
    for uri in new.redirect_uris.iter().chain(&new.post_logout_redirect_uris) {
        check_admin_uri(uri).map_err(|message| ApiError::field("redirectUris", "redirect_uri", message))?;
    }
    if let Some(uri) = new.backchannel_logout_uri.as_deref().filter(|uri| !uri.is_empty()) {
        check_admin_uri(uri).map_err(|message| ApiError::field("backchannelLogoutUri", "redirect_uri", message))?;
    }
    if let Some(url) = new.launch_url.as_deref().filter(|url| !url.is_empty())
        && !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(ApiError::field("launchUrl", "url", "The address to open the app is an http(s) address."));
    }
    let grants = new.grant_types.clone().unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    if grants.is_empty() || grants.iter().any(|grant| !GRANTS.contains(&grant.as_str())) {
        return Err(ApiError::field("grantTypes", "grant_types", "Unknown grant type."));
    }
    if grants.iter().any(|grant| grant == "authorization_code") && new.redirect_uris.is_empty() {
        return Err(ApiError::field(
            "redirectUris",
            "required",
            "An app that signs people in needs a redirect address.",
        ));
    }
    let known: Vec<String> = state.store.groups().await?.into_iter().map(|group| group.id).collect();
    app.description = policy::optional(new.description.as_deref(), 500).unwrap_or_default();
    app.redirect_uris = new.redirect_uris;
    app.post_logout_redirect_uris = new.post_logout_redirect_uris;
    app.backchannel_logout_uri = new.backchannel_logout_uri.filter(|uri| !uri.is_empty());
    app.grant_types = grants;
    app.token_auth_method = match new.token_auth_method.as_deref() {
        Some("client_secret_post") => "client_secret_post".into(),
        Some("none") => "none".into(),
        _ => "client_secret_basic".into(),
    };
    app.id_token_alg = if new.id_token_alg.as_deref() == Some("ES256") { "ES256".into() } else { "RS256".into() };
    app.consent = new.consent;
    app.require_pkce = new.require_pkce;
    app.allowed_groups = new.allowed_groups.into_iter().filter(|group| known.contains(group)).collect();
    app.require_mfa = new.require_mfa;
    let roles: Vec<RoleIn> = new
        .roles
        .into_iter()
        .filter(|role| known.contains(&role.group))
        .filter_map(|role| policy::optional(Some(&role.role), 60).map(|name| RoleIn { group: role.group, role: name }))
        .collect();
    app.roles = serde_json::to_string(&roles).unwrap_or_else(|_| "[]".into());
    app.access_token_minutes = new.access_token_minutes.unwrap_or(15).clamp(1, 24 * 60);
    app.refresh_token_days = new.refresh_token_days.unwrap_or(30).clamp(1, 3650);
    app.launch_url = new.launch_url.filter(|url| !url.is_empty());
    Ok(app)
}

pub fn app_view(app: &App) -> Value {
    json!({
        "id": app.id,
        "clientId": app.client_id,
        "name": app.name,
        "description": app.description,
        "template": app.template,
        "public": app.secret_hash.is_none(),
        "redirectUris": app.redirect_uris,
        "postLogoutRedirectUris": app.post_logout_redirect_uris,
        "backchannelLogoutUri": app.backchannel_logout_uri,
        "grantTypes": app.grant_types,
        "tokenAuthMethod": app.token_auth_method,
        "idTokenAlg": app.id_token_alg,
        "consent": app.consent,
        "requirePkce": app.require_pkce,
        "allowedGroups": app.allowed_groups,
        "requireMfa": app.require_mfa,
        "roles": serde_json::from_str::<Value>(&app.roles).unwrap_or_default(),
        "accessTokenMinutes": app.access_token_minutes,
        "refreshTokenDays": app.refresh_token_days,
        "launchUrl": app.launch_url,
        "disabled": app.disabled,
        "created": app.created,
        "updated": app.updated,
    })
}

async fn list(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let apps = state.store.apps().await?;
    let extras = Extras::load(&state).await?;
    Ok(Json(json!(
        apps.iter()
            .map(|app| {
                let mut body = app_view(app);
                extras.add(&state, &app.id, &mut body);
                body
            })
            .collect::<Vec<_>>()
    )))
}

async fn create(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(new): Json<NewApp>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let (app, secret) = make(&state, new, admin.person().map(|person| person.id.as_str())).await?;
    audit(&state, "app_created", Some(&admin.actor_id()), None, Some(&app.id), &ip, json!({ "name": app.name })).await;
    let mut body = app_view(&app);
    body["clientSecret"] = json!(secret);
    body["issuer"] = json!(state.config.public);
    Ok((StatusCode::CREATED, Json(body)))
}

async fn show(State(state): State<AppState>, admin: AdminOnly, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let app = state.store.app(&id).await?.ok_or_else(ApiError::not_found)?;
    let mut body = app_view(&app);
    body["issuer"] = json!(state.config.public);
    Extras::load(&state).await?.add(&state, &app.id, &mut body);
    if let Some(template) = app.template.as_deref().and_then(templates::find) {
        let language = admin.person().map_or("de", |person| person.language.as_str());
        body["notes"] = json!(
            if language == "en" { template.notes_en } else { template.notes_de }
                .replace("{issuer}", &state.config.public)
        );
    }
    Ok(Json(body))
}

/// A change to an app: only what is sent changes, everything else stays as it is.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Change {
    name: Option<String>,
    disabled: Option<bool>,
    description: Option<String>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    /// An empty string takes it away.
    backchannel_logout_uri: Option<String>,
    grant_types: Option<Vec<String>>,
    /// `true` takes the secret away (the app becomes public); a secret comes with "new secret".
    public: Option<bool>,
    token_auth_method: Option<String>,
    id_token_alg: Option<String>,
    consent: Option<bool>,
    require_pkce: Option<bool>,
    allowed_groups: Option<Vec<String>>,
    require_mfa: Option<bool>,
    roles: Option<Vec<RoleIn>>,
    access_token_minutes: Option<i64>,
    refresh_token_days: Option<i64>,
    /// An empty string takes it away.
    launch_url: Option<String>,
}

/// The app as `NewApp`, with what `change` says on top.
fn merged(current: &App, change: Change, public: bool) -> NewApp {
    NewApp {
        name: current.name.clone(),
        description: Some(change.description.unwrap_or_else(|| current.description.clone())),
        template: None,
        url: None,
        slug: None,
        redirect_uris: change.redirect_uris.unwrap_or_else(|| current.redirect_uris.clone()),
        post_logout_redirect_uris: change
            .post_logout_redirect_uris
            .unwrap_or_else(|| current.post_logout_redirect_uris.clone()),
        backchannel_logout_uri: change.backchannel_logout_uri.or_else(|| current.backchannel_logout_uri.clone()),
        grant_types: Some(change.grant_types.unwrap_or_else(|| current.grant_types.clone())),
        public,
        token_auth_method: Some(change.token_auth_method.unwrap_or_else(|| current.token_auth_method.clone())),
        id_token_alg: Some(change.id_token_alg.unwrap_or_else(|| current.id_token_alg.clone())),
        consent: change.consent.unwrap_or(current.consent),
        require_pkce: change.require_pkce.unwrap_or(current.require_pkce),
        allowed_groups: change.allowed_groups.unwrap_or_else(|| current.allowed_groups.clone()),
        require_mfa: change.require_mfa.unwrap_or(current.require_mfa),
        roles: change.roles.unwrap_or_else(|| serde_json::from_str(&current.roles).unwrap_or_default()),
        access_token_minutes: Some(change.access_token_minutes.unwrap_or(current.access_token_minutes)),
        refresh_token_days: Some(change.refresh_token_days.unwrap_or(current.refresh_token_days)),
        launch_url: change.launch_url.or_else(|| current.launch_url.clone()),
    }
}

async fn change(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(change): Json<Change>,
) -> ApiResult<Json<Value>> {
    let current = state.store.app(&id).await?.ok_or_else(ApiError::not_found)?;
    let public = current.secret_hash.is_none() || change.public == Some(true);
    let name = match change.name.as_deref() {
        Some(name) => {
            policy::optional(Some(name), 80).ok_or_else(|| ApiError::field("name", "required", "A name is needed."))?
        }
        None => current.name.clone(),
    };
    let disabled = change.disabled.unwrap_or(current.disabled);
    let checked = fields(&state, current.clone(), merged(&current, change, public)).await?;
    let updated = state
        .store
        .update_app(&id, move |app| {
            *app = App {
                name,
                disabled,
                secret_hash: if public { None } else { app.secret_hash.clone() },
                token_auth_method: if public { "none".into() } else { checked.token_auth_method.clone() },
                ..checked
            };
        })
        .await?
        .ok_or_else(ApiError::not_found)?;
    audit(&state, "app_changed", Some(&admin.actor_id()), None, Some(&id), &ip, json!({ "name": updated.name })).await;
    // Who may use it or its roles may have changed: that goes to the app over SCIM.
    state.scim.wake();
    let mut body = app_view(&updated);
    Extras::load(&state).await?.add(&state, &id, &mut body);
    Ok(Json(body))
}

async fn remove(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let app = state.store.app(&id).await?.ok_or_else(ApiError::not_found)?;
    state.store.delete_app(&id).await?;
    audit(&state, "app_deleted", Some(&admin.actor_id()), None, Some(&id), &ip, json!({ "name": app.name })).await;
    Ok(StatusCode::NO_CONTENT)
}

/// A new secret for an app: the old one stops working at once. For an app without a secret, it
/// gets one (it becomes confidential).
async fn new_secret(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if let AdminOnly::Person(me) = &admin {
        me.require_fresh()?;
    }
    let secret = random_token(32);
    let hash = sha256(secret.as_bytes());
    let app = state
        .store
        .update_app(&id, move |app| {
            app.secret_hash = Some(hash);
            if app.token_auth_method == "none" {
                app.token_auth_method = "client_secret_basic".into();
            }
        })
        .await?
        .ok_or_else(ApiError::not_found)?;
    audit(&state, "app_secret_renewed", Some(&admin.actor_id()), None, Some(&id), &ip, json!({ "name": app.name }))
        .await;
    Ok(Json(json!({ "clientId": app.client_id, "clientSecret": secret })))
}

async fn app_templates(State(state): State<AppState>, me: Me) -> ApiResult<Json<Value>> {
    if !me.admin {
        return Err(ApiError::forbidden("Only admins can do this."));
    }
    Ok(Json(templates::list(&state.config.public, &me.person.language)))
}

async fn registration_tokens(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let tokens = state.store.registration_tokens().await?;
    Ok(Json(json!(tokens
        .iter()
        .map(|token| json!({ "id": token.id, "name": token.name, "usesLeft": token.uses_left, "created": token.created, "expires": token.expires, "createdBy": token.created_by }))
        .collect::<Vec<_>>())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewRegistration {
    name: String,
    #[serde(default)]
    uses: Option<i64>,
    #[serde(default)]
    hours: Option<i64>,
}

async fn create_registration_token(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(new): Json<NewRegistration>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let name = policy::optional(Some(&new.name), 80)
        .ok_or_else(|| ApiError::field("name", "required", "A name is needed."))?;
    let secret = format!("uwureg_{}", random_token(32));
    let expires = clock::in_seconds(new.hours.unwrap_or(24).clamp(1, 24 * 30) * 3600);
    let made = state
        .store
        .create_registration_token(
            sha256(secret.as_bytes()),
            &name,
            new.uses.unwrap_or(1).clamp(1, 100),
            admin.person().map(|person| person.id.as_str()),
            &expires,
        )
        .await?;
    audit(
        &state,
        "registration_token_created",
        Some(&admin.actor_id()),
        None,
        Some(&made.id),
        &ip,
        json!({ "name": name }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": made.id, "name": made.name, "usesLeft": made.uses_left, "expires": made.expires, "secret": secret }),
        ),
    ))
}

async fn delete_registration_token(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_registration_token(&id).await? {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// "My apps": the apps this person may use that have an address to open, and the apps they
/// signed in to, with what they allowed each.
async fn my_apps(State(state): State<AppState>, me: Me) -> ApiResult<Json<Value>> {
    let apps = state.store.apps().await?;
    let membership = state.store.membership().await?;
    let groups = membership.groups_of(&me.person.id);
    let grants = state.store.grants_of(&me.person.id).await?;
    let extras = Extras::load(&state).await?;
    let usable: Vec<Value> = apps
        .iter()
        .filter(|app| !app.disabled && app.launch_url.is_some())
        .filter(|app| app.allowed_groups.is_empty() || app.allowed_groups.iter().any(|group| groups.contains(group)))
        .map(|app| json!({ "id": app.id, "name": app.name, "description": app.description, "launchUrl": app.launch_url, "template": app.template, "icon": extras.icon(&state, &app.id) }))
        .collect();
    let connected: Vec<Value> = grants
        .iter()
        .filter_map(|grant| {
            let app = apps.iter().find(|app| app.id == grant.app_id)?;
            Some(json!({ "id": grant.id, "app": app.name, "appId": app.id, "scopes": grant.scope.split_whitespace().collect::<Vec<_>>(), "created": grant.created, "lastUsed": grant.last_used }))
        })
        .collect();
    Ok(Json(json!({ "apps": usable, "connected": connected })))
}

async fn revoke_grant(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.revoke_grant(&me.person.id, &id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "grant_revoked", Some(&me.person.id), Some(&me.person.id), Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_addresses() {
        for good in [
            "https://app.example.com/cb",
            "http://127.0.0.1:8080/cb",
            "http://localhost/cb",
            "com.example.app:/oauth",
            "app.immich:///oauth-callback",
        ] {
            assert!(check_uri(good).is_ok(), "{good}");
        }
        for bad in [
            "javascript:alert(1)",
            "https://app.example.com/cb#x",
            "https://user:pw@app.example.com/",
            "http://app.example.com/cb",
            "data:text/html,x",
            "not a url",
        ] {
            assert!(check_uri(bad).is_err(), "{bad}");
        }
        assert!(check_admin_uri("http://nas.example.com:8080/cb").is_ok(), "an admin may use http in the home network");
    }

    #[test]
    fn client_ids_are_readable() {
        let id = client_id("Nextcloud Familie!");
        assert!(id.starts_with("nextcloud-familie-"), "{id}");
        assert!(client_id("!!!").starts_with("app-"));
    }
}
