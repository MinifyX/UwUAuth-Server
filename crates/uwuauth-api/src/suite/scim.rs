//! Pushing people and groups to apps over SCIM 2.0 (RFC 7643, RFC 7644).
//!
//! An app with a SCIM address — every paired suite app that named one, or any app an admin set
//! one up for — gets:
//!
//! - **the people who may use it** (all, or those in its allowed groups) as `User`s: `userName`
//!   (their address, or their user name if the app wants that), `externalId` (their id here, which
//!   never changes), `displayName`, `name`, `emails`, `active`;
//! - **the groups it cares about** — its allowed groups and those its roles come from, never
//!   `everyone` — as `Group`s with those people as members, if it takes groups.
//!
//! Somebody who may no longer use the app, is disabled, ran out or is in the trash becomes
//! `active: false`; somebody gone for good is deleted there. The app's ids and what it was sent
//! last are kept, so a push only sends what changed: `POST` for someone new (a `409` means the
//! app knows them already — found by filter and taken over), `PATCH` for a change, `DELETE` for
//! who is gone. An address is never changed by SCIM when it is the `userName`: for UwULock it is
//! part of the vault's key, and the person changes it there.
//!
//! One task pushes, in the background: when the directory changes, when an app is paired or
//! changed, when an admin asks, and every five minutes anyway (accounts run out without anybody
//! changing anything). Suite apps are the admin's own, often in the same home network, so
//! private addresses are fine; redirects are never followed.

use super::scim_view;
use crate::errors::{ApiError, ApiResult};
use crate::session::{AdminOnly, ClientIp};
use crate::{AppState, audit};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uwuauth_store::{EVERYONE_ID, Person, ScimObject, ScimTarget};

/// How often the task looks whether the directory changed.
const TICK: Duration = Duration::from_secs(30);
/// How often it pushes even when nothing seems to have changed.
const EVERY: Duration = Duration::from_secs(5 * 60);
/// What an answer from an app may be at the most.
const MAX_ANSWER: usize = 1024 * 1024;

const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// Wakes the task that pushes.
#[derive(Default)]
pub struct Pusher {
    wake: tokio::sync::Notify,
}

impl Pusher {
    /// Push soon: something changed that the directory's generation does not count.
    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

/// Start the task that pushes.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut seen = None;
        let mut last: Option<Instant> = None;
        loop {
            let woken = tokio::select! {
                () = state.scim.wake.notified() => true,
                () = tokio::time::sleep(TICK) => false,
            };
            let generation = state.store.generation();
            if !woken && seen == Some(generation) && last.is_some_and(|at| at.elapsed() < EVERY) {
                continue;
            }
            seen = Some(generation);
            last = Some(Instant::now());
            push_all(&state).await;
        }
    });
}

/// Push to every app with a SCIM address.
pub async fn push_all(state: &AppState) {
    let targets = match state.store.scim_targets().await {
        Ok(targets) => targets,
        Err(error) => return tracing::warn!(%error, "SCIM: the apps to push to could not be read"),
    };
    for target in targets {
        if let Err(error) = push(state, &target.app_id).await {
            tracing::warn!(app = target.app_id, error = error.message, "SCIM: pushing failed");
        }
    }
}

/// What one push did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pushed {
    pub created: usize,
    pub changed: usize,
    pub deleted: usize,
    pub errors: Vec<String>,
}

/// Something that ended a push early: the app could not be reached at all.
struct Unreachable(String);

/// An app's SCIM endpoint.
struct Endpoint {
    base: String,
    token: String,
    http: reqwest::Client,
}

fn client() -> Result<reqwest::Client, String> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent("UwUAuth-Server")
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())
}

impl Endpoint {
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value), Unreachable> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/scim+json, application/json");
        if let Some(body) = body {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/scim+json").body(body.to_string());
        }
        let mut response = request.send().await.map_err(|error| Unreachable(without_url(error)))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| Unreachable(without_url(error)))? {
            if bytes.len() + chunk.len() > MAX_ANSWER {
                return Err(Unreachable("the app answered with far too much".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
    }

    /// The id of the one resource `filter` finds.
    async fn find(&self, resource: &str, attribute: &str, value: &str) -> Result<Option<String>, Unreachable> {
        let filter = format!("{attribute} eq {}", Value::String(value.to_string()));
        let query: String =
            url::form_urlencoded::Serializer::new(String::new()).append_pair("filter", &filter).finish();
        let (status, body) = self.send(reqwest::Method::GET, &format!("/{resource}?{query}"), None).await?;
        if status != 200 {
            return Ok(None);
        }
        Ok(body["Resources"].get(0).and_then(|found| found["id"].as_str()).map(str::to_string))
    }
}

/// An error without the address in it (which the admin knows) — only what went wrong.
fn without_url(error: reqwest::Error) -> String {
    if error.is_timeout() { "the app did not answer in time".into() } else { error.without_url().to_string() }
}

/// What an app said went wrong: its status and a little of its `detail`.
fn refused(what: &str, status: u16, body: &Value) -> String {
    let detail: String = body["detail"].as_str().unwrap_or_default().chars().take(200).collect();
    if detail.is_empty() { format!("{what}: {status}") } else { format!("{what}: {status} {detail}") }
}

/// A person as they are sent, and what is compared to know whether they changed.
struct UserDoc {
    person: String,
    user_name: String,
    display_name: String,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    language: String,
    active: bool,
}

impl UserDoc {
    fn full(&self) -> Value {
        let mut body = json!({
            "schemas": [USER],
            "userName": self.user_name,
            "externalId": self.person,
            "displayName": self.display_name,
            "name": { "formatted": self.display_name },
            "preferredLanguage": self.language,
            "active": self.active,
        });
        if let Some(given) = &self.given_name {
            body["name"]["givenName"] = json!(given);
        }
        if let Some(family) = &self.family_name {
            body["name"]["familyName"] = json!(family);
        }
        if let Some(email) = &self.email {
            body["emails"] = json!([{ "value": email, "type": "work", "primary": true }]);
        }
        body
    }

    /// What a later PATCH may change, as kept.
    fn sent(&self) -> Value {
        json!({ "userName": self.user_name, "externalId": self.person, "displayName": self.display_name, "active": self.active })
    }
}

/// What a PATCH changes on a person. `userName` only when the app keys people by user name: an
/// address is never changed by SCIM.
const USER_FIELDS: &[&str] = &["active", "displayName", "externalId"];
const USER_FIELDS_AND_NAME: &[&str] = &["active", "displayName", "externalId", "userName"];
/// What a PATCH changes on a group.
const GROUP_FIELDS: &[&str] = &["displayName", "members"];

/// PATCH operations that make `before` into `after`, for `fields`.
fn operations(before: &Value, after: &Value, fields: &[&str]) -> Vec<Value> {
    fields
        .iter()
        .filter(|field| after.get(*field).is_some() && before.get(*field) != after.get(*field))
        .map(|field| json!({ "op": "replace", "path": field, "value": after[field] }))
        .collect()
}

fn patch(operations: Vec<Value>) -> Value {
    json!({ "schemas": [PATCH], "Operations": operations })
}

/// Push to one app now. Errors about single people or groups are collected and noted on the app;
/// an app that cannot be reached at all ends the push.
pub async fn push(state: &AppState, app_id: &str) -> ApiResult<Pushed> {
    let Some(target) = state.store.scim_target(app_id).await? else { return Ok(Pushed::default()) };
    let Some(app) = state.store.app(app_id).await? else { return Ok(Pushed::default()) };
    if app.disabled {
        return Ok(Pushed::default());
    }
    let mut pushed = Pushed::default();
    let outcome = match open(state, &target) {
        Ok(endpoint) => run(state, &app, &target, &endpoint, &mut pushed).await,
        Err(error) => Err(Unreachable(error)),
    };
    let error = match outcome {
        Err(Unreachable(error)) => Some(error),
        Ok(()) if !pushed.errors.is_empty() => Some(format!(
            "{}{}",
            pushed.errors[0],
            if pushed.errors.len() > 1 { format!(" (and {} more)", pushed.errors.len() - 1) } else { String::new() }
        )),
        Ok(()) => None,
    };
    state.store.scim_pushed(app_id, error.as_deref()).await?;
    if let Some(error) = &error
        && target.error.is_none()
    {
        tracing::warn!(app = app.name, error, "SCIM: pushing to the app failed");
        let nobody: std::net::IpAddr = std::net::Ipv4Addr::UNSPECIFIED.into();
        audit(
            state,
            "app_scim_failed",
            None,
            None,
            Some(&app.id),
            &nobody,
            json!({ "name": app.name, "error": error }),
        )
        .await;
    }
    if let Some(error) = error
        && pushed.errors.is_empty()
    {
        pushed.errors.push(error);
    }
    Ok(pushed)
}

fn open(state: &AppState, target: &ScimTarget) -> Result<Endpoint, String> {
    let token = state
        .sealer
        .open(&target.token)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or("the SCIM token cannot be opened with this server's key")?;
    Ok(Endpoint { base: target.base_url.trim_end_matches('/').to_string(), token, http: client()? })
}

async fn run(
    state: &AppState,
    app: &uwuauth_store::App,
    target: &ScimTarget,
    endpoint: &Endpoint,
    pushed: &mut Pushed,
) -> Result<(), Unreachable> {
    let store = &state.store;
    let internal = |error: uwuauth_store::StoreError| Unreachable(format!("database: {error}"));
    let people = store.people().await.map_err(internal)?;
    let membership = store.membership().await.map_err(internal)?;
    let groups = store.groups().await.map_err(internal)?;
    let known = store.scim_objects(&app.id).await.map_err(internal)?;
    let mut users: HashMap<String, ScimObject> = HashMap::new();
    let mut remote_groups: HashMap<String, ScimObject> = HashMap::new();
    for object in known {
        if object.kind == "group" {
            remote_groups.insert(object.local_id.clone(), object);
        } else {
            users.insert(object.local_id.clone(), object);
        }
    }
    let allowed: BTreeSet<&str> =
        app.allowed_groups.iter().map(String::as_str).filter(|group| *group != EVERYONE_ID).collect();
    let may_use = |person: &Person| {
        person.deleted.is_none()
            && (allowed.is_empty()
                || membership.groups_of(&person.id).iter().any(|group| allowed.contains(group.as_str())))
    };
    let by_user_name = target.user_name == "username";

    // People.
    let mut active: BTreeMap<String, String> = BTreeMap::new();
    let present: BTreeSet<&str> = people.iter().map(|person| person.id.as_str()).collect();
    for person in &people {
        let before = users.get(&person.id);
        let wanted = may_use(person);
        if !wanted && before.is_none() {
            continue;
        }
        let sent_before: Value =
            before.map(|object| serde_json::from_str(&object.sent).unwrap_or_default()).unwrap_or_default();
        // The address the app knows the person by stays what it was (see above).
        let user_name = if by_user_name {
            Some(person.username.clone())
        } else {
            sent_before["userName"].as_str().map(str::to_string).or_else(|| person.email.clone())
        };
        let Some(user_name) = user_name else { continue };
        let doc = UserDoc {
            person: person.id.clone(),
            user_name,
            display_name: person.display_name.clone(),
            given_name: person.given_name.clone(),
            family_name: person.family_name.clone(),
            email: person.email.clone(),
            language: person.language.clone(),
            active: wanted && person.active(),
        };
        let what = format!("{} ({})", person.username, if before.is_some() { "change" } else { "new" });
        let remote = match before {
            Some(object) => {
                update_user(endpoint, object, &sent_before, &doc, by_user_name, true, &what, pushed).await?
            }
            None => create_user(endpoint, &doc, &what, pushed).await?,
        };
        if let Some((remote, current)) = remote {
            if current {
                let sent = doc.sent().to_string();
                let object =
                    ScimObject { kind: "user".into(), local_id: person.id.clone(), remote_id: remote.clone(), sent };
                store.put_scim_object(&app.id, object).await.map_err(internal)?;
            }
            if doc.active {
                active.insert(person.id.clone(), remote);
            }
        }
    }
    for (local, object) in &users {
        if present.contains(local.as_str()) {
            continue;
        }
        let (status, body) =
            endpoint.send(reqwest::Method::DELETE, &format!("/Users/{}", segment(&object.remote_id)), None).await?;
        if matches!(status, 200 | 204 | 404) {
            pushed.deleted += 1;
            store.delete_scim_object(&app.id, "user", local).await.map_err(internal)?;
        } else {
            pushed.errors.push(refused("deleting a person", status, &body));
        }
    }

    // Groups.
    let wanted_groups: BTreeSet<String> = if target.resources.iter().any(|resource| resource == "Group") {
        let roles: Vec<crate::routes::apps::RoleIn> = serde_json::from_str(&app.roles).unwrap_or_default();
        allowed
            .iter()
            .map(|group| group.to_string())
            .chain(roles.into_iter().map(|role| role.group))
            .filter(|group| group != EVERYONE_ID && groups.iter().any(|known| known.id == *group))
            .collect()
    } else {
        BTreeSet::new()
    };
    let everybody: Vec<String> =
        people.iter().filter(|person| person.deleted.is_none()).map(|p| p.id.clone()).collect();
    for group in groups.iter().filter(|group| wanted_groups.contains(&group.id)) {
        let members: Vec<String> = membership
            .people_in(&group.id, &everybody)
            .iter()
            .filter_map(|person| active.get(person).cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let doc = json!({
            "displayName": group.name,
            "externalId": group.id,
            "members": members.iter().map(|id| json!({ "value": id })).collect::<Vec<_>>(),
        });
        let what = format!("group {}", group.name);
        let remote = match remote_groups.get(&group.id) {
            Some(object) => update_group(endpoint, object, &doc, true, &what, pushed).await?,
            None => create_group(endpoint, &doc, &what, pushed).await?,
        };
        if let Some((remote, true)) = remote {
            store
                .put_scim_object(
                    &app.id,
                    ScimObject {
                        kind: "group".into(),
                        local_id: group.id.clone(),
                        remote_id: remote,
                        sent: doc.to_string(),
                    },
                )
                .await
                .map_err(internal)?;
        }
    }
    for (local, object) in &remote_groups {
        if wanted_groups.contains(local) {
            continue;
        }
        let (status, body) =
            endpoint.send(reqwest::Method::DELETE, &format!("/Groups/{}", segment(&object.remote_id)), None).await?;
        if matches!(status, 200 | 204 | 404) {
            pushed.deleted += 1;
            store.delete_scim_object(&app.id, "group", local).await.map_err(internal)?;
        } else {
            pushed.errors.push(refused("deleting a group", status, &body));
        }
    }
    Ok(())
}

/// An id from the app, safe in a path.
fn segment(id: &str) -> String {
    url::form_urlencoded::byte_serialize(id.as_bytes()).collect()
}

/// What a create or an update ended with: the app's id, and whether it has what was sent — or
/// nothing, when the app refused.
type Outcome = Result<Option<(String, bool)>, Unreachable>;

/// A new person there.
async fn create_user(endpoint: &Endpoint, doc: &UserDoc, what: &str, pushed: &mut Pushed) -> Outcome {
    if !doc.active {
        return Ok(None);
    }
    let (status, body) = endpoint.send(reqwest::Method::POST, "/Users", Some(&doc.full())).await?;
    match status {
        200 | 201 => match body["id"].as_str() {
            Some(id) => {
                pushed.created += 1;
                Ok(Some((id.to_string(), true)))
            }
            None => {
                pushed.errors.push(format!("{what}: the app answered without an id"));
                Ok(None)
            }
        },
        // The app knows them already: found, and brought up to date.
        409 => match endpoint.find("Users", "userName", &doc.user_name).await? {
            Some(id) => {
                let object =
                    ScimObject { kind: "user".into(), local_id: doc.person.clone(), remote_id: id, sent: "{}".into() };
                update_user(endpoint, &object, &json!({}), doc, false, false, what, pushed).await
            }
            None => {
                pushed.errors.push(refused(what, status, &body));
                Ok(None)
            }
        },
        _ => {
            pushed.errors.push(refused(what, status, &body));
            Ok(None)
        }
    }
}

/// A change to a person there. `again`: make them anew if the app lost them.
#[allow(clippy::too_many_arguments)]
async fn update_user(
    endpoint: &Endpoint,
    object: &ScimObject,
    before: &Value,
    doc: &UserDoc,
    by_user_name: bool,
    again: bool,
    what: &str,
    pushed: &mut Pushed,
) -> Outcome {
    let operations = operations(before, &doc.sent(), if by_user_name { USER_FIELDS_AND_NAME } else { USER_FIELDS });
    if operations.is_empty() {
        return Ok(Some((object.remote_id.clone(), true)));
    }
    let path = format!("/Users/{}", segment(&object.remote_id));
    let (status, body) = endpoint.send(reqwest::Method::PATCH, &path, Some(&patch(operations))).await?;
    match status {
        200 | 204 => {
            pushed.changed += 1;
            Ok(Some((object.remote_id.clone(), true)))
        }
        // Gone there: made again, if they may use it.
        404 if again => Box::pin(create_user(endpoint, doc, what, pushed)).await,
        _ => {
            pushed.errors.push(refused(what, status, &body));
            // The id is still right; what was sent stays as it was, so it is tried again.
            Ok(Some((object.remote_id.clone(), false)))
        }
    }
}

async fn create_group(endpoint: &Endpoint, doc: &Value, what: &str, pushed: &mut Pushed) -> Outcome {
    let mut body = doc.clone();
    body["schemas"] = json!([GROUP]);
    let (status, answer) = endpoint.send(reqwest::Method::POST, "/Groups", Some(&body)).await?;
    match status {
        200 | 201 => match answer["id"].as_str() {
            Some(id) => {
                pushed.created += 1;
                Ok(Some((id.to_string(), true)))
            }
            None => {
                pushed.errors.push(format!("{what}: the app answered without an id"));
                Ok(None)
            }
        },
        409 => match endpoint.find("Groups", "displayName", doc["displayName"].as_str().unwrap_or_default()).await? {
            Some(id) => {
                let object =
                    ScimObject { kind: "group".into(), local_id: String::new(), remote_id: id, sent: "{}".into() };
                update_group(endpoint, &object, doc, false, what, pushed).await
            }
            None => {
                pushed.errors.push(refused(what, status, &answer));
                Ok(None)
            }
        },
        _ => {
            pushed.errors.push(refused(what, status, &answer));
            Ok(None)
        }
    }
}

async fn update_group(
    endpoint: &Endpoint,
    object: &ScimObject,
    doc: &Value,
    again: bool,
    what: &str,
    pushed: &mut Pushed,
) -> Outcome {
    let before: Value = serde_json::from_str(&object.sent).unwrap_or_default();
    let operations = operations(&before, doc, GROUP_FIELDS);
    if operations.is_empty() {
        return Ok(Some((object.remote_id.clone(), true)));
    }
    let path = format!("/Groups/{}", segment(&object.remote_id));
    let (status, answer) = endpoint.send(reqwest::Method::PATCH, &path, Some(&patch(operations))).await?;
    match status {
        200 | 204 => {
            pushed.changed += 1;
            Ok(Some((object.remote_id.clone(), true)))
        }
        404 if again => Box::pin(create_group(endpoint, doc, what, pushed)).await,
        _ => {
            pushed.errors.push(refused(what, status, &answer));
            Ok(Some((object.remote_id.clone(), false)))
        }
    }
}

// ── The admin portal ──────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetUp {
    base_url: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    resources: Option<Vec<String>>,
    #[serde(default)]
    user_name: Option<String>,
}

/// `PUT /uwu/v1/apps/{id}/scim`: where an app's SCIM is and the token to send. For a paired app
/// that means a new token from the app; for any other app, pushing starts.
pub(crate) async fn set_up(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<SetUp>,
) -> ApiResult<Json<Value>> {
    let app = state.store.app(&id).await?.ok_or_else(ApiError::not_found)?;
    let before = state.store.scim_target(&id).await?;
    let base_url = body.base_url.trim().trim_end_matches('/').to_string();
    let url = url::Url::parse(&base_url).map_err(|_| ApiError::field("baseUrl", "uri", "That is not an address."))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.fragment().is_some()
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || base_url.len() > 500
    {
        return Err(ApiError::field(
            "baseUrl",
            "uri",
            "The SCIM address is an http(s) address without anything after it.",
        ));
    }
    let token = match (body.token.as_deref().map(str::trim).filter(|token| !token.is_empty()), &before) {
        (Some(token), _) if token.len() <= 4096 => state.sealer.seal(token.as_bytes()),
        (Some(_), _) => return Err(ApiError::field("token", "invalid", "That token is far too long.")),
        (None, Some(before)) => before.token.clone(),
        (None, None) => return Err(ApiError::field("token", "required", "The app's SCIM token is needed.")),
    };
    let resources = body.resources.unwrap_or_else(|| {
        before.as_ref().map_or_else(|| vec!["User".into(), "Group".into()], |before| before.resources.clone())
    });
    if !resources.iter().any(|resource| resource == "User")
        || resources.iter().any(|resource| resource != "User" && resource != "Group")
    {
        return Err(ApiError::field("resources", "invalid", "SCIM resources are User and Group."));
    }
    let user_name = match body.user_name.as_deref() {
        Some("username") => "username".to_string(),
        Some("email") => "email".to_string(),
        None => before.as_ref().map_or_else(|| "email".to_string(), |before| before.user_name.clone()),
        Some(_) => return Err(ApiError::field("userName", "invalid", "userName is email or username.")),
    };
    let target = ScimTarget { app_id: id.clone(), base_url, token, resources, user_name, ..ScimTarget::default() };
    state.store.set_scim_target(target).await?;
    audit(&state, "app_scim_changed", Some(&admin.actor_id()), None, Some(&id), &ip, json!({ "name": app.name })).await;
    state.scim.wake();
    let target = state.store.scim_target(&id).await?.ok_or_else(ApiError::not_found)?;
    Ok(Json(scim_view(&target, 0, 0)))
}

/// `DELETE /uwu/v1/apps/{id}/scim`: stop pushing. What the app has stays there.
pub(crate) async fn remove(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let app = state.store.app(&id).await?.ok_or_else(ApiError::not_found)?;
    if !state.store.delete_scim_target(&id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "app_scim_removed", Some(&admin.actor_id()), None, Some(&id), &ip, json!({ "name": app.name })).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct SyncNow {
    /// Send everybody again, not only what changed.
    all: bool,
}

/// `POST /uwu/v1/apps/{id}/scim/sync`: push now, in the background.
pub(crate) async fn sync_now(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(id): Path<String>,
    body: Option<Json<SyncNow>>,
) -> ApiResult<StatusCode> {
    state.store.scim_target(&id).await?.ok_or_else(ApiError::not_found)?;
    if body.is_some_and(|Json(body)| body.all) {
        state.store.scim_resend(&id).await?;
    }
    state.scim.wake();
    Ok(StatusCode::ACCEPTED)
}
