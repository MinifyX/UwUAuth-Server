//! Managing people, for admins — and for managers, the people they look after.
//!
//! A manager (a parent, a team lead) sees only the people they look after and may: make new
//! accounts they then look after (a kid's), change names and language and the picture, set a
//! password, make a setup link (the QR code for the kid's tablet), take away the authenticator
//! app, disable and enable, end sessions, set the time windows, and read the events. Admins may
//! do everything, to everybody. Nobody can take away the last admin.

use super::me::{check_jpeg, end_by_short_id, event_view, notify, now_text, session_view};
use super::{new_password, passkey_view, person_view};
use crate::crypto::{random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::session::{ClientIp, Me};
use crate::{AppState, audit, policy};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uwuauth_mail::{Language, Mail};
use uwuauth_store::{ADMINS_ID, AttributeDef, EventFilter, Managed, NewPerson, Person, Purpose, Window, clock, people};

/// How long a setup link works: long enough to get to the kid's tablet.
pub const SETUP_DAYS: i64 = 7;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/people", get(list).post(create))
        .route("/uwu/v1/people/{id}", get(show).patch(change).delete(trash))
        .route("/uwu/v1/people/{id}/restore", post(restore))
        .route("/uwu/v1/people/{id}/purge", delete(purge))
        .route("/uwu/v1/people/{id}/disable", post(disable))
        .route("/uwu/v1/people/{id}/enable", post(enable))
        .route("/uwu/v1/people/{id}/link", post(link))
        .route("/uwu/v1/people/{id}/password", post(set_password))
        .route("/uwu/v1/people/{id}/totp", delete(remove_totp))
        .route("/uwu/v1/people/{id}/passkeys/{passkey}", delete(remove_passkey))
        .route("/uwu/v1/people/{id}/sessions", delete(end_sessions))
        .route("/uwu/v1/people/{id}/sessions/{session}", delete(end_session))
        .route("/uwu/v1/people/{id}/events", get(events))
        .route("/uwu/v1/people/{id}/groups", put(set_groups))
        .route("/uwu/v1/people/{id}/managers", put(set_managers))
        .route("/uwu/v1/people/{id}/manages", put(set_manages))
        .route("/uwu/v1/people/{id}/windows", put(set_windows))
        .route("/uwu/v1/people/{id}/avatar", put(set_avatar).delete(remove_avatar))
}

/// What the person asking may do to others.
pub(crate) enum Access {
    Admin,
    /// A manager, with the people they look after.
    Manager(BTreeSet<String>),
}

impl Access {
    pub(crate) async fn of(state: &AppState, me: &Me) -> ApiResult<Self> {
        if me.admin {
            return Ok(Access::Admin);
        }
        let membership = state.store.membership().await?;
        let everybody: Vec<String> = state.store.people().await?.into_iter().map(|person| person.id).collect();
        let managed = state.store.people_managed_by(&me.person.id, &membership, &everybody).await?;
        if managed.is_empty() && !state.store.managers().await?.contains(&me.person.id) {
            return Err(ApiError::forbidden("Only admins and managers can do this."));
        }
        Ok(Access::Manager(managed))
    }

    fn admin(&self) -> ApiResult<()> {
        match self {
            Access::Admin => Ok(()),
            Access::Manager(_) => Err(ApiError::forbidden("Only admins can do this.")),
        }
    }

    fn reaches(&self, person: &str) -> bool {
        match self {
            Access::Admin => true,
            Access::Manager(people) => people.contains(person),
        }
    }
}

/// The person `id`, if the one asking may see them; a manager gets "not found" for anybody else.
async fn target(state: &AppState, me: &Me, id: &str) -> ApiResult<(Access, Person)> {
    let access = Access::of(state, me).await?;
    if !access.reaches(id) {
        return Err(ApiError::not_found());
    }
    let person = state.store.person(id).await?.ok_or_else(ApiError::not_found)?;
    Ok((access, person))
}

/// Refuse to take the last admin away: disabling, deleting or leaving `admins`.
async fn keep_an_admin(state: &AppState, leaving: &str) -> ApiResult<()> {
    let admins = state.store.admin_ids().await?;
    if !admins.contains(leaving) {
        return Ok(());
    }
    let mut others = 0;
    for id in admins.iter().filter(|id| id.as_str() != leaving) {
        if state.store.person(id).await?.is_some_and(|person| person.active()) {
            others += 1;
        }
    }
    if others == 0 {
        return Err(ApiError::bad("last_admin", "That is the last admin. Make somebody else an admin first."));
    }
    Ok(())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct ListQuery {
    trash: bool,
}

async fn list(State(state): State<AppState>, me: Me, Query(query): Query<ListQuery>) -> ApiResult<Json<Value>> {
    let access = Access::of(&state, &me).await?;
    let membership = state.store.membership().await?;
    let admins = membership.people_in(ADMINS_ID, &[]);
    let avatars: BTreeSet<String> = state.store.avatar_ids().await?.into_iter().collect();
    let managers = state.store.managers().await?;
    let people: Vec<Value> = state
        .store
        .people()
        .await?
        .into_iter()
        .filter(|person| access.reaches(&person.id) && person.deleted.is_some() == query.trash)
        .map(|person| {
            let mut view = person_view(
                &state,
                &person,
                &membership.direct_groups_of(&person.id),
                admins.contains(&person.id),
                avatars.contains(&person.id),
            );
            view["manager"] = json!(managers.contains(&person.id));
            view
        })
        .collect();
    Ok(Json(json!(people)))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct NewAccount {
    username: String,
    display_name: String,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    language: Option<String>,
    managed: bool,
    groups: Vec<String>,
    admin: bool,
    password: Option<String>,
    /// Make a setup link at once (and mail it, if there is an address and `mail`).
    setup_link: bool,
    mail: bool,
}

async fn create(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Json(new): Json<NewAccount>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let access = Access::of(&state, &me).await?;
    let is_admin = matches!(access, Access::Admin);
    let username = policy::username(&new.username)?;
    let display_name =
        policy::display_name(if new.display_name.trim().is_empty() { &username } else { &new.display_name })?;
    let email = new.email.as_deref().filter(|email| !email.trim().is_empty()).map(policy::email).transpose()?;
    let language = policy::language(new.language.as_deref().unwrap_or(state.settings().default_language.code()));
    let person = state
        .store
        .create_person(NewPerson {
            id: None,
            username,
            display_name,
            given_name: policy::optional(new.given_name.as_deref(), 100),
            family_name: policy::optional(new.family_name.as_deref(), 100),
            email,
            email_verified: false,
            language,
            // What a manager makes, they look after.
            managed: new.managed || !is_admin,
        })
        .await?;
    // Groups: an admin any; a manager only groups they own.
    let membership = state.store.membership().await?;
    let mut groups: Vec<String> = new
        .groups
        .into_iter()
        .filter(|group| is_admin || membership.owners.get(group).is_some_and(|owners| owners.contains(&me.person.id)))
        .collect();
    if new.admin && is_admin {
        groups.push(ADMINS_ID.to_string());
    }
    state.store.set_groups_of(&person.id, groups).await?;
    if !is_admin {
        let mut managed = state.store.managed_by(&me.person.id).await?;
        managed.people.push(person.id.clone());
        state.store.set_managed(&me.person.id, managed).await?;
    }
    if let Some(password) = new.password.filter(|password| !password.is_empty()) {
        let hash = match new_password(&state, &person, &password).await {
            Ok(hash) => hash,
            Err(error) => {
                state.store.purge_person(&person.id).await?;
                return Err(error);
            }
        };
        state
            .store
            .update_person(&person.id, move |person| {
                person.password_hash = Some(hash);
                person.password_changed = Some(clock::now());
            })
            .await?;
    }
    audit(
        &state,
        "person_created",
        Some(&me.person.id),
        Some(&person.id),
        None,
        &ip,
        json!({ "username": person.username }),
    )
    .await;
    let mut body = json!({ "id": person.id, "username": person.username });
    if new.setup_link {
        body["link"] = make_link(&state, &me, &person, new.mail).await?;
    }
    Ok((StatusCode::CREATED, Json(body)))
}

async fn show(State(state): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (access, person) = target(&state, &me, &id).await?;
    let membership = state.store.membership().await?;
    let admins = membership.people_in(ADMINS_ID, &[]);
    let has_avatar = state.store.avatar(&person.id).await?.is_some();
    let mut body =
        person_view(&state, &person, &membership.direct_groups_of(&person.id), admins.contains(&person.id), has_avatar);
    body["memberOf"] = json!(membership.groups_of(&person.id));
    body["passkeys"] = json!(state.store.passkeys(&person.id).await?.iter().map(passkey_view).collect::<Vec<_>>());
    body["recoveryCodesLeft"] = json!(state.store.recovery_codes_left(&person.id).await?);
    body["appPasswords"] = json!(state.store.app_passwords(&person.id).await?.len());
    body["sessions"] = json!(
        state
            .store
            .sessions_of(&person.id)
            .await?
            .iter()
            .map(|session| session_view(session, None))
            .collect::<Vec<_>>()
    );
    body["windows"] =
        json!(state.store.windows("person", &person.id).await?.iter().map(window_view).collect::<Vec<_>>());
    body["attributes"] = json!(state.store.attributes_of(&person.id).await?);
    body["managers"] = json!(state.store.managers_of(&person.id).await?);
    let manages = state.store.managed_by(&person.id).await?;
    body["manages"] = json!({ "people": manages.people, "groups": manages.groups });
    body["canEdit"] = json!(if matches!(access, Access::Admin) { "all" } else { "managed" });
    Ok(Json(body))
}

pub(crate) fn window_view(window: &Window) -> Value {
    json!({ "days": window.days, "start": window.start_minute, "end": window.end_minute, "app": window.app_id })
}

/// Check one attribute's value against its definition: the value as it is kept.
pub(crate) fn check_attribute(def: &AttributeDef, value: &str) -> ApiResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(value);
    }
    let bad = || ApiError::field(&def.name, "attribute", format!("That is not a valid {}.", def.label));
    match def.kind.as_str() {
        "number" => {
            value.parse::<f64>().map_err(|_| bad())?;
        }
        "date" => {
            time::Date::parse(&value, time::macros::format_description!("[year]-[month]-[day]")).map_err(|_| bad())?;
        }
        "choice" => {
            let choices: Vec<String> = serde_json::from_str(&def.choices).unwrap_or_default();
            if !choices.contains(&value) {
                return Err(bad());
            }
        }
        _ => {}
    }
    Ok(value.chars().filter(|c| !c.is_control()).take(500).collect())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Change {
    username: Option<String>,
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    language: Option<String>,
    managed: Option<bool>,
    /// `null` or empty for never.
    expires: Option<String>,
    login_shell: Option<String>,
    home_directory: Option<String>,
    attributes: Option<BTreeMap<String, String>>,
}

async fn change(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(change): Json<Change>,
) -> ApiResult<Json<Value>> {
    let (access, person) = target(&state, &me, &id).await?;
    let admin_only = change.username.is_some()
        || change.email.is_some()
        || change.email_verified.is_some()
        || change.managed.is_some()
        || change.expires.is_some()
        || change.login_shell.is_some()
        || change.home_directory.is_some()
        || change.attributes.is_some();
    if admin_only {
        access.admin()?;
    }
    let username = change.username.as_deref().map(policy::username).transpose()?;
    let display = change.display_name.as_deref().map(policy::display_name).transpose()?;
    let email = match change.email.as_deref() {
        Some("") => Some(None),
        Some(email) => Some(Some(policy::email(email)?)),
        None => None,
    };
    let expires = match change.expires.as_deref() {
        Some("") => Some(None),
        Some(text) => Some(Some(clock::format(
            clock::parse(text).ok_or_else(|| ApiError::field("expires", "date", "That is not a time."))?,
        ))),
        None => None,
    };
    let mut attributes = BTreeMap::new();
    if let Some(values) = change.attributes {
        let defs = state.store.attribute_defs().await?;
        for (name, value) in values {
            let def = defs
                .iter()
                .find(|def| def.name == name)
                .ok_or_else(|| ApiError::field(&name, "unknown", "There is no such attribute."))?;
            attributes.insert(name, check_attribute(def, &value)?);
        }
    }
    let renamed = username.is_some() || email.is_some();
    let updated = state
        .store
        .update_person(&person.id, move |person| {
            if let Some(username) = username {
                person.username = username;
            }
            if let Some(display) = display {
                person.display_name = display;
            }
            if let Some(given) = change.given_name {
                person.given_name = policy::optional(Some(&given), 100);
            }
            if let Some(family) = change.family_name {
                person.family_name = policy::optional(Some(&family), 100);
            }
            if let Some(email) = email {
                if person.email != email {
                    person.email_verified = false;
                }
                person.email = email;
            }
            if let Some(verified) = change.email_verified {
                person.email_verified = verified && person.email.is_some();
            }
            if let Some(language) = change.language {
                person.language = policy::language(&language);
            }
            if let Some(managed) = change.managed {
                person.managed = managed;
            }
            if let Some(expires) = expires {
                person.expires = expires;
            }
            if let Some(shell) = change.login_shell {
                person.login_shell = policy::optional(Some(&shell), 200);
            }
            if let Some(home) = change.home_directory {
                person.home_directory = policy::optional(Some(&home), 200);
            }
        })
        .await?;
    state.store.set_attributes(&updated.id, attributes).await?;
    audit(&state, "person_changed", Some(&me.person.id), Some(&updated.id), None, &ip, json!({ "renamed": renamed }))
        .await;
    Ok(Json(json!({ "id": updated.id, "updated": updated.updated })))
}

async fn trash(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let (access, person) = target(&state, &me, &id).await?;
    access.admin()?;
    if person.id == me.person.id {
        return Err(ApiError::bad("self", "You cannot delete yourself."));
    }
    keep_an_admin(&state, &person.id).await?;
    state
        .store
        .update_person(&person.id, |person| {
            person.deleted = Some(clock::now());
            person.security_stamp = people::stamp();
        })
        .await?;
    state.store.end_sessions(&person.id, None).await?;
    audit(
        &state,
        "person_deleted",
        Some(&me.person.id),
        Some(&person.id),
        None,
        &ip,
        json!({ "username": person.username }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn restore(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let (access, person) = target(&state, &me, &id).await?;
    access.admin()?;
    state.store.update_person(&person.id, |person| person.deleted = None).await?;
    audit(&state, "person_restored", Some(&me.person.id), Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn purge(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let (access, person) = target(&state, &me, &id).await?;
    access.admin()?;
    if person.deleted.is_none() {
        return Err(ApiError::bad("not_in_trash", "Move the person to the trash first."));
    }
    state.store.purge_person(&person.id).await?;
    audit(
        &state,
        "person_purged",
        Some(&me.person.id),
        Some(&person.id),
        None,
        &ip,
        json!({ "username": person.username }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn disable(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let (_, person) = target(&state, &me, &id).await?;
    if person.id == me.person.id {
        return Err(ApiError::bad("self", "You cannot disable yourself."));
    }
    keep_an_admin(&state, &person.id).await?;
    state
        .store
        .update_person(&person.id, |person| {
            person.disabled = true;
            person.security_stamp = people::stamp();
        })
        .await?;
    state.store.end_sessions(&person.id, None).await?;
    audit(&state, "person_disabled", Some(&me.person.id), Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn enable(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let (_, person) = target(&state, &me, &id).await?;
    state.store.update_person(&person.id, |person| person.disabled = false).await?;
    audit(&state, "person_enabled", Some(&me.person.id), Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LinkRequest {
    mail: bool,
}

/// A setup link (for somebody without a way to sign in) or a new-password link: to show as a QR
/// code, pass on, or mail.
async fn make_link(state: &AppState, me: &Me, person: &Person, mail: bool) -> ApiResult<Value> {
    let setup = person.password_hash.is_none() && state.store.passkeys(&person.id).await?.is_empty();
    let purpose = if setup { Purpose::Setup } else { Purpose::Reset };
    let token = random_token(32);
    let expires = clock::in_seconds(if setup { SETUP_DAYS * 86_400 } else { 86_400 });
    state
        .store
        .create_link(sha256(token.as_bytes()), purpose, Some(&person.id), "{}", Some(&me.person.id), &expires)
        .await?;
    let path = if setup { "setup" } else { "reset" };
    let link = state.link(&format!("/{path}?token={token}"));
    let mut mailed = None;
    if mail && let Some(to) = person.email.clone() {
        let mail = if setup {
            Mail::Invitation {
                link: link.clone(),
                organization: state.settings().organization,
                invited_by: Some(me.person.display_name.clone()),
                expires: clock::parse(&expires).map(|at| at.date().to_string()).unwrap_or_default(),
            }
        } else {
            Mail::PasswordReset { link: link.clone(), minutes: 24 * 60 }
        };
        state
            .mailer
            .send(&to, &mail, Language::from_code(&person.language))
            .await
            .map_err(|error| ApiError::bad("mail_failed", error.to_string()))?;
        mailed = Some(to);
    }
    Ok(json!({ "purpose": path, "link": link, "expires": expires, "mailed": mailed }))
}

async fn link(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    body: Option<Json<LinkRequest>>,
) -> ApiResult<Json<Value>> {
    let (_, person) = target(&state, &me, &id).await?;
    if person.deleted.is_some() {
        return Err(ApiError::not_found());
    }
    let mail = body.is_some_and(|Json(body)| body.mail);
    let link = make_link(&state, &me, &person, mail).await?;
    audit(
        &state,
        "link_made",
        Some(&me.person.id),
        Some(&person.id),
        None,
        &ip,
        json!({ "purpose": link["purpose"], "mailed": link["mailed"] }),
    )
    .await;
    Ok(Json(link))
}

#[derive(Deserialize)]
struct NewPassword {
    password: String,
}

async fn set_password(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<NewPassword>,
) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    let (_, person) = target(&state, &me, &id).await?;
    let hash = new_password(&state, &person, &body.password).await?;
    let person = state
        .store
        .update_person(&person.id, move |person| {
            person.password_hash = Some(hash);
            person.password_changed = Some(clock::now());
            person.security_stamp = people::stamp();
        })
        .await?;
    state.store.end_sessions(&person.id, None).await?;
    audit(&state, "password_set", Some(&me.person.id), Some(&person.id), None, &ip, json!({})).await;
    notify(&state, &person, Mail::PasswordChanged { time: now_text(&state) });
    Ok(StatusCode::NO_CONTENT)
}

/// For a lost phone: the authenticator app goes, and with it the recovery codes.
async fn remove_totp(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    let (_, person) = target(&state, &me, &id).await?;
    state.store.update_person(&person.id, |person| person.totp_secret = None).await?;
    state.store.set_recovery_codes(&person.id, Vec::new()).await?;
    audit(&state, "totp_reset", Some(&me.person.id), Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_passkey(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path((id, passkey)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    me.require_fresh()?;
    let (_, person) = target(&state, &me, &id).await?;
    if !state.store.remove_passkey(&person.id, &passkey).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "passkey_removed", Some(&me.person.id), Some(&person.id), Some(&passkey), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn end_sessions(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, person) = target(&state, &me, &id).await?;
    let keep = (person.id == me.person.id).then_some(me.session.id.as_slice());
    let ended = state.store.end_sessions(&person.id, keep).await?;
    audit(&state, "sessions_ended", Some(&me.person.id), Some(&person.id), None, &ip, json!({ "count": ended })).await;
    Ok(Json(json!({ "ended": ended })))
}

async fn end_session(
    State(state): State<AppState>,
    me: Me,
    Path((id, session)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (_, person) = target(&state, &me, &id).await?;
    end_by_short_id(&state, &person.id, &session).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn events(
    State(state): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Query(page): Query<super::me::Page>,
) -> ApiResult<Json<Value>> {
    let (_, person) = target(&state, &me, &id).await?;
    let events = state
        .store
        .events(EventFilter { people: Some(vec![person.id.clone()]), kind: page.kind, before: page.before, limit: 100 })
        .await?;
    Ok(Json(json!(events.iter().map(event_view).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
struct GroupList {
    groups: Vec<String>,
}

async fn set_groups(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<GroupList>,
) -> ApiResult<StatusCode> {
    let (access, person) = target(&state, &me, &id).await?;
    access.admin()?;
    let known: BTreeSet<String> = state.store.groups().await?.into_iter().map(|group| group.id).collect();
    let groups: Vec<String> = body.groups.into_iter().filter(|group| known.contains(group)).collect();
    if !groups.iter().any(|group| group == ADMINS_ID) {
        let membership = state.store.membership().await?;
        if membership.people.get(ADMINS_ID).is_some_and(|admins| admins.contains(&person.id)) {
            keep_an_admin(&state, &person.id).await?;
        }
    }
    state.store.set_groups_of(&person.id, groups.clone()).await?;
    audit(
        &state,
        "person_groups_changed",
        Some(&me.person.id),
        Some(&person.id),
        None,
        &ip,
        json!({ "groups": groups }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ManagerList {
    managers: Vec<String>,
}

/// Who looks after this person directly.
async fn set_managers(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<ManagerList>,
) -> ApiResult<StatusCode> {
    let (access, person) = target(&state, &me, &id).await?;
    access.admin()?;
    let wanted: BTreeSet<String> = body.managers.into_iter().filter(|manager| *manager != person.id).collect();
    let current: BTreeSet<String> = state.store.managers_of(&person.id).await?.into_iter().collect();
    for manager in current.union(&wanted) {
        if state.store.person(manager).await?.is_none() {
            continue;
        }
        let mut managed = state.store.managed_by(manager).await?;
        managed.people.retain(|other| *other != person.id);
        if wanted.contains(manager) {
            managed.people.push(person.id.clone());
        }
        state.store.set_managed(manager, managed).await?;
    }
    audit(&state, "managers_changed", Some(&me.person.id), Some(&person.id), None, &ip, json!({ "managers": wanted }))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Manages {
    people: Vec<String>,
    groups: Vec<String>,
}

/// Whom this person looks after.
async fn set_manages(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<Manages>,
) -> ApiResult<StatusCode> {
    let (access, person) = target(&state, &me, &id).await?;
    access.admin()?;
    state.store.set_managed(&person.id, Managed { people: body.people, groups: body.groups }).await?;
    audit(&state, "manages_changed", Some(&me.person.id), Some(&person.id), None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct WindowIn {
    days: u8,
    start: u16,
    end: u16,
    #[serde(default)]
    app: Option<String>,
}

pub(crate) fn windows_from(input: Vec<WindowIn>) -> ApiResult<Vec<Window>> {
    if input.len() > 50 {
        return Err(ApiError::bad("too_many", "That is too many windows."));
    }
    input
        .into_iter()
        .map(|window| {
            if !(1..=127).contains(&window.days)
                || window.start > 1439
                || !(1..=1440).contains(&window.end)
                || window.start == window.end
            {
                return Err(ApiError::bad("window", "A window needs days, and a start and end that differ."));
            }
            Ok(Window {
                id: String::new(),
                subject_kind: String::new(),
                subject_id: String::new(),
                app_id: window.app,
                days: window.days,
                start_minute: window.start,
                end_minute: window.end,
            })
        })
        .collect()
}

async fn set_windows(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<Vec<WindowIn>>,
) -> ApiResult<StatusCode> {
    let (_, person) = target(&state, &me, &id).await?;
    let windows = windows_from(body)?;
    let count = windows.len();
    state.store.set_windows("person", &person.id, windows).await?;
    audit(&state, "windows_changed", Some(&me.person.id), Some(&person.id), None, &ip, json!({ "count": count })).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_avatar(
    State(state): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let (_, person) = target(&state, &me, &id).await?;
    check_jpeg(&body)?;
    state.store.set_avatar(&person.id, Some(body.to_vec())).await?;
    state.store.update_person(&person.id, |_| {}).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_avatar(State(state): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let (_, person) = target(&state, &me, &id).await?;
    state.store.set_avatar(&person.id, None).await?;
    state.store.update_person(&person.id, |_| {}).await?;
    Ok(StatusCode::NO_CONTENT)
}
