//! The rest of the admin portal: the first-run assistant, the overview, the event log, the
//! server's log, backups, attributes, and moving the directory in and out (JSON and CSV).

use super::me::event_view;
use crate::errors::{ApiError, ApiResult};
use crate::routes::groups::group_name;
use crate::session::{AdminOnly, ClientIp, Me};
use crate::settings::Mode;
use crate::{AppState, audit, policy};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uwuauth_mail::Language;
use uwuauth_store::{
    ADMINS_ID, AttributeDef, EVERYONE_ID, EventFilter, GroupFields, Members, NewPerson, backups, with_suffix,
};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/setup", post(setup))
        .route("/uwu/v1/overview", get(overview))
        .route("/uwu/v1/events", get(events))
        .route("/uwu/v1/logs", get(logs))
        .route("/uwu/v1/backups", get(list_backups).post(create_backup))
        .route("/uwu/v1/backups/{name}", post(download_backup))
        .route("/uwu/v1/attributes", get(attributes).put(set_attributes))
        .route("/uwu/v1/export", get(export))
}

/// Routes that take large bodies.
pub(crate) fn import_routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/import", post(import))
}

fn admin(me: &Me) -> ApiResult<()> {
    if me.admin { Ok(()) } else { Err(ApiError::forbidden("Only admins can do this.")) }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Setup {
    organization: String,
    mode: Mode,
    language: String,
    timezone: String,
}

/// The first admin's assistant: what the household or company is called, family or office,
/// the language and the time zone. Mail comes later, in the settings.
async fn setup(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Json(body): Json<Setup>,
) -> ApiResult<StatusCode> {
    admin(&me)?;
    let mut settings = state.settings();
    settings.organization = policy::optional(Some(&body.organization), 80)
        .ok_or_else(|| ApiError::field("organization", "required", "A name is needed."))?;
    settings.mode = body.mode;
    settings.default_language = Language::from_code(&body.language);
    if jiff::tz::TimeZone::get(&body.timezone).is_err() {
        return Err(ApiError::field("timezone", "timezone", "That is not a time zone."));
    }
    settings.timezone = body.timezone;
    settings.setup_done = true;
    settings.save(&state.store, &state.sealer).await.map_err(ApiError::internal)?;
    *state.settings.write() = settings;
    audit(&state, "setup_done", Some(&me.person.id), None, None, &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn overview(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let people = state.store.people().await?;
    let groups = state.store.groups().await?;
    let admins = state.store.admin_ids().await?;
    let invitations = state.store.open_invitations().await?;
    let failed = state
        .store
        .events(EventFilter { kind: Some("login_failed".into()), limit: 500, ..EventFilter::default() })
        .await?
        .into_iter()
        .filter(|event| event.time.as_str() > uwuauth_store::clock::in_seconds(-86_400).as_str())
        .count();
    let database = state.store.path().to_path_buf();
    let size = |path: &std::path::Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
    let list = backups::list(&state.config.backups);
    let update = state.update.read().clone();
    let alive: Vec<_> = people.iter().filter(|person| person.deleted.is_none()).collect();
    Ok(Json(json!({
        "version": state.version,
        "uptimeSeconds": state.started.elapsed().as_secs(),
        "people": alive.len(),
        "disabled": alive.iter().filter(|person| person.disabled).count(),
        "managed": alive.iter().filter(|person| person.managed).count(),
        "withTotp": alive.iter().filter(|person| person.totp_secret.is_some()).count(),
        "trash": people.len() - alive.len(),
        "admins": admins.len(),
        "groups": groups.len(),
        "invitations": invitations.len(),
        "failedLoginsDay": failed,
        "databaseBytes": size(&database) + size(&with_suffix(&database, "-wal")),
        "backups": list.len(),
        "lastBackup": list.last().map(|(name, _)| name),
        "mail": state.mailer.enabled(),
        "update": {
            "checked": update.checked,
            "newer": update.newer,
            "url": update.url,
            "commits": update.commits,
            "error": update.error,
            "channel": update.channel,
            "commit": update.commit,
        },
    })))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EventQuery {
    before: Option<i64>,
    kind: Option<String>,
    person: Option<String>,
}

async fn events(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Query(query): Query<EventQuery>,
) -> ApiResult<Json<Value>> {
    let events = state
        .store
        .events(EventFilter {
            people: query.person.map(|person| vec![person]),
            kind: query.kind,
            before: query.before,
            limit: 200,
        })
        .await?;
    Ok(Json(json!(events.iter().map(event_view).collect::<Vec<_>>())))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogQuery {
    after: u64,
    level: Option<String>,
    limit: Option<usize>,
}

async fn logs(State(state): State<AppState>, _admin: AdminOnly, Query(query): Query<LogQuery>) -> Json<Value> {
    let lines =
        state.logs.lines(query.after, query.level.as_deref().unwrap_or("info"), query.limit.unwrap_or(500).min(2000));
    Json(json!(lines))
}

async fn list_backups(State(state): State<AppState>, _admin: AdminOnly) -> Json<Value> {
    let list: Vec<Value> = backups::list(&state.config.backups)
        .into_iter()
        .rev()
        .map(|(name, bytes)| json!({ "name": name, "bytes": bytes, "time": backups::stamp_of(&name) }))
        .collect();
    Json(json!(list))
}

async fn create_backup(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
) -> ApiResult<Json<Value>> {
    let path = backups::write(&state.store, &state.config.backups, None)
        .await
        .map_err(|error| ApiError::bad("backup", error))?;
    backups::keep_newest(&state.config.backups, backups::KEPT);
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    audit(&state, "backup_written", Some(&admin.actor_id()), None, Some(&name), &ip, json!({})).await;
    let bytes = std::fs::metadata(&path).map_or(0, |meta| meta.len());
    Ok(Json(json!({ "name": name, "bytes": bytes })))
}

/// A backup to take home: the whole directory, password hashes included. Only for a signed-in
/// admin who confirmed who they are a moment ago — a session that got away is not enough — and
/// only names the list has.
async fn download_backup(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(name): Path<String>,
) -> ApiResult<Response> {
    admin(&me)?;
    me.require_fresh()?;
    if !backups::list(&state.config.backups).iter().any(|(known, _)| *known == name) {
        return Err(ApiError::not_found());
    }
    let bytes = tokio::fs::read(state.config.backups.join(&name)).await.map_err(ApiError::internal)?;
    audit(&state, "backup_downloaded", Some(&me.person.id), None, Some(&name), &ip, json!({})).await;
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        bytes,
    )
        .into_response())
}

fn def_view(def: &AttributeDef) -> Value {
    json!({
        "name": def.name,
        "label": def.label,
        "kind": def.kind,
        "choices": serde_json::from_str::<Value>(&def.choices).unwrap_or_default(),
        "selfEditable": def.self_editable,
    })
}

async fn attributes(State(state): State<AppState>, _me: Me) -> ApiResult<Json<Value>> {
    let defs = state.store.attribute_defs().await?;
    Ok(Json(json!(defs.iter().map(def_view).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DefIn {
    name: String,
    label: String,
    kind: String,
    #[serde(default)]
    choices: Vec<String>,
    #[serde(default)]
    self_editable: bool,
}

/// Names LDAP and OpenID Connect could confuse with their own.
const RESERVED: &[&str] = &[
    "cn",
    "uid",
    "sn",
    "mail",
    "dn",
    "objectclass",
    "memberof",
    "member",
    "email",
    "name",
    "sub",
    "groups",
    "username",
    "picture",
    "locale",
    "samaccountname",
    "userprincipalname",
    "displayname",
    "givenname",
];

async fn set_attributes(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(body): Json<Vec<DefIn>>,
) -> ApiResult<Json<Value>> {
    let mut seen = BTreeSet::new();
    let mut defs = Vec::new();
    for (position, def) in body.into_iter().enumerate() {
        let name = def.name.trim().to_string();
        let valid = name.len() <= 40
            && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid || RESERVED.contains(&name.as_str()) || !seen.insert(name.clone()) {
            return Err(ApiError::field("name", "attribute_name", format!("{name} cannot be an attribute's name.")));
        }
        if !matches!(def.kind.as_str(), "text" | "number" | "date" | "choice") {
            return Err(ApiError::field("kind", "attribute_kind", "text, number, date or choice."));
        }
        let choices: Vec<String> = def.choices.iter().filter_map(|choice| policy::optional(Some(choice), 80)).collect();
        if def.kind == "choice" && choices.is_empty() {
            return Err(ApiError::field("choices", "required", "A choice needs choices."));
        }
        defs.push(AttributeDef {
            name,
            label: policy::optional(Some(&def.label), 80).unwrap_or_else(|| def.name.clone()),
            kind: def.kind,
            choices: serde_json::to_string(&choices).unwrap_or_else(|_| "[]".into()),
            self_editable: def.self_editable,
            position: position as i64,
        });
    }
    state.store.set_attribute_defs(defs).await?;
    audit(&state, "attributes_changed", Some(&admin.actor_id()), None, None, &ip, json!({})).await;
    let defs = state.store.attribute_defs().await?;
    Ok(Json(json!(defs.iter().map(def_view).collect::<Vec<_>>())))
}

// ── Import and export ─────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PersonOut {
    username: String,
    display_name: String,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    language: Option<String>,
    managed: bool,
    disabled: bool,
    groups: Vec<String>,
    attributes: BTreeMap<String, String>,
    uid_number: Option<i64>,
    login_shell: Option<String>,
    home_directory: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct GroupOut {
    name: String,
    description: String,
    /// User names.
    members: Vec<String>,
    /// Group names.
    subgroups: Vec<String>,
    owners: Vec<String>,
    require_mfa: bool,
    ldap_app_passwords_only: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Directory {
    people: Vec<PersonOut>,
    groups: Vec<GroupOut>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ExportQuery {
    format: Option<String>,
}

/// The directory as JSON (people and groups, for another UwUAuth) or CSV (people, for a
/// spreadsheet). No passwords, no passkeys, nothing to sign in with.
async fn export(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Query(query): Query<ExportQuery>,
) -> ApiResult<Response> {
    let people = state.store.people().await?;
    let groups = state.store.groups().await?;
    let membership = state.store.membership().await?;
    let attributes = state.store.all_attributes().await?;
    let username: BTreeMap<String, String> =
        people.iter().map(|person| (person.id.clone(), person.username.clone())).collect();
    let group_name: BTreeMap<String, String> =
        groups.iter().map(|group| (group.id.clone(), group.name.clone())).collect();
    let directory = Directory {
        people: people
            .iter()
            .filter(|person| person.deleted.is_none())
            .map(|person| PersonOut {
                username: person.username.clone(),
                display_name: person.display_name.clone(),
                given_name: person.given_name.clone(),
                family_name: person.family_name.clone(),
                email: person.email.clone(),
                language: Some(person.language.clone()),
                managed: person.managed,
                disabled: person.disabled,
                groups: membership
                    .direct_groups_of(&person.id)
                    .iter()
                    .filter_map(|id| group_name.get(id).cloned())
                    .collect(),
                attributes: attributes.get(&person.id).cloned().unwrap_or_default(),
                uid_number: Some(person.uid_number),
                login_shell: person.login_shell.clone(),
                home_directory: person.home_directory.clone(),
            })
            .collect(),
        groups: groups
            .iter()
            .filter(|group| group.id != EVERYONE_ID)
            .map(|group| {
                let names = |ids: Option<&BTreeSet<String>>, map: &BTreeMap<String, String>| -> Vec<String> {
                    ids.map(|ids| ids.iter().filter_map(|id| map.get(id).cloned()).collect()).unwrap_or_default()
                };
                GroupOut {
                    name: group.name.clone(),
                    description: group.description.clone(),
                    members: names(membership.people.get(&group.id), &username),
                    subgroups: names(membership.groups.get(&group.id), &group_name),
                    owners: names(membership.owners.get(&group.id), &username),
                    require_mfa: group.require_mfa,
                    ldap_app_passwords_only: group.ldap_app_passwords_only,
                }
            })
            .collect(),
    };
    audit(&state, "exported", Some(&admin.actor_id()), None, None, &ip, json!({ "format": query.format })).await;
    if query.format.as_deref() == Some("csv") {
        let mut csv = String::from("username,displayName,givenName,familyName,email,language,groups\r\n");
        for person in &directory.people {
            let fields = [
                person.username.as_str(),
                person.display_name.as_str(),
                person.given_name.as_deref().unwrap_or_default(),
                person.family_name.as_deref().unwrap_or_default(),
                person.email.as_deref().unwrap_or_default(),
                person.language.as_deref().unwrap_or_default(),
                &person.groups.join(";"),
            ];
            csv.push_str(&fields.iter().map(|field| csv_field(field)).collect::<Vec<_>>().join(","));
            csv.push_str("\r\n");
        }
        return Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"uwuauth-people.csv\""),
            ],
            csv,
        )
            .into_response());
    }
    Ok((
        [(header::CONTENT_DISPOSITION, "attachment; filename=\"uwuauth-directory.json\"")],
        Json(serde_json::to_value(&directory).map_err(ApiError::internal)?),
    )
        .into_response())
}

/// A CSV field, quoted when it has to be. A leading `=`, `+`, `-` or `@` gets a `'` in front, so
/// a spreadsheet does not run it as a formula.
fn csv_field(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@']) { format!("'{value}") } else { value.to_string() };
    if value.contains([',', '"', '\n', '\r']) { format!("\"{}\"", value.replace('"', "\"\"")) } else { value }
}

/// Split CSV into rows of fields: quotes, doubled quotes and line breaks in quotes.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => quoted = true,
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\r', false) => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|field| !field.is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            (c, _) => field.push(c),
        }
    }
    row.push(field);
    if row.iter().any(|field| !field.is_empty()) {
        rows.push(row);
    }
    rows
}

fn directory_from_csv(text: &str) -> ApiResult<Directory> {
    let rows = parse_csv(text);
    let Some((head, rest)) = rows.split_first() else { return Ok(Directory::default()) };
    let column = |name: &str| head.iter().position(|field| field.trim().eq_ignore_ascii_case(name));
    let username = column("username").ok_or_else(|| ApiError::bad("csv", "The first row needs a column username."))?;
    let get = |row: &[String], name: &str| {
        column(name)
            .and_then(|index| row.get(index))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    Ok(Directory {
        people: rest
            .iter()
            .map(|row| PersonOut {
                username: row.get(username).cloned().unwrap_or_default(),
                display_name: get(row, "displayName").unwrap_or_default(),
                given_name: get(row, "givenName"),
                family_name: get(row, "familyName"),
                email: get(row, "email"),
                language: get(row, "language"),
                groups: get(row, "groups")
                    .map(|groups| {
                        groups
                            .split(';')
                            .map(|group| group.trim().to_string())
                            .filter(|group| !group.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                ..PersonOut::default()
            })
            .collect(),
        groups: Vec::new(),
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct ImportQuery {
    dry_run: bool,
}

/// Bring people and groups in: what is there already (by user name, by group name) stays as it
/// is. New people have no way to sign in yet; the portal sends them setup links afterwards.
async fn import(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Query(query): Query<ImportQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let text = std::str::from_utf8(&body).map_err(|_| ApiError::bad("encoding", "The file has to be UTF-8."))?;
    let csv = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/csv"));
    let directory: Directory = if csv {
        directory_from_csv(text)?
    } else {
        serde_json::from_str(text)
            .map_err(|error| ApiError::bad("json", format!("That is not an UwUAuth export: {error}")))?
    };
    let mut report = json!({ "people": { "created": [], "skipped": [], "failed": [] }, "groups": { "created": [], "skipped": [] }, "dryRun": query.dry_run });
    let push = |report: &mut Value, path: [&str; 2], value: Value| {
        if let Some(list) = report[path[0]][path[1]].as_array_mut() {
            list.push(value);
        }
    };
    // Groups first, so people can go into them.
    let mut group_ids: BTreeMap<String, String> =
        state.store.groups().await?.into_iter().map(|group| (group.name.to_lowercase(), group.id)).collect();
    // Groups this import makes: only theirs get members from it. A group that is there already —
    // `admins` above all — stays as it is.
    let mut created_groups: BTreeSet<String> = BTreeSet::new();
    for group in &directory.groups {
        let Ok(name) = group_name(&group.name) else { continue };
        if group_ids.contains_key(&name.to_lowercase()) {
            push(&mut report, ["groups", "skipped"], json!(name));
            continue;
        }
        if !query.dry_run {
            let made = state
                .store
                .create_group(GroupFields {
                    name: name.clone(),
                    description: group.description.clone(),
                    require_mfa: group.require_mfa,
                    ldap_app_passwords_only: group.ldap_app_passwords_only,
                })
                .await?;
            created_groups.insert(made.id.clone());
            group_ids.insert(name.to_lowercase(), made.id);
        }
        push(&mut report, ["groups", "created"], json!(name));
    }
    let builtin: BTreeSet<String> = [ADMINS_ID.to_string(), EVERYONE_ID.to_string()].into();
    let defs = state.store.attribute_defs().await?;
    let mut person_ids: BTreeMap<String, String> =
        state.store.people().await?.into_iter().map(|person| (person.username.clone(), person.id)).collect();
    for person in &directory.people {
        let checked = (|| -> ApiResult<(String, String, Option<String>)> {
            let username = policy::username(&person.username)?;
            let display =
                policy::display_name(if person.display_name.is_empty() { &username } else { &person.display_name })?;
            let email = person.email.as_deref().map(policy::email).transpose()?;
            Ok((username, display, email))
        })();
        let (username, display, email) = match checked {
            Ok(values) => values,
            Err(error) => {
                push(&mut report, ["people", "failed"], json!({ "username": person.username, "error": error.message }));
                continue;
            }
        };
        if person_ids.contains_key(&username) {
            push(&mut report, ["people", "skipped"], json!(username));
            continue;
        }
        if !query.dry_run {
            let made = state
                .store
                .create_person(NewPerson {
                    id: None,
                    username: username.clone(),
                    display_name: display,
                    given_name: policy::optional(person.given_name.as_deref(), 100),
                    family_name: policy::optional(person.family_name.as_deref(), 100),
                    email,
                    email_verified: false,
                    language: policy::language(
                        person.language.as_deref().unwrap_or(state.settings().default_language.code()),
                    ),
                    managed: person.managed,
                })
                .await;
            let made = match made {
                Ok(made) => made,
                Err(error) => {
                    push(
                        &mut report,
                        ["people", "failed"],
                        json!({ "username": username, "error": ApiError::from(error).message }),
                    );
                    continue;
                }
            };
            // Never into a group that comes with the server: an export of another server must not
            // make anybody an admin here.
            let groups: Vec<String> = person
                .groups
                .iter()
                .filter_map(|name| group_ids.get(&name.to_lowercase()).cloned())
                .filter(|id| !builtin.contains(id))
                .collect();
            state.store.set_groups_of(&made.id, groups).await?;
            let attributes: BTreeMap<String, String> = person
                .attributes
                .iter()
                .filter_map(|(name, value)| {
                    let def = defs.iter().find(|def| &def.name == name)?;
                    Some((name.clone(), crate::routes::people::check_attribute(def, value).ok()?))
                })
                .collect();
            state.store.set_attributes(&made.id, attributes).await?;
            person_ids.insert(username.clone(), made.id);
        }
        push(&mut report, ["people", "created"], json!(username));
    }
    // Then who is in which group, owners and groups inside groups, from a JSON export.
    if !query.dry_run {
        for group in &directory.groups {
            let Some(id) = group_ids.get(&group.name.trim().to_lowercase()) else { continue };
            if !created_groups.contains(id) {
                continue;
            }
            let current = state.store.members(id).await?;
            let mut people: BTreeSet<String> = current.people.into_iter().collect();
            people.extend(group.members.iter().filter_map(|name| person_ids.get(name).cloned()));
            let mut groups: BTreeSet<String> = current.groups.into_iter().collect();
            groups.extend(group.subgroups.iter().filter_map(|name| group_ids.get(&name.to_lowercase()).cloned()));
            let mut owners: BTreeSet<String> = current.owners.into_iter().collect();
            owners.extend(group.owners.iter().filter_map(|name| person_ids.get(name).cloned()));
            let members = Members {
                people: people.into_iter().collect(),
                groups: groups.into_iter().collect(),
                owners: owners.into_iter().collect(),
            };
            if let Err(error) = state.store.set_members(id, members).await {
                tracing::warn!(group = group.name, %error, "an imported group's members did not go in");
            }
        }
        audit(
            &state,
            "imported",
            Some(&admin.actor_id()),
            None,
            None,
            &ip,
            json!({ "people": report["people"]["created"].as_array().map_or(0, Vec::len) }),
        )
        .await;
    }
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_both_ways() {
        let rows = parse_csv("username,displayName\r\nnyu,\"Nyu, the cat\"\r\nmia,\"Mia \"\"M\"\"\"\n\n");
        assert_eq!(rows, vec![vec!["username", "displayName"], vec!["nyu", "Nyu, the cat"], vec!["mia", "Mia \"M\""]]);
        assert_eq!(csv_field("Nyu, the cat"), "\"Nyu, the cat\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
    }

    #[test]
    fn a_csv_needs_a_username_column() {
        assert!(directory_from_csv("name\nnyu").is_err());
        let directory = directory_from_csv("Username,groups\nnyu,Familie; Kinder\n").unwrap();
        assert_eq!(directory.people[0].username, "nyu");
        assert_eq!(directory.people[0].groups, ["Familie", "Kinder"]);
    }
}
