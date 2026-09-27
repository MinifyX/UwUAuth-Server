//! Groups. Admins make, change and delete them; a group's owners may change who is in it.
//! Everybody signed in may see the list of groups — LDAP shows it to every app anyway.

use super::people::{WindowIn, window_view, windows_from};
use crate::errors::{ApiError, ApiResult};
use crate::session::{ClientIp, Me};
use crate::{AppState, audit};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uwuauth_store::{ADMINS_ID, EVERYONE_ID, Group, GroupFields, Members};

/// `admins` and every group inside it: whoever is in one of them is an admin, so only admins
/// change them.
pub(crate) fn admin_groups(membership: &uwuauth_store::Membership) -> BTreeSet<String> {
    let mut found = BTreeSet::from([ADMINS_ID.to_string()]);
    let mut queue = vec![ADMINS_ID.to_string()];
    while let Some(group) = queue.pop() {
        for inner in membership.groups.get(&group).into_iter().flatten() {
            if found.insert(inner.clone()) {
                queue.push(inner.clone());
            }
        }
    }
    found
}

/// Refuse a change that would leave no active admin: `membership` is how it would be after it.
pub(crate) async fn keep_admins(state: &AppState, membership: &uwuauth_store::Membership) -> ApiResult<()> {
    let before = state.store.admin_ids().await?;
    if before.is_empty() {
        return Ok(());
    }
    for admin in membership.people_in(ADMINS_ID, &[]) {
        if state.store.person(&admin).await?.is_some_and(|person| person.active()) {
            return Ok(());
        }
    }
    Err(ApiError::bad("last_admin", "That would leave no admin."))
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/groups", get(list).post(create))
        .route("/uwu/v1/groups/{id}", get(show).patch(change).delete(remove))
        .route("/uwu/v1/groups/{id}/members", put(set_members))
        .route("/uwu/v1/groups/{id}/windows", put(set_windows))
}

/// Letters, digits, spaces, `.`, `_` and `-`; up to 64. Unicode letters are fine: LDAP escapes
/// what it has to.
pub fn group_name(text: &str) -> ApiResult<String> {
    let name: String = text.trim().to_string();
    let valid = !name.is_empty()
        && name.chars().count() <= 64
        && name.chars().all(|c| c.is_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'));
    if !valid {
        return Err(ApiError::field(
            "name",
            "group_name",
            "A group name is letters, digits, spaces, dots, dashes and underscores.",
        ));
    }
    Ok(name)
}

fn view(group: &Group, members: usize, owners: &BTreeSet<String>, me: &str) -> Value {
    json!({
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "builtin": group.builtin,
        "gidNumber": group.gid_number,
        "requireMfa": group.require_mfa,
        "ldapAppPasswordsOnly": group.ldap_app_passwords_only,
        "members": members,
        "owners": owners,
        "owner": owners.contains(me),
        "created": group.created,
        "updated": group.updated,
    })
}

async fn list(State(state): State<AppState>, me: Me) -> ApiResult<Json<Value>> {
    let groups = state.store.groups().await?;
    let membership = state.store.membership().await?;
    let everybody: Vec<String> = state
        .store
        .people()
        .await?
        .into_iter()
        .filter(|person| person.deleted.is_none())
        .map(|person| person.id)
        .collect();
    let empty = BTreeSet::new();
    Ok(Json(json!(
        groups
            .iter()
            .map(|group| {
                let count = membership.people_in(&group.id, &everybody).len();
                view(group, count, membership.owners.get(&group.id).unwrap_or(&empty), &me.person.id)
            })
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Fields {
    name: Option<String>,
    description: Option<String>,
    require_mfa: Option<bool>,
    ldap_app_passwords_only: Option<bool>,
}

fn admin(me: &Me) -> ApiResult<()> {
    if me.admin { Ok(()) } else { Err(ApiError::forbidden("Only admins can do this.")) }
}

async fn create(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Json(fields): Json<Fields>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    admin(&me)?;
    let group = state
        .store
        .create_group(GroupFields {
            name: group_name(fields.name.as_deref().unwrap_or_default())?,
            description: crate::policy::optional(fields.description.as_deref(), 500).unwrap_or_default(),
            require_mfa: fields.require_mfa.unwrap_or(false),
            ldap_app_passwords_only: fields.ldap_app_passwords_only.unwrap_or(false),
        })
        .await?;
    audit(&state, "group_created", Some(&me.person.id), None, Some(&group.id), &ip, json!({ "name": group.name }))
        .await;
    Ok((StatusCode::CREATED, Json(view(&group, 0, &BTreeSet::new(), &me.person.id))))
}

/// The group `id`, if the one asking may manage it: admins every group, owners theirs.
async fn managed_group(state: &AppState, me: &Me, id: &str) -> ApiResult<(Group, bool)> {
    let group = state.store.group(id).await?.ok_or_else(ApiError::not_found)?;
    let members = state.store.members(id).await?;
    let owner = members.owners.contains(&me.person.id);
    if !me.admin && !owner {
        return Err(ApiError::not_found());
    }
    Ok((group, me.admin))
}

async fn show(State(state): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (group, _) = managed_group(&state, &me, &id).await?;
    let members = state.store.members(&id).await?;
    let membership = state.store.membership().await?;
    let everybody: Vec<String> = state
        .store
        .people()
        .await?
        .into_iter()
        .filter(|person| person.deleted.is_none())
        .map(|person| person.id)
        .collect();
    let all = membership.people_in(&id, &everybody);
    let owners: BTreeSet<String> = members.owners.iter().cloned().collect();
    let mut body = view(&group, all.len(), &owners, &me.person.id);
    body["people"] = json!(members.people);
    body["groups"] = json!(members.groups);
    body["everybody"] = json!(all);
    body["windows"] = json!(state.store.windows("group", &id).await?.iter().map(window_view).collect::<Vec<_>>());
    Ok(Json(body))
}

async fn change(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(fields): Json<Fields>,
) -> ApiResult<Json<Value>> {
    let (group, is_admin) = managed_group(&state, &me, &id).await?;
    if !is_admin && (fields.name.is_some() || fields.require_mfa.is_some() || fields.ldap_app_passwords_only.is_some())
    {
        return Err(ApiError::forbidden("Owners may change the description and the members."));
    }
    let name = match fields.name.as_deref() {
        Some(name) => group_name(name)?,
        None => group.name.clone(),
    };
    let updated = state
        .store
        .update_group(
            &id,
            GroupFields {
                name,
                description: fields
                    .description
                    .map(|description| crate::policy::optional(Some(&description), 500).unwrap_or_default())
                    .unwrap_or(group.description),
                require_mfa: fields.require_mfa.unwrap_or(group.require_mfa),
                ldap_app_passwords_only: fields.ldap_app_passwords_only.unwrap_or(group.ldap_app_passwords_only),
            },
        )
        .await?
        .ok_or_else(ApiError::not_found)?;
    audit(&state, "group_changed", Some(&me.person.id), None, Some(&id), &ip, json!({ "name": updated.name })).await;
    Ok(Json(json!({ "id": updated.id, "name": updated.name })))
}

async fn remove(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    admin(&me)?;
    let group = state.store.group(&id).await?.ok_or_else(ApiError::not_found)?;
    if group.builtin.is_some() {
        return Err(ApiError::bad("builtin", "This group comes with the server and stays."));
    }
    let mut after = state.store.membership().await?;
    if admin_groups(&after).contains(&id) {
        me.require_fresh()?;
    }
    after.people.remove(&id);
    after.groups.remove(&id);
    for inner in after.groups.values_mut() {
        inner.remove(&id);
    }
    keep_admins(&state, &after).await?;
    state.store.delete_group(&id).await?;
    audit(&state, "group_deleted", Some(&me.person.id), None, Some(&id), &ip, json!({ "name": group.name })).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MemberList {
    people: Vec<String>,
    groups: Vec<String>,
    owners: Option<Vec<String>>,
}

async fn set_members(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<MemberList>,
) -> ApiResult<StatusCode> {
    let (group, is_admin) = managed_group(&state, &me, &id).await?;
    if id == EVERYONE_ID {
        return Err(ApiError::bad("builtin", "Everybody is in this group by themselves."));
    }
    let current = state.store.members(&id).await?;
    let mut membership = state.store.membership().await?;
    let admin_group = admin_groups(&membership).contains(&id);
    if !is_admin && admin_group {
        return Err(ApiError::forbidden("Only admins change who is in a group that makes admins."));
    }
    if admin_group {
        me.require_fresh()?;
    }
    let owners = match body.owners {
        Some(owners) if is_admin => owners,
        Some(owners) if owners != current.owners => {
            return Err(ApiError::forbidden("Only admins change who owns a group."));
        }
        _ => current.owners,
    };
    let people: BTreeSet<String> = state.store.people().await?.into_iter().map(|person| person.id).collect();
    let groups: BTreeSet<String> = state.store.groups().await?.into_iter().map(|group| group.id).collect();
    // Owners change who is in their group, person by person; which groups are inside it is the
    // admins' to say — a group put inside could be anybody's.
    let inner = if is_admin { body.groups } else { current.groups };
    let members = Members {
        people: body.people.into_iter().filter(|id| people.contains(id)).collect(),
        groups: inner.into_iter().filter(|id| groups.contains(id)).collect(),
        owners: owners.into_iter().filter(|id| people.contains(id)).collect(),
    };
    membership.people.insert(id.clone(), members.people.iter().cloned().collect());
    membership.groups.insert(id.clone(), members.groups.iter().cloned().collect());
    keep_admins(&state, &membership).await?;
    let count = members.people.len();
    state.store.set_members(&id, members).await?;
    audit(
        &state,
        "group_members_changed",
        Some(&me.person.id),
        None,
        Some(&id),
        &ip,
        json!({ "name": group.name, "people": count }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_windows(
    State(state): State<AppState>,
    me: Me,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(body): Json<Vec<WindowIn>>,
) -> ApiResult<StatusCode> {
    admin(&me)?;
    state.store.group(&id).await?.ok_or_else(ApiError::not_found)?;
    let windows = windows_from(body)?;
    state.store.set_windows("group", &id, windows).await?;
    audit(&state, "windows_changed", Some(&me.person.id), None, Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn group_names() {
        assert_eq!(super::group_name(" Kinder ").unwrap(), "Kinder");
        assert!(super::group_name("Büro-Team 2").is_ok());
        for bad in ["", "a,b", "x=y", "<script>", &"a".repeat(65)] {
            assert!(super::group_name(bad).is_err(), "{bad}");
        }
    }
}
