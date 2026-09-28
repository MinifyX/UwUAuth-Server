//! What an app learns about a person: the claims, by scope.
//!
//! - `openid`: `sub`, the person's id, which never changes (names and addresses may).
//! - `profile`: `name`, `preferred_username` and `nickname` (both the user name: Forgejo and Gitea
//!   read the second), `given_name`, `family_name`, `picture`, `locale`, `updated_at`.
//! - `email`: `email`, `email_verified`.
//! - `groups`: `groups`, the names of every group the person is in (through groups inside groups
//!   too), not counting `everyone`.
//! - `roles`: `roles`, what the app's role mapping makes of those groups.
//! - `attributes`: the admin's own attributes, each under its name.

use crate::AppState;
use crate::routes::avatar_url;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use uwuauth_store::{App, EVERYONE_ID, Person};

pub const SUPPORTED: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "azp",
    "at_hash",
    "name",
    "preferred_username",
    "nickname",
    "given_name",
    "family_name",
    "picture",
    "locale",
    "updated_at",
    "email",
    "email_verified",
    "groups",
    "roles",
];

#[derive(Debug, Deserialize)]
struct RoleMapping {
    group: String,
    role: String,
}

/// What `person` is to `app`: the role names their groups map to.
pub fn roles(app: &App, groups: &BTreeSet<String>) -> Vec<String> {
    let mappings: Vec<RoleMapping> = serde_json::from_str(&app.roles).unwrap_or_default();
    let mut roles: Vec<String> = Vec::new();
    for mapping in mappings {
        if groups.contains(&mapping.group) && !roles.contains(&mapping.role) {
            roles.push(mapping.role);
        }
    }
    roles
}

/// The claims about `person` that `scopes` open up, for an ID token or the userinfo endpoint.
pub async fn about(
    state: &AppState,
    app: &App,
    person: &Person,
    scopes: &[String],
) -> crate::ApiResult<Map<String, Value>> {
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(person.id));
    let has = |scope: &str| scopes.iter().any(|known| known == scope);
    if has("profile") {
        claims.insert("name".into(), json!(person.display_name));
        claims.insert("preferred_username".into(), json!(person.username));
        claims.insert("nickname".into(), json!(person.username));
        if let Some(given) = &person.given_name {
            claims.insert("given_name".into(), json!(given));
        }
        if let Some(family) = &person.family_name {
            claims.insert("family_name".into(), json!(family));
        }
        if state.store.avatar(&person.id).await?.is_some() {
            claims.insert("picture".into(), json!(avatar_url(state, person)));
        }
        claims.insert("locale".into(), json!(person.language));
        if let Some(updated) = uwuauth_store::clock::parse(&person.updated) {
            claims.insert("updated_at".into(), json!(updated.unix_timestamp()));
        }
    }
    if has("email")
        && let Some(email) = &person.email
    {
        claims.insert("email".into(), json!(email));
        claims.insert("email_verified".into(), json!(person.email_verified));
    }
    if has("groups") || has("roles") {
        let membership = state.store.membership().await?;
        let ids = membership.groups_of(&person.id);
        if has("groups") {
            let groups = state.store.groups().await?;
            let names: Vec<&str> = groups
                .iter()
                .filter(|group| ids.contains(&group.id) && group.id != EVERYONE_ID)
                .map(|group| group.name.as_str())
                .collect();
            claims.insert("groups".into(), json!(names));
        }
        if has("roles") {
            claims.insert("roles".into(), json!(roles(app, &ids)));
        }
    }
    if has("attributes") {
        for (name, value) in state.store.attributes_of(&person.id).await? {
            // An attribute never stands in for a claim of the standard.
            if !SUPPORTED.contains(&name.as_str()) {
                claims.insert(name, json!(value));
            }
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_come_from_groups() {
        let app = App {
            roles: r#"[{"group":"g1","role":"admin"},{"group":"g2","role":"viewer"},{"group":"g3","role":"admin"}]"#
                .into(),
            ..App::default()
        };
        let groups: BTreeSet<String> = ["g1", "g3"].into_iter().map(String::from).collect();
        assert_eq!(roles(&app, &groups), ["admin"]);
        assert!(roles(&App::default(), &groups).is_empty());
    }
}
