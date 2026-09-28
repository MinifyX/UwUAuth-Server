//! LDAP in the admin portal: how it is set up, and the accounts apps bind with to read the
//! directory. Their password is shown once.

use crate::crypto::{random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::session::{AdminOnly, ClientIp};
use crate::{AppState, audit, policy};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwuauth_store::LdapAccount;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/ldap", get(info))
        .route("/uwu/v1/ldap/accounts", get(list).post(create))
        .route("/uwu/v1/ldap/accounts/{id}", delete(remove))
        .route("/uwu/v1/ldap/accounts/{id}/secret", post(renew))
}

/// `cn=<name>,ou=services,<base>`, the DN an app binds with.
fn bind_dn(state: &AppState, name: &str) -> String {
    let base = state.config.ldap.as_ref().map_or("dc=example,dc=com", |ldap| ldap.base.as_str());
    format!("cn={name},ou=services,{base}")
}

fn view(state: &AppState, account: &LdapAccount) -> Value {
    json!({
        "id": account.id,
        "name": account.name,
        "description": account.description,
        "bindDn": bind_dn(state, &account.name),
        "created": account.created,
        "lastUsed": account.last_used,
        "lastIp": account.last_ip,
    })
}

async fn info(State(state): State<AppState>, _admin: AdminOnly) -> Json<Value> {
    let Some(ldap) = &state.config.ldap else {
        return Json(json!({ "enabled": false }));
    };
    let host =
        state.config.public.split("://").nth(1).unwrap_or_default().split(':').next().unwrap_or_default().to_string();
    Json(json!({
        "enabled": true,
        "base": ldap.base,
        "domain": ldap.domain,
        "host": host,
        "ldapPort": ldap.ldap.map(|address| address.port()),
        "ldapsPort": ldap.ldaps.map(|address| address.port()),
        "plainBind": ldap.plain_bind,
        "people": format!("ou=people,{}", ldap.base),
        "groups": format!("ou=groups,{}", ldap.base),
        "services": format!("ou=services,{}", ldap.base),
    }))
}

async fn list(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let accounts = state.store.ldap_accounts().await?;
    Ok(Json(json!(accounts.iter().map(|account| view(&state, account)).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
struct New {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

/// Lower case letters, digits, `.`, `_` and `-`: what goes into a DN without escaping.
fn account_name(text: &str) -> ApiResult<String> {
    let name = text.trim().to_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(ApiError::field("name", "name", "Lower case letters, digits, dots, dashes and underscores."));
    }
    Ok(name)
}

async fn create(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(new): Json<New>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let name = account_name(&new.name)?;
    let secret = random_token(24);
    let description = policy::optional(new.description.as_deref(), 200).unwrap_or_default();
    let account = state
        .store
        .create_ldap_account(
            &name,
            &description,
            sha256(secret.as_bytes()),
            admin.person().map(|person| person.id.as_str()),
        )
        .await?;
    audit(
        &state,
        "ldap_account_created",
        Some(&admin.actor_id()),
        None,
        Some(&account.id),
        &ip,
        json!({ "name": name }),
    )
    .await;
    let mut body = view(&state, &account);
    body["secret"] = json!(secret);
    Ok((StatusCode::CREATED, Json(body)))
}

async fn remove(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_ldap_account(&id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "ldap_account_deleted", Some(&admin.actor_id()), None, Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let secret = random_token(24);
    let account =
        state.store.renew_ldap_account(&id, sha256(secret.as_bytes())).await?.ok_or_else(ApiError::not_found)?;
    audit(
        &state,
        "ldap_account_renewed",
        Some(&admin.actor_id()),
        None,
        Some(&id),
        &ip,
        json!({ "name": account.name }),
    )
    .await;
    let mut body = view(&state, &account);
    body["secret"] = json!(secret);
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn an_account_s_password_is_shown_once() {
        let server = TestServer::new().await;
        let admin = server.person("admin", true).await;
        let made = admin.ok("POST", "/uwu/v1/ldap/accounts", json!({ "name": "Nextcloud" })).await;
        assert_eq!(made["name"], "nextcloud");
        assert!(made["bindDn"].as_str().unwrap().starts_with("cn=nextcloud,ou=services,"));
        assert_eq!(made["secret"].as_str().unwrap().len(), 32);
        let list = admin.json("/uwu/v1/ldap/accounts").await;
        assert!(list[0].get("secret").is_none());
        assert_eq!(admin.json("/uwu/v1/ldap").await["enabled"], false);
        let taken = admin.request("POST", "/uwu/v1/ldap/accounts", Some(json!({ "name": "nextcloud" }))).await;
        assert_eq!(taken.status(), axum::http::StatusCode::CONFLICT);
    }
}
