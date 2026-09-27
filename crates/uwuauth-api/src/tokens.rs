//! API tokens for scripts: `uwu_` and 43 random characters, shown once, kept as SHA-256.

use crate::crypto::{random_token, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::session::{AdminOnly, ClientIp};
use crate::{AppState, audit};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwuauth_store::{ApiToken, clock};

pub const PREFIX: &str = "uwu_";

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/tokens", get(list).post(create)).route("/uwu/v1/tokens/{id}", delete(remove))
}

fn view(token: &ApiToken) -> Value {
    json!({
        "id": token.id,
        "name": token.name,
        "readOnly": token.read_only,
        "createdBy": token.created_by,
        "created": token.created,
        "expires": token.expires,
        "lastUsed": token.last_used,
    })
}

async fn list(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let tokens = state.store.api_tokens().await?;
    Ok(Json(json!(tokens.iter().map(view).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct New {
    name: String,
    #[serde(default)]
    read_only: bool,
    /// Days until it stops working; none for never.
    #[serde(default)]
    days: Option<u32>,
}

async fn create(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(new): Json<New>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // Only a person makes tokens: a token that makes tokens would outlive whoever revoked it.
    let AdminOnly::Person(me) = &admin else {
        return Err(ApiError::forbidden("Only a signed-in admin can make tokens."));
    };
    me.require_fresh()?;
    let name = crate::policy::optional(Some(&new.name), 80)
        .ok_or_else(|| ApiError::field("name", "required", "A name is needed."))?;
    let secret = format!("{PREFIX}{}", random_token(32));
    let expires = new.days.filter(|days| *days > 0).map(|days| clock::in_seconds(i64::from(days) * 86_400));
    let token =
        state.store.create_api_token(&name, sha256(secret.as_bytes()), new.read_only, &me.person.id, expires).await?;
    audit(&state, "token_created", Some(&me.person.id), None, Some(&token.id), &ip, json!({ "name": name })).await;
    let mut body = view(&token);
    body["secret"] = json!(secret);
    Ok((StatusCode::CREATED, Json(body)))
}

async fn remove(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_api_token(&id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "token_deleted", Some(&admin.actor_id()), None, Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}
