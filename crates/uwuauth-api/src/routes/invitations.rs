//! Invitations: a link (and its QR code) that makes one account, with its groups and role
//! chosen beforehand. By mail when there is an address and mail, otherwise passed on by hand.
//! The link is shown once; "a new link" replaces it.

use super::links::Invitation;
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
use uwuauth_mail::{Language, Mail};
use uwuauth_store::{Link, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/invitations", get(list).post(create))
        .route("/uwu/v1/invitations/{id}", delete(remove))
        .route("/uwu/v1/invitations/{id}/renew", post(renew))
}

fn view(link: &Link) -> Value {
    let invitation: Invitation = serde_json::from_str(&link.data).unwrap_or_default();
    json!({
        "id": link.id,
        "email": invitation.email,
        "displayName": invitation.display_name,
        "groups": invitation.groups,
        "admin": invitation.admin,
        "managed": invitation.managed,
        "managers": invitation.managers,
        "createdBy": link.created_by,
        "created": link.created,
        "expires": link.expires,
        "expired": link.expires.as_str() <= clock::now().as_str(),
    })
}

async fn list(State(state): State<AppState>, _admin: AdminOnly) -> ApiResult<Json<Value>> {
    let links = state.store.open_invitations().await?;
    Ok(Json(json!(links.iter().map(view).collect::<Vec<_>>())))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct New {
    email: Option<String>,
    display_name: Option<String>,
    groups: Vec<String>,
    admin: bool,
    managed: bool,
    managers: Vec<String>,
    language: Option<String>,
    mail: bool,
}

/// Send the invitation's link, if it can go by mail.
async fn send(
    state: &AppState,
    invitation: &Invitation,
    link: &str,
    expires: &str,
    from: Option<String>,
) -> ApiResult<Option<String>> {
    let Some(to) = invitation.email.clone() else { return Ok(None) };
    let language =
        Language::from_code(invitation.language.as_deref().unwrap_or(state.settings().default_language.code()));
    let settings = state.settings();
    let expires = clock::parse(expires)
        .map(|at| {
            jiff::Timestamp::from_second(at.unix_timestamp())
                .unwrap_or_default()
                .to_zoned(settings.tz())
                .strftime("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default();
    let mail =
        Mail::Invitation { link: link.to_string(), organization: settings.organization, invited_by: from, expires };
    state.mailer.send(&to, &mail, language).await.map_err(|error| ApiError::bad("mail_failed", error.to_string()))?;
    Ok(Some(to))
}

pub async fn invite(state: &AppState, created_by: Option<&str>, new: InviteFields) -> ApiResult<Value> {
    let email = new.email.as_deref().filter(|email| !email.trim().is_empty()).map(policy::email).transpose()?;
    if let Some(email) = &email
        && state.store.person_by_login(email).await?.is_some()
    {
        return Err(ApiError::field("email", "exists", "That address has an account already."));
    }
    let known: Vec<String> = state.store.groups().await?.into_iter().map(|group| group.id).collect();
    let mut invitation = Invitation {
        mailed: new.mail && email.is_some() && state.mailer.enabled(),
        email,
        display_name: policy::optional(new.display_name.as_deref(), 100),
        groups: new.groups.into_iter().filter(|group| known.contains(group)).collect(),
        admin: new.admin,
        managed: new.managed,
        managers: new.managers,
        language: new.language.map(|language| policy::language(&language)),
    };
    let token = random_token(32);
    let expires = clock::in_seconds(i64::from(state.settings().invitation_days) * 86_400);
    let data = serde_json::to_string(&invitation).map_err(ApiError::internal)?;
    let link = state
        .store
        .create_link(sha256(token.as_bytes()), uwuauth_store::Purpose::Invite, None, &data, created_by, &expires)
        .await?;
    let url = state.link(&format!("/invite?token={token}"));
    let from = match created_by {
        Some(id) => state.store.person(id).await?.map(|person| person.display_name),
        None => None,
    };
    let mailed = if invitation.mailed { send(state, &invitation, &url, &expires, from).await? } else { None };
    invitation.mailed = mailed.is_some();
    let mut body = view(&link);
    body["link"] = json!(url);
    body["mailed"] = json!(mailed);
    Ok(body)
}

/// What an invitation is made of, for the portal and for `uwuauth-server invite`.
#[derive(Debug, Default)]
pub struct InviteFields {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub admin: bool,
    pub managed: bool,
    pub managers: Vec<String>,
    pub language: Option<String>,
    pub mail: bool,
}

async fn create(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(new): Json<New>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // An invitation that makes an admin is as much as an admin's password: only a person who
    // confirmed a moment ago, never a script's token.
    if new.admin {
        match &admin {
            AdminOnly::Person(me) => me.require_fresh()?,
            AdminOnly::Token(_) => return Err(ApiError::forbidden("A token cannot invite admins.")),
        }
    }
    let created_by = admin.person().map(|person| person.id.clone());
    let body = invite(
        &state,
        created_by.as_deref(),
        InviteFields {
            email: new.email,
            display_name: new.display_name,
            groups: new.groups,
            admin: new.admin,
            managed: new.managed,
            managers: new.managers,
            language: new.language,
            mail: new.mail,
        },
    )
    .await?;
    audit(
        &state,
        "invitation_created",
        Some(&admin.actor_id()),
        None,
        body["id"].as_str(),
        &ip,
        json!({ "email": body["email"], "admin": body["admin"] }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(body)))
}

async fn remove(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_link(&id).await? {
        return Err(ApiError::not_found());
    }
    audit(&state, "invitation_deleted", Some(&admin.actor_id()), None, Some(&id), &ip, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Renew {
    mail: bool,
}

/// A new link for an invitation: the old one stops working, and it runs for the full time again.
async fn renew(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    body: Option<Json<Renew>>,
) -> ApiResult<Json<Value>> {
    let token = random_token(32);
    let expires = clock::in_seconds(i64::from(state.settings().invitation_days) * 86_400);
    let link =
        state.store.renew_link(&id, sha256(token.as_bytes()), &expires).await?.ok_or_else(ApiError::not_found)?;
    let url = state.link(&format!("/invite?token={token}"));
    let invitation: Invitation = serde_json::from_str(&link.data).unwrap_or_default();
    let mailed = if body.is_some_and(|Json(body)| body.mail) {
        send(&state, &invitation, &url, &expires, admin.person().map(|person| person.display_name.clone())).await?
    } else {
        None
    };
    audit(&state, "invitation_renewed", Some(&admin.actor_id()), None, Some(&id), &ip, json!({})).await;
    let mut body = view(&link);
    body["link"] = json!(url);
    body["mailed"] = json!(mailed);
    Ok(Json(body))
}
