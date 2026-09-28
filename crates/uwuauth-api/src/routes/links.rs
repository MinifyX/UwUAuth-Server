//! Where the links lead: `/#/invite?token=…` and the others open the web app, which asks here.
//!
//! - **invite**: make an account. With a passkey (the web app offers that first) or a password —
//!   one of the two, never none, in the same request that makes the account.
//! - **setup**: an account an admin or a parent made, set up on its own device — often a kid's
//!   tablet, from a QR code on the parent's phone.
//! - **reset**: a new password, from "forgot password" or from an admin.
//! - **verify**: confirming a new address.
//!
//! Every link works once and runs out. What a link needs is checked before it is used up, and
//! it is used up before the result counts: two tabs with the same link get one account.

use super::{NewPasskey, new_password, passkey_options, register_passkey};
use crate::crypto::{hash_password, sha256};
use crate::errors::{ApiError, ApiResult};
use crate::routes::login::finish;
use crate::session::{ClientIp, SignIn};
use crate::{AppState, audit, policy};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uwuauth_store::{ADMINS_ID, Link, Managed, NewPerson, Person, Purpose, clock, people};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/links/{purpose}/{token}", get(show).post(complete))
        .route("/uwu/v1/links/{purpose}/{token}/passkey-options", post(options))
}

/// What an invitation brings along.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Invitation {
    /// The address it was for. Mailed there, it counts as confirmed once the account is made.
    pub email: Option<String>,
    pub mailed: bool,
    /// A name to start from.
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub admin: bool,
    /// The account is looked after by `managers`.
    pub managed: bool,
    pub managers: Vec<String>,
    pub language: Option<String>,
}

/// What a verify link confirms.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Verify {
    pub email: String,
}

fn purpose(text: &str) -> ApiResult<Purpose> {
    Ok(match text {
        "invite" => Purpose::Invite,
        "setup" => Purpose::Setup,
        "reset" => Purpose::Reset,
        "verify" => Purpose::Verify,
        _ => return Err(ApiError::not_found()),
    })
}

fn gone() -> ApiError {
    ApiError::new(StatusCode::GONE, "link_gone", "This link was used already or ran out.")
}

async fn find(state: &AppState, ip: std::net::IpAddr, purpose_text: &str, token: &str) -> ApiResult<(Purpose, Link)> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many());
    }
    let purpose = purpose(purpose_text)?;
    let link = state.store.link(&sha256(token.as_bytes()), purpose).await?.ok_or_else(gone)?;
    Ok((purpose, link))
}

async fn person_of(state: &AppState, link: &Link) -> ApiResult<Person> {
    let id = link.person_id.as_deref().ok_or_else(gone)?;
    let person = state.store.person(id).await?.ok_or_else(gone)?;
    if person.deleted.is_some() || person.disabled {
        return Err(gone());
    }
    Ok(person)
}

async fn show(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((purpose, token)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (purpose, link) = find(&state, ip, &purpose, &token).await?;
    let settings = state.settings();
    let mut body = json!({
        "purpose": purpose.as_str(),
        "expires": link.expires,
        "organization": settings.organization,
        "mode": settings.mode,
        "passwordMinLength": settings.password_min_length,
    });
    match purpose {
        Purpose::Invite => {
            let invitation: Invitation = serde_json::from_str(&link.data).unwrap_or_default();
            let inviter = match &link.created_by {
                Some(id) => state.store.person(id).await?.map(|person| person.display_name),
                None => None,
            };
            body["email"] = json!(invitation.email);
            body["displayName"] = json!(invitation.display_name);
            body["managed"] = json!(invitation.managed);
            body["invitedBy"] = json!(inviter);
            body["language"] = json!(invitation.language);
        }
        Purpose::Setup | Purpose::Reset => {
            let person = person_of(&state, &link).await?;
            body["username"] = json!(person.username);
            body["displayName"] = json!(person.display_name);
            body["hasPassword"] = json!(person.password_hash.is_some());
            body["language"] = json!(person.language);
        }
        Purpose::Verify => {
            let verify: Verify = serde_json::from_str(&link.data).unwrap_or_default();
            body["email"] = json!(verify.email);
        }
    }
    Ok(Json(body))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct OptionsFor {
    username: Option<String>,
    display_name: Option<String>,
}

/// Options for a passkey made through a link. For an invitation there is nobody yet: the account
/// will get the invitation's id, which the passkey carries from now on.
async fn options(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((purpose, token)): Path<(String, String)>,
    body: Option<Json<OptionsFor>>,
) -> ApiResult<Json<Value>> {
    let (purpose, link) = find(&state, ip, &purpose, &token).await?;
    let body = body.map(|Json(body)| body).unwrap_or_default();
    let key = format!("link:{}", link.id);
    let options = match purpose {
        Purpose::Invite => {
            let username = policy::username(body.username.as_deref().unwrap_or_default())?;
            let display = policy::display_name(body.display_name.as_deref().unwrap_or(&username))?;
            passkey_options(&state, &key, &link.id, &username, &display, &[])
        }
        Purpose::Setup | Purpose::Reset => {
            let person = person_of(&state, &link).await?;
            let existing = state.store.passkeys(&person.id).await?;
            passkey_options(&state, &key, &person.id, &person.username, &person.display_name, &existing)
        }
        Purpose::Verify => return Err(ApiError::not_found()),
    };
    Ok(Json(options))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Complete {
    // For an invitation.
    username: Option<String>,
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    language: Option<String>,
    // For every link but verify: one of the two.
    password: Option<String>,
    passkey: Option<NewPasskey>,
    remember: bool,
}

async fn complete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path((purpose, token)): Path<(String, String)>,
    body: Option<Json<Complete>>,
) -> ApiResult<Response> {
    let (purpose, link) = find(&state, ip, &purpose, &token).await?;
    let body = body.map(|Json(body)| body).unwrap_or_default();
    match purpose {
        Purpose::Invite => accept(&state, ip, &headers, link, body).await,
        Purpose::Setup | Purpose::Reset => set_up(&state, ip, &headers, purpose, link, body).await,
        Purpose::Verify => verify(&state, ip, link).await,
    }
}

async fn accept(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
    link: Link,
    body: Complete,
) -> ApiResult<Response> {
    let invitation: Invitation = serde_json::from_str(&link.data).unwrap_or_default();
    let username = policy::username(body.username.as_deref().unwrap_or_default())?;
    let display_name = policy::display_name(body.display_name.as_deref().unwrap_or(&username))?;
    // The address the invitation went to stays; otherwise what the person typed, if anything.
    let email = match (&invitation.email, body.email.as_deref().filter(|email| !email.trim().is_empty())) {
        (Some(email), _) => Some(email.clone()),
        (None, Some(typed)) => Some(policy::email(typed)?),
        (None, None) => None,
    };
    let language = policy::language(
        body.language.as_deref().or(invitation.language.as_deref()).unwrap_or(state.settings().default_language.code()),
    );
    if state.store.person_by_login(&username).await?.is_some() {
        return Err(ApiError::field("username", "exists", "That name is taken."));
    }
    if let Some(email) = &email
        && state.store.person_by_login(email).await?.is_some()
    {
        return Err(ApiError::field("email", "exists", "That address has an account already."));
    }
    let hash = match (&body.password, &body.passkey) {
        (Some(password), None) => {
            policy::password(state, password, Some((&username, email.as_deref()))).await?;
            Some(hash_password(state.config.hash_cost, password).await.map_err(ApiError::internal)?)
        }
        (None, Some(_)) => None,
        _ => return Err(ApiError::bad("credential", "Either a password or a passkey.")),
    };
    // The account gets the invitation's id: the passkey was made for that.
    let person = state
        .store
        .create_person(NewPerson {
            id: Some(link.id.clone()),
            username,
            display_name,
            given_name: policy::optional(body.given_name.as_deref(), 100),
            family_name: policy::optional(body.family_name.as_deref(), 100),
            email_verified: email.is_some() && invitation.mailed && invitation.email.is_some(),
            email,
            language,
            managed: invitation.managed,
        })
        .await?;
    let finish_account = async {
        let method = match &body.passkey {
            Some(passkey) => {
                register_passkey(state, &format!("link:{}", link.id), &person.id, passkey).await?;
                SignIn::Passkey
            }
            None => {
                state
                    .store
                    .update_person(&person.id, move |person| {
                        person.password_hash = hash;
                        person.password_changed = Some(clock::now());
                    })
                    .await?;
                SignIn::Password
            }
        };
        if !state.store.use_link(&link.id).await? {
            return Err(gone());
        }
        Ok(method)
    };
    let method = match finish_account.await {
        Ok(method) => method,
        Err(error) => {
            // Nothing half-made stays behind: the invitation can be tried again.
            state.store.purge_person(&person.id).await?;
            return Err(error);
        }
    };
    let mut groups = invitation.groups.clone();
    if invitation.admin {
        groups.push(ADMINS_ID.to_string());
    }
    let known: Vec<String> = state.store.groups().await?.into_iter().map(|group| group.id).collect();
    groups.retain(|group| known.contains(group));
    state.store.set_groups_of(&person.id, groups).await?;
    for manager in &invitation.managers {
        let mut managed = state.store.managed_by(manager).await?;
        managed.people.push(person.id.clone());
        state.store.set_managed(manager, Managed { people: managed.people, groups: managed.groups }).await?;
    }
    let person = state.store.person(&person.id).await?.ok_or_else(ApiError::not_found)?;
    audit(
        state,
        "invitation_accepted",
        link.created_by.as_deref(),
        Some(&person.id),
        Some(&link.id),
        &ip,
        json!({ "username": person.username }),
    )
    .await;
    finish(state, &person, &[method], body.remember, ip, headers).await
}

async fn set_up(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
    purpose: Purpose,
    link: Link,
    body: Complete,
) -> ApiResult<Response> {
    let person = person_of(state, &link).await?;
    let method = match (&body.password, &body.passkey) {
        (Some(password), None) => {
            let hash = new_password(state, &person, password).await?;
            if !state.store.use_link(&link.id).await? {
                return Err(gone());
            }
            let from_mail = purpose == Purpose::Reset && link.created_by.is_none();
            state
                .store
                .update_person(&person.id, move |person| {
                    person.password_hash = Some(hash);
                    person.password_changed = Some(clock::now());
                    person.security_stamp = people::stamp();
                    // A link that came by mail proves the address.
                    person.email_verified |= from_mail;
                })
                .await?;
            SignIn::Password
        }
        (None, Some(passkey)) => {
            register_passkey(state, &format!("link:{}", link.id), &person.id, passkey).await?;
            if !state.store.use_link(&link.id).await? {
                return Err(gone());
            }
            state.store.update_person(&person.id, |person| person.security_stamp = people::stamp()).await?;
            SignIn::Passkey
        }
        _ => return Err(ApiError::bad("credential", "Either a password or a passkey.")),
    };
    // Whoever had a session before does not keep it: the account is somebody else's to use now.
    state.store.end_sessions(&person.id, None).await?;
    let kind = if purpose == Purpose::Setup { "account_set_up" } else { "password_reset" };
    audit(state, kind, None, Some(&person.id), Some(&link.id), &ip, json!({ "method": method.amr() })).await;
    let person = state.store.person(&person.id).await?.ok_or_else(ApiError::not_found)?;
    finish(state, &person, &[method], body.remember, ip, headers).await
}

async fn verify(state: &AppState, ip: std::net::IpAddr, link: Link) -> ApiResult<Response> {
    use axum::response::IntoResponse;
    let person = person_of(state, &link).await?;
    let verify: Verify = serde_json::from_str(&link.data).unwrap_or_default();
    if verify.email.is_empty() {
        return Err(gone());
    }
    if let Some(other) = state.store.person_by_login(&verify.email).await?
        && other.id != person.id
    {
        return Err(ApiError::conflict("exists", "That address has an account already."));
    }
    if !state.store.use_link(&link.id).await? {
        return Err(gone());
    }
    let email = verify.email.clone();
    state
        .store
        .update_person(&person.id, move |person| {
            person.email = Some(email);
            person.email_verified = true;
        })
        .await?;
    audit(state, "email_verified", Some(&person.id), Some(&person.id), None, &ip, json!({ "email": verify.email }))
        .await;
    Ok(Json(json!({ "email": verify.email })).into_response())
}
