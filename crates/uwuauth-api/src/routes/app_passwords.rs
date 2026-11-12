//! Checking an app password without a name: for a caller that has the secret and no user name,
//! such as a reverse proxy that takes `Authorization: Basic` (the name) or a bare secret. The
//! caller is trusted with an admin's API token; a read-only token is enough. The secret goes in
//! `X-App-Password`, in any spelling the portal shows it in.
//!
//! The answer is what a bind would tell: the name, the address, the group names. A disabled or
//! expired account, or one outside its time windows, is refused with the reason, as LDAP does.
//! Wrong secrets count per address, like wrong LDAP binds.

use crate::crypto::secret_hash;
use crate::errors::{ApiError, ApiResult};
use crate::session::{AdminOnly, ClientIp};
use crate::{AppState, audit, policy};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use serde_json::{Value, json};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/app-passwords/check", get(check))
}

async fn check(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    if !state.limits.ldap.allows_ip(ip) {
        return Err(ApiError::too_many());
    }
    let secret = headers
        .get("x-app-password")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    let Some(app) = state.store.use_app_password_by_hash(secret_hash(secret), &ip.to_string()).await? else {
        state.limits.ldap.check(ip);
        audit(&state, "app_password_check_failed", Some(&admin.actor_id()), None, None, &ip, json!({})).await;
        return Err(ApiError::unauthorized());
    };
    let person = state.store.person(&app.person_id).await?.ok_or_else(ApiError::unauthorized)?;
    let membership = state.store.membership().await?;
    let groups = membership.groups_of(&person.id);
    let refused = match policy::refusal(&state, &person).await? {
        Some(reason) => Some(reason),
        None => {
            let windows = state.store.windows_for(&person.id, &groups).await?;
            (!policy::within_windows(&state, &windows, None)).then_some("time")
        }
    };
    if let Some(reason) = refused {
        audit(
            &state,
            "app_password_refused",
            Some(&admin.actor_id()),
            Some(&person.id),
            Some(&app.id),
            &ip,
            json!({ "reason": reason }),
        )
        .await;
        return Err(ApiError::forbidden("This account may not sign in now.").with_detail(json!({ "reason": reason })));
    }
    let names: Vec<String> = state
        .store
        .groups()
        .await?
        .into_iter()
        .filter(|group| groups.contains(&group.id))
        .map(|group| group.name)
        .collect();
    audit(&state, "app_password_checked", Some(&admin.actor_id()), Some(&person.id), Some(&app.id), &ip, json!({}))
        .await;
    Ok(Json(json!({
        "username": person.username,
        "displayName": person.display_name,
        "email": person.email,
        "groups": names,
    })))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestServer, json as read_json};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;

    fn check(token: &str, secret: Option<&str>) -> Request<Body> {
        let mut request =
            Request::get("/uwu/v1/app-passwords/check").header("authorization", format!("Bearer {token}"));
        if let Some(secret) = secret {
            request = request.header("x-app-password", secret);
        }
        request.body(Body::empty()).unwrap()
    }

    /// An admin, a read-only token for a proxy, and a person with an app password.
    async fn setup(server: &TestServer) -> (String, String, String) {
        let admin = server.person("boss", true).await;
        let token = admin.ok("POST", "/uwu/v1/tokens", json!({ "name": "proxy", "readOnly": true })).await["secret"]
            .as_str()
            .unwrap()
            .to_string();
        let kid = server.person("kid", false).await;
        let secret = kid.ok("POST", "/uwu/v1/me/app-passwords", json!({ "name": "nas" })).await["secret"]
            .as_str()
            .unwrap()
            .to_string();
        let id = server.state.store.people().await.unwrap().into_iter().find(|p| p.username == "kid").unwrap().id;
        (token, secret, id)
    }

    #[tokio::test]
    async fn a_secret_alone_names_its_person() {
        let server = TestServer::new().await;
        let (token, secret, _) = setup(&server).await;
        let response = server.send(check(&token, Some(&secret))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["username"], "kid");
        assert!(body["groups"].as_array().unwrap().iter().any(|g| g == "everyone"));
    }

    #[tokio::test]
    async fn the_secret_in_any_spelling_is_the_same() {
        let server = TestServer::new().await;
        let (token, secret, _) = setup(&server).await;
        let spelled = secret.to_uppercase();
        assert_eq!(server.send(check(&token, Some(&spelled))).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_wrong_or_missing_secret_is_unauthorized() {
        let server = TestServer::new().await;
        let (token, _, _) = setup(&server).await;
        assert_eq!(server.send(check(&token, Some("not-a-secret"))).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(server.send(check(&token, None)).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_token_means_no_answer() {
        let server = TestServer::new().await;
        let (_, secret, _) = setup(&server).await;
        let request =
            Request::get("/uwu/v1/app-passwords/check").header("x-app-password", secret).body(Body::empty()).unwrap();
        assert_eq!(server.send(request).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_disabled_person_is_refused_with_the_reason() {
        let server = TestServer::new().await;
        let (token, secret, id) = setup(&server).await;
        let admin = server.person("boss2", true).await;
        admin.ok("POST", &format!("/uwu/v1/people/{id}/disable"), json!({})).await;
        let response = server.send(check(&token, Some(&secret))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(read_json(response).await["detail"]["reason"], "disabled");
    }
}
