//! OpenID Connect from the app's side: every flow an app goes through, checked the way an app
//! checks it — the ID token against the published keys, not against the server's own.

use crate::crypto::{b64, sha256};
use crate::test_support::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ring::signature::{self, UnparsedPublicKey};
use serde_json::{Value, json};

const REDIRECT: &str = "http://127.0.0.1/callback";

struct Pkce {
    verifier: String,
    challenge: String,
}

fn pkce() -> Pkce {
    let verifier = crate::crypto::random_token(32);
    let challenge = b64(&sha256(verifier.as_bytes()));
    Pkce { verifier, challenge }
}

/// An app made through the admin API: its client id and secret (none for a public one).
async fn app(admin: &Browser<'_>, body: Value) -> (String, Option<String>, String) {
    let made = admin.ok("POST", "/uwu/v1/apps", body).await;
    (
        made["clientId"].as_str().unwrap().to_string(),
        made["clientSecret"].as_str().map(str::to_string),
        made["id"].as_str().unwrap().to_string(),
    )
}

fn location(response: &axum::http::Response<Body>) -> String {
    response.headers().get("location").map(|value| value.to_str().unwrap().to_string()).unwrap_or_default()
}

fn query_of(url: &str) -> Vec<(String, String)> {
    let query = url.split_once('?').map(|(_, query)| query).unwrap_or_default();
    url::form_urlencoded::parse(query.as_bytes()).into_owned().collect()
}

fn param(url: &str, name: &str) -> Option<String> {
    query_of(url).into_iter().find(|(key, _)| key == name).map(|(_, value)| value)
}

async fn authorize(browser: &Browser<'_>, client_id: &str, extra: &[(&str, &str)]) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("scope", "openid profile email groups")
        .append_pair("state", "xyz")
        .append_pair("nonce", "n-0S6");
    for (name, value) in extra {
        query.append_pair(name, value);
    }
    let response = browser.get(&format!("/oauth/authorize?{}", query.finish())).await;
    assert!(response.status().is_redirection(), "{}", response.status());
    location(&response)
}

async fn token(server: &TestServer, basic: Option<(&str, &str)>, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
    let mut request = Request::post("/oauth/token").header("content-type", "application/x-www-form-urlencoded");
    if let Some((id, secret)) = basic {
        use base64::Engine as _;
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        request = request.header("authorization", format!("Basic {credentials}"));
    }
    let response = server.send(request.body(Body::from(body)).unwrap()).await;
    let status = response.status();
    (status, json(response).await)
}

/// The claims of a JWT, checked against the server's JWKS like an app would.
async fn verified(server: &TestServer, token: &str) -> Value {
    let jwks = json(server.get("/oauth/jwks").await).await;
    let mut parts = token.split('.');
    let (header, claims, signature) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
    let head: Value = serde_json::from_slice(&crate::crypto::unb64(header).unwrap()).unwrap();
    let key =
        jwks["keys"].as_array().unwrap().iter().find(|key| key["kid"] == head["kid"]).expect("the key is published");
    let message = format!("{header}.{claims}");
    let signature = crate::crypto::unb64(signature).unwrap();
    let field = |name: &str| crate::crypto::unb64(key[name].as_str().unwrap()).unwrap();
    match head["alg"].as_str().unwrap() {
        "RS256" => signature::RsaPublicKeyComponents { n: field("n"), e: field("e") }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &signature)
            .expect("RS256 signature"),
        "ES256" => {
            let mut point = vec![4];
            point.extend(field("x"));
            point.extend(field("y"));
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(message.as_bytes(), &signature)
                .expect("ES256 signature")
        }
        other => panic!("{other}"),
    }
    serde_json::from_slice(&crate::crypto::unb64(claims).unwrap()).unwrap()
}

async fn userinfo(server: &TestServer, access: &str) -> (StatusCode, Value) {
    let response = server
        .send(
            Request::get("/oauth/userinfo")
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let status = response.status();
    let body = if status == StatusCode::OK { json(response).await } else { Value::Null };
    (status, body)
}

#[tokio::test]
async fn discovery_says_where_everything_is() {
    let server = TestServer::new().await;
    let document = json(server.get("/.well-known/openid-configuration").await).await;
    assert_eq!(document["issuer"], PUBLIC);
    assert_eq!(document["token_endpoint"], format!("{PUBLIC}/oauth/token"));
    assert_eq!(document["code_challenge_methods_supported"], json!(["S256"]));
    let jwks = json(server.get("/oauth/jwks").await).await;
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
    assert!(jwks["keys"].as_array().unwrap().iter().all(|key| key.get("d").is_none()), "only public keys");
}

#[tokio::test]
async fn a_public_app_signs_in_with_pkce_and_gets_verified_tokens() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) =
        app(&admin, json!({ "name": "Handy-App", "public": true, "redirectUris": [REDIRECT], "idTokenAlg": "ES256" }))
            .await;
    assert!(secret.is_none());
    let pkce = pkce();
    let answer =
        authorize(&admin, &client_id, &[("code_challenge", &pkce.challenge), ("code_challenge_method", "S256")]).await;
    assert!(answer.starts_with(REDIRECT), "{answer}");
    assert_eq!(param(&answer, "state").as_deref(), Some("xyz"));
    assert_eq!(param(&answer, "iss").as_deref(), Some(PUBLIC));
    let code = param(&answer, "code").unwrap();

    let (status, _) = token(
        &server,
        None,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", "wrong-verifier-wrong-verifier-wrong-verifier-x"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a wrong verifier");
    // The code went with the wrong try: a new one.
    let answer =
        authorize(&admin, &client_id, &[("code_challenge", &pkce.challenge), ("code_challenge_method", "S256")]).await;
    let code = param(&answer, "code").unwrap();
    let (status, tokens) = token(
        &server,
        None,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let id_token = verified(&server, tokens["id_token"].as_str().unwrap()).await;
    let me = admin.json("/uwu/v1/me").await;
    assert_eq!(id_token["sub"], me["id"]);
    assert_eq!((id_token["aud"].as_str(), id_token["nonce"].as_str()), (Some(client_id.as_str()), Some("n-0S6")));
    assert_eq!(id_token["preferred_username"], "admin");
    assert_eq!(id_token["groups"], json!(["admins"]));
    assert_eq!(id_token["at_hash"], crate::oidc::keys::half_hash(tokens["access_token"].as_str().unwrap()));
    let (status, info) = userinfo(&server, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["sub"], me["id"]);
    let (again, _) = token(
        &server,
        None,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(again, StatusCode::BAD_REQUEST, "a code works once");
}

#[tokio::test]
async fn a_confidential_app_shows_its_secret() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "Nextcloud", "template": "nextcloud", "url": "https://cloud.example.com", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let answer = authorize(&admin, &client_id, &[]).await;
    let code = param(&answer, "code").expect("PKCE is optional with a secret");
    let (status, body) = token(
        &server,
        Some((&client_id, "not the secret")),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid_client")));
    // The wrong secret was refused before the code was looked at: it still works.
    let (status, tokens) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
}

#[tokio::test]
async fn a_confidential_app_signs_in() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "Grafana", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let answer = authorize(&admin, &client_id, &[]).await;
    let code = param(&answer, "code").unwrap();
    let (status, tokens) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let id_token = verified(&server, tokens["id_token"].as_str().unwrap()).await;
    assert_eq!(id_token["amr"], json!(["pwd"]));
}

#[tokio::test]
async fn without_a_session_the_browser_goes_to_sign_in_and_prompt_none_says_so() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let stranger = server.browser();
    let answer = authorize(&stranger, &client_id, &[]).await;
    assert!(answer.starts_with(&format!("{PUBLIC}/#/login?continue=")), "{answer}");
    let continue_to = param(&answer.replace("/#/login", ""), "continue").unwrap();
    assert!(continue_to.starts_with("/oauth/authorize?"));
    let answer = authorize(&stranger, &client_id, &[("prompt", "none")]).await;
    assert_eq!(param(&answer, "error").as_deref(), Some("login_required"));
}

#[tokio::test]
async fn a_wrong_redirect_never_reaches_the_app() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let response = admin.get(&format!("/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fevil.example.net%2F&scope=openid")).await;
    assert!(location(&response).starts_with(&format!("{PUBLIC}/#/oauth-error?reason=redirect")));
    let response = admin.get("/oauth/authorize?response_type=code&client_id=nobody&scope=openid").await;
    assert!(location(&response).contains("reason=unknown_app"));
}

#[tokio::test]
async fn refresh_tokens_rotate_and_a_stolen_one_ends_the_family() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let code = param(&authorize(&admin, &client_id, &[]).await, "code").unwrap();
    let (_, first) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    let old = first["refresh_token"].as_str().unwrap().to_string();
    let (status, second) =
        token(&server, Some((&client_id, &secret)), &[("grant_type", "refresh_token"), ("refresh_token", &old)]).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let new = second["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    let (status, stolen) =
        token(&server, Some((&client_id, &secret)), &[("grant_type", "refresh_token"), ("refresh_token", &old)]).await;
    assert_eq!((status, stolen["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_grant")));
    let (status, _) =
        token(&server, Some((&client_id, &secret)), &[("grant_type", "refresh_token"), ("refresh_token", &new)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the newer one of the family ended too");
}

#[tokio::test]
async fn an_app_for_some_groups_refuses_everybody_else_even_at_refresh() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let kid = server.person("mia", false).await;
    let kid_id = kid.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Streaming" })).await;
    let group_id = group["id"].as_str().unwrap().to_string();
    let (client_id, secret, _) =
        app(&admin, json!({ "name": "Jellyfin", "redirectUris": [REDIRECT], "allowedGroups": [group_id] })).await;
    let answer = authorize(&kid, &client_id, &[]).await;
    assert!(answer.starts_with(&format!("{PUBLIC}/#/denied?reason=groups")), "{answer}");
    admin.ok("PUT", &format!("/uwu/v1/groups/{group_id}/members"), json!({ "people": [kid_id] })).await;
    let code = param(&authorize(&kid, &client_id, &[]).await, "code").unwrap();
    let secret = secret.unwrap();
    let (_, tokens) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    admin.ok("PUT", &format!("/uwu/v1/groups/{group_id}/members"), json!({ "people": [] })).await;
    let (status, _) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "refresh_token"), ("refresh_token", tokens["refresh_token"].as_str().unwrap())],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "out of the group, out of the app");
}

#[tokio::test]
async fn a_kid_s_time_window_closes_the_app() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let kid = server.person("mia", false).await;
    let kid_id = kid.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let (client_id, _, app_id) = app(&admin, json!({ "name": "Spiele", "redirectUris": [REDIRECT] })).await;
    let now = jiff::Timestamp::now().to_zoned(server.state.settings().tz());
    let minute = now.hour() as i64 * 60 + now.minute() as i64;
    // Open in an hour, for an hour: closed now.
    let later = json!([{ "days": 127, "start": (minute + 60) % 1440, "end": (minute + 120) % 1440, "app": app_id }]);
    admin.ok("PUT", &format!("/uwu/v1/people/{kid_id}/windows"), later).await;
    let answer = authorize(&kid, &client_id, &[]).await;
    assert!(answer.contains("reason=time"), "{answer}");
    // Open now.
    let open =
        json!([{ "days": 127, "start": (minute + 1440 - 30) % 1440, "end": (minute + 30) % 1440, "app": app_id }]);
    admin.ok("PUT", &format!("/uwu/v1/people/{kid_id}/windows"), open).await;
    assert!(param(&authorize(&kid, &client_id, &[]).await, "code").is_some());
}

#[tokio::test]
async fn an_app_that_asks_for_agreement_gets_it_once() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) =
        app(&admin, json!({ "name": "Fremde App", "redirectUris": [REDIRECT], "consent": true })).await;
    let answer = authorize(&admin, &client_id, &[]).await;
    assert!(answer.starts_with(&format!("{PUBLIC}/#/consent?request=")), "{answer}");
    let request = param(&answer.replace("/#/consent", ""), "request").unwrap();
    let info = admin.json(&format!("/uwu/v1/consent/{request}")).await;
    assert_eq!(info["app"]["name"], "Fremde App");
    assert_eq!(info["scopes"], json!(["openid", "profile", "email", "groups"]));
    let decided = admin.ok("POST", &format!("/uwu/v1/consent/{request}"), json!({ "approve": true })).await;
    assert!(param(decided["redirect"].as_str().unwrap(), "code").is_some());
    // Asked once: the next sign-in goes straight through.
    assert!(param(&authorize(&admin, &client_id, &[]).await, "code").is_some());
    let answer = authorize(&admin, &client_id, &[("prompt", "consent")]).await;
    assert!(answer.contains("/#/consent?request="), "prompt=consent asks again");
}

#[tokio::test]
async fn a_new_password_ends_the_app_s_tokens() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let code = param(&authorize(&admin, &client_id, &[]).await, "code").unwrap();
    let (_, tokens) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    admin.ok("POST", "/uwu/v1/me/password", json!({ "password": "a completely new one" })).await;
    let (status, _) = userinfo(&server, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "refresh_token"), ("refresh_token", tokens["refresh_token"].as_str().unwrap())],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_tv_signs_in_with_a_code_typed_on_the_phone() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "Fernseher", "public": true, "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"] })).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &client_id)
        .append_pair("scope", "openid profile")
        .finish();
    let started = json(
        server
            .send(
                Request::post("/oauth/device_authorization")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await,
    )
    .await;
    let device_code = started["device_code"].as_str().unwrap().to_string();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    let poll = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code.as_str()),
        ("client_id", client_id.as_str()),
    ];
    let (_, waiting) = token(&server, None, &poll).await;
    assert_eq!(waiting["error"], "authorization_pending");
    let (_, slow) = token(&server, None, &poll).await;
    assert_eq!(slow["error"], "slow_down", "asked again at once");
    let typed = user_code.to_lowercase().replace('-', "%20");
    assert_eq!(admin.json(&format!("/uwu/v1/device/{typed}")).await["app"]["name"], "Fernseher");
    admin.ok("POST", &format!("/uwu/v1/device/{typed}"), json!({ "approve": true })).await;
    // Past the interval, the device asks again.
    let key = b64(&sha256(device_code.as_bytes()));
    let mut grant = server.state.oidc().devices.peek(&key).unwrap();
    grant.last_poll = None;
    server.state.oidc().devices.put(key, grant);
    let (status, tokens) = token(&server, None, &poll).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens["id_token"].is_string());
}

#[tokio::test]
async fn an_app_with_a_secret_gets_a_token_for_itself() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "Dienst", "grantTypes": ["client_credentials"] })).await;
    let secret = secret.unwrap();
    let (status, tokens) =
        token(&server, Some((&client_id, &secret)), &[("grant_type", "client_credentials"), ("scope", "groups")]).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens.get("refresh_token").is_none() && tokens.get("id_token").is_none());
    let claims = verified(&server, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(claims["sub"], client_id);
    let (status, _) =
        token(&server, Some((&client_id, &secret)), &[("grant_type", "authorization_code"), ("code", "x")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "only what the app may");
}

#[tokio::test]
async fn an_app_registers_itself_with_a_token_from_an_admin() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let register = |token: Option<String>, body: Value| {
        let mut request = Request::post("/oauth/register").header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        server.send(request.body(Body::from(body.to_string())).unwrap())
    };
    let metadata = json!({ "client_name": "UwUMail Server", "redirect_uris": ["https://mail.example.com/api/auth/oidc/callback"], "backchannel_logout_uri": "https://mail.example.com/api/auth/oidc/logout" });
    assert_eq!(register(None, metadata.clone()).await.status(), StatusCode::UNAUTHORIZED);
    let token = admin.ok("POST", "/uwu/v1/registration-tokens", json!({ "name": "UwUMail" })).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let bad = register(Some(token.clone()), json!({ "redirect_uris": ["javascript:alert(1)"] })).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let made = register(Some(token.clone()), metadata.clone()).await;
    assert_eq!(made.status(), StatusCode::CREATED, "a bad request did not use the token up");
    let made = json(made).await;
    assert!(made["client_secret"].is_string());
    assert!(admin.json("/uwu/v1/apps").await.as_array().unwrap().iter().any(|app| app["name"] == "UwUMail Server"));
    assert_eq!(register(Some(token), metadata).await.status(), StatusCode::UNAUTHORIZED, "used up");
}

#[tokio::test]
async fn signing_out_from_an_app_tells_the_other_apps() {
    use std::sync::{Arc, Mutex};
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = received.clone();
    let (notified_tx, mut notified) = tokio::sync::mpsc::unbounded_channel::<()>();
    let receiver = axum::Router::new().route(
        "/logout",
        axum::routing::post(move |body: String| {
            let seen = seen.clone();
            let notified_tx = notified_tx.clone();
            async move {
                seen.lock().unwrap().push(body);
                let _ = notified_tx.send(());
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, receiver).await.unwrap() });

    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (first, secret, _) = app(&admin, json!({ "name": "Erste", "redirectUris": [REDIRECT], "postLogoutRedirectUris": ["https://first.example.com/bye"] })).await;
    let (second, _, _) = app(&admin, json!({ "name": "Zweite", "redirectUris": [REDIRECT], "backchannelLogoutUri": format!("http://{address}/logout") })).await;
    let code = param(&authorize(&admin, &first, &[]).await, "code").unwrap();
    let (_, tokens) = token(
        &server,
        Some((&first, &secret.unwrap())),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    authorize(&admin, &second, &[]).await;

    let hint = tokens["id_token"].as_str().unwrap();
    let response = admin
        .get(&format!(
            "/oauth/logout?id_token_hint={hint}&post_logout_redirect_uri=https%3A%2F%2Ffirst.example.com%2Fbye&state=s1"
        ))
        .await;
    assert_eq!(location(&response), "https://first.example.com/bye?state=s1");
    assert_eq!(admin.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED);
    notified.recv().await.expect("the second app heard about it");
    let body = received.lock().unwrap()[0].clone();
    let logout_token =
        url::form_urlencoded::parse(body.as_bytes()).find(|(key, _)| key == "logout_token").unwrap().1.into_owned();
    let claims = verified(&server, &logout_token).await;
    assert_eq!(claims["aud"], second);
    assert!(claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
}

#[tokio::test]
async fn without_a_hint_signing_out_is_confirmed_first() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let response = admin.get("/oauth/logout").await;
    let answer = location(&response);
    assert!(answer.starts_with(&format!("{PUBLIC}/#/logout?request=")), "{answer}");
    assert_eq!(admin.get("/uwu/v1/me").await.status(), StatusCode::OK, "still signed in");
    let request = param(&answer.replace("/#/logout", ""), "request").unwrap();
    let info = admin.json(&format!("/uwu/v1/logout-request/{request}")).await;
    assert_eq!((info["app"].clone(), info["returns"].clone()), (Value::Null, json!(false)));
    let done = admin.ok("POST", &format!("/uwu/v1/logout-request/{request}"), json!({ "confirm": true })).await;
    assert_eq!(done["redirect"], format!("{PUBLIC}/#/signed-out"));
    assert_eq!(admin.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn form_post_sends_the_answer_as_a_form() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let response = admin.get(&format!("/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&state=s&response_mode=form_post", url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect::<String>())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = text(response).await;
    assert!(
        page.contains(&format!("action=\"{REDIRECT}\""))
            && page.contains("name=\"code\"")
            && page.contains("name=\"state\" value=\"s\"")
    );
}

#[tokio::test]
async fn max_age_zero_asks_to_sign_in_again_once() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let answer = authorize(&admin, &client_id, &[("max_age", "0")]).await;
    let continue_to = param(&answer.replace("/#/login", ""), "continue").unwrap();
    assert!(continue_to.contains("uwu_login="));
    assert!(answer.contains("fresh=1"), "the sign-in page asks even somebody signed in");
    // Signing in again, then back where the sign-in page sends the browser.
    admin.ok("POST", "/uwu/v1/login", json!({ "login": "admin", "password": PASSWORD })).await;
    let response = admin.get(&continue_to).await;
    assert!(param(&location(&response), "code").is_some(), "{}", location(&response));
}

#[tokio::test]
async fn an_app_that_asks_for_a_second_factor_sends_password_only_sessions_back() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) =
        app(&admin, json!({ "name": "Tresor", "redirectUris": [REDIRECT], "requireMfa": true })).await;
    let answer = authorize(&admin, &client_id, &[]).await;
    assert!(answer.contains("/#/denied?reason=mfa"), "{answer}");
    let key = admin.add_passkey().await;
    let options = admin.ok("POST", "/uwu/v1/reauth/options", json!({})).await;
    let mut key = key;
    let assertion = key.get(&options, PUBLIC, None);
    admin.ok("POST", "/uwu/v1/reauth", json!({ "passkey": assertion })).await;
    assert!(param(&authorize(&admin, &client_id, &[]).await, "code").is_some());
}

#[tokio::test]
async fn my_apps_lists_what_i_may_open_and_what_i_signed_in_to() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "Nextcloud", "template": "nextcloud", "url": "https://cloud.example.com", "redirectUris": [REDIRECT] })).await;
    authorize(&admin, &client_id, &[]).await;
    let mine = admin.json("/uwu/v1/me/apps").await;
    assert_eq!(mine["apps"][0]["launchUrl"], "https://cloud.example.com/");
    let grant = mine["connected"][0]["id"].as_str().unwrap().to_string();
    admin.ok("DELETE", &format!("/uwu/v1/me/grants/{grant}"), json!({})).await;
    assert!(admin.json("/uwu/v1/me/apps").await["connected"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn agreeing_to_an_app_that_wants_a_form_post_goes_through_the_answer_page() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT], "consent": true })).await;
    let answer = authorize(&admin, &client_id, &[("response_mode", "form_post")]).await;
    let request = param(&answer.replace("/#/consent", ""), "request").unwrap();
    let info = admin.json(&format!("/uwu/v1/consent/{request}")).await;
    assert_eq!(info["app"]["template"], Value::Null);
    let decided = admin.ok("POST", &format!("/uwu/v1/consent/{request}"), json!({ "approve": true })).await;
    let redirect = decided["redirect"].as_str().unwrap();
    assert!(redirect.starts_with(&format!("{PUBLIC}/oauth/answer/")), "{redirect}");
    let path = redirect.trim_start_matches(PUBLIC);
    let page = admin.get(path).await;
    assert_eq!(page.status(), StatusCode::OK);
    let page = text(page).await;
    assert!(
        page.contains(&format!("action=\"{REDIRECT}\""))
            && page.contains("name=\"code\"")
            && page.contains("name=\"state\" value=\"xyz\"")
    );
    assert_eq!(admin.get(path).await.status(), StatusCode::NOT_FOUND, "the answer is fetched once");
}

#[tokio::test]
async fn changing_an_app_changes_only_what_is_sent() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let device = "urn:ietf:params:oauth:grant-type:device_code";
    let (client_id, secret, id) = app(
        &admin,
        json!({ "name": "App", "redirectUris": [REDIRECT], "grantTypes": ["authorization_code", device], "accessTokenMinutes": 30, "launchUrl": "https://app.example.com/" }),
    )
    .await;
    assert!(secret.is_some());
    let changed = admin.ok("PATCH", &format!("/uwu/v1/apps/{id}"), json!({ "disabled": true })).await;
    assert_eq!(changed["disabled"], true);
    assert_eq!(changed["redirectUris"], json!([REDIRECT]));
    assert_eq!(changed["grantTypes"], json!(["authorization_code", device]));
    assert_eq!((changed["accessTokenMinutes"].as_i64(), changed["public"].as_bool()), (Some(30), Some(false)));
    let changed = admin.ok("PATCH", &format!("/uwu/v1/apps/{id}"), json!({ "launchUrl": "", "consent": true })).await;
    assert_eq!((changed["launchUrl"].clone(), changed["consent"].clone()), (Value::Null, json!(true)));
    assert_eq!(changed["clientId"], client_id.as_str());
    let changed = admin.ok("PATCH", &format!("/uwu/v1/apps/{id}"), json!({ "public": true })).await;
    assert_eq!((changed["public"].as_bool(), changed["tokenAuthMethod"].as_str()), (Some(true), Some("none")));
}

// ── What the security review found, fixed ─────────────────

#[tokio::test]
async fn a_made_up_login_marker_skips_nothing() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    for extra in [
        &[("prompt", "login"), ("uwu_after", "0")][..],
        &[("prompt", "login"), ("uwu_login", "made-up")],
        &[("max_age", "0"), ("uwu_login", "made-up")],
    ] {
        let answer = authorize(&admin, &client_id, extra).await;
        assert!(answer.contains("/#/login"), "{extra:?}: {answer}");
    }
}

#[tokio::test]
async fn a_registered_app_asks_first_stays_out_of_my_apps_and_reaches_no_internal_address() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let kid = server.person("kid", false).await;
    let token = admin.ok("POST", "/uwu/v1/registration-tokens", json!({ "name": "pair", "uses": 3 })).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let register = |body: Value| {
        server.send(
            Request::post("/oauth/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    };
    let internal = register(json!({ "client_name": "X", "redirect_uris": ["https://app.example.net/cb"], "backchannel_logout_uri": "http://169.254.169.254/latest" })).await;
    assert_eq!(internal.status(), StatusCode::BAD_REQUEST);
    let internal = register(json!({ "client_name": "X", "redirect_uris": ["https://app.example.net/cb"], "backchannel_logout_uri": "https://10.0.0.1/logout" })).await;
    assert_eq!(internal.status(), StatusCode::BAD_REQUEST);
    let made = json(register(json!({ "client_name": "Nextcloud", "redirect_uris": ["https://app.example.net/cb"], "client_uri": "https://app.example.net/" })).await).await;
    let client_id = made["client_id"].as_str().unwrap();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", "https://app.example.net/cb")
        .append_pair("scope", "openid");
    let answer = location(&kid.get(&format!("/oauth/authorize?{}", query.finish())).await);
    assert!(answer.contains("/#/consent?request="), "{answer}");
    assert!(kid.json("/uwu/v1/me/apps").await["apps"].as_array().unwrap().is_empty());
    // Two bad requests did not use the token up: it had three uses.
    let again = register(json!({ "client_name": "Y", "redirect_uris": ["https://app.example.net/cb"] })).await;
    assert_eq!(again.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn only_an_id_token_is_a_hint_and_only_a_hint_leads_back() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(
        &admin,
        json!({ "name": "App", "redirectUris": [REDIRECT], "postLogoutRedirectUris": ["https://app.example.com/bye"] }),
    )
    .await;
    let code = param(&authorize(&admin, &client_id, &[]).await, "code").unwrap();
    let (_, tokens) = token(
        &server,
        Some((&client_id, &secret.unwrap())),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    let access = tokens["access_token"].as_str().unwrap();
    let answer = location(
        &admin
            .get(&format!(
                "/oauth/logout?id_token_hint={access}&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fbye"
            ))
            .await,
    );
    assert!(answer.contains("/#/logout?request="), "an access token is no hint: {answer}");
    assert_eq!(admin.get("/uwu/v1/me").await.status(), StatusCode::OK);
    let stranger = server.browser();
    let answer = location(
        &stranger
            .get(&format!(
                "/oauth/logout?client_id={client_id}&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fbye"
            ))
            .await,
    );
    assert!(answer.ends_with("/#/signed-out"), "no hint, no way back to the app: {answer}");
}

#[tokio::test]
async fn a_redirect_uri_sent_before_is_sent_again() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let code = param(&authorize(&admin, &client_id, &[]).await, "code").unwrap();
    let (status, _) =
        token(&server, Some((&client_id, &secret)), &[("grant_type", "authorization_code"), ("code", &code)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_device_app_without_refresh_tokens_still_reads_userinfo() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, _, _) = app(
        &admin,
        json!({ "name": "TV", "public": true, "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code"] }),
    )
    .await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &client_id)
        .append_pair("scope", "openid profile")
        .finish();
    let started = json(
        server
            .send(
                Request::post("/oauth/device_authorization")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await,
    )
    .await;
    admin
        .ok("POST", &format!("/uwu/v1/device/{}", started["user_code"].as_str().unwrap()), json!({ "approve": true }))
        .await;
    let poll = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", started["device_code"].as_str().unwrap()),
        ("client_id", client_id.as_str()),
    ];
    let (_, tokens) = token(&server, None, &poll).await;
    let (status, _) = userinfo(&server, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn two_refreshes_at_once_leave_no_token_alive() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let code = param(&authorize(&admin, &client_id, &[]).await, "code").unwrap();
    let (_, first) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT)],
    )
    .await;
    let old = first["refresh_token"].as_str().unwrap().to_string();
    let pairs = [("grant_type", "refresh_token"), ("refresh_token", old.as_str())];
    let (a, b) = tokio::join!(
        token(&server, Some((&client_id, &secret)), &pairs),
        token(&server, Some((&client_id, &secret)), &pairs)
    );
    for (status, body) in [a, b] {
        if status == StatusCode::OK {
            let new = body["refresh_token"].as_str().unwrap();
            let (status, _) =
                token(&server, Some((&client_id, &secret)), &[("grant_type", "refresh_token"), ("refresh_token", new)])
                    .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "a copy was used: the whole family ended");
        }
    }
}

#[tokio::test]
async fn a_change_to_an_app_keeps_what_it_does_not_name() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (_, _, id) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT], "allowedGroups": [uwuauth_store::ADMINS_ID], "requireMfa": true, "consent": true })).await;
    let changed = admin
        .ok("PATCH", &format!("/uwu/v1/apps/{id}"), json!({ "redirectUris": [REDIRECT, "https://new.example.com/cb"] }))
        .await;
    assert_eq!(changed["allowedGroups"], json!([uwuauth_store::ADMINS_ID]));
    assert_eq!((changed["requireMfa"].as_bool(), changed["consent"].as_bool()), (Some(true), Some(true)));
    assert_eq!(changed["redirectUris"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_code_that_comes_again_ends_what_it_gave() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (client_id, secret, _) = app(&admin, json!({ "name": "App", "redirectUris": [REDIRECT] })).await;
    let secret = secret.unwrap();
    let code = param(&authorize(&admin, &client_id, &[]).await, "code").unwrap();
    let exchange = [("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", REDIRECT)];
    let (_, first) = token(&server, Some((&client_id, &secret)), &exchange).await;
    let (status, _) = token(&server, Some((&client_id, &secret)), &exchange).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = token(
        &server,
        Some((&client_id, &secret)),
        &[("grant_type", "refresh_token"), ("refresh_token", first["refresh_token"].as_str().unwrap())],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the first refresh token went with the replayed code");
}
