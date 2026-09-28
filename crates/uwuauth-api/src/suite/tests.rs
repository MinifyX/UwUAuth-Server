//! Pairing and SCIM from the suite app's side: a code from the admin portal, `/uwu/v1/pair`, a
//! sign-in with what it gave, and a SCIM server on this machine that people are pushed to.

use super::*;
use crate::test_support::*;
use axum::body::Body;
use axum::http::Request;
use parking_lot::Mutex;
use std::sync::Arc;
use uwuauth_store::{GroupFields, NewPerson};

const LOCK: &str = "https://lock.example.com";

fn suite_app(url: &str, scim: Option<&str>) -> Value {
    let mut app = json!({
        "product": "UwULock",
        "version": "0.6.0",
        "name": "UwULock (lock.example.com)",
        "url": url,
        "icon": format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\nrest")),
        "redirectUris": [format!("{url}/identity/connect/oidc-signin")],
        "postLogoutRedirectUris": [format!("{url}/")],
        "scopes": ["openid", "email", "profile", "groups", "roles", "made-up"],
        "roles": [
            { "id": "admin", "name": "Administrator", "description": "Uses the admin portal" },
            { "id": "user", "name": "User", "description": "May create a vault without an invitation" }
        ],
    });
    if let Some(scim) = scim {
        app["scim"] = json!({ "baseUrl": scim, "resources": ["User", "Group"] });
    }
    app
}

async fn pair_request(server: &TestServer, body: Value) -> (StatusCode, Value) {
    let response = server
        .send(
            Request::post("/uwu/v1/pair")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    let status = response.status();
    (status, json(response).await)
}

#[test]
fn codes_are_read_the_way_people_type_them() {
    let code = new_code();
    assert_eq!(code.len(), 14);
    assert!(code.chars().all(|c| c == '-' || CROCKFORD.contains(&(c as u8))), "{code}");
    let plain = code.replace('-', "");
    assert_eq!(normalize(&code).as_deref(), Some(plain.as_str()));
    assert_eq!(normalize(&code.to_lowercase().replace('-', " ")).as_deref(), Some(plain.as_str()));
    assert_eq!(normalize(&format!("https://auth.example.com/#pair={code}")).as_deref(), Some(plain.as_str()));
    assert_eq!(normalize("7KQ4-M2XD-9HFT").as_deref(), Some("7KQ4M2XD9HFT"));
    assert_eq!(normalize("IKQ4-M2XD-9HFO").as_deref(), Some("1KQ4M2XD9HF0"), "I and O read as digits");
    for bad in ["", "7KQ4-M2XD", "7KQ4-M2XD-9HFT-1", "7KQ4-M2XD-9HFU", "7KQ4-M2XD-9HFÄ"] {
        assert!(normalize(bad).is_none(), "{bad}");
    }
}

#[tokio::test]
async fn a_suite_app_pairs_once_and_signs_people_in_with_roles() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "vault-admins" })).await;
    let me = admin.json("/uwu/v1/me").await;
    server.state.store.add_member(group["id"].as_str().unwrap(), me["id"].as_str().unwrap()).await.unwrap();

    let made = admin.ok("POST", "/uwu/v1/pairing-codes", json!({ "roleGroups": { "admin": ["vault-admins"] } })).await;
    let code = made["code"].as_str().unwrap().to_string();
    assert_eq!(made["link"], format!("{PUBLIC}/#pair={code}"));
    assert_eq!(admin.json("/uwu/v1/pairing-codes").await.as_array().unwrap().len(), 1);

    let info = json(server.get("/uwu/v1/server").await).await;
    assert_eq!((info["product"].as_str(), info["pairing"].as_u64()), (Some("UwUAuth"), Some(1)));

    // The whole QR text works as the code, too.
    let (status, paired) = pair_request(
        &server,
        json!({ "code": made["link"], "app": suite_app(LOCK, Some(&format!("{LOCK}/scim/v2"))) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{paired}");
    assert_eq!(paired["issuer"], PUBLIC);
    assert_eq!(paired["tokenEndpointAuthMethod"], "client_secret_basic");
    assert_eq!(paired["scopes"], json!(["openid", "email", "profile", "groups", "roles"]));
    assert_eq!((paired["groupsClaim"].as_str(), paired["rolesClaim"].as_str()), (Some("groups"), Some("roles")));
    assert_eq!(paired["scimToken"].as_str().map(str::len), Some(43));
    let app_id = paired["appId"].as_str().unwrap();
    assert_eq!(paired["manageUrl"], format!("{PUBLIC}/admin#/apps/{app_id}"));

    let (again, body) = pair_request(&server, json!({ "code": code, "app": suite_app(LOCK, None) })).await;
    assert_eq!((again, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_code")), "once only");

    let app = admin.json(&format!("/uwu/v1/apps/{app_id}")).await;
    assert_eq!(app["template"], TEMPLATE);
    assert_eq!((app["public"].as_bool(), app["consent"].as_bool()), (Some(false), Some(false)));
    assert_eq!(app["requirePkce"], true);
    assert_eq!(app["launchUrl"], format!("{LOCK}/"));
    assert_eq!(app["suite"]["product"], "UwULock");
    assert_eq!(app["suite"]["roles"][0]["id"], "admin");
    assert_eq!(app["scim"]["baseUrl"], format!("{LOCK}/scim/v2"));
    assert_eq!(app["suite"]["icon"], format!("{PUBLIC}/uwu/v1/apps/{app_id}/icon"));
    let icon = server.get(&format!("/uwu/v1/apps/{app_id}/icon")).await;
    assert_eq!(icon.headers()["content-type"], "image/png");
    let status = admin.json(&format!("/uwu/v1/pairing-codes/{}", made["id"].as_str().unwrap())).await;
    assert_eq!((status["open"].as_bool(), status["app"]["id"].as_str()), (Some(false), Some(app_id)));
    let events = admin.json("/uwu/v1/events?kind=app_paired").await;
    assert_eq!(events[0]["detail"]["product"], "UwULock", "{events}");

    // A sign-in, as the suite app does it: PKCE, the secret, no consent screen.
    let verifier = crate::crypto::random_token(32);
    let challenge = crate::crypto::b64(&sha256(verifier.as_bytes()));
    let client_id = paired["clientId"].as_str().unwrap();
    let redirect = format!("{LOCK}/identity/connect/oidc-signin");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("scope", "openid email profile groups roles")
        .append_pair("state", "s")
        .append_pair("nonce", "n")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let answer = admin.get(&format!("/oauth/authorize?{query}")).await;
    let location = answer.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&redirect), "{location}");
    let code = url::Url::parse(&location).unwrap().query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", &redirect)
        .append_pair("code_verifier", &verifier)
        .finish();
    let basic = base64::engine::general_purpose::STANDARD
        .encode(format!("{client_id}:{}", paired["clientSecret"].as_str().unwrap()));
    let response = server
        .send(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {basic}"))
                .body(Body::from(form))
                .unwrap(),
        )
        .await;
    let tokens = json(response).await;
    let id_token = tokens["id_token"].as_str().expect("an ID token");
    let claims: Value =
        serde_json::from_slice(&crate::crypto::unb64(id_token.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let mut roles: Vec<&str> = claims["roles"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    roles.sort_unstable();
    assert_eq!(roles, ["admin", "user"], "admin from the group, user for everybody who may use it");
    assert!(claims["groups"].as_array().unwrap().contains(&json!("vault-admins")));
}

#[tokio::test]
async fn pairing_refuses_what_it_should() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let unknown = admin.request("POST", "/uwu/v1/pairing-codes", Some(json!({ "allowedGroups": ["nope"] }))).await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    let made = admin.ok("POST", "/uwu/v1/pairing-codes", json!({})).await;
    let code = made["code"].as_str().unwrap();

    for wrong in ["0000-0000-0000", "nonsense", ""] {
        let (status, body) = pair_request(&server, json!({ "code": wrong, "app": suite_app(LOCK, None) })).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_code")), "{wrong}");
    }
    let refused = |app: Value| {
        let server = &server;
        async move { pair_request(server, json!({ "code": code, "app": app })).await }
    };
    let mut other_host = suite_app(LOCK, None);
    other_host["redirectUris"] = json!(["https://evil.example.net/cb"]);
    let mut plain_http = suite_app("http://lock.example.com", None);
    plain_http["redirectUris"] = json!(["http://lock.example.com/cb"]);
    let mut not_png = suite_app(LOCK, None);
    not_png["icon"] = json!("data:image/png;base64,PHN2Zz4=");
    let mut too_big = suite_app(LOCK, None);
    too_big["icon"] = json!(format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode([b"\x89PNG\r\n\x1a\n".as_slice(), &[0; 70_000]].concat())
    ));
    let scim_elsewhere = suite_app(LOCK, Some("https://intranet.example.org/scim/v2"));
    let mut bad_role = suite_app(LOCK, None);
    bad_role["roles"] = json!([{ "id": "Admin Role" }]);
    for (what, app) in [
        ("other host", other_host),
        ("plain http", plain_http),
        ("not a png", not_png),
        ("too big", too_big),
        ("SCIM elsewhere", scim_elsewhere),
        ("bad role", bad_role),
    ] {
        let (status, body) = refused(app).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {body}");
        assert_ne!(body["error"], "invalid_code", "{what}");
    }
    // None of that used the code up; withdrawing it does.
    admin.ok("DELETE", &format!("/uwu/v1/pairing-codes/{}", made["id"].as_str().unwrap()), json!({})).await;
    let (status, body) = refused(suite_app(LOCK, None)).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_code")));

    // A code that ran out.
    let old = "7KQ4M2XD9HFT";
    server
        .state
        .store
        .create_pairing_code(PairingCode {
            hash: Some(sha256(old.as_bytes())),
            expires: clock::in_seconds(-1),
            ..PairingCode::default()
        })
        .await
        .unwrap();
    let (status, body) = pair_request(&server, json!({ "code": old, "app": suite_app(LOCK, None) })).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_code")));
    let refusals = admin.json("/uwu/v1/events?kind=app_pairing_refused").await;
    assert!(refusals.as_array().unwrap().len() >= 4);
}

#[tokio::test]
async fn pairing_is_rate_limited() {
    let server = TestServer::new().await;
    let mut state = server.state.clone();
    state.limits = Arc::new(crate::Limits::default());
    let router = crate::router(state);
    let mut statuses = Vec::new();
    for _ in 0..11 {
        let request = Request::post("/uwu/v1/pair")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "code": "0000-0000-0000", "app": suite_app(LOCK, None) }).to_string()))
            .unwrap();
        statuses.push(tower::ServiceExt::oneshot(router.clone(), request).await.unwrap().status());
    }
    assert!(statuses[..10].iter().all(|status| *status == StatusCode::BAD_REQUEST));
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS);
}

// ── SCIM ──────────────────────────────────────────────────

/// A SCIM server on this machine: people and groups in memory, every request noted.
#[derive(Default)]
struct Fake {
    users: BTreeMap<String, Value>,
    groups: BTreeMap<String, Value>,
    requests: Vec<String>,
    tokens: Vec<String>,
}

type Shared = Arc<(Mutex<Fake>, tokio::sync::Notify)>;

fn apply(resource: &mut Value, body: &Value) {
    for operation in body["Operations"].as_array().unwrap() {
        assert_eq!(operation["op"], "replace");
        resource[operation["path"].as_str().unwrap()] = operation["value"].clone();
    }
}

async fn fake_scim() -> (String, Shared) {
    use axum::extract::{Path as P, Query, State as S};
    use axum::http::HeaderMap;
    let shared: Shared = Arc::default();
    async fn handle(
        S(shared): S<Shared>,
        method: axum::http::Method,
        P(path): P<String>,
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, Json<Value>) {
        let (fake, notify) = &*shared;
        let mut fake = fake.lock();
        let token = headers["authorization"].to_str().unwrap().trim_start_matches("Bearer ").to_string();
        fake.tokens.push(token);
        fake.requests.push(format!("{method} /{path}"));
        notify.notify_waiters();
        let body: Value = serde_json::from_slice(&body).unwrap_or_default();
        let (kind, id) = path.split_once('/').map_or((path.as_str(), None), |(kind, id)| (kind, Some(id.to_string())));
        let key = if kind == "Users" { "userName" } else { "displayName" };
        let fake = &mut *fake;
        let store = if kind == "Users" { &mut fake.users } else { &mut fake.groups };
        match (method.as_str(), id) {
            ("POST", None) => {
                if store.values().any(|known| known[key] == body[key]) {
                    return (StatusCode::CONFLICT, Json(json!({ "status": "409", "scimType": "uniqueness" })));
                }
                let id = uuid::Uuid::new_v4().to_string();
                let mut made = body.clone();
                made["id"] = json!(id);
                store.insert(id, made.clone());
                (StatusCode::CREATED, Json(made))
            }
            ("GET", None) => {
                let filter = query.get("filter").cloned().unwrap_or_default();
                let wanted: Value = serde_json::from_str(filter.split_once(" eq ").unwrap().1).unwrap();
                let found: Vec<Value> = store.values().filter(|known| known[key] == wanted).cloned().collect();
                (StatusCode::OK, Json(json!({ "totalResults": found.len(), "Resources": found })))
            }
            ("PATCH", Some(id)) => match store.get_mut(&id) {
                Some(known) => {
                    apply(known, &body);
                    (StatusCode::OK, Json(known.clone()))
                }
                None => (StatusCode::NOT_FOUND, Json(json!({ "status": "404" }))),
            },
            ("DELETE", Some(id)) => match store.remove(&id) {
                Some(_) => (StatusCode::NO_CONTENT, Json(Value::Null)),
                None => (StatusCode::NOT_FOUND, Json(json!({ "status": "404" }))),
            },
            _ => (StatusCode::BAD_REQUEST, Json(json!({ "detail": "not in this fake" }))),
        }
    }
    let app = axum::Router::new().route("/scim/v2/{*path}", axum::routing::any(handle)).with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), shared)
}

async fn person(server: &TestServer, name: &str, email: Option<&str>) -> String {
    let made = server
        .state
        .store
        .create_person(NewPerson {
            username: name.into(),
            display_name: name.to_uppercase(),
            email: email.map(str::to_string),
            language: "de".into(),
            ..NewPerson::default()
        })
        .await
        .unwrap();
    made.id
}

/// Everything the fake got, with the requests since the last look.
fn look(shared: &Shared) -> (Vec<Value>, Vec<Value>, Vec<String>) {
    let mut fake = shared.0.lock();
    let requests = std::mem::take(&mut fake.requests);
    (fake.users.values().cloned().collect(), fake.groups.values().cloned().collect(), requests)
}

#[tokio::test]
async fn people_who_may_use_a_paired_app_are_pushed_over_scim() {
    let server = TestServer::new().await;
    let store = &server.state.store;
    let admin = server.person("admin", true).await;
    let (url, shared) = fake_scim().await;
    let family = store.create_group(GroupFields { name: "family".into(), ..GroupFields::default() }).await.unwrap();
    let mia = person(&server, "mia", Some("mia@example.com")).await;
    let kid = person(&server, "kid", None).await;
    let anna = person(&server, "anna", Some("anna@example.com")).await;
    for id in [&mia, &kid, &anna] {
        store.add_member(&family.id, id).await.unwrap();
    }
    // Anna is known there already.
    shared.0.lock().users.insert("anna-there".into(), json!({ "id": "anna-there", "userName": "anna@example.com" }));

    let made = admin.ok("POST", "/uwu/v1/pairing-codes", json!({ "allowedGroups": ["family"] })).await;
    let (status, paired) =
        pair_request(&server, json!({ "code": made["code"], "app": suite_app(&url, Some(&format!("{url}/scim/v2"))) }))
            .await;
    assert_eq!(status, StatusCode::OK, "{paired}");
    let app_id = paired["appId"].as_str().unwrap().to_string();

    let pushed = scim::push(&server.state, &app_id).await.unwrap();
    assert!(pushed.errors.is_empty(), "{pushed:?}");
    let (users, groups, _) = look(&shared);
    assert_eq!(users.len(), 2, "mia and anna; the kid has no address, the admin is not in the family");
    let mia_there = users.iter().find(|user| user["userName"] == "mia@example.com").unwrap().clone();
    assert_eq!(mia_there["externalId"], mia.as_str());
    assert_eq!((mia_there["displayName"].as_str(), mia_there["active"].as_bool()), (Some("MIA"), Some(true)));
    assert_eq!(mia_there["emails"][0]["value"], "mia@example.com");
    let anna_there = users.iter().find(|user| user["id"] == "anna-there").unwrap();
    assert_eq!(anna_there["externalId"], anna.as_str(), "taken over, not made twice");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["displayName"], "family");
    assert_eq!(groups[0]["members"].as_array().unwrap().len(), 2);
    assert!(shared.0.lock().tokens.iter().all(|token| token == paired["scimToken"].as_str().unwrap()));
    let app = admin.json(&format!("/uwu/v1/apps/{app_id}")).await;
    assert_eq!((app["scim"]["users"].as_i64(), app["scim"]["groups"].as_i64()), (Some(2), Some(1)));
    assert!(app["scim"]["synced"].is_string());

    // Nothing changed: nothing is sent.
    scim::push(&server.state, &app_id).await.unwrap();
    assert!(look(&shared).2.is_empty());

    // Disabled: inactive there, and out of the group.
    store.update_person(&mia, |person| person.disabled = true).await.unwrap();
    scim::push(&server.state, &app_id).await.unwrap();
    let (users, groups, requests) = look(&shared);
    assert_eq!(requests.len(), 2, "one PATCH for mia, one for the group: {requests:?}");
    assert_eq!(users.iter().find(|user| user["id"] == mia_there["id"]).unwrap()["active"], false);
    assert_eq!(groups[0]["members"].as_array().unwrap().len(), 1);

    // Out of the family: inactive too; gone for good: deleted there.
    store.update_person(&mia, |person| person.disabled = false).await.unwrap();
    store.remove_member(&family.id, &anna).await.unwrap();
    scim::push(&server.state, &app_id).await.unwrap();
    let (users, _, _) = look(&shared);
    assert_eq!(users.iter().find(|user| user["id"] == "anna-there").unwrap()["active"], false);
    assert_eq!(users.iter().find(|user| user["id"] == mia_there["id"]).unwrap()["active"], true);
    store.purge_person(&anna).await.unwrap();
    let pushed = scim::push(&server.state, &app_id).await.unwrap();
    assert_eq!(pushed.deleted, 1);
    assert_eq!(look(&shared).0.len(), 1);

    // Deleted there by hand: made again.
    shared.0.lock().users.clear();
    store.update_person(&mia, |person| person.display_name = "Mia".into()).await.unwrap();
    scim::push(&server.state, &app_id).await.unwrap();
    assert_eq!(look(&shared).0[0]["displayName"], "Mia");

    // An app that cannot be reached: noted on the app and in the events, once.
    let _ = kid;
    let target = store.scim_target(&app_id).await.unwrap().unwrap();
    store.set_scim_target(ScimTarget { base_url: "http://127.0.0.1:9/scim/v2".into(), ..target }).await.unwrap();
    for _ in 0..2 {
        let pushed = scim::push(&server.state, &app_id).await.unwrap();
        assert_eq!(pushed.errors.len(), 1);
    }
    let app = admin.json(&format!("/uwu/v1/apps/{app_id}")).await;
    assert!(app["scim"]["error"].is_string());
    let failed = admin.json("/uwu/v1/events?kind=app_scim_failed").await;
    assert_eq!(failed.as_array().unwrap().len(), 1, "{failed}");
}

#[tokio::test]
async fn an_admin_sets_up_scim_for_any_app_and_the_task_pushes() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let (url, shared) = fake_scim().await;
    person(&server, "mia", Some("mia@example.com")).await;
    let app = admin
        .ok("POST", "/uwu/v1/apps", json!({ "name": "Wiki", "redirectUris": ["https://wiki.example.com/cb"] }))
        .await;
    let id = app["id"].as_str().unwrap();
    let path = format!("/uwu/v1/apps/{id}/scim");
    let without = admin.request("PUT", &path, Some(json!({ "baseUrl": format!("{url}/scim/v2") }))).await;
    assert_eq!(without.status(), StatusCode::BAD_REQUEST, "a token is needed");
    scim::spawn(server.state.clone());
    let waiting = shared.1.notified();
    let set = admin
        .ok(
            "PUT",
            &path,
            json!({ "baseUrl": format!("{url}/scim/v2/"), "token": "from-the-wiki", "userName": "username" }),
        )
        .await;
    assert_eq!(set["baseUrl"], format!("{url}/scim/v2"));
    tokio::time::timeout(std::time::Duration::from_secs(10), waiting).await.expect("the task pushes");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while server.state.store.scim_target(id).await.unwrap().unwrap().tried.is_none() {
        assert!(tokio::time::Instant::now() < deadline, "the push ends");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let (users, _, _) = look(&shared);
    assert!(users.iter().any(|user| user["userName"] == "mia"), "by user name: {users:?}");
    assert!(shared.0.lock().tokens.iter().all(|token| token == "from-the-wiki"));
    let now = admin.request("POST", &format!("{path}/sync"), Some(json!({ "all": true }))).await;
    assert_eq!(now.status(), StatusCode::ACCEPTED);
    admin.ok("DELETE", &path, json!({})).await;
    assert!(server.state.store.scim_target(id).await.unwrap().is_none());
    assert_eq!(admin.request("POST", &format!("{path}/sync"), Some(json!({}))).await.status(), StatusCode::NOT_FOUND);
}
