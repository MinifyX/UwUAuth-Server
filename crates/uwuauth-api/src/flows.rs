//! Whole flows through the API, the way the web app goes through them: invitations, signing in
//! every way there is, managers and their kids, what admins may not do, and what nobody may.

use crate::routes::invitations::InviteFields;
use crate::test_support::*;
use crate::totp;
use axum::http::StatusCode;
use serde_json::{Value, json};
use uwuauth_store::clock;

async fn login(browser: &Browser<'_>, name: &str, password: &str) -> (StatusCode, Value) {
    let response = browser.post("/uwu/v1/login", json!({ "login": name, "password": password })).await;
    let status = response.status();
    (status, json(response).await)
}

/// The authenticator app's code for a secret the setup showed, `steps` steps from now.
fn code(secret: &str, steps: i64) -> String {
    let secret = totp::base32_decode(secret).unwrap();
    totp::code(&secret, time::OffsetDateTime::now_utc().unix_timestamp() / 30 + steps)
}

#[tokio::test]
async fn an_invitation_makes_an_account_once() {
    let server = TestServer::new().await;
    let token = server
        .invitation(InviteFields {
            email: Some("nyu@example.com".into()),
            mail: true,
            admin: true,
            ..InviteFields::default()
        })
        .await;
    let mail = server.mail_to("nyu@example.com").expect("the invitation went out");
    assert!(mail.link().unwrap().contains(&token));

    let anybody = server.browser();
    let info = anybody.json(&format!("/uwu/v1/links/invite/{token}")).await;
    assert_eq!(info["email"], "nyu@example.com");

    let browser = server.browser();
    let answer = browser
        .ok(
            "POST",
            &format!("/uwu/v1/links/invite/{token}"),
            json!({ "username": "Nyu", "displayName": "Nyu", "password": PASSWORD }),
        )
        .await;
    assert_eq!(answer["status"], "signed_in");
    let me = browser.json("/uwu/v1/me").await;
    assert_eq!(me["username"], "nyu");
    assert_eq!(me["admin"], true);
    assert_eq!(me["emailVerified"], true, "the link came to that address");

    let again = server
        .browser()
        .post(&format!("/uwu/v1/links/invite/{token}"), json!({ "username": "other", "password": PASSWORD }))
        .await;
    assert_eq!(again.status(), StatusCode::GONE);
}

#[tokio::test]
async fn an_invitation_needs_a_password_or_a_passkey_and_a_free_name() {
    let server = TestServer::new().await;
    server.person("nyu", true).await;
    let token = server.invitation(InviteFields::default()).await;
    let path = format!("/uwu/v1/links/invite/{token}");
    let browser = server.browser();
    assert_eq!(browser.post(&path, json!({ "username": "mia" })).await.status(), StatusCode::BAD_REQUEST);
    let taken = browser.post(&path, json!({ "username": "NYU", "password": PASSWORD })).await;
    assert_eq!(json(taken).await["error"], "exists");
    let short = browser.post(&path, json!({ "username": "mia", "password": "short" })).await;
    assert_eq!(json(short).await["error"], "too_short");
    let named = browser.post(&path, json!({ "username": "mia", "password": "mia-is-the-best" })).await;
    assert_eq!(json(named).await["error"], "contains_name");
    // And the invitation still works after all that.
    browser.ok("POST", &path, json!({ "username": "mia", "password": PASSWORD })).await;
}

#[tokio::test]
async fn an_invitation_accepted_with_a_passkey_signs_in_with_it() {
    let server = TestServer::new().await;
    let token = server.invitation(InviteFields::default()).await;
    let browser = server.browser();
    let options = browser
        .ok(
            "POST",
            &format!("/uwu/v1/links/invite/{token}/passkey-options"),
            json!({ "username": "mia", "displayName": "Mia" }),
        )
        .await;
    let mut key = crate::webauthn::tests::SoftKey::new();
    let credential = key.create(&options, PUBLIC);
    browser
        .ok("POST", &format!("/uwu/v1/links/invite/{token}"), json!({ "username": "mia", "displayName": "Mia", "passkey": { "credential": credential, "name": "Tablet" } }))
        .await;
    let me = browser.json("/uwu/v1/me").await;
    assert_eq!(me["hasPassword"], false);
    assert_eq!(me["passkeys"][0]["name"], "Tablet");

    // Signing in with it later, without a name.
    let fresh = server.browser();
    let started = fresh.ok("POST", "/uwu/v1/login/passkey/options", json!({})).await;
    let handle = crate::crypto::b64(&crate::webauthn::user_handle(me["id"].as_str().unwrap()));
    let assertion = key.get(&started["options"], PUBLIC, Some(&handle));
    let answer =
        fresh.ok("POST", "/uwu/v1/login/passkey", json!({ "id": started["id"], "credential": assertion })).await;
    assert_eq!(answer["status"], "signed_in");
    assert_eq!(fresh.json("/uwu/v1/me").await["username"], "mia");
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_counted() {
    let server = TestServer::new().await;
    let own_device = server.person("nyu", false).await;
    let stranger = server.browser();
    let (status, body) = login(&stranger, "nyu", "wrong password").await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("wrong")));
    let (status, _) = login(&stranger, "nobody", "wrong password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the same answer for a name nobody has");
    for _ in 0..9 {
        login(&stranger, "nyu", "wrong password").await;
    }
    // Locked for devices it never saw: even the right password counts as wrong there, and says
    // nothing about the account.
    let (status, body) = login(&stranger, "nyu", PASSWORD).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("wrong")));
    // The owner's own device still gets in.
    own_device.post("/uwu/v1/logout", json!({})).await;
    let (status, _) = login(&own_device, "nyu", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "a stranger cannot lock the owner out");
    let events = server
        .state
        .store
        .events(uwuauth_store::EventFilter { kind: Some("login_failed".into()), limit: 50, ..Default::default() })
        .await
        .unwrap();
    assert_eq!(events.len(), 11);
}

#[tokio::test]
async fn the_authenticator_app_is_the_second_step_and_each_code_works_once() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    let setup = browser.ok("POST", "/uwu/v1/me/totp/start", json!({})).await;
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(setup["uri"].as_str().unwrap().starts_with("otpauth://totp/UwUAuth%3Anyu?secret="));
    let wrong = browser.request("POST", "/uwu/v1/me/totp", Some(json!({ "code": "000000" }))).await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    let done = browser.ok("POST", "/uwu/v1/me/totp", json!({ "code": code(&secret, 0) })).await;
    let recovery = done["recoveryCodes"].as_array().unwrap().clone();
    assert_eq!(recovery.len(), 10);

    let other = server.browser();
    let (status, body) = login(&other, "nyu", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "second_factor");
    assert_eq!(body["methods"], json!(["totp", "recovery"]));
    let pending = body["pending"].clone();
    assert_eq!(other.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED, "not signed in yet");
    let used = other.post("/uwu/v1/login/second", json!({ "pending": pending, "code": code(&secret, 0) })).await;
    assert_eq!(used.status(), StatusCode::UNAUTHORIZED, "the code the setup used works no more");
    let next = other.ok("POST", "/uwu/v1/login/second", json!({ "pending": pending, "code": code(&secret, 1) })).await;
    assert_eq!(next["status"], "signed_in");

    // A recovery code, once.
    let third = server.browser();
    let (_, body) = login(&third, "nyu", PASSWORD).await;
    let recovery_code = recovery[0].as_str().unwrap().to_uppercase();
    third.ok("POST", "/uwu/v1/login/second", json!({ "pending": body["pending"], "recovery": recovery_code })).await;
    let fourth = server.browser();
    let (_, body) = login(&fourth, "nyu", PASSWORD).await;
    let again =
        fourth.post("/uwu/v1/login/second", json!({ "pending": body["pending"], "recovery": recovery[0] })).await;
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fourth.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_group_that_asks_for_a_second_factor_restricts_until_there_is_one() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Büro", "requireMfa": true })).await;
    let worker = server.person("worker", false).await;
    let worker_id = worker.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    admin
        .ok(
            "PUT",
            &format!("/uwu/v1/groups/{}/members", group["id"].as_str().unwrap()),
            json!({ "people": [worker_id], "groups": [] }),
        )
        .await;

    let browser = server.browser();
    let (_, body) = login(&browser, "worker", PASSWORD).await;
    assert_eq!(body["restricted"], true);
    let me = browser.json("/uwu/v1/me").await;
    assert_eq!((me["restricted"].as_bool(), me["needsMfa"].as_bool()), (Some(true), Some(true)));
    let blocked = browser.get("/uwu/v1/me/sessions").await;
    assert_eq!(json(blocked).await["detail"]["restricted"], true);
    browser.add_passkey().await;
    assert_eq!(browser.json("/uwu/v1/me").await["restricted"], false);
    assert_eq!(browser.get("/uwu/v1/me/sessions").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn changing_how_one_signs_in_asks_again_after_a_while() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    // Ten minutes and more ago.
    let me = browser.json("/uwu/v1/me").await;
    let sessions = server.state.store.sessions_of(me["id"].as_str().unwrap()).await.unwrap();
    let mut old = sessions[0].clone();
    server.state.store.end_session(&old.id).await.unwrap();
    old.auth_time = clock::in_seconds(-11 * 60);
    server.state.store.create_session(old).await.unwrap();

    let refused =
        browser.request("POST", "/uwu/v1/me/password", Some(json!({ "password": "another long password" }))).await;
    assert_eq!(json(refused).await["error"], "reauth");
    let wrong = browser.request("POST", "/uwu/v1/reauth", Some(json!({ "password": "nope" }))).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    browser.ok("POST", "/uwu/v1/reauth", json!({ "password": PASSWORD })).await;
    browser.ok("POST", "/uwu/v1/me/password", json!({ "password": "another long password" })).await;
    assert_eq!(browser.get("/uwu/v1/me").await.status(), StatusCode::OK, "this browser stays signed in");
    let (status, _) = login(&server.browser(), "nyu", "another long password").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_new_password_signs_out_everywhere_else() {
    let server = TestServer::new().await;
    let first = server.person("nyu", false).await;
    let second = server.browser();
    login(&second, "nyu", PASSWORD).await;
    assert_eq!(second.get("/uwu/v1/me").await.status(), StatusCode::OK);
    first.ok("POST", "/uwu/v1/me/password", json!({ "password": "another long password" })).await;
    assert_eq!(second.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(first.get("/uwu/v1/me").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_only_way_to_sign_in_stays() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    let key = browser.add_passkey().await;
    drop(key);
    browser.ok("DELETE", "/uwu/v1/me/password", json!({})).await;
    let me = browser.json("/uwu/v1/me").await;
    let passkey = me["passkeys"][0]["id"].as_str().unwrap();
    let refused = browser.request("DELETE", &format!("/uwu/v1/me/passkeys/{passkey}"), None).await;
    assert_eq!(json(refused).await["error"], "last_credential");
}

#[tokio::test]
async fn forgot_password_mails_a_link_that_works_once() {
    let server = TestServer::new().await;
    let token = server
        .invitation(InviteFields { email: Some("nyu@example.com".into()), mail: true, ..InviteFields::default() })
        .await;
    let old = server.browser();
    old.ok("POST", &format!("/uwu/v1/links/invite/{token}"), json!({ "username": "nyu", "password": PASSWORD })).await;

    let anybody = server.browser();
    let answer = anybody.post("/uwu/v1/forgot", json!({ "login": "nyu@example.com" })).await;
    assert_eq!(answer.status(), StatusCode::ACCEPTED);
    let nobody = anybody.post("/uwu/v1/forgot", json!({ "login": "nobody@example.com" })).await;
    assert_eq!(nobody.status(), StatusCode::ACCEPTED, "the same answer either way");
    let link = server.mail_to("nyu@example.com").unwrap().link().unwrap().to_string();
    assert!(link.contains("/#/reset?token="));
    let token = token_of(&link);
    anybody.ok("POST", &format!("/uwu/v1/links/reset/{token}"), json!({ "password": "a brand new password" })).await;
    assert_eq!(old.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED, "the old session ended");
    assert_eq!(anybody.get("/uwu/v1/me").await.status(), StatusCode::OK);
    let again = server
        .browser()
        .post(&format!("/uwu/v1/links/reset/{token}"), json!({ "password": "yet another password" }))
        .await;
    assert_eq!(again.status(), StatusCode::GONE);
}

#[tokio::test]
async fn a_parent_looks_after_their_kid_and_nobody_else() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let parent = server.person("mama", false).await;
    let stranger = server.person("nachbar", false).await;
    let parent_id = parent.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let stranger_id = stranger.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();

    // Nobody looks after anybody yet; then an admin makes them the manager of an empty group.
    assert_eq!(parent.get("/uwu/v1/people").await.status(), StatusCode::FORBIDDEN);
    let kids = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Kinder" })).await;
    admin
        .ok("PUT", &format!("/uwu/v1/people/{parent_id}/manages"), json!({ "people": [], "groups": [kids["id"]] }))
        .await;
    assert_eq!(parent.json("/uwu/v1/people").await, json!([]));

    let kid = parent
        .ok("POST", "/uwu/v1/people", json!({ "username": "mia", "displayName": "Mia", "setupLink": true }))
        .await;
    let kid_id = kid["id"].as_str().unwrap().to_string();
    assert_eq!(kid["link"]["purpose"], "setup");
    let people = parent.json("/uwu/v1/people").await;
    let ids: Vec<&str> = people.as_array().unwrap().iter().map(|person| person["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&kid_id.as_str()));
    assert!(!ids.contains(&stranger_id.as_str()), "only the people they look after");
    let detail = parent.json(&format!("/uwu/v1/people/{kid_id}")).await;
    assert_eq!(detail["managed"], true);
    assert_eq!(detail["canEdit"], "managed");
    assert_eq!(parent.get(&format!("/uwu/v1/people/{stranger_id}")).await.status(), StatusCode::NOT_FOUND);
    let not_theirs =
        parent.request("PATCH", &format!("/uwu/v1/people/{kid_id}"), Some(json!({ "username": "other" }))).await;
    assert_eq!(not_theirs.status(), StatusCode::FORBIDDEN, "user names are the admins' to change");
    parent.ok("PATCH", &format!("/uwu/v1/people/{kid_id}"), json!({ "displayName": "Mia Maus" })).await;
    let delete = parent.request("DELETE", &format!("/uwu/v1/people/{kid_id}"), None).await;
    assert_eq!(delete.status(), StatusCode::FORBIDDEN);

    // The kid's tablet: the setup link, a passkey.
    let token = token_of(kid["link"]["link"].as_str().unwrap());
    let tablet = server.browser();
    let options = tablet.ok("POST", &format!("/uwu/v1/links/setup/{token}/passkey-options"), json!({})).await;
    assert_eq!(options["user"]["name"], "mia");
    let key = crate::webauthn::tests::SoftKey::new();
    tablet
        .ok(
            "POST",
            &format!("/uwu/v1/links/setup/{token}"),
            json!({ "passkey": { "credential": key.create(&options, PUBLIC) } }),
        )
        .await;
    assert_eq!(tablet.json("/uwu/v1/me").await["username"], "mia");

    // School days, 7 to 20; and the kid's events for the parent.
    parent
        .ok("PUT", &format!("/uwu/v1/people/{kid_id}/windows"), json!([{ "days": 31, "start": 420, "end": 1200 }]))
        .await;
    assert_eq!(parent.json(&format!("/uwu/v1/people/{kid_id}")).await["windows"][0]["end"], 1200);
    let events = parent.json(&format!("/uwu/v1/people/{kid_id}/events")).await;
    assert!(events.as_array().unwrap().iter().any(|event| event["kind"] == "account_set_up"));
    parent.ok("POST", &format!("/uwu/v1/people/{kid_id}/disable"), json!({})).await;
    assert_eq!(tablet.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED, "disabled means signed out");
}

#[tokio::test]
async fn the_last_admin_stays() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let admin_id = admin.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let refused =
        admin.request("PUT", &format!("/uwu/v1/people/{admin_id}/groups"), Some(json!({ "groups": [] }))).await;
    assert_eq!(json(refused).await["error"], "last_admin");
    let refused = admin
        .request("PUT", &format!("/uwu/v1/groups/{}/members", uwuauth_store::ADMINS_ID), Some(json!({ "people": [] })))
        .await;
    assert_eq!(json(refused).await["error"], "last_admin");
    let second = server.person("second", true).await;
    let second_id = second.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    admin.ok("POST", &format!("/uwu/v1/people/{second_id}/disable"), json!({})).await;
    let refused =
        admin.request("PUT", &format!("/uwu/v1/people/{admin_id}/groups"), Some(json!({ "groups": [] }))).await;
    assert_eq!(json(refused).await["error"], "last_admin", "a disabled admin does not count");
}

#[tokio::test]
async fn only_admins_manage_and_nobody_else_sees_the_portal() {
    let server = TestServer::new().await;
    let _admin = server.person("admin", true).await;
    let member = server.person("member", false).await;
    for path in ["/uwu/v1/settings", "/uwu/v1/overview", "/uwu/v1/events", "/uwu/v1/invitations", "/uwu/v1/tokens"] {
        assert_eq!(member.get(path).await.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(server.get(path).await.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let refused = member.request("POST", "/uwu/v1/groups", Some(json!({ "name": "mine" }))).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(member.get("/uwu/v1/groups").await.status(), StatusCode::OK, "the list is for everybody");
}

#[tokio::test]
async fn a_request_from_another_site_changes_nothing() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let cookie = admin.cookie(crate::session::SESSION_COOKIE).unwrap();
    let request = axum::http::Request::post("/uwu/v1/groups")
        .header("cookie", format!("{}={cookie}", crate::session::SESSION_COOKIE))
        .header("origin", "https://evil.example.net")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(json!({ "name": "evil" }).to_string()))
        .unwrap();
    assert_eq!(server.send(request).await.status(), StatusCode::FORBIDDEN);
    let request = axum::http::Request::post("/uwu/v1/groups")
        .header("cookie", format!("{}={cookie}", crate::session::SESSION_COOKIE))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(json!({ "name": "evil" }).to_string()))
        .unwrap();
    assert_eq!(server.send(request).await.status(), StatusCode::FORBIDDEN, "no origin, no fetch metadata");
}

#[tokio::test]
async fn groups_inside_groups_and_their_owners() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let owner = server.person("owner", false).await;
    let owner_id = owner.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let kids = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Kinder" })).await;
    let family = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Familie" })).await;
    let (kids, family) = (kids["id"].as_str().unwrap().to_string(), family["id"].as_str().unwrap().to_string());
    admin
        .ok(
            "PUT",
            &format!("/uwu/v1/groups/{family}/members"),
            json!({ "people": [], "groups": [kids], "owners": [owner_id] }),
        )
        .await;
    let circle =
        admin.request("PUT", &format!("/uwu/v1/groups/{kids}/members"), Some(json!({ "groups": [family] }))).await;
    assert_eq!(json(circle).await["error"], "loop");
    // The owner may change members, not owners.
    owner
        .ok("PUT", &format!("/uwu/v1/groups/{family}/members"), json!({ "people": [owner_id], "groups": [kids] }))
        .await;
    let refused = owner
        .request("PUT", &format!("/uwu/v1/groups/{family}/members"), Some(json!({ "people": [], "owners": [] })))
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let me = owner.json("/uwu/v1/me").await;
    assert!(me["memberOf"].as_array().unwrap().iter().any(|group| group["name"] == "Familie"));
}

#[tokio::test]
async fn a_leaked_password_is_refused_when_the_check_is_on() {
    let (url, asked) = crate::hibp::tests::fake_hibp().await;
    let server = TestServer::with(|config| {
        config.hibp_url = url;
        config.start_settings.hibp = true;
        config.start_settings.password_min_length = 8;
    })
    .await;
    let token = server.invitation(InviteFields::default()).await;
    let refused = server
        .browser()
        .post(&format!("/uwu/v1/links/invite/{token}"), json!({ "username": "nyu", "password": "password" }))
        .await;
    let body = json(refused).await;
    assert_eq!((body["error"].as_str(), body["detail"]["count"].as_u64()), (Some("pwned"), Some(3)));
    server
        .browser()
        .ok("POST", &format!("/uwu/v1/links/invite/{token}"), json!({ "username": "nyu", "password": PASSWORD }))
        .await;
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_directory_goes_out_and_comes_back_in() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    admin.ok("PUT", "/uwu/v1/attributes", json!([{ "name": "room", "label": "Zimmer", "kind": "text" }])).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Familie" })).await;
    let mia = admin
        .ok(
            "POST",
            "/uwu/v1/people",
            json!({ "username": "mia", "displayName": "Mia", "email": "mia@example.com", "groups": [group["id"]] }),
        )
        .await;
    admin
        .ok(
            "PATCH",
            &format!("/uwu/v1/people/{}", mia["id"].as_str().unwrap()),
            json!({ "attributes": { "room": "12" } }),
        )
        .await;
    let export = admin.json("/uwu/v1/export").await;
    assert!(
        export["people"]
            .as_array()
            .unwrap()
            .iter()
            .any(|person| person["username"] == "mia" && person["attributes"]["room"] == "12")
    );
    assert!(
        export["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["name"] == "Familie" && group["members"] == json!(["mia"]))
    );
    let csv = admin.get("/uwu/v1/export?format=csv").await;
    assert!(text(csv).await.contains("mia,Mia,,,mia@example.com,de,Familie"));

    let other = TestServer::new().await;
    let other_admin = other.person("admin", true).await;
    other_admin.ok("PUT", "/uwu/v1/attributes", json!([{ "name": "room", "label": "Zimmer", "kind": "text" }])).await;
    let dry = other_admin.ok("POST", "/uwu/v1/import?dryRun=true", export.clone()).await;
    assert_eq!(dry["people"]["created"], json!(["mia"]));
    assert_eq!(dry["people"]["skipped"], json!(["admin"]));
    assert_eq!(other_admin.json("/uwu/v1/people").await.as_array().unwrap().len(), 1, "a dry run changes nothing");
    other_admin.ok("POST", "/uwu/v1/import", export).await;
    let people = other_admin.json("/uwu/v1/people").await;
    let mia = people.as_array().unwrap().iter().find(|person| person["username"] == "mia").unwrap();
    assert_eq!(mia["hasPassword"], false);
    let groups = other_admin.json("/uwu/v1/groups").await;
    assert!(groups.as_array().unwrap().iter().any(|group| group["name"] == "Familie" && group["members"] == 1));
}

#[tokio::test]
async fn a_read_only_token_only_reads() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let token = admin.ok("POST", "/uwu/v1/tokens", json!({ "name": "backup script", "readOnly": true })).await;
    let secret = token["secret"].as_str().unwrap();
    assert!(secret.starts_with("uwu_"));
    let read = axum::http::Request::get("/uwu/v1/overview")
        .header("authorization", format!("Bearer {secret}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.send(read).await.status(), StatusCode::OK);
    let write = axum::http::Request::post("/uwu/v1/backups")
        .header("authorization", format!("Bearer {secret}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.send(write).await.status(), StatusCode::FORBIDDEN);
    let wrong = axum::http::Request::get("/uwu/v1/overview")
        .header("authorization", "Bearer uwu_nope")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.send(wrong).await.status(), StatusCode::UNAUTHORIZED);
    assert!(admin.json("/uwu/v1/tokens").await[0].get("secret").is_none(), "shown once");
}

#[tokio::test]
async fn app_passwords_are_shown_once() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    let made = browser.ok("POST", "/uwu/v1/me/app-passwords", json!({ "name": "NAS" })).await;
    assert_eq!(made["secret"].as_str().unwrap().len(), 29);
    let me = browser.json("/uwu/v1/me").await;
    assert_eq!(me["appPasswords"][0]["name"], "NAS");
    assert!(me["appPasswords"][0].get("secret").is_none());
}

#[tokio::test]
async fn a_new_address_counts_once_confirmed() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    browser.ok("POST", "/uwu/v1/me/email", json!({ "email": "neu@example.com" })).await;
    assert_eq!(browser.json("/uwu/v1/me").await["email"], Value::Null);
    let token = token_of(server.mail_to("neu@example.com").unwrap().link().unwrap());
    server.browser().ok("POST", &format!("/uwu/v1/links/verify/{token}"), json!({})).await;
    let me = browser.json("/uwu/v1/me").await;
    assert_eq!((me["email"].as_str(), me["emailVerified"].as_bool()), (Some("neu@example.com"), Some(true)));
}

#[tokio::test]
async fn signing_out_ends_the_session() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    let cookie = browser.cookie(crate::session::SESSION_COOKIE).unwrap();
    let response = browser.post("/uwu/v1/logout", json!({})).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(browser.cookie(crate::session::SESSION_COOKIE).is_none());
    let replay = axum::http::Request::get("/uwu/v1/me")
        .header("cookie", format!("uwuauth_session={cookie}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.send(replay).await.status(), StatusCode::UNAUTHORIZED, "the old cookie is worth nothing");
    browser.forget_cookies();
}

// ── What the security review found, fixed ─────────────────

/// Make the session in `browser` look like its sign-in was long ago.
async fn age(server: &TestServer, browser: &Browser<'_>) {
    let id = browser.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    for mut session in server.state.store.sessions_of(&id).await.unwrap() {
        server.state.store.end_session(&session.id).await.unwrap();
        session.auth_time = clock::in_seconds(-3600);
        server.state.store.create_session(session).await.unwrap();
    }
}

#[tokio::test]
async fn a_reset_link_still_asks_for_the_second_factor() {
    let server = TestServer::new().await;
    let token = server
        .invitation(InviteFields {
            email: Some("nyu@example.com".into()),
            mail: true,
            admin: true,
            ..InviteFields::default()
        })
        .await;
    let owner = server.browser();
    owner
        .ok("POST", &format!("/uwu/v1/links/invite/{token}"), json!({ "username": "nyu", "password": PASSWORD }))
        .await;
    let setup = owner.ok("POST", "/uwu/v1/me/totp/start", json!({})).await;
    owner.ok("POST", "/uwu/v1/me/totp", json!({ "code": code(setup["secret"].as_str().unwrap(), 0) })).await;

    let thief = server.browser();
    thief.post("/uwu/v1/forgot", json!({ "login": "nyu@example.com" })).await;
    let reset = token_of(server.mail_to("nyu@example.com").unwrap().link().unwrap());
    let options = thief.request("POST", &format!("/uwu/v1/links/reset/{reset}/passkey-options"), Some(json!({}))).await;
    if options.status() == StatusCode::OK {
        let key = crate::webauthn::tests::SoftKey::new();
        let refused = thief
            .post(
                &format!("/uwu/v1/links/reset/{reset}"),
                json!({ "passkey": { "credential": key.create(&json(options).await, PUBLIC) } }),
            )
            .await;
        assert_eq!(json(refused).await["error"], "second_factor_kept");
    }
    let answer = thief
        .ok("POST", &format!("/uwu/v1/links/reset/{reset}"), json!({ "password": "a new password of mine" }))
        .await;
    assert_eq!(answer["status"], "second_factor", "a new password alone is no way in");
    assert_eq!(thief.get("/uwu/v1/me").await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_manager_reaches_managed_accounts_only_and_an_owner_only_people() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let parent = server.person("mama", false).await;
    let parent_id = parent.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let admin_id = admin.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let kids =
        admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Kinder" })).await["id"].as_str().unwrap().to_string();
    admin
        .ok(
            "PUT",
            &format!("/uwu/v1/groups/{kids}/members"),
            json!({ "people": [admin_id], "groups": [], "owners": [parent_id] }),
        )
        .await;
    admin.ok("PUT", &format!("/uwu/v1/people/{parent_id}/manages"), json!({ "people": [], "groups": [kids] })).await;
    // The admin is in Kinder, but no account the parent looks after.
    assert_eq!(parent.json("/uwu/v1/people").await, json!([]));
    assert_eq!(
        parent.request("POST", &format!("/uwu/v1/people/{admin_id}/disable"), Some(json!({}))).await.status(),
        StatusCode::NOT_FOUND
    );
    // An owner changes people, not the groups inside: `admins` does not go into Kinder.
    parent
        .ok(
            "PUT",
            &format!("/uwu/v1/groups/{kids}/members"),
            json!({ "people": [], "groups": [uwuauth_store::ADMINS_ID] }),
        )
        .await;
    assert!(admin.json(&format!("/uwu/v1/groups/{kids}")).await["groups"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_group_inside_admins_is_the_admins_to_change() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let owner = server.person("owner", false).await;
    let owner_id = owner.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let admin_id = admin.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let parents =
        admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Eltern" })).await["id"].as_str().unwrap().to_string();
    admin
        .ok(
            "PUT",
            &format!("/uwu/v1/groups/{parents}/members"),
            json!({ "people": [], "groups": [], "owners": [owner_id.clone()] }),
        )
        .await;
    admin
        .ok(
            "PUT",
            &format!("/uwu/v1/groups/{}/members", uwuauth_store::ADMINS_ID),
            json!({ "people": [admin_id], "groups": [parents] }),
        )
        .await;
    let refused =
        owner.request("PUT", &format!("/uwu/v1/groups/{parents}/members"), Some(json!({ "people": [owner_id] }))).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "no way to make oneself an admin");
}

#[tokio::test]
async fn powerful_admin_actions_want_a_recent_sign_in() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let other = server.person("other", true).await;
    let other_id = other.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    age(&server, &admin).await;
    let link = admin.request("POST", &format!("/uwu/v1/people/{other_id}/link"), Some(json!({}))).await;
    assert_eq!(json(link).await["error"], "reauth");
    let invite = admin.request("POST", "/uwu/v1/invitations", Some(json!({ "admin": true }))).await;
    assert_eq!(json(invite).await["error"], "reauth");
    let groups =
        admin.request("PUT", &format!("/uwu/v1/people/{other_id}/groups"), Some(json!({ "groups": [] }))).await;
    assert_eq!(json(groups).await["error"], "reauth");
}

#[tokio::test]
async fn somebody_with_a_passkey_confirms_with_it() {
    let server = TestServer::new().await;
    let browser = server.person("nyu", false).await;
    browser.add_passkey().await;
    let refused = browser.request("POST", "/uwu/v1/reauth", Some(json!({ "password": PASSWORD }))).await;
    assert_eq!(json(refused).await["error"], "use_passkey");
}

#[tokio::test]
async fn a_token_ends_with_its_maker_s_admin_right() {
    let server = TestServer::new().await;
    let first = server.person("first", true).await;
    let second = server.person("second", true).await;
    let secret =
        second.ok("POST", "/uwu/v1/tokens", json!({ "name": "script" })).await["secret"].as_str().unwrap().to_string();
    let second_id = second.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let ask = || {
        axum::http::Request::get("/uwu/v1/overview")
            .header("authorization", format!("Bearer {secret}"))
            .body(axum::body::Body::empty())
            .unwrap()
    };
    assert_eq!(server.send(ask()).await.status(), StatusCode::OK);
    first.ok("PUT", &format!("/uwu/v1/people/{second_id}/groups"), json!({ "groups": [] })).await;
    assert_eq!(server.send(ask()).await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_import_makes_nobody_an_admin() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let export = json!({ "people": [{ "username": "mallory", "displayName": "M", "groups": ["admins"] }], "groups": [{ "name": "admins", "members": ["mallory"] }] });
    admin.ok("POST", "/uwu/v1/import", export).await;
    let people = admin.json("/uwu/v1/people").await;
    let mallory = people.as_array().unwrap().iter().find(|person| person["username"] == "mallory").unwrap();
    assert_eq!(mallory["admin"], false);
}
