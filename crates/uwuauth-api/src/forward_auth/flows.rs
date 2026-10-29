//! Forward auth end to end: a proxy asking, a browser signing in and coming back.

use super::COOKIE;
use crate::test_support::{Browser, PUBLIC, TestServer, text};
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use serde_json::{Value, json};

/// A server whose forward-auth cookie goes to every host below example.com.
async fn server() -> TestServer {
    TestServer::with(|config| config.start_settings.cookie_domain = "example.com".into()).await
}

async fn forward_app(admin: &Browser<'_>, body: Value) -> Value {
    let mut body = body;
    body["template"] = json!("forward-auth");
    admin.ok("POST", "/uwu/v1/apps", body).await
}

/// What the proxy asks: the request it guards, with the browser's forward-auth cookie.
async fn ask(server: &TestServer, cookie: Option<&str>, method: &str, host: &str, uri: &str) -> Response<Body> {
    let mut request = Request::get("/uwu/v1/forward-auth")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", host)
        .header("x-forwarded-uri", uri)
        .header("x-forwarded-method", method);
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("{COOKIE}={cookie}"));
    }
    server.send(request.body(Body::empty()).unwrap()).await
}

/// The proxy asks with exactly these headers.
async fn ask_with(server: &TestServer, path: &str, headers: &[(&str, &str)]) -> Response<Body> {
    let mut request = Request::get(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    server.send(request.body(Body::empty()).unwrap()).await
}

/// The same the way nginx asks.
async fn ask_nginx(server: &TestServer, cookie: Option<&str>, url: &str) -> Response<Body> {
    let mut request = Request::get("/uwu/v1/forward-auth/nginx").header("x-original-url", url);
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("{COOKIE}={cookie}"));
    }
    server.send(request.body(Body::empty()).unwrap()).await
}

fn location(response: &Response<Body>) -> String {
    response.headers().get(header::LOCATION).map(|value| value.to_str().unwrap().to_string()).unwrap_or_default()
}

fn remote<'a>(response: &'a Response<Body>, name: &str) -> &'a str {
    response.headers().get(name).map_or("", |value| value.to_str().unwrap())
}

fn rd(url: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new()).append_pair("rd", url).finish()
}

/// The browser comes back from signing in: the forward-auth cookie, and where it goes.
async fn come_back(browser: &Browser<'_>, url: &str) -> (Response<Body>, String) {
    let response = browser.get(&format!("/oauth/forward-auth?{}", rd(url))).await;
    let cookie = browser.cookie(COOKIE).unwrap_or_default();
    (response, cookie)
}

async fn events(admin: &Browser<'_>, kind: &str) -> Vec<Value> {
    admin.json(&format!("/uwu/v1/events?kind={kind}")).await.as_array().unwrap().clone()
}

#[tokio::test]
async fn forward_auth_signs_in_once_and_tells_the_app_who_it_is() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Wiki-Leute" })).await;
    let group_id = group["id"].as_str().unwrap();
    let admin_id = admin.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    admin.ok("PUT", &format!("/uwu/v1/groups/{group_id}/members"), json!({ "people": [admin_id] })).await;
    let app = forward_app(&admin, json!({ "name": "Wiki", "forwardAuth": ["https://Wiki.Example.com/"] })).await;
    assert_eq!(app["forwardAuth"], json!(["wiki.example.com"]));
    assert_eq!(app["grantTypes"], json!([]));
    assert_eq!(app["clientSecret"], Value::Null);
    assert_eq!(app["launchUrl"], "https://wiki.example.com");

    // Not signed in: off to UwUAuth, which knows where to send the browser back.
    let page = "https://wiki.example.com/page?x=1";
    let answer = ask(&server, None, "GET", "wiki.example.com", "/page?x=1").await;
    assert_eq!(answer.status(), StatusCode::FOUND);
    assert_eq!(location(&answer), format!("{PUBLIC}/oauth/forward-auth?{}", rd(page)));
    let answer = ask(&server, None, "POST", "wiki.example.com", "/page?x=1").await;
    assert_eq!(answer.status(), StatusCode::SEE_OTHER);

    // A browser that is not signed in at UwUAuth either goes to the sign-in page first.
    let stranger = server.browser();
    let (answer, cookie) = come_back(&stranger, page).await;
    assert!(location(&answer).starts_with(&format!("{PUBLIC}/#/login?continue=%2Foauth%2Fforward-auth%3Frd%3D")));
    assert!(cookie.is_empty());

    // Signed in: the cookie for the whole domain, and back to the page.
    let response = admin.get(&format!("/oauth/forward-auth?{}", rd(page))).await;
    assert_eq!(location(&response), page);
    let set = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let set = set.iter().find(|value| value.starts_with(&format!("{COOKIE}="))).expect("the forward-auth cookie");
    for part in ["Domain=example.com", "HttpOnly", "SameSite=Lax", "Secure", "Path=/"] {
        assert!(set.contains(part), "{set}");
    }
    let cookie = admin.cookie(COOKIE).unwrap();

    let answer = ask(&server, Some(&cookie), "GET", "wiki.example.com", "/page").await;
    assert_eq!(answer.status(), StatusCode::OK);
    assert_eq!(remote(&answer, "remote-user"), "admin");
    let groups: Vec<&str> = remote(&answer, "remote-groups").split(',').collect();
    assert!(groups.contains(&"Wiki-Leute"), "{groups:?}");
    assert!(groups.is_sorted(), "{groups:?}");
    assert_eq!(remote(&answer, "remote-name"), "admin");
    assert!(answer.headers().contains_key("remote-email"));

    // Nginx asks with X-Original-URL, and also a POST with a cookie from elsewhere gets through.
    let answer = ask_nginx(&server, Some(&cookie), "https://wiki.example.com/x").await;
    assert_eq!(answer.status(), StatusCode::OK);

    // The first time is noted: "My apps" lists it, and there is an event.
    let mine = admin.json("/uwu/v1/me/apps").await;
    assert!(mine["apps"].as_array().unwrap().iter().any(|app| app["launchUrl"] == "https://wiki.example.com"));
    let logins = events(&admin, "app_login").await;
    assert_eq!(logins.len(), 1, "once, not for every request: {logins:?}");

    // A made-up cookie, or the session cookie's value in its place, opens nothing.
    let session = admin.cookie("uwuauth_session").unwrap();
    for fake in [session.as_str(), "AAAA.BBBB", "garbage"] {
        assert_eq!(ask(&server, Some(fake), "GET", "wiki.example.com", "/").await.status(), StatusCode::FOUND);
    }
}

#[tokio::test]
async fn forward_auth_for_nginx_says_401_with_where_to_go() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    forward_app(&admin, json!({ "name": "Wiki", "forwardAuth": ["wiki.example.com"] })).await;
    let answer = ask_nginx(&server, None, "https://wiki.example.com/a?b=c").await;
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(location(&answer), format!("{PUBLIC}/oauth/forward-auth?{}", rd("https://wiki.example.com/a?b=c")));
}

#[tokio::test]
async fn forward_auth_refuses_hosts_it_does_not_know_and_people_not_in_the_groups() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    let kid = server.person("kid", false).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Grown-ups" })).await;
    let group_id = group["id"].as_str().unwrap();
    forward_app(&admin, json!({ "name": "Media", "forwardAuth": ["media.example.com"], "allowedGroups": [group_id] }))
        .await;

    let unknown = ask(&server, None, "GET", "other.example.com", "/").await;
    assert_eq!(unknown.status(), StatusCode::FORBIDDEN);
    // Made-up hosts and paths, without signing in: answered, but not one event each.
    for at in 0..30 {
        let host = format!("{}{at}.example.com", "x".repeat(500));
        assert_eq!(ask(&server, None, "GET", &host, "/").await.status(), StatusCode::FORBIDDEN);
        let path = format!("/a/..%2f{at}");
        assert_eq!(ask(&server, None, "GET", "media.example.com", &path).await.status(), StatusCode::FORBIDDEN);
    }

    let (_, cookie) = come_back(&kid, "https://media.example.com/").await;
    assert!(!cookie.is_empty());
    for _ in 0..3 {
        let answer = ask(&server, Some(&cookie), "GET", "media.example.com", "/movie").await;
        assert_eq!(answer.status(), StatusCode::FORBIDDEN);
        assert!(!answer.headers().contains_key("remote-user"));
        assert!(text(answer).await.contains("reason=groups"));
    }
    let denied = events(&admin, "forward_auth_denied").await;
    let reasons: Vec<&str> = denied.iter().filter_map(|event| event["detail"]["reason"].as_str()).collect();
    assert_eq!(reasons.iter().filter(|reason| **reason == "unknown_host").count(), 1, "by address: {denied:?}");
    assert_eq!(reasons.iter().filter(|reason| **reason == "path").count(), 1, "by address: {denied:?}");
    assert!(denied.iter().all(|event| event["detail"]["host"].as_str().unwrap().len() <= 100), "{denied:?}");
    assert_eq!(reasons.iter().filter(|reason| **reason == "groups").count(), 1, "once for many: {denied:?}");
}

#[tokio::test]
async fn forward_auth_the_closest_address_decides() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    let kid = server.person("kid", false).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Grown-ups" })).await;
    let group_id = group["id"].as_str().unwrap();
    forward_app(&admin, json!({ "name": "Site", "forwardAuth": ["example.com"] })).await;
    forward_app(&admin, json!({ "name": "Admin", "forwardAuth": ["example.com/admin"], "allowedGroups": [group_id] }))
        .await;
    let taken = admin
        .request(
            "POST",
            "/uwu/v1/apps",
            Some(json!({ "name": "Again", "template": "forward-auth", "forwardAuth": ["EXAMPLE.com/admin/"] })),
        )
        .await;
    assert_eq!(taken.status(), StatusCode::BAD_REQUEST, "an address belongs to one app");

    let (_, cookie) = come_back(&kid, "https://example.com/").await;
    assert_eq!(ask(&server, Some(&cookie), "GET", "example.com", "/").await.status(), StatusCode::OK);
    assert_eq!(ask(&server, Some(&cookie), "GET", "example.com", "/administrator").await.status(), StatusCode::OK);
    for sneaky in [
        "/admin",
        "/admin/",
        "//admin",
        "/admin;x/",
        // Into the stricter rule …
        "/Public/../admin/x",
        "/public/%2e%2e/admin",
        "/public/..%2fadmin",
        "/public%2fadmin",
        // … and, the other way round, out of it: an app may well read these as /admin/….
        "/admin/../public",
        "/admin/..%2fpublic",
        "/admin/..%2Fpublic",
        "/admin/..\\public",
        "/admin/..%5cpublic",
        "/admin/%2e%2e/public",
        "/admin/%252e%252e/public",
        "/admin;/../public",
    ] {
        let answer = ask(&server, Some(&cookie), "GET", "example.com", sneaky).await;
        assert_eq!(answer.status(), StatusCode::FORBIDDEN, "{sneaky}");
    }
}

#[tokio::test]
async fn forward_auth_reads_only_the_headers_of_its_own_endpoint() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    let kid = server.person("kid", false).await;
    let group = admin.ok("POST", "/uwu/v1/groups", json!({ "name": "Grown-ups" })).await;
    let group_id = group["id"].as_str().unwrap();
    forward_app(&admin, json!({ "name": "Open", "forwardAuth": ["open.example.com"] })).await;
    forward_app(&admin, json!({ "name": "Media", "forwardAuth": ["media.example.com"], "allowedGroups": [group_id] }))
        .await;
    let (_, cookie) = come_back(&kid, "https://open.example.com/").await;
    let cookie = format!("{COOKIE}={cookie}");

    // Caddy and Traefik pass the browser's own headers on: X-Original-URL is the browser's here.
    let spoofed = [
        ("cookie", cookie.as_str()),
        ("x-forwarded-proto", "https"),
        ("x-forwarded-host", "media.example.com"),
        ("x-forwarded-uri", "/movie"),
        ("x-forwarded-method", "GET"),
        ("x-original-url", "https://open.example.com/"),
    ];
    let answer = ask_with(&server, "/uwu/v1/forward-auth", &spoofed).await;
    assert_eq!(answer.status(), StatusCode::FORBIDDEN);
    assert!(text(answer).await.contains("reason=groups"));
    // A forwarded host added by the browser goes in front; the proxy's own is the last.
    let chained = [
        ("cookie", cookie.as_str()),
        ("x-forwarded-host", "open.example.com, media.example.com"),
        ("x-forwarded-uri", "/movie"),
    ];
    assert_eq!(ask_with(&server, "/uwu/v1/forward-auth", &chained).await.status(), StatusCode::FORBIDDEN);

    // nginx's endpoint needs nginx's header, and reads no other.
    let without = [("cookie", cookie.as_str()), ("x-forwarded-host", "open.example.com"), ("x-forwarded-uri", "/")];
    assert_eq!(ask_with(&server, "/uwu/v1/forward-auth/nginx", &without).await.status(), StatusCode::FORBIDDEN);
    let nginx = [("cookie", cookie.as_str()), ("x-original-url", "https://open.example.com/")];
    assert_eq!(ask_with(&server, "/uwu/v1/forward-auth/nginx", &nginx).await.status(), StatusCode::OK);

    // Two forward-auth cookies: one was set by another host below the cookie domain.
    let tossed = format!("{cookie}; {COOKIE}=planted");
    let twice = [("cookie", tossed.as_str()), ("x-forwarded-host", "open.example.com"), ("x-forwarded-uri", "/")];
    assert_eq!(ask_with(&server, "/uwu/v1/forward-auth", &twice).await.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn forward_auth_with_a_second_factor_sends_password_only_sessions_to_confirm() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    forward_app(&admin, json!({ "name": "Tresor", "forwardAuth": ["vault.example.com"], "requireMfa": true })).await;
    let (_, cookie) = come_back(&admin, "https://vault.example.com/").await;
    let answer = ask(&server, Some(&cookie), "GET", "vault.example.com", "/").await;
    assert_eq!(answer.status(), StatusCode::FOUND);
    let to = location(&answer);
    assert!(
        to.starts_with(&format!("{PUBLIC}/#/denied?reason=mfa&app=Tresor&continue=%2Foauth%2Fforward-auth")),
        "{to}"
    );

    let mut key = admin.add_passkey().await;
    let options = admin.ok("POST", "/uwu/v1/reauth/options", json!({})).await;
    let assertion = key.get(&options, PUBLIC, None);
    admin.ok("POST", "/uwu/v1/reauth", json!({ "passkey": assertion })).await;
    // The way back asks again at once, even though the answer was kept for a moment.
    let (_, cookie) = come_back(&admin, "https://vault.example.com/").await;
    assert_eq!(ask(&server, Some(&cookie), "GET", "vault.example.com", "/").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn forward_auth_only_goes_back_to_its_own_apps() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    forward_app(&admin, json!({ "name": "Wiki", "forwardAuth": ["wiki.example.com"] })).await;
    forward_app(&admin, json!({ "name": "Far", "forwardAuth": ["far.example.net"] })).await;
    for (bad, status) in [
        ("https://evil.example.org/", StatusCode::BAD_REQUEST),
        ("https://wiki.example.com.invalid/", StatusCode::BAD_REQUEST),
        ("http://wiki.example.com/", StatusCode::BAD_REQUEST),
        ("https://far.example.net/", StatusCode::BAD_REQUEST),
        ("https://user@wiki.example.com/", StatusCode::SEE_OTHER),
        ("javascript:alert(1)", StatusCode::SEE_OTHER),
        ("//wiki.example.com/", StatusCode::SEE_OTHER),
        ("/#/admin", StatusCode::SEE_OTHER),
    ] {
        let (answer, _) = come_back(&admin, bad).await;
        assert_eq!(answer.status(), status, "{bad}");
        let to = location(&answer);
        assert!(to.is_empty() || to == format!("{PUBLIC}/#/"), "{bad} → {to}");
    }
    assert!(admin.cookie(COOKIE).is_none(), "no cookie for a way back that is refused");
    for refused in ["https://wiki.example.com/x/../y", "https://wiki.example.com/x%2fy"] {
        let (answer, _) = come_back(&admin, refused).await;
        assert_eq!(location(&answer), format!("{PUBLIC}/#/"), "{refused}");
    }
    // Back to the address as UwUAuth read it, not as it was written.
    let (answer, _) = come_back(&admin, "https://WIKI.example.com/a b?q=<x>").await;
    assert_eq!(location(&answer), "https://wiki.example.com/a%20b?q=%3Cx%3E");
}

#[tokio::test]
async fn forward_auth_ends_with_signing_out() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    forward_app(&admin, json!({ "name": "Wiki", "forwardAuth": ["wiki.example.com"] })).await;
    let (_, cookie) = come_back(&admin, "https://wiki.example.com/").await;
    assert_eq!(ask(&server, Some(&cookie), "GET", "wiki.example.com", "/").await.status(), StatusCode::OK);
    let response = admin.post("/uwu/v1/logout", json!({})).await;
    let cleared = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .find(|value| value.starts_with(&format!("{COOKIE}=;")))
        .expect("the forward-auth cookie goes too");
    assert!(cleared.contains("Max-Age=0") && cleared.contains("Domain=example.com"), "{cleared}");
    // At once, not only when the kept answer runs out.
    assert_eq!(ask(&server, Some(&cookie), "GET", "wiki.example.com", "/").await.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn forward_auth_ends_when_an_admin_ends_the_sessions() {
    let server = server().await;
    let admin = server.person("admin", true).await;
    let anna = server.person("anna", false).await;
    forward_app(&admin, json!({ "name": "Wiki", "forwardAuth": ["wiki.example.com"] })).await;
    let (_, cookie) = come_back(&anna, "https://wiki.example.com/").await;
    assert_eq!(ask(&server, Some(&cookie), "GET", "wiki.example.com", "/").await.status(), StatusCode::OK);
    let id = anna.json("/uwu/v1/me").await["id"].as_str().unwrap().to_string();
    let response = admin.request("DELETE", &format!("/uwu/v1/people/{id}/sessions"), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    // The cookie is still in Anna's browser, but the kept answer is not trusted any more.
    assert_eq!(ask(&server, Some(&cookie), "GET", "wiki.example.com", "/").await.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn forward_auth_cookie_domain_is_checked_and_stays_off_the_admin_api() {
    let server = TestServer::new().await;
    let admin = server.person("admin", true).await;
    let settings = admin.json("/uwu/v1/settings").await;
    assert_eq!(settings["cookieDomain"], "");
    let mut change = settings.clone();
    change["cookieDomain"] = json!("example.net");
    let response = admin.request("PUT", "/uwu/v1/settings", Some(change.clone())).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "auth.example.com is not in example.net");
    change["cookieDomain"] = json!("com");
    assert_eq!(admin.request("PUT", "/uwu/v1/settings", Some(change.clone())).await.status(), StatusCode::BAD_REQUEST);
    change["cookieDomain"] = json!(".Example.com");
    assert_eq!(admin.ok("PUT", "/uwu/v1/settings", change).await["cookieDomain"], "example.com");

    // Without a domain the cookie only went to this host; the forward-auth cookie never opens
    // the API, and pages on other hosts below the domain are not this server's pages.
    forward_app(&admin, json!({ "name": "Wiki", "forwardAuth": ["wiki.example.com"] })).await;
    let (_, cookie) = come_back(&admin, "https://wiki.example.com/").await;
    let request =
        Request::get("/uwu/v1/me").header("cookie", format!("{COOKIE}={cookie}")).body(Body::empty()).unwrap();
    assert_eq!(server.send(request).await.status(), StatusCode::UNAUTHORIZED);
    let session = admin.cookie("uwuauth_session").unwrap();
    let request = Request::post("/uwu/v1/groups")
        .header("cookie", format!("uwuauth_session={session}"))
        .header("origin", "https://wiki.example.com")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "name": "Sneaky" }).to_string()))
        .unwrap();
    assert_eq!(server.send(request).await.status(), StatusCode::FORBIDDEN);
}
