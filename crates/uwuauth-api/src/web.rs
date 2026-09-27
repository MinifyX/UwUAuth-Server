//! The web app: sign-in pages, the self-service portal and the admin portal — one app, built into
//! the binary, at `/` and `/admin`.
//!
//! Its files come compressed already (brotli or gzip, whichever the browser takes), those with
//! a content hash in their name are cached for good, and the page itself says where scripts may
//! come from: only here. Nobody may frame it — a sign-in page in somebody else's frame is how
//! clickjacking starts.

use crate::AppState;
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use uwuauth_web::Asset;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; \
     object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/", get(app)).route("/admin", get(app)).route("/admin/", get(app))
}

async fn app(headers: HeaderMap) -> Response {
    match uwuauth_web::find("/index.html") {
        Some(index) => respond(index, &headers),
        None => Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>UwUAuth Server</title>\
             <p style=\"font-family:sans-serif\">UwUAuth Server {} is running. This build has no web app.</p>",
            env!("CARGO_PKG_VERSION")
        ))
        .into_response(),
    }
}

/// Where the API and the protocols live: nothing of the web app is ever served there, so a file
/// in the build can never stand in for an endpoint.
const API_PREFIXES: &[&str] = &["/api/", "/uwu/", "/oauth/", "/.well-known/", "/scim/", "/saml/"];

/// Everything no route took: a file of the app, or a 404 in JSON.
pub(crate) async fn fallback(request: Request) -> Response {
    let path = request.uri().path();
    let api = API_PREFIXES.iter().any(|prefix| path.starts_with(prefix));
    if !api && let Some(asset) = uwuauth_web::find(path) {
        return respond(asset, request.headers());
    }
    crate::errors::not_found()
}

fn respond(asset: &'static Asset, request: &HeaderMap) -> Response {
    let accepts = request.get(header::ACCEPT_ENCODING).and_then(|value| value.to_str().ok()).unwrap_or_default();
    let takes =
        |coding: &str| accepts.split(',').any(|part| part.split(';').next().is_some_and(|name| name.trim() == coding));
    let (bytes, encoding) = match (asset.brotli, asset.gzip) {
        (Some(brotli), _) if takes("br") => (brotli, Some("br")),
        (_, Some(gzip)) if takes("gzip") => (gzip, Some("gzip")),
        _ => (asset.bytes, None),
    };
    let cache = if asset.path.starts_with("/assets/") {
        // Vite puts a hash of the content into these names: a new build means new names.
        "public, max-age=31536000, immutable"
    } else if asset.path.ends_with(".html") {
        "no-cache"
    } else {
        "public, max-age=3600"
    };
    let mut response = (StatusCode::OK, bytes).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if asset.brotli.is_some() || asset.gzip.is_some() {
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    if let Some(encoding) = encoding {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    }
    if asset.content_type.starts_with("text/html") {
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
        // A page that opened the sign-in page gets no handle on it, to send it somewhere else.
        headers.insert(
            axum::http::HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn the_root_answers_with_or_without_a_build() {
        let server = TestServer::new().await;
        let response = server.get("/").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()["content-type"].to_str().unwrap().starts_with("text/html"));
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(server.get("/uwu/v1/nope").await.status(), StatusCode::NOT_FOUND);
        assert_eq!(server.get("/no-such-file.js").await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_page_may_not_be_framed_and_loads_only_its_own_scripts() {
        let server = TestServer::new().await;
        let page = server.get("/").await;
        if !uwuauth_web::is_built() {
            return;
        }
        let policy = page.headers()["content-security-policy"].to_str().unwrap().to_string();
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
        assert!(policy.contains("script-src 'self';"), "{policy}");
    }

    #[tokio::test]
    async fn over_https_the_browser_is_told_to_stay_there() {
        let server = TestServer::new().await;
        let response = server.get("/alive").await;
        assert_eq!(response.headers()["strict-transport-security"], "max-age=63072000");
    }
}
