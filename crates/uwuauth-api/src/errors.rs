//! How the API says no.
//!
//! Every error is JSON with a machine-readable `error` and a `message` for people, so the web
//! app, scripts and the other UwUSuite programs read them the same way. The protocols bring
//! their own error formats later (OAuth's `error`/`error_description`, SCIM's `detail`), each
//! where it is spoken.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub(crate) fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found", "message": "There is nothing here." }))).into_response()
}
