//! How the API says no.
//!
//! Every error is JSON: a machine-readable `error` the web app and scripts can act on, and a
//! `message` in English for people and logs. The web app shows its own translated text for the
//! codes it knows and falls back to the message. The protocols bring their own error formats
//! (OAuth's `error`/`error_description`), each where it is spoken.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// More for the web app, like which field was wrong.
    pub detail: Option<Value>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into(), detail: None }
    }

    /// 400 with a code and a message.
    pub fn bad(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// 400 because of one field.
    pub fn field(field: &str, code: &'static str, message: impl Into<String>) -> Self {
        let mut error = Self::bad(code, message);
        error.detail = Some(json!({ "field": field }));
        error
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "Sign in first.")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// The person has to prove again who they are before this.
    pub fn reauth() -> Self {
        Self::new(StatusCode::FORBIDDEN, "reauth", "Confirm who you are first.")
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "There is nothing here.")
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn too_many() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "too_many", "Too many tries. Wait a minute and try again.")
    }

    /// Something went wrong on this side. What exactly goes to the log, not to the client.
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Something went wrong on the server.")
    }

    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

impl From<uwuauth_store::StoreError> for ApiError {
    fn from(error: uwuauth_store::StoreError) -> Self {
        match error {
            uwuauth_store::StoreError::Exists => Self::conflict("exists", "That name or address is taken."),
            uwuauth_store::StoreError::Loop => Self::bad("loop", "A group cannot end up inside itself."),
            other => Self::internal(other),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code, "message": self.message });
        if let Some(detail) = self.detail {
            body["detail"] = detail;
        }
        (self.status, Json(body)).into_response()
    }
}

pub(crate) fn not_found() -> Response {
    ApiError::not_found().into_response()
}
