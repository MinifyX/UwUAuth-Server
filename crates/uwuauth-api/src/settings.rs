//! What an admin sets in the portal, kept as JSON in the database. The mail server's password is
//! sealed in there; the rest is plain.
//!
//! `.env` only gives where a new server starts (mail server, language); from the first save in
//! the portal on, the database holds them.

use crate::crypto::Sealer;
use crate::errors::{ApiError, ApiResult};
use crate::session::{AdminOnly, ClientIp};
use crate::{AppState, audit};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uwuauth_mail::{Language, Mail, SmtpSettings};

const KEY: &str = "settings";

/// Family or office: only which words the web app uses and a few defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Family,
    Office,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// The first admin went through the assistant.
    pub setup_done: bool,
    /// The household's or the company's name: in mails and on the sign-in page.
    pub organization: String,
    pub mode: Mode,
    /// For mails to people who never chose, and for new accounts.
    pub default_language: Language,
    /// IANA name, for time windows: `Europe/Berlin`.
    pub timezone: String,
    pub smtp: Option<SmtpSettings>,
    pub password_min_length: u32,
    /// Check new passwords against Have I Been Pwned (k-anonymity: five characters of a hash
    /// leave the server).
    pub hibp: bool,
    /// How long a sign-in lasts without "stay signed in", in hours since last use.
    pub session_hours: u32,
    /// And with it, in days.
    pub remember_days: u32,
    /// Tell people by mail when a device they never used signs in.
    pub new_device_mail: bool,
    /// Wrong passwords in a row before an account waits 15 minutes.
    pub lockout_attempts: u32,
    /// How long an invitation works.
    pub invitation_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            setup_done: false,
            organization: "UwUAuth".into(),
            mode: Mode::Family,
            default_language: Language::De,
            timezone: "Europe/Berlin".into(),
            smtp: None,
            password_min_length: 10,
            hibp: false,
            session_hours: 12,
            remember_days: 30,
            new_device_mail: true,
            lockout_attempts: 10,
            invitation_days: 7,
        }
    }
}

impl Settings {
    /// From the database, or the start values when nothing was saved yet.
    pub async fn load(store: &uwuauth_store::Store, sealer: &Sealer, start: &Settings) -> Result<Self, String> {
        let Some(text) = store.setting(KEY).await.map_err(|error| error.to_string())? else {
            return Ok(start.clone());
        };
        let mut settings: Settings = serde_json::from_str(&text).map_err(|error| format!("settings: {error}"))?;
        if let Some(smtp) = settings.smtp.as_mut()
            && let Some(sealed) = smtp.password.take()
        {
            smtp.password = sealer.open(&sealed).and_then(|plain| String::from_utf8(plain).ok());
            if smtp.password.is_none() {
                tracing::warn!("the mail password in the database does not open with secret.key; set it again");
            }
        }
        Ok(settings)
    }

    pub async fn save(&self, store: &uwuauth_store::Store, sealer: &Sealer) -> Result<(), String> {
        let mut sealed = self.clone();
        if let Some(smtp) = sealed.smtp.as_mut()
            && let Some(password) = smtp.password.take()
        {
            smtp.password = Some(sealer.seal(password.as_bytes()));
        }
        let text = serde_json::to_string(&sealed).map_err(|error| error.to_string())?;
        store.set_setting(KEY, &text).await.map_err(|error| error.to_string())
    }

    pub fn tz(&self) -> jiff::tz::TimeZone {
        jiff::tz::TimeZone::get(&self.timezone).unwrap_or(jiff::tz::TimeZone::UTC)
    }

    /// As the portal shows them: the mail password only as whether there is one.
    fn public(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let Some(smtp) = value.get_mut("smtp").and_then(Value::as_object_mut) {
            let set = smtp.remove("password").is_some_and(|password| !password.is_null());
            smtp.insert("passwordSet".into(), json!(set));
        }
        value
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/settings", get(show).put(change))
        .route("/uwu/v1/settings/test-mail", post(test_mail))
        .route("/uwu/v1/timezones", get(timezones))
}

async fn show(State(state): State<AppState>, _admin: AdminOnly) -> Json<Value> {
    Json(state.settings().public())
}

/// What the portal sends: the settings, and the mail password only when it was typed again.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    #[serde(flatten)]
    settings: Settings,
    #[serde(default)]
    smtp_password: Option<String>,
}

async fn change(
    State(state): State<AppState>,
    admin: AdminOnly,
    ClientIp(ip): ClientIp,
    Json(change): Json<Change>,
) -> ApiResult<Json<Value>> {
    let mut next = change.settings;
    let before = state.settings();
    next.organization = next.organization.trim().chars().take(80).collect();
    if next.organization.is_empty() {
        return Err(ApiError::field("organization", "required", "A name is needed."));
    }
    if jiff::tz::TimeZone::get(&next.timezone).is_err() {
        return Err(ApiError::field("timezone", "timezone", "That is not a time zone."));
    }
    if !(8..=128).contains(&next.password_min_length) {
        return Err(ApiError::field("passwordMinLength", "range", "Between 8 and 128."));
    }
    if !(1..=24 * 30).contains(&next.session_hours) || !(1..=365).contains(&next.remember_days) {
        return Err(ApiError::field("sessionHours", "range", "That is too short or too long."));
    }
    if !(3..=100).contains(&next.lockout_attempts) || !(1..=90).contains(&next.invitation_days) {
        return Err(ApiError::field("lockoutAttempts", "range", "That is too few or too many."));
    }
    if let Some(smtp) = next.smtp.as_mut() {
        if !smtp.is_set() {
            next.smtp = None;
        } else {
            // The password stays with the server it was typed for: pointing the settings at
            // another server asks for it again.
            let same_server = before.smtp.as_ref().is_some_and(|old| old.host == smtp.host && old.port == smtp.port);
            smtp.password = match change.smtp_password {
                Some(password) if !password.is_empty() => Some(password),
                Some(_) => None,
                None if same_server => before.smtp.as_ref().and_then(|old| old.password.clone()),
                None => None,
            };
        }
    }
    state.mailer.configure(next.smtp.as_ref()).map_err(|error| ApiError::field("smtp", "smtp", error.to_string()))?;
    next.save(&state.store, &state.sealer).await.map_err(ApiError::internal)?;
    *state.settings.write() = next.clone();
    audit(&state, "settings_changed", Some(&admin.actor_id()), None, None, &ip, json!({})).await;
    Ok(Json(next.public()))
}

async fn test_mail(State(state): State<AppState>, admin: AdminOnly) -> ApiResult<Json<Value>> {
    let Some(to) = admin.person().and_then(|person| person.email.clone()) else {
        return Err(ApiError::bad("no_email", "Your account has no address to send the test to."));
    };
    let language = admin.person().map_or(Language::De, |person| Language::from_code(&person.language));
    match state.mailer.send(&to, &Mail::Test, language).await {
        Ok(()) => Ok(Json(json!({ "sent": to }))),
        Err(error) => {
            tracing::warn!(%error, "the test mail did not go out");
            Err(ApiError::bad("mail_failed", error.to_string()))
        }
    }
}

/// Every time zone the server knows, for the settings.
async fn timezones() -> Json<Vec<String>> {
    let mut names: Vec<String> = jiff::tz::db().available().map(|name| name.to_string()).collect();
    names.sort();
    Json(names)
}
