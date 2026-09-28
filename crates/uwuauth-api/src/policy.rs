//! The rules: what a user name, an address and a password have to be, whether somebody may sign
//! in right now, and whether they need a second factor.

use crate::errors::{ApiError, ApiResult};
use crate::{AppState, hibp};
use std::collections::BTreeSet;
use uwuauth_store::{Group, Person, Window, clock};

/// Lower case letters, digits, `.`, `_` and `-`, starting with a letter or digit, up to 64: what
/// works as a Linux login and in an LDAP DN without escaping. Never an `@`, so a name is never
/// taken for an address.
pub fn username(text: &str) -> ApiResult<String> {
    let name = text.trim().to_lowercase();
    let first_ok = name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if name.is_empty() || name.len() > 64 || !first_ok || !rest_ok {
        return Err(ApiError::field(
            "username",
            "username",
            "A user name is lower case letters, digits, dots, dashes and underscores, and starts with a letter or digit.",
        ));
    }
    Ok(name)
}

/// Something with one `@`, a dot after it, and nothing that does not belong in an address.
pub fn email(text: &str) -> ApiResult<String> {
    let address = text.trim().to_string();
    let valid = address.len() <= 254
        && address.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !domain.contains('@')
        })
        && !address.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"'));
    if !valid {
        return Err(ApiError::field("email", "email", "That is not an address."));
    }
    Ok(address)
}

/// A display name: something, not too long, one line.
pub fn display_name(text: &str) -> ApiResult<String> {
    let name: String = text.trim().chars().filter(|c| !c.is_control()).take(100).collect();
    if name.is_empty() {
        return Err(ApiError::field("displayName", "required", "A name is needed."));
    }
    Ok(name)
}

/// An optional short text: trimmed, one line, none when empty.
pub fn optional(text: Option<&str>, most: usize) -> Option<String> {
    text.map(|text| text.trim().chars().filter(|c| !c.is_control()).take(most).collect::<String>())
        .filter(|text| !text.is_empty())
}

pub fn language(text: &str) -> String {
    if text.trim().to_ascii_lowercase().starts_with("en") { "en".into() } else { "de".into() }
}

/// Long enough, not the name, and — if the admin turned it on — not in a known leak. Length over
/// rules for special characters, as NIST SP 800-63B says.
pub async fn password(state: &AppState, password: &str, person: Option<(&str, Option<&str>)>) -> ApiResult<()> {
    let settings = state.settings();
    let length = password.chars().count();
    if length < settings.password_min_length as usize {
        return Err(ApiError::field("password", "too_short", "The password is too short.")
            .with_detail(serde_json::json!({ "field": "password", "min": settings.password_min_length })));
    }
    if length > 1024 {
        return Err(ApiError::field("password", "too_long", "The password is too long."));
    }
    if let Some((username, email)) = person {
        let lower = password.to_lowercase();
        let local = email.and_then(|email| email.split('@').next()).map(str::to_lowercase);
        if lower.contains(&username.to_lowercase()) && username.len() >= 3
            || local.is_some_and(|local| local.len() >= 3 && lower.contains(&local))
        {
            return Err(ApiError::field("password", "contains_name", "The password contains your name."));
        }
    }
    if settings.hibp {
        match hibp::pwned(state, password).await {
            Ok(0) => {}
            Ok(count) => {
                return Err(ApiError::field("password", "pwned", "This password is in known leaks.")
                    .with_detail(serde_json::json!({ "field": "password", "count": count })));
            }
            // A check that does not answer lets the password through: it is an extra, and the
            // person should not be stuck because a third party is down.
            Err(error) => tracing::warn!(%error, "Have I Been Pwned did not answer; the password was not checked"),
        }
    }
    Ok(())
}

/// Whether a second factor is asked of `person`: some group they are in wants one.
pub fn needs_mfa(groups: &[Group], of_person: &BTreeSet<String>) -> bool {
    groups.iter().any(|group| group.require_mfa && of_person.contains(&group.id))
}

/// Whether windows allow a sign-in now, in the server's time zone.
pub fn within_windows(state: &AppState, windows: &[Window], app: Option<&str>) -> bool {
    let relevant: Vec<Window> =
        windows.iter().filter(|window| window.app_id.is_none() || window.app_id.as_deref() == app).cloned().collect();
    if relevant.is_empty() {
        return true;
    }
    let now = jiff::Timestamp::now().to_zoned(state.settings().tz());
    let weekday = now.weekday().to_monday_zero_offset() as u8;
    let minute = now.hour() as u16 * 60 + now.minute() as u16;
    uwuauth_store::access::allowed(&relevant, weekday, minute)
}

/// Why somebody may not sign in at all, or nothing: disabled, in the trash, run out.
pub async fn refusal(_state: &AppState, person: &Person) -> ApiResult<Option<&'static str>> {
    if person.deleted.is_some() || person.disabled {
        return Ok(Some("disabled"));
    }
    if person.expires.as_deref().is_some_and(|expires| expires <= clock::now().as_str()) {
        return Ok(Some("expired"));
    }
    Ok(None)
}

/// Whether passwords for `person` wait a quarter of an hour: too many wrong ones lately.
///
/// Only ever for a password from a device the person never signed in on. A passkey, a device
/// they used before, and the apps they signed in to keep working: otherwise anybody who knows a
/// name could lock its owner out by typing wrong passwords.
pub async fn locked(state: &AppState, person: &Person, device: Option<&str>) -> ApiResult<bool> {
    if let Some(device) = device
        && state.store.known_device(&person.id, device).await?
    {
        return Ok(false);
    }
    let attempts = i64::from(state.settings().lockout_attempts);
    let failed = state.store.failed_logins_since(&person.id, &clock::in_seconds(-15 * 60)).await?;
    Ok(failed >= attempts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_names() {
        assert_eq!(username(" Nyu.Neko ").unwrap(), "nyu.neko");
        for bad in ["", "-nyu", "nyu@example.com", "ny u", "nyü", &"a".repeat(65)] {
            assert!(username(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn addresses() {
        assert_eq!(email(" nyu@example.com ").unwrap(), "nyu@example.com");
        for bad in
            ["nyu", "nyu@", "@example.com", "nyu@example", "a b@example.com", "nyu@.example.com", "<x>@example.com"]
        {
            assert!(email(bad).is_err(), "{bad}");
        }
    }
}
