//! What happened: sign-ins (refused ones too) and changes, with who did it and from where.

use crate::{Result, Store, clock};
use rusqlite::{Row, params};

/// Days events are kept.
pub const EVENT_DAYS: i64 = 365;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: i64,
    pub time: String,
    /// Like `login`, `login_failed`, `person_created`, `group_changed`.
    pub kind: String,
    /// Who did it, when it was a person.
    pub actor_id: Option<String>,
    /// Whom it is about.
    pub person_id: Option<String>,
    /// What else it is about: a group, an invitation, an app.
    pub target: Option<String>,
    pub ip: Option<String>,
    /// JSON with whatever else belongs to the kind.
    pub detail: String,
}

fn event_from(row: &Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        time: row.get(1)?,
        kind: row.get(2)?,
        actor_id: row.get(3)?,
        person_id: row.get(4)?,
        target: row.get(5)?,
        ip: row.get(6)?,
        detail: row.get(7)?,
    })
}

/// Which events to list.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// About or by any of these people. None: everybody.
    pub people: Option<Vec<String>>,
    /// Kinds starting with this, like `login`.
    pub kind: Option<String>,
    /// Older than this id, for the next page.
    pub before: Option<i64>,
    pub limit: i64,
}

impl Store {
    pub async fn record(
        &self,
        kind: &str,
        actor: Option<&str>,
        person: Option<&str>,
        target: Option<&str>,
        ip: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        let values = (
            kind.to_string(),
            actor.map(str::to_string),
            person.map(str::to_string),
            target.map(str::to_string),
            ip.map(str::to_string),
            detail.to_string(),
        );
        self.sqlite_write(move |tx| {
            let (kind, actor, person, target, ip, detail) = values;
            tx.execute(
                "INSERT INTO events (time, kind, actor_id, person_id, target, ip, detail) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![clock::now(), kind, actor, person, target, ip, detail],
            )
            .map(drop)
        })
        .await
    }

    /// Newest first.
    pub async fn events(&self, filter: EventFilter) -> Result<Vec<Event>> {
        self.sqlite_read(move |conn| {
            let mut sql = String::from(
                "SELECT id, time, kind, actor_id, person_id, target, ip, detail FROM events WHERE id < ?1 \
                 AND (?2 IS NULL OR kind LIKE ?2 || '%')",
            );
            let restricted = filter.people.is_some();
            let people = filter.people.unwrap_or_default();
            if restricted {
                sql.push_str(" AND (person_id IN (SELECT value FROM json_each(?4)) OR actor_id IN (SELECT value FROM json_each(?4)))");
            }
            sql.push_str(" ORDER BY id DESC LIMIT ?3");
            let people = serde_json_array(&people);
            let mut statement = conn.prepare(&sql)?;
            let before = filter.before.unwrap_or(i64::MAX);
            let limit = filter.limit.clamp(1, 500);
            if restricted {
                statement.query_map(params![before, filter.kind, limit, people], event_from)?.collect()
            } else {
                statement.query_map(params![before, filter.kind, limit], event_from)?.collect()
            }
        })
        .await
    }

    /// Sign-ins that failed for `person` since `since`: the lockout counts them.
    pub async fn failed_logins_since(&self, person: &str, since: &str) -> Result<i64> {
        let (person, since) = (person.to_string(), since.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT count(*) FROM events WHERE person_id = ?1 AND kind = 'login_failed' AND time > ?2 \
                 AND id > coalesce((SELECT max(id) FROM events WHERE person_id = ?1 AND kind = 'login'), 0)",
                params![person, since],
                |row| row.get(0),
            )
        })
        .await
    }
}

/// A JSON array of strings, for `json_each`.
fn serde_json_array(items: &[String]) -> String {
    let quoted: Vec<String> =
        items.iter().map(|item| format!("\"{}\"", item.replace('\\', "\\\\").replace('"', "\\\""))).collect();
    format!("[{}]", quoted.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_store;

    #[tokio::test]
    async fn events_come_newest_first_and_filtered() {
        let (store, _dir) = test_store();
        store.record("login", Some("a"), Some("a"), None, Some("192.0.2.1"), "{}").await.unwrap();
        store.record("login_failed", None, Some("b"), None, None, "{}").await.unwrap();
        store.record("group_changed", Some("a"), None, Some("g"), None, "{}").await.unwrap();
        let all = store.events(EventFilter { limit: 10, ..EventFilter::default() }).await.unwrap();
        assert_eq!(all.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["group_changed", "login_failed", "login"]);
        let logins = store
            .events(EventFilter { kind: Some("login".into()), limit: 10, ..EventFilter::default() })
            .await
            .unwrap();
        assert_eq!(logins.len(), 2);
        let about_b = store
            .events(EventFilter { people: Some(vec!["b".into()]), limit: 10, ..EventFilter::default() })
            .await
            .unwrap();
        assert_eq!(about_b.len(), 1);
        let nobody =
            store.events(EventFilter { people: Some(vec![]), limit: 10, ..EventFilter::default() }).await.unwrap();
        assert!(nobody.is_empty(), "a manager with nobody to look after sees nothing");
        let page =
            store.events(EventFilter { before: Some(all[1].id), limit: 10, ..EventFilter::default() }).await.unwrap();
        assert_eq!(page.len(), 1);
    }

    #[tokio::test]
    async fn failed_logins_count_since_the_last_good_one() {
        let (store, _dir) = test_store();
        let since = clock::in_seconds(-3600);
        store.record("login_failed", None, Some("a"), None, None, "{}").await.unwrap();
        store.record("login", None, Some("a"), None, None, "{}").await.unwrap();
        store.record("login_failed", None, Some("a"), None, None, "{}").await.unwrap();
        store.record("login_failed", None, Some("a"), None, None, "{}").await.unwrap();
        assert_eq!(store.failed_logins_since("a", &since).await.unwrap(), 2);
    }
}
