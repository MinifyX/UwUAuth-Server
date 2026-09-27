//! Who looks after whom, and when somebody may sign in.

use crate::groups::Membership;
use crate::{Result, Store};
use rusqlite::{Row, params};
use std::collections::BTreeSet;

/// Whom a manager looks after: people directly, and everybody in some groups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Managed {
    pub people: Vec<String>,
    pub groups: Vec<String>,
}

/// A window in which somebody may sign in, in the server's time zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub id: String,
    /// `person` or `group`.
    pub subject_kind: String,
    pub subject_id: String,
    /// Only for this app; none for every app.
    pub app_id: Option<String>,
    /// Monday 1, Tuesday 2, … Sunday 64.
    pub days: u8,
    /// Minutes after midnight.
    pub start_minute: u16,
    /// Minutes after midnight, up to 1440; before `start_minute`, the window goes past midnight.
    pub end_minute: u16,
}

fn window_from(row: &Row<'_>) -> rusqlite::Result<Window> {
    Ok(Window {
        id: row.get(0)?,
        subject_kind: row.get(1)?,
        subject_id: row.get(2)?,
        app_id: row.get(3)?,
        days: row.get(4)?,
        start_minute: row.get(5)?,
        end_minute: row.get(6)?,
    })
}

impl Window {
    /// Whether `weekday` (Monday 0 … Sunday 6) at `minute` after midnight falls into this window.
    /// A window past midnight belongs to the day it starts on.
    pub fn contains(&self, weekday: u8, minute: u16) -> bool {
        let day = |weekday: u8| self.days & (1 << (weekday % 7)) != 0;
        if self.start_minute < self.end_minute {
            day(weekday) && (self.start_minute..self.end_minute).contains(&minute)
        } else {
            (day(weekday) && minute >= self.start_minute) || (day((weekday + 6) % 7) && minute < self.end_minute)
        }
    }
}

/// Whether the windows allow signing in now. No windows at all allow everything.
pub fn allowed(windows: &[Window], weekday: u8, minute: u16) -> bool {
    windows.is_empty() || windows.iter().any(|window| window.contains(weekday, minute))
}

impl Store {
    pub async fn managed_by(&self, manager: &str) -> Result<Managed> {
        let manager = manager.to_string();
        self.sqlite_read(move |conn| {
            let list = |sql: &str| -> rusqlite::Result<Vec<String>> {
                let mut statement = conn.prepare_cached(sql)?;
                statement.query_map([&manager], |row| row.get(0))?.collect()
            };
            Ok(Managed {
                people: list("SELECT person_id FROM managed_people WHERE manager_id = ?1")?,
                groups: list("SELECT group_id FROM managed_groups WHERE manager_id = ?1")?,
            })
        })
        .await
    }

    pub async fn set_managed(&self, manager: &str, managed: Managed) -> Result<()> {
        let manager = manager.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM managed_people WHERE manager_id = ?1", [&manager])?;
            tx.execute("DELETE FROM managed_groups WHERE manager_id = ?1", [&manager])?;
            for person in managed.people.iter().filter(|person| **person != manager) {
                tx.execute(
                    "INSERT OR IGNORE INTO managed_people (manager_id, person_id) VALUES (?1, ?2)",
                    [&manager, person],
                )?;
            }
            for group in &managed.groups {
                tx.execute(
                    "INSERT OR IGNORE INTO managed_groups (manager_id, group_id) VALUES (?1, ?2)",
                    [&manager, group],
                )?;
            }
            Ok(())
        })
        .await
    }

    /// Everybody `manager` looks after, never themselves.
    pub async fn people_managed_by(
        &self,
        manager: &str,
        membership: &Membership,
        everybody: &[String],
    ) -> Result<BTreeSet<String>> {
        let managed = self.managed_by(manager).await?;
        let mut people: BTreeSet<String> = managed.people.into_iter().collect();
        for group in &managed.groups {
            people.extend(membership.people_in(group, everybody));
        }
        people.remove(manager);
        Ok(people)
    }

    /// Who looks after `person` directly (not through groups).
    pub async fn managers_of(&self, person: &str) -> Result<Vec<String>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached("SELECT manager_id FROM managed_people WHERE person_id = ?1")?;
            statement.query_map([person], |row| row.get(0))?.collect()
        })
        .await
    }

    /// Everybody who is a manager at all.
    pub async fn managers(&self) -> Result<BTreeSet<String>> {
        self.sqlite_read(|conn| {
            let mut statement = conn
                .prepare_cached("SELECT manager_id FROM managed_people UNION SELECT manager_id FROM managed_groups")?;
            statement.query_map([], |row| row.get(0))?.collect()
        })
        .await
    }

    /// The windows written down for one person or group.
    pub async fn windows(&self, kind: &str, subject: &str) -> Result<Vec<Window>> {
        let (kind, subject) = (kind.to_string(), subject.to_string());
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT id, subject_kind, subject_id, app_id, days, start_minute, end_minute FROM schedules \
                 WHERE subject_kind = ?1 AND subject_id = ?2 ORDER BY start_minute",
            )?;
            statement.query_map([kind, subject], window_from)?.collect()
        })
        .await
    }

    /// Replace the windows of one person or group.
    pub async fn set_windows(&self, kind: &str, subject: &str, windows: Vec<Window>) -> Result<()> {
        let (kind, subject) = (kind.to_string(), subject.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM schedules WHERE subject_kind = ?1 AND subject_id = ?2", [&kind, &subject])?;
            for window in windows {
                tx.execute(
                    "INSERT INTO schedules (id, subject_kind, subject_id, app_id, days, start_minute, end_minute) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        kind,
                        subject,
                        window.app_id,
                        window.days,
                        window.start_minute,
                        window.end_minute
                    ],
                )?;
            }
            Ok(())
        })
        .await
    }

    /// Every window that applies to `person`: their own and those of every group they are in.
    pub async fn windows_for(&self, person: &str, groups: &BTreeSet<String>) -> Result<Vec<Window>> {
        let person = person.to_string();
        let groups: Vec<String> = groups.iter().cloned().collect();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT id, subject_kind, subject_id, app_id, days, start_minute, end_minute FROM schedules \
                 WHERE (subject_kind = 'person' AND subject_id = ?1) OR subject_kind = 'group'",
            )?;
            let all: Vec<Window> = statement.query_map([&person], window_from)?.collect::<rusqlite::Result<_>>()?;
            Ok(all
                .into_iter()
                .filter(|window| window.subject_kind == "person" || groups.contains(&window.subject_id))
                .collect())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(days: u8, start: u16, end: u16) -> Window {
        Window {
            id: String::new(),
            subject_kind: "person".into(),
            subject_id: String::new(),
            app_id: None,
            days,
            start_minute: start,
            end_minute: end,
        }
    }

    #[test]
    fn a_window_on_school_days() {
        // Monday to Friday, 7:00 to 20:00.
        let school = window(0b0011111, 7 * 60, 20 * 60);
        assert!(school.contains(0, 7 * 60));
        assert!(school.contains(4, 19 * 60 + 59));
        assert!(!school.contains(4, 20 * 60));
        assert!(!school.contains(5, 12 * 60), "Saturday");
        assert!(!school.contains(0, 6 * 60 + 59));
    }

    #[test]
    fn a_window_past_midnight_belongs_to_the_day_it_starts() {
        // Friday 22:00 to 1:00.
        let late = window(1 << 4, 22 * 60, 60);
        assert!(late.contains(4, 23 * 60));
        assert!(late.contains(5, 30), "Saturday half past midnight");
        assert!(!late.contains(4, 30), "Friday half past midnight belongs to Thursday");
        assert!(!late.contains(6, 30));
    }

    #[test]
    fn no_windows_allow_everything() {
        assert!(allowed(&[], 3, 3 * 60));
        assert!(!allowed(&[window(1, 0, 60)], 3, 3 * 60));
        assert!(allowed(&[window(1, 0, 60), window(1 << 3, 0, 1440)], 3, 3 * 60));
    }
}
