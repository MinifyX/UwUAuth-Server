//! The schema, one numbered step at a time.
//!
//! Each step is a file under `migrations/sqlite`, applied once, in order, inside a transaction.
//! How far a database has come is its `user_version`. A step is never changed once it is
//! released: a database that went through it already would not go through it again.

use crate::{Result, StoreError};
use rusqlite::Connection;

const STEPS: &[&str] = &[
    include_str!("../migrations/sqlite/0001_server.sql"),
    include_str!("../migrations/sqlite/0002_directory.sql"),
    include_str!("../migrations/sqlite/0003_apps.sql"),
    include_str!("../migrations/sqlite/0004_ldap.sql"),
];

/// The schema this build writes.
pub const SCHEMA_VERSION: i64 = STEPS.len() as i64;

pub(crate) fn run(conn: &mut Connection) -> Result<()> {
    let found: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::TooNew { found, known: SCHEMA_VERSION });
    }
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    // A step may build a table again (SQLite changes no column in place), which with foreign
    // keys on would take everything that points at the old table with it. So they are off while
    // the steps run — outside the transactions, the only place SQLite lets that change — and
    // checked before they are on again.
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let result = (|| -> Result<()> {
        for (index, step) in STEPS.iter().enumerate().skip(found as usize) {
            let version = index as i64 + 1;
            let tx = conn.transaction()?;
            tx.execute_batch(step)?;
            let broken: i64 = tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))?;
            if broken > 0 {
                return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY),
                    Some(format!("schema step {version} left {broken} broken references")),
                )));
            }
            tx.pragma_update(None, "user_version", version)?;
            tx.commit()?;
            tracing::info!(version, "database schema updated");
        }
        Ok(())
    })();
    conn.pragma_update(None, "foreign_keys", "ON")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_runs_once_and_foreign_keys_are_on_again() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        run(&mut conn).unwrap();
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let created: i64 =
            conn.query_row("SELECT count(*) FROM server WHERE key = 'created'", [], |row| row.get(0)).unwrap();
        assert_eq!(created, 1, "the first step ran once");
        let on: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0)).unwrap();
        assert_eq!(on, 1);
    }
}
