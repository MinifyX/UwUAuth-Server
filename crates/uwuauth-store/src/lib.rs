//! UwUAuth Server's database.
//!
//! One SQLite file today. Everything above this crate talks to [`Store`] and never to SQLite
//! itself, so PostgreSQL can come later as a second backend behind the same methods — for a
//! company that wants its directory where its other databases are, or runs more than one server.
//!
//! Stage 1 brings the directory: people, groups, how they sign in, who looks after whom, and a
//! log of what happened. Every write bumps a counter ([`Store::generation`]), so what reads the
//! whole directory often — LDAP, later — can keep it in memory until something changes.

pub mod access;
pub mod apps;
pub mod attributes;
mod backup;
pub mod backups;
pub mod clock;
pub mod credentials;
pub mod events;
pub mod groups;
pub mod ldap;
mod migrations;
pub mod people;
pub mod sessions;
mod sqlite;

pub use access::{Managed, Window};
pub use apps::{App, Grant, Refresh, RefreshToken, RegistrationToken};
pub use attributes::{ApiToken, AttributeDef};
pub use backup::restore;
pub use credentials::{AppPassword, Passkey};
pub use events::{Event, EventFilter};
pub use groups::{ADMINS_ID, EVERYONE_ID, Group, GroupFields, Members, Membership};
pub use ldap::LdapAccount;
pub use migrations::SCHEMA_VERSION;
pub use people::{NewPerson, Person};
pub use sessions::{Link, Purpose, Session};

use rusqlite::{OptionalExtension, params};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// What can go wrong down here.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Something with that name is there already, like a person with that user name.
    #[error("it exists already")]
    Exists,
    /// A group would end up inside itself.
    #[error("a group cannot be inside itself")]
    Loop,
    /// The file was last opened by a newer UwUAuth Server, which changed it in ways this one
    /// does not know. Going on would mean guessing.
    #[error("the database comes from a newer UwUAuth Server (schema {found}, this one knows up to {known})")]
    TooNew { found: i64, known: i64 },
    /// A query's thread went away before it answered, which only happens while shutting down.
    #[error("the database task did not finish")]
    Gone,
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Tuning that differs between a server and a test.
#[derive(Debug, Clone)]
pub struct Options {
    /// Connections that only read, each used by one query at a time. Reads never wait for a
    /// write in WAL mode, so this is how many logins and directory searches run at once.
    pub readers: usize,
}

impl Default for Options {
    fn default() -> Self {
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        Self { readers: cores.clamp(2, 8) }
    }
}

/// The database. Cheap to clone: every clone is the same connections.
#[derive(Clone)]
pub struct Store {
    backend: Arc<Backend>,
    generation: Arc<AtomicU64>,
}

enum Backend {
    Sqlite(sqlite::Sqlite),
}

impl Store {
    /// Open (or make) the SQLite database at `path` and bring its schema up to date.
    pub fn open_sqlite(path: &Path, options: &Options) -> Result<Self> {
        let sqlite = sqlite::Sqlite::open(path, options)?;
        Ok(Self { backend: Arc::new(Backend::Sqlite(sqlite)), generation: Arc::default() })
    }

    /// Counts up with every write. Whatever keeps a copy of the directory compares it to know
    /// whether its copy is still current.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// A setting or key the server keeps, as text.
    pub async fn setting(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT value FROM server WHERE key = ?1", [key], |row| row.get(0)).optional()
        })
        .await
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_string(), value.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO server (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(drop)
        })
        .await
    }

    /// The setting under `key`, or `value` written there first if there is none: for keys made
    /// once on the first start.
    pub async fn setting_or_insert(&self, key: &str, value: &str) -> Result<String> {
        let (key, value) = (key.to_string(), value.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("INSERT OR IGNORE INTO server (key, value) VALUES (?1, ?2)", params![key, value])?;
            tx.query_row("SELECT value FROM server WHERE key = ?1", [key], |row| row.get(0))
        })
        .await
    }

    /// Once a day: sessions and links that ran out, events older than a year, people in the
    /// trash for 30 days. How many people went for good.
    pub async fn sweep(&self) -> Result<usize> {
        self.sqlite_write(|tx| {
            let now = clock::now();
            tx.execute("DELETE FROM sessions WHERE expires < ?1", [&now])?;
            tx.execute("DELETE FROM links WHERE expires < ?1 AND purpose != 'invite'", [&now])?;
            tx.execute("DELETE FROM links WHERE expires < ?1", [clock::in_seconds(-30 * 86_400)])?;
            tx.execute("DELETE FROM events WHERE time < ?1", [clock::in_seconds(-events::EVENT_DAYS * 86_400)])?;
            tx.execute("DELETE FROM refresh_tokens WHERE expires < ?1", [&now])?;
            tx.execute("DELETE FROM registration_tokens WHERE expires < ?1", [&now])?;
            tx.execute("DELETE FROM session_apps WHERE created < ?1", [clock::in_seconds(-400 * 86_400)])?;
            tx.execute(
                "DELETE FROM schedules WHERE subject_kind = 'person' AND subject_id IN \
                 (SELECT id FROM people WHERE deleted < ?1)",
                [clock::in_seconds(-people::TRASH_DAYS * 86_400)],
            )?;
            tx.execute("DELETE FROM people WHERE deleted < ?1", [clock::in_seconds(-people::TRASH_DAYS * 86_400)])
        })
        .await
    }

    /// Whether the database answers. What `/healthz` asks.
    pub async fn ping(&self) -> Result<()> {
        match &*self.backend {
            Backend::Sqlite(_) => self.sqlite_read(|conn| conn.query_row("SELECT 1", [], |_| Ok(()))).await,
        }
    }

    /// The schema the database is at.
    pub async fn schema_version(&self) -> Result<i64> {
        match &*self.backend {
            Backend::Sqlite(_) => {
                self.sqlite_read(|conn| conn.pragma_query_value(None, "user_version", |row| row.get(0))).await
            }
        }
    }

    /// When this database was made, as the server wrote it down (RFC 3339, UTC).
    pub async fn created(&self) -> Result<String> {
        self.sqlite_read(|conn| conn.query_row("SELECT value FROM server WHERE key = 'created'", [], |row| row.get(0)))
            .await
    }

    /// A consistent copy of the running database at `path`, which copying the file is not: the
    /// write-ahead log would be missing. The server goes on answering while it is written.
    pub async fn backup_to(&self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || match &*backend {
            Backend::Sqlite(sqlite) => sqlite.backup_to(&path),
        })
        .await
        .map_err(|_| StoreError::Gone)?
    }

    /// The file behind this store, for the size of a backup.
    pub fn path(&self) -> &Path {
        match &*self.backend {
            Backend::Sqlite(sqlite) => sqlite.path(),
        }
    }

    /// Run `query` on a read connection, on a blocking thread.
    pub(crate) async fn sqlite_read<T, F>(&self, query: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || match &*backend {
            Backend::Sqlite(sqlite) => sqlite.read(query),
        })
        .await
        .map_err(|_| StoreError::Gone)?
        .map_err(StoreError::from)
    }

    /// Run `change` in a transaction on the write connection, on a blocking thread. It commits
    /// when `change` returns `Ok`, and rolls back otherwise.
    pub(crate) async fn sqlite_write<T, F>(&self, change: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T> + Send + 'static,
    {
        let backend = self.backend.clone();
        let generation = self.generation.clone();
        tokio::task::spawn_blocking(move || {
            let result = match &*backend {
                Backend::Sqlite(sqlite) => sqlite.write(change),
            };
            generation.fetch_add(1, Ordering::AcqRel);
            result
        })
        .await
        .map_err(|_| StoreError::Gone)?
        .map_err(StoreError::from)
    }
}

/// `name` with `suffix` added to its file name: `uwuauth.db` and `-wal` make `uwuauth.db-wal`.
pub fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

/// A store in a temporary directory of its own, for tests.
#[cfg(test)]
pub(crate) fn test_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = Store::open_sqlite(&dir.path().join("uwuauth.db"), &Options { readers: 2 }).expect("a database");
    (store, dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &tempfile::TempDir) -> Store {
        Store::open_sqlite(&dir.path().join("uwuauth.db"), &Options { readers: 2 }).unwrap()
    }

    #[tokio::test]
    async fn a_new_database_is_at_the_newest_schema() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.ping().await.unwrap();
        assert_eq!(store.schema_version().await.unwrap(), SCHEMA_VERSION);
        let created = store.created().await.unwrap();
        assert!(created.ends_with('Z') && created.len() == 20, "{created}");
    }

    #[tokio::test]
    async fn opening_again_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let first = open(&dir).created().await.unwrap();
        let second = open(&dir).created().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn a_write_that_fails_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        let failed = store
            .sqlite_write(|tx| {
                tx.execute("INSERT INTO server (key, value) VALUES ('half', 'done')", [])?;
                tx.execute("INSERT INTO nowhere VALUES (1)", [])
            })
            .await;
        assert!(failed.is_err());
        let left: i64 = store
            .sqlite_read(|conn| conn.query_row("SELECT count(*) FROM server WHERE key = 'half'", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn readers_see_what_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store
            .sqlite_write(|tx| tx.execute("INSERT INTO server (key, value) VALUES ('seen', 'yes')", []))
            .await
            .unwrap();
        // Every reader, not only the one that happens to be free first.
        for _ in 0..4 {
            let value: String = store
                .sqlite_read(|conn| conn.query_row("SELECT value FROM server WHERE key = 'seen'", [], |row| row.get(0)))
                .await
                .unwrap();
            assert_eq!(value, "yes");
        }
    }

    #[tokio::test]
    async fn a_database_from_a_newer_server_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("uwuauth.db");
        drop(open(&dir));
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        drop(conn);
        match Store::open_sqlite(&path, &Options::default()) {
            Err(StoreError::TooNew { found, known }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(known, SCHEMA_VERSION);
            }
            Err(other) => panic!("{other}"),
            Ok(_) => panic!("a newer schema was opened"),
        }
    }
}
