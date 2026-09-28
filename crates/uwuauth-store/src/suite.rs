//! The UwUSuite: one-time codes that pair a suite app with UwUAuth, what a paired app said about
//! itself, and where people and groups are pushed over SCIM — with what was pushed last, so only
//! changes go out.

use crate::apps::{App, to_json, write_app};
use crate::people::unique;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

/// At most this many codes are open at once.
pub const OPEN_CODES: i64 = 20;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PairingCode {
    pub id: String,
    /// SHA-256 of the code; none once it was used.
    pub hash: Option<Vec<u8>>,
    pub allowed_groups: Vec<String>,
    /// JSON object: role id → group ids.
    pub role_groups: String,
    pub created_by: Option<String>,
    pub created: String,
    pub expires: String,
    pub used: Option<String>,
    pub app_id: Option<String>,
}

impl PairingCode {
    /// Not used and not run out.
    pub fn open(&self) -> bool {
        self.hash.is_some() && clock::now() < self.expires
    }
}

const CODE_COLUMNS: &str = "id, hash, allowed_groups, role_groups, created_by, created, expires, used, app_id";

fn code_from(row: &Row<'_>) -> rusqlite::Result<PairingCode> {
    Ok(PairingCode {
        id: row.get(0)?,
        hash: row.get(1)?,
        allowed_groups: serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
        role_groups: row.get(3)?,
        created_by: row.get(4)?,
        created: row.get(5)?,
        expires: row.get(6)?,
        used: row.get(7)?,
        app_id: row.get(8)?,
    })
}

/// What a paired suite app said about itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SuiteApp {
    pub app_id: String,
    pub product: String,
    pub version: String,
    pub url: String,
    /// Only when asked for one app; lists say whether there is one with `has_icon`.
    pub icon: Option<Vec<u8>>,
    pub has_icon: bool,
    /// JSON array of `{"id", "name", "description"}`.
    pub roles: String,
    pub paired_by: Option<String>,
    pub paired: String,
}

const SUITE_COLUMNS: &str = "app_id, product, version, url, icon, roles, paired_by, paired";
const SUITE_SELECT: &str = "app_id, product, version, url, icon, roles, paired_by, paired, icon IS NOT NULL";

fn suite_from(row: &Row<'_>) -> rusqlite::Result<SuiteApp> {
    Ok(SuiteApp {
        app_id: row.get(0)?,
        product: row.get(1)?,
        version: row.get(2)?,
        url: row.get(3)?,
        icon: row.get(4)?,
        roles: row.get(5)?,
        paired_by: row.get(6)?,
        paired: row.get(7)?,
        has_icon: row.get(8)?,
    })
}

/// Where an app takes people and groups over SCIM.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimTarget {
    pub app_id: String,
    pub base_url: String,
    /// Sealed; the API opens it.
    pub token: String,
    pub resources: Vec<String>,
    /// `email` or `username`.
    pub user_name: String,
    pub created: String,
    pub synced: Option<String>,
    pub tried: Option<String>,
    pub error: Option<String>,
}

const TARGET_COLUMNS: &str = "app_id, base_url, token, resources, user_name, created, synced, tried, error";

fn target_from(row: &Row<'_>) -> rusqlite::Result<ScimTarget> {
    Ok(ScimTarget {
        app_id: row.get(0)?,
        base_url: row.get(1)?,
        token: row.get(2)?,
        resources: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
        user_name: row.get(4)?,
        created: row.get(5)?,
        synced: row.get(6)?,
        tried: row.get(7)?,
        error: row.get(8)?,
    })
}

/// A person or group as an app knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimObject {
    /// `user` or `group`.
    pub kind: String,
    pub local_id: String,
    pub remote_id: String,
    /// What it was sent last, as JSON.
    pub sent: String,
}

fn write_target(tx: &rusqlite::Transaction<'_>, target: &ScimTarget) -> rusqlite::Result<()> {
    tx.execute(
        &format!(
            "INSERT INTO scim_targets ({TARGET_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL) \
             ON CONFLICT (app_id) DO UPDATE SET base_url = excluded.base_url, token = excluded.token, \
             resources = excluded.resources, user_name = excluded.user_name, error = NULL"
        ),
        params![
            target.app_id,
            target.base_url,
            target.token,
            to_json(&target.resources),
            target.user_name,
            clock::now()
        ],
    )
    .map(drop)
}

impl Store {
    /// Keep a new pairing code. Codes that ran out a day ago are swept up on the way. None when
    /// [`OPEN_CODES`] are open already.
    pub async fn create_pairing_code(&self, code: PairingCode) -> Result<Option<PairingCode>> {
        self.sqlite_write(move |tx| {
            let now = clock::now();
            tx.execute("DELETE FROM pairing_codes WHERE expires < ?1", [clock::in_seconds(-86_400)])?;
            let open: i64 = tx.query_row(
                "SELECT count(*) FROM pairing_codes WHERE hash IS NOT NULL AND expires > ?1",
                [&now],
                |row| row.get(0),
            )?;
            if open >= OPEN_CODES {
                return Ok(None);
            }
            let code =
                PairingCode { id: uuid::Uuid::new_v4().to_string(), created: now, used: None, app_id: None, ..code };
            tx.execute(
                &format!("INSERT INTO pairing_codes ({CODE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)"),
                params![
                    code.id,
                    code.hash,
                    to_json(&code.allowed_groups),
                    code.role_groups,
                    code.created_by,
                    code.created,
                    code.expires
                ],
            )?;
            Ok(Some(code))
        })
        .await
    }

    /// The codes that can still be used.
    pub async fn open_pairing_codes(&self) -> Result<Vec<PairingCode>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {CODE_COLUMNS} FROM pairing_codes WHERE hash IS NOT NULL AND expires > ?1 ORDER BY created DESC"
            ))?;
            statement.query_map([clock::now()], code_from)?.collect()
        })
        .await
    }

    pub async fn pairing_code(&self, id: &str) -> Result<Option<PairingCode>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {CODE_COLUMNS} FROM pairing_codes WHERE id = ?1"), [id], code_from)
                .optional()
        })
        .await
    }

    pub async fn delete_pairing_code(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM pairing_codes WHERE id = ?1 AND hash IS NOT NULL", [id]).map(|n| n == 1)
        })
        .await
    }

    /// Pair: use the code up and keep the app it makes, with what the suite app said about itself
    /// and where its SCIM goes — all or nothing. None when the code was used or ran out in the
    /// meantime. The app's `id`, `created` and `updated` are set here.
    pub async fn pair(
        &self,
        code_id: &str,
        mut app: App,
        suite: SuiteApp,
        scim: Option<ScimTarget>,
    ) -> Result<Option<App>> {
        let code_id = code_id.to_string();
        app.id = uuid::Uuid::new_v4().to_string();
        app.created = clock::now();
        app.updated = app.created.clone();
        self.sqlite_write(move |tx| {
            let now = clock::now();
            let used = tx.execute(
                "UPDATE pairing_codes SET hash = NULL, used = ?2 WHERE id = ?1 AND hash IS NOT NULL AND expires > ?2",
                params![code_id, now],
            )?;
            if used != 1 {
                return Ok(None);
            }
            write_app(tx, &app, true)?;
            tx.execute("UPDATE pairing_codes SET app_id = ?2 WHERE id = ?1", params![code_id, app.id])?;
            tx.execute(
                &format!("INSERT INTO suite_apps ({SUITE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
                params![app.id, suite.product, suite.version, suite.url, suite.icon, suite.roles, suite.paired_by, now],
            )?;
            if let Some(target) = scim {
                write_target(tx, &ScimTarget { app_id: app.id.clone(), ..target })?;
            }
            Ok(Some(app))
        })
        .await
        .map_err(unique)
    }

    pub async fn suite_app(&self, app_id: &str) -> Result<Option<SuiteApp>> {
        let app_id = app_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {SUITE_SELECT} FROM suite_apps WHERE app_id = ?1"), [app_id], suite_from)
                .optional()
        })
        .await
    }

    /// Every paired app, without icons.
    pub async fn suite_apps(&self) -> Result<Vec<SuiteApp>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(
                "SELECT app_id, product, version, url, NULL, roles, paired_by, paired, icon IS NOT NULL FROM suite_apps",
            )?;
            statement.query_map([], suite_from)?.collect()
        })
        .await
    }

    pub async fn scim_target(&self, app_id: &str) -> Result<Option<ScimTarget>> {
        let app_id = app_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!("SELECT {TARGET_COLUMNS} FROM scim_targets WHERE app_id = ?1"),
                [app_id],
                target_from,
            )
            .optional()
        })
        .await
    }

    pub async fn scim_targets(&self) -> Result<Vec<ScimTarget>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(&format!("SELECT {TARGET_COLUMNS} FROM scim_targets"))?;
            statement.query_map([], target_from)?.collect()
        })
        .await
    }

    /// Set up (or change) where an app's SCIM goes. A new address forgets what was pushed: the
    /// ids of another server mean nothing.
    pub async fn set_scim_target(&self, target: ScimTarget) -> Result<()> {
        self.sqlite_write(move |tx| {
            let before: Option<String> = tx
                .query_row("SELECT base_url FROM scim_targets WHERE app_id = ?1", [&target.app_id], |row| row.get(0))
                .optional()?;
            if before.is_some_and(|before| before != target.base_url) {
                tx.execute("DELETE FROM scim_objects WHERE app_id = ?1", [&target.app_id])?;
            }
            write_target(tx, &target)
        })
        .await
    }

    /// Stop pushing to an app, and forget what was pushed.
    pub async fn delete_scim_target(&self, app_id: &str) -> Result<bool> {
        let app_id = app_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM scim_objects WHERE app_id = ?1", [&app_id])?;
            tx.execute("DELETE FROM scim_targets WHERE app_id = ?1", [&app_id]).map(|n| n == 1)
        })
        .await
    }

    /// Note how a push went: `error` none means it went through.
    pub async fn scim_pushed(&self, app_id: &str, error: Option<&str>) -> Result<()> {
        let (app_id, error) = (app_id.to_string(), error.map(str::to_string));
        self.sqlite_write(move |tx| {
            let now = clock::now();
            match error {
                None => tx.execute(
                    "UPDATE scim_targets SET synced = ?2, tried = ?2, error = NULL WHERE app_id = ?1",
                    params![app_id, now],
                ),
                Some(error) => tx.execute(
                    "UPDATE scim_targets SET tried = ?2, error = ?3 WHERE app_id = ?1",
                    params![app_id, now, error],
                ),
            }
            .map(drop)
        })
        .await
    }

    /// Forget what was sent (the ids stay), so the next push sends everything again.
    pub async fn scim_resend(&self, app_id: &str) -> Result<()> {
        let app_id = app_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE scim_objects SET sent = '{}' WHERE app_id = ?1", [app_id]).map(drop)
        })
        .await
    }

    pub async fn scim_objects(&self, app_id: &str) -> Result<Vec<ScimObject>> {
        let app_id = app_id.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT kind, local_id, remote_id, sent FROM scim_objects WHERE app_id = ?1 ORDER BY kind, local_id",
            )?;
            statement
                .query_map([app_id], |row| {
                    Ok(ScimObject {
                        kind: row.get(0)?,
                        local_id: row.get(1)?,
                        remote_id: row.get(2)?,
                        sent: row.get(3)?,
                    })
                })?
                .collect()
        })
        .await
    }

    /// How many people and groups an app was sent, by app.
    pub async fn scim_counts(&self) -> Result<Vec<(String, i64, i64)>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(
                "SELECT app_id, sum(kind = 'user'), sum(kind = 'group') FROM scim_objects GROUP BY app_id",
            )?;
            statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?.collect()
        })
        .await
    }

    pub async fn put_scim_object(&self, app_id: &str, object: ScimObject) -> Result<()> {
        let app_id = app_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO scim_objects (app_id, kind, local_id, remote_id, sent) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (app_id, kind, local_id) DO UPDATE SET remote_id = excluded.remote_id, sent = excluded.sent",
                params![app_id, object.kind, object.local_id, object.remote_id, object.sent],
            )
            .map(drop)
        })
        .await
    }

    pub async fn delete_scim_object(&self, app_id: &str, kind: &str, local_id: &str) -> Result<()> {
        let (app_id, kind, local_id) = (app_id.to_string(), kind.to_string(), local_id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "DELETE FROM scim_objects WHERE app_id = ?1 AND kind = ?2 AND local_id = ?3",
                params![app_id, kind, local_id],
            )
            .map(drop)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_store;

    fn code(hash: u8) -> PairingCode {
        PairingCode { hash: Some(vec![hash]), expires: clock::in_seconds(900), ..PairingCode::default() }
    }

    #[tokio::test]
    async fn a_code_pairs_once() {
        let (store, _dir) = test_store();
        let made = store.create_pairing_code(code(1)).await.unwrap().unwrap();
        assert_eq!(store.open_pairing_codes().await.unwrap().len(), 1);
        let app = App { client_id: "lock".into(), name: "UwULock".into(), ..App::default() };
        let suite =
            SuiteApp { product: "UwULock".into(), url: "https://lock.example.com".into(), ..SuiteApp::default() };
        let target = ScimTarget {
            base_url: "https://lock.example.com/scim/v2".into(),
            token: "sealed".into(),
            resources: vec!["User".into()],
            user_name: "email".into(),
            ..ScimTarget::default()
        };
        let paired = store.pair(&made.id, app.clone(), suite.clone(), Some(target)).await.unwrap().unwrap();
        assert_eq!(store.suite_app(&paired.id).await.unwrap().unwrap().product, "UwULock");
        assert_eq!(store.scim_target(&paired.id).await.unwrap().unwrap().resources, ["User"]);
        let used = store.pairing_code(&made.id).await.unwrap().unwrap();
        assert!(!used.open() && used.app_id.as_deref() == Some(paired.id.as_str()));
        assert!(store.open_pairing_codes().await.unwrap().is_empty());

        let again = App { client_id: "lock-2".into(), ..app };
        assert!(store.pair(&made.id, again, suite, None).await.unwrap().is_none(), "used up");
        assert_eq!(store.apps().await.unwrap().len(), 1, "and nothing was kept");

        assert!(store.delete_app(&paired.id).await.unwrap());
        assert!(store.suite_app(&paired.id).await.unwrap().is_none());
        assert!(store.scim_target(&paired.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn only_so_many_codes_are_open() {
        let (store, _dir) = test_store();
        for n in 0..OPEN_CODES {
            assert!(store.create_pairing_code(code(n as u8)).await.unwrap().is_some());
        }
        assert!(store.create_pairing_code(code(200)).await.unwrap().is_none());
        let first = store.open_pairing_codes().await.unwrap().remove(0);
        assert!(store.delete_pairing_code(&first.id).await.unwrap());
        assert!(store.create_pairing_code(code(201)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_new_scim_address_forgets_what_was_pushed() {
        let (store, _dir) = test_store();
        let app = store.create_app(App { client_id: "c".into(), name: "App".into(), ..App::default() }).await.unwrap();
        let target = ScimTarget {
            app_id: app.id.clone(),
            base_url: "https://a.example.com/scim/v2".into(),
            token: "t".into(),
            user_name: "email".into(),
            ..ScimTarget::default()
        };
        store.set_scim_target(target.clone()).await.unwrap();
        let object = ScimObject { kind: "user".into(), local_id: "p".into(), remote_id: "r".into(), sent: "{}".into() };
        store.put_scim_object(&app.id, object).await.unwrap();
        store.set_scim_target(ScimTarget { token: "u".into(), ..target.clone() }).await.unwrap();
        assert_eq!(store.scim_objects(&app.id).await.unwrap().len(), 1, "a new token keeps them");
        assert_eq!(store.scim_counts().await.unwrap(), [(app.id.clone(), 1, 0)]);
        store.set_scim_target(ScimTarget { base_url: "https://b.example.com/scim/v2".into(), ..target }).await.unwrap();
        assert!(store.scim_objects(&app.id).await.unwrap().is_empty());
        store.scim_pushed(&app.id, Some("down")).await.unwrap();
        assert_eq!(store.scim_target(&app.id).await.unwrap().unwrap().error.as_deref(), Some("down"));
        store.scim_pushed(&app.id, None).await.unwrap();
        let pushed = store.scim_target(&app.id).await.unwrap().unwrap();
        assert!(pushed.error.is_none() && pushed.synced.is_some());
    }
}
