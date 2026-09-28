//! Apps that sign people in through UwUAuth (OpenID Connect clients), what people allowed them,
//! their refresh tokens, and the tokens apps register themselves with.

use crate::people::unique;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct App {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: String,
    pub template: Option<String>,
    /// SHA-256 of the secret; none for a public client.
    pub secret_hash: Option<Vec<u8>>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub grant_types: Vec<String>,
    pub token_auth_method: String,
    pub id_token_alg: String,
    pub consent: bool,
    pub require_pkce: bool,
    pub allowed_groups: Vec<String>,
    pub require_mfa: bool,
    /// JSON array of `{"group": id, "role": name}`.
    pub roles: String,
    pub access_token_minutes: i64,
    pub refresh_token_days: i64,
    pub launch_url: Option<String>,
    pub disabled: bool,
    pub created_by: Option<String>,
    pub created: String,
    pub updated: String,
}

const APP_COLUMNS: &str = "id, client_id, name, description, template, secret_hash, redirect_uris, \
     post_logout_redirect_uris, backchannel_logout_uri, grant_types, token_auth_method, id_token_alg, consent, \
     require_pkce, allowed_groups, require_mfa, roles, access_token_minutes, refresh_token_days, launch_url, disabled, \
     created_by, created, updated";

fn list(text: String) -> Vec<String> {
    serde_json::from_str(&text).unwrap_or_default()
}

/// A JSON array of strings.
pub fn to_json(items: &[String]) -> String {
    serde_json::to_string(items).unwrap_or_else(|_| "[]".into())
}

fn app_from(row: &Row<'_>) -> rusqlite::Result<App> {
    Ok(App {
        id: row.get(0)?,
        client_id: row.get(1)?,
        name: row.get(2)?,
        description: row.get(3)?,
        template: row.get(4)?,
        secret_hash: row.get(5)?,
        redirect_uris: list(row.get(6)?),
        post_logout_redirect_uris: list(row.get(7)?),
        backchannel_logout_uri: row.get(8)?,
        grant_types: list(row.get(9)?),
        token_auth_method: row.get(10)?,
        id_token_alg: row.get(11)?,
        consent: row.get(12)?,
        require_pkce: row.get(13)?,
        allowed_groups: list(row.get(14)?),
        require_mfa: row.get(15)?,
        roles: row.get(16)?,
        access_token_minutes: row.get(17)?,
        refresh_token_days: row.get(18)?,
        launch_url: row.get(19)?,
        disabled: row.get(20)?,
        created_by: row.get(21)?,
        created: row.get(22)?,
        updated: row.get(23)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub app_id: String,
    pub person_id: String,
    pub scope: String,
    pub consented: bool,
    pub created: String,
    pub last_used: String,
}

fn grant_from(row: &Row<'_>) -> rusqlite::Result<Grant> {
    Ok(Grant {
        id: row.get(0)?,
        app_id: row.get(1)?,
        person_id: row.get(2)?,
        scope: row.get(3)?,
        consented: row.get(4)?,
        created: row.get(5)?,
        last_used: row.get(6)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub hash: Vec<u8>,
    pub grant_id: String,
    pub family: String,
    pub scope: String,
    pub stamp: String,
    pub auth_time: i64,
    pub amr: String,
    pub sid: Option<String>,
    pub nonce: Option<String>,
    pub created: String,
    pub expires: String,
    pub used: Option<String>,
}

fn refresh_from(row: &Row<'_>) -> rusqlite::Result<RefreshToken> {
    Ok(RefreshToken {
        hash: row.get(0)?,
        grant_id: row.get(1)?,
        family: row.get(2)?,
        scope: row.get(3)?,
        stamp: row.get(4)?,
        auth_time: row.get(5)?,
        amr: row.get(6)?,
        sid: row.get(7)?,
        nonce: row.get(8)?,
        created: row.get(9)?,
        expires: row.get(10)?,
        used: row.get(11)?,
    })
}

const REFRESH_COLUMNS: &str =
    "hash, grant_id, family, scope, stamp, auth_time, amr, sid, nonce, created, expires, used";

/// What using a refresh token found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refresh {
    /// It was good, and is used up now.
    Fresh(Box<RefreshToken>),
    /// It had been used before: stolen, or a client that kept an old one. Its whole family is
    /// gone now.
    Reused,
    /// No such token, or run out.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationToken {
    pub id: String,
    pub name: String,
    pub uses_left: i64,
    pub created_by: Option<String>,
    pub created: String,
    pub expires: String,
}

fn registration_from(row: &Row<'_>) -> rusqlite::Result<RegistrationToken> {
    Ok(RegistrationToken {
        id: row.get(0)?,
        name: row.get(1)?,
        uses_left: row.get(2)?,
        created_by: row.get(3)?,
        created: row.get(4)?,
        expires: row.get(5)?,
    })
}

fn write_app(tx: &rusqlite::Transaction<'_>, app: &App, insert: bool) -> rusqlite::Result<()> {
    let sql = if insert {
        format!(
            "INSERT INTO apps ({APP_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
             ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)"
        )
    } else {
        "UPDATE apps SET client_id = ?2, name = ?3, description = ?4, template = ?5, secret_hash = ?6, \
         redirect_uris = ?7, post_logout_redirect_uris = ?8, backchannel_logout_uri = ?9, grant_types = ?10, \
         token_auth_method = ?11, id_token_alg = ?12, consent = ?13, require_pkce = ?14, allowed_groups = ?15, \
         require_mfa = ?16, roles = ?17, access_token_minutes = ?18, refresh_token_days = ?19, launch_url = ?20, \
         disabled = ?21, created_by = ?22, created = ?23, updated = ?24 WHERE id = ?1"
            .to_string()
    };
    tx.execute(
        &sql,
        params![
            app.id,
            app.client_id,
            app.name,
            app.description,
            app.template,
            app.secret_hash,
            to_json(&app.redirect_uris),
            to_json(&app.post_logout_redirect_uris),
            app.backchannel_logout_uri,
            to_json(&app.grant_types),
            app.token_auth_method,
            app.id_token_alg,
            app.consent,
            app.require_pkce,
            to_json(&app.allowed_groups),
            app.require_mfa,
            app.roles,
            app.access_token_minutes,
            app.refresh_token_days,
            app.launch_url,
            app.disabled,
            app.created_by,
            app.created,
            app.updated,
        ],
    )
    .map(drop)
}

impl Store {
    pub async fn apps(&self) -> Result<Vec<App>> {
        self.sqlite_read(|conn| {
            let mut statement =
                conn.prepare_cached(&format!("SELECT {APP_COLUMNS} FROM apps ORDER BY name COLLATE NOCASE"))?;
            statement.query_map([], app_from)?.collect()
        })
        .await
    }

    pub async fn app(&self, id: &str) -> Result<Option<App>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {APP_COLUMNS} FROM apps WHERE id = ?1"), [id], app_from).optional()
        })
        .await
    }

    pub async fn app_by_client_id(&self, client_id: &str) -> Result<Option<App>> {
        let client_id = client_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {APP_COLUMNS} FROM apps WHERE client_id = ?1"), [client_id], app_from)
                .optional()
        })
        .await
    }

    /// Keep a new app. Its `id`, `created` and `updated` are set here.
    pub async fn create_app(&self, mut app: App) -> Result<App> {
        app.id = uuid::Uuid::new_v4().to_string();
        app.created = clock::now();
        app.updated = app.created.clone();
        self.sqlite_write(move |tx| {
            write_app(tx, &app, true)?;
            Ok(app)
        })
        .await
        .map_err(unique)
    }

    pub async fn update_app(&self, id: &str, change: impl FnOnce(&mut App) + Send + 'static) -> Result<Option<App>> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            let Some(mut app) =
                tx.query_row(&format!("SELECT {APP_COLUMNS} FROM apps WHERE id = ?1"), [&id], app_from).optional()?
            else {
                return Ok(None);
            };
            change(&mut app);
            app.id = id;
            app.updated = clock::now();
            write_app(tx, &app, false)?;
            Ok(Some(app))
        })
        .await
        .map_err(unique)
    }

    pub async fn delete_app(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM schedules WHERE app_id = ?1", [&id])?;
            tx.execute("DELETE FROM apps WHERE id = ?1", [&id]).map(|n| n == 1)
        })
        .await
    }

    /// The grant of `person` for `app`, made or brought up to date: the scopes they allowed now,
    /// added to what they allowed before.
    pub async fn touch_grant(&self, app: &str, person: &str, scope: &str, consented: bool) -> Result<Grant> {
        let (app, person, scope) = (app.to_string(), person.to_string(), scope.to_string());
        self.sqlite_write(move |tx| {
            let now = clock::now();
            let existing = tx
                .query_row(
                    "SELECT id, app_id, person_id, scope, consented, created, last_used FROM grants \
                     WHERE app_id = ?1 AND person_id = ?2",
                    [&app, &person],
                    grant_from,
                )
                .optional()?;
            match existing {
                Some(grant) => {
                    let mut scopes: Vec<&str> = grant.scope.split_whitespace().collect();
                    for extra in scope.split_whitespace() {
                        if !scopes.contains(&extra) {
                            scopes.push(extra);
                        }
                    }
                    let joined = scopes.join(" ");
                    tx.execute(
                        "UPDATE grants SET scope = ?2, consented = consented OR ?3, last_used = ?4 WHERE id = ?1",
                        params![grant.id, joined, consented, now],
                    )?;
                    Ok(Grant { scope: joined, consented: grant.consented || consented, last_used: now, ..grant })
                }
                None => {
                    let id = uuid::Uuid::new_v4().to_string();
                    tx.execute(
                        "INSERT INTO grants (id, app_id, person_id, scope, consented, created, last_used) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                        params![id, app, person, scope, consented, now],
                    )?;
                    Ok(Grant {
                        id,
                        app_id: app,
                        person_id: person,
                        scope,
                        consented,
                        created: now.clone(),
                        last_used: now,
                    })
                }
            }
        })
        .await
    }

    pub async fn grant(&self, app: &str, person: &str) -> Result<Option<Grant>> {
        let (app, person) = (app.to_string(), person.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT id, app_id, person_id, scope, consented, created, last_used FROM grants \
                 WHERE app_id = ?1 AND person_id = ?2",
                [app, person],
                grant_from,
            )
            .optional()
        })
        .await
    }

    pub async fn grant_by_id(&self, id: &str) -> Result<Option<Grant>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT id, app_id, person_id, scope, consented, created, last_used FROM grants WHERE id = ?1",
                [id],
                grant_from,
            )
            .optional()
        })
        .await
    }

    pub async fn grants_of(&self, person: &str) -> Result<Vec<Grant>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT id, app_id, person_id, scope, consented, created, last_used FROM grants \
                 WHERE person_id = ?1 ORDER BY last_used DESC",
            )?;
            statement.query_map([person], grant_from)?.collect()
        })
        .await
    }

    /// Take a grant back: the app's refresh tokens stop working with it.
    pub async fn revoke_grant(&self, person: &str, id: &str) -> Result<bool> {
        let (person, id) = (person.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM grants WHERE id = ?1 AND person_id = ?2", [id, person]).map(|n| n == 1)
        })
        .await
    }

    pub async fn add_refresh_token(&self, token: RefreshToken) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                &format!("INSERT INTO refresh_tokens ({REFRESH_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)"),
                params![
                    token.hash,
                    token.grant_id,
                    token.family,
                    token.scope,
                    token.stamp,
                    token.auth_time,
                    token.amr,
                    token.sid,
                    token.nonce,
                    token.created,
                    token.expires
                ],
            )
            .map(drop)
        })
        .await
    }

    /// Use a refresh token up. A token used a second time ends its family.
    pub async fn use_refresh_token(&self, hash: &[u8]) -> Result<Refresh> {
        let hash = hash.to_vec();
        self.sqlite_write(move |tx| {
            let Some(token) = tx
                .query_row(
                    &format!("SELECT {REFRESH_COLUMNS} FROM refresh_tokens WHERE hash = ?1"),
                    [&hash],
                    refresh_from,
                )
                .optional()?
            else {
                return Ok(Refresh::Unknown);
            };
            if token.used.is_some() {
                tx.execute("DELETE FROM refresh_tokens WHERE family = ?1", [&token.family])?;
                return Ok(Refresh::Reused);
            }
            if token.expires.as_str() <= clock::now().as_str() {
                return Ok(Refresh::Unknown);
            }
            tx.execute("UPDATE refresh_tokens SET used = ?2 WHERE hash = ?1", params![hash, clock::now()])?;
            Ok(Refresh::Fresh(Box::new(token)))
        })
        .await
    }

    /// The refresh token with this hash, used or not.
    pub async fn refresh_token(&self, hash: &[u8]) -> Result<Option<RefreshToken>> {
        let hash = hash.to_vec();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!("SELECT {REFRESH_COLUMNS} FROM refresh_tokens WHERE hash = ?1"),
                [hash],
                refresh_from,
            )
            .optional()
        })
        .await
    }

    pub async fn revoke_family(&self, family: &str) -> Result<()> {
        let family = family.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM refresh_tokens WHERE family = ?1", [family]).map(drop))
            .await
    }

    /// Every refresh token of `person`, for "sign out everywhere".
    pub async fn revoke_refresh_tokens_of(&self, person: &str) -> Result<()> {
        let person = person.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "DELETE FROM refresh_tokens WHERE grant_id IN (SELECT id FROM grants WHERE person_id = ?1)",
                [person],
            )
            .map(drop)
        })
        .await
    }

    /// Note that the browser session `sid` signed in to `app`.
    pub async fn note_session_app(&self, sid: &str, app: &str, person: &str) -> Result<()> {
        let (sid, app, person) = (sid.to_string(), app.to_string(), person.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT OR IGNORE INTO session_apps (sid, app_id, person_id, created) VALUES (?1, ?2, ?3, ?4)",
                params![sid, app, person, clock::now()],
            )
            .map(drop)
        })
        .await
    }

    /// The apps session `sid` signed in to, forgotten at once: for logging them out.
    pub async fn take_session_apps(&self, sid: &str) -> Result<Vec<(String, String)>> {
        let sid = sid.to_string();
        self.sqlite_write(move |tx| {
            let apps: Vec<(String, String)> = {
                let mut statement = tx.prepare("SELECT app_id, person_id FROM session_apps WHERE sid = ?1")?;
                statement.query_map([&sid], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?
            };
            tx.execute("DELETE FROM session_apps WHERE sid = ?1", [&sid])?;
            Ok(apps)
        })
        .await
    }

    pub async fn registration_tokens(&self) -> Result<Vec<RegistrationToken>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(
                "SELECT id, name, uses_left, created_by, created, expires FROM registration_tokens ORDER BY created DESC",
            )?;
            statement.query_map([], registration_from)?.collect()
        })
        .await
    }

    pub async fn create_registration_token(
        &self,
        hash: Vec<u8>,
        name: &str,
        uses: i64,
        created_by: Option<&str>,
        expires: &str,
    ) -> Result<RegistrationToken> {
        let id = uuid::Uuid::new_v4().to_string();
        let (name, created_by, expires) = (name.to_string(), created_by.map(str::to_string), expires.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO registration_tokens (id, hash, name, uses_left, created_by, created, expires) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, hash, name, uses, created_by, clock::now(), expires],
            )?;
            tx.query_row(
                "SELECT id, name, uses_left, created_by, created, expires FROM registration_tokens WHERE id = ?1",
                [&id],
                registration_from,
            )
        })
        .await
    }

    /// Use one registration of the token with this hash. False when there is none left.
    pub async fn use_registration_token(&self, hash: &[u8]) -> Result<Option<RegistrationToken>> {
        let hash = hash.to_vec();
        self.sqlite_write(move |tx| {
            let changed = tx.execute(
                "UPDATE registration_tokens SET uses_left = uses_left - 1 WHERE hash = ?1 AND uses_left > 0 AND expires > ?2",
                params![hash, clock::now()],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            tx.query_row(
                "SELECT id, name, uses_left, created_by, created, expires FROM registration_tokens WHERE hash = ?1",
                [&hash],
                registration_from,
            )
            .optional()
        })
        .await
    }

    pub async fn delete_registration_token(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM registration_tokens WHERE id = ?1", [id]).map(|n| n == 1))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::people::NewPerson;
    use crate::test_store;

    #[tokio::test]
    async fn a_refresh_token_works_once_and_a_second_use_ends_the_family() {
        let (store, _dir) = test_store();
        let person = store
            .create_person(NewPerson { username: "nyu".into(), display_name: "Nyu".into(), ..NewPerson::default() })
            .await
            .unwrap();
        let app = store.create_app(App { client_id: "c".into(), name: "App".into(), ..App::default() }).await.unwrap();
        let grant = store.touch_grant(&app.id, &person.id, "openid", false).await.unwrap();
        let token = |hash: u8| RefreshToken {
            hash: vec![hash],
            grant_id: grant.id.clone(),
            family: "f".into(),
            scope: "openid".into(),
            stamp: "s".into(),
            auth_time: 0,
            amr: "[]".into(),
            sid: None,
            nonce: None,
            created: clock::now(),
            expires: clock::in_seconds(60),
            used: None,
        };
        store.add_refresh_token(token(1)).await.unwrap();
        assert!(matches!(store.use_refresh_token(&[1]).await.unwrap(), Refresh::Fresh(_)));
        store.add_refresh_token(token(2)).await.unwrap();
        assert_eq!(store.use_refresh_token(&[1]).await.unwrap(), Refresh::Reused);
        assert_eq!(store.use_refresh_token(&[2]).await.unwrap(), Refresh::Unknown, "the family is gone");
    }

    #[tokio::test]
    async fn a_grant_collects_scopes() {
        let (store, _dir) = test_store();
        let person = store
            .create_person(NewPerson { username: "nyu".into(), display_name: "Nyu".into(), ..NewPerson::default() })
            .await
            .unwrap();
        let app = store.create_app(App { client_id: "c".into(), name: "App".into(), ..App::default() }).await.unwrap();
        store.touch_grant(&app.id, &person.id, "openid profile", false).await.unwrap();
        let grant = store.touch_grant(&app.id, &person.id, "openid email", true).await.unwrap();
        assert_eq!(grant.scope, "openid profile email");
        assert!(grant.consented);
        assert!(store.revoke_grant(&person.id, &grant.id).await.unwrap());
        assert!(store.grant(&app.id, &person.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_registration_token_runs_out() {
        let (store, _dir) = test_store();
        store.create_registration_token(vec![9], "pairing", 1, None, &clock::in_seconds(60)).await.unwrap();
        assert!(store.use_registration_token(&[9]).await.unwrap().is_some());
        assert!(store.use_registration_token(&[9]).await.unwrap().is_none());
    }
}
