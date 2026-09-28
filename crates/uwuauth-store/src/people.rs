//! People: who they are, and the parts of how they sign in that live on the person itself (the
//! password hash and the authenticator app's secret).

use crate::{Result, Store, StoreError, clock};
use rusqlite::{OptionalExtension, Row, params};

/// Where uid numbers start. Below are the system's own users.
pub const FIRST_UID: i64 = 10000;

/// Days a person stays in the trash before they are gone for good.
pub const TRASH_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub language: String,
    pub disabled: bool,
    pub managed: bool,
    pub password_hash: Option<String>,
    pub password_changed: Option<String>,
    /// Sealed; the API opens it.
    pub totp_secret: Option<String>,
    pub totp_step: i64,
    pub security_stamp: String,
    pub expires: Option<String>,
    pub uid_number: i64,
    pub login_shell: Option<String>,
    pub home_directory: Option<String>,
    pub created: String,
    pub updated: String,
    pub last_login: Option<String>,
    pub deleted: Option<String>,
}

impl Person {
    /// Whether the account may sign in at all right now: not disabled, not in the trash, not run
    /// out.
    pub fn active(&self) -> bool {
        !self.disabled
            && self.deleted.is_none()
            && self.expires.as_deref().is_none_or(|expires| clock::now().as_str() < expires)
    }
}

const COLUMNS: &str = "id, username, display_name, given_name, family_name, email, email_verified, language, \
     disabled, managed, password_hash, password_changed, totp_secret, totp_step, security_stamp, expires, \
     uid_number, login_shell, home_directory, created, updated, last_login, deleted";

pub(crate) fn person_from(row: &Row<'_>) -> rusqlite::Result<Person> {
    Ok(Person {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        given_name: row.get(3)?,
        family_name: row.get(4)?,
        email: row.get(5)?,
        email_verified: row.get(6)?,
        language: row.get(7)?,
        disabled: row.get(8)?,
        managed: row.get(9)?,
        password_hash: row.get(10)?,
        password_changed: row.get(11)?,
        totp_secret: row.get(12)?,
        totp_step: row.get(13)?,
        security_stamp: row.get(14)?,
        expires: row.get(15)?,
        uid_number: row.get(16)?,
        login_shell: row.get(17)?,
        home_directory: row.get(18)?,
        created: row.get(19)?,
        updated: row.get(20)?,
        last_login: row.get(21)?,
        deleted: row.get(22)?,
    })
}

/// What it takes to make somebody.
#[derive(Debug, Clone, Default)]
pub struct NewPerson {
    /// The id to give them; a new one when none. An invitation's account gets the invitation's
    /// id, which the passkey made while accepting it carries already.
    pub id: Option<String>,
    pub username: String,
    pub display_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub language: String,
    pub managed: bool,
}

/// A new security stamp.
pub fn stamp() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A UNIQUE constraint becomes [`StoreError::Exists`], which the API turns into "that name is
/// taken".
pub(crate) fn unique(error: StoreError) -> StoreError {
    match &error {
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(failure, _))
            if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY =>
        {
            StoreError::Exists
        }
        _ => error,
    }
}

impl Store {
    /// Make a person, with the next free uid number.
    pub async fn create_person(&self, new: NewPerson) -> Result<Person> {
        let id = new.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let now = clock::now();
        self.directory_write(move |tx| {
            let uid: i64 =
                tx.query_row("SELECT max(coalesce(max(uid_number) + 1, ?1), ?1) FROM people", [FIRST_UID], |row| {
                    row.get(0)
                })?;
            tx.execute(
                "INSERT INTO people (id, username, display_name, given_name, family_name, email, email_verified, \
                     language, managed, security_stamp, uid_number, created, updated) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
                params![
                    id,
                    new.username,
                    new.display_name,
                    new.given_name,
                    new.family_name,
                    new.email,
                    new.email_verified,
                    new.language,
                    new.managed,
                    stamp(),
                    uid,
                    now
                ],
            )?;
            tx.query_row(&format!("SELECT {COLUMNS} FROM people WHERE id = ?1"), [&id], person_from)
        })
        .await
        .map_err(unique)
    }

    pub async fn person(&self, id: &str) -> Result<Option<Person>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {COLUMNS} FROM people WHERE id = ?1"), [id], person_from).optional()
        })
        .await
    }

    /// By user name or address, whichever `login` is. Names never hold an `@`, so it is never both.
    pub async fn person_by_login(&self, login: &str) -> Result<Option<Person>> {
        let login = login.trim().to_string();
        self.sqlite_read(move |conn| {
            let column = if login.contains('@') { "email" } else { "username" };
            conn.query_row(&format!("SELECT {COLUMNS} FROM people WHERE {column} = ?1"), [login], person_from)
                .optional()
        })
        .await
    }

    /// Everybody, trash included, by name.
    pub async fn people(&self) -> Result<Vec<Person>> {
        self.sqlite_read(|conn| {
            let mut statement =
                conn.prepare_cached(&format!("SELECT {COLUMNS} FROM people ORDER BY display_name COLLATE NOCASE"))?;
            statement.query_map([], person_from)?.collect()
        })
        .await
    }

    /// Change what `change` changes and write the person back. `updated` is set here; the stamp
    /// only when `change` sets a new one.
    pub async fn update_person(&self, id: &str, change: impl FnOnce(&mut Person) + Send + 'static) -> Result<Person> {
        let id = id.to_string();
        self.directory_write(move |tx| {
            let mut person =
                tx.query_row(&format!("SELECT {COLUMNS} FROM people WHERE id = ?1"), [&id], person_from)?;
            change(&mut person);
            person.updated = clock::now();
            tx.execute(
                "UPDATE people SET username = ?2, display_name = ?3, given_name = ?4, family_name = ?5, email = ?6, \
                 email_verified = ?7, language = ?8, disabled = ?9, managed = ?10, password_hash = ?11, \
                 password_changed = ?12, totp_secret = ?13, totp_step = ?14, security_stamp = ?15, expires = ?16, \
                 uid_number = ?17, login_shell = ?18, home_directory = ?19, updated = ?20, last_login = ?21, \
                 deleted = ?22 WHERE id = ?1",
                params![
                    person.id,
                    person.username,
                    person.display_name,
                    person.given_name,
                    person.family_name,
                    person.email,
                    person.email_verified,
                    person.language,
                    person.disabled,
                    person.managed,
                    person.password_hash,
                    person.password_changed,
                    person.totp_secret,
                    person.totp_step,
                    person.security_stamp,
                    person.expires,
                    person.uid_number,
                    person.login_shell,
                    person.home_directory,
                    person.updated,
                    person.last_login,
                    person.deleted,
                ],
            )?;
            Ok(person)
        })
        .await
        .map_err(unique)
    }

    /// Take an authenticator code's time step, if it is later than the last one used: a code
    /// works once. False when it was used already.
    pub async fn take_totp_step(&self, id: &str, step: i64) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE people SET totp_step = ?2 WHERE id = ?1 AND totp_step < ?2", params![id, step])
                .map(|changed| changed == 1)
        })
        .await
    }

    /// Note a sign-in.
    pub async fn touch_login(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE people SET last_login = ?2 WHERE id = ?1", params![id, clock::now()]).map(drop)
        })
        .await
    }

    /// Gone for good, with everything that hangs on them.
    pub async fn purge_person(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.directory_write(move |tx| tx.execute("DELETE FROM people WHERE id = ?1", [id]).map(|n| n == 1)).await
    }

    pub async fn avatar(&self, id: &str) -> Result<Option<(Vec<u8>, String)>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT jpeg, updated FROM avatars WHERE person_id = ?1", [id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
        })
        .await
    }

    /// Which people have an avatar, for lists.
    pub async fn avatar_ids(&self) -> Result<Vec<String>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached("SELECT person_id FROM avatars")?;
            statement.query_map([], |row| row.get(0))?.collect()
        })
        .await
    }

    pub async fn set_avatar(&self, id: &str, jpeg: Option<Vec<u8>>) -> Result<()> {
        let id = id.to_string();
        self.directory_write(move |tx| match jpeg {
            Some(jpeg) => tx
                .execute(
                    "INSERT INTO avatars (person_id, jpeg, updated) VALUES (?1, ?2, ?3) \
                     ON CONFLICT (person_id) DO UPDATE SET jpeg = excluded.jpeg, updated = excluded.updated",
                    params![id, jpeg, clock::now()],
                )
                .map(drop),
            None => tx.execute("DELETE FROM avatars WHERE person_id = ?1", [id]).map(drop),
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::test_store;

    use super::*;

    pub(crate) fn nyu() -> NewPerson {
        NewPerson {
            username: "nyu".into(),
            display_name: "Nyu".into(),
            email: Some("nyu@example.com".into()),
            language: "de".into(),
            ..NewPerson::default()
        }
    }

    #[tokio::test]
    async fn people_get_uid_numbers_one_after_another() {
        let (store, _dir) = test_store();
        let first = store.create_person(nyu()).await.unwrap();
        let second = store
            .create_person(NewPerson { username: "mia".into(), display_name: "Mia".into(), ..NewPerson::default() })
            .await
            .unwrap();
        assert_eq!(first.uid_number, FIRST_UID);
        assert_eq!(second.uid_number, FIRST_UID + 1);
        assert!(second.email.is_none(), "a kid needs no address");
    }

    #[tokio::test]
    async fn names_and_addresses_are_unique_whatever_the_case() {
        let (store, _dir) = test_store();
        store.create_person(nyu()).await.unwrap();
        let again = NewPerson { username: "NYU".into(), email: None, ..nyu() };
        assert!(matches!(store.create_person(again).await, Err(StoreError::Exists)));
        let same_mail = NewPerson { username: "other".into(), email: Some("Nyu@Example.com".into()), ..nyu() };
        assert!(matches!(store.create_person(same_mail).await, Err(StoreError::Exists)));
    }

    #[tokio::test]
    async fn found_by_name_or_address() {
        let (store, _dir) = test_store();
        let nyu = store.create_person(nyu()).await.unwrap();
        assert_eq!(store.person_by_login("NYU").await.unwrap().unwrap().id, nyu.id);
        assert_eq!(store.person_by_login(" nyu@EXAMPLE.com ").await.unwrap().unwrap().id, nyu.id);
        assert!(store.person_by_login("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_code_step_is_taken_once() {
        let (store, _dir) = test_store();
        let nyu = store.create_person(nyu()).await.unwrap();
        assert!(store.take_totp_step(&nyu.id, 100).await.unwrap());
        assert!(!store.take_totp_step(&nyu.id, 100).await.unwrap());
        assert!(!store.take_totp_step(&nyu.id, 99).await.unwrap());
        assert!(store.take_totp_step(&nyu.id, 101).await.unwrap());
    }

    #[tokio::test]
    async fn an_update_writes_every_field_back() {
        let (store, _dir) = test_store();
        let nyu = store.create_person(nyu()).await.unwrap();
        let changed = store
            .update_person(&nyu.id, |person| {
                person.display_name = "Nyu Neko".into();
                person.disabled = true;
                person.login_shell = Some("/bin/zsh".into());
            })
            .await
            .unwrap();
        let read = store.person(&nyu.id).await.unwrap().unwrap();
        assert_eq!(read, changed);
        assert!(!read.active());
    }
}
