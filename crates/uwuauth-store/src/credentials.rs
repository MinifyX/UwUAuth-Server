//! How people prove who they are, besides the password on the person itself: passkeys, recovery
//! codes and app passwords.

use crate::people::unique;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

/// At most this many passkeys per person.
pub const MAX_PASSKEYS: i64 = 20;
/// At most this many app passwords per person.
pub const MAX_APP_PASSWORDS: i64 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    pub id: String,
    pub person_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub name: String,
    pub created: String,
    pub last_used: Option<String>,
}

fn passkey_from(row: &Row<'_>) -> rusqlite::Result<Passkey> {
    Ok(Passkey {
        id: row.get(0)?,
        person_id: row.get(1)?,
        credential_id: row.get(2)?,
        public_key: row.get(3)?,
        counter: row.get(4)?,
        name: row.get(5)?,
        created: row.get(6)?,
        last_used: row.get(7)?,
    })
}

const PASSKEY_COLUMNS: &str = "id, person_id, credential_id, public_key, counter, name, created, last_used";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPassword {
    pub id: String,
    pub person_id: String,
    pub name: String,
    pub created: String,
    pub last_used: Option<String>,
    pub last_ip: Option<String>,
}

fn app_password_from(row: &Row<'_>) -> rusqlite::Result<AppPassword> {
    Ok(AppPassword {
        id: row.get(0)?,
        person_id: row.get(1)?,
        name: row.get(2)?,
        created: row.get(3)?,
        last_used: row.get(4)?,
        last_ip: row.get(5)?,
    })
}

impl Store {
    pub async fn passkeys(&self, person: &str) -> Result<Vec<Passkey>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {PASSKEY_COLUMNS} FROM passkeys WHERE person_id = ?1 ORDER BY created"
            ))?;
            statement.query_map([person], passkey_from)?.collect()
        })
        .await
    }

    pub async fn passkey_by_credential(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        let credential_id = credential_id.to_vec();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!("SELECT {PASSKEY_COLUMNS} FROM passkeys WHERE credential_id = ?1"),
                [credential_id],
                passkey_from,
            )
            .optional()
        })
        .await
    }

    /// Keep a new passkey. False when the person has as many as they may.
    pub async fn add_passkey(&self, passkey: Passkey) -> Result<bool> {
        self.sqlite_write(move |tx| {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM passkeys WHERE person_id = ?1", [&passkey.person_id], |row| {
                    row.get(0)
                })?;
            if count >= MAX_PASSKEYS {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO passkeys (id, person_id, credential_id, public_key, counter, name, created) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    passkey.id,
                    passkey.person_id,
                    passkey.credential_id,
                    passkey.public_key,
                    passkey.counter,
                    passkey.name,
                    passkey.created
                ],
            )?;
            Ok(true)
        })
        .await
        .map_err(unique)
    }

    /// After a sign-in with it: the counter it is at now.
    pub async fn used_passkey(&self, id: &str, counter: u32) -> Result<()> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE passkeys SET counter = ?2, last_used = ?3 WHERE id = ?1",
                params![id, counter, clock::now()],
            )
            .map(drop)
        })
        .await
    }

    pub async fn rename_passkey(&self, person: &str, id: &str, name: &str) -> Result<bool> {
        let (person, id, name) = (person.to_string(), id.to_string(), name.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE passkeys SET name = ?3 WHERE id = ?1 AND person_id = ?2", params![id, person, name])
                .map(|n| n == 1)
        })
        .await
    }

    pub async fn remove_passkey(&self, person: &str, id: &str) -> Result<bool> {
        let (person, id) = (person.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM passkeys WHERE id = ?1 AND person_id = ?2", params![id, person]).map(|n| n == 1)
        })
        .await
    }

    /// Replace a person's recovery codes with these hashes (none: take them all away).
    pub async fn set_recovery_codes(&self, person: &str, hashes: Vec<Vec<u8>>) -> Result<()> {
        let person = person.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM recovery_codes WHERE person_id = ?1", [&person])?;
            for hash in hashes {
                tx.execute("INSERT INTO recovery_codes (person_id, code_hash) VALUES (?1, ?2)", params![person, hash])?;
            }
            Ok(())
        })
        .await
    }

    /// Use up a recovery code. False when there is no such unused code.
    pub async fn take_recovery_code(&self, person: &str, hash: Vec<u8>) -> Result<bool> {
        let person = person.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM recovery_codes WHERE person_id = ?1 AND code_hash = ?2", params![person, hash])
                .map(|n| n == 1)
        })
        .await
    }

    pub async fn recovery_codes_left(&self, person: &str) -> Result<i64> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT count(*) FROM recovery_codes WHERE person_id = ?1", [person], |row| row.get(0))
        })
        .await
    }

    pub async fn app_passwords(&self, person: &str) -> Result<Vec<AppPassword>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT id, person_id, name, created, last_used, last_ip FROM app_passwords \
                 WHERE person_id = ?1 ORDER BY created",
            )?;
            statement.query_map([person], app_password_from)?.collect()
        })
        .await
    }

    /// Keep a new app password by its hash. False when the person has as many as they may.
    pub async fn add_app_password(&self, person: &str, name: &str, hash: Vec<u8>) -> Result<Option<AppPassword>> {
        let (person, name) = (person.to_string(), name.to_string());
        let id = uuid::Uuid::new_v4().to_string();
        self.sqlite_write(move |tx| {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM app_passwords WHERE person_id = ?1", [&person], |row| row.get(0))?;
            if count >= MAX_APP_PASSWORDS {
                return Ok(None);
            }
            let now = clock::now();
            tx.execute(
                "INSERT INTO app_passwords (id, person_id, name, hash, created) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, person, name, hash, now],
            )?;
            Ok(Some(AppPassword { id, person_id: person, name, created: now, last_used: None, last_ip: None }))
        })
        .await
    }

    /// The app password of `person` with this hash, noted as used from `ip`.
    pub async fn use_app_password(&self, person: &str, hash: Vec<u8>, ip: &str) -> Result<Option<AppPassword>> {
        let (person, ip) = (person.to_string(), ip.to_string());
        self.sqlite_write(move |tx| {
            let changed = tx.execute(
                "UPDATE app_passwords SET last_used = ?3, last_ip = ?4 WHERE person_id = ?1 AND hash = ?2",
                params![person, hash, clock::now(), ip],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            tx.query_row(
                "SELECT id, person_id, name, created, last_used, last_ip FROM app_passwords \
                 WHERE person_id = ?1 AND hash = ?2",
                params![person, hash],
                app_password_from,
            )
            .optional()
        })
        .await
    }

    pub async fn remove_app_password(&self, person: &str, id: &str) -> Result<bool> {
        let (person, id) = (person.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM app_passwords WHERE id = ?1 AND person_id = ?2", params![id, person])
                .map(|n| n == 1)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::people::NewPerson;
    use crate::test_store;

    #[tokio::test]
    async fn a_recovery_code_works_once() {
        let (store, _dir) = test_store();
        let nyu = store
            .create_person(NewPerson { username: "nyu".into(), display_name: "Nyu".into(), ..NewPerson::default() })
            .await
            .unwrap();
        store.set_recovery_codes(&nyu.id, vec![vec![1], vec![2]]).await.unwrap();
        assert!(store.take_recovery_code(&nyu.id, vec![1]).await.unwrap());
        assert!(!store.take_recovery_code(&nyu.id, vec![1]).await.unwrap());
        assert_eq!(store.recovery_codes_left(&nyu.id).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn app_passwords_belong_to_their_person() {
        let (store, _dir) = test_store();
        let new = |name: &str| NewPerson { username: name.into(), display_name: name.into(), ..NewPerson::default() };
        let nyu = store.create_person(new("nyu")).await.unwrap();
        let mia = store.create_person(new("mia")).await.unwrap();
        let added = store.add_app_password(&nyu.id, "NAS", vec![7; 32]).await.unwrap().unwrap();
        assert!(store.use_app_password(&mia.id, vec![7; 32], "192.0.2.1").await.unwrap().is_none());
        let used = store.use_app_password(&nyu.id, vec![7; 32], "192.0.2.1").await.unwrap().unwrap();
        assert_eq!(used.id, added.id);
        assert_eq!(used.last_ip.as_deref(), Some("192.0.2.1"));
        assert!(!store.remove_app_password(&mia.id, &added.id).await.unwrap());
        assert!(store.remove_app_password(&nyu.id, &added.id).await.unwrap());
    }
}
