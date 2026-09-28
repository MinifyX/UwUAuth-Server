//! Accounts apps bind with over LDAP to read the directory.

use crate::people::unique;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapAccount {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_by: Option<String>,
    pub created: String,
    pub last_used: Option<String>,
    pub last_ip: Option<String>,
}

fn account_from(row: &Row<'_>) -> rusqlite::Result<LdapAccount> {
    Ok(LdapAccount {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        created_by: row.get(3)?,
        created: row.get(4)?,
        last_used: row.get(5)?,
        last_ip: row.get(6)?,
    })
}

const COLUMNS: &str = "id, name, description, created_by, created, last_used, last_ip";

impl Store {
    pub async fn ldap_accounts(&self) -> Result<Vec<LdapAccount>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(&format!("SELECT {COLUMNS} FROM ldap_accounts ORDER BY name"))?;
            statement.query_map([], account_from)?.collect()
        })
        .await
    }

    pub async fn create_ldap_account(
        &self,
        name: &str,
        description: &str,
        hash: Vec<u8>,
        created_by: Option<&str>,
    ) -> Result<LdapAccount> {
        let id = uuid::Uuid::new_v4().to_string();
        let (name, description, created_by) =
            (name.to_string(), description.to_string(), created_by.map(str::to_string));
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO ldap_accounts (id, name, description, hash, created_by, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, name, description, hash, created_by, clock::now()],
            )?;
            tx.query_row(&format!("SELECT {COLUMNS} FROM ldap_accounts WHERE id = ?1"), [&id], account_from)
        })
        .await
        .map_err(unique)
    }

    /// The account `name` if `hash` is its password's, noted as used from `ip`.
    pub async fn use_ldap_account(&self, name: &str, hash: Vec<u8>, ip: &str) -> Result<Option<LdapAccount>> {
        let (name, ip) = (name.to_string(), ip.to_string());
        self.sqlite_write(move |tx| {
            let changed = tx.execute(
                "UPDATE ldap_accounts SET last_used = ?3, last_ip = ?4 WHERE name = ?1 AND hash = ?2",
                params![name, hash, clock::now(), ip],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            tx.query_row(&format!("SELECT {COLUMNS} FROM ldap_accounts WHERE name = ?1"), [&name], account_from)
                .optional()
        })
        .await
    }

    /// A new password for an account.
    pub async fn renew_ldap_account(&self, id: &str, hash: Vec<u8>) -> Result<Option<LdapAccount>> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE ldap_accounts SET hash = ?2 WHERE id = ?1", params![id, hash])?;
            tx.query_row(&format!("SELECT {COLUMNS} FROM ldap_accounts WHERE id = ?1"), [&id], account_from).optional()
        })
        .await
    }

    pub async fn delete_ldap_account(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM ldap_accounts WHERE id = ?1", [id]).map(|n| n == 1)).await
    }
}

#[cfg(test)]
mod tests {
    use crate::test_store;

    #[tokio::test]
    async fn an_account_binds_only_with_its_password() {
        let (store, _dir) = test_store();
        store.create_ldap_account("nextcloud", "", vec![1; 32], None).await.unwrap();
        assert!(store.use_ldap_account("nextcloud", vec![2; 32], "192.0.2.1").await.unwrap().is_none());
        let used = store.use_ldap_account("NEXTCLOUD", vec![1; 32], "192.0.2.1").await.unwrap().unwrap();
        assert_eq!(used.last_ip.as_deref(), Some("192.0.2.1"));
    }
}
