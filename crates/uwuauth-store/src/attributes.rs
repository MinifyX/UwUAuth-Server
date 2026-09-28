//! Attributes an admin adds to everybody, and API tokens for scripts.

use crate::people::unique;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDef {
    /// Letters, digits and `_`: what LDAP and OpenID Connect call it.
    pub name: String,
    pub label: String,
    /// `text`, `number`, `date` or `choice`.
    pub kind: String,
    /// JSON array, for `choice`.
    pub choices: String,
    pub self_editable: bool,
    pub position: i64,
}

fn def_from(row: &Row<'_>) -> rusqlite::Result<AttributeDef> {
    Ok(AttributeDef {
        name: row.get(0)?,
        label: row.get(1)?,
        kind: row.get(2)?,
        choices: row.get(3)?,
        self_editable: row.get(4)?,
        position: row.get(5)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub read_only: bool,
    pub created_by: Option<String>,
    pub created: String,
    pub expires: Option<String>,
    pub last_used: Option<String>,
}

fn token_from(row: &Row<'_>) -> rusqlite::Result<ApiToken> {
    Ok(ApiToken {
        id: row.get(0)?,
        name: row.get(1)?,
        read_only: row.get(2)?,
        created_by: row.get(3)?,
        created: row.get(4)?,
        expires: row.get(5)?,
        last_used: row.get(6)?,
    })
}

impl Store {
    pub async fn attribute_defs(&self) -> Result<Vec<AttributeDef>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(
                "SELECT name, label, kind, choices, self_editable, position FROM attribute_defs ORDER BY position, name",
            )?;
            statement.query_map([], def_from)?.collect()
        })
        .await
    }

    /// Replace every definition with these. Values of attributes that are gone go with them.
    pub async fn set_attribute_defs(&self, defs: Vec<AttributeDef>) -> Result<()> {
        self.directory_write(move |tx| {
            let names: Vec<&str> = defs.iter().map(|def| def.name.as_str()).collect();
            let existing: Vec<String> = {
                let mut statement = tx.prepare("SELECT name FROM attribute_defs")?;
                statement.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?
            };
            for old in existing.iter().filter(|old| !names.contains(&old.as_str())) {
                tx.execute("DELETE FROM attribute_defs WHERE name = ?1", [old])?;
            }
            for (position, def) in defs.iter().enumerate() {
                tx.execute(
                    "INSERT INTO attribute_defs (name, label, kind, choices, self_editable, position, created) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (name) DO UPDATE SET label = excluded.label, \
                     kind = excluded.kind, choices = excluded.choices, self_editable = excluded.self_editable, \
                     position = excluded.position",
                    params![
                        def.name,
                        def.label,
                        def.kind,
                        def.choices,
                        def.self_editable,
                        position as i64,
                        clock::now()
                    ],
                )?;
            }
            Ok(())
        })
        .await
    }

    pub async fn attributes_of(&self, person: &str) -> Result<BTreeMap<String, String>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached("SELECT name, value FROM attribute_values WHERE person_id = ?1")?;
            statement.query_map([person], |row| Ok((row.get(0)?, row.get(1)?)))?.collect()
        })
        .await
    }

    /// Every person's attributes at once: person id → name → value.
    pub async fn all_attributes(&self) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached("SELECT person_id, name, value FROM attribute_values")?;
            let mut all: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
            for row in statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?)))? {
                let (person, name, value) = row?;
                all.entry(person).or_default().insert(name, value);
            }
            Ok(all)
        })
        .await
    }

    /// Set these attributes of `person`; an empty value removes one.
    pub async fn set_attributes(&self, person: &str, values: BTreeMap<String, String>) -> Result<()> {
        let person = person.to_string();
        self.directory_write(move |tx| {
            for (name, value) in values {
                if value.is_empty() {
                    tx.execute("DELETE FROM attribute_values WHERE person_id = ?1 AND name = ?2", [&person, &name])?;
                } else {
                    tx.execute(
                        "INSERT INTO attribute_values (person_id, name, value) VALUES (?1, ?2, ?3) \
                         ON CONFLICT (person_id, name) DO UPDATE SET value = excluded.value",
                        [&person, &name, &value],
                    )?;
                }
            }
            Ok(())
        })
        .await
    }

    pub async fn api_tokens(&self) -> Result<Vec<ApiToken>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(
                "SELECT id, name, read_only, created_by, created, expires, last_used FROM api_tokens ORDER BY created",
            )?;
            statement.query_map([], token_from)?.collect()
        })
        .await
    }

    pub async fn create_api_token(
        &self,
        name: &str,
        hash: Vec<u8>,
        read_only: bool,
        created_by: &str,
        expires: Option<String>,
    ) -> Result<ApiToken> {
        let id = uuid::Uuid::new_v4().to_string();
        let (name, created_by) = (name.to_string(), created_by.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO api_tokens (id, name, hash, read_only, created_by, created, expires) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, name, hash, read_only, created_by, clock::now(), expires],
            )?;
            tx.query_row(
                "SELECT id, name, read_only, created_by, created, expires, last_used FROM api_tokens WHERE id = ?1",
                [&id],
                token_from,
            )
        })
        .await
        .map_err(unique)
    }

    /// The token with this hash that has not run out, noted as used.
    pub async fn use_api_token(&self, hash: Vec<u8>) -> Result<Option<ApiToken>> {
        self.sqlite_write(move |tx| {
            let now = clock::now();
            tx.execute(
                "UPDATE api_tokens SET last_used = ?2 WHERE hash = ?1 AND (expires IS NULL OR expires > ?2)",
                params![hash, now],
            )?;
            tx.query_row(
                "SELECT id, name, read_only, created_by, created, expires, last_used FROM api_tokens \
                 WHERE hash = ?1 AND (expires IS NULL OR expires > ?2)",
                params![hash, now],
                token_from,
            )
            .optional()
        })
        .await
    }

    pub async fn delete_api_token(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM api_tokens WHERE id = ?1", [id]).map(|n| n == 1)).await
    }
}
