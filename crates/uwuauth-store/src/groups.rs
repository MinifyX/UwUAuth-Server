//! Groups, who is in them (people directly, and groups inside groups), and who owns them.
//!
//! Two groups are there from the start: `admins`, whose members run the server, and `everyone`,
//! which everybody is in without being written down. Neither can be deleted or renamed away from
//! what it is; the names can change.

use crate::people::unique;
use crate::{Result, Store, StoreError, clock};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use std::collections::{BTreeSet, HashMap, HashSet};

pub const ADMINS_ID: &str = "00000000-0000-4000-8000-000000000001";
pub const EVERYONE_ID: &str = "00000000-0000-4000-8000-000000000002";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: String,
    /// `admins` or `everyone` for the two that come with the server.
    pub builtin: Option<String>,
    pub gid_number: i64,
    pub require_mfa: bool,
    pub ldap_app_passwords_only: bool,
    pub created: String,
    pub updated: String,
}

const COLUMNS: &str =
    "id, name, description, builtin, gid_number, require_mfa, ldap_app_passwords_only, created, updated";

fn group_from(row: &Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        builtin: row.get(3)?,
        gid_number: row.get(4)?,
        require_mfa: row.get(5)?,
        ldap_app_passwords_only: row.get(6)?,
        created: row.get(7)?,
        updated: row.get(8)?,
    })
}

/// Who is in a group, as written down: people and groups directly in it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Members {
    pub people: Vec<String>,
    pub groups: Vec<String>,
    pub owners: Vec<String>,
}

/// Everything about groups at once, for lists and for working out who is in what.
#[derive(Debug, Clone, Default)]
pub struct Membership {
    /// Group id → people directly in it.
    pub people: HashMap<String, BTreeSet<String>>,
    /// Group id → groups directly in it.
    pub groups: HashMap<String, BTreeSet<String>>,
    /// Group id → its owners.
    pub owners: HashMap<String, BTreeSet<String>>,
}

impl Membership {
    /// Every group `person` is in, directly or through groups inside groups, `everyone` included.
    pub fn groups_of(&self, person: &str) -> BTreeSet<String> {
        let mut found: BTreeSet<String> = BTreeSet::from([EVERYONE_ID.to_string()]);
        let mut queue: Vec<String> = self
            .people
            .iter()
            .filter(|(_, members)| members.contains(person))
            .map(|(group, _)| group.clone())
            .collect();
        while let Some(group) = queue.pop() {
            if !found.insert(group.clone()) {
                continue;
            }
            for (outer, inner) in &self.groups {
                if inner.contains(&group) && !found.contains(outer) {
                    queue.push(outer.clone());
                }
            }
        }
        found
    }

    /// The groups `person` is directly in, `everyone` not counted.
    pub fn direct_groups_of(&self, person: &str) -> BTreeSet<String> {
        self.people.iter().filter(|(_, members)| members.contains(person)).map(|(group, _)| group.clone()).collect()
    }

    /// Everybody in `group`, directly or through groups inside it. For `everyone`, pass the list
    /// of all people as `everybody`.
    pub fn people_in(&self, group: &str, everybody: &[String]) -> BTreeSet<String> {
        if group == EVERYONE_ID {
            return everybody.iter().cloned().collect();
        }
        let mut seen = HashSet::new();
        let mut found = BTreeSet::new();
        let mut queue = vec![group.to_string()];
        while let Some(group) = queue.pop() {
            if !seen.insert(group.clone()) {
                continue;
            }
            if group == EVERYONE_ID {
                found.extend(everybody.iter().cloned());
                continue;
            }
            if let Some(people) = self.people.get(&group) {
                found.extend(people.iter().cloned());
            }
            if let Some(groups) = self.groups.get(&group) {
                queue.extend(groups.iter().cloned());
            }
        }
        found
    }

    /// Whether putting `inner` into `outer` would make a circle: `outer` is inside `inner` already.
    pub fn would_loop(&self, outer: &str, inner: &str) -> bool {
        let mut seen = HashSet::new();
        let mut queue = vec![inner.to_string()];
        while let Some(group) = queue.pop() {
            if group == outer {
                return true;
            }
            if seen.insert(group.clone())
                && let Some(groups) = self.groups.get(&group)
            {
                queue.extend(groups.iter().cloned());
            }
        }
        false
    }
}

fn load_membership(conn: &rusqlite::Connection) -> rusqlite::Result<Membership> {
    let mut membership = Membership::default();
    let read = |sql: &str, into: &mut HashMap<String, BTreeSet<String>>| -> rusqlite::Result<()> {
        let mut statement = conn.prepare_cached(sql)?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        for row in rows {
            let (group, member) = row?;
            into.entry(group).or_default().insert(member);
        }
        Ok(())
    };
    read("SELECT group_id, person_id FROM memberships", &mut membership.people)?;
    read("SELECT group_id, member_group_id FROM subgroups", &mut membership.groups)?;
    read("SELECT group_id, person_id FROM group_owners", &mut membership.owners)?;
    Ok(membership)
}

/// What an admin fills in for a group.
#[derive(Debug, Clone, Default)]
pub struct GroupFields {
    pub name: String,
    pub description: String,
    pub require_mfa: bool,
    pub ldap_app_passwords_only: bool,
}

impl Store {
    pub async fn groups(&self) -> Result<Vec<Group>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM groups ORDER BY builtin IS NULL, name COLLATE NOCASE"
            ))?;
            statement.query_map([], group_from)?.collect()
        })
        .await
    }

    pub async fn group(&self, id: &str) -> Result<Option<Group>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {COLUMNS} FROM groups WHERE id = ?1"), [id], group_from).optional()
        })
        .await
    }

    pub async fn group_by_name(&self, name: &str) -> Result<Option<Group>> {
        let name = name.trim().to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(&format!("SELECT {COLUMNS} FROM groups WHERE name = ?1"), [name], group_from).optional()
        })
        .await
    }

    pub async fn create_group(&self, fields: GroupFields) -> Result<Group> {
        let id = uuid::Uuid::new_v4().to_string();
        self.sqlite_write(move |tx| {
            let gid: i64 = tx.query_row("SELECT max(gid_number) + 1 FROM groups", [], |row| row.get(0))?;
            let now = clock::now();
            tx.execute(
                "INSERT INTO groups (id, name, description, gid_number, require_mfa, ldap_app_passwords_only, \
                 created, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![
                    id,
                    fields.name,
                    fields.description,
                    gid,
                    fields.require_mfa,
                    fields.ldap_app_passwords_only,
                    now
                ],
            )?;
            tx.query_row(&format!("SELECT {COLUMNS} FROM groups WHERE id = ?1"), [&id], group_from)
        })
        .await
        .map_err(unique)
    }

    pub async fn update_group(&self, id: &str, fields: GroupFields) -> Result<Option<Group>> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE groups SET name = ?2, description = ?3, require_mfa = ?4, ldap_app_passwords_only = ?5, \
                 updated = ?6 WHERE id = ?1",
                params![
                    id,
                    fields.name,
                    fields.description,
                    fields.require_mfa,
                    fields.ldap_app_passwords_only,
                    clock::now()
                ],
            )?;
            tx.query_row(&format!("SELECT {COLUMNS} FROM groups WHERE id = ?1"), [&id], group_from).optional()
        })
        .await
        .map_err(unique)
    }

    /// Delete a group that is not one of the two built in. False when there was none to delete.
    pub async fn delete_group(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM schedules WHERE subject_kind = 'group' AND subject_id = ?1", [&id])?;
            tx.execute("DELETE FROM groups WHERE id = ?1 AND builtin IS NULL", [&id]).map(|n| n == 1)
        })
        .await
    }

    /// Who is in what, all at once.
    pub async fn membership(&self) -> Result<Membership> {
        self.sqlite_read(load_membership).await
    }

    pub async fn members(&self, group: &str) -> Result<Members> {
        let group = group.to_string();
        self.sqlite_read(move |conn| {
            let list = |sql: &str| -> rusqlite::Result<Vec<String>> {
                let mut statement = conn.prepare_cached(sql)?;
                statement.query_map([&group], |row| row.get(0))?.collect()
            };
            Ok(Members {
                people: list("SELECT person_id FROM memberships WHERE group_id = ?1")?,
                groups: list("SELECT member_group_id FROM subgroups WHERE group_id = ?1")?,
                owners: list("SELECT person_id FROM group_owners WHERE group_id = ?1")?,
            })
        })
        .await
    }

    /// Put exactly these people, groups and owners into `group`. Refused with
    /// [`StoreError::Loop`] when a group would end up inside itself.
    pub async fn set_members(&self, group: &str, members: Members) -> Result<()> {
        let group = group.to_string();
        self.sqlite_write(move |tx| {
            let mut membership = load_membership(tx)?;
            membership.groups.insert(group.clone(), members.groups.iter().cloned().collect());
            if members.groups.iter().any(|inner| inner == EVERYONE_ID || membership.would_loop(&group, inner)) {
                return Ok(Err(StoreError::Loop));
            }
            replace(tx, "memberships", "person_id", &group, &members.people)?;
            replace(tx, "subgroups", "member_group_id", &group, &members.groups)?;
            replace(tx, "group_owners", "person_id", &group, &members.owners)?;
            tx.execute("UPDATE groups SET updated = ?2 WHERE id = ?1", params![group, clock::now()])?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Add `person` to `group`; nothing when they are in it already.
    pub async fn add_member(&self, group: &str, person: &str) -> Result<()> {
        let (group, person) = (group.to_string(), person.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("INSERT OR IGNORE INTO memberships (group_id, person_id) VALUES (?1, ?2)", [group, person])
                .map(drop)
        })
        .await
    }

    pub async fn remove_member(&self, group: &str, person: &str) -> Result<()> {
        let (group, person) = (group.to_string(), person.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM memberships WHERE group_id = ?1 AND person_id = ?2", [group, person]).map(drop)
        })
        .await
    }

    /// Put `person` into exactly these groups (directly), leaving groups inside groups alone.
    pub async fn set_groups_of(&self, person: &str, groups: Vec<String>) -> Result<()> {
        let person = person.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM memberships WHERE person_id = ?1", [&person])?;
            for group in groups.iter().filter(|group| group.as_str() != EVERYONE_ID) {
                tx.execute(
                    "INSERT OR IGNORE INTO memberships (group_id, person_id) VALUES (?1, ?2)",
                    [group, &person],
                )?;
            }
            Ok(())
        })
        .await
    }

    /// The admins: everybody in `admins`, directly or through a group inside it.
    pub async fn admin_ids(&self) -> Result<BTreeSet<String>> {
        let membership = self.membership().await?;
        Ok(membership.people_in(ADMINS_ID, &[]))
    }
}

fn replace(tx: &Transaction<'_>, table: &str, column: &str, group: &str, ids: &[String]) -> rusqlite::Result<()> {
    tx.execute(&format!("DELETE FROM {table} WHERE group_id = ?1"), [group])?;
    let mut insert =
        tx.prepare_cached(&format!("INSERT OR IGNORE INTO {table} (group_id, {column}) VALUES (?1, ?2)"))?;
    for id in ids {
        insert.execute([group, id])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::people::NewPerson;
    use crate::test_store;

    async fn person(store: &Store, name: &str) -> String {
        store
            .create_person(NewPerson { username: name.into(), display_name: name.into(), ..NewPerson::default() })
            .await
            .unwrap()
            .id
    }

    async fn group(store: &Store, name: &str) -> String {
        store.create_group(GroupFields { name: name.into(), ..GroupFields::default() }).await.unwrap().id
    }

    #[tokio::test]
    async fn two_groups_come_with_the_server() {
        let (store, _dir) = test_store();
        let groups = store.groups().await.unwrap();
        assert_eq!(groups.len(), 2);
        assert!(!store.delete_group(ADMINS_ID).await.unwrap());
        assert!(!store.delete_group(EVERYONE_ID).await.unwrap());
        let next = group(&store, "Familie").await;
        assert_eq!(store.group(&next).await.unwrap().unwrap().gid_number, 10002);
    }

    #[tokio::test]
    async fn groups_inside_groups_count() {
        let (store, _dir) = test_store();
        let (mia, papa) = (person(&store, "mia").await, person(&store, "papa").await);
        let (kids, family) = (group(&store, "kids").await, group(&store, "family").await);
        store.add_member(&kids, &mia).await.unwrap();
        store
            .set_members(&family, Members { people: vec![papa.clone()], groups: vec![kids.clone()], owners: vec![] })
            .await
            .unwrap();
        let membership = store.membership().await.unwrap();
        let of_mia = membership.groups_of(&mia);
        assert!(of_mia.contains(&kids) && of_mia.contains(&family) && of_mia.contains(EVERYONE_ID));
        assert!(!membership.groups_of(&papa).contains(&kids));
        let everybody = vec![mia.clone(), papa.clone()];
        assert_eq!(membership.people_in(&family, &everybody), BTreeSet::from([mia.clone(), papa.clone()]));
        assert_eq!(membership.people_in(EVERYONE_ID, &everybody).len(), 2);
    }

    #[tokio::test]
    async fn a_group_never_ends_up_inside_itself() {
        let (store, _dir) = test_store();
        let (a, b, c) = (group(&store, "a").await, group(&store, "b").await, group(&store, "c").await);
        store.set_members(&a, Members { groups: vec![b.clone()], ..Members::default() }).await.unwrap();
        store.set_members(&b, Members { groups: vec![c.clone()], ..Members::default() }).await.unwrap();
        let circle = store.set_members(&c, Members { groups: vec![a.clone()], ..Members::default() }).await;
        assert!(matches!(circle, Err(StoreError::Loop)));
        let everyone = store.set_members(&c, Members { groups: vec![EVERYONE_ID.into()], ..Members::default() }).await;
        assert!(matches!(everyone, Err(StoreError::Loop)), "everyone is in no group");
        assert!(store.members(&c).await.unwrap().groups.is_empty(), "nothing was written");
    }

    #[tokio::test]
    async fn admins_through_a_group_are_admins() {
        let (store, _dir) = test_store();
        let (nyu, papa) = (person(&store, "nyu").await, person(&store, "papa").await);
        let parents = group(&store, "parents").await;
        store.add_member(ADMINS_ID, &nyu).await.unwrap();
        store.add_member(&parents, &papa).await.unwrap();
        store
            .set_members(ADMINS_ID, Members { people: vec![nyu.clone()], groups: vec![parents], owners: vec![] })
            .await
            .unwrap();
        assert_eq!(store.admin_ids().await.unwrap(), BTreeSet::from([nyu, papa]));
    }
}
