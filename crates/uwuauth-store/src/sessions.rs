//! Signed-in browsers, the devices an account has used, and links that work once.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// SHA-256 of the token in the cookie.
    pub id: Vec<u8>,
    pub person_id: String,
    pub created: String,
    pub last_seen: String,
    pub expires: String,
    pub auth_time: String,
    /// JSON array of how: `pwd`, `otp`, `hwk`, `swk`, `mfa`, `rec`.
    pub methods: String,
    pub restricted: bool,
    pub remember: bool,
    pub stamp: String,
    pub device_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

const SESSION_COLUMNS: &str = "id, person_id, created, last_seen, expires, auth_time, methods, restricted, remember, \
     stamp, device_id, ip, user_agent";

fn session_from(row: &Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: row.get(0)?,
        person_id: row.get(1)?,
        created: row.get(2)?,
        last_seen: row.get(3)?,
        expires: row.get(4)?,
        auth_time: row.get(5)?,
        methods: row.get(6)?,
        restricted: row.get(7)?,
        remember: row.get(8)?,
        stamp: row.get(9)?,
        device_id: row.get(10)?,
        ip: row.get(11)?,
        user_agent: row.get(12)?,
    })
}

/// What a link is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// An invitation: somebody makes an account.
    Invite,
    /// A kid's account set up on its device, or a new account made by an admin: a first
    /// passkey or password.
    Setup,
    /// A new password.
    Reset,
    /// Confirming an address.
    Verify,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Invite => "invite",
            Purpose::Setup => "setup",
            Purpose::Reset => "reset",
            Purpose::Verify => "verify",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "invite" => Purpose::Invite,
            "setup" => Purpose::Setup,
            "reset" => Purpose::Reset,
            "verify" => Purpose::Verify,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub id: String,
    pub purpose: Purpose,
    pub person_id: Option<String>,
    /// JSON.
    pub data: String,
    pub created_by: Option<String>,
    pub created: String,
    pub expires: String,
    pub used: Option<String>,
}

fn link_from(row: &Row<'_>) -> rusqlite::Result<Link> {
    let purpose: String = row.get(1)?;
    Ok(Link {
        id: row.get(0)?,
        purpose: Purpose::parse(&purpose).unwrap_or(Purpose::Verify),
        person_id: row.get(2)?,
        data: row.get(3)?,
        created_by: row.get(4)?,
        created: row.get(5)?,
        expires: row.get(6)?,
        used: row.get(7)?,
    })
}

const LINK_COLUMNS: &str = "id, purpose, person_id, data, created_by, created, expires, used";

impl Store {
    pub async fn create_session(&self, session: Session) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                &format!(
                    "INSERT INTO sessions ({SESSION_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
                ),
                params![
                    session.id,
                    session.person_id,
                    session.created,
                    session.last_seen,
                    session.expires,
                    session.auth_time,
                    session.methods,
                    session.restricted,
                    session.remember,
                    session.stamp,
                    session.device_id,
                    session.ip,
                    session.user_agent
                ],
            )
            .map(drop)
        })
        .await
    }

    /// A session that has not run out.
    pub async fn session(&self, id: &[u8]) -> Result<Option<Session>> {
        let id = id.to_vec();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ?1 AND expires > ?2"),
                params![id, clock::now()],
                session_from,
            )
            .optional()
        })
        .await
    }

    pub async fn sessions_of(&self, person: &str) -> Result<Vec<Session>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE person_id = ?1 AND expires > ?2 ORDER BY last_seen DESC"
            ))?;
            statement.query_map(params![person, clock::now()], session_from)?.collect()
        })
        .await
    }

    /// Seen again: when, from where, and until when it lasts now.
    pub async fn touch_session(&self, id: &[u8], ip: &str, expires: &str) -> Result<()> {
        let (id, ip, expires) = (id.to_vec(), ip.to_string(), expires.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE sessions SET last_seen = ?2, ip = ?3, expires = max(expires, ?4) WHERE id = ?1",
                params![id, clock::now(), ip, expires],
            )
            .map(drop)
        })
        .await
    }

    /// Proved again who they are.
    pub async fn reauthenticated(&self, id: &[u8], methods: &str) -> Result<()> {
        let (id, methods) = (id.to_vec(), methods.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE sessions SET auth_time = ?2, methods = ?3 WHERE id = ?1",
                params![id, clock::now(), methods],
            )
            .map(drop)
        })
        .await
    }

    /// Set up the second factor it waited for: the session reaches everything now.
    pub async fn unrestrict(&self, id: &[u8]) -> Result<()> {
        let id = id.to_vec();
        self.sqlite_write(move |tx| tx.execute("UPDATE sessions SET restricted = 0 WHERE id = ?1", [id]).map(drop))
            .await
    }

    /// Keep a session going after the person's stamp changed because of what they did in it
    /// themselves: a new password signs out every other session, not this one.
    pub async fn restamp_session(&self, id: &[u8], stamp: &str) -> Result<()> {
        let (id, stamp) = (id.to_vec(), stamp.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE sessions SET stamp = ?2 WHERE id = ?1", params![id, stamp]).map(drop)
        })
        .await
    }

    pub async fn end_session(&self, id: &[u8]) -> Result<()> {
        let id = id.to_vec();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM sessions WHERE id = ?1", [id]).map(drop)).await
    }

    /// End one of `person`'s sessions, found by the start of its id as the list shows it.
    pub async fn end_session_of(&self, person: &str, id: &[u8]) -> Result<bool> {
        let (person, id) = (person.to_string(), id.to_vec());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM sessions WHERE person_id = ?1 AND id = ?2", params![person, id]).map(|n| n == 1)
        })
        .await
    }

    /// End every session of `person`, but `keep`.
    pub async fn end_sessions(&self, person: &str, keep: Option<&[u8]>) -> Result<usize> {
        let (person, keep) = (person.to_string(), keep.map(<[u8]>::to_vec).unwrap_or_default());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM sessions WHERE person_id = ?1 AND id != ?2", params![person, keep])
        })
        .await
    }

    /// Note that `person` used `device`. True when it had never been seen for them.
    pub async fn saw_device(&self, person: &str, device: &str, user_agent: Option<&str>) -> Result<bool> {
        let (person, device, user_agent) = (person.to_string(), device.to_string(), user_agent.map(str::to_string));
        self.sqlite_write(move |tx| {
            let now = clock::now();
            let new = tx.execute(
                "INSERT OR IGNORE INTO devices (person_id, device_id, first_seen, last_seen, user_agent) \
                 VALUES (?1, ?2, ?3, ?3, ?4)",
                params![person, device, now, user_agent],
            )? == 1;
            if !new {
                tx.execute(
                    "UPDATE devices SET last_seen = ?3, user_agent = ?4 WHERE person_id = ?1 AND device_id = ?2",
                    params![person, device, now, user_agent],
                )?;
            }
            Ok(new)
        })
        .await
    }

    /// Whether `person` has signed in on `device` before.
    pub async fn known_device(&self, person: &str, device: &str) -> Result<bool> {
        let (person, device) = (person.to_string(), device.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM devices WHERE person_id = ?1 AND device_id = ?2)",
                [person, device],
                |row| row.get(0),
            )
        })
        .await
    }

    /// Whether `person` has signed in anywhere before.
    pub async fn has_devices(&self, person: &str) -> Result<bool> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT EXISTS (SELECT 1 FROM devices WHERE person_id = ?1)", [person], |row| row.get(0))
        })
        .await
    }

    /// A link that works once until `expires`, found later by `hash`.
    pub async fn create_link(
        &self,
        hash: Vec<u8>,
        purpose: Purpose,
        person: Option<&str>,
        data: &str,
        created_by: Option<&str>,
        expires: &str,
    ) -> Result<Link> {
        let id = uuid::Uuid::new_v4().to_string();
        let (person, data, created_by, expires) =
            (person.map(str::to_string), data.to_string(), created_by.map(str::to_string), expires.to_string());
        self.sqlite_write(move |tx| {
            // A new link for the same thing replaces the one before: only the newest reset works.
            if let Some(person) = &person
                && purpose != Purpose::Invite
            {
                tx.execute(
                    "DELETE FROM links WHERE person_id = ?1 AND purpose = ?2 AND used IS NULL",
                    params![person, purpose.as_str()],
                )?;
            }
            tx.execute(
                "INSERT INTO links (id, hash, purpose, person_id, data, created_by, created, expires) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![id, hash, purpose.as_str(), person, data, created_by, clock::now(), expires],
            )?;
            tx.query_row(&format!("SELECT {LINK_COLUMNS} FROM links WHERE id = ?1"), [&id], link_from)
        })
        .await
    }

    /// A link for `purpose` by its hash, unused and not run out.
    pub async fn link(&self, hash: &[u8], purpose: Purpose) -> Result<Option<Link>> {
        let hash = hash.to_vec();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {LINK_COLUMNS} FROM links WHERE hash = ?1 AND purpose = ?2 AND used IS NULL AND expires > ?3"
                ),
                params![hash, purpose.as_str(), clock::now()],
                link_from,
            )
            .optional()
        })
        .await
    }

    /// Use a link up. False when somebody else was faster.
    pub async fn use_link(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE links SET used = ?2 WHERE id = ?1 AND used IS NULL", params![id, clock::now()])
                .map(|n| n == 1)
        })
        .await
    }

    /// Invitations nobody used yet, newest first, run-out ones included.
    pub async fn open_invitations(&self) -> Result<Vec<Link>> {
        self.sqlite_read(|conn| {
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {LINK_COLUMNS} FROM links WHERE purpose = 'invite' AND used IS NULL ORDER BY created DESC"
            ))?;
            statement.query_map([], link_from)?.collect()
        })
        .await
    }

    /// Links of `purpose` for `person` that still work.
    pub async fn open_links_of(&self, person: &str, purpose: Purpose) -> Result<Vec<Link>> {
        let person = person.to_string();
        self.sqlite_read(move |conn| {
            let mut statement = conn.prepare_cached(&format!(
                "SELECT {LINK_COLUMNS} FROM links WHERE person_id = ?1 AND purpose = ?2 AND used IS NULL AND expires > ?3"
            ))?;
            statement.query_map(params![person, purpose.as_str(), clock::now()], link_from)?.collect()
        })
        .await
    }

    pub async fn delete_link(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM links WHERE id = ?1", [id]).map(|n| n == 1)).await
    }

    /// Replace a link's secret, for "a new link" on an invitation: the old one stops working.
    pub async fn renew_link(&self, id: &str, hash: Vec<u8>, expires: &str) -> Result<Option<Link>> {
        let (id, expires) = (id.to_string(), expires.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE links SET hash = ?2, expires = ?3 WHERE id = ?1 AND used IS NULL",
                params![id, hash, expires],
            )?;
            tx.query_row(&format!("SELECT {LINK_COLUMNS} FROM links WHERE id = ?1 AND used IS NULL"), [&id], link_from)
                .optional()
        })
        .await
    }
}
