-- Stage 1: the directory. People, groups, how they sign in, and what the server remembers about
-- it. Every id is a UUID made by the server and never changes; names may.

CREATE TABLE people (
    id               TEXT PRIMARY KEY NOT NULL,
    username         TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name     TEXT NOT NULL,
    given_name       TEXT,
    family_name      TEXT,
    -- A kid's account may have none.
    email            TEXT COLLATE NOCASE UNIQUE,
    email_verified   INTEGER NOT NULL DEFAULT 0,
    language         TEXT NOT NULL DEFAULT 'de',
    disabled         INTEGER NOT NULL DEFAULT 0,
    -- Looked after by somebody else: no password reset by mail, the manager does it.
    managed          INTEGER NOT NULL DEFAULT 0,
    -- Argon2id, PHC string. None for somebody who only uses passkeys.
    password_hash    TEXT,
    password_changed TEXT,
    -- The authenticator app's secret, sealed with the server's key; and the last time step a
    -- code was used for, so no code works twice.
    totp_secret      TEXT,
    totp_step        INTEGER NOT NULL DEFAULT 0,
    -- Changes whenever a password, a passkey or the account's state changes: sessions and tokens
    -- that carry an older one stop working.
    security_stamp   TEXT NOT NULL,
    -- After this, the account signs in nowhere.
    expires          TEXT,
    -- For Linux machines and NAS over LDAP.
    uid_number       INTEGER NOT NULL UNIQUE,
    login_shell      TEXT,
    home_directory   TEXT,
    created          TEXT NOT NULL,
    updated          TEXT NOT NULL,
    last_login       TEXT,
    -- In the trash since then; gone for good 30 days later.
    deleted          TEXT
) STRICT;

-- A small JPEG, made small in the browser before it comes here.
CREATE TABLE avatars (
    person_id TEXT PRIMARY KEY NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    jpeg      BLOB NOT NULL,
    updated   TEXT NOT NULL
) STRICT;

CREATE TABLE groups (
    id                      TEXT PRIMARY KEY NOT NULL,
    name                    TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description             TEXT NOT NULL DEFAULT '',
    -- 'admins' and 'everyone' are there from the start and cannot be deleted. Everybody is in
    -- 'everyone' without being written down.
    builtin                 TEXT UNIQUE CHECK (builtin IN ('admins', 'everyone')),
    gid_number              INTEGER NOT NULL UNIQUE,
    -- Everybody in the group (or a group inside it) needs a second factor or a passkey.
    require_mfa             INTEGER NOT NULL DEFAULT 0,
    -- Over LDAP, only app passwords count for them, never the account's own password.
    ldap_app_passwords_only INTEGER NOT NULL DEFAULT 0,
    created                 TEXT NOT NULL,
    updated                 TEXT NOT NULL
) STRICT;

CREATE TABLE memberships (
    group_id  TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, person_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX memberships_person ON memberships (person_id);

-- Groups inside groups. Whoever is in the inner one is in the outer one too.
CREATE TABLE subgroups (
    group_id        TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    member_group_id TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, member_group_id),
    CHECK (group_id != member_group_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX subgroups_member ON subgroups (member_group_id);

-- Owners may change a group's members without being admins.
CREATE TABLE group_owners (
    group_id  TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, person_id)
) STRICT, WITHOUT ROWID;

-- Who looks after whom: parents their kids, a team lead a team. Directly, or everybody in a group.
CREATE TABLE managed_people (
    manager_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    person_id  TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    PRIMARY KEY (manager_id, person_id),
    CHECK (manager_id != person_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE managed_groups (
    manager_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (manager_id, group_id)
) STRICT, WITHOUT ROWID;

-- Attributes an admin adds to everybody: a room number, a birthday, a team.
CREATE TABLE attribute_defs (
    name          TEXT PRIMARY KEY NOT NULL,
    label         TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('text', 'number', 'date', 'choice')),
    -- For 'choice': a JSON array of the choices.
    choices       TEXT NOT NULL DEFAULT '[]',
    -- Whether people may set their own value in the self-service portal.
    self_editable INTEGER NOT NULL DEFAULT 0,
    position      INTEGER NOT NULL DEFAULT 0,
    created       TEXT NOT NULL
) STRICT;

CREATE TABLE attribute_values (
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    name      TEXT NOT NULL REFERENCES attribute_defs (name) ON DELETE CASCADE ON UPDATE CASCADE,
    value     TEXT NOT NULL,
    PRIMARY KEY (person_id, name)
) STRICT, WITHOUT ROWID;

CREATE TABLE passkeys (
    id            TEXT PRIMARY KEY NOT NULL,
    person_id     TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    -- COSE, as the authenticator sent it.
    public_key    BLOB NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL,
    created       TEXT NOT NULL,
    last_used     TEXT
) STRICT;

CREATE INDEX passkeys_person ON passkeys (person_id);

-- SHA-256 of each unused recovery code.
CREATE TABLE recovery_codes (
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    PRIMARY KEY (person_id, code_hash)
) STRICT, WITHOUT ROWID;

-- For what cannot do passkeys: LDAP binds today, RADIUS and mail apps later. Random and long, so
-- SHA-256 is enough to keep them.
CREATE TABLE app_passwords (
    id        TEXT PRIMARY KEY NOT NULL,
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    hash      BLOB NOT NULL UNIQUE,
    created   TEXT NOT NULL,
    last_used TEXT,
    last_ip   TEXT
) STRICT;

CREATE INDEX app_passwords_person ON app_passwords (person_id);

-- Signed-in browsers. The cookie holds the token; this, its SHA-256.
CREATE TABLE sessions (
    id         BLOB PRIMARY KEY NOT NULL,
    person_id  TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    created    TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    expires    TEXT NOT NULL,
    -- When the person last proved who they are: changing a password or a passkey asks again after
    -- a while.
    auth_time  TEXT NOT NULL,
    -- How: a JSON array like ["pwd","otp"] or ["hwk"], as OpenID Connect's `amr` has it.
    methods    TEXT NOT NULL DEFAULT '[]',
    -- Signed in, but has to set up a second factor before anything else.
    restricted INTEGER NOT NULL DEFAULT 0,
    remember   INTEGER NOT NULL DEFAULT 0,
    stamp      TEXT NOT NULL,
    device_id  TEXT,
    ip         TEXT,
    user_agent TEXT
) STRICT;

CREATE INDEX sessions_person ON sessions (person_id);

-- Browsers an account has signed in on, so a new one can be told about.
CREATE TABLE devices (
    person_id  TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    user_agent TEXT,
    PRIMARY KEY (person_id, device_id)
) STRICT, WITHOUT ROWID;

-- Links that work once: invitations, setting up a kid's account on its device, a new password, a
-- new address. The link holds the token; this, its SHA-256.
CREATE TABLE links (
    id         TEXT PRIMARY KEY NOT NULL,
    hash       BLOB NOT NULL UNIQUE,
    purpose    TEXT NOT NULL CHECK (purpose IN ('invite', 'setup', 'reset', 'verify')),
    person_id  TEXT REFERENCES people (id) ON DELETE CASCADE,
    -- What an invitation brings along (address, groups, role), or the address to confirm.
    data       TEXT NOT NULL DEFAULT '{}',
    created_by TEXT REFERENCES people (id) ON DELETE SET NULL,
    created    TEXT NOT NULL,
    expires    TEXT NOT NULL,
    used       TEXT
) STRICT;

CREATE INDEX links_person ON links (person_id);

-- When somebody may sign in, per person or per group, in the server's time zone. Somebody with
-- none, and in no group with any, may sign in any time. `app_id` narrows a window to one app
-- (stage 2); NULL is every app.
CREATE TABLE schedules (
    id           TEXT PRIMARY KEY NOT NULL,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('person', 'group')),
    subject_id   TEXT NOT NULL,
    app_id       TEXT,
    -- Monday is 1, Tuesday 2, … Sunday 64.
    days         INTEGER NOT NULL CHECK (days BETWEEN 1 AND 127),
    start_minute INTEGER NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
    end_minute   INTEGER NOT NULL CHECK (end_minute BETWEEN 1 AND 1440)
) STRICT;

CREATE INDEX schedules_subject ON schedules (subject_kind, subject_id);

-- For scripts: the admin API with a bearer token.
CREATE TABLE api_tokens (
    id         TEXT PRIMARY KEY NOT NULL,
    name       TEXT NOT NULL,
    hash       BLOB NOT NULL UNIQUE,
    read_only  INTEGER NOT NULL DEFAULT 0,
    created_by TEXT REFERENCES people (id) ON DELETE SET NULL,
    created    TEXT NOT NULL,
    expires    TEXT,
    last_used  TEXT
) STRICT;

-- What happened: every sign-in, refused or not, and every change, with who and from where. No
-- references, so it outlives who it is about.
CREATE TABLE events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    time      TEXT NOT NULL,
    kind      TEXT NOT NULL,
    actor_id  TEXT,
    person_id TEXT,
    target    TEXT,
    ip        TEXT,
    detail    TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX events_time ON events (time);
CREATE INDEX events_person ON events (person_id, time);

INSERT INTO groups (id, name, description, builtin, gid_number, created, updated) VALUES
    ('00000000-0000-4000-8000-000000000001', 'admins', '', 'admins', 10000,
     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('00000000-0000-4000-8000-000000000002', 'everyone', '', 'everyone', 10001,
     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
