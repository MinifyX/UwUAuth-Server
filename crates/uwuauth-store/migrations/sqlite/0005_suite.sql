-- Stage 4: pairing with the UwUSuite, and pushing people and groups to apps over SCIM.

-- One-time codes an admin shows to pair a suite app: 15 minutes, once. Only the SHA-256 of the
-- code is kept; a used code keeps its row a while (hash gone), so the portal can tell the admin
-- which app took it.
CREATE TABLE pairing_codes (
    id             TEXT PRIMARY KEY NOT NULL,
    -- NULL once used.
    hash           BLOB UNIQUE,
    -- JSON array of group ids: who may use the app. Empty: everybody.
    allowed_groups TEXT NOT NULL DEFAULT '[]',
    -- JSON object: role id → group ids that get it.
    role_groups    TEXT NOT NULL DEFAULT '{}',
    created_by     TEXT REFERENCES people (id) ON DELETE SET NULL,
    created        TEXT NOT NULL,
    expires        TEXT NOT NULL,
    used           TEXT,
    app_id         TEXT REFERENCES apps (id) ON DELETE SET NULL
) STRICT;

-- What a paired suite app said about itself.
CREATE TABLE suite_apps (
    app_id    TEXT PRIMARY KEY NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    -- 'UwULock', 'UwUMail', …
    product   TEXT NOT NULL,
    version   TEXT NOT NULL DEFAULT '',
    url       TEXT NOT NULL,
    -- A PNG, 64 KiB at most.
    icon      BLOB,
    -- JSON array of {"id", "name", "description"}: the roles the app knows.
    roles     TEXT NOT NULL DEFAULT '[]',
    paired_by TEXT REFERENCES people (id) ON DELETE SET NULL,
    paired    TEXT NOT NULL
) STRICT;

-- Where UwUAuth pushes people and groups for an app (SCIM 2.0), with the token it sends.
CREATE TABLE scim_targets (
    app_id     TEXT PRIMARY KEY NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    base_url   TEXT NOT NULL,
    -- Sealed with the server's key: it has to be sent, so it cannot be a hash.
    token      TEXT NOT NULL,
    -- JSON array: 'User', 'Group'.
    resources  TEXT NOT NULL DEFAULT '["User","Group"]',
    -- What goes into userName: 'email' or 'username'.
    user_name  TEXT NOT NULL DEFAULT 'email',
    created    TEXT NOT NULL,
    -- The last push that went through without an error, and the last one that did not.
    synced     TEXT,
    tried      TEXT,
    error      TEXT
) STRICT;

-- What was pushed: the app's id for each person or group, and what it was sent last, so only
-- changes go out.
CREATE TABLE scim_objects (
    app_id    TEXT NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    -- 'user' or 'group'.
    kind      TEXT NOT NULL,
    local_id  TEXT NOT NULL,
    remote_id TEXT NOT NULL,
    -- JSON: the fields as last sent.
    sent      TEXT NOT NULL,
    PRIMARY KEY (app_id, kind, local_id)
) STRICT, WITHOUT ROWID;
