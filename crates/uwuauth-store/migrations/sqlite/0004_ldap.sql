-- Stage 3: accounts apps bind with over LDAP to read the directory (Nextcloud, a NAS, SSSD).
-- People bind with their own password or an app password; these are for the apps themselves.
CREATE TABLE ldap_accounts (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    -- SHA-256 of the password, which is random and long.
    hash        BLOB NOT NULL,
    created_by  TEXT REFERENCES people (id) ON DELETE SET NULL,
    created     TEXT NOT NULL,
    last_used   TEXT,
    last_ip     TEXT
) STRICT;
