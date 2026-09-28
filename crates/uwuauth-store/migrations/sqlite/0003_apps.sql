-- Stage 2: apps that sign people in through UwUAuth, with OpenID Connect and OAuth 2.

CREATE TABLE apps (
    id                        TEXT PRIMARY KEY NOT NULL,
    client_id                 TEXT NOT NULL UNIQUE,
    name                      TEXT NOT NULL,
    description               TEXT NOT NULL DEFAULT '',
    -- The template it was made from, like 'nextcloud'; NULL for one made by hand.
    template                  TEXT,
    -- SHA-256 of the client secret. NULL: a public client (an app on a phone or a desktop, a
    -- single-page app), which proves itself with PKCE instead.
    secret_hash               BLOB,
    -- JSON arrays.
    redirect_uris             TEXT NOT NULL DEFAULT '[]',
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    backchannel_logout_uri    TEXT,
    grant_types               TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
    -- 'client_secret_basic', 'client_secret_post' or 'none'.
    token_auth_method         TEXT NOT NULL DEFAULT 'client_secret_basic',
    -- 'RS256' (what OpenID Connect assumes) or 'ES256'.
    id_token_alg              TEXT NOT NULL DEFAULT 'RS256',
    -- Ask people before the app gets their data: for apps somebody else runs.
    consent                   INTEGER NOT NULL DEFAULT 0,
    -- PKCE even for a confidential client.
    require_pkce              INTEGER NOT NULL DEFAULT 0,
    -- Only people in one of these groups may use it; empty: everybody.
    allowed_groups            TEXT NOT NULL DEFAULT '[]',
    -- A passkey or a second factor for this app.
    require_mfa               INTEGER NOT NULL DEFAULT 0,
    -- JSON array of {"group": id, "role": "admin"}: what goes into the `roles` claim.
    roles                     TEXT NOT NULL DEFAULT '[]',
    access_token_minutes      INTEGER NOT NULL DEFAULT 15,
    refresh_token_days        INTEGER NOT NULL DEFAULT 30,
    -- Where "My apps" sends people.
    launch_url                TEXT,
    disabled                  INTEGER NOT NULL DEFAULT 0,
    created_by                TEXT REFERENCES people (id) ON DELETE SET NULL,
    created                   TEXT NOT NULL,
    updated                   TEXT NOT NULL
) STRICT;

-- What a person allowed an app, and that they use it: one per person and app.
CREATE TABLE grants (
    id        TEXT PRIMARY KEY NOT NULL,
    app_id    TEXT NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    -- Space-separated, as OAuth writes scopes.
    scope     TEXT NOT NULL,
    consented INTEGER NOT NULL DEFAULT 0,
    created   TEXT NOT NULL,
    last_used TEXT NOT NULL,
    UNIQUE (app_id, person_id)
) STRICT;

CREATE INDEX grants_person ON grants (person_id);

-- Refresh tokens, by the SHA-256 of the token. Each is used once and replaced; one of a family
-- used a second time means it was stolen, and the whole family ends.
CREATE TABLE refresh_tokens (
    hash       BLOB PRIMARY KEY NOT NULL,
    grant_id   TEXT NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    family     TEXT NOT NULL,
    scope      TEXT NOT NULL,
    -- The person's security stamp when it was made: a new password or "sign out everywhere"
    -- makes it worthless.
    stamp      TEXT NOT NULL,
    auth_time  INTEGER NOT NULL,
    amr        TEXT NOT NULL DEFAULT '[]',
    sid        TEXT,
    nonce      TEXT,
    created    TEXT NOT NULL,
    expires    TEXT NOT NULL,
    used       TEXT
) STRICT;

CREATE INDEX refresh_tokens_family ON refresh_tokens (family);
CREATE INDEX refresh_tokens_grant ON refresh_tokens (grant_id);

-- Which apps a browser session signed in to, for logging them out with it (back-channel).
CREATE TABLE session_apps (
    sid    TEXT NOT NULL,
    app_id TEXT NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    person_id TEXT NOT NULL REFERENCES people (id) ON DELETE CASCADE,
    created TEXT NOT NULL,
    PRIMARY KEY (sid, app_id)
) STRICT, WITHOUT ROWID;

-- Tokens an admin hands to an app so it can register itself (RFC 7591): the UwUSuite's pairing
-- builds on them.
CREATE TABLE registration_tokens (
    id         TEXT PRIMARY KEY NOT NULL,
    hash       BLOB NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    -- How many apps may still register with it.
    uses_left  INTEGER NOT NULL DEFAULT 1,
    created_by TEXT REFERENCES people (id) ON DELETE SET NULL,
    created    TEXT NOT NULL,
    expires    TEXT NOT NULL
) STRICT;
