-- Stage 5: forward auth. An app a reverse proxy guards: UwUAuth answers the proxy's question
-- "may this request through?" for the addresses below, instead of the app speaking OpenID Connect.

-- JSON array of addresses the app answers at: a host, optionally with a path prefix
-- ("app.example.com", "example.com/wiki"). Empty: an OpenID Connect app as before.
ALTER TABLE apps ADD COLUMN forward_auth TEXT NOT NULL DEFAULT '[]';
