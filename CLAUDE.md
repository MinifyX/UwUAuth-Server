# UwUAuth-Server

Identitätsserver der UwUSuite (Personen/Gruppen an einer Stelle): OIDC, LDAP, SCIM, Forward-Auth; SAML und RADIUS sind geplant (Stufe 6, `docs/plan.md`). Allgemeine Befehle/Regeln: siehe `~/Projects/CLAUDE.md`.

## Layout
- `crates/uwuauth-store`: Datenbank (SQLite, Migrationen `migrations/sqlite/NNNN_*.sql`, in `src/migrations.rs` per `include_str!` eingehängt).
- `crates/uwuauth-api`: HTTP-Seite: eigene API unter `/uwu` (`routes/`), `oidc/`, `forward_auth/`, `suite/` (Kopplung + SCIM), `webauthn.rs`, `totp.rs`, `tokens.rs`, `session.rs`.
- `crates/uwuauth-ldap`: LDAP-Server (AD-Dialekt: sAMAccountName, memberOf …). Kein Domain Controller, ausdrücklich kein Ziel.
- `crates/uwuauth-mail`: SMTP + Vorlagen (de/en). `crates/uwuauth-web`: bettet `web/dist` per `build.rs` ein.
- `crates/uwuauth-server`: Binary, Config, TLS, Update-Check, Subcommands (z. B. `invite --admin`).
- `web/`: Vite/React/TS (pnpm). `scripts/e2e/web.mjs` (Browser-E2E), `scripts/interop/` (echte Apps in Docker, eigener Workflow `interop.yml`, `run.sh <binary> [ldap|oidc|forward-auth|all]`; `nextcloud` nur explizit).
- `docs/`: `api.md`, `oidc.md`, `ldap.md`, `forward-auth.md`, `deployment.md`, `suite.md`.

## Befehle
- Gezielt: `cargo test -p uwuauth-api [filter]`, `-p uwuauth-store`, `-p uwuauth-ldap`; Integrationstests: `crates/uwuauth-server/tests/integration`, `crates/uwuauth-ldap/tests/integration` (neue Tests dort als `mod` einhängen).
- Web: `pnpm --dir web lint` (eslint + `scripts/check-i18n.mjs`: de/en-Schlüssel müssen übereinstimmen), `format:check` (prettier), `typecheck`, `test` (vitest).
- Interop/E2E brauchen Docker und ein linux/amd64-Binary mit Web-App; nicht routinemäßig laufen lassen.

## Fallen
- `Cargo.lock`, `web/pnpm-lock.yaml`, `scripts/interop/pnpm-lock.yaml`, `web/dist/` nie von Hand bearbeiten.
- Nach dem ersten `pnpm build` in `web/` `crates/uwuauth-web/build.rs` anfassen (`touch`), sonst bemerkt Cargo das neue `web/dist` nicht. Ohne Build läuft der Server, meldet aber „Web-App fehlt“.
- Migrationen nur anhängen (nächste Nummer), bestehende nie ändern.
- UI-Texte immer in beiden Sprachen pflegen (i18n-Check in `pnpm lint`); gemeinsame UI folgt UwUSuite-Design.
- Beispiele/Tests nur mit reservierten Domains (`auth.example.com`, `*.example.test`).

## Plan/Stand
- `docs/plan.md` (Stufen 0–5 fertig, als Nächstes SAML), `CHANGELOG.md` (nach `-beta.N`-Schema), `SECURITY.md`.

## Release
- Version in `Cargo.toml` (`workspace.package.version`, aktuell `0.5.0-beta.2`) heben; `CHANGELOG.md` braucht eine Zeile exakt `## <version>` (CI: `grep -qx`, Text wird ins GitHub-Release kopiert). Tag `vX` auf dem Merge-Commit.

## Security
- Sicherheitskritisch: OIDC (`uwuauth-api/src/oidc`, Redirect-URI, PKCE, Tokens), `tokens.rs`/`session.rs`/`crypto.rs`, `webauthn.rs`/`totp.rs`, `forward_auth/`, SCIM (`suite/scim.rs`), LDAP-Parser (`uwuauth-ldap`: `filter.rs`, `dn.rs`, `server.rs`), Passwort-Hashing (Argon2id), später SAML (XML-Signaturen) und RADIUS.
- Vor jedem Feature-Release den globalen Subagent `security-reviewer` über den Bereich seit dem letzten Tag laufen lassen; Ergebnis nach `docs/security-review-<version>.md` (bisher `docs/security-review-2026-09.md`).
