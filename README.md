<p align="center">
  <img src="brand/uwuauth-app-icon.svg" width="112" alt="UwUAuth logo" />
</p>

<h1 align="center">UwUAuth Server</h1>

<p align="center">
  The identity server I build for myself, because the others annoyed me. (◕‿◕✿)<br/>
  People and groups in one place · OIDC, LDAP the way AD speaks it, SAML, SCIM, RADIUS · Rust, one container
</p>

---

## Why this exists

At home everybody has an account in every app: the NAS, Jellyfin, Immich, Home Assistant, the
Wi-Fi, and in [UwUMail](https://github.com/MinifyX/UwUMail-Server) and
[UwULock](https://github.com/MinifyX/UwULock-Server) too. When somebody changes their password,
they change it five times. When a kid gets a tablet, somebody makes five accounts.

UwUAuth is the one place for people and groups. Apps sign in through it — with OpenID Connect,
with LDAP (spoken so that apps set to "Active Directory" believe it), SAML, RADIUS for the
Wi-Fi, or behind a reverse proxy — and the UwUSuite programs pair with it in a few clicks. Made
for a family first and a small office second, and built so that a company would not outgrow it.

- **Just for fun.** No company, no team, no schedule, no promises. I work on it when I have time
  and feel like it.
- **Written with AI.** Almost all of the code is written with Claude, because I'm honestly not a
  great programmer. Not your thing? No hard feelings.
- **Use it, fork it, do what you want with it.** The license (AGPL-3.0) only asks one thing: if
  you pass on a changed version, or run one for others, its source stays open too.
- **No support.** Issues and pull requests are okay, but I might answer late or not at all.

> **Status: 0.3 beta.** People, groups, passkeys, two-step login, invitations, kids' accounts,
> the self-service and admin portal (0.1), signing in to apps with OpenID Connect (0.2), and LDAP
> in Active Directory's dialect for a NAS, Linux logins and older apps (0.3). A beta: try it at
> home, not yet for the only way into something important. Pairing with the UwUSuite is next.
> The [plan](docs/plan.md) has every step (in German).

## What it will do

- **People and groups first.** Invitations by link or QR code, passkeys before passwords, two-step
  login, a self-service portal for everybody and an admin portal for whoever runs it.
- **Accounts for kids.** Parents manage their children's accounts: reset a password, set up a
  passkey on the kid's tablet, see where they signed in, and say which apps they may use and when.
- **Every common way to sign in**, one after another:
  OpenID Connect and OAuth 2 → LDAP with Active Directory's attributes → pairing with the
  UwUSuite → forward auth for Caddy, Traefik and nginx → SAML 2.0 → SCIM 2.0 → RADIUS for
  WPA-Enterprise Wi-Fi.
- **The UwUSuite, paired in a minute.** Type the address and a one-time code into UwUMail Server,
  UwULock Server or UwUSync, and they sign people in through UwUAuth and get their users and
  groups from it. Underneath it is plain OIDC and SCIM, so every suite program works with
  Keycloak or Authentik as well, and UwUAuth with every other app.

## What it won't do

- **Be a Windows domain controller.** LDAP in Active Directory's dialect, yes. Joining Windows
  PCs to a domain, Kerberos, NTLM and group policies, no — that is what Samba is for.
- **Talk to anybody behind your back.** No telemetry. The only connections it opens on its own
  are Let's Encrypt (if you use it), your mail server, a daily look at GitHub for a newer
  release (`UWUAUTH_UPDATE_CHECK=off` stops it), the sign-out notices apps ask for, and — only
  if an admin turns it on — Have I Been Pwned, which gets the first five characters of a
  password's SHA-1 hash and never the password.

## Install

On a Linux machine — a VPS, a NAS, a box at home — with a name pointing to it and port 443
reaching it, or behind a reverse proxy you already run:

```bash
curl -fsSLO https://github.com/MinifyX/UwUAuth-Server/releases/latest/download/install.sh
sudo bash install.sh
```

While 0.3 is a beta, the newest `install.sh` is the beta's (`latest` still points to 0.0.1,
which knows neither `--admin` nor `--ldap`):

```bash
curl -fsSLO https://github.com/MinifyX/UwUAuth-Server/releases/download/v0.3.0-beta.1/install.sh
sudo bash install.sh --version beta
```

It installs Docker when it is missing, asks whether the server gets its own certificate from
Let's Encrypt or sits behind your proxy, sets up `/opt/uwuauth` and starts it. Without questions:

```bash
sudo bash install.sh --domain auth.example.com --admin you@example.com --yes
sudo bash install.sh --behind-proxy https://auth.example.com --yes
# the proxy runs as a container here: the server joins its Docker network
sudo bash install.sh --behind-proxy https://auth.example.com --proxy-network proxy --yes
```

`--admin` prints the link to make the first admin's account with. LDAP is off unless asked for
(`--ldap --ldap-bind <an address in your network>`).

[docs/deployment.md](docs/deployment.md) has the rest: Caddy and nginx in front, your own
certificate, backups, every setting.

## Update

```bash
cd /opt/uwuauth && sudo bash update.sh
```

A backup first, then the new image, and the old one back if the new one does not come up.
`UWUAUTH_VERSION` in `.env` says what the machine follows: `latest`, `beta`, `edge` or one exact
version.

## Project layout

| Path                    | What lives there                                                          |
| ----------------------- | ------------------------------------------------------------------------- |
| `crates/uwuauth-store`  | The database: SQLite now, behind methods PostgreSQL can implement later    |
| `crates/uwuauth-api`    | HTTP: UwUAuth's own API under `/uwu/v1`, OpenID Connect and OAuth 2; later SAML, SCIM, forward auth |
| `crates/uwuauth-ldap`   | LDAP, in the dialects of OpenLDAP and Active Directory at once             |
| `crates/uwuauth-mail`   | Mail: SMTP and the templates, in German and English                        |
| `crates/uwuauth-web`    | The web app's files, embedded into the binary                              |
| `crates/uwuauth-server` | The program: settings, TLS and Let's Encrypt, commands, backups, updates  |
| `web/`                  | The web app (React): sign-in pages, self-service and admin portal          |
| `docker/`, `compose.yaml`, `install.sh`, `update.sh` | The container and how it gets onto a machine |
| `brand/`                | Nyu, as an ID badge                                                        |
| `docs/`                 | Plan, deployment, admin API, OpenID Connect, LDAP, the security review     |
| `scripts/`              | The browser test, and real apps (SSSD, Grafana, Forgejo, Nextcloud) in Docker |

## Development

Requirements: Rust stable, and Node 24 with pnpm for the web app. Docker for the container.

```bash
# the server, with a data directory next to the checkout
cargo run -p uwuauth-server

# the web app, built into the next cargo build, or served by Vite against the running server
cd web && pnpm install && pnpm build
cd web && pnpm dev

# what CI checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cd web && pnpm format:check && pnpm lint && pnpm typecheck && pnpm test
```

## The UwUSuite

UwUAuth is one of a family of programs I build for myself:
[UwUMail](https://github.com/MinifyX/UwUMail-Client) and
[UwUMail Server](https://github.com/MinifyX/UwUMail-Server),
[UwULock](https://github.com/MinifyX/UwULock-Client) and
[UwULock Server](https://github.com/MinifyX/UwULock-Server),
[UwUSSH](https://github.com/MinifyX/UwUSSH-Client), [UwURDP](https://github.com/MinifyX/UwURDP-Client)
and [UwUSync Server](https://github.com/MinifyX/UwUSync-Server),
[UwUNotes](https://github.com/MinifyX/UwUNotes-Client) and [UwUMirror](https://github.com/MinifyX/UwUMirror).

## License

[AGPL-3.0](LICENSE).
