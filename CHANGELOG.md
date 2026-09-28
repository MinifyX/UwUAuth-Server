# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

## 0.3.0-beta.1

**People, and three ways for apps to sign them in.** The first release to use: user management,
OpenID Connect and LDAP, together as one beta. Try it at home before anything depends on it.

**People and groups**

- People with a trash (30 days), nested groups with owners, `admins` and `everyone` from the
  start, extra fields per person, POSIX numbers, pictures, CSV and JSON import and export.
- **Invitations** by link and QR code, once, for seven days, groups preselected, by mail when
  there is a mail server. `install.sh --admin` prints the first admin's.
- **Signing in** with passkeys (also offered in the name field), passwords by NIST's rules
  (Have I Been Pwned by k-anonymity, off unless turned on), an authenticator app and recovery
  codes, a second factor required per group, sessions and devices to sign out of, "forgot
  password", a soft lock after wrong passwords, a mail about new devices.
- **Kids' accounts**: managers for people or groups, accounts without an address, a setup link
  as a QR code for the kid's tablet, time windows.
- **The self-service portal** for everybody and **the admin portal** at `/admin`: a first-run
  assistant (family or office), settings with a test mail, the event log in sentences, the
  server log, backups, API tokens for scripts (`docs/api.md`), import and export.
- CLI commands to get back in without a working admin: `invite`, `admin`, `reset-password`,
  `reset-two-factor`.

**OpenID Connect and OAuth 2**

- Authorization code with PKCE, refresh tokens that rotate (and revoke their whole family when
  one is used twice), client credentials, the device flow for TVs and command lines, userinfo,
  introspection, revocation, RP-initiated and back-channel logout. ID tokens RS256 or ES256.
- Apps in the admin portal from templates (Nextcloud, Immich, Jellyfin, Home Assistant,
  Forgejo/Gitea, Grafana, Paperless-ngx, Proxmox, Portainer, Audiobookshelf, Open WebUI), the
  secret shown once. Per app: allowed groups, time windows, a second factor, consent.
- "My apps" in the portal, with the access one gave and can take back.
- Apps that register themselves (RFC 7591), only with a token an admin made.
- Tested against Grafana, Forgejo and Nextcloud in a real browser.

**LDAP in the style of Active Directory**

- Off unless turned on; for your own network. LDAPS and StartTLS with the server's certificate.
- The same people and groups as `inetOrgPerson`/`posixAccount` and as AD's `user`/`group` at
  once, nested groups with `LDAP_MATCHING_RULE_IN_CHAIN`, paged results, AD's reasons for a
  refused bind.
- Accounts for apps in the admin portal; people bind with their password or an app password
  and see only themselves and their groups. Password changes with `ldappasswd` or AD's
  `unicodePwd`.
- Tested with SSSD on every build and with Nextcloud before releases.

**Security.** Three reviews of all of the above before this beta; what they found and what was
done is in [docs/security-review-2026-09.md](https://github.com/MinifyX/UwUAuth-Server/blob/main/docs/security-review-2026-09.md).

## 0.0.1

**The frame.** Nothing to sign in with yet — this release is the ground the rest is built on, and
the proof that building, testing, publishing, installing and updating work end to end. What comes
next, step by step, is in the [plan](https://github.com/MinifyX/UwUAuth-Server/blob/main/docs/plan.md).

- **One container, one volume.** A Docker image for amd64 and arm64, running as an unprivileged
  user on a read-only file system without any Linux capability.
- **TLS three ways**: a certificate from Let's Encrypt that the server gets and renews itself
  (port 443 only), certificate files that are read again when they change, or plain HTTP behind
  a reverse proxy.
- **`install.sh` and `update.sh`**: from an empty machine to a running server, also next to a
  proxy that runs in a container; updates with a backup first and the old version back if the
  new one does not come up. Channels `latest`, `beta`, `edge`.
- **The database**: SQLite with numbered schema steps, a backup every night and before every
  update (the newest seven kept), and `restore` to put one back.
- **`/healthz`, `/alive`** and **`/uwu/v1/server`**, which tells other programs that a UwUAuth
  answers here and which protocols it speaks — none yet.
- **A page of its own** at `/`, in German and English, light and dark, with Nyu as an ID badge.
