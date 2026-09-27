# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

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
