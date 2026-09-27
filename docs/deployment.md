# Running UwUAuth Server

- [With install.sh](#with-installsh)
- [With Let's Encrypt](#with-lets-encrypt)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [With your own certificate](#with-your-own-certificate)
- [Updates](#updates)
- [Backups](#backups)
- [Settings](#settings)
- [Without Docker](#without-docker)

UwUAuth Server runs in one container with one volume, `/data`: the database `uwuauth.db`, the
nightly backups under `backups/`, and with Let's Encrypt its account and certificate under
`acme/`. Everything that differs from one machine to the next is in `.env`.

Apps only accept a sign-in server — an OpenID Connect issuer, a SAML IdP, LDAPS — whose
certificate the system trusts. So there are two ways to run it: the server gets its own
certificate from Let's Encrypt, or a reverse proxy you already have does TLS in front of it.

> **0.0.x is the frame.** It serves, backs up and updates itself, but there are no people in it
> yet: those come with 0.1 ([the plan](plan.md)). This page grows with it — mail, the first
> admin, and the ports for LDAP and RADIUS get their sections when they arrive.

## With install.sh

On a Linux machine with a public name — a VPS, a box at home with port 443 forwarded:

```bash
curl -fsSLO https://github.com/MinifyX/UwUAuth-Server/releases/latest/download/install.sh
sudo bash install.sh
```

It installs Docker if it is missing, asks which of the two ways, sets up `/opt/uwuauth`, starts
the server and waits until it is healthy. Without questions:

```bash
sudo bash install.sh --domain auth.example.com --acme-email admin@example.com --yes
sudo bash install.sh --behind-proxy https://auth.example.com --yes
```

`sudo bash install.sh --help` lists every flag.

## With Let's Encrypt

`UWUAUTH_TLS=acme`. The server asks Let's Encrypt for a certificate for the name in
`UWUAUTH_PUBLIC` and renews it by itself, well before it runs out. It uses the TLS-ALPN-01
challenge: Let's Encrypt connects to port 443 of that name, so

- the name has to point to this machine (an A and/or AAAA record), and
- port 443 has to reach the container (`UWUAUTH_BIND=443`, and forwarded in your router if the
  box is at home).

Port 80 is not needed. The certificate and the ACME account are kept in the volume under
`acme/`, so a restart does not ask for a new one — Let's Encrypt only issues a few per week for
the same name. While trying things out, `UWUAUTH_ACME_DIRECTORY=staging` uses Let's Encrypt's
test CA, whose certificates no browser trusts but which has much higher limits.

The container counts as healthy once it has its certificate, which takes a few seconds to half a
minute on the first start. If it does not come: `docker compose logs uwuauth | grep certificate`
says what Let's Encrypt said.

## Behind a reverse proxy

`UWUAUTH_TLS=off`: the server speaks plain HTTP and listens on this machine only
(`UWUAUTH_BIND=127.0.0.1:8443`). Your proxy terminates TLS and passes requests on. Set
`UWUAUTH_TRUST_FORWARDED=on`, so the server sees who is asking and not only the proxy — and only
then, because anybody can send that header to a server that believes it.

Caddy:

```caddyfile
auth.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name auth.example.com;
    # ssl_certificate ... ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Forward auth — the proxy asking UwUAuth whether a request may pass to some other app — comes
with stage 5 and gets its own examples then.

### A proxy in a container

When the proxy itself runs as a Docker container on the same machine, `127.0.0.1` inside it is
the proxy's own, not the machine's: `reverse_proxy 127.0.0.1:8443` answers 502. The server joins
the proxy's Docker network instead and takes no port on the machine at all:

```bash
sudo bash install.sh --behind-proxy https://auth.example.com --proxy-network proxy --yes
```

The proxy then reaches it at `http://uwuauth:8443`. In an ipvlan or macvlan network, where every
container has an address of your network and the proxy reaches services by it, the server needs a
fixed one that no other machine uses:

```bash
sudo bash install.sh --behind-proxy https://auth.example.com \
  --proxy-network dmz --proxy-ip 192.0.2.64 --yes
```

and the proxy passes on to `http://192.0.2.64:8443`. Without the flags, install.sh asks for the
network once you choose the proxy. What it writes is `compose.override.yaml` next to
`compose.yaml`, which update.sh leaves alone; by hand it is:

```yaml
services:
  uwuauth:
    ports: !reset []        # Compose 2.24 or newer
    networks:
      proxy: {}             # or, in ipvlan/macvlan:  dmz: { ipv4_address: 192.0.2.64 }
networks:
  proxy:
    external: true
```

then `docker compose up -d`.

## With your own certificate

`UWUAUTH_TLS=files`, with `UWUAUTH_TLS_CERT` and `UWUAUTH_TLS_KEY` pointing at PEM files inside
the container — from certbot, a company CA, anything your apps trust. The server reads them
again within a minute when they change, so a renewal needs no restart. Mount them with a
`compose.override.yaml` next to `compose.yaml` (update.sh leaves that file alone):

```yaml
services:
  uwuauth:
    environment:
      UWUAUTH_TLS: files
      UWUAUTH_TLS_CERT: /certs/fullchain.pem
      UWUAUTH_TLS_KEY: /certs/privkey.pem
    volumes:
      - /etc/letsencrypt/live/auth.example.com:/certs:ro
```

The files must be readable by uid 10001, which the server runs as.

## Updates

```bash
cd /opt/uwuauth && sudo bash update.sh
```

It fetches a newer copy of itself first, then brings `compose.yaml` up to date (a file you changed
by hand stays unless you say `--force`), writes a backup, pulls the new image and waits for the
health check. If the new version does not come up, the one from before goes back in, with the
backup from just before if the new one had already changed the database.

`UWUAUTH_VERSION` in `.env` is what the machine follows: `latest` for stable releases, `beta` for
every release, `edge` for every commit on `main` that passed CI, or one exact version.
`sudo bash update.sh --version beta` switches.

Once a day the server asks GitHub whether there is something newer on that channel and says so
in its log. `UWUAUTH_UPDATE_CHECK=off` stops it. Nothing installs itself: a sign-in server that
could replace itself from the network would be one more way in.

## Backups

Every night, and before every update, the server writes a consistent copy of its database to
`/data/backups/uwuauth-<date>-<time>.db` and keeps the newest seven. It skips a backup rather than
fill the disk: a backup is only written if a twentieth of the disk (at least 256 MiB) stays free
afterwards.

Those backups protect against a bad update or a mistake, not against a dead disk. Copy them
somewhere else:

```bash
cd /opt/uwuauth
sudo docker compose exec uwuauth uwuauth-server backup
sudo docker compose cp uwuauth:/data/backups ./backups-copy
```

Putting one back — only with the server stopped:

```bash
cd /opt/uwuauth
sudo docker compose run --rm uwuauth restore            # lists them
sudo docker compose stop
sudo docker compose run --rm uwuauth restore uwuauth-2026-09-25-031000.db
sudo docker compose up -d
```

The database that was there is kept next to it as `uwuauth.db.before-restore-<time>`.

## Settings

All in `.env`, read when the container starts (`docker compose up -d` after a change). From 0.1
on, what a person changes while the server runs — mail, password rules, apps — lives in the
admin portal instead.

| Variable | Default | What it does |
| --- | --- | --- |
| `UWUAUTH_PUBLIC` | — | The address people and apps use, like `https://auth.example.com`. It becomes the issuer of every token later, so pick the name you keep. With `acme`, the name the certificate is for. |
| `UWUAUTH_TLS` | `off` | `acme`, `files` or `off` (see above). |
| `UWUAUTH_BIND` | `443` | Where the container's port is published on this machine: a port or `address:port`. |
| `UWUAUTH_VERSION` | `latest` | Image tag: `latest`, `beta`, `edge` or a version. |
| `UWUAUTH_ACME_EMAIL` | — | Where Let's Encrypt writes about certificates that did not renew. |
| `UWUAUTH_ACME_DIRECTORY` | `letsencrypt` | `letsencrypt`, `staging`, or the https address of another ACME directory. |
| `UWUAUTH_TLS_CERT`, `UWUAUTH_TLS_KEY` | `/data/tls/cert.pem`, `/data/tls/key.pem` | The PEM files for `files`. |
| `UWUAUTH_TRUST_FORWARDED` | `off` | Believe the address the proxy added last to `X-Forwarded-For`. Only behind a proxy that sets it. |
| `UWUAUTH_UPDATE_CHECK` | `on` | Ask GitHub once a day whether there is a newer release. |
| `RUST_LOG` | `info` for the server | How much it logs, e.g. `uwuauth_server=debug`. |

## Without Docker

```bash
cargo build --release -p uwuauth-server
UWUAUTH_DATA=/var/lib/uwuauth UWUAUTH_LISTEN=127.0.0.1:8443 ./target/release/uwuauth-server
```

It needs a directory to write to and nothing else. Behind a proxy as above; for TLS of its own,
`UWUAUTH_LISTEN=0.0.0.0:443` needs the right to bind a port below 1024
(`setcap cap_net_bind_service=+ep uwuauth-server`).
