# Signing in to apps with OpenID Connect

UwUAuth is an OpenID Connect provider and OAuth 2.0 authorization server. An app sends people
to UwUAuth to sign in — with a passkey, or a password and whatever second factor they have — and
gets back who they are, their groups, and tokens to call UwUAuth with.

- [Adding an app](#adding-an-app)
- [Who may use an app](#who-may-use-an-app)
- [Endpoints](#endpoints)
- [Scopes and claims](#scopes-and-claims)
- [Tokens](#tokens)
- [Signing out](#signing-out)
- [Devices without a browser](#devices-without-a-browser)
- [Apps that register themselves](#apps-that-register-themselves)

## Adding an app

In the admin portal, *Apps → New app*. Pick a template if there is one for the app — Nextcloud,
Immich, Jellyfin, Home Assistant, Forgejo/Gitea, Grafana, Paperless-ngx, Proxmox, Portainer,
Audiobookshelf, Open WebUI — and type the app's own address: the template fills in the redirect
addresses and says what to set on the app's side. For anything else, *OpenID Connect* and the
redirect address from the app's documentation.

Every app gets a **client ID**, and — unless it runs on people's own devices and cannot keep a
secret (*public*) — a **client secret**, shown once. *New secret* makes another; the old one
stops working at once.

What the app's side needs, whichever app it is:

| | |
| --- | --- |
| Issuer / discovery | `https://auth.example.com` / `https://auth.example.com/.well-known/openid-configuration` |
| Client ID, secret | from the portal |
| Scopes | `openid profile email groups` (see below) |
| PKCE | S256 — required for public apps, welcome for all |
| ID token algorithm | RS256 by default; ES256 if the app is set to it |

## Who may use an app

- **Groups**: an app can be for some groups only (*Allowed groups*). Everybody else sees a page
  that says so; the app gets nothing.
- **Time windows**: a person's (or their groups') windows apply to every app, or to one app
  only. Outside them, signing in to the app is refused — and so is its next refresh, so an app
  that is open already loses access within its access token's lifetime (15 minutes by default).
- **Second factor**: an app can ask for one. Somebody who signed in with a password alone
  confirms with a passkey or their authenticator app first.
- **Consent**: an app somebody else runs can ask people before it gets their data. Apps of the
  household or the office usually don't.

Being disabled, run out, or signing out everywhere ends an app's tokens as well.

## Endpoints

| | |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery (also at `/.well-known/oauth-authorization-server`) |
| `GET /oauth/jwks` | The public keys (RSA and P-256) |
| `GET/POST /oauth/authorize` | Authorization code flow; `response_mode` `query` or `form_post` |
| `POST /oauth/token` | `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code` |
| `GET/POST /oauth/userinfo` | Claims, with the access token as bearer |
| `POST /oauth/introspect` | RFC 7662, for apps with a secret, about their own tokens |
| `POST /oauth/revoke` | RFC 7009 |
| `POST /oauth/device_authorization` | RFC 8628 |
| `POST /oauth/register` | RFC 7591, with a registration token |
| `GET/POST /oauth/logout` | RP-initiated logout |

Client authentication at the token endpoint: `client_secret_basic`, `client_secret_post`, or
`none` for public apps. `prompt` understands `none`, `login`, `consent` and `select_account`;
`max_age` (`0` signs in again); `request` and `request_uri` are refused.

## Scopes and claims

| Scope | Claims |
| --- | --- |
| `openid` | `sub` — the person's id, which never changes (names and addresses may) |
| `profile` | `name`, `preferred_username`, `given_name`, `family_name`, `picture`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `groups` | `groups`: the names of every group the person is in, groups inside groups included, `everyone` left out |
| `roles` | `roles`: what the app's role mapping makes of the groups (*admins → admin*, …) |
| `attributes` | the admin's own attributes, each under its name |
| `offline_access` | accepted; refresh tokens come whenever the app may use them |

ID tokens carry `auth_time`, `amr` (`pwd`, `otp`, `hwk`, `mfa`, …), `sid`, `nonce` and
`at_hash` as well.

## Tokens

- **Access tokens** are JWTs (RFC 9068, `typ: at+jwt`), signed like the app's ID tokens, valid
  for the app's *access token minutes* (15 by default).
- **Refresh tokens** last the app's *refresh token days* (30 by default) and work **once**: each
  refresh brings a new one. A refresh token that comes back a second time was copied — the whole
  chain ends and the app has to sign the person in again. Every refresh checks again that the
  person may use the app.
- **Codes** work once, for a minute.

## Signing out

`/oauth/logout` with an `id_token_hint` for the person signed in signs them out at once and sends
the browser to `post_logout_redirect_uri` (one the app registered), with `state`. Without a
hint, the person confirms on UwUAuth's page first — otherwise any link could sign them out.

Apps with a **back-channel logout URI** get a logout token (OpenID Connect Back-Channel Logout
1.0, with `sid`) whenever a session they signed in with ends: signing out in the portal, or from
another app.

## Devices without a browser

A TV or a command line asks `/oauth/device_authorization`, shows the code (`XXXX-XXXX`) and the
address `https://auth.example.com/#/device`, and asks `/oauth/token` every five seconds until the
person has typed the code on their phone and confirmed. The app needs the device grant turned on.

## Apps that register themselves

An admin makes a **registration token** (*Apps → Registration tokens*: a name, how many apps may
register with it, how long it works). An app posts its metadata to `/oauth/register` with it as
bearer token and gets its client ID and secret. Redirect addresses there have to be `https`,
`http` to the device itself, or the app's own scheme. The UwUSuite's pairing (stage 4) builds on
this.
