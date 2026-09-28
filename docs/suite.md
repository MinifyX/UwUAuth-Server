# Pairing with the UwUSuite

UwUMail, UwULock and the UwUSuite's other servers connect to UwUAuth with a one-time code: the
admin makes a code in UwUAuth, types it (with UwUAuth's address) into the app, and the app gets
everything it needs — an OpenID Connect client for signing people in, and a token with which
UwUAuth pushes the people who may use it over SCIM. Nothing to copy by hand.

Underneath it is plain OpenID Connect and SCIM 2.0: a suite app works the same with Keycloak or
Authentik set up by hand, and pairing only saves the typing.

- [In the admin portal](#in-the-admin-portal)
- [The protocol](#the-protocol)
- [SCIM: what UwUAuth pushes](#scim-what-uwuauth-pushes)
- [SCIM for any app](#scim-for-any-app)
- [Finding UwUAuth](#finding-uwuauth)
- [The admin API](#the-admin-api)

## In the admin portal

*Apps → Pair a UwUSuite app*:

1. Pick **who may use the app** (nobody picked: everybody) and, optionally, **who is an admin
   there** (the app's `admin` role).
2. *Make a code* shows the code — `7KQ4-M2XD-9HFT`, 12 characters, once, for 15 minutes — and a
   QR code of `https://auth.example.com/#pair=7KQ4-M2XD-9HFT`, which suite apps take as a whole.
3. In the suite app, *Connect with UwUAuth*: UwUAuth's address and the code. The dialog in
   UwUAuth notices when the app used the code and leads to the app's page.

A paired app is an app like any other (see [OpenID Connect](oidc.md)), with a few things more on
its page: its icon, program and version, **roles** — the roles the app said it knows, each with
the groups that get it — and **people and groups (SCIM)**: when it was last synced, how many
people and groups it has, the last error. *Sync now* pushes at once, *Send everything again*
sends every person and group again, *Stop syncing* stops (what the app has stays there).
Deleting the app unpairs it; the app forgets the pairing on its side.

Open codes are listed under the apps and can be withdrawn. At most 20 are open at once.

## The protocol

### `GET /uwu/v1/server`

What the app asks first, without signing in:

```json
{
  "product": "UwUAuth",
  "version": "0.4.0",
  "name": "Familie Neko",
  "issuer": "https://auth.example.com",
  "protocols": ["oidc", "scim"],
  "openidConfiguration": "https://auth.example.com/.well-known/openid-configuration",
  "pairing": 1,
  "pair": "https://auth.example.com/uwu/v1/pair",
  "scim": true
}
```

`protocols` has `ldap` too when LDAP is on. An app pairs only with `product` `UwUAuth` and
`pairing` ≥ 1; `scim: true` means UwUAuth pushes people to apps.

### `POST /uwu/v1/pair`

No session and no token: the code is the proof. JSON in, JSON out.

```json
{
  "code": "7KQ4-M2XD-9HFT",
  "app": {
    "product": "UwULock",
    "version": "0.6.0",
    "name": "UwULock (lock.example.com)",
    "url": "https://lock.example.com",
    "icon": "data:image/png;base64,…",
    "redirectUris": ["https://lock.example.com/identity/connect/oidc-signin"],
    "postLogoutRedirectUris": ["https://lock.example.com/"],
    "backchannelLogoutUri": "https://lock.example.com/identity/connect/backchannel-logout",
    "scopes": ["openid", "email", "profile", "groups", "roles"],
    "roles": [
      { "id": "admin", "name": "Administrator", "description": "Uses the admin portal" },
      { "id": "user", "name": "User", "description": "May create a vault without an invitation" }
    ],
    "scim": {
      "baseUrl": "https://lock.example.com/scim/v2",
      "resources": ["User", "Group"],
      "userName": "email"
    }
  }
}
```

- `code`: as typed — capitals or not, with or without dashes and spaces, `I`/`L` read as `1` and
  `O` as `0` (Crockford's base32), or the whole QR text.
- `product` (required): a short name, letters, digits, space, `.`, `_`, `-`, up to 40.
  `version`: up to 40 characters. `name` (required): up to 80, what the app is called in UwUAuth.
- `url` (required): the app's own address, `https` (plain `http` only on `localhost`,
  `127.0.0.1` or `[::1]`). It becomes the app's tile in "My apps".
- `redirectUris` (1–20, required), `postLogoutRedirectUris` (up to 20), `backchannelLogoutUri`
  (optional): `https` on the host of `url`, or a loopback address (RFC 8252).
- `icon` (optional): a PNG as a `data:image/png;base64,` address, 64 KiB at most.
- `scopes` (optional): what the app will ask for. Unknown ones are left out, `openid` is always
  in. Default: `openid email profile groups roles`.
- `roles` (optional, up to 20): `id` lowercase letters, digits, `_`, `-`, `.`, up to 40; `name`
  and `description` for the admin portal.
- `scim` (optional): where UwUAuth pushes people. `baseUrl` is `https` on the host of `url`;
  `resources` `["User"]` or `["User", "Group"]` (default both); `userName` `email` (default:
  what the suite apps know people by) or `username`.

The answer, 200:

```json
{
  "issuer": "https://auth.example.com",
  "clientId": "uwulock-lock-example-com-k3j9x2",
  "clientSecret": "…",
  "tokenEndpointAuthMethod": "client_secret_basic",
  "scopes": ["openid", "email", "profile", "groups", "roles"],
  "groupsClaim": "groups",
  "rolesClaim": "roles",
  "scimToken": "…",
  "appId": "…",
  "manageUrl": "https://auth.example.com/admin#/apps/…"
}
```

`scimToken` is `null` when the app sent no `scim`. The app keeps the secret (and the SCIM token,
or its SHA-256: UwUAuth sends it as `Authorization: Bearer <token>`).

Errors are UwUAuth's usual `{"error": "<code>", "message": "…", "detail": {"field": "…"}}`:

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_code` | The code is unknown, used, withdrawn or ran out — always the same answer |
| 400 | `invalid` | The body is not JSON of this shape |
| 400 | `uri`, `icon`, `role`, `required`, `invalid` | A field is wrong (`detail.field`, e.g. `app.redirectUris`); the code stays usable |
| 429 | `too_many` | 10 tries per address, 60 in all, per 15 minutes |

What UwUAuth makes of it: a confidential OpenID Connect client (`client_secret_basic`, PKCE
required, `authorization_code` and `refresh_token`, no consent screen — it is the admin's own
app), allowed for the groups picked with the code, with the app's `url` as its tile. Its roles
get the groups picked with the code; a role `user` nobody picked groups for goes to whoever may
use the app. The ID token and userinfo carry `groups` (group names) and `roles` (the role ids
the person has) when the app asks for those scopes.

**Security.** Codes have 60 bits and last 15 minutes; with 60 tries per 15 minutes from anywhere
there is nothing to guess. Only the SHA-256 of a code is kept, every open code is compared in
constant time, and the code is used up in the same transaction that keeps the app — two
requests with one code make one app. Every refused code and every pairing is in the event log.

## SCIM: what UwUAuth pushes

To `scim.baseUrl`, with `Authorization: Bearer <scimToken>` and `application/scim+json`
(RFC 7643, RFC 7644). Redirects are not followed.

**People** — everybody who may use the app (all, or those in its allowed groups):

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "mia@example.com",
  "externalId": "<the person's id in UwUAuth — never changes>",
  "displayName": "Mia",
  "name": { "formatted": "Mia", "givenName": "Mia", "familyName": "Neko" },
  "emails": [{ "value": "mia@example.com", "type": "work", "primary": true }],
  "preferredLanguage": "de",
  "active": true
}
```

- New: `POST /Users`. A `409` means the app knows them already: UwUAuth finds them with
  `GET /Users?filter=userName eq "mia@example.com"` and takes that id over.
- Changed: `PATCH /Users/{id}` with `replace` operations, one per changed field, of `active`,
  `displayName` and `externalId` (and `userName` when the app keys people by user name). An
  address used as `userName` is never changed: the person changes it in the app.
- Disabled, ran out, in the trash, or no longer allowed to use the app: `PATCH` `active: false`.
- Gone for good (30 days after the trash): `DELETE /Users/{id}`.
- A person without an address is not sent to an app that keys people by address.
- A `404` on a `PATCH` means the app lost them: made again.

**Groups** — if the app takes them: its allowed groups and the groups its roles come from (never
`everyone`), with the people above who are active as members:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "vault-admins",
  "externalId": "<the group's id>",
  "members": [{ "value": "<the app's id of the person>" }]
}
```

New: `POST /Groups` (a `409`: found by `displayName` and taken over); changed:
`PATCH /Groups/{id}` with `replace` of `displayName` and `members` (the whole list); no longer
wanted: `DELETE /Groups/{id}`.

**When.** In the background: after every change to people and groups, when an app is paired or
changed, when the admin asks, and every five minutes anyway (accounts run out without anybody
changing anything). Only what changed goes out. An error is shown on the app's page; the first
one after a good sync goes into the event log. An app that cannot be reached is tried again at
the next round.

Suite apps usually live in the same home or office network, so their addresses may be private
ones: the admin handed the code out, and what goes there is what the admin decided the app gets.

## SCIM for any app

Any app that takes SCIM can get the same: on its page, *People and groups (SCIM) → Set up SCIM*
with its SCIM address and the token it shows in its SCIM settings, whether it knows people by
address or by user name, and whether it takes groups. So far this is tested against the
UwUSuite only.

## Finding UwUAuth

`GET /.well-known/uwusuite` answers where the suite's servers are:

```json
{
  "uwusuite": 1,
  "servers": [
    { "product": "UwUAuth", "url": "https://auth.example.com", "info": "https://auth.example.com/uwu/v1/server" }
  ]
}
```

A suite app that knows only a domain asks `https://example.com/.well-known/uwusuite`; a reverse
proxy in front of `example.com` can hand that path to UwUAuth.

## The admin API

With an admin session or an [API token](api.md#tokens):

| | |
| --- | --- |
| `POST /uwu/v1/pairing-codes` | `{ "allowedGroups": [], "roleGroups": { "admin": ["vault-admins"] } }` (group ids or names) → 201 `{ "id", "code", "link", "expires", … }`, the code only now |
| `GET /uwu/v1/pairing-codes` | The open codes |
| `GET /uwu/v1/pairing-codes/{id}` | One code: `open`, `used`, and `app: { id, name }` once an app took it |
| `DELETE /uwu/v1/pairing-codes/{id}` | Withdraw an open code |
| `GET /uwu/v1/apps/{id}` | An app; for a paired one also `suite: { product, version, url, roles, paired, pairedBy, icon }`, and `scim: { baseUrl, resources, userName, synced, tried, error, users, groups }` |
| `GET /uwu/v1/apps/{id}/icon` | A paired app's icon (PNG) |
| `PUT /uwu/v1/apps/{id}/scim` | `{ "baseUrl", "token", "userName", "resources" }`: set up SCIM, or change it (without `token`: the old one stays) |
| `POST /uwu/v1/apps/{id}/scim/sync` | Push now; `{ "all": true }` sends everything again. 202 |
| `DELETE /uwu/v1/apps/{id}/scim` | Stop pushing |
| `PATCH /uwu/v1/apps/{id}` | `roles: [{ "group": "<id>", "role": "admin" }]` among the rest |
