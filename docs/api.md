# The admin API

Everything the admin portal does, a script can do: the portal is a web app on top of this API.
Scripts use an **API token** instead of a session.

- [Tokens](#tokens)
- [Conventions](#conventions)
- [People](#people)
- [Groups](#groups)
- [Invitations](#invitations)
- [Attributes](#attributes)
- [Settings](#settings)
- [Events, log, backups](#events-log-backups)
- [Import and export](#import-and-export)

Apps, pairing codes and SCIM are in [Pairing with the UwUSuite](suite.md#the-admin-api).

## Tokens

An admin makes a token in the portal (*API tokens*): a name, *read only* or not, and optionally
the days it works. The secret starts with `uwu_` and is shown once; the server keeps only its
hash. It goes into every request:

```bash
curl -H "Authorization: Bearer uwu_…" https://auth.example.com/uwu/v1/people
```

A read-only token may only `GET`. A token cannot make tokens, and nothing that needs a recent
sign-in (downloading a backup, setting someone's password) works with a token.

## Conventions

- JSON in and out, field names in camelCase. Times are RFC 3339 in UTC
  (`2026-09-27T12:00:00.000000Z`).
- An error is `{"error": "<code>", "message": "<English>", "detail": {…}}`: `unauthorized` (401),
  `forbidden` (403), `not_found` (404), `exists` (409, a name or address is taken), `too_many`
  (429), `reauth` (a signed-in person has to confirm who they are first) and, for a field that is
  wrong, a code like `username`, `email`, `too_short` with `detail.field`.
- Every change goes into the event log, with the token as `token:<id>`.

## People

| | |
| --- | --- |
| `GET /uwu/v1/people[?trash=true]` | Everybody (or the trash) |
| `POST /uwu/v1/people` | `{username, displayName, givenName?, familyName?, email?, language?, managed?, groups?, admin?, password?, setupLink?, mail?}` → `{id, username, link?}` |
| `GET /uwu/v1/people/{id}` | One person, with passkeys, sessions, windows, attributes, managers |
| `PATCH /uwu/v1/people/{id}` | Any of `username, displayName, givenName, familyName, email, emailVerified, language, managed, expires, loginShell, homeDirectory, attributes` |
| `DELETE /uwu/v1/people/{id}` | Into the trash (gone for good after 30 days) |
| `POST /uwu/v1/people/{id}/restore`, `DELETE …/purge` | Out of the trash, or gone now |
| `POST /uwu/v1/people/{id}/disable`, `…/enable` | Disabled people sign in nowhere |
| `POST /uwu/v1/people/{id}/link` | `{mail?}` → a setup link (nobody set up yet) or a new-password link |
| `PUT /uwu/v1/people/{id}/groups` | `{groups: [id]}` — the groups they are directly in |
| `PUT /uwu/v1/people/{id}/managers` | `{managers: [id]}` — who looks after them |
| `PUT /uwu/v1/people/{id}/manages` | `{people: [id], groups: [id]}` — whom they look after |
| `PUT /uwu/v1/people/{id}/windows` | `[{days, start, end, app?}]` — `days` a bit mask (Monday 1 … Sunday 64), `start`/`end` minutes after midnight |
| `DELETE /uwu/v1/people/{id}/totp` | Takes the authenticator app and the recovery codes away |
| `DELETE /uwu/v1/people/{id}/sessions` | Signs them out everywhere |
| `GET /uwu/v1/people/{id}/events` | What happened to them |
| `PUT`/`DELETE /uwu/v1/people/{id}/avatar` | A JPEG of at most 256 KiB |

## Groups

| | |
| --- | --- |
| `GET /uwu/v1/groups`, `POST` | `{name, description?, requireMfa?, ldapAppPasswordsOnly?}` |
| `GET`/`PATCH`/`DELETE /uwu/v1/groups/{id}` | `admins` and `everyone` cannot be deleted |
| `PUT /uwu/v1/groups/{id}/members` | `{people: [id], groups: [id], owners?: [id]}` — a group never ends up inside itself |
| `PUT /uwu/v1/groups/{id}/windows` | Like a person's |

## Invitations

| | |
| --- | --- |
| `GET /uwu/v1/invitations` | Open ones |
| `POST /uwu/v1/invitations` | `{email?, displayName?, groups?, admin?, managed?, managers?, language?, mail?}` → with `link`, shown once |
| `POST /uwu/v1/invitations/{id}/renew` | `{mail?}` → a new link; the old one stops working |
| `DELETE /uwu/v1/invitations/{id}` | |

## Attributes

`GET /uwu/v1/attributes`, `PUT /uwu/v1/attributes` with the whole list:
`[{name, label, kind: "text"|"number"|"date"|"choice", choices?, selfEditable?}]`. An attribute
that is left out goes, with its values.

## Settings

`GET /uwu/v1/settings`, `PUT /uwu/v1/settings` with the whole object (the mail password only as
`smtpPassword`, when it changes); `POST /uwu/v1/settings/test-mail` for a signed-in admin.

## Events, log, backups

| | |
| --- | --- |
| `GET /uwu/v1/overview` | Counts, mail, the update notice, the last backup |
| `GET /uwu/v1/events?before=&kind=&person=` | Newest first, 200 at a time |
| `GET /uwu/v1/logs?after=&level=` | The server's log |
| `GET /uwu/v1/backups`, `POST` | List, or write one now |
| `GET/POST/DELETE /uwu/v1/tokens` | API tokens (only a signed-in admin makes them) |

## Import and export

- `GET /uwu/v1/export` — people and groups as JSON (no passwords, no passkeys, nothing to sign in
  with); `?format=csv` — people as CSV.
- `POST /uwu/v1/import[?dryRun=true]` — the same JSON, or CSV with `Content-Type: text/csv` and a
  first row naming the columns (`username` needed; `displayName`, `givenName`, `familyName`,
  `email`, `language`, `groups` separated by `;`). What exists already (by user name, by group
  name) stays as it is. The answer says what was created, skipped and why something failed. New
  people have no way to sign in yet: send them setup links with `POST /uwu/v1/people/{id}/link`.
