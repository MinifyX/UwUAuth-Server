# Security review, September 2026

Before 0.3.0-beta.1, three reviews looked at the code of stages 1 to 3, each on its own: signing
in and the directory (sessions, links, passkeys, second factors, people, groups, admin), the
OpenID Connect provider, and the LDAP server with `install.sh`. Every finding rated High or
Medium was confirmed with a test against the code of that time, and is fixed. Each fix has a
regression test next to the code it guards (`crates/uwuauth-api/src/flows.rs`,
`crates/uwuauth-api/src/oidc/flows.rs`, `crates/uwuauth-ldap/tests/integration/ldap.rs`).

Nothing was rated Critical.

| | High | Medium | Low |
| --- | --- | --- | --- |
| Signing in and the directory | 3 | 2 | 4 |
| OpenID Connect | 0 | 4 | 6 |
| LDAP and install.sh | 3 | 4 | 3 |

## Signing in and the directory

**High — a reset link skipped the second factor.** Whoever could read somebody's mail could reset
the password and got a full session, even for an admin with TOTP; a reset link also took a new
passkey, and a restricted session could mint recovery codes. *Fixed:* after a link sets a
password, a person with a second factor gets the same second step as at signing in. A reset link
refuses a passkey from people who have a factor. Recovery codes need a full session, and a
restricted session may only set up a first factor.

**High — managers and group owners reached admins.** A manager could act on everybody in a group
they looked after, admins included, and a group owner could put `admins` into their group; a
reset link for anybody they reached followed. *Fixed:* managers reach managed accounts only,
never admins or other managers. Owners change the people in their group, not the groups in it.
Groups inside `admins` are for admins only. Making a link needs a fresh sign-in.

**High — anybody could lock any account, and tell which accounts exist.** Ten wrong passwords
locked an account, passkeys and apps' tokens included, and the answer differed from the one for
an unknown name. *Fixed:* the password is checked first, and a locked account answers "wrong"
like a wrong password. The lock applies to passwords from unknown devices only: devices the person
signed in on before, passkeys and apps' existing grants go on working.

**Medium — admin actions as strong as a password needed no fresh sign-in.** Links, admin
invitations, admin group membership and who manages whom. *Fixed:* all need a fresh sign-in.

**Medium — owners of a group inside `admins` could make or remove admins, and the last admin
could go.** *Fixed:* every group inside `admins`, at any depth, is changed by admins only. After
every change to members, groups or deleting a group, at least one active admin has to be left.

**Low, fixed:**

- Re-confirming with a password alone for people whose second factor is a passkey: they confirm
  with the passkey now.
- "Forgot password" answered later for accounts that exist, because it sent the mail first. Now
  the mail goes out after the answer.
- API tokens outlived their maker's admin rights. Now a token works only while whoever made it is
  an active admin.
- Importing another server's export made local people with the same names admins. Now an import
  fills only the groups it creates, never built-in ones, and checks attributes.

## OpenID Connect

**Medium — `prompt=login` and `max_age` could be skipped** with a parameter the client made up.
*Fixed:* the login page gets a one-time marker kept on the server, and the sign-in behind it has
to be fresh.

**Medium — apps that registered themselves were trusted like an admin's.** No consent screen, a
link in everybody's "My apps", a back-channel address anywhere (SSRF), and an open redirect after
logout. *Fixed:*

- Such apps always ask for consent and never show in "My apps".
- Their back-channel address has to be public https. It is resolved before every call, refused
  if any address is not public, and pinned for the call.
- After logout, the redirect happens only with a valid ID token as hint.

**Medium — changing one field of an app reset the others**, dropping allowed groups, the second
factor and consent. *Fixed:* a change is merged over what is there.

**Medium — device authorization filled memory without signing in.** *Fixed:* OAuth's endpoints
have a limit per address, and every table of pending things holds at most 10,000.

**Low, fixed:**

- Two refreshes at once could slip past reuse detection. The new token is now only kept if the
  old one was still unused, in one step.
- Any token the server signed worked as `id_token_hint`. Now only an ID token for that app does.
- A `redirect_uri` sent at authorize is required at the token endpoint.
- Two polls of the device flow could both get tokens, and device apps without refresh had no
  grant.
- Introspection called refresh tokens active that refreshing would refuse.
- A code used twice now revokes what the first use got. A registration token is used up only by
  a request that is valid.

## LDAP and install.sh

**High — an app password led to the account password.** Bound with an app password, a password
change could guess the old password without limit and then set a new one. *Fixed:* changes of the
account password need a bind with the account password. A wrong old password counts like a
wrong password at signing in: per account, per address, and towards the lock.

**High — about 1000 idle connections took the whole server down.** No limit on connections, no
deadline to bind, and a busy loop once file handles ran out. *Fixed:*

- At most 512 connections, 64 per address.
- 30 seconds to bind, which asking for the root DSE does not extend.
- A pause after a failed accept.
- The soft file-handle limit is raised to the hard one at start.

**High — every person could read the whole directory.** *Fixed:* bound as a person, LDAP shows
the base, the containers, their own entry and their groups. Of the groups it shows only names
and ids, and among the members only that person. Apps' accounts read everything, as before.

**Medium — the lock was a password oracle over LDAP.** A locked account answered `775` for the
right password and `52e` for a wrong one. *Fixed:* both answer `52e`. App passwords are no guess
and keep working.

**Medium — an app's correct binds used up the address's tries**, so one person typing wrong could
lock everybody out of an app. *Fixed:* LDAP has its own limit per address, and only wrong binds
count against it.

**Medium — the directory was rebuilt after every write**, including log entries, and several
rebuilds could run at once, all photos included. *Fixed:* only changes to the directory count.
One rebuild runs at a time. Photos are read only when a search asks for them by name.

**Medium — `install.sh --yes --ldap` published 389 and 636 on every address**, past ufw.
*Fixed:* with `--yes` it needs `--ldap-bind`, and `0.0.0.0` has to be written out. Asked
interactively, it suggests a private address and warns about the firewall.

**Low, fixed:**

- Filters full of nested-group matches ran on the async threads. They now run on a thread of
  their own, work out nested groups once per search, and allow at most 32 such matches.
- LDAP's TLS offered HTTP's ALPN and shared HTTPS's session cache. It now has neither.
- A bound connection was never checked again, the bind DN of a failed bind was logged at any
  length, and groups requiring a second step still took the account password over LDAP. Now:
  - the bound person or account is checked on every request;
  - names are cut at 254 characters;
  - such groups mean app passwords over LDAP.

## Left as they are (Low)

- **Time tells a little over LDAP.** A bind for a name that exists makes two more database reads
  than one for a name that does not. The answer is the same, and wrong binds are limited per
  address.
- **In-chain matches on a person's own groups.** A person can ask whether some DN is a member of
  one of their own groups through nested groups (`member:1.2.840.113556.1.4.1941:=`). They learn
  nothing about groups they are not in.
- **Two admins removing each other at the very same moment.** The last-admin check and the
  change are two steps. Both would have to be admins acting within milliseconds; the CLI's
  `admin` command makes a new admin if it ever happens.
- **Pending device codes are looked up by a scan.** The table holds at most 10,000, and the
  endpoint is rate-limited.
- **The lock can still be triggered from outside for new devices.** That is what a lock is for.
  Known devices, passkeys and apps are exempt, so the owner is not locked out.
