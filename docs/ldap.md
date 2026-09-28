# LDAP, in the style of Active Directory

For what cannot sign people in with OpenID Connect: a NAS, Linux logins with SSSD, Nextcloud's
LDAP backend, Jellyfin's LDAP plugin, Proxmox, anything with an "LDAP" or "Active Directory"
setting. UwUAuth shows the same people and groups over LDAP, in two dialects at once, so an app
set to "OpenLDAP" and one set to "Active Directory" both find what they look for.

It is **not a domain controller**: no Kerberos, no NTLM, no joining Windows PCs to a domain, no
group policies. For that there is Samba.

- [Turning it on](#turning-it-on)
- [The tree](#the-tree)
- [Binding](#binding)
- [What apps see](#what-apps-see)
- [Settings for common apps](#settings-for-common-apps)
- [Passwords](#passwords)

## Turning it on

LDAP is off unless asked for, and it is **for your own network only**: 389 and 636 must never be
reachable from the internet.

```bash
sudo bash install.sh --domain auth.example.com --ldap --ldap-bind 192.0.2.10 --yes
```

`--ldap-bind` is the address of this machine in your own network. `0.0.0.0` (every address) has to
be written out: Docker's published ports go past ufw and firewalld, so then only the router keeps
LDAP from the internet.

or later, by hand, in `.env`:

```bash
UWUAUTH_LDAP_LISTEN=0.0.0.0:10389     # LDAP, with StartTLS
UWUAUTH_LDAPS_LISTEN=0.0.0.0:10636    # LDAPS
```

and in `compose.override.yaml` next to `compose.yaml` (update.sh leaves it alone):

```yaml
services:
  uwuauth:
    ports:
      - "192.0.2.10:389:10389"
      - "192.0.2.10:636:10636"
```

then `docker compose up -d`. Apps in the same Docker network reach `uwuauth:10389` without any
port on the machine.

**TLS.** LDAPS and StartTLS use the server's own certificate — from Let's Encrypt or from files —
and pick up a renewed one without a restart. Behind a reverse proxy the server has none; give LDAP
one with `UWUAUTH_LDAP_TLS_CERT` and `UWUAUTH_LDAP_TLS_KEY` (PEM files inside the container), or,
only where nobody else is on the network (the Docker network next to the apps), allow passwords
without TLS: `UWUAUTH_LDAP_PLAIN_BIND=on`. Without either, a bind with a password over plain LDAP
is refused (`confidentialityRequired`).

## The tree

The base DN comes from the server's name — `auth.example.com` gives `dc=example,dc=com` — or from
`UWUAUTH_LDAP_BASE_DN`.

| DN | What |
| --- | --- |
| `dc=example,dc=com` | the base |
| `uid=<user name>,ou=people,dc=example,dc=com` | everybody, but the trash |
| `cn=<group>,ou=groups,dc=example,dc=com` | every group, `admins` and `everyone` included |
| `cn=<name>,ou=services,dc=example,dc=com` | accounts of apps, for binding only |

## Binding

- **Apps** bind with an account from the admin portal (*LDAP → Accounts*): the DN is
  `cn=<name>,ou=services,dc=example,dc=com`, the password is shown once. Such an account may read
  the whole directory, and change nothing.
- **People** bind with their own password or with an **app password** (made in the self-service
  portal under *Security*). A group can say that for its members only app passwords count over
  LDAP (*For LDAP only app passwords*); a group that wants a second step does the same, since LDAP
  has no way to ask for one. The name can be written however the app writes it:
  `uid=nyu,ou=people,dc=example,dc=com`, `nyu`, `nyu@example.com` (the user principal name, or
  the address), `EXAMPLE\nyu`.
- **Anonymous** clients only see the root DSE (`namingContexts` and what the server can do).

What a bind may read:

| Bound as | Sees |
| --- | --- |
| an app's account | everything below, all of it; changes nothing |
| a person | the base, the three containers, their own entry, and the groups they are in — of those only `cn`, `sAMAccountName`, `description`, `gidNumber` and the ids, and among the members only themselves |
| nobody | the root DSE |

So an app that checks a password by binding as the person, and then reads that person's entry
and groups, finds what it needs; to list everybody, an app needs an account of its own.

A refused bind answers like Active Directory, so apps that read the reason understand it:
`data 52e` wrong name or password, `533` disabled, `701` run out, `530` outside the person's time
window. After too many wrong passwords (the same count as on the web) the account password is
turned away for a quarter of an hour with `52e` like a wrong one, so whoever is guessing learns
nothing; app passwords go on working. Wrong binds count per address too, and every bind goes into
the event log.

Whoever is bound is looked at again on every request: once a person is disabled, changes their
password or is signed out everywhere, or an app's account is deleted, the connection is anonymous.
A connection has 30 seconds to bind; one that is bound is closed after five idle minutes. At most
512 connections are open at once, 64 from one address.

## What apps see

**People** are `inetOrgPerson`, `posixAccount` and `user`:

| Attribute | |
| --- | --- |
| `uid`, `sAMAccountName` | the user name |
| `cn`, `displayName`, `gecos` | the display name |
| `givenName`, `sn` | first and last name (`sn` falls back to the display name) |
| `mail` | the address |
| `userPrincipalName` | `name@example.com` |
| `distinguishedName` | the entry's DN, as Active Directory has it |
| `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell` | for Linux (`gidNumber` is `everyone`'s) |
| `memberOf` | the groups they are in directly, and `everyone` |
| `objectGUID`, `objectSid` | the id, the way Windows writes it; the SID is `S-1-5-21-…-<uidNumber>` |
| `userAccountControl` | `512`, or `514` when disabled |
| `jpegPhoto`, `thumbnailPhoto` | the picture, when asked for by name (filters do not see it) |
| `entryUUID`, `createTimestamp`, `modifyTimestamp` | when asked for by name, or with `+` |
| your attributes | each under its name |

**Groups** are `groupOfNames`, `groupOfUniqueNames`, `posixGroup` and `group`, with `cn`,
`sAMAccountName`, `description`, `gidNumber`, `member` and `uniqueMember` (people and groups
inside), `memberUid` (user names), `memberOf`, `objectGUID` and `objectSid`.

Filters compare names and addresses case-insensitively, numbers as numbers, DNs as DNs. Two of
Active Directory's matching rules are understood:

- `(memberOf:1.2.840.113556.1.4.1941:=cn=Familie,ou=groups,dc=example,dc=com)` — everybody in a
  group, through groups inside it too;
- `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` — only those not disabled.

A filter may hold at most 32 such extensible matches.

Searches return at most 10,000 entries; paged results (RFC 2696) page through more.

## Settings for common apps

**Nextcloud** (LDAP/AD integration): host `ldaps://auth.example.com`, port 636, user DN and
password of an LDAP account, base DN `dc=example,dc=com`. User filter
`(&(objectClass=inetOrgPerson)(memberOf=cn=nextcloud,ou=groups,dc=example,dc=com))`, login filter
`(&(objectClass=inetOrgPerson)(|(uid=%uid)(mail=%uid)))`, group filter `(objectClass=groupOfNames)`,
group member association `member`. Internal username: `uid`; UUID attribute: `entryUUID`.

**SSSD** (Linux logins), in `/etc/sssd/sssd.conf`:

```ini
[domain/example.com]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldaps://auth.example.com
ldap_search_base = dc=example,dc=com
ldap_default_bind_dn = cn=linux,ou=services,dc=example,dc=com
ldap_default_authtok = <the account's password>
ldap_schema = rfc2307bis
ldap_user_search_base = ou=people,dc=example,dc=com
ldap_group_search_base = ou=groups,dc=example,dc=com
ldap_group_member = member
ldap_user_uuid = entryUUID
ldap_group_uuid = entryUUID
```

**Synology / QNAP**: "LDAP client", server type "other" (or "Active Directory" style with
`sAMAccountName`), base DN `dc=example,dc=com`, bind DN of an LDAP account, encryption SSL/TLS.

**Jellyfin** (LDAP plugin): server `auth.example.com`, port 636, secure LDAP, bind user and
password of an account, base DN `ou=people,dc=example,dc=com`, search filter
`(memberOf=cn=streaming,ou=groups,dc=example,dc=com)`, search attributes `uid, mail`, UID attribute
`uid`.

**Proxmox** (realm "LDAP" or "Active Directory"): server `auth.example.com`, base DN
`ou=people,dc=example,dc=com`, user attribute `uid` (or `sAMAccountName` for AD), bind user of an
account, mode LDAPS.

## Passwords

People can change their own password over LDAP — bound with their own password (not an app
password), with the old one, and only over TLS (or where plain binds are allowed). A wrong old
password counts like a wrong password at signing in. Two ways are understood:

- the Password Modify operation (RFC 3062), as `ldappasswd` sends it;
- Active Directory's way: a modify that deletes the old `unicodePwd` and adds the new one.

The new password follows the same rules as in the portal (length, not the name, Have I Been Pwned
if turned on), and every other session ends with it. Nothing else changes over LDAP: people,
groups and resets belong in the portal.
