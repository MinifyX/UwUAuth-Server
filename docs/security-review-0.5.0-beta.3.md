# Security review, 0.5.0-beta.3

Before 0.5.0, an audit looked at the whole server: signing in, OpenID Connect, forward auth,
the suite (SCIM, pairing), LDAP, backups and `install.sh`. A second round looked again at admin
rights through groups and at second factors asked for by groups. A dependency audit found one
bundled library with a known flaw. Every finding was checked against the code first; none was
refuted. Each fix with logic has a regression test next to the code it guards
(`crates/uwuauth-api/src/flows.rs`, `crates/uwuauth-api/src/oidc/flows.rs`,
`crates/uwuauth-api/src/suite/tests.rs`, `crates/uwuauth-ldap/tests/integration/ldap.rs`, and
unit tests in the files named).

Nothing was rated Critical or High.

| | Medium | Low | Fixed | Open |
| --- | --- | --- | --- | --- |
| Round 1 | 4 | 17 | 19 | 2 (L-16, L-17) |
| Round 2 | 3 | 5 | 8 | 0 |
| Dependencies | 1 | 0 | 1 | 0 |

## Round 1

**Medium (M-1) — an app's SCIM token could be sent to another host without a fresh sign-in.**
*Where:* `suite/scim.rs` (`set_up`, `hosts_of`, `pinned`), `routes/apps.rs` (`change`).
*Cause:* leaving the token out of a SCIM change kept the old one whatever the new address was,
and neither SCIM nor redirect address changes asked for a recent sign-in. *Fixed:* moving SCIM to
another host or port needs the token again (400, field `token`). Setting up SCIM and the address
changes in L-9 need a sign-in within the last ten minutes when a person does them; API tokens
are unaffected. *Test:* `an_admin_sets_up_scim_for_any_app_and_the_task_pushes`,
`where_an_app_sends_people_and_pairing_want_a_recent_sign_in`.

**Medium (M-2) — an app's second factor was asked for at authorize only.**
*Where:* `oidc/token.rs`, the code, refresh and device grants. *Cause:* an app switched to
`require_mfa` later kept accepting codes and refresh tokens from password-only sign-ins.
*Fixed:* all three grants check the sign-in's methods and answer `invalid_grant`; refresh also
ends the token family. *Test:* `a_second_factor_the_app_asks_for_later_holds_at_every_grant`.

**Medium (M-3) — a device code did not run out while it was polled.**
*Where:* `memory.rs` (`Expiring::put`), `oidc/token.rs`, `oidc/device.rs`. *Cause:* every poll
stored the entry again with a new time. *Fixed:* a new `Expiring::replace` keeps the first
time and fails once it has passed; polling then answers `expired_token`. *Test:*
`a_device_code_runs_out_however_often_it_is_asked`, `a_replaced_value_keeps_its_time`.

**Medium (M-4) — a bound LDAP connection outlived the secret it bound with.**
*Where:* `uwuauth-ldap/src/server.rs` (`still_bound`), `uwuauth-store/src/ldap.rs`,
`credentials.rs`. *Cause:* the check after a bind looked at the person or account, not at the
secret; renewing an account's password or removing an app password did not count as a directory
change. *Fixed:* a bound connection remembers the app password or account hash it used and
checks it again whenever the directory changes, as well as a group's new "app passwords only"
rule and the access windows the person had when binding. Both writes now mark the directory as
changed. *Test:* `a_bound_connection_ends_with_the_secret_it_bound_with`.

**Low (L-1) — wrong passwords when confirming a sign-in did not count towards the lock.**
*Where:* `uwuauth-store/src/events.rs` (`failed_logins_since`). *Fixed:* `reauth_failed`
counts like `login_failed`. *Test:* `failed_logins_count_since_the_last_good_one`.

**Low (L-2) — "forgot password" took longer for addresses that exist.** *Where:*
`routes/login.rs` (`forgot`). *Fixed:* making the link, the audit entry and the mail run after
the answer. *Test:* `forgot_password_mails_a_link_that_works_once` (no timing test).

**Low (L-3) — a huge token lifetime panicked the handler.** *Where:* `tokens.rs`. *Fixed:* more
than 3650 days is refused (400, field `days`). *Test:* `a_read_only_token_only_reads`.

**Low (L-4) — full stores of pending sign-ins were ignored.** *Where:* `oidc/authorize.rs`,
`oidc/logout.rs`. *Cause:* when a store was full, the code went on with a value it had not kept.
*Fixed:* the answer is 503 `temporarily_unavailable`. A per-person limit was not added; the
stores are bounded and the endpoints rate-limited. *Test:* none (error paths only).

**Low (L-5) — the "public address" check let internal ranges through.** *Where:*
`oidc/logout.rs` (`public_ip`), also used by client registration. *Fixed:* embedded IPv4
(mapped, compatible, NAT64, 6to4) is unwrapped and judged, and 240.0.0.0/4, 198.18.0.0/15,
192.0.0.0/24, fec0::/10 and 64:ff9b:1::/48 are refused. *Test:* `only_the_internet_is_public`.

**Low (L-6) — loopback redirects took a fragment and user info.** *Where:*
`oidc/authorize.rs` (`redirect_matches`). *Fixed:* refused. *Test:*
`loopback_redirects_take_any_port`.

**Low (L-7) — a switched-off app was still a target after signing out.** *Where:*
`oidc/logout.rs`. *Fixed:* disabled apps are skipped. *Test:*
`a_switched_off_app_is_not_where_signing_out_leads`.

**Low (L-8) — SCIM pinning ignored the port.** *Where:* `suite/scim.rs`, `suite/mod.rs`.
*Fixed:* host and port are compared; pairing keeps SCIM on the app's own port (400, field
`app.scim.baseUrl`). *Test:* `an_admin_sets_up_scim_for_any_app_and_the_task_pushes`.

**Low (L-9) — pairing codes and changes to where an app sends people needed no fresh sign-in.**
*Where:* `suite/mod.rs` (`create_code`), `routes/apps.rs` (`change`). *Fixed:* a person needs a
recent sign-in to make a pairing code, and to change redirect, post-logout, back-channel or
launch addresses, consent or forward auth. Other app changes are as before. *Test:*
`where_an_app_sends_people_and_pairing_want_a_recent_sign_in`.

**Low (L-10) — the global pairing limit could be used up from outside.** *Where:*
`suite/mod.rs` (`pair`). *Fixed:* only a wrong code is charged to it. *Test:* none.

**Low (L-11) — in-chain filters told a person about DNs they could not see.** *Where:*
`uwuauth-ldap/src/filter.rs`, `server.rs`. *Cause:* nested matching used the whole directory.
*Fixed:* for a person, in-chain matches only answer about their own DN and their groups. *Test:*
`people_see_themselves_and_their_groups_but_not_everybody`.

**Low (L-12) — the LDAP limit per address counted each IPv6 address.** *Where:*
`uwuauth-ldap/src/server.rs`. *Fixed:* connections count per /64 with the server's existing
`limits::network`; logs keep the real address. *Test:* none (reuses tested code).

**Low (L-13) — a page of LDAP results with photos was held whole in memory.** *Where:*
`uwuauth-ldap/src/server.rs`. *Fixed:* searches asking for photos get at most 100 entries per
page or answer. *Test:* none (a constant cap).

**Low (L-14) — the LDAP protocol library logged raw buffers on parse errors**, which can hold a
bind password. *Where:* `uwuauth-server/src/main.rs`. *Fixed:* `ldap3_proto=off` in the default
log filter. *Test:* none.

**Low (L-15) — a restore took triggers and views from the file.** *Where:*
`uwuauth-store/src/backup.rs`. *Fixed:* `trusted_schema` is off while checking and copying, and
files with triggers, views or virtual tables are refused; our own schema has none. *Test:*
`only_a_database_of_ours`.

**Note — `install.sh` checked for a symlink after resolving it**, so the check never fired.
*Fixed:* it runs before `realpath`. *Test:* `bash -n` and shellcheck.

## Round 2

**Medium (M1) — a group's second factor was asked for at signing in only.** *Where:*
`oidc/authorize.rs`, `oidc/token.rs`, `oidc/device.rs`, `forward_auth/mod.rs`. *Cause:* sessions
from before a group started asking kept reaching its apps. *Fixed:* one check,
`second_factor_missing`, covers the app's and the groups' rule at authorize, device approval,
all grants and forward auth. *Test:*
`a_group_that_starts_asking_for_a_second_factor_holds_for_open_sessions`.

**Medium (M2) — an invitation into a group inside Admins was not treated as an admin
invitation.** *Where:* `routes/invitations.rs`, `routes/links.rs`. *Cause:* only `admin: true`
counted. *Fixed:* `groups::makes_admin` counts groups inside Admins too: tokens may not, people
need a recent sign-in. *Test:*
`a_group_inside_admins_counts_as_admin_for_invitations_and_new_people`.

**Medium (M3) — a manager owning a group inside Admins could create an admin.** *Where:*
`routes/people.rs` (`create`). *Fixed:* only admins may create people with admin rights, and
they need a recent sign-in, also for `admin: true`. *Test:* as M2.

**Low (L1) — an import could place people in groups nested inside Admins.** *Where:*
`routes/admin.rs` (import). *Fixed:* all admin groups are left out like Admins itself. *Test:*
`an_import_makes_nobody_an_admin`.

**Low (L2) — renewing and withdrawing an invitation by id worked for any link.** *Where:*
`uwuauth-store/src/sessions.rs`. *Fixed:* limited to invitations. *Test:*
`an_invitation_ends_with_its_maker_s_admin_right`.

**Low (L3) — an invitation outlived its maker's admin right.** *Where:* `routes/links.rs`
(accept). *Fixed:* an invitation whose maker is no longer an active admin answers 410
`link_gone`. Invitations without a maker (CLI) work as before; no migration. *Test:* as L2.

**Low (L4) — invitation managers were not checked.** *Where:* `routes/invitations.rs`.
*Fixed:* only existing, not deleted people are kept, like groups. *Test:* as L2.

**Low (L5) — CSV export let a leading tab or carriage return through.** *Where:*
`routes/admin.rs` (`csv_field`). *Fixed:* prefixed like the other formula characters. *Test:*
`csv_both_ways`.

## D-1 Dependency

**Medium — the bundled SQLite had a known flaw** (RUSTSEC-2026-0459, CVE-2026-119375, in
libsqlite3-sys 0.38.2). *Fixed:* rusqlite 0.41 (0.41.1, with libsqlite3-sys 0.39.1); no code
changes were needed. *Test:* `cargo audit` is clean, and all tests pass.

## Open

- **L-16 — releases and images are not signed.** Signing needs a decision by the owner on keys
  and where they live.
- **L-17 — downloading a backup reads the whole file into memory.** Streaming it would need
  tokio-util's `io` feature, a new dependency edge. Backups are admin-only and as large as the
  database.
- **Invitations whose maker was purged.** Purging sets the maker to empty, so such an invitation
  is treated like one from the CLI and still works. While the maker is only in the trash, it is
  refused.
- **Access windows edited after an LDAP bind.** A bound connection ends when the windows it
  bound with close, not when an admin edits them.
- **No tests for L-4, L-10, L-12, L-13, L-14 and the timing of L-2.**

## Notes (not changed)

- A manager can switch an account back on that an admin switched off.
- A read-only API token can read the logs.
- Invitation and reset links keep their token in the address after opening; the web app handles
  that separately.

## Not reviewed

- `routes/ldap.rs`.
- What log lines contain, beyond L-14.
- The web app's forms, line by line.
- Behaviour of a running server; everything above was checked against code and tests.
