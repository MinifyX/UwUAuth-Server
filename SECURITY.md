# Security

UwUAuth Server decides who gets into other people's apps — a flaw here opens everything behind
it. Thank you for looking.

## Reporting

Please report a vulnerability privately, through GitHub:
**[Report a vulnerability](https://github.com/MinifyX/UwUAuth-Server/security/advisories/new)**.
Not in a public issue.

Say what you found, how to reproduce it, and what you think it allows. I answer within a week,
and I will tell you when a fix is out and credit you in the release notes unless you would rather
not be named.

## What is in scope

- The server: this repository, and the images at `ghcr.io/minifyx/uwuauth-server`.
- `install.sh` and `update.sh`, which run as root.
- Where the server speaks a standard (OpenID Connect, LDAP, SAML, SCIM, RADIUS) in a way that
  lets somebody sign in as somebody else, or read what they should not.

## Supported versions

The newest release. Updating is `sudo bash update.sh`.
