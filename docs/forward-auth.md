# Guarding apps with forward auth

Some apps have no sign-in of their own, or none worth having: a dashboard, a wiki, a file
browser. Forward auth puts UwUAuth in front of them. The reverse proxy asks UwUAuth about every
request; UwUAuth says yes (and who it is), no, or "sign in first". The app sees only requests
that got through, with the person in a few headers.

- [Adding an app](#adding-an-app)
- [The cookie domain](#the-cookie-domain)
- [Who may in](#who-may-in)
- [The endpoint](#the-endpoint)
- [Caddy](#caddy)
- [Traefik](#traefik)
- [nginx](#nginx)
- [Nginx Proxy Manager](#nginx-proxy-manager)
- [Signing out](#signing-out)
- [What to keep in mind](#what-to-keep-in-mind)

## Adding an app

In the admin portal, *Apps → New app → Forward-Auth*. Give it a name and the **addresses** the
proxy guards with it: a host (`wiki.example.com`), a host with a port (`wiki.example.com:8080`),
or a host with a path (`example.com/admin`). The app shows up in *My apps* — with the first
address, unless *Address to open* says otherwise — and has no client ID or secret: the proxy
needs none.

An address belongs to one app. When a request fits several, **the most specific one decides**:
the longest path, compared by whole segments (`/admin` covers `/admin/users`, not
`/administrator`), and an address with a port before one without. `%xx` is decoded and `//`
counts as `/`. A path that apps read in different ways — a `.` or `..` segment, an encoded `/`,
`\`, `.` or `%`, a `\`, a `;` — gets **403**: it could walk out of one rule into a looser one.
Browsers never send such paths by themselves. A host that no app has gets **403** as well: forward
auth fails closed.

## The cookie domain

To answer, UwUAuth needs to know who is asking: the browser sends a cookie with every request.
Browsers send a cookie only to the host that set it — or, with a *Domain*, to every host below
that domain. So:

- **Apps on UwUAuth's own host** (`auth.example.com/wiki`): nothing to set.
- **Apps on other hosts** (`wiki.example.com`): *Settings → Sign-in → Cookie domain for forward
  auth*, e.g. `example.com`. UwUAuth's own address has to be in it.

The domain-wide cookie is its own cookie (`uwuauth_fa`), not the portal's session cookie: it
opens forward-auth apps and nothing else. The portal and the admin API still take only the
session cookie, which stays on UwUAuth's host, and still check that a request comes from
UwUAuth's own page — another host below the domain is not trusted for that. Still, every host
below the cookie domain gets the cookie: set it only to a domain whose hosts you trust.

The cookie is `HttpOnly`, `SameSite=Lax` and — with UwUAuth on https — `Secure`. It lasts as long
as the session it belongs to: until the browser closes, or for *Stay signed in*'s days.

## Who may in

The same rules as for [OpenID Connect apps](oidc.md#who-may-use-an-app):

- **Groups**: *Allowed groups*. Anybody else gets 403, and the event log a
  `forward_auth_denied` entry (one per person, app and reason every five minutes, not one per
  request).
- **Time windows**, for every app or this one: outside them, 403.
- **Second factor**: a session signed in with a password alone goes to a page that asks for a
  passkey or the authenticator app first, and then back to the app.
- Being disabled, run out or locked out ends access too.

UwUAuth keeps an answer for ten seconds, so a proxy asking for every image and script of a page
costs nothing. A change of groups or time windows takes effect within those seconds; signing out
at once.

The first time a session gets through to an app, the event log says so (`app_login`, with
`"via": "forward_auth"`).

## The endpoint

| | |
| --- | --- |
| `GET /uwu/v1/forward-auth` | For Caddy, Traefik and anything that passes a redirect on |
| `GET /uwu/v1/forward-auth/nginx` | For nginx `auth_request`: 401 instead of a redirect |
| `GET /oauth/forward-auth?rd=` | Where the browser signs in and comes back from |

Any method is fine for the first two; the proxy says what it is guarding in headers, and each
endpoint reads only its own kind:

- `/uwu/v1/forward-auth`: `X-Forwarded-Proto`, `X-Forwarded-Host` (or `Host`), `X-Forwarded-Uri`,
  `X-Forwarded-Method`, as Caddy and Traefik send them. Of a comma-separated list, the last value
  counts: the one the proxy next to UwUAuth added.
- `/uwu/v1/forward-auth/nginx`: `X-Original-URL` and `X-Original-Method`. Without
  `X-Original-URL`, 403.

Caddy and Traefik pass the browser's other headers on, so an `X-Original-URL` the browser made up
reaches UwUAuth there too — which is why the first endpoint never reads it.

The answers:

| | |
| --- | --- |
| **200** | Let it through. `Remote-User` (user name), `Remote-Groups` (group names, comma-separated), `Remote-Email` (may be empty), `Remote-Name` (display name). |
| **302** / **303** | Not signed in (or a second factor missing): `Location` points to UwUAuth. 303 for a request that is not `GET` or `HEAD`, so the browser comes back with a `GET`. |
| **401** + `Location` | The same, for nginx, which passes on only 2xx, 401 and 403. |
| **403** | No: a host no app has, a path apps read in different ways, a group, a time window, a disabled account. A small page links to UwUAuth's explanation. |

**The way back** (`/oauth/forward-auth?rd=…`) goes only to an address a forward-auth app has,
that the cookie reaches (UwUAuth's own host, or one in the cookie domain), with `https` when
UwUAuth runs on https, and without a user name in it. Anything else is refused — UwUAuth is no
open redirect. The browser goes to the address as UwUAuth read it, not as it was written. A
browser not signed in signs in first and then comes back here.

A browser that sends two forward-auth cookies counts as not signed in: the second one was set by
another host below the cookie domain.

The proxy should send the app's request headers to UwUAuth (for the cookie), but not its body.
The `Remote-*` headers the app gets come from UwUAuth; a proxy that copies them (all four below
do) replaces whatever the browser sent under those names. Take them only from the proxy: an app
reachable without it believes anybody.

The app gets the browser's cookies too, the forward-auth cookie among them. Where the proxy can
take that one out before passing the request on, do; most apps never need it.

## Caddy

```caddyfile
wiki.example.com {
	forward_auth uwuauth:8443 {
		uri /uwu/v1/forward-auth
		copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
	}
	reverse_proxy wiki:3000
}
```

`uwuauth:8443` is how Caddy reaches UwUAuth — in the same Docker network, or `127.0.0.1:8443`
on the same machine. Over its public address instead (`https://auth.example.com`), add
`header_up Host {upstream_hostport}` inside `forward_auth`, so that a proxy in front of UwUAuth
knows where the request goes. This setup runs in CI against a real Caddy
(`scripts/interop/forward-auth.sh`).

## Traefik

```yaml
http:
  middlewares:
    uwuauth:
      forwardAuth:
        address: http://uwuauth:8443/uwu/v1/forward-auth
        authResponseHeaders: [Remote-User, Remote-Groups, Remote-Email, Remote-Name]
  routers:
    wiki:
      rule: Host(`wiki.example.com`)
      middlewares: [uwuauth]
      service: wiki
```

With Docker labels, the same:

```yaml
labels:
  traefik.http.middlewares.uwuauth.forwardauth.address: http://uwuauth:8443/uwu/v1/forward-auth
  traefik.http.middlewares.uwuauth.forwardauth.authResponseHeaders: Remote-User,Remote-Groups,Remote-Email,Remote-Name
  traefik.http.routers.wiki.middlewares: uwuauth
```

## nginx

nginx's `auth_request` passes on 2xx, 401 and 403 only — so UwUAuth answers 401 with a
`Location`, and `error_page 401 =302` turns that into the redirect:

```nginx
server {
    server_name wiki.example.com;
    # listen, ssl_certificate … as usual

    location / {
        auth_request /uwuauth;
        auth_request_set $uwuauth_location $upstream_http_location;
        error_page 401 =302 $uwuauth_location;

        auth_request_set $uwuauth_user   $upstream_http_remote_user;
        auth_request_set $uwuauth_groups $upstream_http_remote_groups;
        auth_request_set $uwuauth_email  $upstream_http_remote_email;
        auth_request_set $uwuauth_name   $upstream_http_remote_name;
        proxy_set_header Remote-User   $uwuauth_user;
        proxy_set_header Remote-Groups $uwuauth_groups;
        proxy_set_header Remote-Email  $uwuauth_email;
        proxy_set_header Remote-Name   $uwuauth_name;

        proxy_pass http://wiki:3000;
    }

    location = /uwuauth {
        internal;
        proxy_pass http://uwuauth:8443/uwu/v1/forward-auth/nginx;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URL $scheme://$server_name$request_uri;
        proxy_set_header X-Original-Method $request_method;
    }
}
```

The variables need names of their own: `$remote_user` is nginx's already.

`$server_name`, not `$http_host`: the `Host` the browser sends is its own to choose, and with a
`server` that takes any host, it would pick the app UwUAuth decides about. Give each guarded host
its own `server` with one `server_name`, and keep a catch-all that answers nothing:

```nginx
server {
    listen 443 ssl default_server;
    ssl_reject_handshake on;
    return 444;
}
```

## Nginx Proxy Manager

Nginx Proxy Manager is nginx underneath. On the proxy host, in *Advanced → Custom Nginx
Configuration*, put the `location = /uwuauth { … }` block from above, and a `location / { … }`
with everything from the nginx `location /` — ending in
`proxy_pass $forward_scheme://$server:$port;` instead of the fixed address, so that the
host and port set in Nginx Proxy Manager still apply. A `location /` of your own replaces the one
Nginx Proxy Manager writes; `proxy_set_header` lines outside a `location` would be ignored there.
Nginx Proxy Manager gives every proxy host one `server` for its domains, so `$server_name` is the
first of them: guard one domain per proxy host.

## Signing out

Signing out of UwUAuth — in the portal, or through an OpenID Connect app — clears the
forward-auth cookie with the same domain, and the next request to a guarded app asks again at
once (UwUAuth forgets its kept answers for that session). *Sign out everywhere*, a new password
and an admin ending sessions take effect at once too: the cookie on other devices stays, but the
session behind it is gone, and UwUAuth asks for a sign-in again.

## What to keep in mind

- **The proxy is the guard.** An app reachable around the proxy — another port, another network —
  is not guarded at all.
- **Every host in the cookie domain sees the cookie**, and could use it against the other
  forward-auth apps of the same person. Do not set the domain to one with hosts you do not run.
- **Without a cookie domain**, only apps on UwUAuth's own host work; for any other host the way
  back says so instead of going round in circles.
- **Paths are case-sensitive**, as most apps read them. An app that treats `/Admin` like `/admin`
  needs both, or a rule on the whole host.
- **Group names with a comma** come through `Remote-Groups` as they are; avoid commas in the names
  of groups an app reads.
- Answers are kept for ten seconds: removing somebody from a group reaches a guarded app within
  that time, not at the same moment.
- Behind a proxy, set `UWUAUTH_TRUST_FORWARDED=on` (see [Deployment](deployment.md)) so that the
  event log shows the person's address, not the proxy's.
