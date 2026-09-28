#!/usr/bin/env bash
# Real apps against a UwUAuth binary, in Docker:
#
#   scripts/interop/run.sh <path to uwuauth-server (linux/amd64, with the web app)> [ldap|oidc|all]
#
# ldap: SSSD on a Linux machine looks people up and signs one in over LDAP.
# oidc: Grafana and Forgejo sign the same person in with OpenID Connect, in a real browser.
# nextcloud: Nextcloud finds people over LDAP, and signs one in with OpenID Connect (user_oidc,
#            from Nextcloud's app store: needs the internet). Slow; not part of `all`.
set -euo pipefail
binary="$(realpath "${1:?the uwuauth-server binary}")"
cd "$(dirname "$0")"
what="${2:-all}"
root="$(realpath ../..)"
work="$(mktemp -d)"
port="${UWUAUTH_PORT:-28491}"
export UWUAUTH_PORT="$port"
jar="$work/jar"
public=http://uwuauth:8443
local="http://127.0.0.1:$port"

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    docker compose --profile oidc --profile nextcloud logs --no-color --tail 60 >&2 || true
  fi
  docker compose --profile oidc --profile nextcloud down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$1"; }
# The API, as the web app calls it: the session in a cookie jar, and the server's own origin.
api() { curl -sf -b "$jar" -c "$jar" -H "Origin: $public" -H 'content-type: application/json' "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

step "the image"
mkdir -p "$work/dist/amd64"
cp "$binary" "$work/dist/amd64/uwuauth-server"
chmod 755 "$work/dist/amd64/uwuauth-server"
cp -r "$root/docker" "$work/docker"
docker build -q --platform linux/amd64 -f "$work/docker/Dockerfile.release" -t uwuauth-server:interop "$work" >/dev/null

step "UwUAuth, with its first admin"
docker compose up -d uwuauth >/dev/null
for _ in $(seq 1 60); do curl -sf "$local/healthz" >/dev/null && break; sleep 0.5; done
link=$(docker compose exec -T uwuauth uwuauth-server invite --admin nyu@example.com | tail -1)
api -d '{"username":"nyu","displayName":"Nyu Neko","password":"correct horse battery"}' "$local/uwu/v1/links/invite/${link##*token=}" >/dev/null
group=$(api -d '{"name":"familie"}' "$local/uwu/v1/groups" | field "['id']")
me=$(api "$local/uwu/v1/me" | field "['id']")
api -X PUT -d "{\"people\":[\"$me\"],\"groups\":[]}" "$local/uwu/v1/groups/$group/members" >/dev/null
echo "nyu is an admin and in familie"

if [ "$what" = ldap ] || [ "$what" = all ]; then
  step "SSSD over LDAP"
  secret=$(api -d '{"name":"linux"}' "$local/uwu/v1/ldap/accounts" | field "['secret']")
  docker build -q -t uwuauth-sssd -f sssd.Dockerfile . >/dev/null
  docker run --rm --network uwuauth-interop_default -v "$PWD/sssd.sh:/sssd.sh:ro" uwuauth-sssd \
    /sssd.sh ldap://uwuauth:10389 dc=example,dc=com cn=linux,ou=services,dc=example,dc=com "$secret" \
    nyu "correct horse battery" familie
fi

if [ "$what" = oidc ] || [ "$what" = all ]; then
  step "Grafana and Forgejo as apps"
  grafana=$(api -d '{"name":"Grafana","template":"grafana","url":"http://grafana:3000"}' "$local/uwu/v1/apps")
  GRAFANA_CLIENT_ID=$(field "['clientId']" <<<"$grafana")
  GRAFANA_CLIENT_SECRET=$(field "['clientSecret']" <<<"$grafana")
  export GRAFANA_CLIENT_ID GRAFANA_CLIENT_SECRET
  forgejo=$(api -d '{"name":"Forgejo","template":"forgejo","url":"http://forgejo:3000","slug":"uwuauth"}' "$local/uwu/v1/apps")
  docker compose --profile oidc up -d grafana forgejo >/dev/null
  for _ in $(seq 1 120); do
    docker compose exec -T forgejo curl -sf http://localhost:3000/api/healthz >/dev/null 2>&1 && break
    sleep 1
  done
  docker compose exec -T -u git forgejo forgejo admin auth add-oauth --name uwuauth --provider openidConnect \
    --key "$(field "['clientId']" <<<"$forgejo")" --secret "$(field "['clientSecret']" <<<"$forgejo")" \
    --auto-discover-url "$public/.well-known/openid-configuration" --scopes "openid profile email groups" >/dev/null
  for _ in $(seq 1 120); do
    docker compose exec -T grafana wget -qO- http://localhost:3000/api/health >/dev/null 2>&1 && break
    sleep 1
  done

  step "a browser signs in to both"
  # Playwright's package from package.json (pnpm install here first); its browsers come with the image.
  docker run --rm --ipc=host --network uwuauth-interop_default -v "$PWD:/interop:ro" \
    mcr.microsoft.com/playwright:v1.63.0-noble node /interop/oidc.mjs "$public" nyu "correct horse battery"
fi

if [ "$what" = nextcloud ]; then
  step "Nextcloud"
  secret=$(api -d '{"name":"nextcloud"}' "$local/uwu/v1/ldap/accounts" | field "['secret']")
  app=$(api -d '{"name":"Nextcloud","template":"nextcloud","url":"http://nextcloud"}' "$local/uwu/v1/apps")
  docker compose --profile nextcloud up -d nextcloud >/dev/null
  occ() { docker compose exec -T -u www-data nextcloud php occ "$@"; }
  for _ in $(seq 1 180); do occ status 2>/dev/null | grep -q 'installed: true' && break; sleep 2; done
  occ status | grep -q 'installed: true' || { echo "Nextcloud did not finish installing" >&2; exit 1; }

  echo "-- LDAP"
  occ app:enable user_ldap >/dev/null
  config=$(occ ldap:create-empty-config -p | tail -1)
  for pair in \
    "ldapHost ldap://uwuauth" "ldapPort 10389" "ldapAgentName cn=nextcloud,ou=services,dc=example,dc=com" \
    "ldapAgentPassword $secret" "ldapBase dc=example,dc=com" "ldapBaseUsers ou=people,dc=example,dc=com" \
    "ldapBaseGroups ou=groups,dc=example,dc=com" "ldapUserFilter (objectClass=inetOrgPerson)" \
    "ldapUserFilterObjectclass inetOrgPerson" "ldapLoginFilter (&(objectClass=inetOrgPerson)(uid=%uid))" \
    "ldapGroupFilter (objectClass=groupOfNames)" "ldapGroupMemberAssocAttr member" \
    "ldapUserDisplayName cn" "ldapEmailAttribute mail" "ldapExpertUUIDUserAttr entryUUID" \
    "ldapExpertUUIDGroupAttr entryUUID" "ldapExpertUsernameAttr uid" "turnOffCertCheck 1" "ldapConfigurationActive 1"; do
    occ ldap:set-config "$config" ${pair%% *} "${pair#* }" >/dev/null
  done
  occ ldap:test-config "$config"
  occ ldap:search nyu | tee "$work/ldap-search"
  grep -q 'nyu' "$work/ldap-search" || { echo "Nextcloud did not find nyu over LDAP" >&2; exit 1; }
  occ group:list | grep -q familie || { echo "Nextcloud did not find the group familie" >&2; exit 1; }
  echo "Nextcloud finds people and groups over LDAP"
  # The same person comes through OpenID Connect next: one backend at a time.
  occ ldap:set-config "$config" ldapConfigurationActive 0 >/dev/null

  echo "-- OpenID Connect"
  occ app:install user_oidc >/dev/null
  occ user_oidc:provider UwUAuth --clientid "$(field "['clientId']" <<<"$app")" \
    --clientsecret "$(field "['clientSecret']" <<<"$app")" \
    --discoveryuri "$public/.well-known/openid-configuration" --scope "openid profile email groups" \
    --unique-uid 0 --mapping-uid preferred_username >/dev/null
  occ config:system:set allow_local_remote_servers --value true --type boolean >/dev/null
  # user_oidc wants Nextcloud on https, except in debug mode: here everything is plain http
  # inside one Docker network.
  occ config:system:set debug --value true --type boolean >/dev/null
  docker run --rm --ipc=host --network uwuauth-interop_default -v "$PWD:/interop:ro" \
    mcr.microsoft.com/playwright:v1.63.0-noble node /interop/nextcloud.mjs "$public" nyu "correct horse battery"
fi

step "all good"
