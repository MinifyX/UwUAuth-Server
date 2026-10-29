#!/bin/sh
# Forward auth through a real Caddy, the way a browser goes: off to UwUAuth, signed in, back
# with the cookie for the whole domain, into the app; a host nobody set up stays shut; signing
# out closes the app again.
#
#   forward-auth.sh <UwUAuth's public address> <user name> <password>
set -eu
public="$1"
user="$2"
password="$3"
jar=/tmp/jar
app='http://whoami.example.test/hello?x=1'

fail() {
  echo "forward-auth: $*" >&2
  exit 1
}
# The status and where it points, through the cookie jar.
ask() { curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -b "$jar" -c "$jar" "$@"; }
api() { curl -sf -b "$jar" -c "$jar" -H "Origin: $public" -H 'content-type: application/json' "$@"; }

echo "-- not signed in: off to UwUAuth"
out=$(ask "$app")
[ "${out%% *}" = 302 ] || fail "expected 302, got: $out"
back="${out#* }"
case "$back" in
"$public/oauth/forward-auth?rd=http%3A%2F%2Fwhoami.example.test%2Fhello%3Fx%3D1") ;;
*) fail "unexpected way to UwUAuth: $back" ;;
esac

echo "-- signed in at UwUAuth, and back with the cookie"
api -d "{\"login\":\"$user\",\"password\":\"$password\"}" "$public/uwu/v1/login" >/dev/null
out=$(ask "$back")
case "$out" in
"302 $app" | "303 $app") ;;
*) fail "expected the way back to the app, got: $out" ;;
esac
# Curl writes HttpOnly cookies with a #HttpOnly_ prefix.
grep -Eq '^(#HttpOnly_)?\.example\.test[[:space:]].*uwuauth_fa' "$jar" ||
  fail "no forward-auth cookie for .example.test: $(cat "$jar")"

echo "-- the app sees who it is"
body=$(curl -sf -b "$jar" "$app") || fail "the app did not answer"
echo "$body" | grep -qi "^Remote-User: $user" || fail "no Remote-User: $body"
echo "$body" | grep -qi '^Remote-Groups: .*familie' || fail "no Remote-Groups: $body"

echo "-- a host no app has stays shut"
out=$(ask http://other.example.test/)
[ "${out%% *}" = 403 ] || fail "expected 403 for an unknown host, got: $out"

echo "-- signed out: the app asks again"
api -d '{}' "$public/uwu/v1/logout" >/dev/null
out=$(ask "$app")
[ "${out%% *}" = 302 ] || fail "expected 302 after signing out, got: $out"
echo "forward auth through Caddy works"
