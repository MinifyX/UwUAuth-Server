#!/usr/bin/env bash
# Inside the SSSD container: point SSSD at UwUAuth, then look people up and sign one in.
#   sssd.sh <ldap uri> <base dn> <bind dn> <bind password> <user> <password> <group>
set -euo pipefail
uri="$1" base="$2" bind_dn="$3" bind_password="$4" user="$5" password="$6" group="$7"

cat >/etc/sssd/sssd.conf <<CONF
[sssd]
services = nss, pam
domains = uwuauth

[domain/uwuauth]
id_provider = ldap
auth_provider = ldap
ldap_uri = $uri
ldap_search_base = $base
ldap_default_bind_dn = $bind_dn
ldap_default_authtok = $bind_password
ldap_schema = rfc2307bis
ldap_user_search_base = ou=people,$base
ldap_group_search_base = ou=groups,$base
ldap_group_member = member
ldap_user_uuid = entryUUID
ldap_group_uuid = entryUUID
ldap_id_use_start_tls = false
ldap_auth_disable_tls_never_use_in_production = true
cache_credentials = false
enumerate = false
CONF
chmod 600 /etc/sssd/sssd.conf
sed -i 's/^passwd:.*/passwd: files sss/; s/^group:.*/group: files sss/' /etc/nsswitch.conf
cat >/etc/pam.d/uwuauth-test <<PAM
auth required pam_sss.so
account required pam_sss.so
PAM
sssd -i >/var/log/sssd.log 2>&1 &
for _ in $(seq 1 50); do getent passwd "$user" >/dev/null && break; sleep 0.2; done

echo "== getent passwd $user"
getent passwd "$user"
echo "== id $user"
id "$user"
id "$user" | grep -q "($group)" || { echo "$user is not in $group" >&2; exit 1; }
echo "== getent group $group"
getent group "$group"
echo "== signing in as $user"
printf '%s\n' "$password" | pamtester uwuauth-test "$user" authenticate
if printf 'wrong password\n' | pamtester uwuauth-test "$user" authenticate 2>/dev/null; then
  echo "a wrong password signed in" >&2
  exit 1
fi
echo "sssd ok"
