# A Linux machine that signs people in through UwUAuth's LDAP, with SSSD.
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      sssd-ldap libnss-sss libpam-sss pamtester ldap-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
