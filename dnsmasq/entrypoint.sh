#!/bin/sh
# Wrapper entrypoint for dnsmasq-normal.
#
# dnsmasq creates its log file with mode 660 (owner: dhcpcd, group: root),
# which prevents the dns-parser container from reading it.  We can't chmod
# before exec because dnsmasq recreates the file at startup.  Instead we
# schedule a one-shot chmod 3 seconds after startup in a background subshell,
# then exec dnsmasq so it becomes PID 1 and handles signals normally.

(sleep 3 && chmod 644 /var/log/dnsmasq-queries.log) &

# Derive the portal domain from PORTAL_URL and inject it as a dnsmasq address
# record so the portal hostname resolves to 192.168.99.4 on VLAN 99.
# PORTAL_URL comes from captive-portal/.env via the env_file in docker-compose.
if [ -n "${PORTAL_URL:-}" ]; then
    PORTAL_DOMAIN=$(printf '%s' "$PORTAL_URL" | sed 's|https\?://||' | cut -d/ -f1)
    printf 'address=/%s/192.168.99.4\n' "$PORTAL_DOMAIN" > /tmp/portal-address.conf
    exec dnsmasq "$@" --conf-file=/tmp/portal-address.conf
else
    exec dnsmasq "$@"
fi
