#!/bin/sh
# Entrypoint for the preauth-relay container (host network, NET_ADMIN).
#
# The hijack dnsmasq answers Microsoft identity domains with HIJACK_DNS_IP and
# everything else with PORTAL_IP. Only HIJACK_DNS_IP:443 is diverted into the
# SNI relay, which forwards allow-listed Microsoft identity SNIs to the real
# internet and closes everything else. Portal traffic (PORTAL_IP:443) goes
# straight to NPM, so the portal always sees the real client IP.
set -eu

ENABLED="${PREAUTH_HTTPS_RELAY_ENABLED:-auto}"
case "$ENABLED" in
  0|false|no|off)
    echo "preauth-relay: disabled (PREAUTH_HTTPS_RELAY_ENABLED=$ENABLED)"
    exec sleep infinity
    ;;
  auto)
    if [ -z "${DOMAIN_AUTH_PROVIDERS:-}" ]; then
      echo "preauth-relay: disabled (no DOMAIN_AUTH_PROVIDERS configured)"
      exec sleep infinity
    fi
    ;;
esac

[ -n "${HIJACK_DNS_IP:-}" ] || { echo "preauth-relay: HIJACK_DNS_IP required" >&2; exit 1; }
PROXY_PORT="${PREAUTH_PROXY_PORT:-8443}"

apk add --no-cache iptables >/dev/null

RULE="-p tcp -d $HIJACK_DNS_IP --dport 443 -j REDIRECT --to-ports $PROXY_PORT"

remove_rules() {
  # Sweep ALL redirects to the relay port, including stale rules left by
  # earlier versions that intercepted PORTAL_IP:443 (those hide the real
  # client IP from the portal and must never survive an upgrade).
  iptables -t nat -S PREROUTING | grep -- "--to-ports $PROXY_PORT" | sed 's/^-A //' | \
  while read -r spec; do
    # shellcheck disable=SC2086
    iptables -t nat -D PREROUTING $spec 2>/dev/null || true
  done
}

remove_rules
# shellcheck disable=SC2086
iptables -t nat -I PREROUTING 1 $RULE
echo "preauth-relay: nat PREROUTING redirect $HIJACK_DNS_IP:443 -> :$PROXY_PORT installed"

trap 'remove_rules; echo "preauth-relay: redirect removed"' EXIT INT TERM

exec python3 /preauth_sni_proxy.py
