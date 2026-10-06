#!/bin/sh
# Entrypoint for the preauth-relay container (host network, NET_ADMIN).
#
# Pre-registration clients have ALL DNS answered with PORTAL_IP by the hijack
# dnsmasq, so their Microsoft-login TLS already arrives at this host on 443.
# This entrypoint inserts one nat rule diverting portal-IP:443 into the SNI
# relay, which forwards allow-listed Microsoft identity SNIs to the real
# internet and passes everything else through to the local NPM listener.
# Registered clients reaching the portal by name transit the relay to NPM
# unchanged; no other traffic is affected.
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

[ -n "${PORTAL_IP:-}" ] || { echo "preauth-relay: PORTAL_IP required" >&2; exit 1; }
PROXY_PORT="${PREAUTH_PROXY_PORT:-8443}"

apk add --no-cache iptables >/dev/null

RULE="-p tcp -d $PORTAL_IP --dport 443 -j REDIRECT --to-ports $PROXY_PORT"

remove_rule() {
  # shellcheck disable=SC2086
  while iptables -t nat -D PREROUTING $RULE 2>/dev/null; do :; done
}

remove_rule
# shellcheck disable=SC2086
iptables -t nat -I PREROUTING 1 $RULE
echo "preauth-relay: nat PREROUTING redirect $PORTAL_IP:443 -> :$PROXY_PORT installed"

trap 'remove_rule; echo "preauth-relay: redirect removed"' EXIT INT TERM

exec python3 /preauth_sni_proxy.py
