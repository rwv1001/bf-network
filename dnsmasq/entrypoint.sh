#!/bin/sh
# Wrapper entrypoint for dnsmasq-hijack.
# Generates hijack config from PORTAL_IP and HIJACK_DNS_IP environment variables.

PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
HIJACK_DNS_IP="${HIJACK_DNS_IP:?HIJACK_DNS_IP required}"

# Microsoft identity domains used by the pre-auth device-code sign-in. These
# resolve to HIJACK_DNS_IP (where the SNI relay intercepts 443) instead of the
# portal IP, so the relay never sits in front of NPM and the portal always
# sees the real client IP. Must stay a superset-compatible subset of the
# relay's allow-list (scripts/preauth_sni_proxy.py DEFAULT_ALLOWED_SNI).
PREAUTH_MS_DOMAINS="${PREAUTH_ALLOWED_SNI:-microsoft.com,login.microsoftonline.com,login.microsoft.com,login.windows.net,login.live.com,login.microsoftonline-p.com,account.activedirectory.windowsazure.com,accounts.accesscontrol.windows.net,autologon.microsoftazuread-sso.com,secure.aadcdn.microsoftonline-p.com,msauth.net,msauthimages.net,msftauth.net,msftauthimages.net,phonefactor.net}"

preauth_enabled=0
case "${PREAUTH_HTTPS_RELAY_ENABLED:-auto}" in
  1|true|yes|on) preauth_enabled=1 ;;
  auto) [ -n "${DOMAIN_AUTH_PROVIDERS:-}" ] && preauth_enabled=1 ;;
esac

# Generate hijack.conf from environment variables
cat > /tmp/hijack.conf << EOF
# DNS Hijacking DNSmasq Configuration (generated from environment)
# This instance runs on ${HIJACK_DNS_IP} and redirects ALL domains to captive portal
listen-address=${HIJACK_DNS_IP}
bind-interfaces
no-resolv
EOF

if [ "$preauth_enabled" = "1" ]; then
  # Specific address lines take precedence over the catch-all below.
  echo "$PREAUTH_MS_DOMAINS" | tr ',;' '\n\n' | while read -r dom; do
    dom="$(echo "$dom" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^\*\.//')"
    [ -n "$dom" ] && echo "address=/${dom}/${HIJACK_DNS_IP}" >> /tmp/hijack.conf
  done
fi

cat >> /tmp/hijack.conf << EOF
address=/#/${PORTAL_IP}
log-queries
log-facility=/var/log/dnsmasq-hijack.log
EOF

exec dnsmasq -k --conf-file=/tmp/hijack.conf "$@"
