#!/bin/sh
# Wrapper entrypoint for dnsmasq-hijack.
# Generates hijack config from PORTAL_IP and HIJACK_DNS_IP environment variables.

PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
HIJACK_DNS_IP="${HIJACK_DNS_IP:?HIJACK_DNS_IP required}"

# Generate hijack.conf from environment variables
cat > /tmp/hijack.conf << EOF
# DNS Hijacking DNSmasq Configuration (generated from environment)
# This instance runs on ${HIJACK_DNS_IP} and redirects ALL domains to captive portal
listen-address=${HIJACK_DNS_IP}
bind-interfaces
no-resolv
address=/#/${PORTAL_IP}
log-queries
log-facility=/var/log/dnsmasq-hijack.log
EOF

exec dnsmasq -k --conf-file=/tmp/hijack.conf "$@"
