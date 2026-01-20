FROM jonasal/kea-dhcp4:3.0-alpine

# Install iptables and postgresql-client for DNS hijack hook
RUN apk add --no-cache iptables postgresql-client

# Use the original entrypoint
ENTRYPOINT ["/entrypoint.sh"]
