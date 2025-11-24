FROM jonasal/kea-dhcp4:3.0-alpine

# Install iptables for DNS hijack hook
RUN apk add --no-cache iptables

# Use the original entrypoint
ENTRYPOINT ["/entrypoint.sh"]
