FROM jonasal/kea-dhcp4:3.0-alpine

# Install iptables, postgresql-client, and ssh client for hook scripts
RUN apk add --no-cache iptables postgresql-client openssh-client

# Use the original entrypoint
ENTRYPOINT ["/entrypoint.sh"]
