FROM jonasal/kea-dhcp4:3.0-alpine

# Install iptables, kea (for kea-lfc), postgresql-client, and ssh client for hook scripts
RUN apk add --no-cache iptables kea postgresql-client openssh-client

# Use the original entrypoint
ENTRYPOINT ["/entrypoint.sh"]
