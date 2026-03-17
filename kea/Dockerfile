FROM jonasal/kea-dhcp4:3.0-alpine

# Install iptables, kea (for kea-lfc), postgresql-client, ssh client for hook scripts,
# and gettext (provides envsubst, used to substitute env vars into dhcp4.json.template)
RUN apk add --no-cache iptables kea postgresql-client openssh-client gettext

# Use the original entrypoint
ENTRYPOINT ["/entrypoint.sh"]
