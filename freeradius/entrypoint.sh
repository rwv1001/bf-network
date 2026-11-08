#!/bin/sh
# FreeRADIUS entrypoint script
# Substitutes environment variables in config files

set -e

echo "Starting FreeRADIUS with environment variable substitution..."

# Substitute variables in clients.conf using sed
if [ -f /etc/freeradius/clients.conf.template ]; then
    echo "Generating clients.conf from template..."
    # Base stanzas (portal + localhost)
    sed \
        -e "s/\${RADIUS_SECRET}/${RADIUS_SECRET}/g" \
        -e "s/\${PORTAL_IP}/${PORTAL_IP}/g" \
        /etc/freeradius/clients.conf.template > /etc/freeradius/clients.conf

    # One client stanza per switch in SWITCH_HOSTS
    #
    # BlastRADIUS (CVE-2024-3596): HP5130/Comware MAC-auth Access-Requests
    # (PAP, Service-Type = Call-Check) contain no Message-Authenticator, so
    # require_message_authenticator must stay "false" for these clients or
    # MAC authentication stops working. Do NOT use "auto": the same switch
    # also sends 802.1X/EAP requests that DO carry it, and auto would then
    # start rejecting the MAC-auth requests. limit_proxy_state = true still
    # blocks the Proxy-State vector. The remaining exposure requires an
    # attacker on-path between the switch and this host on the management
    # VLAN; closing it fully needs HPE firmware that adds the attribute
    # (set SWITCH_RADIUS_REQUIRE_MA=yes once such firmware is running).
    sw_require_ma="${SWITCH_RADIUS_REQUIRE_MA:-false}"
    idx=0
    for sw_ip in ${SWITCH_HOSTS}; do
        idx=$((idx + 1))
        echo "" >> /etc/freeradius/clients.conf
        cat >> /etc/freeradius/clients.conf <<EOF
# HP 5130 switch ${idx} - MAC authentication
client hp5130-sw${idx} {
        ipaddr = ${sw_ip}
        secret = ${RADIUS_SECRET}
        shortname = hp5130-sw${idx}
        nas_type = other
        require_message_authenticator = ${sw_require_ma}
        limit_proxy_state = true
}
EOF
        echo "  Added RADIUS client for switch ${idx}: ${sw_ip}"
    done
    echo "clients.conf generated (${idx} switch(es))"
else
    echo "Warning: No clients.conf.template found, using existing clients.conf"
fi

# Substitute variables in sql module config if present
if [ -f /etc/freeradius/sql.template ]; then
    sed \
        -e "s/\${DB_HOST}/${DB_HOST}/g" \
        -e "s/\${DB_PORT}/${DB_PORT}/g" \
        -e "s/\${DB_NAME}/${DB_NAME}/g" \
        -e "s/\${DB_USER}/${DB_USER}/g" \
        -e "s/\${DB_PASSWORD}/${DB_PASSWORD}/g" \
        /etc/freeradius/sql.template > /etc/freeradius/mods-enabled/sql
    echo "sql module generated with DB settings from environment"
fi

# Substitute variables in proxy.conf from template if present
if [ -f /etc/freeradius/proxy.conf.template ]; then
    sed \
        -e "s/\${RADIUS_SECRET}/${RADIUS_SECRET}/g" \
        -e "s/\${SWITCH_HOST}/$(echo "${SWITCH_HOSTS:-}" | awk '{print $1}')/g" \
    /etc/freeradius/proxy.conf.template > /etc/freeradius/proxy.conf
    echo "proxy.conf generated with RADIUS_SECRET and SWITCH_HOSTS from environment"
fi

# Set proper permissions
chmod 640 /etc/raddb/clients.conf 2>/dev/null || true

# Validate the generated configuration before starting so a template error
# is reported once, clearly, instead of a silent restart loop.
if ! freeradius -C -f >/tmp/radius-check.log 2>&1; then
    echo "FATAL: FreeRADIUS configuration check failed:" >&2
    grep -E "Errors reading|error|EOF reached|Failed|Unknown|expected" /tmp/radius-check.log >&2 || cat /tmp/radius-check.log >&2
    echo "Generated /etc/freeradius/clients.conf (secrets redacted):" >&2
    sed -E 's/(secret *= *).*/\1<redacted>/' /etc/freeradius/clients.conf >&2
    exit 1
fi

# Start FreeRADIUS (the executable is called 'freeradius' not 'radiusd' in this image)
echo "Starting freeradius..."
exec freeradius -X -f