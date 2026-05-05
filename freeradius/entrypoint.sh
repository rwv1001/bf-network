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
        require_message_authenticator = false
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

# Start FreeRADIUS (the executable is called 'freeradius' not 'radiusd' in this image)
echo "Starting freeradius..."
exec freeradius -X -f
