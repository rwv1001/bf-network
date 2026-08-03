#!/bin/sh
set -e

echo "Starting FreeRADIUS with environment variable substitution..."

# First switch for proxy.conf (if template uses ${SWITCH_HOST})
SWITCH_HOST="$(echo "${SWITCH_HOSTS:-}" | awk '{print $1}')"
export RADIUS_SECRET PORTAL_IP DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD SWITCH_HOST

if [ -f /etc/freeradius/clients.conf.template ]; then
    echo "Generating clients.conf from template..."
    envsubst '${RADIUS_SECRET} ${PORTAL_IP}' \
        < /etc/freeradius/clients.conf.template > /etc/freeradius/clients.conf

    idx=0
    for sw_ip in ${SWITCH_HOSTS}; do
        idx=$((idx + 1))
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

if [ -f /etc/freeradius/sql.template ]; then
    envsubst '${DB_HOST} ${DB_PORT} ${DB_NAME} ${DB_USER} ${DB_PASSWORD}' \
        < /etc/freeradius/sql.template > /etc/freeradius/mods-enabled/sql
    echo "sql module generated with DB settings from environment"
fi

if [ -f /etc/freeradius/proxy.conf.template ]; then
    envsubst '${RADIUS_SECRET} ${SWITCH_HOST}' \
        < /etc/freeradius/proxy.conf.template > /etc/freeradius/proxy.conf
    echo "proxy.conf generated with RADIUS_SECRET and SWITCH_HOST from environment"
fi

chmod 644 /etc/freeradius/clients.conf 2>/dev/null || true

echo "Starting freeradius..."
exec freeradius -f