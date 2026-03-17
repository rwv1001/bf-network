#!/bin/sh
# FreeRADIUS entrypoint script
# Substitutes environment variables in config files

set -e

echo "Starting FreeRADIUS with environment variable substitution..."

# Substitute variables in clients.conf using sed
if [ -f /etc/freeradius/clients.conf.template ]; then
    echo "Generating clients.conf from template..."
    sed \
        -e "s/\${RADIUS_SECRET}/${RADIUS_SECRET}/g" \
        -e "s/\${SWITCH_HOST}/${SWITCH_HOST}/g" \
        -e "s/\${SW2_IP}/${SW2_IP}/g" \
        -e "s/\${PORTAL_IP}/${PORTAL_IP}/g" \
        /etc/freeradius/clients.conf.template > /etc/freeradius/clients.conf
    echo "clients.conf generated with vars from environment"
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
        -e "s/\${SWITCH_HOST}/${SWITCH_HOST}/g" \
        /etc/freeradius/proxy.conf.template > /etc/freeradius/proxy.conf
    echo "proxy.conf generated with RADIUS_SECRET and SWITCH_HOST from environment"
fi

# Set proper permissions
chmod 640 /etc/raddb/clients.conf 2>/dev/null || true

# Start FreeRADIUS (the executable is called 'freeradius' not 'radiusd' in this image)
echo "Starting freeradius..."
exec freeradius -X -f
