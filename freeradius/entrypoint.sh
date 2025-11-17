#!/bin/sh
# FreeRADIUS entrypoint script
# Substitutes environment variables in config files

set -e

echo "Starting FreeRADIUS with environment variable substitution..."

# Substitute variables in clients.conf using sed
if [ -f /etc/raddb/clients.conf.template ]; then
    echo "Generating clients.conf from template..."
    sed "s/\${RADIUS_SECRET}/${RADIUS_SECRET}/g" /etc/raddb/clients.conf.template > /etc/raddb/clients.conf
    echo "clients.conf generated with RADIUS_SECRET from environment"
else
    echo "Warning: No clients.conf.template found, using existing clients.conf"
fi

# Set proper permissions
chmod 640 /etc/raddb/clients.conf 2>/dev/null || true

# Start FreeRADIUS (the executable is called 'freeradius' not 'radiusd' in this image)
echo "Starting freeradius..."
exec freeradius -X -f
