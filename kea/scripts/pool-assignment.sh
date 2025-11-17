#!/bin/bash
#
# Kea DHCP Hook Script for Dynamic Pool Assignment
#
# This script is called by Kea's run_script hook library during DHCP processing.
# It queries the captive portal database to determine which pool a MAC should use:
# - REGISTERED: Approved devices (.5-.127, 24h lease, public DNS)
# - NEWLY_UNREGISTERED: First seen <30 min (.128-.191, 60s lease, portal DNS)
# - OLD_UNREGISTERED: First seen >30 min (.192-.254, 24h lease, portal DNS)
#
# Environment variables provided by Kea:
# - KEA_QUERY4_HWADDR: Client MAC address
# - KEA_SUBNET4: Subnet ID
# - KEA_QUERY4_TYPE: DHCP message type (DISCOVER, REQUEST, etc.)

# Configuration
DB_HOST="127.0.0.1"
DB_PORT="5432"
DB_NAME="${POSTGRES_DB:-captive_portal}"
DB_USER="${POSTGRES_USER:-captive_user}"
DB_PASSWORD="${POSTGRES_PASSWORD}"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# Exit if no MAC address provided
if [ -z "$KEA_QUERY4_HWADDR" ]; then
    log "ERROR: No MAC address provided"
    exit 1
fi

MAC="$KEA_QUERY4_HWADDR"
SUBNET="$KEA_SUBNET4"

log "Processing DHCP request: MAC=$MAC, Subnet=$SUBNET, Type=$KEA_QUERY4_TYPE"

# Query database for device registration status and first_seen timestamp
SQL="SELECT registration_status, first_seen, EXTRACT(EPOCH FROM (NOW() - first_seen)) AS age_seconds 
     FROM devices 
     WHERE mac_address = '$MAC';"

RESULT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "$SQL" 2>/dev/null)

if [ -z "$RESULT" ]; then
    # Device not in database - create entry and assign to NEWLY_UNREGISTERED
    log "New device detected: $MAC - creating database entry"
    
    INSERT_SQL="INSERT INTO devices (mac_address, registration_status, first_seen) 
                VALUES ('$MAC', 'pending', NOW()) 
                ON CONFLICT (mac_address) DO NOTHING;"
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$INSERT_SQL" >/dev/null 2>&1
    
    # Set client class to NEWLY_UNREGISTERED
    echo "NEWLY_UNREGISTERED"
    log "Assigned to NEWLY_UNREGISTERED pool"
    exit 0
fi

# Parse result: registration_status | first_seen | age_seconds
STATUS=$(echo "$RESULT" | awk '{print $1}')
AGE_SECONDS=$(echo "$RESULT" | awk '{print $3}')

log "Device found: status=$STATUS, age_seconds=$AGE_SECONDS"

# Determine pool assignment
if [ "$STATUS" = "approved" ]; then
    echo "REGISTERED"
    log "Assigned to REGISTERED pool"
elif [ -n "$AGE_SECONDS" ] && [ "$(echo "$AGE_SECONDS < 1800" | bc)" = "1" ]; then
    # Less than 30 minutes (1800 seconds)
    echo "NEWLY_UNREGISTERED"
    log "Assigned to NEWLY_UNREGISTERED pool (age: ${AGE_SECONDS}s)"
else
    # More than 30 minutes old
    echo "OLD_UNREGISTERED"
    log "Assigned to OLD_UNREGISTERED pool (age: ${AGE_SECONDS}s)"
fi

# Update last_seen timestamp
UPDATE_SQL="UPDATE devices SET last_seen = NOW() WHERE mac_address = '$MAC';"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$UPDATE_SQL" >/dev/null 2>&1

exit 0
