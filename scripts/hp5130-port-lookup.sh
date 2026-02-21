#!/bin/sh
# hp5130-port-lookup.sh - Background switch port lookup for a single MAC
# Called asynchronously by the Kea DHCP hook. Discovers which switch port a
# device is plugged into and writes the result to the DB cache.
#
# Usage:  hp5130-port-lookup.sh <mac>
#   <mac> can be in any format (colons, dashes, or plain hex)
#
# Environment variables (inherited from Kea container):
#   SWITCH_HOSTS           Space-separated ordered list of switch IPs to query.
#                          Each switch is tried in turn; if the result port name
#                          contains 'Ten' (i.e. a Ten-GigabitEthernet uplink/trunk)
#                          the next switch in the list is tried, because the device
#                          is downstream of that trunk.  The first switch to return
#                          a non-Ten port wins.  Falls back to SWITCH_HOST if unset.
#                          Example: SWITCH_HOSTS="192.168.99.2 192.168.99.3"
#   SWITCH_HOST            Fallback single switch IP (used if SWITCH_HOSTS is unset)
#   SWITCH_USER, SWITCH_SSH_PORT, SWITCH_KEY_PATH
#   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
#   SWITCH_PORT_LOOKUP_CACHE_TTL  (seconds before re-querying; default 120)

set -e

MAC_RAW="${1:-}"
if [ -z "$MAC_RAW" ]; then
    echo "Usage: $0 <mac-address>" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Normalize MAC to lowercase colon-separated  (aa:bb:cc:dd:ee:ff)
# ---------------------------------------------------------------------------
MAC_HEX="$(printf '%s' "$MAC_RAW" | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f')"
if [ "${#MAC_HEX}" -ne 12 ]; then
    echo "Invalid MAC (${#MAC_HEX} hex digits): $MAC_RAW" >&2
    exit 2
fi
MAC_COLON="$(printf '%s' "$MAC_HEX" | sed 's/\(..\)/\1:/g; s/:$//')"

# HP5130 uses 4-char groups:  aabb-ccdd-eeff
MAC_LOOKUP="$(printf '%s' "$MAC_HEX" | sed 's/\(....\)/\1-/g; s/-$//')"

# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-captive_portal}"
DB_USER="${DB_USER:-portal_user}"
DB_PASSWORD="${DB_PASSWORD:-}"

# ---------------------------------------------------------------------------
# Fresh-cache check – skip SSH if we already have a recent entry
# ---------------------------------------------------------------------------
FRESHNESS_TTL="${SWITCH_PORT_LOOKUP_CACHE_TTL:-120}"   # seconds
CACHED="$(PGPASSWORD="$DB_PASSWORD" \
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT switch_iface FROM mac_port_cache
     WHERE mac_address = '${MAC_COLON}'
       AND last_seen > NOW() - INTERVAL '${FRESHNESS_TTL} seconds'
     LIMIT 1" 2>/dev/null | tr -d ' \n\r' || true)"
if [ -n "$CACHED" ]; then
    # Cache hit – nothing to do
    exit 0
fi

# ---------------------------------------------------------------------------
# SSH configuration
# ---------------------------------------------------------------------------
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/keys/id_rsa}"

# Build ordered switch list from SWITCH_HOSTS, falling back to SWITCH_HOST
if [ -n "${SWITCH_HOSTS:-}" ]; then
    SWITCH_LIST="$SWITCH_HOSTS"
elif [ -n "${SWITCH_HOST:-}" ]; then
    SWITCH_LIST="$SWITCH_HOST"
else
    echo "Neither SWITCH_HOSTS nor SWITCH_HOST is set – skipping port lookup for $MAC_COLON" >&2
    exit 3
fi

SSH_OPTS="-tt -i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2"

# ---------------------------------------------------------------------------
# Helper: query one switch for the MAC.
# Sets IFACE to the raw port name as the switch reported it (e.g. GE3/0/1,
# XGE1/0/28).  Returns "" if the MAC is not found.
# ---------------------------------------------------------------------------
query_switch() {
    _HOST="$1"
    set +e
    _OUT="$(printf 'display mac-address | include %s\nquit\n' "$MAC_LOOKUP" \
        | ssh $SSH_OPTS "${SWITCH_USER}@${_HOST}" 2>/dev/null)"
    set -e
    if [ -z "$_OUT" ]; then
        set +e
        _OUT="$(printf 'display mac-address dynamic | include %s\nquit\n' "$MAC_LOOKUP" \
            | ssh $SSH_OPTS "${SWITCH_USER}@${_HOST}" 2>/dev/null)"
        set -e
    fi
    MAC_UPPER="$(printf '%s' "$MAC_HEX" | tr 'a-z' 'A-Z')"
    IFACE="$(printf '%s\n' "$_OUT" | awk -v mac="$MAC_UPPER" '
    {
        field = toupper($1)
        gsub(/[-]/, "", field)
        if (field == mac) { print $4; exit }
    }')"
}

# ---------------------------------------------------------------------------
# Walk SWITCH_LIST in order.
# If a switch reports the MAC on a Ten-GigabitEthernet port (uplink/trunk)
# the device is downstream, so try the next switch in the list.
# Stop at the first non-Ten result, or keep the last result if all are Ten.
# ---------------------------------------------------------------------------
FINAL_HOST=""
IFACE=""

for _SW in $SWITCH_LIST; do
    query_switch "$_SW"
    if [ -z "$IFACE" ]; then
        # Not found on this switch – try the next one
        echo "Port lookup: MAC $MAC_COLON not found on $_SW – trying next" >&2
        continue
    fi
    FINAL_HOST="$_SW"
    case "$IFACE" in
        XGE*)
            # Ten-GigabitEthernet uplink/trunk – device is downstream; try next switch
            echo "Port lookup: MAC $MAC_COLON on $IFACE at $_SW – looking downstream" >&2
            ;;
        *)
            # Concrete access port (GE or similar) – done
            break
            ;;
    esac
done

if [ -z "$IFACE" ] || [ -z "$FINAL_HOST" ]; then
    # MAC not found on any switch – nothing to store
    exit 0
fi

# ---------------------------------------------------------------------------
# Expand short abbreviations for DB storage
# ---------------------------------------------------------------------------
case "$IFACE" in
    GE*)  IFACE="GigabitEthernet${IFACE#GE}" ;;
    XGE*) IFACE="Ten-GigabitEthernet${IFACE#XGE}" ;;
esac

# ---------------------------------------------------------------------------
# Persist to DB:  mac_port_cache  +  devices.switch_iface
# ---------------------------------------------------------------------------
PGPASSWORD="$DB_PASSWORD" \
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "INSERT INTO mac_port_cache (mac_address, switch_iface, switch_host, last_seen)
        VALUES ('${MAC_COLON}', '${IFACE}', '${FINAL_HOST}', NOW())
        ON CONFLICT (mac_address) DO UPDATE SET
            switch_iface  = EXCLUDED.switch_iface,
            switch_host   = EXCLUDED.switch_host,
            last_seen     = NOW();" \
    -c "UPDATE devices
        SET switch_iface = '${IFACE}', switch_iface_seen_at = NOW()
        WHERE mac_address = '${MAC_COLON}';" \
    2>/dev/null || true

exit 0
