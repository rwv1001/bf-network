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
#                          a non-Ten port wins.
#                          Example: SWITCH_HOSTS="192.168.99.2 192.168.99.3"
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

# Near the top, after MAC_COLON is set
LOG_FILE="${PORT_LOOKUP_LOG:-/kea/logs/hp5130-port-lookup.log}"
log() {
    # timestamp + message; ignore failures if log dir missing
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >> "$LOG_FILE" 2>/dev/null || true
    # optional: also stderr when not discarded
    echo "$*" >&2
}

log "START mac=$MAC_COLON raw=$MAC_RAW"

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

# Run SQL: logs statement + result. For -tAc (tuples only) prints one line.
# Usage: run_sql_tAc "SELECT ..."
# Sets RUN_SQL_RESULT
run_sql_tAc() {
    _sql="$1"
    log "SQL: $_sql"
    RUN_SQL_RESULT="$(PGPASSWORD="$DB_PASSWORD" \
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "$_sql" 2>/dev/null | tr -d ' \n\r' || true)"
    log "SQL_RESULT: '${RUN_SQL_RESULT:-<empty>}'"
}

# Usage: run_sql_c "UPDATE/INSERT ..."
run_sql_c() {
    _sql="$1"
    log "SQL: $_sql"
    set +e
    _out="$(PGPASSWORD="$DB_PASSWORD" \
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -c "$_sql" 2>&1)"
    _rc=$?
    set -e
    # collapse newlines for the log line
    _out_one="$(printf '%s' "$_out" | tr '\n' ' ' | tr -s ' ')"
    log "SQL_RC=$_rc SQL_OUT: ${_out_one:-<empty>}"
    return 0
}

# ---------------------------------------------------------------------------
# Fresh-cache check
# ---------------------------------------------------------------------------
FRESHNESS_TTL="${SWITCH_PORT_LOOKUP_CACHE_TTL:-120}"   # seconds
run_sql_tAc "SELECT switch_iface FROM mac_port_cache
 WHERE mac_address = '${MAC_COLON}'
   AND last_seen > NOW() - INTERVAL '${FRESHNESS_TTL} seconds'
 LIMIT 1"
CACHED="$RUN_SQL_RESULT"
if [ -n "$CACHED" ]; then
    # Cache hit – SSH query not needed, but still backfill devices.switch_iface
    # in case the device was registered after the initial lookup ran.
    log "CACHE_HIT mac=$MAC_COLON iface=$CACHED"
    run_sql_c "UPDATE devices
 SET switch_iface = '${CACHED}', switch_iface_seen_at = NOW() WHERE mac_address = '${MAC_COLON}' AND (switch_iface IS NULL OR switch_iface != '${CACHED}');"
    exit 0
fi
log "CACHE_MISS mac=$MAC_COLON ttl=${FRESHNESS_TTL}s"

# ---------------------------------------------------------------------------
# SSH configuration
# ---------------------------------------------------------------------------
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/keys/id_rsa}"

# Build ordered switch list from SWITCH_HOSTS, falling back to SWITCH_HOST
if [ -n "${SWITCH_HOSTS:-}" ]; then
    SWITCH_LIST="$SWITCH_HOSTS"
else
    echo "SWITCH_HOSTS is not set – skipping port lookup for $MAC_COLON" >&2
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
        log "MISS mac=$MAC_COLON switch=$_SW"
        continue
    fi
    FINAL_HOST="$_SW"
    _IFACE_EXP="$IFACE"
    case "$IFACE" in
        GE*)  _IFACE_EXP="GigabitEthernet${IFACE#GE}" ;;
        XGE*) _IFACE_EXP="Ten-GigabitEthernet${IFACE#XGE}" ;;
    esac

    # Flexible match: short name, long name, or suffix (1/0/47)
    _SUF="$(printf '%s' "$_IFACE_EXP" | sed -E 's/.*(GigabitEthernet|Ten-GigabitEthernet|GE|XGE)//I')"
    run_sql_tAc "SELECT port_role FROM switch_ports
 WHERE switch_host = '${_SW}'
   AND port_role = 'inter_switch'
   AND (
     port_name IN ('${IFACE}', '${_IFACE_EXP}', 'GE${_SUF}', 'GigabitEthernet${_SUF}',
                   'XGE${_SUF}', 'Ten-GigabitEthernet${_SUF}')
     OR port_name LIKE '%${_SUF}'
   )
 LIMIT 1"
    _ROLE="$RUN_SQL_RESULT"

    if [ "$_ROLE" = "inter_switch" ]; then
        log "TRUNK mac=$MAC_COLON switch=$_SW iface=$IFACE – continue"
    else
        log "ACCESS mac=$MAC_COLON switch=$_SW iface=$IFACE – stop"
        break
    fi
done

if [ -z "$IFACE" ] || [ -z "$FINAL_HOST" ]; then
    log "NOT_FOUND mac=$MAC_COLON hosts=$SWITCH_LIST"
    exit 0
fi
log "FOUND mac=$MAC_COLON iface=$IFACE switch=$FINAL_HOST"

case "$IFACE" in
    GE*)  IFACE="GigabitEthernet${IFACE#GE}" ;;
    XGE*) IFACE="Ten-GigabitEthernet${IFACE#XGE}" ;;
esac

run_sql_c "INSERT INTO mac_port_cache (mac_address, switch_iface, switch_host, last_seen)
 VALUES ('${MAC_COLON}', '${IFACE}', '${FINAL_HOST}', NOW())
 ON CONFLICT (mac_address) DO UPDATE SET
     switch_iface  = EXCLUDED.switch_iface,
     switch_host   = EXCLUDED.switch_host,
     last_seen     = NOW();"

run_sql_c "UPDATE devices SET switch_iface = '${IFACE}', switch_host = '${FINAL_HOST}', switch_iface_seen_at = NOW() WHERE mac_address = '${MAC_COLON}';"

log "DB_OK mac=$MAC_COLON iface=$IFACE switch=$FINAL_HOST"
exit 0
