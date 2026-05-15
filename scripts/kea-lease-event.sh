#!/bin/sh
# kea-lease-event.sh — Update portal DB on Kea DHCP lease events (Table 6 + Table 7).
# Called asynchronously (double-fork) from dns_hijack_hook.so on every
# lease4_select, lease4_renew, and lease4_expire callout.
#
# Usage: kea-lease-event.sh <action> <mac> <ip> <vlan_id> <lease_seconds> <from_blocked_pool> <dns_hijacked>
#   action:            new_lease | renew | expire
#   mac:               aa:bb:cc:dd:ee:ff
#   ip:                e.g. 192.168.10.5
#   vlan_id:           integer (Kea subnet_id == VLAN ID)
#   lease_seconds:     integer (0 on expire)
#   from_blocked_pool: true | false
#   dns_hijacked:      true | false

ACTION="${1:-}"
MAC_ADDRESS="${2:-}"
IP_ADDRESS="${3:-}"
VLAN_ID="${4:-0}"
LEASE_SECONDS="${5:-3600}"
FROM_BLOCKED_POOL="${6:-false}"
DNS_HIJACKED="${7:-false}"

[ -z "$MAC_ADDRESS" ] || [ -z "$IP_ADDRESS" ] && exit 1

# ── Input validation: prevent SQL injection ──────────────────────────────────
echo "$MAC_ADDRESS" | grep -qE '^[0-9a-fA-F:]{11,17}$'           || exit 1
echo "$IP_ADDRESS"  | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'   || exit 1
echo "$VLAN_ID"     | grep -qE '^[0-9]+$'                          || VLAN_ID=0
echo "$LEASE_SECONDS" | grep -qE '^[0-9]+$'                        || LEASE_SECONDS=3600
[ "$FROM_BLOCKED_POOL" = "true" ] || FROM_BLOCKED_POOL=false
[ "$DNS_HIJACKED"      = "true" ] || DNS_HIJACKED=false

# Override from_blocked_pool with an accurate check against the Kea config.
# The C++ hook's is_blocked_pool_ip() used a naive last-octet check that is
# wrong for /22 subnets; re-derive it here so the DB value is always correct.
_kea_cfg="${KEA_CONFIG_PATH:-/kea/config/dhcp4.json}"
if [ -f "$_kea_cfg" ]; then
    _recalc=$(python3 - <<'PY' "$_kea_cfg" "$IP_ADDRESS" 2>/dev/null
import ipaddress, json, sys
cfg_path, ip_str = sys.argv[1], sys.argv[2]
ip = ipaddress.ip_address(ip_str)
try:
    with open(cfg_path) as fh:
        data = json.load(fh)
except Exception:
    print('false'); sys.exit(0)
for subnet in data.get('Dhcp4', {}).get('subnet4', []):
    net = ipaddress.ip_network(subnet.get('subnet', ''), strict=False)
    if ip not in net:
        continue
    for pool in subnet.get('pools', []):
        if 'BLOCKED' in (pool.get('client-classes') or []):
            start, end = [p.strip() for p in pool['pool'].split('-')]
            for cidr in ipaddress.summarize_address_range(
                    ipaddress.ip_address(start), ipaddress.ip_address(end)):
                if ip in cidr:
                    print('true'); sys.exit(0)
    print('false'); sys.exit(0)
print('false')
PY
    )
    [ "$_recalc" = "true" ] && FROM_BLOCKED_POOL=true || FROM_BLOCKED_POOL=false
fi

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-captive_portal}"
DB_USER="${DB_USER:-portal_user}"
DB_PASSWORD="${DB_PASSWORD:-}"

export PGPASSWORD="$DB_PASSWORD"
PSQL="psql -q -t -A -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME"

# Compute lease expiry timestamp (UTC).
if [ "$LEASE_SECONDS" -gt 0 ] 2>/dev/null; then
    EXPIRY=$(python3 -c "
from datetime import datetime, timedelta
print((datetime.utcnow() + timedelta(seconds=${LEASE_SECONDS})).strftime('%Y-%m-%d %H:%M:%S'))
" 2>/dev/null)
    [ -z "$EXPIRY" ] && EXPIRY=$(date -u -d "+${LEASE_SECONDS} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    [ -z "$EXPIRY" ] && EXPIRY=$(date -u '+%Y-%m-%d %H:%M:%S')
else
    EXPIRY=$(date -u '+%Y-%m-%d %H:%M:%S')
fi

case "$ACTION" in
    new_lease|renew)
        # ── Table 6: upsert devices row ───────────────────────────────────────
        # INSERT on first-seen (new MAC); UPDATE only tracking fields on conflict.
        # ip_address is NOT stored on devices (Table 6) per spec — it lives in Table 7 (ip_leases).
        $PSQL <<ENDSQL
INSERT INTO devices (mac_address, current_vlan)
VALUES ('${MAC_ADDRESS}', ${VLAN_ID})
ON CONFLICT (mac_address) DO UPDATE SET
    last_seen    = NOW(),
    current_vlan = EXCLUDED.current_vlan;
-- Clear wrong_vlan status once the device lands on its assigned VLAN
UPDATE devices
   SET registration_status = 'registered',
       wired_target_vlan   = NULL
 WHERE mac_address = '${MAC_ADDRESS}'
   AND registration_status = 'wrong_vlan'
   AND assigned_vlan IS NOT NULL
   AND assigned_vlan = ${VLAN_ID};
ENDSQL

        # ── Table 7: upsert ip_leases row ─────────────────────────────────────
        # ip_leases has no UNIQUE constraint on (mac_address, ip_address), so
        # we simulate an upsert with a transaction: UPDATE then INSERT WHERE NOT EXISTS.
        $PSQL <<ENDSQL
BEGIN;
UPDATE ip_leases
   SET vlan_id           = ${VLAN_ID},
       lease_start       = NOW(),
       lease_expiry      = '${EXPIRY}',
       from_blocked_pool = ${FROM_BLOCKED_POOL},
       dns_hijacked      = ${DNS_HIJACKED}
 WHERE mac_address = '${MAC_ADDRESS}'
   AND ip_address  = '${IP_ADDRESS}';
INSERT INTO ip_leases
    (ip_address, vlan_id, mac_address, lease_start, lease_expiry,
     from_blocked_pool, dns_hijacked)
SELECT '${IP_ADDRESS}', ${VLAN_ID}, '${MAC_ADDRESS}',
       NOW(), '${EXPIRY}', ${FROM_BLOCKED_POOL}, ${DNS_HIJACKED}
WHERE NOT EXISTS (
    SELECT 1 FROM ip_leases
     WHERE mac_address = '${MAC_ADDRESS}'
       AND ip_address  = '${IP_ADDRESS}'
);
COMMIT;
ENDSQL

        # ── Blocked-pool transition: expire old regular-pool leases ───────────
        # When a device lands in the blocked pool, any per-IP ACL/DNS rules that
        # were applied to its previous regular-pool IP are now redundant (the
        # blanket blocked-pool range rules cover it).  Expire those rows now so
        # the portal's lease sweep cleans up the stale rules within ~20 seconds.
        # force_lease_renewal uses lease4-del which does NOT trigger lease4_expire,
        # so without this the rows would linger until their original TTL elapsed.
        if [ "$FROM_BLOCKED_POOL" = "true" ]; then
            $PSQL -c "UPDATE ip_leases
                         SET lease_expiry = NOW()
                       WHERE mac_address     = '${MAC_ADDRESS}'
                         AND ip_address     != '${IP_ADDRESS}'
                         AND from_blocked_pool = false
                         AND lease_expiry    > NOW();"
        fi
        ;;

    expire)
        # ── Table 7: mark ip_leases row as expired ────────────────────────────
        $PSQL -c "UPDATE ip_leases
                     SET lease_expiry = NOW()
                   WHERE mac_address = '${MAC_ADDRESS}'
                     AND ip_address  = '${IP_ADDRESS}';"

        # ── Table 6: update last_seen ─────────────────────────────────────────
        $PSQL -c "UPDATE devices
                     SET last_seen = NOW()
                   WHERE mac_address = '${MAC_ADDRESS}';"
        ;;
esac
