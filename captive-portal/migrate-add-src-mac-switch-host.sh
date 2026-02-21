#!/bin/bash
# migrate-add-src-mac-switch-host.sh
# Adds src_mac and switch_host columns to nat_sessions, then rebuilds
# nat_sessions_enriched to expose them directly (no unreliable IP join).
set -euo pipefail

DB_CONTAINER="${REPLUG_DB_CONTAINER:-captive-portal-db}"
DB_USER="${DB_USER:-portal_user}"
DB_NAME="${DB_NAME:-captive_portal}"

echo "Running src_mac/switch_host migration on container: $DB_CONTAINER"

psql() {
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

# Add new columns to nat_sessions
psql -c "ALTER TABLE nat_sessions ADD COLUMN IF NOT EXISTS src_mac VARCHAR(17);"
psql -c "ALTER TABLE nat_sessions ADD COLUMN IF NOT EXISTS switch_host VARCHAR(255);"

# Rebuild the enriched view: switch_iface, switch_host, src_mac come from
# nat_sessions directly (stored at session write time) so they reflect the
# actual state when the session was recorded, not the current device state.
# DROP first because column set/order changes — CREATE OR REPLACE requires
# the existing columns to match exactly.
psql -c "DROP VIEW IF EXISTS nat_sessions_enriched;"
psql -c "
CREATE VIEW nat_sessions_enriched AS
SELECT
    n.id              AS session_id,
    n.session_start,
    n.session_end,
    n.src_ip,
    n.src_port,
    n.src_mac,
    u.email           AS user_email,
    u.first_name      AS user_first_name,
    u.last_name       AS user_last_name,
    d.registration_status,
    n.dst_ip,
    n.dst_port,
    dns.domain_name,
    dns.query_count   AS dns_query_count,
    n.packet_count,
    EXTRACT(EPOCH FROM (n.session_end - n.session_start)) AS duration_seconds,
    n.switch_iface,
    n.switch_host
FROM nat_sessions n
LEFT JOIN devices d ON host(n.src_ip) = d.ip_address
LEFT JOIN users u ON d.user_id = u.id
LEFT JOIN LATERAL (
    SELECT domain_name, resolved_ip, query_count FROM dns_resolutions
    WHERE resolved_ip = n.dst_ip
      AND last_seen >= n.session_start - INTERVAL '12 hours'
      AND last_seen <= n.session_start + INTERVAL '12 hours'
    ORDER BY ABS(EXTRACT(EPOCH FROM (last_seen - n.session_start)))
    LIMIT 1
) dns ON true
ORDER BY n.session_start DESC;"

echo "Migration complete."
