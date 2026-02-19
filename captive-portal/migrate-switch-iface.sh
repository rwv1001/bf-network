#!/bin/bash
# migrate-switch-iface.sh
# Adds mac_port_cache table, switch_iface columns on devices, and updates
# the nat_sessions_enriched view to include switch port information.
set -euo pipefail

DB_CONTAINER="${REPLUG_DB_CONTAINER:-captive-portal-db}"
DB_USER="${DB_USER:-portal_user}"
DB_NAME="${DB_NAME:-captive_portal}"

echo "Running switch-iface migration on container: $DB_CONTAINER"

psql() {
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

psql -c "CREATE TABLE IF NOT EXISTS mac_port_cache (
    mac_address  VARCHAR(17) PRIMARY KEY,
    switch_iface VARCHAR(100) NOT NULL,
    switch_host  VARCHAR(255),
    vlan_id      INTEGER,
    last_seen    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);"

psql -c "CREATE INDEX IF NOT EXISTS idx_mac_port_cache_last_seen ON mac_port_cache(last_seen);"

psql -c "ALTER TABLE devices ADD COLUMN IF NOT EXISTS switch_iface VARCHAR(100);"
psql -c "ALTER TABLE devices ADD COLUMN IF NOT EXISTS switch_iface_seen_at TIMESTAMP WITH TIME ZONE;"

psql -c "
CREATE OR REPLACE VIEW nat_sessions_enriched AS
SELECT
    n.id AS session_id, n.session_start, n.session_end, n.src_ip, n.src_port,
    u.email AS user_email, u.first_name AS user_first_name, u.last_name AS user_last_name,
    d.registration_status,
    n.dst_ip, n.dst_port, dns.domain_name, dns.query_count AS dns_query_count,
    n.packet_count,
    EXTRACT(EPOCH FROM (n.session_end - n.session_start)) AS duration_seconds,
    d.switch_iface
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
