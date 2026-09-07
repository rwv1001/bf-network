#!/bin/bash
set -e
psql "$DATABASE_URL" -c "ALTER TABLE vlan_mappings ADD COLUMN IF NOT EXISTS visible_vlans TEXT;"
psql "$DATABASE_URL" -c "ALTER TABLE vlan_mappings ADD COLUMN IF NOT EXISTS allow_doh BOOLEAN NOT NULL DEFAULT FALSE;"
psql "$DATABASE_URL" <<'SQL'
CREATE OR REPLACE VIEW traffic_combined AS
SELECT
    l.lookup_id,
    l.lookup_timestamp,
    l.client_ip,
    l.lan_src_port,
    l.domain_name,
    l.domain_ip,
    l.src_mac,
    l.user_email,
    l.user_first_name,
    l.user_last_name,
    l.wan_src_port,
    l.dst_port,
    'dns'::text AS traffic_source
FROM dns_traffic_view l

UNION ALL

SELECT
    n.session_id AS lookup_id,
    n.session_start AS lookup_timestamp,
    host(n.src_ip::inet) AS client_ip,
    n.src_port AS lan_src_port,
    n.domain_name,
    host(n.dst_ip::inet) AS domain_ip,
    n.src_mac,
    n.user_email,
    n.user_first_name,
    n.user_last_name,
    n.src_port AS wan_src_port,
    n.dst_port,
    'nat'::text AS traffic_source
FROM nat_sessions_enriched n
WHERE NOT EXISTS (
    SELECT 1
    FROM dns_lookups d
    WHERE host(d.client_ip) = host(n.src_ip::inet)
      AND d.lookup_timestamp >= n.session_start - INTERVAL '5 minutes'
      AND d.lookup_timestamp <= COALESCE(n.session_end, n.session_start) + INTERVAL '5 minutes'
);
SQL
echo "245da90 up migration complete."
