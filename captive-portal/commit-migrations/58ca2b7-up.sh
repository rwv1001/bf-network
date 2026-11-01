#!/usr/bin/env bash
set -euo pipefail

# Run by the firmware page inside the portal web container.
DB_CONTAINER="${NAT_DB_CONTAINER:-captive-portal-db}"
DB_USER="${NAT_DB_USER:-portal_user}"
DB_NAME="${NAT_DB_NAME:-captive_portal}"

command -v docker >/dev/null || { echo "docker unavailable" >&2; exit 1; }
docker inspect "$DB_CONTAINER" >/dev/null || { echo "DB container unavailable" >&2; exit 1; }

echo "Applying NAT metrics upgrade..."
docker exec -i "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME" <<'NAT_UP_SQL'
-- Apply ONCE to an EXISTING PostgreSQL volume before restarting nat-parser.
-- Non-destructive: existing rows are left alone (historical packet counts are
-- legacy event counts and cannot be retroactively repaired).
ALTER TABLE nat_sessions ADD COLUMN IF NOT EXISTS wan_src_port INTEGER;
ALTER TABLE nat_sessions ADD COLUMN IF NOT EXISTS event_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nat_sessions ADD COLUMN IF NOT EXISTS start_event_seen BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE nat_sessions ADD COLUMN IF NOT EXISTS end_event_seen BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE nat_sessions ALTER COLUMN packet_count DROP DEFAULT;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'nat_sessions_wan_src_port_range'
          AND conrelid = 'nat_sessions'::regclass
    ) THEN
        ALTER TABLE nat_sessions ADD CONSTRAINT nat_sessions_wan_src_port_range
            CHECK (wan_src_port BETWEEN 1 AND 65535) NOT VALID;
    END IF;
END $$;
-- CREATE INDEX CONCURRENTLY must run outside an explicit transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_il_ip_lease_start
    ON ip_leases (ip_address, lease_start DESC) INCLUDE (lease_expiry, mac_address);


CREATE OR REPLACE VIEW nat_active_sessions AS
SELECT 
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    session_start,
    session_end,
    packet_count,
    CASE WHEN start_event_seen AND end_event_seen
         THEN EXTRACT(EPOCH FROM (session_end - session_start))
         ELSE NULL END AS duration_seconds
FROM nat_sessions
WHERE session_end > (CURRENT_TIMESTAMP - INTERVAL '2 minutes')
ORDER BY session_end DESC;

CREATE OR REPLACE VIEW nat_session_stats_by_ip AS
SELECT 
    src_ip,
    COUNT(*) AS total_sessions,
    SUM(packet_count) AS total_packets,
    MIN(session_start) AS first_seen,
    MAX(session_end) AS last_seen,
    AVG(EXTRACT(EPOCH FROM (session_end - session_start))) FILTER
        (WHERE start_event_seen AND end_event_seen) AS avg_session_duration_seconds
FROM nat_sessions
GROUP BY src_ip
ORDER BY last_seen DESC;

CREATE OR REPLACE VIEW nat_sessions_enriched AS
SELECT
    n.id AS session_id,
    n.session_start,
    n.session_end,
    n.src_ip,
    n.src_port,
    n.src_mac,
    u.email AS user_email,
    u.first_name AS user_first_name,
    u.last_name AS user_last_name,
    d.registration_status,
    n.dst_ip,
    n.dst_port,
    dns.domain_name,
    dns.query_count AS dns_query_count,
    n.packet_count,
    CASE WHEN n.start_event_seen AND n.end_event_seen
         THEN EXTRACT(EPOCH FROM (n.session_end - n.session_start))
         ELSE NULL END AS duration_seconds,
    COALESCE(n.switch_iface, d.switch_iface) AS switch_iface,
    n.switch_host,
    n.wan_src_port,
    n.event_count,
    n.start_event_seen,
    n.end_event_seen
FROM nat_sessions n
LEFT JOIN devices d ON n.src_mac = d.mac_address
LEFT JOIN LATERAL (
    SELECT o.user_id
    FROM device_ownership o
    WHERE o.mac_address = n.src_mac
      AND o.start_datetime < n.session_start
      AND (o.end_datetime IS NULL OR n.session_end < o.end_datetime)
    ORDER BY o.start_datetime DESC
    LIMIT 1
) own ON true
LEFT JOIN users u ON u.id = own.user_id
LEFT JOIN LATERAL (
    SELECT domain_name, resolved_ip, query_count
    FROM dns_resolutions
    WHERE resolved_ip = n.dst_ip
      AND last_seen >= n.session_start - INTERVAL '12 hours'
      AND last_seen <= n.session_start + INTERVAL '12 hours'
    ORDER BY ABS(EXTRACT(EPOCH FROM (last_seen - n.session_start)))
    LIMIT 1
) dns ON true
ORDER BY n.session_start DESC;

CREATE OR REPLACE VIEW dns_traffic_view AS
SELECT DISTINCT ON (
    l.lookup_timestamp,
    host(l.client_ip),
    l.client_port,
    l.domain_name
)
    l.id                          AS lookup_id,
    l.lookup_timestamp,
    host(l.client_ip)             AS client_ip,
    l.client_port                 AS lan_src_port,
    l.domain_name,
    host(l.resolved_ip)           AS domain_ip,
    lse.mac_address               AS src_mac,
    u.email                       AS user_email,
    u.first_name                  AS user_first_name,
    u.last_name                   AS user_last_name,
    n.src_port                    AS wan_src_port,
    n.dst_port
FROM dns_lookups l
LEFT JOIN LATERAL (
    SELECT mac_address
    FROM ip_leases
    WHERE host(ip_address::inet) = host(l.client_ip)
      AND lease_start  <= l.lookup_timestamp
      AND lease_expiry  >  l.lookup_timestamp
    ORDER BY lease_start DESC
    LIMIT 1
) lse ON true
LEFT JOIN LATERAL (
    SELECT o.user_id
    FROM device_ownership o
    WHERE o.mac_address = lse.mac_address
      AND o.start_datetime <= l.lookup_timestamp
      AND (o.end_datetime IS NULL OR o.end_datetime > l.lookup_timestamp)
    ORDER BY o.start_datetime DESC
    LIMIT 1
) own ON lse.mac_address IS NOT NULL
LEFT JOIN users u ON u.id = own.user_id
LEFT JOIN LATERAL (
    SELECT n2.wan_src_port AS src_port, n2.dst_port
    FROM nat_sessions n2
    WHERE n2.src_ip = l.client_ip
      AND n2.dst_ip = l.resolved_ip
      AND n2.session_start >= l.lookup_timestamp - INTERVAL '5 minutes'
      AND n2.session_start <= l.lookup_timestamp + INTERVAL '30 minutes'
    ORDER BY n2.session_start
    LIMIT 1
) n ON true
ORDER BY
    l.lookup_timestamp,
    host(l.client_ip),
    l.client_port,
    l.domain_name,
    l.id;

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
    n.wan_src_port AS wan_src_port,
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
NAT_UP_SQL
