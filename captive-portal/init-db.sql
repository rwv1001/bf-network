-- Captive portal schema

-- Admin users with role-based permissions
CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    can_manage_users BOOLEAN DEFAULT TRUE NOT NULL,
    can_manage_vlans BOOLEAN DEFAULT FALSE NOT NULL,
    can_view_traffic BOOLEAN DEFAULT FALSE NOT NULL,
    can_manage_admins BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    last_login TIMESTAMP,
    traffic_viewer_settings TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    mfa_secret VARCHAR(32),
    must_change_password BOOLEAN DEFAULT FALSE NOT NULL,
    can_manage_switch_ports BOOLEAN DEFAULT FALSE NOT NULL,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    can_manage_firmware BOOLEAN DEFAULT FALSE NOT NULL,
    can_manage_isp_routers BOOLEAN DEFAULT FALSE NOT NULL,
    can_manage_pihole BOOLEAN DEFAULT FALSE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);
CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email);
CREATE INDEX IF NOT EXISTS ix_admins_password_reset_token ON admins(password_reset_token);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(20),
    begin_date DATE NOT NULL,
    expiry_date DATE NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT 'admin',
    notes TEXT,
    blocked BOOLEAN DEFAULT FALSE NOT NULL,
    allowed_vlans TEXT,
    adoptable_vlans TEXT,
    allowed_vlans_override TEXT,
    allowed_vlans_deny TEXT,
    adoptable_vlans_override TEXT,
    adoptable_vlans_deny TEXT,
    require_approval_every_device BOOLEAN DEFAULT FALSE NOT NULL,
    network_password_hash VARCHAR(255),
    network_password_set_token VARCHAR(255),
    network_password_set_token_expires TIMESTAMP,
    network_password_approval_mode VARCHAR(20)
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS ix_users_network_password_set_token ON users(network_password_set_token);

CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    device_name VARCHAR(100),
    current_vlan INTEGER,
    registration_status VARCHAR(50) DEFAULT 'pending',
    verification_token VARCHAR(255),
    verification_expires_at TIMESTAMP,
    registered_at TIMESTAMP DEFAULT NOW(),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP,
    ip_address VARCHAR(45),
    connection_type VARCHAR(10) DEFAULT 'unknown',
    ssid VARCHAR(100),
    is_wired BOOLEAN DEFAULT FALSE NOT NULL,
    wired_target_vlan INTEGER,
    unregister_token VARCHAR(255) UNIQUE,
    confirmation_token VARCHAR(255) UNIQUE,
    confirmation_deadline TIMESTAMP,
    confirmation_confirmed_at TIMESTAMP,
    profile_snapshot TEXT,
    switch_iface VARCHAR(100),
    switch_iface_seen_at TIMESTAMP WITH TIME ZONE,
    switch_host VARCHAR(50),
    internet_accessible  BOOLEAN,
    internet_blocked     BOOLEAN,
    assigned_vlan        INTEGER,
    ownership_validated  BOOLEAN,
    fixed_ip VARCHAR(45),
    stale BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_registration_status ON devices(registration_status);
CREATE INDEX IF NOT EXISTS idx_devices_first_seen ON devices(first_seen);
CREATE INDEX IF NOT EXISTS idx_devices_confirmation_token ON devices(confirmation_token);
CREATE INDEX IF NOT EXISTS idx_devices_switch_iface ON devices(switch_iface);

-- Cache table for HP5130 switch MAC->port mappings (populated by hp5130-mac-poll.py)
CREATE TABLE IF NOT EXISTS mac_port_cache (
    mac_address     VARCHAR(17) PRIMARY KEY,  -- lowercase colon format: aa:bb:cc:dd:ee:ff
    switch_iface    VARCHAR(100) NOT NULL,
    switch_host     VARCHAR(255),
    vlan_id         INTEGER,
    last_seen       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mac_port_cache_last_seen ON mac_port_cache(last_seen);

CREATE TABLE IF NOT EXISTS registration_requests (
    id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL,
    email VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(20),
    device_type VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    requested_vlan INTEGER,
    approval_token VARCHAR(255),
    submitted_at TIMESTAMP DEFAULT NOW(),
    processed_at TIMESTAMP,
    processed_by VARCHAR(100),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_registration_requests_mac ON registration_requests(mac_address);
CREATE INDEX IF NOT EXISTS idx_registration_requests_email ON registration_requests(email);
CREATE INDEX IF NOT EXISTS idx_registration_requests_status ON registration_requests(status);

CREATE TABLE IF NOT EXISTS isp_routers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    subnet VARCHAR(50) NOT NULL,
    vlan_id INTEGER NOT NULL,
    switch_port VARCHAR(100),
    dhcp_snooping_trust BOOLEAN DEFAULT TRUE NOT NULL,
    switch_host VARCHAR(50),
    gateway_ip VARCHAR(45),
    nat_logger_type VARCHAR(20) NOT NULL DEFAULT 'none',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vlan_mappings (
    id SERIAL PRIMARY KEY,
    status VARCHAR(50) UNIQUE NOT NULL,
    vlan_id INTEGER NOT NULL,
    description TEXT,
    display_name TEXT,
    ssid TEXT,
    wired_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    require_password BOOLEAN DEFAULT FALSE NOT NULL,
    isp_router_id INTEGER REFERENCES isp_routers(id) ON DELETE SET NULL,
    visible_vlans TEXT
);

CREATE TABLE IF NOT EXISTS switch_ports (
    id               SERIAL PRIMARY KEY,
    switch_host      VARCHAR(255) NOT NULL,
    port_name        VARCHAR(100) NOT NULL,
    port_description TEXT         NOT NULL DEFAULT '',
    port_role        VARCHAR(20)  NOT NULL DEFAULT 'unknown',
    link_status      VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    last_discovered  TIMESTAMP,
    last_updated     TIMESTAMP,
    UNIQUE (switch_host, port_name)
);

CREATE TABLE IF NOT EXISTS domain_policies (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    allowed_vlans TEXT,
    adoptable_vlans TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS unregistered_leases (
    mac_address VARCHAR(17) PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_unregistered_leases_expires_at ON unregistered_leases(expires_at);



-- NAT Session Tracking Schema
-- Stores SNAT sessions with start/end timestamps
-- Groups continuous activity (< 60 second gaps) into sessions

CREATE TABLE IF NOT EXISTS nat_sessions (
    id SERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INTEGER NOT NULL,
    session_start TIMESTAMP NOT NULL,
    session_end TIMESTAMP NOT NULL,
    packet_count INTEGER DEFAULT 1,
    switch_iface VARCHAR(100),
    src_mac VARCHAR(17),
    switch_host VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_nat_session UNIQUE (src_ip, src_port, dst_ip, dst_port, session_start)
);

CREATE INDEX IF NOT EXISTS idx_nat_sessions_src ON nat_sessions(src_ip, src_port, session_end DESC);
CREATE INDEX IF NOT EXISTS idx_nat_sessions_active ON nat_sessions(src_ip, src_port, session_end);
CREATE INDEX IF NOT EXISTS idx_nat_sessions_time ON nat_sessions(session_start DESC, session_end DESC);
CREATE INDEX IF NOT EXISTS idx_nat_sessions_dst ON nat_sessions(dst_ip, dst_port);

-- Generic updated_at trigger function (used by dns_resolutions and others)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE VIEW nat_active_sessions AS
SELECT 
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    session_start,
    session_end,
    packet_count,
    EXTRACT(EPOCH FROM (session_end - session_start)) AS duration_seconds
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
    AVG(EXTRACT(EPOCH FROM (session_end - session_start))) AS avg_session_duration_seconds
FROM nat_sessions
GROUP BY src_ip
ORDER BY last_seen DESC;

-- ============================================================================
-- DNS RESOLUTIONS TABLE
-- ============================================================================
-- Tracks DNS query resolutions with deduplication (12-hour threshold)
-- Used to map destination IPs in NAT sessions to domain names

CREATE TABLE IF NOT EXISTS dns_resolutions (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    resolved_ip INET NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    query_count INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_domain_ip UNIQUE (domain_name, resolved_ip)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_dns_resolved_ip ON dns_resolutions(resolved_ip, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_resolutions(domain_name);
CREATE INDEX IF NOT EXISTS idx_dns_last_seen ON dns_resolutions(last_seen DESC);

-- Trigger to update updated_at timestamp
DROP TRIGGER IF EXISTS dns_resolutions_updated_at ON dns_resolutions;
CREATE TRIGGER dns_resolutions_updated_at
    BEFORE UPDATE ON dns_resolutions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- View: Recent DNS resolutions (last 24 hours)
CREATE OR REPLACE VIEW dns_recent_resolutions AS
SELECT 
    domain_name,
    resolved_ip,
    first_seen,
    last_seen,
    query_count,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) AS tracking_duration_seconds
FROM dns_resolutions
WHERE last_seen > (CURRENT_TIMESTAMP - INTERVAL '24 hours')
ORDER BY last_seen DESC;

-- View: DNS resolution stats by domain
CREATE OR REPLACE VIEW dns_stats_by_domain AS
SELECT 
    domain_name,
    COUNT(DISTINCT resolved_ip) AS unique_ips,
    MAX(last_seen) AS last_queried,
    SUM(query_count) AS total_queries
FROM dns_resolutions
GROUP BY domain_name
ORDER BY total_queries DESC;

-- ── Table 9: DeviceOwnership history ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_ownership (
    id             SERIAL PRIMARY KEY,
    mac_address    VARCHAR(17)  NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
    user_id        INTEGER      REFERENCES users(id) ON DELETE SET NULL,
    admin_id       INTEGER      REFERENCES admins(id) ON DELETE SET NULL,
    start_datetime TIMESTAMP    NOT NULL DEFAULT NOW(),
    end_datetime   TIMESTAMP
);

-- View: NAT sessions with DNS and user info (JOIN view)
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
    EXTRACT(EPOCH FROM (n.session_end - n.session_start)) AS duration_seconds,
    COALESCE(n.switch_iface, d.switch_iface) AS switch_iface,
    n.switch_host
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


-- ============================================================
-- DNS Lookups: one row per resolved lookup, with client identity.
-- No deduplication — the traffic viewer shows every request.
-- ============================================================
CREATE TABLE IF NOT EXISTS dns_lookups (
    id               SERIAL PRIMARY KEY,
    lookup_timestamp TIMESTAMP NOT NULL,
    client_ip        INET      NOT NULL,
    client_port      INTEGER,
    domain_name      VARCHAR(255) NOT NULL,
    resolved_ip      INET      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dl_timestamp  ON dns_lookups(lookup_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_dl_client_ip  ON dns_lookups(client_ip, lookup_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_dl_domain     ON dns_lookups(domain_name);
CREATE INDEX IF NOT EXISTS idx_dl_resolved   ON dns_lookups(resolved_ip);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dl_dedup ON dns_lookups (lookup_timestamp, client_ip, client_port, domain_name, resolved_ip);    



-- Populated by dns-parser polling the Pi-Hole v6 API.
-- client_ip joins to devices.ip_address → users for attribution.
-- ============================================================
CREATE TABLE IF NOT EXISTS pihole_blocked_queries (
    id              SERIAL PRIMARY KEY,
    pihole_query_id BIGINT NOT NULL,
    blocked_at      TIMESTAMP NOT NULL,
    domain          VARCHAR(255) NOT NULL,
    query_type      VARCHAR(10) NOT NULL DEFAULT 'A',
    status          VARCHAR(30) NOT NULL,
    client_ip       INET NOT NULL,
    -- MAC stored at poll time (within 30s of the query) so the IP→MAC
    -- binding is captured while it is still current.  Future DHCP
    -- reassignments cannot alter this historical record.
    mac_address     VARCHAR(17),
    device_id       INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    list_id         INTEGER,
    UNIQUE (pihole_query_id)
);

CREATE INDEX IF NOT EXISTS idx_pbq_blocked_at  ON pihole_blocked_queries(blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_pbq_client_ip   ON pihole_blocked_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_pbq_user_id     ON pihole_blocked_queries(user_id);
CREATE INDEX IF NOT EXISTS idx_pbq_domain      ON pihole_blocked_queries(domain);

-- View: Pi-Hole blocked queries shaped like nat_sessions_enriched for the traffic viewer.
-- Used as a fallback when nat_sessions has no data (NAT logger not yet installed).
CREATE OR REPLACE VIEW pihole_blocked_enriched AS
SELECT
    p.id            AS session_id,
    p.blocked_at    AS session_start,
    NULL::TIMESTAMP AS session_end,
    CAST(p.client_ip AS TEXT) AS src_ip,
    NULL::INTEGER   AS src_port,
    p.mac_address   AS src_mac,
    u.email         AS user_email,
    u.first_name    AS user_first_name,
    u.last_name     AS user_last_name,
    d.registration_status,
    NULL::TEXT      AS dst_ip,
    NULL::INTEGER   AS dst_port,
    p.domain        AS domain_name,
    1               AS dns_query_count,
    NULL::INTEGER   AS packet_count,
    NULL::FLOAT     AS duration_seconds,
    d.switch_iface,
    NULL::TEXT      AS switch_host
FROM pihole_blocked_queries p
LEFT JOIN users   u ON u.id = p.user_id
LEFT JOIN devices d ON d.mac_address = p.mac_address
ORDER BY p.blocked_at DESC;



CREATE INDEX IF NOT EXISTS idx_do_mac        ON device_ownership(mac_address);
CREATE INDEX IF NOT EXISTS idx_do_user_id    ON device_ownership(user_id);
CREATE INDEX IF NOT EXISTS idx_do_mac_active ON device_ownership(mac_address)
    WHERE end_datetime IS NULL;

-- ── Table 7: IPLease tracking ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_leases (
    id                SERIAL PRIMARY KEY,
    ip_address        VARCHAR(45)  NOT NULL,
    vlan_id           INTEGER,
    mac_address       VARCHAR(17),
    lease_start       TIMESTAMP    NOT NULL,
    lease_expiry      TIMESTAMP    NOT NULL,
    from_blocked_pool BOOLEAN      NOT NULL DEFAULT FALSE,
    dns_hijacked      BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_il_mac    ON ip_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_il_ip     ON ip_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_il_expiry ON ip_leases(lease_expiry);

-- View: DNS lookups enriched with lease→device→user info and optional NAT port data.
-- Join path: dns_lookups → ip_leases (by IP + time) → device_ownership (by MAC + time) → users.
-- NAT session is joined on matching src_ip + dst_ip within ±30 min to surface WAN/dst ports.
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
    SELECT n2.src_port, n2.dst_port
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



-- ── Central sync: outbound event queue ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS central_outbound_events (
    id              SERIAL PRIMARY KEY,
    event_type      VARCHAR(64)  NOT NULL,
    payload         JSON         NOT NULL,
    status          VARCHAR(32)  NOT NULL DEFAULT 'pending',
    attempts        INTEGER      NOT NULL DEFAULT 0,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_central_outbound_events_status ON central_outbound_events(status);

