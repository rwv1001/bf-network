-- NAT Session Tracking Schema
-- Stores SNAT sessions with start/end timestamps
-- Groups continuous activity (< 60 second gaps) into sessions

CREATE TABLE IF NOT EXISTS nat_sessions (
    id SERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol VARCHAR(10),
    session_start TIMESTAMP WITH TIME ZONE NOT NULL,
    session_end TIMESTAMP WITH TIME ZONE NOT NULL,
    packet_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for efficient lookups by source IP:port and time range
CREATE INDEX IF NOT EXISTS idx_nat_sessions_src ON nat_sessions(src_ip, src_port, session_end DESC);

-- Index for finding active sessions (for session merging)
CREATE INDEX IF NOT EXISTS idx_nat_sessions_active ON nat_sessions(src_ip, src_port, session_end) WHERE session_end > (CURRENT_TIMESTAMP - INTERVAL '2 minutes');

-- Index for efficient time-based queries
CREATE INDEX IF NOT EXISTS idx_nat_sessions_time ON nat_sessions(session_start DESC, session_end DESC);

-- Index for destination lookups
CREATE INDEX IF NOT EXISTS idx_nat_sessions_dst ON nat_sessions(dst_ip, dst_port);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_nat_session_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
DROP TRIGGER IF EXISTS nat_sessions_updated_at ON nat_sessions;
CREATE TRIGGER nat_sessions_updated_at
    BEFORE UPDATE ON nat_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_nat_session_timestamp();

-- View for active sessions (last seen within 2 minutes)
CREATE OR REPLACE VIEW nat_active_sessions AS
SELECT 
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol,
    session_start,
    session_end,
    packet_count,
    EXTRACT(EPOCH FROM (session_end - session_start)) AS duration_seconds
FROM nat_sessions
WHERE session_end > (CURRENT_TIMESTAMP - INTERVAL '2 minutes')
ORDER BY session_end DESC;

-- View for session statistics by source IP
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

COMMENT ON TABLE nat_sessions IS 'Tracks SNAT sessions from UDM with grouped continuous activity';
COMMENT ON COLUMN nat_sessions.src_ip IS 'Source IP address from internal network';
COMMENT ON COLUMN nat_sessions.src_port IS 'Source port from internal network';
COMMENT ON COLUMN nat_sessions.dst_ip IS 'Destination IP address';
COMMENT ON COLUMN nat_sessions.dst_port IS 'Destination port';
COMMENT ON COLUMN nat_sessions.session_start IS 'Start of continuous session (first packet)';
COMMENT ON COLUMN nat_sessions.session_end IS 'End of continuous session (last packet within 60s gap)';
COMMENT ON COLUMN nat_sessions.packet_count IS 'Number of packets/entries seen in this session';
