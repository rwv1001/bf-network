#!/bin/bash
set -e

psql "$DATABASE_URL" -c "
CREATE TABLE IF NOT EXISTS pihole_blocked_queries (
    id              SERIAL PRIMARY KEY,
    pihole_query_id BIGINT NOT NULL,
    blocked_at      TIMESTAMP NOT NULL,
    domain          VARCHAR(255) NOT NULL,
    query_type      VARCHAR(10) NOT NULL DEFAULT 'A',
    status          VARCHAR(30) NOT NULL,
    client_ip       INET NOT NULL,
    mac_address     VARCHAR(17),
    device_id       INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    list_id         INTEGER,
    UNIQUE (pihole_query_id)
);
CREATE INDEX IF NOT EXISTS idx_pbq_blocked_at ON pihole_blocked_queries(blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_pbq_client_ip  ON pihole_blocked_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_pbq_user_id    ON pihole_blocked_queries(user_id);
CREATE INDEX IF NOT EXISTS idx_pbq_domain     ON pihole_blocked_queries(domain);
"
