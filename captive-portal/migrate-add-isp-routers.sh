#!/bin/bash
# Migration: add isp_routers table and isp_router_id column to vlan_mappings
# Also seeds the default ISP router from env vars.

set -e
CONTAINER="captive-portal-db"
DB="${DB_NAME:-captive_portal}"
USER="${DB_USER:-portal_user}"

run_sql() {
    docker exec -i "$CONTAINER" psql -U "$USER" -d "$DB" -c "$1"
}

echo "=== migrate-add-isp-routers ==="

echo "Creating isp_routers table..."
run_sql "
CREATE TABLE IF NOT EXISTS isp_routers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    subnet VARCHAR(50) NOT NULL,
    vlan_id INTEGER NOT NULL,
    switch_port VARCHAR(100),
    dhcp_snooping_trust BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
"

echo "Adding isp_router_id to vlan_mappings (if missing)..."
run_sql "
ALTER TABLE vlan_mappings
    ADD COLUMN IF NOT EXISTS isp_router_id INTEGER
        REFERENCES isp_routers(id) ON DELETE SET NULL;
"

# Seed default ISP router from env (defaults match .env.example)
DEFAULT_NAME="${DEFAULT_ISP_ROUTER_NAME:-UDM}"
DEFAULT_SUBNET="${DEFAULT_ISP_ROUTER_SUBNET:-192.168.1.0/24}"
DEFAULT_VLAN="${DEFAULT_ISP_ROUTER_VLAN:-1}"
DEFAULT_PORT="${DEFAULT_ISP_ROUTER_PORT:-}"
DEFAULT_DHCP="${DEFAULT_ISP_ROUTER_DHCP_TRUST:-true}"

echo "Seeding default ISP router '${DEFAULT_NAME}' (if none exist)..."
run_sql "
INSERT INTO isp_routers (name, subnet, vlan_id, switch_port, dhcp_snooping_trust)
SELECT '${DEFAULT_NAME}', '${DEFAULT_SUBNET}', ${DEFAULT_VLAN},
       NULLIF('${DEFAULT_PORT}', ''), ${DEFAULT_DHCP}
WHERE NOT EXISTS (SELECT 1 FROM isp_routers);
"

echo "=== Migration complete ==="
