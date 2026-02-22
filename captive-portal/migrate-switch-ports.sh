#!/bin/bash
# migrate-switch-ports.sh
# Creates the switch_ports table used by the admin Switch Ports page.
set -euo pipefail

DB_CONTAINER="${REPLUG_DB_CONTAINER:-captive-portal-db}"
DB_USER="${DB_USER:-portal_user}"
DB_NAME="${DB_NAME:-captive_portal}"

echo "Running switch_ports migration on container: $DB_CONTAINER"

psql() {
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

psql -c "
CREATE TABLE IF NOT EXISTS switch_ports (
    id               SERIAL PRIMARY KEY,
    switch_host      VARCHAR(255) NOT NULL,
    port_name        VARCHAR(100) NOT NULL,   -- abbreviated: GE1/0/1, XGE1/0/28
    port_description TEXT         NOT NULL DEFAULT '',
    port_role        VARCHAR(20)  NOT NULL DEFAULT 'unknown',
        -- ap | wired | pi | inter_switch | uplink_udm | unknown
    link_status      VARCHAR(10)  NOT NULL DEFAULT 'unknown',  -- UP | DOWN | ADM
    last_discovered  TIMESTAMP,
    last_updated     TIMESTAMP,
    UNIQUE (switch_host, port_name)
);"

echo "Migration complete."
