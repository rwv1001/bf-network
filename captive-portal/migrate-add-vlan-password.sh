#!/bin/bash
# migrate-add-vlan-password.sh
# Adds require_password column to vlan_mappings table and
# network_password_hash column to users table.
set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-captive-portal-db}"
DB_USER="${DB_USER:-portal_user}"
DB_NAME="${DB_NAME:-captive_portal}"

echo "Running vlan-password migration on container: $DB_CONTAINER"

psql() {
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

psql -c "
ALTER TABLE vlan_mappings
  ADD COLUMN IF NOT EXISTS require_password BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS network_password_hash VARCHAR(255);
"

echo "Migration complete."
