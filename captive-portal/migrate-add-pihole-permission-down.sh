#!/bin/bash
# migrate-add-pihole-permission-down.sh
# Rolls back the can_manage_pihole column from the admins table.
# Reverses migrate-add-pihole-permission.sh
set -euo pipefail

DB_CONTAINER="${REPLUG_DB_CONTAINER:-captive-portal-db}"
DB_USER="${DB_USER:-portal_user}"
DB_NAME="${DB_NAME:-captive_portal}"

echo "Rolling back can_manage_pihole migration on container: $DB_CONTAINER"

psql() {
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

psql -c "ALTER TABLE admins DROP COLUMN IF EXISTS can_manage_pihole;"

echo "Rollback complete."
