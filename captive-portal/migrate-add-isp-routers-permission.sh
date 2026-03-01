#!/bin/bash
# migrate-add-isp-routers-permission.sh
# Adds the can_manage_isp_routers column to the admins table.
set -euo pipefail

DB_CONTAINER="${REPLUG_DB_CONTAINER:-captive-portal-db}"
DB_USER="${DB_USER:-portal_user}"
DB_NAME="${DB_NAME:-captive_portal}"

echo "Running can_manage_isp_routers migration on container: $DB_CONTAINER"

psql() {
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

psql -c "ALTER TABLE admins ADD COLUMN IF NOT EXISTS can_manage_isp_routers BOOLEAN NOT NULL DEFAULT FALSE;"

echo "Migration complete."
