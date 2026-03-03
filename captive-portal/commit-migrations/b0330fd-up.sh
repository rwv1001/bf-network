#!/bin/bash
# b0330fd-up.sh — removes firmware test DB objects
set -euo pipefail

echo "[b0330fd-up] Dropping firmware_test_col from users..."
psql "$DATABASE_URL" -c "ALTER TABLE users DROP COLUMN IF EXISTS firmware_test_col;"

echo "[b0330fd-up] Dropping firmware_test_table..."
psql "$DATABASE_URL" -c "DROP TABLE IF EXISTS firmware_test_table;"

echo "[b0330fd-up] Done."
