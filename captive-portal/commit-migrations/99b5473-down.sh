#!/bin/bash
# 99b5473-down.sh — reverses test DB migration
set -euo pipefail

echo "[99b5473-down] Dropping firmware_test_col from users..."
psql "$DATABASE_URL" <<'SQL'
ALTER TABLE users DROP COLUMN IF EXISTS firmware_test_col;
SQL

echo "[99b5473-down] Dropping firmware_test_table..."
psql "$DATABASE_URL" <<'SQL'
DROP TABLE IF EXISTS firmware_test_table;
SQL

echo "[99b5473-down] Done."
