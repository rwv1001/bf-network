#!/bin/bash
# 6434a23-down.sh
# Reverses test DB migration: drops firmware_test_col from users and firmware_test_table.
set -euo pipefail

echo "[6434a23-down] Dropping firmware_test_col from users..."
psql "$DATABASE_URL" <<'SQL'
ALTER TABLE users DROP COLUMN IF EXISTS firmware_test_col;
SQL

echo "[6434a23-down] Dropping firmware_test_table..."
psql "$DATABASE_URL" <<'SQL'
DROP TABLE IF EXISTS firmware_test_table;
SQL

echo "[6434a23-down] Done."
