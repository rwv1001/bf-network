#!/bin/bash
# commit-migrations/046af83-down.sh
# Test down-migration: drops firmware_test_table and removes firmware_test_col from users.
# Reverses 046af83-up.sh.
set -euo pipefail

echo "=== 046af83 down-migration: removing test table and column ==="

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
-- Remove test column from users
ALTER TABLE users DROP COLUMN IF EXISTS firmware_test_col;

-- Drop test table
DROP TABLE IF EXISTS firmware_test_table;
SQL

echo "=== 046af83 down-migration: complete ==="
