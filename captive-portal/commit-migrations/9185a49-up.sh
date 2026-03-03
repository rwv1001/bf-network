#!/bin/bash
# commit-migrations/9185a49-up.sh
# Cleanup up-migration: drops firmware_test_table and removes firmware_test_col from users.
# Reverses the test migration introduced in 046af83.
set -euo pipefail

echo "=== 9185a49 up-migration: removing test table and column ==="

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
ALTER TABLE users DROP COLUMN IF EXISTS firmware_test_col;
DROP TABLE IF EXISTS firmware_test_table;
SQL

echo "=== 9185a49 up-migration: complete ==="
