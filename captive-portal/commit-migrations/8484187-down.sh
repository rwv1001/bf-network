#!/bin/bash
set -e
psql "$DATABASE_URL" -c "ALTER TABLE users DROP COLUMN IF EXISTS firmware_test_col;"
psql "$DATABASE_URL" -c "DROP TABLE IF EXISTS firmware_test_table;"
