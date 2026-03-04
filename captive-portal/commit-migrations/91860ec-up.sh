#!/bin/bash
set -e
psql "$DATABASE_URL" -c "ALTER TABLE users ADD COLUMN IF NOT EXISTS test_col_v2 TEXT;"
