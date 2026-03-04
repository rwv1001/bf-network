#!/bin/bash
set -e
psql "$DATABASE_URL" -c "ALTER TABLE users DROP COLUMN IF EXISTS test_col_v2;"
