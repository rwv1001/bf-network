#!/bin/bash
set -e
# Drop only the indexes this migration ensures. IF EXISTS keeps rollback safe.
psql "$DATABASE_URL" -c "DROP INDEX IF EXISTS idx_dl_timestamp;"
psql "$DATABASE_URL" -c "DROP INDEX IF EXISTS idx_dl_client_ip;"
psql "$DATABASE_URL" -c "DROP INDEX IF EXISTS idx_nat_sessions_time;"
psql "$DATABASE_URL" -c "DROP INDEX IF EXISTS idx_nat_sessions_src;"
