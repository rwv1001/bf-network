#!/bin/bash
set -e
# traffic_combined is a view; index the tables it reads.
psql "$DATABASE_URL" -c "CREATE INDEX IF NOT EXISTS idx_dl_timestamp ON dns_lookups (lookup_timestamp DESC);"
psql "$DATABASE_URL" -c "CREATE INDEX IF NOT EXISTS idx_dl_client_ip ON dns_lookups (client_ip, lookup_timestamp DESC);"
psql "$DATABASE_URL" -c "CREATE INDEX IF NOT EXISTS idx_nat_sessions_time ON nat_sessions (session_start DESC, session_end DESC);"
psql "$DATABASE_URL" -c "CREATE INDEX IF NOT EXISTS idx_nat_sessions_src ON nat_sessions (src_ip, src_port, session_end DESC);"
