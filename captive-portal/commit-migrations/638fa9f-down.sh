#!/bin/bash
set -e

psql "$DATABASE_URL" -c "
DROP INDEX IF EXISTS idx_pbq_domain;
DROP INDEX IF EXISTS idx_pbq_user_id;
DROP INDEX IF EXISTS idx_pbq_client_ip;
DROP INDEX IF EXISTS idx_pbq_blocked_at;
DROP TABLE IF EXISTS pihole_blocked_queries;
"
