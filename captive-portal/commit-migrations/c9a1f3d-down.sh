#!/bin/bash
set -e

psql "$DATABASE_URL" -c "
ALTER TABLE isp_routers DROP COLUMN IF EXISTS switch_host;
"
