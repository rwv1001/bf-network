#!/bin/bash
set -e

psql "$DATABASE_URL" -c "
ALTER TABLE isp_routers ADD COLUMN IF NOT EXISTS switch_host VARCHAR(50);
"
