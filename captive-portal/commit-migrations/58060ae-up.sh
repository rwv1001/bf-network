#!/bin/bash
set -e

psql "$DATABASE_URL" -c "
ALTER TABLE isp_routers ADD COLUMN IF NOT EXISTS nat_logger_type VARCHAR(20) NOT NULL DEFAULT 'none';
UPDATE isp_routers SET nat_logger_type = 'udm' WHERE vlan_id = 1;
"
