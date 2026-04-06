#!/bin/bash
# Rollback: Remove spec Table 6 columns, drop device_ownership and ip_leases.
set -e

psql "$DATABASE_URL" <<'SQL'

DROP TABLE IF EXISTS ip_leases;
DROP TABLE IF EXISTS device_ownership;

ALTER TABLE devices
    DROP COLUMN IF EXISTS internet_accessible,
    DROP COLUMN IF EXISTS internet_blocked,
    DROP COLUMN IF EXISTS assigned_vlan,
    DROP COLUMN IF EXISTS ownership_validated;

SQL

echo "Rollback complete: spec columns and tables removed."
