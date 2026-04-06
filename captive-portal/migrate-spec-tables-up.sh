#!/bin/bash
# Migration: Add spec Table 6 columns to devices, create device_ownership (Table 9)
# and ip_leases (Table 7).
set -e

psql "$DATABASE_URL" <<'SQL'

-- ── Table 6 additions: orthogonal internet-access state columns ──────────────
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS internet_accessible BOOLEAN,
    ADD COLUMN IF NOT EXISTS internet_blocked     BOOLEAN,
    ADD COLUMN IF NOT EXISTS assigned_vlan        INTEGER,
    ADD COLUMN IF NOT EXISTS ownership_validated  BOOLEAN;

-- Backfill from existing registration_status values
UPDATE devices SET
    internet_accessible = CASE WHEN registration_status = 'registered' THEN TRUE  ELSE NULL END,
    internet_blocked    = CASE WHEN registration_status = 'blocked'    THEN TRUE  ELSE NULL END,
    assigned_vlan       = CASE WHEN registration_status IN ('registered', 'blocked')
                               THEN current_vlan ELSE NULL END,
    ownership_validated = CASE WHEN registration_status IN ('registered', 'blocked')
                               THEN TRUE ELSE NULL END
WHERE internet_accessible IS NULL
  AND internet_blocked    IS NULL
  AND assigned_vlan       IS NULL;

-- ── Table 9: DeviceOwnership history ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_ownership (
    id             SERIAL PRIMARY KEY,
    mac_address    VARCHAR(17)  NOT NULL,
    user_id        INTEGER      REFERENCES users(id) ON DELETE SET NULL,
    start_datetime TIMESTAMP    NOT NULL DEFAULT NOW(),
    end_datetime   TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_do_mac        ON device_ownership(mac_address);
CREATE INDEX IF NOT EXISTS idx_do_user_id    ON device_ownership(user_id);
-- Partial index for quick active-ownership lookups
CREATE INDEX IF NOT EXISTS idx_do_mac_active ON device_ownership(mac_address)
    WHERE end_datetime IS NULL;

-- Migrate existing registered/blocked devices into device_ownership.
-- One active row per device that has a user assigned.
INSERT INTO device_ownership (mac_address, user_id, start_datetime, end_datetime)
SELECT d.mac_address,
       d.user_id,
       COALESCE(d.registered_at, NOW()),
       NULL
FROM   devices d
WHERE  d.user_id IS NOT NULL
  AND  d.registration_status IN ('registered', 'blocked')
  AND  NOT EXISTS (
           SELECT 1 FROM device_ownership o
           WHERE  o.mac_address = d.mac_address
             AND  o.end_datetime IS NULL
       );

-- ── Table 7: IPLease tracking ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_leases (
    id               SERIAL PRIMARY KEY,
    ip_address       VARCHAR(45)  NOT NULL,
    vlan_id          INTEGER,
    mac_address      VARCHAR(17),
    lease_start      TIMESTAMP    NOT NULL,
    lease_expiry     TIMESTAMP    NOT NULL,
    from_blocked_pool BOOLEAN     NOT NULL DEFAULT FALSE,
    dns_hijacked     BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_il_mac    ON ip_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_il_ip     ON ip_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_il_expiry ON ip_leases(lease_expiry);

-- Migrate unregistered_leases → ip_leases (mark dns_hijacked=true because
-- those IPs were already being hijacked before the migration).
INSERT INTO ip_leases (ip_address, vlan_id, mac_address,
                       lease_start, lease_expiry,
                       from_blocked_pool, dns_hijacked)
SELECT ul.ip_address,
       NULL,
       ul.mac_address,
       ul.created_at,
       ul.expires_at,
       FALSE,
       TRUE
FROM   unregistered_leases ul
WHERE  NOT EXISTS (
           SELECT 1 FROM ip_leases il
           WHERE  il.mac_address = ul.mac_address
             AND  il.ip_address  = ul.ip_address
       );

SQL

echo "Migration complete: devices columns added, device_ownership and ip_leases created."
