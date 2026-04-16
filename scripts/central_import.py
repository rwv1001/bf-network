#!/usr/bin/env python3
"""
central_import.py <mac_address>

Called from the Kea DHCP hook when a device has no local reservation.
Queries the central server; if the device is known there, imports user/device/
ownership into the portal DB and adds a Kea reservation so the next DISCOVER
gives the correct pool assignment.

Stdout (single word, no trailing newline printed by sys.exit path):
  registered  – device imported, not blocked
  blocked     – device imported, is blocked
  not_found   – central has no record for this MAC
  disabled    – CENTRAL_* env vars not set (fail-open)
  error       – any unexpected failure (fail-open)
"""
import sys
import os
import json
import datetime
import subprocess
import urllib.request
import urllib.error


# ── args ──────────────────────────────────────────────────────────────────────

MAC = sys.argv[1].lower().strip() if len(sys.argv) > 1 else ""
if not MAC:
    print("error")
    sys.exit(0)

# ── central config ────────────────────────────────────────────────────────────

API_URL = os.getenv("CENTRAL_API_URL", "").rstrip("/")
API_KEY = os.getenv("CENTRAL_API_KEY", "")
SITE_ID = os.getenv("CENTRAL_SITE_ID", "")
if not API_URL or not API_KEY or not SITE_ID:
    print("disabled")
    sys.exit(0)

# ── query central ─────────────────────────────────────────────────────────────

try:
    req = urllib.request.Request(
        f"{API_URL}/api/v1/device/{MAC}",
        headers={"X-API-Key": API_KEY},
    )
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read().decode())
except urllib.error.HTTPError as e:
    if e.code == 404:
        print("not_found")
        sys.exit(0)
    print("error")
    sys.exit(0)
except Exception:
    print("error")
    sys.exit(0)

email = (data.get("email") or "").lower().strip()
if not email:
    print("error")
    sys.exit(0)

device_blocked = bool(data.get("device_blocked") or data.get("user_blocked"))
assigned_vlan  = data.get("assigned_vlan")
device_name    = (data.get("device_name") or "")
first_name     = (data.get("first_name") or "")
last_name      = (data.get("last_name") or "")
phone          = (data.get("phone_number") or "")

# ── DB helpers ────────────────────────────────────────────────────────────────

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "captive_portal")
DB_USER = os.getenv("DB_USER", "portal_user")
DB_PASS = os.getenv("DB_PASSWORD", "")

db_env = {**os.environ, "PGPASSWORD": DB_PASS}


def psql(sql: str) -> str:
    """Run a SQL statement; return stripped stdout."""
    result = subprocess.run(
        ["psql", "-h", DB_HOST, "-p", DB_PORT, "-U", DB_USER, "-d", DB_NAME,
         "-t", "-A", "-c", sql],
        env=db_env,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def q(s: str) -> str:
    """Minimal SQL string escaping (single-quote doubling only)."""
    return s.replace("'", "''")


# ── write to portal DB ────────────────────────────────────────────────────────

now   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
today = datetime.date.today().isoformat()

# Upsert user (begin_date is NOT NULL)
psql(f"""
INSERT INTO users (email, first_name, last_name, phone_number, begin_date, created_at, updated_at)
VALUES (
    '{q(email)}', '{q(first_name)}', '{q(last_name)}',
    '{q(phone)}', '{today}', '{now}', '{now}'
)
ON CONFLICT (email) DO UPDATE SET
    first_name  = COALESCE(NULLIF(users.first_name,  ''), EXCLUDED.first_name),
    last_name   = COALESCE(NULLIF(users.last_name,   ''), EXCLUDED.last_name),
    updated_at  = EXCLUDED.updated_at;
""")

user_id = psql(f"SELECT id FROM users WHERE email = '{q(email)}' LIMIT 1;")
if not user_id:
    print("error")
    sys.exit(0)

# Upsert device
blocked_val = "true" if device_blocked else "false"
vlan_val    = str(assigned_vlan) if assigned_vlan else "NULL"

psql(f"""
INSERT INTO devices (
    mac_address, user_id, device_name, internet_blocked,
    ownership_validated, first_seen, registered_at
)
VALUES (
    '{MAC}', {user_id}, '{q(device_name)}', {blocked_val},
    true, '{now}', '{now}'
)
ON CONFLICT (mac_address) DO UPDATE SET
    internet_blocked    = EXCLUDED.internet_blocked,
    user_id             = EXCLUDED.user_id,
    ownership_validated = true;
""")

# Set assigned_vlan only when it's currently NULL (don't overwrite a known vlan)
if assigned_vlan:
    psql(f"""
UPDATE devices
   SET assigned_vlan = {vlan_val}
 WHERE mac_address = '{MAC}'
   AND assigned_vlan IS NULL;
""")

# Insert ownership only when there is no currently-active entry
psql(f"""
INSERT INTO device_ownership (mac_address, user_id, start_datetime, end_datetime)
SELECT '{MAC}', {user_id}, '{now}', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM device_ownership
     WHERE mac_address = '{MAC}'
       AND end_datetime IS NULL
);
""")

# ── add Kea reservation directly to PostgreSQL ───────────────────────────────
# We cannot use the Kea control socket here because central_import.py is called
# via popen() from inside a Kea callout.  Kea's callout thread cannot service
# socket requests while blocked waiting for the child process, causing a
# deadlock.  Writing directly to the hosts table avoids this entirely.

client_class = "BLOCKED" if device_blocked else "REGISTERED"

# MAC as raw hex bytes (binary) — Kea stores it as bytea
mac_hex = MAC.replace(":", "")

psql(f"""
INSERT INTO hosts (
    dhcp_identifier,
    dhcp_identifier_type,
    dhcp4_subnet_id,
    dhcp4_client_classes
)
VALUES (
    decode('{mac_hex}', 'hex'),
    0,
    0,
    '{client_class}'
)
ON CONFLICT DO NOTHING;
""")

# ── done ──────────────────────────────────────────────────────────────────────

print("blocked" if device_blocked else "registered")
