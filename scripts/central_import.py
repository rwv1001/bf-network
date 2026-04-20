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

device_blocked   = bool(data.get("device_blocked") or data.get("user_blocked"))
assigned_vlan    = data.get("assigned_vlan")
is_wired         = bool(data.get("is_wired"))
connection_type  = "wired" if is_wired else (data.get("connection_type") or "unknown")
device_name      = (data.get("device_name") or "")
first_name       = (data.get("first_name") or "")
last_name        = (data.get("last_name") or "")
phone            = (data.get("phone_number") or "")

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

# If central didn't return is_wired, infer from local VLAN mapping
if not is_wired and assigned_vlan:
    try:
        wired_check = psql(
            f"SELECT wired_enabled FROM vlan_mappings WHERE vlan_id = {int(assigned_vlan)} LIMIT 1;"
        )
        if wired_check in ('t', 'true', '1'):
            is_wired = True
            connection_type = 'wired'
    except Exception:
        pass

# Upsert device
blocked_val = "true" if device_blocked else "false"
vlan_val    = str(assigned_vlan) if assigned_vlan else "NULL"
is_wired_val = "true" if is_wired else "false"
conn_type_escaped = connection_type.replace("'", "''")

psql(f"""
INSERT INTO devices (
    mac_address, user_id, device_name, internet_blocked,
    ownership_validated, first_seen, registered_at,
    is_wired, connection_type
)
VALUES (
    '{MAC}', {user_id}, '{q(device_name)}', {blocked_val},
    true, '{now}', '{now}',
    {is_wired_val}, '{conn_type_escaped}'
)
ON CONFLICT (mac_address) DO UPDATE SET
    internet_blocked    = EXCLUDED.internet_blocked,
    user_id             = EXCLUDED.user_id,
    ownership_validated = true,
    is_wired            = CASE WHEN {is_wired_val} THEN true ELSE devices.is_wired END,
    connection_type     = CASE WHEN {is_wired_val} THEN '{conn_type_escaped}' ELSE devices.connection_type END;
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

# ── Wired cross-site: trigger port bounce if device is on the wrong VLAN ─────
# The device arrived on VLAN 250 (wired_unregistered). Now that we've created
# local DB records and a Kea reservation, bounce the switch port so the HP5130
# fires a MAB re-auth. RADIUS will return the correct VLAN. We cannot use the
# control socket here (risk of Kea deadlock); instead we append directly to the
# replug queue file which the queue worker daemon picks up within seconds.
# A short-lease expiry alone is NOT sufficient — DHCP DISCOVER goes out on
# whichever VLAN the switch port is currently on, not the target VLAN.
if is_wired and assigned_vlan and not device_blocked:
    # Find wired_unregistered VLAN ID from Kea config to confirm we're on it
    wired_unreg_vlan = 250  # default fallback
    kea_cfg = os.getenv("KEA_CONFIG_PATH", "/kea/config/dhcp4.json")
    try:
        import json as _json
        with open(kea_cfg) as _fh:
            _kea = _json.load(_fh)
        for _s in _kea.get("Dhcp4", {}).get("subnet4", []):
            _ctx = _s.get("user-context", {})
            if _ctx.get("vlan_status") == "wired_unregistered":
                wired_unreg_vlan = int(_s["id"])
                break
    except Exception:
        pass

    current_vlan_row = psql(
        f"SELECT current_vlan FROM devices WHERE mac_address = '{MAC}';"
    )
    try:
        current_vlan = int(current_vlan_row)
    except (TypeError, ValueError):
        current_vlan = None

    if current_vlan in (None, wired_unreg_vlan) or current_vlan != assigned_vlan:
        # Mark device as wrong_vlan so FreeRADIUS returns the target VLAN on
        # the next auth (the queries.conf already accepts wrong_vlan status).
        psql(f"""
UPDATE devices
   SET registration_status = 'wrong_vlan',
       wired_target_vlan   = {assigned_vlan}
 WHERE mac_address = '{MAC}';
""")
        # Trigger port bounce directly by running the replug script in background.
        # Also append to queue as a fallback in case the direct invocation fails.
        import time as _time
        mac_norm = MAC.replace(":", "").upper()
        mac_norm = ":".join(mac_norm[i:i+2] for i in range(0, 12, 2))

        replug_script = "/scripts/hp5130-replug.sh"
        try:
            subprocess.Popen(
                [replug_script, mac_norm, "2"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            # Fall back to queue file if direct invocation fails
            queue_base = "/acl-queue" if os.path.isdir("/acl-queue") else os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", "shared", "acl-queue"
            )
            queue_file = os.path.join(queue_base, "hp5130-replug.queue")
            ts = _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime())
            try:
                os.makedirs(queue_base, exist_ok=True)
                with open(queue_file, "a") as _qf:
                    _qf.write(f"{ts}|{mac_norm}|2\n")
            except Exception:
                pass  # fail-open

# ── done ──────────────────────────────────────────────────────────────────────

print("blocked" if device_blocked else "registered")
