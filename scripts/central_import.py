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

# ── debug log ─────────────────────────────────────────────────────────────────
# Stdout is read by the Kea hook (result word only); stderr is suppressed
# (2>/dev/null in the hook command).  Write debug to a file instead.

_LOG_PATH = os.getenv("CENTRAL_IMPORT_LOG", "/kea/logs/central_import.log")

def _dbg(*parts):
    """Append a timestamped debug line to the log file."""
    try:
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        msg = " ".join(str(p) for p in parts)
        with open(_LOG_PATH, "a") as _lf:
            _lf.write(f"{ts} {msg}\n")
    except Exception:
        pass  # never break the main flow


# ── args ──────────────────────────────────────────────────────────────────────

MAC = sys.argv[1].lower().strip() if len(sys.argv) > 1 else ""
_dbg("=== central_import.py called MAC=%r" % MAC)
if not MAC:
    _dbg("ERROR: no MAC argument")
    print("error")
    sys.exit(0)

# ── central config ────────────────────────────────────────────────────────────

API_URL = os.getenv("CENTRAL_API_URL", "").rstrip("/")
API_KEY = os.getenv("CENTRAL_API_KEY", "")
SITE_ID = os.getenv("CENTRAL_SITE_ID", "")
_dbg(f"central config: API_URL={API_URL!r} SITE_ID={SITE_ID!r} API_KEY={'SET' if API_KEY else 'MISSING'}")
if not API_URL or not API_KEY or not SITE_ID:
    _dbg("RESULT: disabled (missing central env vars)")
    print("disabled")
    sys.exit(0)

# ── DB helpers ────────────────────────────────────────────────────────────────
# Defined early so the 404 fallback (local-queue check) can use them.

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


# ── query central ─────────────────────────────────────────────────────────────

data = None
try:
    req = urllib.request.Request(
        f"{API_URL}/api/v1/device/{MAC}",
        headers={"X-API-Key": API_KEY},
    )
    _dbg(f"querying central: GET {API_URL}/api/v1/device/{MAC}")
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read().decode())
    _dbg(f"central response (200): {json.dumps(data)}")
except urllib.error.HTTPError as e:
    if e.code == 404:
        _dbg(f"central returned 404 for {MAC} — checking local outbound queue")
        # Central doesn't know this device yet.  This can happen when a device
        # registered locally but the outbound event hasn't been processed by
        # the background worker (up to CENTRAL_POLL_INTERVAL_SEC delay).
        # Check the local outbound queue for a recent device_registered payload
        # so we can honour the registration without waiting for central to catch up.
        row = psql(
            f"SELECT payload FROM central_outbound_events"
            f" WHERE event_type = 'device_registered'"
            f"   AND payload->>'mac_address' = '{q(MAC)}'"
            f"   AND created_at > NOW() - INTERVAL '24 hours'"
            f" ORDER BY created_at DESC LIMIT 1;"
        )
        _dbg(f"local outbound queue result: {row!r}")
        if row:
            try:
                data = json.loads(row)
                _dbg(f"using local queue payload: {json.dumps(data)}")
            except Exception as ex:
                _dbg(f"failed to parse local queue payload: {ex}")
        if data is None:
            _dbg("RESULT: not_found (central 404, no local queue entry)")
            print("not_found")
            sys.exit(0)
    else:
        _dbg(f"central HTTP error {e.code} — RESULT: error")
        print("error")
        sys.exit(0)
except Exception as ex:
    _dbg(f"central request exception: {ex} — RESULT: error")
    print("error")
    sys.exit(0)

email = (data.get("email") or "").lower().strip()
if not email:
    _dbg("ERROR: no email in data — RESULT: error")
    print("error")
    sys.exit(0)

device_blocked   = bool(data.get("device_blocked") or data.get("user_blocked"))
assigned_vlan    = data.get("assigned_vlan")
# Keep is_wired as None when the field is absent so we can distinguish
# "explicitly wireless" (False) from "not provided" (None).
is_wired         = data.get("is_wired")  # None | True | False
if is_wired is not None:
    is_wired = bool(is_wired)
connection_type  = "wired" if is_wired else (data.get("connection_type") or "unknown")
device_name      = (data.get("device_name") or "")
ssid             = (data.get("ssid") or "")
first_name       = (data.get("first_name") or "")
last_name        = (data.get("last_name") or "")
phone            = (data.get("phone_number") or "")
_dbg(f"parsed: email={email!r} device_blocked={device_blocked} assigned_vlan={assigned_vlan} "
     f"is_wired={is_wired} connection_type={connection_type!r} ssid={ssid!r} device_name={device_name!r}")

# ── write to portal DB ────────────────────────────────────────────────────────

now   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
today = datetime.date.today().isoformat()

# Upsert user (begin_date is NOT NULL)
_dbg(f"INSERT/UPDATE users: email={email!r} first_name={first_name!r} last_name={last_name!r}")
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
_dbg(f"user_id lookup result: {user_id!r}")
if not user_id:
    _dbg("ERROR: user_id is empty after upsert — RESULT: error")
    print("error")
    sys.exit(0)

# If central didn't return is_wired (None = unknown), infer from local VLAN mapping.
# Do NOT infer when is_wired is explicitly False (WiFi device — already known).
if is_wired is None and assigned_vlan:
    try:
        wired_check = psql(
            f"SELECT wired_enabled FROM vlan_mappings WHERE vlan_id = {int(assigned_vlan)} LIMIT 1;"
        )
        _dbg(f"wired_enabled for vlan {assigned_vlan}: {wired_check!r}")
        if wired_check in ('t', 'true', '1'):
            is_wired = True
            connection_type = 'wired'
            _dbg("inferred is_wired=True from vlan_mappings")
        else:
            is_wired = False
            _dbg("inferred is_wired=False from vlan_mappings")
    except Exception as ex:
        _dbg(f"wired inference failed: {ex}")

# Resolve any remaining None to False before writing to SQL
if is_wired is None:
    is_wired = False

# Upsert device
vlan_val          = str(assigned_vlan) if assigned_vlan else "NULL"
is_wired_val      = "true" if is_wired else "false"
conn_type_escaped = connection_type.replace("'", "''")
ssid_escaped      = ssid.replace("'", "''")
# internet_blocked: NULL means "not blocked" in this schema; True means blocked.
internet_blocked_val = "true" if device_blocked else "NULL"
# registration_status reflects the central block state.
reg_status = "blocked" if device_blocked else "registered"
_dbg(f"device upsert values: vlan_val={vlan_val} is_wired_val={is_wired_val} "
     f"internet_blocked_val={internet_blocked_val} reg_status={reg_status!r} "
     f"conn_type={conn_type_escaped!r} ssid={ssid_escaped!r}")

psql(f"""
INSERT INTO devices (
    mac_address, device_name, internet_blocked,
    assigned_vlan, ownership_validated, first_seen, registered_at,
    registration_status, is_wired, connection_type, ssid
)
VALUES (
    '{MAC}', '{q(device_name)}', {internet_blocked_val},
    {vlan_val}, true, '{now}', '{now}',
    '{reg_status}', {is_wired_val}, '{conn_type_escaped}', '{ssid_escaped}'
)
ON CONFLICT (mac_address) DO UPDATE SET
    internet_blocked    = {internet_blocked_val},
    registration_status = '{reg_status}',
    assigned_vlan       = {vlan_val},
    ownership_validated = true,
    is_wired            = CASE WHEN {is_wired_val} THEN true ELSE devices.is_wired END,
    connection_type     = CASE WHEN {is_wired_val} THEN '{conn_type_escaped}' ELSE devices.connection_type END,
    ssid                = CASE WHEN '{ssid_escaped}' <> '' THEN '{ssid_escaped}' ELSE devices.ssid END;
""")
_dbg("devices upsert done")

# Insert ownership only when there is no currently-active entry
_dbg("checking/inserting device_ownership")
psql(f"""
INSERT INTO device_ownership (mac_address, user_id, start_datetime, end_datetime)
SELECT '{MAC}', {user_id}, '{now}', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM device_ownership
     WHERE mac_address = '{MAC}'
       AND end_datetime IS NULL
);
""")
_dbg("device_ownership upsert done")

# ── add Kea reservation directly to PostgreSQL ───────────────────────────────
# We cannot use the Kea control socket here because central_import.py is called
# via popen() from inside a Kea callout.  Kea's callout thread cannot service
# socket requests while blocked waiting for the child process, causing a
# deadlock.  Writing directly to the hosts table avoids this entirely.

client_class = "BLOCKED" if device_blocked else "REGISTERED"

# MAC as raw hex bytes (binary) — Kea stores it as bytea
mac_hex = MAC.replace(":", "")
_dbg(f"INSERT hosts: mac_hex={mac_hex!r} client_class={client_class!r} dhcp4_subnet_id=0")

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
ON CONFLICT (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id)
    WHERE dhcp4_subnet_id IS NOT NULL
DO UPDATE SET dhcp4_client_classes = EXCLUDED.dhcp4_client_classes;
""")
_dbg("hosts upsert done")

# ── Wired cross-site: trigger port bounce if device is on the wrong VLAN ─────
# The device arrived on VLAN 250 (wired_unregistered). Now that we've created
# local DB records and a Kea reservation, bounce the switch port so the HP5130
# fires a MAB re-auth. RADIUS will return the correct VLAN. We cannot use the
# control socket here (risk of Kea deadlock); instead we append directly to the
# replug queue file which the queue worker daemon picks up within seconds.
# A short-lease expiry alone is NOT sufficient — DHCP DISCOVER goes out on
# whichever VLAN the switch port is currently on, not the target VLAN.
if is_wired and assigned_vlan and not device_blocked:
    _dbg(f"wired device on wrong VLAN check: is_wired={is_wired} assigned_vlan={assigned_vlan} device_blocked={device_blocked}")
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
    _dbg(f"wired VLAN check: current_vlan={current_vlan} wired_unreg_vlan={wired_unreg_vlan} assigned_vlan={assigned_vlan}")

    if current_vlan in (None, wired_unreg_vlan) or current_vlan != assigned_vlan:
        _dbg(f"wired VLAN mismatch — setting wrong_vlan and queuing port bounce")
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

result_word = "blocked" if device_blocked else "registered"
_dbg(f"RESULT: {result_word}")
print(result_word)
