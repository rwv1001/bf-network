#!/usr/bin/env python3
"""
hp5130-mac-poll.py
==================
Polls the HP5130 switch MAC address table via SSH, then upserts every
mac->port mapping into the ``mac_port_cache`` table and updates the
``devices.switch_iface`` column for any matching registered device.

Environment variables
---------------------
SWITCH_HOST              Switch IP (default: 192.168.1.3)
SWITCH_USER              SSH user  (default: robert)
SWITCH_KEY_PATH          Path to private key (default: /keys/id_rsa)
SWITCH_SSH_PORT          SSH port  (default: 22)
SWITCH_REPLUG_DENY_PATTERN  Regex; ports matching this are skipped (e.g. Bridge-Aggregation)

DATABASE_URL             Full SQLAlchemy-style URL  -OR- use the fine-grained vars:
DB_HOST                  (default: localhost)
DB_PORT                  (default: 5432)
DB_NAME                  (default: captive_portal)
DB_USER                  (default: portal_user)
DB_PASS                  (default: password)

POLL_INTERVAL_SEC        Seconds between polls (default: 60).  Set to 0 for single-shot.
POLL_CACHE_STALE_SEC     Rows older than this (seconds) are considered stale (default: 300).
"""

import os
import re
import sys
import time
import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("hp5130-mac-poll")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(name, default=""):
    return os.getenv(name, default).strip()


def _expand_iface(iface):
    if iface.startswith("GE") and not iface.startswith("GigabitEthernet"):
        return "GigabitEthernet" + iface[2:]
    if iface.startswith("XGE") and not iface.startswith("Ten-GigabitEthernet"):
        return "Ten-GigabitEthernet" + iface[3:]
    return iface


def _switch_port_allowed(iface):
    deny_pattern = _env("SWITCH_REPLUG_DENY_PATTERN")
    if deny_pattern and re.search(deny_pattern, iface):
        return False
    allowed_raw = _env("SWITCH_REPLUG_ALLOWED_PREFIXES", "GigabitEthernet,GE")
    allowed = [p.strip() for p in allowed_raw.split(",") if p.strip()]
    if not allowed:
        return True
    return any(iface.startswith(p) for p in allowed)


def _normalize_to_colon(raw_mac):
    """
    Accept any common MAC format and return lowercase colon format.
    e.g.  0a1b-2c3d-4e5f  ->  0a:1b:2c:3d:4e:5f
          AA-BB-CC-DD-EE-FF -> aa:bb:cc:dd:ee:ff
          aabbccddeeff      -> aa:bb:cc:dd:ee:ff
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw_mac).lower()
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))


# ---------------------------------------------------------------------------
# SSH MAC table fetch
# ---------------------------------------------------------------------------

def fetch_mac_table(host, user, key_path, port):
    """
    SSH to the switch and run 'display mac-address'.
    Returns the raw output string.
    """
    try:
        import paramiko
    except ImportError:
        log.error("paramiko is not installed; run: pip install paramiko")
        sys.exit(1)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=user,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
        disabled_algorithms={"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]},
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
    else:
        pw = _env("SWITCH_PASS")
        if not pw:
            log.error("No SWITCH_KEY_PATH or SWITCH_PASS configured")
            return ""
        connect_kwargs["password"] = pw

    try:
        client.connect(**connect_kwargs)
    except Exception as exc:
        log.error("SSH connect failed: %s", exc)
        return ""

    output = ""
    try:
        # Use interactive shell so the switch prompt is handled gracefully
        chan = client.invoke_shell()
        time.sleep(0.5)
        # Drain banner
        if chan.recv_ready():
            chan.recv(65535)
        chan.send("display mac-address\n")
        time.sleep(2)
        buf = ""
        deadline = time.time() + 10
        while time.time() < deadline:
            if chan.recv_ready():
                chunk = chan.recv(65535).decode("utf-8", errors="ignore")
                buf += chunk
                # HP5130 shows "---- More ----" for paged output; send space
                while "---- More ----" in buf or "-- More --" in buf:
                    chan.send(" ")
                    time.sleep(0.5)
                    if chan.recv_ready():
                        buf += chan.recv(65535).decode("utf-8", errors="ignore")
            else:
                time.sleep(0.3)
        output = buf
        chan.close()
    except Exception as exc:
        log.error("SSH command failed: %s", exc)
    finally:
        try:
            client.close()
        except Exception:
            pass

    return output


# ---------------------------------------------------------------------------
# Parse MAC table output
# ---------------------------------------------------------------------------

# HP5130 'display mac-address' line format (typical):
#   0a1b-2c3d-4e5f   10      Learned    GigabitEthernet1/0/5
# Columns may vary by firmware; we look for a MAC-like token then an interface.
_IFACE_RE = re.compile(
    r"\b(?P<iface>(?:GigabitEthernet|Ten-GigabitEthernet|GE|XGE|Ethernet|Bridge-Aggregation)\S+)\b",
    re.IGNORECASE,
)
_MAC_RE = re.compile(r"\b([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\b", re.IGNORECASE)
_VLAN_RE = re.compile(r"\b(\d{1,4})\b")


def parse_mac_table(output):
    """
    Parse 'display mac-address' output.
    Returns list of dicts: {mac_colon, switch_iface, vlan_id}
    """
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        mac_m = _MAC_RE.search(line)
        if not mac_m:
            continue
        iface_m = _IFACE_RE.search(line)
        if not iface_m:
            continue

        raw_mac = mac_m.group(1)
        mac_colon = _normalize_to_colon(raw_mac)
        if not mac_colon:
            continue

        iface = _expand_iface(iface_m.group("iface"))

        if not _switch_port_allowed(iface):
            continue

        # Extract VLAN (first isolated integer on the line that looks like a VLAN)
        vlan_id = None
        # Remove MAC and iface from line to find VLAN more reliably
        stripped = _MAC_RE.sub("", line)
        stripped = _IFACE_RE.sub("", stripped)
        vlan_m = _VLAN_RE.search(stripped)
        if vlan_m:
            candidate = int(vlan_m.group(1))
            if 1 <= candidate <= 4094:
                vlan_id = candidate

        entries.append({
            "mac_colon": mac_colon,
            "switch_iface": iface,
            "vlan_id": vlan_id,
        })

    return entries


# ---------------------------------------------------------------------------
# Database upserts
# ---------------------------------------------------------------------------

def get_db_conn():
    """Return a raw psycopg2 connection."""
    try:
        import psycopg2
    except ImportError:
        log.error("psycopg2 is not installed; run: pip install psycopg2-binary")
        sys.exit(1)

    db_url = _env("DATABASE_URL")
    if db_url:
        # Strip SQLAlchemy driver prefix if present
        db_url = re.sub(r"^postgresql\+\w+://", "postgresql://", db_url)
        return psycopg2.connect(db_url)

    return psycopg2.connect(
        host=_env("DB_HOST", "localhost"),
        port=int(_env("DB_PORT", "5432")),
        dbname=_env("DB_NAME", "captive_portal"),
        user=_env("DB_USER", "portal_user"),
        password=_env("DB_PASS", "password"),
    )


def upsert_entries(entries, switch_host):
    """
    Upsert each entry into mac_port_cache.
    Also update devices.switch_iface for matching registered devices.
    """
    if not entries:
        log.info("No entries to upsert.")
        return

    conn = get_db_conn()
    try:
        cur = conn.cursor()

        # Upsert into mac_port_cache
        upsert_sql = """
            INSERT INTO mac_port_cache (mac_address, switch_iface, switch_host, vlan_id, last_seen)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (mac_address) DO UPDATE SET
                switch_iface = EXCLUDED.switch_iface,
                switch_host  = EXCLUDED.switch_host,
                vlan_id      = EXCLUDED.vlan_id,
                last_seen    = EXCLUDED.last_seen
        """
        cache_rows = [
            (e["mac_colon"], e["switch_iface"], switch_host, e["vlan_id"])
            for e in entries
        ]
        cur.executemany(upsert_sql, cache_rows)

        # Update devices.switch_iface for known registered devices
        update_sql = """
            UPDATE devices
            SET switch_iface = %s,
                switch_iface_seen_at = NOW()
            WHERE mac_address = %s
        """
        device_rows = [
            (e["switch_iface"], e["mac_colon"])
            for e in entries
        ]
        cur.executemany(update_sql, device_rows)

        conn.commit()
        log.info(
            "Upserted %d MAC entries; updated device switch_iface for matching devices.",
            len(entries),
        )
    except Exception as exc:
        conn.rollback()
        log.error("Database upsert failed: %s", exc)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main poll loop
# ---------------------------------------------------------------------------

def poll_once(switch_host, switch_user, switch_key, switch_port):
    log.info("Polling switch %s ...", switch_host)
    output = fetch_mac_table(switch_host, switch_user, switch_key, switch_port)
    if not output:
        log.warning("Empty output from switch.")
        return
    entries = parse_mac_table(output)
    log.info("Parsed %d usable MAC entries.", len(entries))
    upsert_entries(entries, switch_host)


def main():
    parser = argparse.ArgumentParser(description="Poll HP5130 MAC table and cache to DB")
    parser.add_argument("--once", action="store_true", help="Single-shot mode (exit after one poll)")
    parser.add_argument("--interval", type=int, default=None,
                        help="Override POLL_INTERVAL_SEC")
    args = parser.parse_args()

    switch_host = _env("SWITCH_HOST", "192.168.1.3")
    switch_user = _env("SWITCH_USER", "robert")
    switch_key  = _env("SWITCH_KEY_PATH", "/keys/id_rsa") or None
    switch_port = int(_env("SWITCH_SSH_PORT", "22"))

    interval = args.interval if args.interval is not None else int(_env("POLL_INTERVAL_SEC", "60"))
    single   = args.once or (interval == 0)

    if single:
        poll_once(switch_host, switch_user, switch_key, switch_port)
    else:
        log.info("Starting poll loop (interval=%ds)", interval)
        while True:
            try:
                poll_once(switch_host, switch_user, switch_key, switch_port)
            except Exception as exc:
                log.error("Poll error: %s", exc)
            time.sleep(interval)


if __name__ == "__main__":
    main()
