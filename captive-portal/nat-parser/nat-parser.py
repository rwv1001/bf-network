#!/usr/bin/env python3
"""
NAT Log Parser Service (Containerized)
Parses remote-syslog.log for NAT-Logger entries and stores sessions in PostgreSQL.
Groups continuous activity (< 60 second gaps) into sessions.
Monitors log freshness and attempts to reinstall UDM logger if stale.
"""

import os
import re
import time
import csv
import logging
import psycopg2
import subprocess
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict
from pathlib import Path

# Configuration from environment
LOG_FILE = os.getenv("LOG_FILE", "/logs/remote-syslog.log")
DB_URL = os.getenv("DATABASE_URL", "postgresql://portal_user:change_this_password@127.0.0.1:5432/captive_portal")
KEA_LEASES_FILE = os.getenv("KEA_LEASES_FILE", "/kea/leases/kea-leases4.csv")
POSITION_FILE = os.getenv("POSITION_FILE", "/state/nat-parser.pos")

UDM_SSH_KEY = os.getenv("UDM_SSH_KEY", "/config/udm_key")
UDM_INSTALL_SCRIPT = os.getenv("UDM_INSTALL_SCRIPT", "/scripts/udm-nat-logger-persist.sh")
ROUTER_SSH_KEY = os.getenv("ROUTER_SSH_KEY", os.getenv("TEL_SSH_KEY", "/config/tel_key"))  # Shared key for all non-UDM routers
ROUTER_INSTALL_SCRIPT = os.getenv("ROUTER_INSTALL_SCRIPT", "/scripts/tel-nat-logger-install.sh")
PORTAL_IP = os.getenv("PORTAL_IP", "")
USER_VLAN_MIN = os.getenv("USER_VLAN_MIN", "")
USER_VLAN_MAX = os.getenv("USER_VLAN_MAX", "")
ROUTER_CHECK_INTERVAL_SECONDS = int(os.getenv("ROUTER_CHECK_INTERVAL_SECONDS", os.getenv("TEL_CHECK_INTERVAL_SECONDS", "300")))  # 5 min

SESSION_GAP_SECONDS = int(os.getenv("SESSION_GAP_SECONDS", "60"))
STALE_LOG_THRESHOLD_SECONDS = int(os.getenv("STALE_LOG_THRESHOLD_SECONDS", "3600"))
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "5"))
REINSTALL_COOLDOWN_SECONDS = int(os.getenv("REINSTALL_COOLDOWN_SECONDS", "300"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))
FLUSH_INTERVAL_SECONDS = int(os.getenv("FLUSH_INTERVAL_SECONDS", "15"))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nat-parser')


class NATParser:
    def __init__(self):
        self.db_conn = None
        self.last_position = None  # None = not yet initialised; will seek to EOF on first open
        self.last_log_timestamp = None
        self.last_reinstall_attempt = None
        self.last_cleanup = None
        self.last_device_ip_sync = None
        self.last_flush = None
        self.active_sessions = {}  # (src_ip, src_port, dst_ip, dst_port) -> session_data
        self.seen_ips = set()  # Track IPs we've seen to trigger updates
        self.cached_routers: list = []       # rows from isp_routers with nat_logger_type != 'none'
        self.last_router_sync: Optional[datetime] = None
        self.router_last_check: Dict[int, datetime] = {}      # router_id -> last check time
        self.router_last_reinstall: Dict[int, datetime] = {}  # router_id -> last reinstall time
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.db_conn = psycopg2.connect(DB_URL)
            logger.info(f"Connected to database")
            return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def parse_nat_line(self, line: str) -> Optional[Tuple]:
        """
        Parse NAT-Logger syslog line
        Expected format: 2026-02-15T23:06:25+00:00 192.168.1.1 NAT-Logger: SNAT: local_src=192.168.10.13:46766 dst=8.8.8.8:443
        Returns: (timestamp, src_ip, src_port, dst_ip, dst_port)
        """
        # Check if line contains NAT-Logger
        if "NAT-Logger" not in line:
            return None
        
        # Extract timestamp (ISO format at start of line)
        ts_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if not ts_match:
            return None
        timestamp_str = ts_match.group(1)
        
        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except ValueError:
            logger.warning(f"Could not parse timestamp: {timestamp_str}")
            return None
        
        # Extract SNAT data: local_src=IP:PORT dst=IP:PORT
        snat_match = re.search(r'local_src=([0-9.]+):(\d+)\s+dst=([0-9.]+):(\d+)', line)
        if not snat_match:
            return None
        
        src_ip = snat_match.group(1)
        src_port = int(snat_match.group(2))
        dst_ip = snat_match.group(3)
        dst_port = int(snat_match.group(4))
        
        return (timestamp, src_ip, src_port, dst_ip, dst_port)
    
    def process_nat_entry(self, timestamp, src_ip, src_port, dst_ip, dst_port):
        """Process a NAT entry - either update existing session or create new one"""
        session_key = (src_ip, src_port, dst_ip, dst_port)
        
        # Check if we have an active session for this connection
        if session_key in self.active_sessions:
            session = self.active_sessions[session_key]
            
            # Check if this entry is within session gap time
            time_gap = (timestamp - session['last_seen']).total_seconds()
            
            if time_gap <= SESSION_GAP_SECONDS:
                # Update existing session
                session['last_seen'] = timestamp
                session['packet_count'] += 1
                logger.debug(f"Updated session {src_ip}:{src_port} -> {dst_ip}:{dst_port} (gap: {time_gap:.1f}s)")
            else:
                # Gap too large - close old session and start new one
                self._close_session(session_key, session)
                self._start_new_session(session_key, timestamp)
                logger.debug(f"New session {src_ip}:{src_port} -> {dst_ip}:{dst_port} (gap: {time_gap:.1f}s)")
        else:
            # New connection - start new session
            self._start_new_session(session_key, timestamp)
            logger.debug(f"Started session {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    def _start_new_session(self, session_key, timestamp):
        """Start a new session"""
        src_ip, src_port, dst_ip, dst_port = session_key
        self.active_sessions[session_key] = {
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'start': timestamp,
            'last_seen': timestamp,
            'packet_count': 1
        }
        # Track this IP for device sync
        self.seen_ips.add(src_ip)
        logger.debug(f"Added {src_ip} to seen_ips (total: {len(self.seen_ips)})")
    
    def _get_port_info_by_ips(self, src_ips):
        """Batch-lookup port info for a set of src IPs.
        Uses Kea leases (timestamped IP->MAC) then mac_port_cache (MAC->port+host)
        so the data reflects what was true when the session was active, not
        the current device state (which may have changed).
        Returns dict of {ip_str: {'src_mac': ..., 'switch_iface': ..., 'switch_host': ...}}.
        """
        if not src_ips:
            return {}

        # Step 1: IP -> MAC via Kea leases file (timestamped)
        ip_to_mac = self._parse_kea_leases(list(src_ips))
        if not ip_to_mac:
            return {}

        # Step 2: MAC -> {switch_iface, switch_host} via mac_port_cache
        macs = list(ip_to_mac.values())
        mac_to_port = {}
        try:
            with self.db_conn.cursor() as cur:
                cur.execute(
                    "SELECT mac_address, switch_iface, switch_host "
                    "FROM mac_port_cache WHERE mac_address = ANY(%s)",
                    (macs,)
                )
                for row in cur.fetchall():
                    mac_to_port[row[0]] = {'switch_iface': row[1], 'switch_host': row[2]}
        except Exception as e:
            logger.debug(f"mac_port_cache lookup failed: {e}")

        # Step 3: Combine into IP-keyed result
        result = {}
        for ip, data in ip_to_mac.items():
            mac = data['mac_address']
            port = mac_to_port.get(mac, {})
            result[ip] = {
                'src_mac':     mac,
                'switch_iface': port.get('switch_iface'),
                'switch_host':  port.get('switch_host'),
            }
        return result

    def _close_session(self, session_key, session):
        """Close a session and write to database"""
        try:
            port_map = self._get_port_info_by_ips({session['src_ip']})
            port_info = port_map.get(session['src_ip'], {})
            src_mac     = port_info.get('src_mac')
            switch_iface = port_info.get('switch_iface')
            switch_host  = port_info.get('switch_host')
            with self.db_conn.cursor() as cur:
                # Use INSERT ... ON CONFLICT to handle duplicates gracefully
                # If the same session already exists, update it with the latest end time and packet count
                cur.execute("""
                    INSERT INTO nat_sessions
                    (src_ip, src_port, dst_ip, dst_port, session_start, session_end,
                     packet_count, src_mac, switch_iface, switch_host)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (src_ip, src_port, dst_ip, dst_port, session_start)
                    DO UPDATE SET
                        session_end  = EXCLUDED.session_end,
                        packet_count = EXCLUDED.packet_count,
                        src_mac      = COALESCE(nat_sessions.src_mac,      EXCLUDED.src_mac),
                        switch_iface = COALESCE(nat_sessions.switch_iface, EXCLUDED.switch_iface),
                        switch_host  = COALESCE(nat_sessions.switch_host,  EXCLUDED.switch_host)
                """, (
                    session['src_ip'],
                    session['src_port'],
                    session['dst_ip'],
                    session['dst_port'],
                    session['start'],
                    session['last_seen'],
                    session['packet_count'],
                    src_mac,
                    switch_iface,
                    switch_host,
                ))
            self.db_conn.commit()
            
            duration = (session['last_seen'] - session['start']).total_seconds()
            logger.info(
                f"Closed session {session['src_ip']}:{session['src_port']} -> "
                f"{session['dst_ip']}:{session['dst_port']} "
                f"(duration: {duration:.1f}s, packets: {session['packet_count']})"
            )
            
            # Remove from active sessions
            del self.active_sessions[session_key]
            
        except Exception as e:
            logger.error(f"Failed to close session: {e}")
            # Rollback the transaction on error
            try:
                self.db_conn.rollback()
            except:
                pass
    
    def update_device_ips(self):
        """
        Update device IPs based on Kea leases for recently seen IPs.
        This ensures the devices table stays in sync with DHCP assignments.
        """
        logger.debug(f"update_device_ips called, seen_ips count: {len(self.seen_ips)}")
        
        if not self.seen_ips:
            return
        
        # Only run this check every 30 seconds to avoid excessive queries
        if self.last_device_ip_sync:
            time_since_sync = (datetime.now() - self.last_device_ip_sync).total_seconds()
            if time_since_sync < 30:
                logger.debug(f"Skipping device IP sync, last sync was {time_since_sync:.1f}s ago")
                return
        
        self.last_device_ip_sync = datetime.now()
        logger.info(f"Starting device IP sync for {len(self.seen_ips)} IPs")
        
        ips_to_check = list(self.seen_ips)
        self.seen_ips.clear()  # Clear the set after processing
        
        if not ips_to_check:
            return
        
        try:
            # Read Kea leases CSV file to get IP -> MAC mappings
            ip_to_mac = self._parse_kea_leases(ips_to_check)
            
            logger.info(f"Parsed Kea leases, found {len(ip_to_mac)} IP->MAC mappings")
            
            if not ip_to_mac:
                logger.info(f"No matching leases found for {len(ips_to_check)} IPs")
                return
            
            # Update devices table with new IPs
            updated_count = 0
            with self.db_conn.cursor() as cur:
                for ip, data in ip_to_mac.items():
                    mac = data['mac_address']
                    expire = data['expire']                    # ← Get expire from parsed data

                    cur.execute("""
                        UPDATE ip_leases
                        SET ip_address = %s,
                            lease_expiry = to_timestamp(%s)
                        WHERE mac_address = %s
                        AND from_blocked_pool = false
                        AND EXISTS (
                            SELECT 1 
                            FROM devices d 
                            WHERE d.mac_address = ip_leases.mac_address 
                                AND d.registration_status = 'registered'
                        )
                    """, (ip, expire, mac))

                    if cur.rowcount > 0:
                        updated_count += 1
                        logger.info(f"Updated IP lease: {mac} -> {ip}")

                if updated_count > 0:
                    self.db_conn.commit()
                    logger.info(f"Device IP sync complete: updated {updated_count} leases")
                else:
                    logger.info(f"Checked {len(ips_to_check)} IPs, no updates needed")
                    
        except Exception as e:
            logger.error(f"Failed to update device IPs: {e}")
            try:
                self.db_conn.rollback()
            except:
                pass
    
    def _parse_kea_leases(self, ip_list: list) -> Dict[str, dict]:
        """
        Parse Kea leases CSV file and return data for given IPs.
        Returns: {ip_address: {'mac_address': str, 'expire': int}}
        """
        ip_set = set(ip_list)
        result = {}

        try:
            if not os.path.exists(KEA_LEASES_FILE):
                logger.warning(f"Kea leases file not found: {KEA_LEASES_FILE}")
                return {}

            current_time = int(time.time())

            with open(KEA_LEASES_FILE, 'r') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        ip_address = row.get('address', '')
                        hwaddr = row.get('hwaddr', '')
                        expire = int(row.get('expire', 0))
                        state = int(row.get('state', 1))

                        if state != 0 or expire < current_time:
                            continue

                        if ip_address in ip_set and hwaddr:
                            result[ip_address] = {
                                'mac_address': hwaddr.lower(),
                                'expire': expire
                            }
                    except (ValueError, KeyError) as e:
                        logger.debug(f"Skipping malformed lease entry: {e}")
                        continue

            logger.debug(f"Found {len(result)} active IP->MAC mappings from Kea leases")
            return result

        except Exception as e:
            logger.error(f"Failed to parse Kea leases file: {e}")
            return {}
    
    def flush_active_sessions(self):
        """Upsert all in-progress sessions to DB without closing them.
        This makes them visible in the Traffic Viewer while still ongoing."""
        if not self.active_sessions:
            return
        now = datetime.now()
        if self.last_flush and (now - self.last_flush).total_seconds() < FLUSH_INTERVAL_SECONDS:
            return
        self.last_flush = now
        try:
            port_map = self._get_port_info_by_ips({s['src_ip'] for s in self.active_sessions.values()})
            with self.db_conn.cursor() as cur:
                for session in self.active_sessions.values():
                    port_info    = port_map.get(session['src_ip'], {})
                    src_mac      = port_info.get('src_mac')
                    switch_iface = port_info.get('switch_iface')
                    switch_host  = port_info.get('switch_host')
                    cur.execute("""
                        INSERT INTO nat_sessions
                        (src_ip, src_port, dst_ip, dst_port, session_start, session_end,
                         packet_count, src_mac, switch_iface, switch_host)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (src_ip, src_port, dst_ip, dst_port, session_start)
                        DO UPDATE SET
                            session_end  = EXCLUDED.session_end,
                            packet_count = EXCLUDED.packet_count,
                            src_mac      = COALESCE(nat_sessions.src_mac,      EXCLUDED.src_mac),
                            switch_iface = COALESCE(nat_sessions.switch_iface, EXCLUDED.switch_iface),
                            switch_host  = COALESCE(nat_sessions.switch_host,  EXCLUDED.switch_host)
                    """, (
                        session['src_ip'], session['src_port'],
                        session['dst_ip'], session['dst_port'],
                        session['start'], session['last_seen'],
                        session['packet_count'], src_mac, switch_iface, switch_host
                    ))
            self.db_conn.commit()
            logger.debug(f"Flushed {len(self.active_sessions)} active sessions to DB")
        except Exception as e:
            logger.error(f"Error flushing active sessions: {e}")

    def close_stale_sessions(self):
        """Close sessions that haven't seen activity recently"""
        current_time = datetime.now()
        stale_keys = []
        
        for key, session in self.active_sessions.items():
            time_since_last = (current_time - session['last_seen']).total_seconds()
            if time_since_last > SESSION_GAP_SECONDS * 2:  # 2x the gap threshold
                stale_keys.append(key)
        
        for key in stale_keys:
            self._close_session(key, self.active_sessions[key])
    
    def _load_position(self):
        """Load last file position from disk, or default to end-of-file."""
        if os.path.exists(POSITION_FILE):
            try:
                with open(POSITION_FILE, 'r') as f:
                    pos = int(f.read().strip())
                logger.info(f"Resuming from saved position {pos}")
                return pos
            except Exception as e:
                logger.warning(f"Could not read position file: {e}")
        # No saved position – start from current end of file so we don't replay history
        try:
            pos = os.path.getsize(LOG_FILE)
            logger.info(f"No saved position; starting from end of log file (byte {pos})")
            return pos
        except Exception:
            return 0

    def _save_position(self, pos):
        """Persist current file position to disk."""
        try:
            os.makedirs(os.path.dirname(POSITION_FILE), exist_ok=True)
            with open(POSITION_FILE, 'w') as f:
                f.write(str(pos))
        except Exception as e:
            logger.warning(f"Could not save position file: {e}")

    def process_log_file(self):
        """Process new entries from log file"""
        try:
            if not os.path.exists(LOG_FILE):
                logger.warning(f"Log file not found: {LOG_FILE}")
                return

            file_size = os.path.getsize(LOG_FILE)

            # Initialise position on first call
            if self.last_position is None:
                self.last_position = self._load_position()

            # Handle log rotation (file got smaller)
            if file_size < self.last_position:
                logger.info("Log file rotated, resetting position")
                self.last_position = 0
            
            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_position)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    result = self.parse_nat_line(line)
                    if result:
                        timestamp, src_ip, src_port, dst_ip, dst_port = result
                        self.process_nat_entry(timestamp, src_ip, src_port, dst_ip, dst_port)
                        self.last_log_timestamp = datetime.now()

                self.last_position = f.tell()
                self._save_position(self.last_position)
        
        except Exception as e:
            logger.error(f"Error processing log file: {e}")
    
    def load_routers(self):
    """Load ISP routers with nat_logger_type != 'none' from the database."""
    try:
        with self.db_conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, nat_logger_type, subnet, gateway_ip
                FROM isp_routers
                WHERE nat_logger_type != 'none'
                ORDER BY id
            """)
            rows = cur.fetchall()
        routers = []
        for row in rows:
            router_id, name, logger_type, subnet, gateway_ip = row
            if not gateway_ip:
                logger.warning(
                    "ISP router id=%s name=%r has empty gateway_ip; skipping",
                    router_id, name,
                )
                continue
            routers.append({
                'id': router_id,
                'name': name,
                'nat_logger_type': logger_type,
                'subnet': subnet,
                'gateway_ip': gateway_ip,
            })
        self.cached_routers = routers
        self.last_router_sync = datetime.now()
        logger.info(
            "Loaded %s NAT logger router(s): %s",
            len(routers),
            [r['name'] for r in routers],
        )
    except Exception as e:
        logger.error("Failed to load routers from DB: %s", e)

    def check_all_routers(self):
        """Check all configured ISP routers and reinstall loggers as needed."""
        # Reload router list from DB every 10 minutes so new routers are picked up
        if (self.last_router_sync is None or
                (datetime.now() - self.last_router_sync).total_seconds() > 600):
            self.load_routers()

        for router in self.cached_routers:
            rid = router['id']
            last_check = self.router_last_check.get(rid)
            if last_check and (datetime.now() - last_check).total_seconds() < ROUTER_CHECK_INTERVAL_SECONDS:
                continue
            if router['nat_logger_type'] == 'udm':
                self._check_udm_router(router)
            elif router['nat_logger_type'] == 'openwrt':
                self._check_openwrt_router(router)
            self.router_last_check[rid] = datetime.now()

    def _check_udm_router(self, router: dict):
        """Check if NAT logger is running on a UDM router, reinstall if not."""
        host = router['gateway_ip']
        name = router['name']
        if not os.path.exists(UDM_SSH_KEY):
            logger.warning(f"UDM SSH key not found: {UDM_SSH_KEY} - skipping {name} check")
            return
        try:
            logger.info(f"Checking NAT logger on {name} ({host})...")
            result = subprocess.run([
                "ssh", "-i", UDM_SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                f"root@{host}", "pgrep -f nat_logger.sh"
            ], capture_output=True, timeout=10)
            if result.returncode == 0:
                pids = result.stdout.decode().strip().split('\n')
                logger.info(f"NAT logger running on {name} (PIDs: {', '.join(pids)})")
            else:
                logger.warning(f"NAT logger NOT running on {name} - attempting reinstall...")
                self._reinstall_udm_router(router)
        except subprocess.TimeoutExpired:
            logger.error(f"{name} connection timed out")
        except Exception as e:
            logger.error(f"Failed to check {name} logger status: {e}")

    def _reinstall_udm_router(self, router: dict):
        """Reinstall NAT logger on a UDM router."""
        rid = router['id']
        host = router['gateway_ip']
        name = router['name']
        last = self.router_last_reinstall.get(rid)
        if last and (datetime.now() - last).total_seconds() < REINSTALL_COOLDOWN_SECONDS:
            remaining = REINSTALL_COOLDOWN_SECONDS - (datetime.now() - last).total_seconds()
            logger.info(f"{name} reinstall cooldown active ({remaining:.0f}s remaining)")
            return
        self.router_last_reinstall[rid] = datetime.now()
        if not os.path.exists(UDM_SSH_KEY) or not os.path.exists(UDM_INSTALL_SCRIPT):
            logger.warning(f"Missing SSH key or install script for {name}")
            return
        try:
            logger.info(f"Copying install script to {name} ({host})...")
            result = subprocess.run([
                "scp", "-i", UDM_SSH_KEY,
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                UDM_INSTALL_SCRIPT, f"root@{host}:/tmp/udm-nat-logger-persist.sh"
            ], capture_output=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"SCP to {name} failed: {result.stderr.decode()}")
                return
            env_prefix = (f"PORTAL_IP='{PORTAL_IP}' "
                          f"USER_VLAN_MIN='{USER_VLAN_MIN}' "
                          f"USER_VLAN_MAX='{USER_VLAN_MAX}'")
            result = subprocess.run([
                "ssh", "-i", UDM_SSH_KEY,
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                f"root@{host}",
                f"{env_prefix} bash /tmp/udm-nat-logger-persist.sh"
            ], capture_output=True, timeout=60)
            if result.returncode == 0:
                logger.info(f"Successfully reinstalled NAT logger on {name}")
                logger.debug(result.stdout.decode())
            else:
                logger.error(f"{name} install script failed: {result.stderr.decode()}")
        except subprocess.TimeoutExpired:
            logger.error(f"{name} connection timed out during reinstall")
        except Exception as e:
            logger.error(f"{name} reinstall failed: {e}")

    def _check_openwrt_router(self, router: dict):
        """Check if NAT logger is running on an OpenWRT router, reinstall if not."""
        host = router['gateway_ip']
        name = router['name']
        if not os.path.exists(ROUTER_SSH_KEY):
            logger.warning(f"Router SSH key not found: {ROUTER_SSH_KEY} - skipping {name} check")
            return
        try:
            logger.info(f"Checking NAT logger on {name} ({host})...")
            result = subprocess.run([
                "ssh", "-i", ROUTER_SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                f"root@{host}", "pgrep -f nat_logger.sh"
            ], capture_output=True, timeout=10)
            if result.returncode == 0:
                pids = result.stdout.decode().strip().split('\n')
                logger.info(f"NAT logger running on {name} (PIDs: {', '.join(pids)})")
            else:
                logger.warning(f"NAT logger NOT running on {name} - attempting reinstall...")
                self._reinstall_openwrt_router(router)
        except subprocess.TimeoutExpired:
            logger.error(f"{name} connection timed out")
        except Exception as e:
            logger.error(f"Failed to check {name} logger status: {e}")

    def _reinstall_openwrt_router(self, router: dict):
        """Reinstall NAT logger on an OpenWRT router."""
        rid = router['id']
        host = router['gateway_ip']
        name = router['name']
        last = self.router_last_reinstall.get(rid)
        if last and (datetime.now() - last).total_seconds() < REINSTALL_COOLDOWN_SECONDS:
            remaining = REINSTALL_COOLDOWN_SECONDS - (datetime.now() - last).total_seconds()
            logger.info(f"{name} reinstall cooldown active ({remaining:.0f}s remaining)")
            return
        self.router_last_reinstall[rid] = datetime.now()
        if not os.path.exists(ROUTER_SSH_KEY) or not os.path.exists(ROUTER_INSTALL_SCRIPT):
            logger.warning(f"Missing SSH key or install script for {name}")
            return
        try:
            logger.info(f"Copying install script to {name} ({host})...")
            result = subprocess.run([
                "scp", "-i", ROUTER_SSH_KEY,
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                ROUTER_INSTALL_SCRIPT, f"root@{host}:/tmp/tel-nat-logger-install.sh"
            ], capture_output=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"SCP to {name} failed: {result.stderr.decode()}")
                return
            env_prefix = (f"PORTAL_IP='{PORTAL_IP}' "
                          f"USER_VLAN_MIN='{USER_VLAN_MIN}' "
                          f"USER_VLAN_MAX='{USER_VLAN_MAX}'")
            result = subprocess.run([
                "ssh", "-i", ROUTER_SSH_KEY,
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                f"root@{host}",
                f"{env_prefix} sh /tmp/tel-nat-logger-install.sh"
            ], capture_output=True, timeout=60)
            if result.returncode == 0:
                logger.info(f"Successfully reinstalled NAT logger on {name}")
                logger.debug(result.stdout.decode())
            else:
                logger.error(f"{name} install script failed: {result.stderr.decode()}")
        except subprocess.TimeoutExpired:
            logger.error(f"{name} connection timed out during reinstall")
        except Exception as e:
            logger.error(f"{name} reinstall failed: {e}")

    def check_log_freshness(self):
        """Check if logs are stale and attempt reinstall if needed"""
        if self.last_log_timestamp is None:
            return  # No logs seen yet
        
        time_since_last_log = (datetime.now() - self.last_log_timestamp).total_seconds()
        
        if time_since_last_log > STALE_LOG_THRESHOLD_SECONDS:
            logger.warning(f"No NAT logs for {time_since_last_log/60:.1f} minutes")
            
            # Check if we can attempt reinstall (cooldown period)
            if self.last_reinstall_attempt:
                time_since_reinstall = (datetime.now() - self.last_reinstall_attempt).total_seconds()
                if time_since_reinstall < REINSTALL_COOLDOWN_SECONDS:
                    logger.info(f"Reinstall cooldown active ({REINSTALL_COOLDOWN_SECONDS - time_since_reinstall:.0f}s remaining)")
                    return
            
            self.attempt_udm_reinstall()
    
    def attempt_udm_reinstall(self):
        """Stale-log triggered reinstall: find the UDM router from cache and reinstall."""
        logger.info("Attempting to reinstall NAT logger on UDM (stale log trigger)...")
        self.last_reinstall_attempt = datetime.now()
        udm_routers = [r for r in self.cached_routers if r['nat_logger_type'] == 'udm']
        if not udm_routers:
            logger.warning("No UDM router found in DB - cannot reinstall")
            return
        for router in udm_routers:
            self._reinstall_udm_router(router)
    
    def cleanup_old_sessions(self):
        """Delete NAT sessions older than RETENTION_DAYS"""
        # Only run cleanup once per day
        if self.last_cleanup:
            time_since_cleanup = (datetime.now() - self.last_cleanup).total_seconds()
            if time_since_cleanup < 86400:  # 24 hours
                return
        
        try:
            cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
            
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM nat_sessions 
                    WHERE session_end < %s
                """, (cutoff_date,))
                
                deleted_count = cur.rowcount
            
            self.db_conn.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} NAT sessions older than {RETENTION_DAYS} days")
            else:
                logger.debug(f"No NAT sessions older than {RETENTION_DAYS} days to clean up")
            
            self.last_cleanup = datetime.now()
            
        except Exception as e:
            logger.error(f"Failed to cleanup old sessions: {e}")
            try:
                self.db_conn.rollback()
            except:
                pass
    
    def check_udm_logger_running(self):
        """Backwards-compatible: delegate to check_all_routers for UDM routers."""
        udm_routers = [r for r in self.cached_routers if r['nat_logger_type'] == 'udm']
        for router in udm_routers:
            self._check_udm_router(router)
            self.router_last_check[router['id']] = datetime.now()
    
    def run(self):
        """Main loop"""
        logger.info("NAT Parser Service starting...")
        
        # Wait for database to be ready
        max_retries = 30
        retry_count = 0
        while retry_count < max_retries:
            if self.connect_db():
                break
            retry_count += 1
            logger.info(f"Waiting for database... ({retry_count}/{max_retries})")
            time.sleep(2)
        
        if not self.db_conn:
            logger.error("Failed to connect to database after retries, exiting")
            return
        
        logger.info(f"Monitoring log file: {LOG_FILE}")
        logger.info(f"Session gap threshold: {SESSION_GAP_SECONDS}s")
        logger.info(f"Stale log threshold: {STALE_LOG_THRESHOLD_SECONDS}s")
        logger.info(f"NAT retention: {RETENTION_DAYS} days")

        # Load router list from DB and check all loggers at startup
        self.load_routers()
        self.check_all_routers()
        
        try:
            while True:
                # Process new log entries
                self.process_log_file()

                # Flush active sessions to DB so Traffic Viewer shows them live
                self.flush_active_sessions()

                # Update device IPs based on recently seen traffic
                self.update_device_ips()
                
                # Close stale sessions
                self.close_stale_sessions()
                
                # Check log freshness (triggers UDM reinstall if stale)
                self.check_log_freshness()

                # Periodically check all routers are still running
                self.check_all_routers()
                
                # Cleanup old sessions (runs once per day)
                self.cleanup_old_sessions()
                
                # Sleep before next check
                time.sleep(CHECK_INTERVAL_SECONDS)
        
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            # Close any remaining active sessions
            logger.info(f"Closing {len(self.active_sessions)} active sessions...")
            for key, session in list(self.active_sessions.items()):
                self._close_session(key, self.active_sessions[key])
            
            if self.db_conn:
                self.db_conn.close()
            logger.info("NAT Parser Service stopped")


if __name__ == "__main__":
    parser = NATParser()
    parser.run()
