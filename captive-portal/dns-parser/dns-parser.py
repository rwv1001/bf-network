#!/usr/bin/env python3
"""
DNS Query Parser Service (Containerized)
Parses dnsmasq query logs and stores domain->IP mappings in PostgreSQL.
Deduplicates entries within 12-hour windows to reduce storage.
Also polls the Pi-Hole v6 API for blocked queries and records them with
user attribution via devices.ip_address → users.
"""

import os
import re
import time
import logging
import urllib.request
import urllib.error
import json
import psycopg2
from datetime import datetime, timedelta
from typing import Optional, Tuple

# Configuration from environment
LOG_FILE = os.getenv("LOG_FILE", "/logs/dnsmasq-queries.log")
DB_URL = os.getenv("DATABASE_URL", "postgresql://portal_user:change_this_password@127.0.0.1:5432/captive_portal")

DEDUP_THRESHOLD_HOURS = int(os.getenv("DNS_DEDUP_THRESHOLD_HOURS", "12"))
CHECK_INTERVAL_SECONDS = int(os.getenv("DNS_CHECK_INTERVAL_SECONDS", "5"))
RETENTION_DAYS = int(os.getenv("DNS_RETENTION_DAYS", "90"))

# Pi-Hole blocked query polling
PIHOLE_BASE_URL = os.getenv("PIHOLE_BASE_URL", "http://127.0.0.1:8055")
PIHOLE_PASSWORD  = os.getenv("PIHOLE_WEBPASSWORD", "")
PIHOLE_POLL_INTERVAL_SECONDS = int(os.getenv("PIHOLE_POLL_INTERVAL_SECONDS", "30"))
PIHOLE_BLOCKED_STATUSES = {"GRAVITY", "GRAVITY_CNAME", "BLOCKLIST", "REGEX", "WILDCARD", "DENYLIST"}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dns-parser')


class DNSParser:
    def __init__(self):
        self.db_conn = None
        self.last_position = 0
        self.last_cleanup = None
        # CNAME chain tracking: pid -> (original_domain, timestamp)
        self.cname_pending = {}
        # Pi-Hole blocked query polling state
        self._pihole_sid = None
        self._pihole_sid_expires = 0
        self._pihole_last_cursor = None   # last Pi-Hole query id processed
        self._pihole_last_poll = 0
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.db_conn = psycopg2.connect(DB_URL)
            logger.info(f"Connected to database")
            return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def parse_dns_line(self, line: str) -> Optional[Tuple]:
        """
        Parse dnsmasq query log line
        Expected formats:
        - Query: dnsmasq[123]: query[A] example.com from 192.168.10.5
        - Reply: dnsmasq[123]: reply example.com is 93.184.216.34
        
        Returns: ('resolve', pid, domain, ip), ('forward', pid, domain), or None
        """
        # Extract dnsmasq process ID — same PID = same DNS query
        pid_match = re.search(r'(?:dnsmasq|pihole-FTL)\[(\d+)\]:', line)
        pid = pid_match.group(1) if pid_match else None

        # Match reply lines: "reply domain is IP" (IPv4 only)
        reply_match = re.search(r'reply\s+(\S+)\s+is\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s|$)', line)
        if reply_match:
            domain = reply_match.group(1)
            ip = reply_match.group(2)
            
            # Filter out special domains and invalid IPs
            if domain.startswith('.') or domain == '<Root>':
                return None
            if ip.startswith('127.') or ip.startswith('0.'):
                return None
                
            return ('resolve', pid, domain, ip)

        # Match forwarded lines — this is the original (pre-CNAME) query domain
        forward_match = re.search(r'forwarded\s+(\S+)\s+to\s+', line)
        if forward_match and pid:
            domain = forward_match.group(1)
            if not domain.startswith('.'):
                return ('forward', pid, domain)

        return None
    
    def store_dns_resolution(self, domain: str, ip: str):
        """
        Store or update DNS resolution with 12-hour deduplication
        """
        try:
            with self.db_conn.cursor() as cur:
                # Check if entry exists and when last seen
                cur.execute("""
                    SELECT id, last_seen, query_count
                    FROM dns_resolutions
                    WHERE domain_name = %s AND resolved_ip = %s
                """, (domain, ip))
                
                existing = cur.fetchone()
                current_time = datetime.now()
                
                if existing:
                    existing_id, last_seen, query_count = existing
                    time_since_last = (current_time - last_seen).total_seconds()
                    
                    # Only update if beyond deduplication threshold
                    if time_since_last > (DEDUP_THRESHOLD_HOURS * 3600):
                        cur.execute("""
                            UPDATE dns_resolutions
                            SET last_seen = %s,                                query_count = query_count + 1
                            WHERE id = %s
                        """, (current_time, existing_id))
                        
                        self.db_conn.commit()
                        logger.debug(f"Updated: {domain} -> {ip} (gap: {time_since_last/3600:.1f}h)")
                    # else: Skip update, within deduplication window
                else:
                    # Insert new resolution
                    cur.execute("""
                        INSERT INTO dns_resolutions 
                        (domain_name, resolved_ip, first_seen, last_seen, query_count)
                        VALUES (%s, %s, %s, %s, 1)
                    """, (domain, ip, current_time, current_time))
                    
                    self.db_conn.commit()
                    logger.info(f"New resolution: {domain} -> {ip}")
                    
        except Exception as e:
            logger.error(f"Failed to store DNS resolution {domain} -> {ip}: {e}")
            try:
                self.db_conn.rollback()
            except:
                pass
    
    def process_log_file(self):
        """Process new entries from log file"""
        try:
            if not os.path.exists(LOG_FILE):
                logger.debug(f"Log file not found: {LOG_FILE}")
                return
            
            file_size = os.path.getsize(LOG_FILE)
            
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
                    
                    result = self.parse_dns_line(line)
                    if result:
                        if result[0] == 'forward':
                            _, pid, domain = result
                            # Remember original query domain for this PID
                            self.cname_pending[pid] = (domain, datetime.now())
                        elif result[0] == 'resolve':
                            _, pid, domain, ip = result
                            self.store_dns_resolution(domain, ip)
                            # If we tracked a forwarded query for this PID,
                            # also record the original (pre-CNAME) domain → same IP
                            if pid and pid in self.cname_pending:
                                orig_domain, _ = self.cname_pending.pop(pid)
                                if orig_domain != domain:
                                    self.store_dns_resolution(orig_domain, ip)

                # Purge stale pending entries (older than 60s) to avoid memory growth
                cutoff = datetime.now()
                self.cname_pending = {
                    pid: (dom, ts)
                    for pid, (dom, ts) in self.cname_pending.items()
                    if (cutoff - ts).total_seconds() < 60
                }
                
                self.last_position = f.tell()
        
        except Exception as e:
            logger.error(f"Error processing log file: {e}")
    
    def cleanup_old_resolutions(self):
        """Delete DNS resolutions older than RETENTION_DAYS"""
        # Only run cleanup once per day
        if self.last_cleanup:
            time_since_cleanup = (datetime.now() - self.last_cleanup).total_seconds()
            if time_since_cleanup < 86400:  # 24 hours
                return
        
        try:
            cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
            
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM dns_resolutions 
                    WHERE last_seen < %s
                """, (cutoff_date,))
                
                deleted_count = cur.rowcount
            
            self.db_conn.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} DNS resolutions older than {RETENTION_DAYS} days")
            else:
                logger.debug(f"No DNS resolutions older than {RETENTION_DAYS} days to clean up")
            
            self.last_cleanup = datetime.now()
            
        except Exception as e:
            logger.error(f"Failed to cleanup old resolutions: {e}")
            try:
                self.db_conn.rollback()
            except:
                pass

    # ------------------------------------------------------------------ #
    #  Pi-Hole blocked-query polling                                       #
    # ------------------------------------------------------------------ #

    def _pihole_request(self, path, *, method='GET', body=None):
        """Make an authenticated request to the Pi-Hole v6 API."""
        url = f"{PIHOLE_BASE_URL}{path}"
        data = json.dumps(body).encode() if body is not None else None
        headers = {'Content-Type': 'application/json'}
        if self._pihole_sid and time.time() < self._pihole_sid_expires:
            headers['sid'] = self._pihole_sid
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return None  # signal re-auth needed
            logger.debug("Pi-Hole API HTTP %s for %s", e.code, path)
            return None
        except Exception as e:
            logger.debug("Pi-Hole API error for %s: %s", path, e)
            return None

    def _pihole_authenticate(self):
        """Obtain a fresh session ID from Pi-Hole."""
        if not PIHOLE_PASSWORD:
            return False
        result = self._pihole_request('/api/auth', method='POST',
                                      body={'password': PIHOLE_PASSWORD})
        if result and result.get('session', {}).get('valid'):
            self._pihole_sid = result['session']['sid']
            validity = result['session'].get('validity', 1800)
            self._pihole_sid_expires = time.time() + validity - 60
            logger.info("Pi-Hole authenticated (session valid %ds)", validity)
            return True
        logger.warning("Pi-Hole authentication failed")
        return False

    def _pihole_get(self, path):
        """GET with automatic re-auth on 401."""
        result = self._pihole_request(path)
        if result is None:
            if self._pihole_authenticate():
                result = self._pihole_request(path)
        return result

    def _load_pihole_cursor(self):
        """Load the last processed Pi-Hole query ID from DB."""
        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    SELECT pihole_query_id FROM pihole_blocked_queries
                    ORDER BY pihole_query_id DESC LIMIT 1
                """)
                row = cur.fetchone()
                if row:
                    self._pihole_last_cursor = row[0]
                    logger.info("Pi-Hole poller resuming after query id %d", self._pihole_last_cursor)
        except Exception as e:
            logger.error("Failed to load Pi-Hole cursor: %s", e)
            try:
                self.db_conn.rollback()
            except:
                pass

    def _resolve_client(self, client_ip):
        """Return (device_id, user_id, mac_address) for a client IP.

        The MAC is captured now (within 30s of the query) while the
        IP→device binding is still current.  Storing it denormalised
        means future DHCP reassignments cannot corrupt the historical record.
        """
        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    SELECT id, user_id, mac_address FROM devices
                    WHERE ip_address = %s
                    LIMIT 1
                """, (client_ip,))
                row = cur.fetchone()
                if row:
                    return row[0], row[1], row[2]
        except Exception as e:
            logger.debug("Device lookup failed for %s: %s", client_ip, e)
            try:
                self.db_conn.rollback()
            except:
                pass
        return None, None, None

    def poll_pihole_blocked(self):
        """
        Poll Pi-Hole /api/queries for newly blocked queries and store them.
        Uses pihole_query_id as a cursor so restarts never double-count.
        """
        if not PIHOLE_PASSWORD:
            return

        now = time.time()
        if now - self._pihole_last_poll < PIHOLE_POLL_INTERVAL_SECONDS:
            return
        self._pihole_last_poll = now

        # Fetch up to 500 recent queries; we'll filter server-side
        data = self._pihole_get('/api/queries?limit=500')
        if not data:
            return

        queries = data.get('queries', [])
        if not queries:
            return

        new_rows = 0
        for q in reversed(queries):  # oldest-first so cursor advances correctly
            qid = q.get('id')
            if qid is None:
                continue
            if self._pihole_last_cursor and qid <= self._pihole_last_cursor:
                continue
            if q.get('status') not in PIHOLE_BLOCKED_STATUSES:
                continue

            domain = q.get('domain', '')
            client_ip = (q.get('client') or {}).get('ip', '')
            if not domain or not client_ip:
                continue

            blocked_at = datetime.fromtimestamp(q['time'])
            query_type = q.get('type', 'A')
            status = q.get('status', '')
            list_id = q.get('list_id')

            device_id, user_id, mac_address = self._resolve_client(client_ip)

            try:
                with self.db_conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO pihole_blocked_queries
                            (pihole_query_id, blocked_at, domain, query_type,
                             status, client_ip, mac_address, device_id, user_id, list_id)
                        VALUES (%s, %s, %s, %s, %s, %s::inet, %s, %s, %s, %s)
                        ON CONFLICT (pihole_query_id) DO NOTHING
                    """, (qid, blocked_at, domain, query_type,
                          status, client_ip, mac_address, device_id, user_id, list_id))
                self.db_conn.commit()
                self._pihole_last_cursor = qid
                new_rows += 1
            except Exception as e:
                logger.error("Failed to insert blocked query id=%s: %s", qid, e)
                try:
                    self.db_conn.rollback()
                except:
                    pass

        if new_rows:
            logger.info("Pi-Hole: stored %d new blocked queries (cursor=%s)",
                        new_rows, self._pihole_last_cursor)

    def run(self):
        """Main loop"""
        logger.info("DNS Parser Service starting...")
        
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
        
        # Load Pi-Hole poll cursor (resume from last seen query id)
        self._load_pihole_cursor()
        if PIHOLE_PASSWORD:
            self._pihole_authenticate()

        logger.info(f"Monitoring log file: {LOG_FILE}")
        logger.info(f"Deduplication threshold: {DEDUP_THRESHOLD_HOURS} hours")
        logger.info(f"DNS retention: {RETENTION_DAYS} days")
        logger.info(f"Pi-Hole polling: {'enabled' if PIHOLE_PASSWORD else 'disabled (PIHOLE_WEBPASSWORD not set)'}")
        
        try:
            while True:
                # Process new log entries
                self.process_log_file()
                
                # Cleanup old resolutions (runs once per day)
                self.cleanup_old_resolutions()

                # Poll Pi-Hole for blocked queries
                self.poll_pihole_blocked()
                
                # Sleep before next check
                time.sleep(CHECK_INTERVAL_SECONDS)
        
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.db_conn:
                self.db_conn.close()
            logger.info("DNS Parser Service stopped")


if __name__ == "__main__":
    parser = DNSParser()
    parser.run()
