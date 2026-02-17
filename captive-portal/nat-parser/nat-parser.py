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
import logging
import psycopg2
import subprocess
from datetime import datetime, timedelta
from typing import Optional, Tuple
from pathlib import Path

# Configuration from environment
LOG_FILE = os.getenv("LOG_FILE", "/logs/remote-syslog.log")
DB_URL = os.getenv("DATABASE_URL", "postgresql://portal_user:change_this_password@127.0.0.1:5432/captive_portal")

UDM_HOST = os.getenv("UDM_HOST", "192.168.1.1")
UDM_SSH_KEY = os.getenv("UDM_SSH_KEY", "/config/udm_key")
UDM_INSTALL_SCRIPT = os.getenv("UDM_INSTALL_SCRIPT", "/scripts/udm-nat-logger-persist.sh")

SESSION_GAP_SECONDS = int(os.getenv("SESSION_GAP_SECONDS", "60"))
STALE_LOG_THRESHOLD_SECONDS = int(os.getenv("STALE_LOG_THRESHOLD_SECONDS", "3600"))
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "5"))
REINSTALL_COOLDOWN_SECONDS = int(os.getenv("REINSTALL_COOLDOWN_SECONDS", "300"))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nat-parser')


class NATParser:
    def __init__(self):
        self.db_conn = None
        self.last_position = 0
        self.last_log_timestamp = None
        self.last_reinstall_attempt = None
        self.active_sessions = {}  # (src_ip, src_port, dst_ip, dst_port) -> session_data
        
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
    
    def _close_session(self, session_key, session):
        """Close a session and write to database"""
        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO nat_sessions 
                    (src_ip, src_port, dst_ip, dst_port, session_start, session_end, packet_count)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    session['src_ip'],
                    session['src_port'],
                    session['dst_ip'],
                    session['dst_port'],
                    session['start'],
                    session['last_seen'],
                    session['packet_count']
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
    
    def process_log_file(self):
        """Process new entries from log file"""
        try:
            if not os.path.exists(LOG_FILE):
                logger.warning(f"Log file not found: {LOG_FILE}")
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
                    
                    result = self.parse_nat_line(line)
                    if result:
                        timestamp, src_ip, src_port, dst_ip, dst_port = result
                        self.process_nat_entry(timestamp, src_ip, src_port, dst_ip, dst_port)
                        self.last_log_timestamp = datetime.now()
                
                self.last_position = f.tell()
        
        except Exception as e:
            logger.error(f"Error processing log file: {e}")
    
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
        """Attempt to reinstall NAT logger on UDM"""
        logger.info("Attempting to reinstall NAT logger on UDM...")
        self.last_reinstall_attempt = datetime.now()
        
        try:
            # Check if SSH key exists
            if not os.path.exists(UDM_SSH_KEY):
                logger.warning(f"SSH key not found: {UDM_SSH_KEY} - skipping reinstall")
                return
            
            # Check if install script exists
            if not os.path.exists(UDM_INSTALL_SCRIPT):
                logger.warning(f"Install script not found: {UDM_INSTALL_SCRIPT} - skipping reinstall")
                return
            
            # Copy script to UDM
            logger.info(f"Copying script to UDM {UDM_HOST}...")
            scp_cmd = [
                "scp",
                "-i", UDM_SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                UDM_INSTALL_SCRIPT,
                f"root@{UDM_HOST}:/tmp/udm-nat-logger-persist.sh"
            ]
            
            result = subprocess.run(scp_cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"SCP failed: {result.stderr.decode()}")
                return
            
            # Execute script on UDM
            logger.info("Executing install script on UDM...")
            ssh_cmd = [
                "ssh",
                "-i", UDM_SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                f"root@{UDM_HOST}",
                "bash /tmp/udm-nat-logger-persist.sh"
            ]
            
            result = subprocess.run(ssh_cmd, capture_output=True, timeout=60)
            if result.returncode == 0:
                logger.info("Successfully reinstalled NAT logger on UDM")
                logger.debug(result.stdout.decode())
            else:
                logger.error(f"Install script failed: {result.stderr.decode()}")
        
        except subprocess.TimeoutExpired:
            logger.error("UDM connection timed out - device may be unreachable")
        except Exception as e:
            logger.error(f"Reinstall attempt failed: {e}")
    
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
        
        try:
            while True:
                # Process new log entries
                self.process_log_file()
                
                # Close stale sessions
                self.close_stale_sessions()
                
                # Check log freshness
                self.check_log_freshness()
                
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
