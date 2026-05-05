#!/usr/bin/env python3
"""
Kea Pool Assignment Synchronizer

Runs periodically to sync device registrations from PostgreSQL to Kea DHCP reservations.
This ensures newly registered devices get moved to the correct pool on their next DHCP renewal.

The three-pool strategy:
1. Registered (.5-.127, 24h): Devices with approved registration
2. Newly Unregistered (.128-.191, 60s): Unregistered devices first seen <30 min
3. Old Unregistered (.192-.254, 24h): Unregistered devices first seen >30 min
"""

import os
import sys
import re
import json
import time
import logging
import requests
import psycopg2
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '127.0.0.1'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('POSTGRES_DB', 'captive_portal'),
    'user': os.getenv('POSTGRES_USER', 'captive_user'),
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

KEA_CONTROL_SOCKET = os.getenv('KEA_CONTROL_SOCKET', '/tmp/kea-dhcp4.sock')
SYNC_INTERVAL = int(os.getenv('SYNC_INTERVAL', '60'))  # seconds

# Switch configuration for port lookup
SWITCH_HOST     = next(iter(os.getenv('SWITCH_HOSTS', '').split()), '')
SWITCH_USER     = os.getenv('SWITCH_USER', 'admin')
SWITCH_KEY_PATH = os.getenv('SWITCH_KEY_PATH', '/keys/id_rsa')
SWITCH_PASS     = os.getenv('SWITCH_PASS', '')
SWITCH_SSH_PORT = int(os.getenv('SWITCH_SSH_PORT', '22'))
SWITCH_PORT_SYNC_ENABLED = os.getenv('SWITCH_PORT_SYNC_ENABLED', '1') not in ('0', 'false', 'no')
SWITCH_REPLUG_DENY_PATTERN   = os.getenv('SWITCH_REPLUG_DENY_PATTERN', '')
SWITCH_REPLUG_ALLOWED_PREFIXES = os.getenv('SWITCH_REPLUG_ALLOWED_PREFIXES', 'GigabitEthernet,GE')

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('kea-sync')


class KeaSync:
    """Synchronizes device registrations with Kea DHCP"""
    
    def __init__(self):
        self.db_conn = None
        self.connect_db()
    
    def connect_db(self):
        """Establish database connection"""
        try:
            self.db_conn = psycopg2.connect(**DB_CONFIG)
            logger.info("Connected to PostgreSQL database")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            sys.exit(1)
    
    def send_kea_command(self, command: Dict) -> Optional[Dict]:
        """
        Send command to Kea via control socket
        
        Args:
            command: Kea command dictionary
            
        Returns:
            Response dictionary or None on error
        """
        try:
            import socket as sock_module
            
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
            s.connect(KEA_CONTROL_SOCKET)
            
            message = json.dumps(command)
            s.sendall(message.encode())
            
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            s.close()
            
            result = json.loads(response.decode())
            return result[0] if isinstance(result, list) else result
            
        except Exception as e:
            logger.error(f"Error communicating with Kea: {e}")
            return None
    
    def get_devices_needing_update(self) -> List[Dict]:
        """
        Query database for devices that need DHCP pool updates
        
        Returns:
            List of device dictionaries with MAC, status, first_seen, current_vlan
        """
        try:
            cursor = self.db_conn.cursor()
            
            query = """
                SELECT 
                    mac_address,
                    registration_status,
                    first_seen,
                    current_vlan,
                    EXTRACT(EPOCH FROM (NOW() - first_seen)) AS age_seconds
                FROM devices
                WHERE mac_address IS NOT NULL
                ORDER BY first_seen DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            devices = []
            for row in rows:
                devices.append({
                    'mac': row[0],
                    'status': row[1],
                    'first_seen': row[2],
                    'vlan': row[3] or 99,  # Default to VLAN 99 if not set
                    'age_seconds': float(row[4]) if row[4] else 0
                })
            
            cursor.close()
            return devices
            
        except Exception as e:
            logger.error(f"Error querying database: {e}")
            return []
    
    def determine_pool(self, device: Dict) -> str:
        """
        Determine which pool a device should be in
        
        Args:
            device: Device dictionary with status and age_seconds
            
        Returns:
            Pool name: 'registered', 'newly_unregistered', or 'old_unregistered'
        """
        if device['status'] == 'approved':
            return 'registered'
        
        # 30 minutes = 1800 seconds
        if device['age_seconds'] < 1800:
            return 'newly_unregistered'
        else:
            return 'old_unregistered'
    
    def get_existing_reservation(self, mac: str, subnet_id: int) -> Optional[Dict]:
        """Get existing Kea reservation for a MAC"""
        command = {
            "command": "reservation-get",
            "service": ["dhcp4"],
            "arguments": {
                "subnet-id": subnet_id,
                "identifier-type": "hw-address",
                "identifier": mac
            }
        }
        
        response = self.send_kea_command(command)
        
        if response and response.get('result') == 0:
            return response.get('arguments', {})
        return None
    
    def add_reservation(self, mac: str, subnet_id: int, pool: str, hostname: str = None) -> bool:
        """
        Add a host reservation in Kea
        
        Args:
            mac: MAC address (normalized to aa:bb:cc:dd:ee:ff)
            subnet_id: Subnet ID (matches VLAN)
            pool: Pool type ('registered', 'newly_unregistered', 'old_unregistered')
            hostname: Optional hostname
            
        Returns:
            True if successful
        """
        # Determine client class and DNS based on pool
        if pool == 'registered':
            client_class = "REGISTERED"
            dns_servers = "8.8.8.8, 8.8.4.4"
        else:
            # Both unregistered pools use portal DNS
            client_class = "NEWLY_UNREGISTERED" if pool == 'newly_unregistered' else "OLD_UNREGISTERED"
            dns_servers = os.getenv('HIJACK_DNS_IP', os.getenv('PORTAL_IP', ''))
        
        reservation = {
            "hw-address": mac,
            "client-classes": [client_class]
        }
        
        if hostname:
            reservation["hostname"] = hostname
        
        # Add DNS override for unregistered devices
        if pool != 'registered':
            reservation["option-data"] = [
                {
                    "name": "domain-name-servers",
                    "data": dns_servers
                }
            ]
        
        command = {
            "command": "reservation-add",
            "service": ["dhcp4"],
            "arguments": {
                "reservation": reservation,
                "subnet-id": subnet_id
            }
        }
        
        response = self.send_kea_command(command)
        
        if response and response.get('result') == 0:
            logger.info(f"Added reservation: {mac} -> {pool} (VLAN {subnet_id})")
            return True
        else:
            # Result 1 might mean duplicate - that's okay
            if response and response.get('result') == 1:
                logger.debug(f"Reservation already exists: {mac}")
                return True
            logger.error(f"Failed to add reservation for {mac}: {response}")
            return False
    
    def remove_reservation(self, mac: str, subnet_id: int) -> bool:
        """Remove a host reservation from Kea"""
        command = {
            "command": "reservation-del",
            "service": ["dhcp4"],
            "arguments": {
                "subnet-id": subnet_id,
                "identifier-type": "hw-address",
                "identifier": mac
            }
        }
        
        response = self.send_kea_command(command)
        
        # Result 0 = deleted, 3 = not found (both okay)
        if response and response.get('result') in [0, 3]:
            logger.info(f"Removed reservation: {mac} (VLAN {subnet_id})")
            return True
        else:
            logger.error(f"Failed to remove reservation for {mac}: {response}")
            return False
    
    def sync_device(self, device: Dict) -> bool:
        """
        Synchronize a single device with Kea
        
        Args:
            device: Device dictionary
            
        Returns:
            True if sync successful
        """
        mac = device['mac'].lower().replace('-', ':')
        subnet_id = device['vlan']
        pool = self.determine_pool(device)
        
        # Check if we need to update
        existing = self.get_existing_reservation(mac, subnet_id)
        
        if pool == 'registered':
            # Registered devices need a reservation
            if not existing:
                hostname = f"device-{mac.replace(':', '')}"
                return self.add_reservation(mac, subnet_id, pool, hostname)
            else:
                # Check if client class needs update
                current_classes = existing.get('client-classes', [])
                if 'REGISTERED' not in current_classes:
                    # Remove old reservation and add new one
                    self.remove_reservation(mac, subnet_id)
                    hostname = existing.get('hostname', f"device-{mac.replace(':', '')}")
                    return self.add_reservation(mac, subnet_id, pool, hostname)
                return True  # Already correct
        else:
            # Unregistered devices don't need reservations (use default pools)
            # But we can still add them to track pool assignment
            if existing:
                # Check if needs client class update
                current_classes = existing.get('client-classes', [])
                expected_class = "NEWLY_UNREGISTERED" if pool == 'newly_unregistered' else "OLD_UNREGISTERED"
                
                if expected_class not in current_classes:
                    # Update by removing and re-adding
                    self.remove_reservation(mac, subnet_id)
                    return self.add_reservation(mac, subnet_id, pool)
            # No action needed for unregistered without reservation
            return True
    
    def sync_all(self):
        """Synchronize all devices with Kea, then update switch port mappings."""
        logger.info("Starting synchronization...")

        devices = self.get_devices_needing_update()
        logger.info(f"Found {len(devices)} devices to process")

        success_count = 0
        for device in devices:
            try:
                if self.sync_device(device):
                    success_count += 1
            except Exception as e:
                logger.error(f"Error syncing device {device['mac']}: {e}")

        logger.info(f"Synchronization complete: {success_count}/{len(devices)} successful")

        if SWITCH_PORT_SYNC_ENABLED and SWITCH_HOST:
            self.sync_switch_ports()
        elif SWITCH_PORT_SYNC_ENABLED and not SWITCH_HOST:
            logger.debug("Switch port sync skipped: SWITCH_HOSTS not configured")

    # ------------------------------------------------------------------
    # Switch port mapping
    # ------------------------------------------------------------------

    def _switch_port_allowed(self, iface: str) -> bool:
        if SWITCH_REPLUG_DENY_PATTERN and re.search(SWITCH_REPLUG_DENY_PATTERN, iface):
            return False
        allowed = [p.strip() for p in SWITCH_REPLUG_ALLOWED_PREFIXES.split(',') if p.strip()]
        if not allowed:
            return True
        return any(iface.startswith(p) for p in allowed)

    def _expand_iface(self, iface: str) -> str:
        if iface.startswith('GE') and not iface.startswith('GigabitEthernet'):
            return 'GigabitEthernet' + iface[2:]
        if iface.startswith('XGE') and not iface.startswith('Ten-GigabitEthernet'):
            return 'Ten-GigabitEthernet' + iface[3:]
        return iface

    def _normalize_to_colon(self, raw: str) -> Optional[str]:
        cleaned = re.sub(r'[^0-9a-fA-F]', '', raw).lower()
        if len(cleaned) != 12:
            return None
        return ':'.join(cleaned[i:i+2] for i in range(0, 12, 2))

    def _fetch_switch_mac_table(self) -> str:
        """SSH to the switch and return raw 'display mac-address' output."""
        try:
            import paramiko
        except ImportError:
            logger.warning("paramiko not installed; switch port sync disabled")
            return ''

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=SWITCH_HOST,
            port=SWITCH_SSH_PORT,
            username=SWITCH_USER,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            disabled_algorithms={'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']},
        )
        if SWITCH_KEY_PATH and os.path.isfile(SWITCH_KEY_PATH):
            kwargs['key_filename'] = SWITCH_KEY_PATH
        elif SWITCH_PASS:
            kwargs['password'] = SWITCH_PASS
        else:
            logger.warning("Switch port sync: no key or password configured")
            return ''
        try:
            client.connect(**kwargs)
            chan = client.invoke_shell()
            time.sleep(0.5)
            if chan.recv_ready():
                chan.recv(65535)  # drain banner
            chan.send('display mac-address\n')
            buf = ''
            deadline = time.time() + 10
            while time.time() < deadline:
                if chan.recv_ready():
                    chunk = chan.recv(65535).decode('utf-8', errors='ignore')
                    buf += chunk
                    while '---- More ----' in buf or '-- More --' in buf:
                        chan.send(' ')
                        time.sleep(0.5)
                        if chan.recv_ready():
                            buf += chan.recv(65535).decode('utf-8', errors='ignore')
                else:
                    time.sleep(0.3)
            chan.close()
            return buf
        except Exception as exc:
            logger.warning("Switch MAC table fetch failed: %s", exc)
            return ''
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _parse_switch_mac_table(self, output: str) -> List[Dict]:
        """Parse 'display mac-address' output into list of {mac_colon, switch_iface, vlan_id}."""
        iface_re = re.compile(
            r'\b(?P<iface>(?:GigabitEthernet|Ten-GigabitEthernet|GE|XGE|Ethernet|Bridge-Aggregation)\S+)\b',
            re.IGNORECASE,
        )
        mac_re  = re.compile(r'\b([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\b', re.IGNORECASE)
        vlan_re = re.compile(r'\b(\d{1,4})\b')
        entries = []
        for line in output.splitlines():
            line = line.strip()
            mm = mac_re.search(line)
            im = iface_re.search(line)
            if not mm or not im:
                continue
            mac_colon = self._normalize_to_colon(mm.group(1))
            if not mac_colon:
                continue
            iface = self._expand_iface(im.group('iface'))
            if not self._switch_port_allowed(iface):
                continue
            stripped = mac_re.sub('', iface_re.sub('', line))
            vlan_id = None
            vm = vlan_re.search(stripped)
            if vm:
                cand = int(vm.group(1))
                if 1 <= cand <= 4094:
                    vlan_id = cand
            entries.append({'mac_colon': mac_colon, 'switch_iface': iface, 'vlan_id': vlan_id})
        return entries

    def sync_switch_ports(self):
        """Fetch full switch MAC table and update mac_port_cache + devices.switch_iface."""
        logger.info("Switch port sync: fetching MAC table from %s", SWITCH_HOST)
        raw = self._fetch_switch_mac_table()
        if not raw:
            logger.warning("Switch port sync: empty output, skipping")
            return
        entries = self._parse_switch_mac_table(raw)
        logger.info("Switch port sync: parsed %d entries", len(entries))
        if not entries:
            return
        try:
            cur = self.db_conn.cursor()
            upsert_cache = """
                INSERT INTO mac_port_cache (mac_address, switch_iface, switch_host, vlan_id, last_seen)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (mac_address) DO UPDATE SET
                    switch_iface = EXCLUDED.switch_iface,
                    switch_host  = EXCLUDED.switch_host,
                    vlan_id      = EXCLUDED.vlan_id,
                    last_seen    = EXCLUDED.last_seen
            """
            update_device = """
                UPDATE devices
                SET switch_iface = %s, switch_iface_seen_at = NOW()
                WHERE mac_address = %s
            """
            cache_rows  = [(e['mac_colon'], e['switch_iface'], SWITCH_HOST, e['vlan_id']) for e in entries]
            device_rows = [(e['switch_iface'], e['mac_colon']) for e in entries]
            cur.executemany(upsert_cache, cache_rows)
            cur.executemany(update_device, device_rows)
            self.db_conn.commit()
            logger.info("Switch port sync: upserted %d cache rows", len(entries))
        except Exception as exc:
            logger.error("Switch port sync DB update failed: %s", exc)
            try:
                self.db_conn.rollback()
            except Exception:
                pass
    
    def run(self):
        """Main loop"""
        logger.info(f"Starting Kea sync service (interval: {SYNC_INTERVAL}s)")
        
        while True:
            try:
                self.sync_all()
                time.sleep(SYNC_INTERVAL)
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(SYNC_INTERVAL)
        
        if self.db_conn:
            self.db_conn.close()


if __name__ == '__main__':
    sync = KeaSync()
    sync.run()
