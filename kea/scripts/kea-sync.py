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
import json
import time
import logging
import requests
import psycopg2
from datetime import datetime, timedelta
from typing import Dict, List, Optional

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
            dns_servers = f"192.168.{subnet_id}.4"
        
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
        """Synchronize all devices with Kea"""
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
