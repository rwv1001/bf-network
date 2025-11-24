"""
Kea DHCP Integration Module

Manages host reservations in Kea DHCP server for three-pool MAC-based assignment:
1. Registered pool (.5-.127, 24h lease): Devices with approved registrations
2. Newly unregistered pool (.128-.191, 60s lease): First seen <30 min ago
3. Old unregistered pool (.192-.254, 24h lease): First seen >30 min ago

Supports both control socket and HTTP API communication.
"""

import json
import socket
import requests
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class KeaIntegration:
    """Interface to Kea DHCP server for managing host reservations."""
    
    def __init__(self, control_socket: Optional[str] = None, api_url: Optional[str] = None):
        """
        Initialize Kea integration.
        
        Args:
            control_socket: Path to Kea control socket (e.g., /kea/kea-dhcp4.sock)
            api_url: URL to Kea HTTP API (e.g., http://localhost:8000)
        """
        self.control_socket = control_socket
        self.api_url = api_url
        
        if not control_socket and not api_url:
            raise ValueError("Either control_socket or api_url must be provided")
    
    def _send_command_socket(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send command to Kea via control socket.
        
        Args:
            command: Kea command dictionary
            
        Returns:
            Response dictionary from Kea
        """
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.control_socket)
            
            message = json.dumps(command)
            sock.sendall(message.encode())
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            
            return json.loads(response.decode())
        
        except Exception as e:
            logger.error(f"Error communicating with Kea socket: {e}")
            raise
    
    def _send_command_http(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send command to Kea via HTTP API.
        
        Args:
            command: Kea command dictionary
            
        Returns:
            Response dictionary from Kea
        """
        try:
            response = requests.post(
                self.api_url,
                json=command,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        
        except Exception as e:
            logger.error(f"Error communicating with Kea HTTP API: {e}")
            raise
    
    def _send_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send command to Kea using configured method.
        
        Args:
            command: Kea command dictionary
            
        Returns:
            Response dictionary from Kea
        """
        if self.control_socket:
            return self._send_command_socket(command)
        else:
            return self._send_command_http(command)
    
    def register_mac(
        self,
        mac: str,
        vlan: int,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Register a MAC address in Kea for the registered IP pool.
        
        Creates a host reservation with user-context marking it as registered.
        Client class expressions in Kea config will evaluate this and assign
        the device to the registered pool (.5-.127) with 24h lease and public DNS.
        
        Args:
            mac: MAC address (format: aa:bb:cc:dd:ee:ff)
            vlan: VLAN number (e.g., 40 for 192.168.40.0/24)
            hostname: Optional hostname for the device
            ip_address: Optional specific IP to reserve (must be in registered pool .5-.127)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Normalize MAC address
            mac = mac.lower().replace('-', ':')
            
            # Build subnet identifier
            subnet_id = vlan  # Assuming subnet ID matches VLAN
            
            # Build reservation with user-context for client class evaluation
            reservation = {
                "subnet-id": subnet_id,
                "hw-address": mac,
                "user-context": {
                    "registered": True,
                    "registered-at": datetime.utcnow().isoformat()
                }
            }
            
            if hostname:
                reservation["hostname"] = hostname
            
            # Don't assign a specific IP - let the hook select the correct subnet
            # and Kea will assign any available IP from that subnet's pool.
            # This avoids NAK issues when switching from unregistered to registered subnet.
            if ip_address:
                # Only set IP if explicitly provided (for manual assignments)
                # Validate IP is in registered pool range (.5-.127)
                ip_parts = ip_address.split('.')
                if len(ip_parts) == 4:
                    last_octet = int(ip_parts[3])
                    if not (5 <= last_octet <= 127):
                        logger.error(f"IP {ip_address} not in registered pool range (.5-.127)")
                        return False
                reservation["ip-address"] = ip_address
                logger.info(f"Assigning specific IP {ip_address} to MAC {mac}")
            else:
                logger.info(f"Creating reservation for MAC {mac} without specific IP - Kea will assign from pool")
            
            # Build command
            command = {
                "command": "reservation-add",
                "service": ["dhcp4"],
                "arguments": {
                    "reservation": reservation
                }
            }
            
            response = self._send_command(command)
            
            # Check response
            if response.get("result") == 0:
                logger.info(f"Successfully registered MAC {mac} in VLAN {vlan} (registered pool)")
                return True
            else:
                error_text = response.get('text', '')
                # Treat duplicate entry as success - reservation already exists
                if 'duplicate' in error_text.lower() or 'already exists' in error_text.lower():
                    logger.info(f"MAC {mac} already registered in VLAN {vlan} (duplicate is OK)")
                    return True
                else:
                    logger.error(f"Failed to register MAC {mac}: {error_text}")
                    return False
        
        except Exception as e:
            logger.error(f"Error registering MAC {mac}: {e}")
            return False
    
    def unregister_mac(self, mac: str, vlan: int) -> bool:
        """
        Unregister a MAC address from Kea.
        
        Removes the host reservation, causing the device to fall back to
        the unregistered IP pool with restricted DNS.
        
        Args:
            mac: MAC address (format: aa:bb:cc:dd:ee:ff)
            vlan: VLAN number
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Normalize MAC address
            mac = mac.lower().replace('-', ':')
            
            subnet_id = vlan
            
            # Build command
            command = {
                "command": "reservation-del",
                "service": ["dhcp4"],
                "arguments": {
                    "subnet-id": subnet_id,
                    "identifier-type": "hw-address",
                    "identifier": mac
                }
            }
            
            response = self._send_command(command)
            
            # Check response (0 = success, 3 = not found is also ok)
            if response.get("result") in [0, 3]:
                logger.info(f"Successfully unregistered MAC {mac} from VLAN {vlan}")
                return True
            else:
                logger.error(f"Failed to unregister MAC {mac}: {response.get('text')}")
                return False
        
        except Exception as e:
            logger.error(f"Error unregistering MAC {mac}: {e}")
            return False
    
    def get_reservation(self, mac: str, vlan: int) -> Optional[Dict[str, Any]]:
        """
        Get reservation details for a MAC address.
        
        Args:
            mac: MAC address
            vlan: VLAN number
            
        Returns:
            Reservation dictionary or None if not found
        """
        try:
            mac = mac.lower().replace('-', ':')
            subnet_id = vlan
            
            command = {
                "command": "reservation-get",
                "service": ["dhcp4"],
                "arguments": {
                    "subnet-id": subnet_id,
                    "identifier-type": "hw-address",
                    "identifier": mac
                }
            }
            
            response = self._send_command(command)
            
            if response.get("result") == 0:
                return response.get("arguments")
            else:
                return None
        
        except Exception as e:
            logger.error(f"Error getting reservation for MAC {mac}: {e}")
            return None
    
    def get_all_reservations(self, vlan: int) -> List[Dict[str, Any]]:
        """
        Get all reservations for a VLAN.
        
        Args:
            vlan: VLAN number
            
        Returns:
            List of reservation dictionaries
        """
        try:
            subnet_id = vlan
            
            command = {
                "command": "reservation-get-all",
                "service": ["dhcp4"],
                "arguments": {
                    "subnet-id": subnet_id
                }
            }
            
            response = self._send_command(command)
            
            if response.get("result") == 0:
                return response.get("arguments", {}).get("reservations", [])
            else:
                return []
        
        except Exception as e:
            logger.error(f"Error getting all reservations for VLAN {vlan}: {e}")
            return []
    
    def _find_available_registered_ip(self, subnet_id: int) -> Optional[str]:
        """
        Find an available IP in the registered pool (.5-.127) for the subnet.
        
        Args:
            subnet_id: Subnet ID (e.g., 10 for 192.168.10.0/24)
            
        Returns:
            Available IP address or None if pool is full
        """
        try:
            # Build base IP from subnet_id (assumes 192.168.X.0/24 format)
            base_ip = f"192.168.{subnet_id}"
            
            # Get all current leases and reservations
            command = {
                "command": "lease4-get-all",
                "service": ["dhcp4"],
                "arguments": {
                    "subnets": [subnet_id]
                }
            }
            
            response = self._send_command(command)
            used_ips = set()
            
            if response.get("result") == 0:
                leases = response.get("arguments", {}).get("leases", [])
                for lease in leases:
                    used_ips.add(lease.get("ip-address"))
            
            # Get all reservations for this subnet
            reservations = self.get_all_reservations(subnet_id)
            for res in reservations:
                if "ip-address" in res:
                    used_ips.add(res["ip-address"])
            
            # Find first available IP in registered pool (.5-.127)
            for last_octet in range(5, 128):
                candidate_ip = f"{base_ip}.{last_octet}"
                if candidate_ip not in used_ips:
                    return candidate_ip
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding available IP: {e}")
            return None
    
    def get_lease(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get current lease information for an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Lease dictionary or None if not found
        """
        try:
            command = {
                "command": "lease4-get",
                "service": ["dhcp4"],
                "arguments": {
                    "ip-address": ip
                }
            }
            
            response = self._send_command(command)
            
            if response.get("result") == 0:
                return response.get("arguments")
            else:
                return None
        
        except Exception as e:
            logger.error(f"Error getting lease for IP {ip}: {e}")
            return None
    
    def get_lease_by_mac(self, mac: str) -> Optional[Dict[str, Any]]:
        """
        Get current lease information for a MAC address.
        
        Args:
            mac: MAC address
            
        Returns:
            Lease dictionary or None if not found
        """
        try:
            mac = mac.lower().replace('-', ':')
            
            command = {
                "command": "lease4-get",
                "service": ["dhcp4"],
                "arguments": {
                    "identifier-type": "hw-address",
                    "identifier": mac
                }
            }
            
            response = self._send_command(command)
            
            if response.get("result") == 0:
                return response.get("arguments")
            else:
                return None
        
        except Exception as e:
            logger.error(f"Error getting lease for MAC {mac}: {e}")
            return None
    
    def force_lease_renewal(self, mac: str, ip_address: Optional[str] = None) -> bool:
        """
        Force a lease to expire, triggering renewal on next request.
        
        Args:
            mac: MAC address
            ip_address: Optional IP address. If not provided, will try to look it up
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # If IP not provided, try to get it from lease
            if not ip_address:
                lease = self.get_lease_by_mac(mac)
                if not lease:
                    logger.warning(f"No active lease found for MAC {mac}")
                    return False
                ip_address = lease.get("ip-address")
            
            if not ip_address:
                logger.error(f"No IP address available for MAC {mac}")
                return False
            
            # Delete the lease by IP (with subnet-id for memfile backend)
            # Extract subnet ID from IP's third octet (e.g., 192.168.10.x -> subnet 10)
            subnet_id = int(ip_address.split('.')[2])
            
            command = {
                "command": "lease4-del",
                "service": ["dhcp4"],
                "arguments": {
                    "ip-address": ip_address,
                    "subnet-id": subnet_id
                }
            }
            
            logger.info(f"Sending lease4-del command: {command}")
            response = self._send_command(command)
            logger.info(f"lease4-del response: {response}")
            
            if response.get("result") == 0:
                logger.info(f"Successfully deleted lease for MAC {mac}, IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to delete lease: {response.get('text')}")
                return False
        
        except Exception as e:
            logger.error(f"Error forcing lease renewal for MAC {mac}: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get Kea DHCP statistics.
        
        Returns:
            Statistics dictionary
        """
        try:
            command = {
                "command": "statistic-get-all",
                "service": ["dhcp4"]
            }
            
            response = self._send_command(command)
            
            if response.get("result") == 0:
                return response.get("arguments", {})
            else:
                return {}
        
        except Exception as e:
            logger.error(f"Error getting Kea stats: {e}")
            return {}


# Helper function for easy integration
def get_kea_client(control_socket: Optional[str] = None, api_url: Optional[str] = None) -> KeaIntegration:
    """
    Factory function to create a Kea integration client.
    
    Args:
        control_socket: Path to Kea control socket
        api_url: URL to Kea HTTP API
        
    Returns:
        KeaIntegration instance
    """
    return KeaIntegration(control_socket=control_socket, api_url=api_url)
