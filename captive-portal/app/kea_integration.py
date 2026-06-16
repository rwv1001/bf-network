"""
Kea DHCP Integration Module

Manages host reservations in Kea DHCP server for three-pool MAC-based assignment:
1. Registered pool (size depends on subnet prefix): Devices with approved registrations
2. Newly unregistered pool (short lease): First seen <30 min ago
3. Old unregistered pool (long lease): First seen >30 min ago

Supports both control socket and HTTP API communication.
"""

import json
import ipaddress
import socket
import requests
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')





def _parse_vlan_prefix_map(raw: str) -> Dict[int, int]:
    mapping: Dict[int, int] = {}
    if not raw:
        return mapping
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry or ':' not in entry:
            continue
        vlan_str, prefix_str = entry.split(':', 1)
        try:
            vlan_id = int(vlan_str.strip())
            prefix = int(prefix_str.strip())
        except ValueError:
            continue
        if prefix not in {24, 23, 22, 21}:
            continue
        mapping[vlan_id] = prefix
    return mapping


def _pool_bounds_for_prefix(prefix: int) -> Dict[str, int]:
    total = 2 ** (32 - prefix)
    block_size = 40 * (2 ** (24 - prefix))
    # Always start the pool at offset 1 (offset 0 is the network address and
    # Kea never allocates it). Infrastructure IPs are protected by ghost host
    # reservations baked into dhcp4.json by generate-kea-config.py.
    registered_start = 1
    registered_end = total - block_size - 1
    blocked_start = registered_end + 1
    blocked_end = total - 1
    return {
        "registered_start": registered_start,
        "registered_end": registered_end,
        "blocked_start": blocked_start,
        "blocked_end": blocked_end,
    }


def _prefix_for_vlan(vlan_id: int) -> int:
    env_map = _parse_vlan_prefix_map(os.getenv('VLAN_PREFIX_MAP', ''))
    if vlan_id in env_map:
        return env_map[vlan_id]

    config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    if os.path.isfile(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
            for subnet in data.get('Dhcp4', {}).get('subnet4', []):
                try:
                    if int(subnet.get('id')) == int(vlan_id):
                        network = ipaddress.ip_network(subnet.get('subnet'), strict=False)
                        return network.prefixlen
                except Exception:
                    continue
        except Exception:
            pass

    return 24


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

    def _resolve_subnet_id(self, vlan_or_subnet_id: int) -> int:
        """Map VLAN to Kea subnet-id via VLAN_SUBNET_ID_MAP env if provided."""
        raw = os.getenv('VLAN_SUBNET_ID_MAP', '').strip()
        if not raw:
            return vlan_or_subnet_id
        mapping = {}
        for entry in raw.split(','):
            entry = entry.strip()
            if not entry or ':' not in entry:
                continue
            vlan_str, subnet_str = entry.split(':', 1)
            try:
                vlan_id = int(vlan_str.strip())
                subnet_id = int(subnet_str.strip())
            except ValueError:
                continue
            mapping[vlan_id] = subnet_id
        return mapping.get(vlan_or_subnet_id, vlan_or_subnet_id)
    
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
        the device to the registered pool with public DNS.
        
        Args:
            mac: MAC address (format: aa:bb:cc:dd:ee:ff)
            vlan: VLAN number (e.g., 40 for 192.168.40.0/24)
            hostname: Optional hostname for the device
            ip_address: Optional specific IP to reserve (must be in registered pool)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Normalize MAC address
            mac = mac.lower().replace('-', ':')
            
            # Build subnet identifier
            subnet_id = self._resolve_subnet_id(vlan)
            
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
                # Sanitize hostname: remove special chars, replace with dash
                import re
                sanitized = re.sub(r'[^a-z0-9-]', '-', hostname.lower())
                sanitized = re.sub(r'-+', '-', sanitized).strip('-')  # Remove multiple dashes
                reservation["hostname"] = sanitized if sanitized else "device"
            
            # Don't assign a specific IP - let the hook select the correct subnet
            # and Kea will assign any available IP from that subnet's pool.
            # This avoids NAK issues when switching from unregistered to registered subnet.
            if ip_address:
                # Only set IP if explicitly provided (for manual assignments)
                prefix = _prefix_for_vlan(vlan)
                bounds = _pool_bounds_for_prefix(prefix)
                network = ipaddress.IPv4Network(f"{_net_word()}.{vlan}.0/{prefix}", strict=False)
                try:
                    ip_value = ipaddress.IPv4Address(ip_address)
                except Exception:
                    logger.error(f"Invalid IP address: {ip_address}")
                    return False
                if ip_value not in network:
                    logger.error(f"IP {ip_address} not in VLAN {vlan} subnet {network}")
                    return False

                offset = int(ip_value) - int(network.network_address)
                if not (bounds["registered_start"] <= offset <= bounds["registered_end"]):
                    logger.error(f"IP {ip_address} not in registered pool range for VLAN {vlan}")
                    return False
                reservation["ip-address"] = ip_address
                logger.info(f"Assigning specific IP {ip_address} to MAC {mac}")
            else:
                logger.info(f"Creating reservation for MAC {mac} without specific IP - Kea will assign from pool")
            
            if ip_address:
                del_cmd = {
                    "command": "reservation-del",
                    "service": ["dhcp4"],
                    "arguments": {
                        "subnet-id": subnet_id,
                        "identifier-type": "hw-address",
                        "identifier": mac
                    }
                }
                try:
                    self._send_command(del_cmd)
                except Exception as exc:
                    logger.warning("Reservation delete failed for %s in VLAN %s: %s", mac, vlan, exc)

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
            
            subnet_id = self._resolve_subnet_id(vlan)
            
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
            
            result = response.get("result")
            text = response.get("text", "")
            # 0 = success, 3 = not found (already gone) — both are fine.
            # Kea also returns result 1 with "fatal database error or connectivity lost"
            # when the reservation doesn't exist in its current database state; treat as gone.
            if result in [0, 3] or "fatal" in text.lower() or "not found" in text.lower():
                logger.info(f"Successfully unregistered MAC {mac} from VLAN {vlan}")
                return True
            else:
                logger.error(f"Failed to unregister MAC {mac}: {text}")
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
            subnet_id = self._resolve_subnet_id(vlan)
            
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

    def get_blocked_ip_from_reservation(self, mac: str, vlan: int) -> Optional[str]:
        """
        Return blocked-ip from reservation user-context if present.
        """
        try:
            res = self.get_reservation(mac, vlan)
            if not res:
                return None
            reservation = res.get("reservation", {})
            user_context = reservation.get("user-context", {}) or {}
            blocked_ip = user_context.get("blocked-ip")
            return blocked_ip
        except Exception as e:
            logger.error(f"Error reading blocked-ip for MAC {mac}: {e}")
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
            subnet_id = self._resolve_subnet_id(vlan)
            
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

    def delete_host_reservation(self, mac_address: str) -> bool:
        """
        Delete a host reservation by MAC address.
        Uses subnet-id=0 so it removes the reservation globally (all subnets).
        """
        if not mac_address:
            return False

        mac = mac_address.lower().strip()

        cmd = {
            "command": "reservation-del",
            "arguments": {
                "subnet-id": 0,                    # 0 = global + all subnets
                "identifier-type": "hw-address",
                "identifier": mac
            }
        }

        try:
            response = self._send_command(cmd)
            result = response.get("result", -1)

            if result == 0:
                logger.info("Deleted Kea host reservation for MAC %s", mac)
                return True
            elif result == 3:
                # Kea returns result=3 when the reservation does not exist
                logger.debug("No host reservation found for MAC %s (already deleted)", mac)
                return True
            else:
                logger.warning("Failed to delete host reservation for %s: %s", mac, response)
                return False

        except Exception as exc:
            logger.warning("Exception while deleting host reservation for %s: %s", mac, exc)
            return False

    def set_block_status(
        self,
        mac: str,
        vlan: int,
        blocked: bool,
        blocked_ip: Optional[str] = None,
        keep_ip: bool = False,
        fixed_ip: Optional[str] = None,
    ) -> bool:
        """
        Set blocked status for a MAC using user-context for pool assignment.

        Args:
            mac: MAC address (format: aa:bb:cc:dd:ee:ff)
            vlan: VLAN number
            blocked: True to mark blocked, False to clear
            blocked_ip: Optional IP to remember for ACL cleanup on renewal

        Returns:
            True if successful, False otherwise
        """
        try:
            mac = mac.lower().replace('-', ':')
            subnet_id = self._resolve_subnet_id(vlan)

            existing = self.get_reservation(mac, vlan)
            reservation = {
                "subnet-id": subnet_id,
                "hw-address": mac,
                "user-context": {}
            }

            if existing:
                existing_res = existing.get("reservation", {})
                if "hostname" in existing_res:
                    reservation["hostname"] = existing_res["hostname"]
                if "ip-address" in existing_res:
                    reservation["ip-address"] = existing_res["ip-address"]
                if "client-classes" in existing_res:
                    reservation["client-classes"] = existing_res["client-classes"]

                user_context = existing_res.get("user-context", {}) or {}
                reservation["user-context"].update(user_context)

            if blocked:
                reservation["client-classes"] = ["BLOCKED"]
                reservation["user-context"]["blocked"] = True
                # Always clear any stale blocked-ip from a previous block before
                # conditionally re-setting it. Without this, if blocked_ip is None
                # (e.g. lease not yet in IPLease), the old value persists.
                reservation["user-context"].pop("blocked-ip", None)
                if blocked_ip:
                    reservation["user-context"]["blocked-ip"] = blocked_ip

                blocked_pool_ip = self._find_available_blocked_ip(vlan, subnet_id)
                if blocked_pool_ip:
                    reservation["ip-address"] = blocked_pool_ip
                else:
                    logger.error(f"Blocked pool is full for subnet {subnet_id}")
                    return False
            else:
                reservation.pop("client-classes", None)
                reservation["user-context"]["blocked"] = False
                if "blocked-ip" in reservation["user-context"]:
                    reservation["user-context"].pop("blocked-ip", None)
                if keep_ip and fixed_ip:
                    reservation["ip-address"] = fixed_ip
                if not keep_ip:
                    reservation.pop("ip-address", None)

                # Clean up any global (subnet_id=0) BLOCKED reservation that
                # central_import.py may have inserted directly into PostgreSQL.
                # Older imports used subnet_id=0; newer ones use the device's
                # actual subnet_id.  Delete both to be safe.
                try:
                    for gid in (0, subnet_id):
                        if gid == subnet_id and existing:
                            # The subnet-specific one is handled by del_cmd below.
                            continue
                        del_global = {
                            "command": "reservation-del",
                            "service": ["dhcp4"],
                            "arguments": {
                                "subnet-id": gid,
                                "identifier-type": "hw-address",
                                "identifier": mac,
                            },
                        }
                        self._send_command(del_global)  # ignore result/errors
                except Exception as _e:
                    logger.debug(f"Global reservation cleanup for {mac}: {_e}")

            if existing:
                del_cmd = {
                    "command": "reservation-del",
                    "service": ["dhcp4"],
                    "arguments": {
                        "subnet-id": subnet_id,
                        "identifier-type": "hw-address",
                        "identifier": mac
                    }
                }
                self._send_command(del_cmd)

            add_cmd = {
                "command": "reservation-add",
                "service": ["dhcp4"],
                "arguments": {
                    "reservation": reservation
                }
            }

            response = self._send_command(add_cmd)
            if response.get("result") == 0:
                logger.info(f"Set blocked={blocked} for MAC {mac} in VLAN {vlan}")
                return True

            error_text = response.get("text", "")
            logger.error(f"Failed to set blocked={blocked} for MAC {mac}: {error_text}")
            return False

        except Exception as e:
            logger.error(f"Error setting blocked status for MAC {mac}: {e}")
            return False
    
    def _find_available_registered_ip(self, vlan: int, subnet_id: int) -> Optional[str]:
        """
        Find an available IP in the registered pool for the subnet.
        
        Args:
            subnet_id: Subnet ID (e.g., 10 for 192.168.10.0/24)
            
        Returns:
            Available IP address or None if pool is full
        """
        try:
            prefix = _prefix_for_vlan(vlan)
            bounds = _pool_bounds_for_prefix(prefix)
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan}.0/{prefix}", strict=False)
            
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
            reservations = self.get_all_reservations(vlan)
            for res in reservations:
                if "ip-address" in res:
                    used_ips.add(res["ip-address"])
            
            start = int(network.network_address) + bounds["registered_start"]
            end = int(network.network_address) + bounds["registered_end"]

            for candidate in range(start, end + 1):
                candidate_ip = str(ipaddress.IPv4Address(candidate))
                if candidate_ip not in used_ips:
                    return candidate_ip
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding available IP: {e}")
            return None

    def get_available_registered_ip(self, vlan: int) -> Optional[str]:
        """Return the next available registered-pool IP for a VLAN."""
        subnet_id = self._resolve_subnet_id(vlan)
        return self._find_available_registered_ip(vlan, subnet_id)

    def _find_available_blocked_ip(self, vlan: int, subnet_id: int) -> Optional[str]:
        """
        Find an available IP in the blocked pool for the subnet.
        """
        try:
            prefix = _prefix_for_vlan(vlan)
            bounds = _pool_bounds_for_prefix(prefix)
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan}.0/{prefix}", strict=False)

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

            reservations = self.get_all_reservations(vlan)
            for res in reservations:
                if "ip-address" in res:
                    used_ips.add(res["ip-address"])

            start = int(network.network_address) + bounds["blocked_start"]
            end = int(network.network_address) + bounds["blocked_end"]

            for candidate in range(start, end + 1):
                candidate_ip = str(ipaddress.IPv4Address(candidate))
                if candidate_ip not in used_ips:
                    return candidate_ip

            return None

        except Exception as e:
            logger.error(f"Error finding blocked pool IP: {e}")
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
    
    def get_lease_by_mac(self, mac: str, subnet_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Get current lease information for a MAC address.
        
        Args:
            mac: MAC address
            
        Returns:
            Lease dictionary or None if not found
        """
        try:
            mac = mac.lower().replace('-', ':')
            
            arguments = {
                "identifier-type": "hw-address",
                "identifier": mac
            }

            if subnet_id is not None:
                arguments["subnet-id"] = self._resolve_subnet_id(subnet_id)

            command = {
                "command": "lease4-get",
                "service": ["dhcp4"],
                "arguments": arguments
            }
            
            response = self._send_command(command)
            
            if response.get("result") == 0:
                return response.get("arguments")
            else:
                return None
        
        except Exception as e:
            logger.error(f"Error getting lease for MAC {mac}: {e}")
            return None

    def get_lease_ip_for_mac(self, mac: str, subnet_id: Optional[int] = None) -> Optional[str]:
        """
        Return the current IP address for a MAC, if present.
        """
        lease = self.get_lease_by_mac(mac, subnet_id=subnet_id)
        if lease and isinstance(lease, dict):
            return lease.get("ip-address")
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
            # Extract VLAN from IP's third octet and map to Kea subnet-id
            vlan_id = int(ip_address.split('.')[2])
            subnet_id = self._resolve_subnet_id(vlan_id)
            
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
