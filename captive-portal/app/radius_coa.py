"""
RADIUS Change-of-Authorization (CoA) client
Sends CoA packets to RADIUS server to change device VLANs
"""

import os
import logging
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import CoARequest, Packet
import io

logger = logging.getLogger(__name__)

# RADIUS configuration
RADIUS_SERVER = os.getenv('RADIUS_SERVER', '192.168.99.4')
RADIUS_SECRET = os.getenv('RADIUS_SECRET', 'testing123').encode('utf-8')
RADIUS_NAS_IP = os.getenv('RADIUS_NAS_IP', '192.168.99.1')
COA_PORT = 3799

# Create a minimal RADIUS dictionary
DICT_CONTENT = """
# Minimal RADIUS dictionary for CoA
ATTRIBUTE User-Name 1 string
ATTRIBUTE NAS-IP-Address 4 ipaddr
ATTRIBUTE Calling-Station-Id 31 string
ATTRIBUTE Tunnel-Type 64 integer
ATTRIBUTE Tunnel-Medium-Type 65 integer
ATTRIBUTE Tunnel-Private-Group-Id 81 string

VALUE Tunnel-Type VLAN 13
VALUE Tunnel-Medium-Type IEEE-802 6
"""


def get_radius_client():
    """Create and return a RADIUS client"""
    try:
        # Create dictionary from string
        dict_file = io.StringIO(DICT_CONTENT)
        dict_obj = Dictionary(dict_file)
        
        # Create client
        client = Client(
            server=RADIUS_SERVER,
            secret=RADIUS_SECRET,
            dict=dict_obj,
            authport=COA_PORT,
            acctport=COA_PORT
        )
        
        return client
    except Exception as e:
        logger.error(f"Failed to create RADIUS client: {e}")
        return None


def send_coa_change(mac_address, vlan_id):
    """
    Send CoA packet to change device VLAN
    
    Args:
        mac_address: Device MAC address (format: xx:xx:xx:xx:xx:xx)
        vlan_id: Target VLAN ID
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        client = get_radius_client()
        if not client:
            logger.error("Failed to create RADIUS client")
            return False
        
        # Create CoA request
        req = client.CreateCoARequest()
        
        # Add attributes
        req['Calling-Station-Id'] = mac_address.replace(':', '-').upper()
        req['NAS-IP-Address'] = RADIUS_NAS_IP
        req['Tunnel-Type'] = 'VLAN'
        req['Tunnel-Medium-Type'] = 'IEEE-802'
        req['Tunnel-Private-Group-Id'] = str(vlan_id)
        
        logger.info(f"Sending CoA to change {mac_address} to VLAN {vlan_id}")
        
        # Send request
        reply = client.SendPacket(req)
        
        if reply.code == Packet.CoAACK:
            logger.info(f"CoA successful: {mac_address} -> VLAN {vlan_id}")
            return True
        else:
            logger.warning(f"CoA failed for {mac_address}: {reply.code}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending CoA for {mac_address}: {e}")
        return False


def send_coa_disconnect(mac_address):
    """
    Send CoA packet to disconnect device
    
    Args:
        mac_address: Device MAC address (format: xx:xx:xx:xx:xx:xx)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        client = get_radius_client()
        if not client:
            logger.error("Failed to create RADIUS client")
            return False
        
        # Create disconnect request
        req = client.CreateCoARequest()
        req.code = 40  # Disconnect-Request
        
        # Add attributes
        req['Calling-Station-Id'] = mac_address.replace(':', '-').upper()
        req['NAS-IP-Address'] = RADIUS_NAS_IP
        
        logger.info(f"Sending CoA disconnect for {mac_address}")
        
        # Send request
        reply = client.SendPacket(req)
        
        if reply.code == Packet.CoAACK:
            logger.info(f"CoA disconnect successful: {mac_address}")
            return True
        else:
            logger.warning(f"CoA disconnect failed for {mac_address}: {reply.code}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending CoA disconnect for {mac_address}: {e}")
        return False
