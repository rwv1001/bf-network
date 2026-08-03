"""
RADIUS Change-of-Authorization (CoA) client
Sends CoA packets to RADIUS server to change device VLANs
"""

import os
import logging
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad import packet as radius_packet
import io

logger = logging.getLogger(__name__)

# RADIUS configuration
RADIUS_SERVER = os.environ['RADIUS_SERVER']
RADIUS_SECRET = os.environ['RADIUS_SECRET'].encode('utf-8')

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

def _lookup_switch_host_for_mac(mac_address: str) -> str | None:
    """Return mac_port_cache.switch_host for this MAC, or None."""
    mac = mac_address.strip().lower().replace('-', ':')
    try:
        from extensions import db
        from sqlalchemy import text
        row = db.session.execute(
            text("""
                SELECT switch_host
                FROM mac_port_cache
                WHERE mac_address = :mac
                  AND switch_host IS NOT NULL
                  AND switch_host <> ''
                LIMIT 1
            """),
            {"mac": mac},
        ).fetchone()
        if row and row[0]:
            return str(row[0]).strip()
    except Exception as e:
        logger.warning("mac_port_cache lookup failed for %s: %s", mac, e)
    return None


def send_coa_change(mac_address, vlan_id):
    """
    Send CoA to the switch that currently has this MAC, to move it to vlan_id.
    """
    try:
        switch_host = _lookup_switch_host_for_mac(mac_address)
        if not switch_host:
            logger.error(
                "No switch_host in mac_port_cache for %s — cannot send CoA "
                "(port lookup may not have run yet)",
                mac_address,
            )
            return False

        # CoA destination = that switch (not a global NAS IP)
        client = get_radius_client(server=switch_host)
        if not client:
            logger.error("Failed to create RADIUS client for switch %s", switch_host)
            return False

        if hasattr(client, 'CreateCoARequest'):
            req = client.CreateCoARequest()
        elif hasattr(client, 'CreateCoAPacket'):
            req = client.CreateCoAPacket(
                code=getattr(radius_packet, 'CoARequest', 43)
            )
        else:
            coa_code = getattr(radius_packet, 'CoARequest', 43)
            req = client.CreatePacket(code=coa_code)

        # HP often expects hyphenated MAC in Calling-Station-Id
        req['Calling-Station-Id'] = mac_address.replace(':', '-').upper()
        req['NAS-IP-Address'] = switch_host  # this switch's management IP
        req['Tunnel-Type'] = 'VLAN'
        req['Tunnel-Medium-Type'] = 'IEEE-802'
        req['Tunnel-Private-Group-Id'] = str(vlan_id)

        logger.info(
            "Sending CoA to %s: %s -> VLAN %s",
            switch_host, mac_address, vlan_id,
        )

        reply = client.SendPacket(req)

        if reply.code == getattr(radius_packet, 'CoAACK', 44):
            logger.info(
                "CoA successful via %s: %s -> VLAN %s",
                switch_host, mac_address, vlan_id,
            )
            return True

        logger.warning(
            "CoA failed via %s for %s: reply code %s",
            switch_host, mac_address, reply.code,
        )
        return False

    except Exception as e:
        logger.error("Error sending CoA for %s: %s", mac_address, e)
        return False


def send_coa_disconnect(mac_address):
    """
    Send Disconnect-Request to the switch that currently has this MAC.

    Args:
        mac_address: Device MAC (xx:xx:xx:xx:xx:xx)

    Returns:
        bool: True if ACK received, False otherwise
    """
    try:
        switch_host = _lookup_switch_host_for_mac(mac_address)
        if not switch_host:
            logger.error(
                "No switch_host in mac_port_cache for %s — cannot send Disconnect "
                "(port lookup may not have run yet)",
                mac_address,
            )
            return False

        client = get_radius_client(server=switch_host)
        if not client:
            logger.error("Failed to create RADIUS client for switch %s", switch_host)
            return False

        disconnect_code = getattr(radius_packet, 'DisconnectRequest', 40)
        if hasattr(client, 'CreateCoARequest'):
            req = client.CreateCoARequest()
            req.code = disconnect_code
        elif hasattr(client, 'CreateCoAPacket'):
            req = client.CreateCoAPacket(code=disconnect_code)
        else:
            req = client.CreatePacket(code=disconnect_code)

        req['Calling-Station-Id'] = mac_address.replace(':', '-').upper()
        req['NAS-IP-Address'] = switch_host

        logger.info("Sending Disconnect to %s for %s", switch_host, mac_address)

        reply = client.SendPacket(req)

        if reply.code in {
            getattr(radius_packet, 'DisconnectACK', 41),
            getattr(radius_packet, 'CoAACK', 44),
        }:
            logger.info(
                "Disconnect successful via %s: %s", switch_host, mac_address
            )
            return True

        logger.warning(
            "Disconnect failed via %s for %s: reply code %s",
            switch_host, mac_address, reply.code,
        )
        return False

    except Exception as e:
        logger.error("Error sending Disconnect for %s: %s", mac_address, e)
        return False
