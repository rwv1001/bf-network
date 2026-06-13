"""
MAC address / IP address / connection-type helpers.

Covers:
- get_client_mac() — resolve MAC from request headers / Kea lease file / DB
- get_client_ip()
- get_ip_for_mac()
- detect_connection_type()
- load_active_lease_counts()
- load_adoptable_leases()
- current_user_from_device()
- normalize_mac_input()
"""

import logging
import os
import re
from datetime import datetime, timedelta

from flask import request

logger = logging.getLogger(__name__)


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


def normalize_mac_input(raw) -> str:
    """Normalise a raw MAC string to xx:xx:xx:xx:xx:xx, or return None."""
    if not raw:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(raw)).lower()
    if len(cleaned) != 12:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))

def get_client_ip() -> str:
    logger.debug("=== get_client_ip() headers ===")
    for h in ['X-Real-IP', 'X-Forwarded-For', 'X-Forwarded-Client-IP', 'CF-Connecting-IP']:
        val = request.headers.get(h)
        if val:
            logger.debug(f"  {h}: {val}")

    # Your existing logic
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def get_client_mac() -> str:
    """
    Resolve the client MAC address from:
    1. X-Client-MAC header / query param / form field
    2. Kea CSV lease file
    3. Kea control socket
    4. ip_leases DB table (fallback)
    """
    logger.debug("=== get_client_mac() called ===")

    # Try direct sources first
    mac = request.headers.get('X-Client-MAC')
    if mac:
        logger.debug(f"[get_client_mac] Found MAC in X-Client-MAC header: {mac}")
    else:
        mac = request.args.get('mac')
        if mac:
            logger.debug(f"[get_client_mac] Found MAC in query param: {mac}")
        else:
            mac = request.form.get('mac')
            if mac:
                logger.debug(f"[get_client_mac] Found MAC in form data: {mac}")

    # Fallback to IP-based lookup
    if not mac:
        ip_address = get_client_ip()
        logger.debug(f"[get_client_mac] No direct MAC found. Trying IP-based lookup for IP: {ip_address}")

        if ip_address:
            mac = _mac_from_lease_file(ip_address)
            if mac:
                logger.debug(f"[get_client_mac] Found MAC via lease file: {mac}")
            else:
                mac = _mac_from_kea_socket(ip_address)
                if mac:
                    logger.debug(f"[get_client_mac] Found MAC via Kea control socket: {mac}")
                else:
                    mac = _mac_from_iplease_db(ip_address)
                    if mac:
                        logger.debug(f"[get_client_mac] Found MAC via ip_leases DB: {mac}")
                    else:
                        logger.debug(f"[get_client_mac] No MAC found for IP {ip_address} in any source")

    # Normalize MAC format
    if mac:
        original_mac = mac
        mac = mac.lower().replace('-', '').replace(':', '')
        if len(mac) == 12:
            mac = ':'.join([mac[i:i + 2] for i in range(0, 12, 2)])
            logger.debug(f"[get_client_mac] Normalized MAC: {original_mac} → {mac}")
        else:
            logger.warning(f"[get_client_mac] MAC found but invalid length after normalization: {mac}")
            mac = None
    else:
        logger.warning("[get_client_mac] No MAC address could be determined")

    return mac


def _mac_from_lease_file(ip_address: str) -> str:
    lease_file = '/kea/leases/kea-leases4.csv'
    matching_macs = []
    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue
                fields = line.strip().split(',')
                if len(fields) >= 2 and fields[0] == ip_address:
                    matching_macs.append(fields[1])
        if matching_macs:
            return matching_macs[-1]
    except FileNotFoundError:
        logger.debug("Kea lease file not found: %s", lease_file)
    except Exception as exc:
        logger.error("Error reading Kea lease file %s: %s", lease_file, exc)
    return None


def _mac_from_kea_socket(ip_address: str) -> str:
    try:
        kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
        from kea_integration import get_kea_client
        kea = get_kea_client(control_socket=kea_socket)
        if kea:
            lease = kea.get_lease(ip_address)
            if lease:
                mac = lease.get('hw-address')
                if mac:
                    logger.info("Found MAC %s for IP %s via Kea control socket", mac, ip_address)
                    return mac
    except Exception as exc:
        logger.error("Error querying Kea control socket: %s", exc)
    return None


def _mac_from_iplease_db(ip_address: str) -> str:
    try:
        from models import IPLease
        lease_row = (
            IPLease.query
            .filter_by(ip_address=ip_address)
            .order_by(IPLease.lease_expiry.desc())
            .first()
        )
        if lease_row and lease_row.mac_address:
            logger.info("Found MAC %s for IP %s via ip_leases DB fallback",
                        lease_row.mac_address, ip_address)
            return lease_row.mac_address
    except Exception as exc:
        logger.error("Error querying ip_leases for MAC lookup: %s", exc)
    return None


def get_ip_for_mac(mac_address: str, subnet_id=None) -> str:
    """Find the most recent IP address for a MAC from the Kea lease file."""
    if not mac_address:
        return None
    normalized = mac_address.lower().replace('-', ':')
    lease_file = '/kea/leases/kea-leases4.csv'
    matching_ips = []
    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue
                fields = line.strip().split(',')
                if len(fields) >= 2 and fields[1].lower() == normalized:
                    matching_ips.append(fields[0])
        if matching_ips:
            return matching_ips[-1]
    except FileNotFoundError:
        logger.debug("Kea lease file not found: %s", lease_file)
    except Exception as exc:
        logger.error("Error reading Kea lease file %s: %s", lease_file, exc)

    try:
        kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
        from kea_integration import get_kea_client
        kea = get_kea_client(control_socket=kea_socket)
        if kea:
            lease_ip = kea.get_lease_ip_for_mac(normalized, subnet_id=subnet_id)
            if lease_ip:
                return lease_ip
    except Exception as exc:
        logger.error("Error querying Kea for MAC %s: %s", normalized, exc)

    return None


def detect_connection_type(ip_address: str) -> tuple:
    """
    Detect if a connection is WiFi or wired based on source IP/VLAN.
    Returns (connection_type, vlan_id, ssid).

    The wired-unregistered VLAN (WIRED_VLAN env var, default 250) and the
    management VLAN (MANAGEMENT_VLAN env var, default 99) are treated as
    wired connections with no SSID.
    """
    from core.vlan_utils import (
        vlan_from_ip,
        get_wired_unregistered_vlan_id,
        get_management_vlan_id,
        get_ssid_for_vlan,
    )
    if not ip_address:
        return ('unknown', None, None)

    vlan_id = vlan_from_ip(ip_address)
    if not vlan_id:
        return ('unknown', None, None)

    wired_unregistered_vlan = get_wired_unregistered_vlan_id()
    mgmt_vlan = get_management_vlan_id()

    if vlan_id in {mgmt_vlan, wired_unregistered_vlan}:
        return ('wired', vlan_id, None)

    ssid = get_ssid_for_vlan(vlan_id)
    if ssid:
        return ('wifi', vlan_id, ssid)
    return ('unknown', vlan_id, None)


def load_active_lease_counts() -> dict:
    """Return {vlan_id: active_lease_count} from the Kea CSV lease file."""
    from core.vlan_utils import get_vlan_prefix_by_id, vlan_from_ip_any
    lease_file = '/kea/leases/kea-leases4.csv'
    counts = {}
    seen_by_vlan = {}
    now = datetime.utcnow()
    prefix_by_id = get_vlan_prefix_by_id()

    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue
                fields = line.strip().split(',')
                if len(fields) < 5:
                    continue
                ip_address = fields[0]
                expire_raw = fields[4].strip()
                expires_at = None
                if expire_raw:
                    try:
                        expires_at = datetime.utcfromtimestamp(int(expire_raw))
                    except Exception:
                        expires_at = None
                if expires_at and expires_at < now:
                    continue

                vlan_id = None
                if len(fields) > 5 and fields[5].strip().isdigit():
                    vlan_id = int(fields[5].strip())
                if vlan_id is None:
                    vlan_id = vlan_from_ip_any(ip_address, prefix_by_id)
                if not vlan_id:
                    continue

                seen = seen_by_vlan.setdefault(vlan_id, set())
                if ip_address in seen:
                    continue
                seen.add(ip_address)
                counts[vlan_id] = counts.get(vlan_id, 0) + 1
    except FileNotFoundError:
        logger.warning("Kea lease file not found for lease counts: %s", lease_file)
    except Exception as exc:
        logger.error("Failed to read lease counts: %s", exc)

    return counts


def load_adoptable_leases(vlan_ids: set) -> list:
    """
    Scan the Kea CSV lease file for active leases on the given VLANs.
    Returns a list of dicts with mac_address, ip_address, vlan_id, first_seen, etc.
    """
    from core.vlan_utils import get_vlan_prefix_by_id, vlan_from_ip_any
    from core.device_utils import upsert_unregistered_lease
    from models import UnregisteredLease
    from extensions import db as _db

    if not vlan_ids:
        return []

    lease_file = '/kea/leases/kea-leases4.csv'
    now = datetime.utcnow()
    adoptable_by_mac = {}
    existing_leases = {
        lease.mac_address: lease
        for lease in UnregisteredLease.query.all()
    }
    prefix_by_id = get_vlan_prefix_by_id()

    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue
                fields = line.strip().split(',')
                if len(fields) < 5:
                    continue
                ip_address = fields[0]
                mac_address = fields[1].lower()
                expire_raw = fields[4].strip() if len(fields) > 4 else ''
                try:
                    if expire_raw and int(expire_raw) < now.timestamp():
                        continue
                except (ValueError, TypeError):
                    pass
                vlan_id = vlan_from_ip_any(ip_address, prefix_by_id)
                if not vlan_id or vlan_id not in vlan_ids:
                    continue

                expires_at = None
                if expire_raw:
                    try:
                        expires_at = datetime.utcfromtimestamp(int(expire_raw))
                    except Exception:
                        expires_at = None
                if not expires_at:
                    expires_at = now + timedelta(hours=1)

                upsert_unregistered_lease(mac_address, ip_address, expires_at, commit=False)

                existing = existing_leases.get(mac_address)
                first_seen = existing.created_at if existing else now
                last_seen = existing.updated_at if existing else now

                current = adoptable_by_mac.get(mac_address)
                if current:
                    current['first_seen'] = min(current['first_seen'], first_seen)
                    current['last_seen'] = max(current['last_seen'], last_seen)
                    if expires_at and (not current['expires_at'] or expires_at > current['expires_at']):
                        current['expires_at'] = expires_at
                        current['ip_address'] = ip_address
                        current['vlan_id'] = vlan_id
                    continue

                adoptable_by_mac[mac_address] = {
                    'mac_address': mac_address,
                    'ip_address': ip_address,
                    'vlan_id': vlan_id,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'expires_at': expires_at,
                }
    except FileNotFoundError:
        logger.warning("Kea lease file not found for adoptable scan: %s", lease_file)
    except Exception as exc:
        logger.error("Failed to read adoptable leases: %s", exc)

    _db.session.commit()
    return list(adoptable_by_mac.values())


def current_user_from_device():
    """
    Return (user, device) for the device making the current request,
    or (None, None) if the device is not registered.
    """
    from models import Device
    from core.device_utils import get_active_ownership

    mac_address = get_client_mac()
    if not mac_address:
        return None, None
    device = Device.query.filter_by(mac_address=mac_address).first()
    if not device:
        return None, None
    ownership = get_active_ownership(mac_address)
    if not ownership and device.registration_status != 'registered':
        return None, None
    if not device.user or device.user.blocked or not device.user.is_active:
        return None, None
    return device.user, device
