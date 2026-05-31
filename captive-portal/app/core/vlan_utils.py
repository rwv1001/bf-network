"""
VLAN configuration helpers.

Covers:
- VLAN map / entry lookups
- Pool / prefix calculations
- Kea config updates
- IP-to-VLAN resolution
- Blocked-pool IP detection
"""

import ipaddress
import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POOL_PREFIX_CHOICES = [24, 23, 22, 21]
POOL_PREFIX_STATUSES = ['friars', 'staff', 'students', 'guests', 'contractors', 'volunteers', 'iot']
WIRED_UNREGISTERED_STATUS = 'wired_unregistered'
FIXED_VLAN_STATUSES = [
    'friars', 'staff', 'students', 'guests', 'contractors',
    'volunteers', 'iot', 'restricted', 'unregistered', WIRED_UNREGISTERED_STATUS,
]


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


# ---------------------------------------------------------------------------
# VLAN map / entry helpers
# ---------------------------------------------------------------------------

def get_vlan_map() -> dict:
    """Return {status: vlan_id} from the database, with env-var fallback."""
    from models import VlanMapping
    mappings = VlanMapping.query.all()
    if mappings:
        return {m.status: m.vlan_id for m in mappings}
    return {
        'friars': 10, 'staff': 20, 'students': 30, 'guests': 40,
        'contractors': 50, 'volunteers': 60, 'iot': 70,
        'restricted': 90, 'unregistered': 99,
        WIRED_UNREGISTERED_STATUS: 250,
    }


def get_vlan_entries() -> list:
    """Return all VlanMapping rows ordered by vlan_id."""
    from models import VlanMapping
    return VlanMapping.query.order_by(VlanMapping.vlan_id.asc()).all()


def get_vlan_meta_by_id() -> dict:
    """Return {vlan_id: {status, display_name, ssid}} for all VLANs."""
    meta = {}
    for entry in get_vlan_entries():
        if entry.vlan_id:
            meta[entry.vlan_id] = {
                'status': entry.status,
                'display_name': entry.display_name,
                'ssid': entry.ssid,
            }
    return meta


def get_ssid_for_vlan(vlan_id):
    """Return the SSID string for a VLAN ID, or None."""
    from models import VlanMapping
    try:
        mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
        if mapping and mapping.ssid:
            return mapping.ssid.strip()
    except Exception:
        pass
    return None


def label_for_vlan(vlan_id, vlan_map=None) -> str:
    """Return a human-readable label for a VLAN ID."""
    if not vlan_id:
        return ''
    meta = get_vlan_meta_by_id().get(vlan_id)
    if meta:
        display_name = (meta.get('display_name') or '').strip()
        status = meta.get('status')
        if display_name:
            return f"{display_name} (VLAN {vlan_id})"
        if status:
            return f"{status.title()} (VLAN {vlan_id})"
    return f"VLAN {vlan_id}"


def vlan_requires_password(vlan_id) -> bool:
    """Return True if the given VLAN requires a network password."""
    if not vlan_id:
        return False
    from models import VlanMapping
    mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    return bool(mapping and mapping.require_password)


def get_wired_unregistered_vlan_id() -> int:
    vlan_map = get_vlan_map()
    return vlan_map.get(WIRED_UNREGISTERED_STATUS, 250)


def get_wired_assignable_entries() -> list:
    entries = []
    for entry in get_vlan_entries():
        if not entry.vlan_id:
            continue
        if entry.status in {'restricted', 'unregistered', WIRED_UNREGISTERED_STATUS}:
            continue
        if entry.wired_enabled:
            entries.append(entry)
    return entries


def get_wired_assignable_vlan_ids() -> set:
    return {entry.vlan_id for entry in get_wired_assignable_entries()}


def get_admin_assignable_entries() -> list:
    """All VLANs admins can assign devices to (excludes restricted/unregistered)."""
    entries = []
    for entry in get_vlan_entries():
        if not entry.vlan_id:
            continue
        if entry.status in {'restricted', 'unregistered', WIRED_UNREGISTERED_STATUS}:
            continue
        entries.append(entry)
    return entries


def parse_valid_vlan_ids() -> list:
    raw = os.getenv('VALID_VLANS', '').strip()
    if not raw:
        return []
    vlan_ids = []
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        try:
            vlan_ids.append(int(entry))
        except ValueError:
            continue
    return sorted(set(vlan_ids))


# ---------------------------------------------------------------------------
# Pool / prefix helpers
# ---------------------------------------------------------------------------

def get_vlan_prefix_map() -> dict:
    """Return {status: prefix} from Settings table."""
    from models import Setting
    prefix_map = {}
    for status in POOL_PREFIX_STATUSES:
        raw = Setting.get_value(f'vlan_prefix_{status}', 24)
        try:
            prefix = int(raw)
        except (TypeError, ValueError):
            prefix = 24
        if prefix not in POOL_PREFIX_CHOICES:
            prefix = 24
        prefix_map[status] = prefix
    return prefix_map


def get_vlan_prefix_by_id() -> dict:
    """Return {vlan_id: prefix} for all known VLANs."""
    vlan_map = get_vlan_map()
    prefix_map = get_vlan_prefix_map()
    prefix_by_id = {}
    for status, vlan_id in vlan_map.items():
        if status in prefix_map:
            prefix_by_id[vlan_id] = prefix_map[status]
        else:
            prefix_by_id[vlan_id] = 24
    return prefix_by_id


def pool_bounds_for_prefix(prefix: int) -> tuple:
    """Return (registered_start, registered_end, blocked_start, blocked_end) offsets."""
    total = 2 ** (32 - prefix)
    block_size = 40 * (2 ** (24 - prefix))
    registered_start = 1
    registered_end = total - block_size - 1
    blocked_start = registered_end + 1
    blocked_end = total - 1
    return registered_start, registered_end, blocked_start, blocked_end


def ip_from_offset(network, offset: int) -> str:
    return str(ipaddress.IPv4Address(int(network.network_address) + offset))


def build_pools_for_vlan(vlan_id: int, prefix: int) -> tuple:
    """Return (subnet_cidr, registered_pools, blocked_pool) for a VLAN."""
    network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
    total = network.num_addresses
    block_size = 40 * (2 ** (24 - prefix))
    registered_start = 1
    registered_end = total - block_size - 1
    block_start = registered_end + 1
    block_end = total - 1

    if registered_end < registered_start:
        raise ValueError(f"Pool size too small for VLAN {vlan_id} /{prefix}")

    registered_pools = [
        f"{ip_from_offset(network, registered_start)} - {ip_from_offset(network, registered_end)}"
    ]
    blocked_pool = f"{ip_from_offset(network, block_start)} - {ip_from_offset(network, block_end)}"
    return str(network), registered_pools, blocked_pool


# ---------------------------------------------------------------------------
# IP-to-VLAN resolution
# ---------------------------------------------------------------------------

def vlan_from_ip(ip_address: str):
    """Return the VLAN ID for an IP address (excludes VLAN 99)."""
    if not ip_address:
        return None
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return None

    prefix_by_id = get_vlan_prefix_by_id()
    for vlan_id, prefix in prefix_by_id.items():
        if vlan_id == 99:
            continue
        try:
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
        except Exception:
            continue
        if ip in network:
            return vlan_id
    return None


def vlan_from_ip_any(ip_address: str, prefix_by_id: dict = None):
    """Return the VLAN ID for an IP address (includes all VLANs)."""
    if not ip_address:
        return None
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return None

    if prefix_by_id is None:
        prefix_by_id = get_vlan_prefix_by_id()

    for vlan_id, prefix in prefix_by_id.items():
        try:
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
        except Exception:
            continue
        if ip in network:
            return vlan_id
    return None


# ---------------------------------------------------------------------------
# Blocked / registered pool detection
# ---------------------------------------------------------------------------

def is_blocked_pool_ip(ip_address: str) -> bool:
    """Return True if the IP falls within the blocked pool of its VLAN."""
    if not ip_address:
        return False
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return False

    prefix_by_id = get_vlan_prefix_by_id()
    for vlan_id, prefix in prefix_by_id.items():
        try:
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
        except Exception:
            continue
        if ip not in network:
            continue
        _, _, blocked_start, blocked_end = pool_bounds_for_prefix(prefix)
        offset = int(ip) - int(network.network_address)
        return blocked_start <= offset <= blocked_end

    return False


def is_registered_pool_ip(ip_address: str, vlan_id) -> bool:
    """Return True if the IP falls within the registered (main) pool of its VLAN."""
    if not ip_address or not vlan_id:
        return False
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return False

    if int(vlan_id) == 99:
        return False

    prefix_by_id = get_vlan_prefix_by_id()
    prefix = prefix_by_id.get(int(vlan_id), 24)
    try:
        network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
    except Exception:
        return False
    if ip not in network:
        return False

    registered_start, registered_end, _, _ = pool_bounds_for_prefix(prefix)
    offset = int(ip) - int(network.network_address)
    return registered_start <= offset <= registered_end


# ---------------------------------------------------------------------------
# Kea config helpers
# ---------------------------------------------------------------------------

def update_kea_config(vlan_prefix_by_id: dict) -> None:
    """Write updated pool ranges into dhcp4.json and vlan-prefix-map.txt."""
    config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Kea config not found at {config_path}")

    with open(config_path, 'r', encoding='utf-8') as handle:
        config = json.load(handle)

    subnets = config.get('Dhcp4', {}).get('subnet4', [])
    updated = 0

    for subnet in subnets:
        vlan_id = subnet.get('id')
        if vlan_id not in vlan_prefix_by_id:
            continue
        prefix = vlan_prefix_by_id[vlan_id]
        subnet_cidr, registered_pools, blocked_pool = build_pools_for_vlan(vlan_id, prefix)
        subnet['subnet'] = subnet_cidr
        subnet['pools'] = [{'pool': pool} for pool in registered_pools] + [
            {'pool': blocked_pool, 'client-classes': ['BLOCKED']},
        ]
        updated += 1

    if not updated:
        raise ValueError("No matching VLAN subnets updated in Kea config")

    with open(config_path, 'w', encoding='utf-8') as handle:
        json.dump(config, handle, indent=2)
        handle.write('\n')

    prefix_map_path = os.path.join(os.path.dirname(config_path), 'vlan-prefix-map.txt')
    prefix_map_str = ','.join(f"{vid}:{pfx}" for vid, pfx in sorted(vlan_prefix_by_id.items()))
    with open(prefix_map_path, 'w', encoding='utf-8') as handle:
        handle.write(prefix_map_str + '\n')


def restart_kea_container() -> tuple:
    """Attempt to restart the Kea Docker container. Returns (success, message)."""
    commands = [
        ['sudo', 'docker', 'compose', '-f', '/kea/docker-compose.yml', 'restart', 'kea'],
        ['sudo', 'docker-compose', '-f', '/kea/docker-compose.yml', 'restart', 'kea'],
        ['sudo', 'docker', 'restart', 'kea'],
    ]
    for command in commands:
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
            return True, result.stdout.strip()
        except Exception:
            continue
    return False, 'Unable to restart Kea via docker commands.'


# ---------------------------------------------------------------------------
# Visible-VLAN CSV parsing (used by VLAN config form)
# ---------------------------------------------------------------------------

def parse_visible_vlans(visible_vlans_list: list, index: int) -> str:
    """Extract and normalise the visible_vlans CSV string for a positional form row."""
    raw = visible_vlans_list[index] if index < len(visible_vlans_list) else ''
    parts = [p.strip() for p in raw.split(',') if p.strip().isdigit()]
    return ','.join(parts)
