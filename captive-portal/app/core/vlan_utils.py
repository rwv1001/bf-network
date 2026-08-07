"""
VLAN configuration helpers.

Covers:
- VLAN map / entry lookups
- Pool / prefix calculations
- Kea config updates
- IP-to-VLAN resolution
- Blocked-pool IP detection

Environment variables
---------------------
WIRED_VLAN            VLAN ID for wired-unregistered devices (default: 250)
MANAGEMENT_VLAN       VLAN ID for management / switch hosts (default: 99)
UNREGISTERED_GW_BYTE  Last octet of the unregistered gateway IP (default: 2)
                      Gateway is derived as NETWORK_WORD.MANAGEMENT_VLAN.<byte>
                      e.g. 192.168.99.2  — replaces the old UNREGISTERED_GW var.
SWITCH_HOSTS_BYTES    Comma-separated last octets of switch management IPs (default: 2)
                      Hosts are derived as NETWORK_WORD.MANAGEMENT_VLAN.<byte>
                      e.g. "2,3" → 192.168.99.2, 192.168.99.3
                      Falls back to the legacy SWITCH_HOSTS env var if set.
"""

import ipaddress
import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

from typing import Dict, List

def get_vlan_defaults() -> Dict[int, str]:
    """Parse VLAN_DEFAULTS from .env into {vlan_id: name}"""
    raw = os.getenv('VLAN_DEFAULTS', '').strip()
    if not raw:
        return {}

    result = {}
    for pair in raw.split(','):
        pair = pair.strip()
        if not pair or ':' not in pair:
            continue
        try:
            vid_str, name = pair.split(':', 1)
            vid = int(vid_str.strip())
            name = name.strip()
            if vid > 0 and name:
                result[vid] = name
        except ValueError:
            continue
    return result


def get_vlan_name(vlan_id: int) -> str:
    """Return the configured name for a VLAN ID, or a fallback."""
    defaults = get_vlan_defaults()
    return defaults.get(vlan_id, f"vlan-{vlan_id}")


def get_fixed_vlan_statuses() -> List[str]:
    """Return list of status names that should be protected (from VLAN_DEFAULTS)."""
    defaults = get_vlan_defaults()
    # You can customize this list if needed
    protected = {'restricted', 'unregistered', 'wired_unregistered'}
    return [name for vid, name in defaults.items() if name not in protected]


def get_pool_prefix_statuses() -> List[str]:
    raw = os.getenv('VLAN_POOL_STATUSES', '').strip()
    statuses = [s.strip() for s in raw.split(',') if s.strip()]

    # Always include wired_unregistered for subnet configuration
    if 'wired_unregistered' not in statuses:
        statuses.append('wired_unregistered')

    return statuses


def seed_vlan_mappings() -> int:
    """
    Seed vlan_mappings from ALL entries in VLAN_DEFAULTS.
    - wired_unregistered always uses the WIRED_VLAN env var.
    - Only inserts rows that don't already exist.
    """
    from models import db, VlanMapping

    defaults = get_vlan_defaults()   # {vlan_id: status_name} from VLAN_DEFAULTS

    if not defaults:
        return 0

    existing = {v.status for v in VlanMapping.query.all()}
    inserted = 0

    wired_vlan_id = get_wired_vlan_id()

    for vlan_id, status in sorted(defaults.items()):
        if status in existing:
            continue

        # wired_unregistered always takes its ID from WIRED_VLAN, not VLAN_DEFAULTS
        if status == 'wired_unregistered':
            vlan_id = wired_vlan_id

        entry = VlanMapping(
            status=status,
            vlan_id=vlan_id,
            display_name=status.replace('_', ' ').title(),
            wired_enabled=True,
            require_password=True,
            visible_vlans='',
        )
        db.session.add(entry)
        inserted += 1

    if inserted:
        db.session.commit()
        logger.info("Seeded %d VLAN mappings from VLAN_DEFAULTS", inserted)

    return inserted



# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POOL_PREFIX_CHOICES = [24, 23, 22, 21]
POOL_PREFIX_STATUSES = get_pool_prefix_statuses()
WIRED_UNREGISTERED_STATUS = 'wired_unregistered'
FIXED_VLAN_STATUSES = get_fixed_vlan_statuses()



def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


# ---------------------------------------------------------------------------
# Dynamic VLAN ID helpers (replaces hardcoded 250 / 99)
# ---------------------------------------------------------------------------

def get_wired_vlan_id() -> int:
    """Return the wired-unregistered VLAN ID (env WIRED_VLAN, default 250)."""
    try:
        return int(os.getenv('WIRED_VLAN', '250'))
    except (TypeError, ValueError):
        return 250


def get_management_vlan_id() -> int:
    """Return the management VLAN ID (env MANAGEMENT_VLAN, default 99)."""
    try:
        return int(os.getenv('MANAGEMENT_VLAN', '99'))
    except (TypeError, ValueError):
        return 99


def get_unregistered_gw() -> str:
    """
    Return the unregistered-network gateway IP.

    Derived from NETWORK_WORD + MANAGEMENT_VLAN + UNREGISTERED_GW_BYTE.
    Example: NETWORK_WORD=192.168, MANAGEMENT_VLAN=99, UNREGISTERED_GW_BYTE=2
             → 192.168.99.2

    Falls back to the legacy UNREGISTERED_GW env var if set, so existing
    deployments that still have that variable continue to work unchanged.
    """
    legacy = os.getenv('UNREGISTERED_GW', '').strip()
    if legacy:
        return legacy
    try:
        gw_byte = int(os.getenv('UNREGISTERED_GW_BYTE', '2'))
    except (TypeError, ValueError):
        gw_byte = 2
    mgmt_vlan = get_management_vlan_id()
    return f"{_net_word()}.{mgmt_vlan}.{gw_byte}"


def get_switch_host_ips() -> list:
    """
    Return the list of switch management IP addresses.

    Derived from NETWORK_WORD + MANAGEMENT_VLAN + SWITCH_HOSTS_BYTES.
    Example: NETWORK_WORD=192.168, MANAGEMENT_VLAN=99, SWITCH_HOSTS_BYTES=2,3
             → ['192.168.99.2', '192.168.99.3']

    Falls back to the legacy SWITCH_HOSTS env var (space-separated IPs) if
    SWITCH_HOSTS_BYTES is not set, so existing deployments are unaffected.
    """
    bytes_raw = os.getenv('SWITCH_HOSTS_BYTES', '').strip()
    if bytes_raw:
        mgmt_vlan = get_management_vlan_id()
        hosts = []
        for part in bytes_raw.split(','):
            part = part.strip()
            if part.isdigit():
                hosts.append(f"{_net_word()}.{mgmt_vlan}.{part}")
        if hosts:
            return hosts

    # Legacy fallback
    legacy = os.getenv('SWITCH_HOSTS', '').strip()
    if legacy:
        return [h.strip() for h in legacy.split() if h.strip()]

    return []


def get_switch_hosts_str() -> str:
    """
    Return switch management IPs as a space-separated string suitable for
    passing to shell scripts via the SWITCH_HOSTS environment variable.

    Example: 'SWITCH_HOSTS_BYTES=2,3' → '192.168.99.2 192.168.99.3'
    """
    return ' '.join(get_switch_host_ips())


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
        'restricted': 90, 'unregistered': get_management_vlan_id(),
        WIRED_UNREGISTERED_STATUS: get_wired_vlan_id(),
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
    # Fall back to VLAN_DEFAULTS for VLANs not in the DB
    name = get_vlan_defaults().get(vlan_id)
    if name:
        return f"{name.replace('_', ' ').title()} (VLAN {vlan_id})"
    return f"VLAN {vlan_id}"


def vlan_requires_password(vlan_id) -> bool:
    """Return True if the given VLAN requires a network password."""
    if not vlan_id:
        return False
    from models import VlanMapping
    mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    return bool(mapping and mapping.require_password)


def get_wired_unregistered_vlan_id() -> int:
    """Return the wired-unregistered VLAN ID (reads WIRED_VLAN env var)."""
    vlan_map = get_vlan_map()
    # Prefer the DB mapping; fall back to the env-var-derived value.
    return vlan_map.get(WIRED_UNREGISTERED_STATUS, get_wired_vlan_id())


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
    from types import SimpleNamespace
    excluded = {'restricted', 'unregistered', WIRED_UNREGISTERED_STATUS}
    entries = []
    seen_vlan_ids = set()
    for entry in get_vlan_entries():
        if not entry.vlan_id:
            continue
        if entry.status in excluded:
            continue
        entries.append(entry)
        seen_vlan_ids.add(entry.vlan_id)
    # Supplement with VLANs defined in VLAN_DEFAULTS but not yet in the DB
    for vid, name in sorted(get_vlan_defaults().items()):
        if name in excluded or vid in seen_vlan_ids:
            continue
        entries.append(SimpleNamespace(vlan_id=vid, wired_enabled=True, status=name,
                                       display_name=name.replace('_', ' ').title()))
    entries.sort(key=lambda e: e.vlan_id)
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
    """Return the VLAN ID for an IP address (excludes management VLAN)."""
    if not ip_address:
        return None
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return None

    mgmt_vlan = get_management_vlan_id()
    prefix_by_id = get_vlan_prefix_by_id()
    for vlan_id, prefix in prefix_by_id.items():
        if vlan_id == mgmt_vlan:
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

    mgmt_vlan = get_management_vlan_id()
    if int(vlan_id) == mgmt_vlan:
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
