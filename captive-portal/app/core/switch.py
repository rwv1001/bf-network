"""
HP5130 switch SSH helpers.

All low-level SSH communication with the switch lives here.
Higher-level ACL / PBR / port-config builders live in core/network.py
and blueprints/admin/isp_routers.py / switch_ports.py.

Switch host resolution
----------------------
Switch management IPs are derived from three env vars:

  NETWORK_WORD          e.g. 192.168
  MANAGEMENT_VLAN       e.g. 99
  SWITCH_HOSTS_BYTES    e.g. 2,3   → 192.168.99.2, 192.168.99.3

The legacy SWITCH_HOSTS env var (space-separated IPs) is still accepted as a
fallback so existing deployments continue to work without changes.
"""

import logging
import os
import re
import subprocess

from sqlalchemy import text

logger = logging.getLogger(__name__)

COMMON_PORT_UNDO_COMMANDS = [
    ' undo description',
    ' undo ip verify source',
    ' undo port-security port-mode',
    ' undo port-security intrusion-mode',
    ' undo port-security max-mac-count',
    ' undo port access vlan',
    ' undo port link-type',
    ' undo port trunk permit vlan all',
    ' undo mac-vlan enable',
    ' undo mac-authentication',
    ' undo web-auth enable',
    ' undo web-auth domain',
    ' undo dhcp snooping trust',
    ' undo arp detection trust',
    ' undo dhcp snooping check mac-address',
    ' undo mac-authentication max-user',
    ' undo mac-authentication domain',
    ' undo mac-authentication host-mode',
    ' undo dhcp snooping binding record',
    ' undo mac-authentication guest-vlan',
    ' undo port-security enable',
    ' undo poe enable',
]


# ---------------------------------------------------------------------------
# Low-level SSH execution
# ---------------------------------------------------------------------------

def run_switch_command(host: str, command: str, extra_input: str = '',
                       disable_paging: bool = False, timeout: int = 120):
    """
    Run one or more newline-separated commands on an HP5130 switch via SSH.

    Uses the same SSH options as hp5130-port-lookup.sh / hp5130-replug.sh so
    the legacy RSA host-key algorithms negotiate correctly.

    extra_input:    additional text sent after the command block (e.g. 'N\\n'
                    for display diagnostic-information's Y/N prompt).
    disable_paging: if True, prepends 'screen-length disable' to prevent
                    '---- More ----' truncation on long output.

    Returns the command stdout as a string, or None on failure.
    """
    import shlex

    switch_user = os.getenv('SWITCH_USER', 'robert')
    switch_port = os.getenv('SWITCH_SSH_PORT', '22')
    switch_key  = os.getenv('SWITCH_KEY_PATH', '')

    ssh_args = [
        'ssh', '-tt',
        '-i', switch_key,
        '-p', switch_port,
        '-o', 'HostKeyAlgorithms=+ssh-rsa',
        '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=5',
        '-o', 'ServerAliveCountMax=3',
        f'{switch_user}@{host}',
    ]

    preamble = 'screen-length disable\n' if disable_paging else ''
    stdin_data = f'{preamble}{command}\n{extra_input}quit\n'

    # === DEBUG OUTPUT ===
    ssh_cmd_str = ' '.join(shlex.quote(arg) for arg in ssh_args)
    logger.info("SSH command to %s:\n%s", host, ssh_cmd_str)
    logger.info("stdin being sent to switch:\n%s", stdin_data)

    try:
        result = subprocess.run(
            ssh_args,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.warning(
                "SSH to %s exited with code %d\n"
                "=== STDERR ===\n%s\n"
                "=== STDOUT (first 500 chars) ===\n%s",
                host,
                result.returncode,
                result.stderr.strip()[:1000],
                result.stdout.strip()[:500],
            )
        else:
            logger.info(
                "SSH to %s succeeded (returncode=0). Output length: %d chars",
                host, len(result.stdout or "")
            )
            logger.info("SSH %s output:\n%s", host, result.stdout)

        return result.stdout if result.stdout and result.stdout.strip() else None

    except subprocess.TimeoutExpired:
        logger.warning("SSH command timed out for %s after %s seconds", host, timeout)
        return None
    except Exception as exc:
        logger.warning("SSH command failed for %s: %s", host, exc)
        return None


# ---------------------------------------------------------------------------
# Switch host resolution helpers
# ---------------------------------------------------------------------------

def get_switch_hosts() -> list:
    """
    Return the list of switch management IP addresses.

    Resolution order:
    1. SWITCH_HOSTS_BYTES (comma-separated last octets) combined with
       NETWORK_WORD and MANAGEMENT_VLAN.
       e.g. NETWORK_WORD=192.168, MANAGEMENT_VLAN=99, SWITCH_HOSTS_BYTES=2,3
            → ['192.168.99.2', '192.168.99.3']
    2. Legacy SWITCH_HOSTS env var (space-separated full IPs) — kept for
       backwards compatibility with existing deployments.
    """
    from core.vlan_utils import get_switch_host_ips
    return get_switch_host_ips()


def switch_host_for_port(port_name: str) -> str:
    """
    Return the switch_host for the given port by looking it up in switch_ports.
    Falls back to the first switch host if the port is not found.
    """
    from extensions import db as _db
    if port_name:
        row = _db.session.execute(
            text("SELECT switch_host FROM switch_ports WHERE port_name = :p LIMIT 1"),
            {'p': port_name},
        ).fetchone()
        if row:
            return row[0]
    hosts = get_switch_hosts()
    return hosts[0] if hosts else ''


def get_switch_host_for_isp_router(router) -> str:
    """
    Return the switch host for the HP5130 that physically hosts this ISP
    router's uplink port.  Uses ISPRouter.switch_host when set; falls back
    to the first switch host.
    """
    if router and router.switch_host:
        return router.switch_host
    hosts = get_switch_hosts()
    return hosts[0] if hosts else ''


def get_switch_host_for_vlan(vlan_id) -> str:
    """
    Return the HP5130 switch_host that hosts the ISP router for the given
    device VLAN.  Resolves via VlanMapping.isp_router_id -> ISPRouter.switch_host.
    Falls back to first switch host.
    """
    if vlan_id:
        try:
            from models import VlanMapping
            mapping = VlanMapping.query.filter_by(vlan_id=int(vlan_id)).first()
            if mapping and mapping.isp_router and mapping.isp_router.switch_host:
                return mapping.isp_router.switch_host
        except Exception:
            pass
    hosts = get_switch_hosts()
    return hosts[0] if hosts else ''


# ---------------------------------------------------------------------------
# MAC / interface name helpers
# ---------------------------------------------------------------------------

def normalize_switch_mac(mac_address: str):
    """Normalise a MAC address to HP switch format: AABB-CCDD-EEFF."""
    if not mac_address:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(mac_address))
    if len(cleaned) != 12:
        return None
    return '-'.join(cleaned[i:i + 2] for i in range(0, 12, 2)).upper()


def expand_switch_iface_name(iface: str) -> str:
    """Expand a short interface name to its full Comware 7 form."""
    if iface.startswith('GE') and not iface.startswith('GigabitEthernet'):
        return f"GigabitEthernet{iface[2:]}"
    if iface.startswith('XGE') and not iface.startswith('Ten-GigabitEthernet'):
        return f"Ten-GigabitEthernet{iface[3:]}"
    return iface


def _is_uplink_port(iface: str, switch_host: str = None) -> bool:
    """Return True if this port has port_role='inter_switch' in switch_ports, or is a Ten-Gig trunk."""
    expanded = expand_switch_iface_name(iface)
    if expanded.startswith('Ten-GigabitEthernet'):
        return True
    if switch_host:
        try:
            from extensions import db
            row = db.session.execute(
                text(
                    "SELECT 1 FROM switch_ports "
                    "WHERE switch_host = :host AND port_name IN (:iface, :expanded) "
                    "AND port_role = 'inter_switch' LIMIT 1"
                ),
                {"host": switch_host, "iface": iface, "expanded": expanded},
            ).fetchone()
            if row is not None:
                return True
        except Exception:
            pass
    return False


def switch_port_allowed(iface: str) -> bool:
    """Return True if the interface name is permitted for replug / role changes."""
    deny_pattern = os.getenv('SWITCH_REPLUG_DENY_PATTERN', '').strip()
    if deny_pattern and re.search(deny_pattern, iface):
        return False
    allowed_raw = os.getenv('SWITCH_REPLUG_ALLOWED_PREFIXES', 'GigabitEthernet,GE')
    allowed = [e.strip() for e in allowed_raw.split(',') if e.strip()]
    if not allowed:
        return True
    return any(iface.startswith(prefix) for prefix in allowed)


# ---------------------------------------------------------------------------
# Port discovery helpers
# ---------------------------------------------------------------------------

def find_switch_port_for_mac(mac_address: str):
    """
    Scan all switches in the switch hosts list for the given MAC address.
    Returns (switch_host, iface) for the first switch that reports the MAC,
    or None if not found on any switch.
    """
    switch_hosts = get_switch_hosts()
    if not switch_hosts:
        logger.warning('find_switch_port_for_mac: no switch hosts configured')
        return None

    normalized = normalize_switch_mac(mac_address)
    if not normalized:
        return None

    iface_pattern = re.compile(
        r"\b(?P<iface>(?:GigabitEthernet|Ten-GigabitEthernet|GE|XGE|Ethernet|Bridge-Aggregation)\S+)\b",
        re.IGNORECASE,
    )

    for switch_host in switch_hosts:
        found_iface = None
        for command in [
            f"display mac-address | include {normalized}",
            f"display mac-address dynamic | include {normalized}",
        ]:
            output = run_switch_command(switch_host, command)
            if not output:
                continue
            for line in output.splitlines():
                if normalized not in line.upper():
                    continue
                match = iface_pattern.search(line)
                if match:
                    iface = expand_switch_iface_name(match.group('iface'))
                    if not _is_uplink_port(iface, switch_host):
                        found_iface = iface
                    break  # found the MAC on this switch; move on regardless
            if found_iface:
                break
        if found_iface:
            return (switch_host, found_iface)

    return None


def persist_switch_port(mac_address: str, iface: str, switch_host: str = None) -> None:
    """
    Persist a confirmed switch port -> MAC mapping.
    Updates both mac_port_cache and devices.switch_iface.
    """
    from extensions import db as _db
    if not mac_address or not iface:
        return
    try:
        if switch_host is None:
            hosts = get_switch_hosts()
            switch_host = hosts[0] if hosts else ''
        _db.session.execute(
            text("""
                INSERT INTO mac_port_cache (mac_address, switch_iface, switch_host, last_seen)
                VALUES (:mac, :iface, :host, NOW())
                ON CONFLICT (mac_address) DO UPDATE SET
                    switch_iface = EXCLUDED.switch_iface,
                    switch_host  = EXCLUDED.switch_host,
                    last_seen    = EXCLUDED.last_seen
            """),
            {"mac": mac_address, "iface": iface, "host": switch_host},
        )
        _db.session.execute(
            text("""
                UPDATE devices
                SET switch_iface = :iface,
                    switch_iface_seen_at = NOW(),
                    switch_host = :host
                WHERE mac_address = :mac
            """),
            {"iface": iface, "host": switch_host, "mac": mac_address},
        )
        _db.session.commit()
        logger.info("Cached switch port %s for %s", iface, mac_address)
    except Exception as exc:
        logger.warning("Failed to persist switch port for %s: %s", mac_address, exc)
        try:
            _db.session.rollback()
        except Exception:
            pass
