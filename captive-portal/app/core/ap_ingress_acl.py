"""Reconcile one managed HPE 5130 IPv4 ingress ACL on every AP-facing GE port.

Opt-in: AP_INGRESS_ACL_ENABLED=1. Defaults to dry-run even when enabled.
This is supplementary IP enforcement, NOT layer-2 wireless client isolation.
Does not remove or replace other ACLs, router uplink ACLs, or VLAN-interface PBR.
"""

from __future__ import annotations

import csv
from datetime import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time

from sqlalchemy import text

logger = logging.getLogger(__name__)

OWNER = 'BF_AP_INGRESS_MANAGED'
AP_ROLES = ('ap', 'cheapap', 'migration_ap')
LOCK_ID = 5173988
_RULE_START = 10000
_RULE_END = 59999
_TERM_RULE = 60000
_GE = re.compile(r'^(?:GE|GigabitEthernet)1/0/(\d+)$', re.I)
_IPV4 = ipaddress.IPv4Address
_TRUE = ('1', 'yes', 'true', 'on')
_LAST_CHECKED: dict[str, tuple[tuple, float]] = {}
_AUDIT_SECONDS = 300
# Comware displays these well-known ports by name; compare in that form or the
# read-back config never equals the desired rules and the ACL is rewritten
# every cycle.
_PORT_NAMES = {'67': 'bootps', '68': 'bootpc', '53': 'dns', '80': 'www', '123': 'ntp', '69': 'tftp'}


def canon_rule(rule: str) -> str:
    """Normalise an ACL rule body to the form `display current-configuration` uses."""
    tokens = ' '.join(str(rule or '').split()).split(' ')
    for i in range(1, len(tokens)):
        if tokens[i - 1].lower() == 'eq':
            tokens[i] = _PORT_NAMES.get(tokens[i], tokens[i])
    return ' '.join(tokens).lower()


def enabled(name: str, default: str = '0') -> bool:
    return os.getenv(name, default).strip().lower() in _TRUE


def canonical_port(value: str) -> str | None:
    m = _GE.fullmatch(str(value or '').strip())
    return f'GigabitEthernet1/0/{int(m.group(1))}' if m else None


def ipv4(value: str) -> str | None:
    try:
        return str(_IPV4(str(value).strip()))
    except ValueError:
        return None


def normalize_mac(value: str) -> str:
    digits = re.sub(r'[^0-9a-f]', '', str(value or '').lower())
    if len(digits) != 12:
        return ''
    return ':'.join(digits[i:i+2] for i in range(0, 12, 2))


def parse_kea_csv(path: str, now: float | None = None) -> dict[str, tuple[str, int | None, bool]]:
    """Read Kea memfile lease journal: newest row wins for each IP.

    Returns {ipv4: (mac, subnet_id, blocked_pool_unknown)}. Kea subnet_id
    is a DHCP subnet identifier; it must NOT be assumed to equal a VLAN ID.
    """
    now = time.time() if now is None else now
    leases: dict[str, tuple[str, int | None, bool]] = {}
    with open(path, newline='', encoding='utf-8') as file:
        for row in csv.DictReader(file):
            ip = ipv4(row.get('address', ''))
            if ip is None:
                continue
            try:
                expiry = int(row.get('expire', '0'))
                state = int(row.get('state') or '0')
            except (TypeError, ValueError):
                continue
            mac = normalize_mac(row.get('hwaddr', ''))
            if state != 0 or expiry <= now or not mac:
                leases.pop(ip, None)
                continue
            try:
                subnet = int(row.get('subnet_id', ''))
            except (ValueError, TypeError):
                subnet = None
            leases[ip] = (mac, subnet, False)
    return leases


def managed_acl_blocks(config: str, number: int) -> tuple[bool, bool, dict[int, str], dict[str, list[str]]]:
    """Parse Comware current-configuration; fail closed if ACL ownership uncertain."""
    conf = (config or '').replace('\r', '')
    if not re.search(r'(?m)^\s*#\s*$', conf):
        raise ValueError('current-configuration missing Comware # delimiters')
    sections = re.split(r'(?m)^\s*#\s*$', conf)
    found = False
    owned = False
    rules: dict[int, str] = {}
    ports: dict[str, list[str]] = {}
    for section in sections:
        lines = [line.strip() for line in section.strip().splitlines() if line.strip()]
        if not lines:
            continue
        header = lines[0]
        if re.fullmatch(r'acl advanced\s+' + str(number), header, re.I):
            if found:
                raise ValueError(f'Duplicate ACL {number} sections')
            found = True
            owned = f'description {OWNER}' in lines[1:]
            for line in lines[1:]:
                m = re.match(r'^rule\s+(\d+)\s+(.+)$', line, re.I)
                if m:
                    rules[int(m.group(1))] = canon_rule(m.group(2))
        port = canonical_port(header.split(' ', 1)[1]) if header.startswith('interface ') else None
        if port:
            ports[port] = [line for line in lines[1:] if line.startswith('packet-filter ') and re.search(r'\binbound\b', line)]
    return found, owned, rules, ports


def static_rules(portal_ip: str, dns_ip: str) -> dict[int, str]:
    """Allow DHCP + portal services to the two trusted appliance IPs.

    Physical ACL applies regardless of VLAN; allow only service ports, not
    arbitrary LAN hosts. NTP is provided as an optional captive service.
    """
    portal = ipv4(portal_ip)
    dns = ipv4(dns_ip)
    if not portal or not dns:
        raise ValueError('PORTAL_IP and HIJACK_DNS_IP must be IPv4 addresses')
    rules = {
        1: 'permit udp source-port eq bootpc destination-port eq bootps',
        2: 'permit udp source-port eq bootps destination-port eq bootpc',
        3: f'permit udp destination {portal} 0 destination-port eq dns',
        4: f'permit tcp destination {portal} 0 destination-port eq dns',
        5: f'permit udp destination {dns} 0 destination-port eq dns',
        6: f'permit tcp destination {dns} 0 destination-port eq dns',
        7: f'permit tcp destination {portal} 0 destination-port eq www',
        8: f'permit tcp destination {portal} 0 destination-port eq 443',
        9: f'permit tcp destination {dns} 0 destination-port eq 443',
        10: f'permit udp destination {portal} 0 destination-port eq ntp',
        11: f'permit icmp destination {portal} 0',
        12: f'permit tcp destination {portal} 0 destination-port eq 8081',
        13: f'permit tcp destination {portal} 0 destination-port eq 8443',
        14: f'permit icmp destination {dns} 0',
    }
    return {n: canon_rule(r) for n, r in rules.items()}


def ip_rules(ips: set[str]) -> dict[int, str]:
    """Stable rule IDs; deterministically resolve unlikely hash collisions."""
    used: set[int] = set()
    result: dict[int, str] = {}
    capacity = _RULE_END - _RULE_START + 1
    for raw in sorted(ips, key=lambda x: int(_IPV4(x))):
        ip = ipv4(raw)
        if not ip:
            raise ValueError(f'Invalid client IP: {raw!r}')
        seed = int.from_bytes(hashlib.sha256(ip.encode()).digest()[:8], 'big') % capacity
        for n in range(capacity):
            key = _RULE_START + ((seed + n) % capacity)
            if key not in used:
                break
        else:
            raise ValueError('Out of ACL rule identifiers')
        used.add(key)
        result[key] = f'deny ip source {ip} 0'
    return result


def desired_rules(ips: set[str], portal_ip: str, dns_ip: str) -> dict[int, str]:
    return {**static_rules(portal_ip, dns_ip), **ip_rules(ips), _TERM_RULE: 'permit ip'}


def _port_filter_number(filters: list[str], number: int) -> bool:
    return len(filters) == 1 and bool(re.fullmatch(r'packet-filter\s+' + str(number) + r'\s+inbound(?:\s+hardware-count)?', filters[0], re.I))


def build_plan(
    config: str, number: int, wanted_ports: set[str], restricted_ips: set[str],
    portal_ip: str, dns_ip: str,
) -> list[str]:
    """Return newline-ready switch commands. Raises on any ownership conflict.

    Entire host is validated before producing any commands. Existing unrelated
    ingress filters are never modified, and an unowned ACL is never adopted.
    """
    if not 3000 <= number <= 3999:
        raise ValueError('ACL number must be an advanced ACL (3000..3999)')
    found, owned, actual, port_filters = managed_acl_blocks(config, number)
    if found and not owned:
        raise ValueError(f'ACL {number} exists without ownership marker; refusing to modify')
    if found:
        unexpected = [n for n in actual if not (1 <= n <= 99 or _RULE_START <= n <= _RULE_END or n == _TERM_RULE)]
        if unexpected:
            raise ValueError(f'ACL {number} has unexpected rule IDs: {unexpected}')
    valid_ports = set()
    for port in wanted_ports:
        if canonical_port(port) != port:
            raise ValueError(f'Invalid AP port name: {port!r}')
        valid_ports.add(port)
        filters = port_filters.get(port, [])
        if filters and not _port_filter_number(filters, number):
            raise ValueError(f'{port} already has different/multiple IPv4 inbound packet-filter(s): {filters}')
    for port, filters in port_filters.items():
        if len(filters) > 1 and any(re.search(r'\b' + str(number) + r'\b', f) for f in filters):
            raise ValueError(f'{port} has multiple inbound filters; refusing to detach')
    # No reliable AP inventory: do NOT detach a previously installed ACL.
    # A transient empty DB table must not briefly lift client isolation.
    if not valid_ports:
        return []
    desired = desired_rules(restricted_ips, portal_ip, dns_ip)
    changes: list[str] = []
    # Ensure rules are correct before attaching the ACL to a new AP port.
    if not found or desired != actual:
        changes += [f'acl advanced {number}']
        if not found:
            changes += [f'description {OWNER}']
        # Add / replace permits and denies first; delete expired denies second.
        for n in sorted(desired):
            if actual.get(n) != desired[n]:
                if n in actual:
                    changes.append(f'undo rule {n}')
                changes.append(f'rule {n} {desired[n]}')
        for n in sorted(set(actual) - set(desired)):
            changes.append(f'undo rule {n}')
        changes.append('quit')
    # Only attach to ports explicitly marked as APs in switch_ports.
    for port in sorted(valid_ports):
        if not _port_filter_number(port_filters.get(port, []), number):
            changes += [f'interface {port}', f'packet-filter {number} inbound', 'quit']
    # Remove *our* ACL from ports no longer designated as AP uplinks.
    for port in sorted(set(port_filters) - valid_ports):
        if _port_filter_number(port_filters[port], number):
            changes += [f'interface {port}', f'undo packet-filter {number} inbound', 'quit']
    if not changes:
        return []
    # No `save force`: restricted IPs change with every guest lease and the
    # nightly scheduler job already saves startup.cfg. After a switch reboot
    # the reconciler rebuilds the ACL within one interval anyway.
    return ['system-view', *changes, 'quit']


def _check_reserved_acl(number: int) -> None:
    if number in {3000, 3001, 3002, 3999, *range(3951, 3958)}:
        raise ValueError(f'ACL {number} is used by the existing HP5130 baseline')
    policy = os.getenv('HP5130_POLICY_PATH', '/scripts/scriptdata/hp5130-policy.json')
    if not os.path.isfile(policy):
        logger.warning('AP ingress ACL policy file not available: %s; relying on live ACL collision check', policy)
        return
    with open(policy, encoding='utf-8') as file:
        tree = json.load(file)
    conflict_keys = {'isolation_acl', 'uplink_acl', 'acl_number', 'acl_id'}
    def scan(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in conflict_keys and str(v) == str(number):
                    raise ValueError(f'ACL {number} reserved by policy as {k}')
                scan(v)
        elif isinstance(node, list):
            for v in node:
                scan(v)
    scan(tree)
    # The baseline also computes ACL numbers when the JSON omits overrides.
    for vlan in tree.get('vlans', []):
        if int(vlan.get('isolation_acl') or (3000 + 10 * int(vlan['vlan_id']) + 1)) == number:
            raise ValueError(f'ACL {number} used by VLAN {vlan["vlan_id"]} baseline isolation')
    for router in tree.get('routers', []):
        if int(router.get('uplink_acl') or (3950 + int(router['vlan_id']))) == number:
            raise ValueError(f'ACL {number} used by router VLAN {router["vlan_id"]} baseline uplink')


def _infrastructure_ip(ip: str, excluded: set[str]) -> bool:
    if ip in excluded:
        return True
    # Existing deployment addresses management/wired VLANs as NETWORK_WORD.VLAN.host.
    parts = (os.getenv('NETWORK_WORD') or '192.168').strip().split('.')
    if len(parts) == 2:
        octets = ip.split('.')
        if octets[:2] == parts and octets[2] in {
            os.getenv('MANAGEMENT_VLAN', '99'), os.getenv('WIRED_VLAN', '250')
        }:
            return True
    return False


def collect_snapshot(db, get_switch_hosts) -> tuple[dict[str, set[str]], set[str]]:
    """Load AP switch ports and active IPv4 clients; return (ports, restricted IPs)."""
    from models import Device, IPLease, UnregisteredLease

    hosts = set(get_switch_hosts())
    ports: dict[str, set[str]] = {host: set() for host in hosts}
    rows = db.session.execute(text(
        "SELECT switch_host, port_name FROM switch_ports "
        "WHERE port_role IN ('ap', 'cheapap', 'migration_ap')"
    )).all()
    for host, name in rows:
        port = canonical_port(name)
        if host in hosts and port:
            ports[host].add(port)
        elif host in hosts:
            logger.warning('Ignoring invalid AP port name %r on switch %s', name, host)

    now = datetime.utcnow()
    leases: dict[str, tuple[str, int | None, bool]] = {}
    for entry in IPLease.query.filter(IPLease.lease_expiry > now).order_by(IPLease.lease_start).all():
        ip = ipv4(entry.ip_address)
        mac = normalize_mac(entry.mac_address)
        if ip and mac:
            leases[ip] = (mac, entry.vlan_id, bool(entry.from_blocked_pool))
    for entry in UnregisteredLease.query.filter(UnregisteredLease.expires_at > now).all():
        ip = ipv4(entry.ip_address)
        mac = normalize_mac(entry.mac_address)
        if ip and mac and ip not in leases:
            leases[ip] = (mac, None, True)
    # Static/reserved addresses have no Kea lease. Include their known IPs so
    # admin Block can also affect a registered device with a fixed IP.
    for dev in Device.query.filter(Device.fixed_ip.isnot(None)).all():
        ip = ipv4(dev.fixed_ip)
        mac = normalize_mac(dev.mac_address)
        if ip and mac and ip not in leases:
            leases[ip] = (mac, dev.assigned_vlan, False)

    path = os.getenv('AP_INGRESS_ACL_KEA_CSV', '/kea/leases/kea-leases4.csv')
    if os.path.isfile(path):
        try:
            # Kea's lease file is more authoritative than potentially old DB mappings.
            for ip, (mac, subnet, _ignored) in parse_kea_csv(path).items():
                # Retain DB's blocked-pool indication when it describes the
                # same live MAC/IP. Kea's CSV does not record client class.
                db_row = leases.get(ip)
                blocked_pool = bool(db_row and db_row[0] == mac and db_row[2])
                leases[ip] = (mac, None, blocked_pool)
        except (OSError, csv.Error) as e:
            raise RuntimeError(f'Cannot read Kea lease journal {path}: {e}') from e
    else:
        logger.warning('Kea CSV missing at %s: using only DB lease tables', path)

    macs = {row[0] for row in leases.values()}
    devices = {
        normalize_mac(dev.mac_address): dev
        for dev in Device.query.filter(Device.mac_address.in_(list(macs))).all()
    } if macs else {}
    excluded = {ipv4(os.getenv(k, '')) for k in ('PORTAL_IP', 'HIJACK_DNS_IP', 'MGMT_GATEWAY')}
    excluded |= {ipv4(host) for host in hosts}
    restricted: set[str] = set()
    for ip, (mac, vlan, from_blocked_pool) in leases.items():
        if _infrastructure_ip(ip, excluded):
            continue
        # Only DB lease VLAN IDs are VLAN IDs. Kea subnet IDs are not.
        if vlan in (int(os.getenv('MANAGEMENT_VLAN', '99')), int(os.getenv('WIRED_VLAN', '250'))):
            continue
        dev = devices.get(mac)
        user = dev.user if dev else None
        approved = bool(
            dev and not dev.stale and dev.registration_status == 'registered'
            and dev.internet_accessible is True
            and not dev.internet_blocked
            and not from_blocked_pool
            and not (user and (user.blocked or not user.is_active))
        )
        if not approved:
            restricted.add(ip)
    limit = int(os.getenv('AP_INGRESS_ACL_MAX_IPS', '250'))
    if len(restricted) > limit:
        raise RuntimeError(f'{len(restricted)} restricted IPs exceeds limit {limit}; no ACL updated')
    return ports, restricted


def reconcile_once(app) -> None:
    """Only one worker can push switch changes at a time (PostgreSQL advisory lock)."""
    from extensions import db
    from core.switch import get_switch_hosts, run_switch_command

    number = int(os.getenv('AP_INGRESS_ACL_NUMBER', '3988'))
    _check_reserved_acl(number)
    with app.app_context():
        with db.engine.connect() as lock_connection:
            acquired = lock_connection.execute(
                text('SELECT pg_try_advisory_lock(:key)'), {'key': LOCK_ID}
            ).scalar()
            if not acquired:
                return
            try:
                ap_ports, ips = collect_snapshot(db, get_switch_hosts)
                dry_run = enabled('AP_INGRESS_ACL_DRY_RUN', '1')
                for host, ports in sorted(ap_ports.items()):
                    signature = (number, dry_run, tuple(sorted(ports)), tuple(sorted(ips)))
                    previous = _LAST_CHECKED.get(host)
                    if (previous and previous[0] == signature and
                            time.monotonic() - previous[1] < _AUDIT_SECONDS):
                        continue
                    if not ports:
                        logger.warning('No AP ports recorded on %s; leaving existing ACL bindings untouched', host)
                        # An empty AP inventory cannot authorize any detaches.
                        _LAST_CHECKED[host] = (signature, time.monotonic())
                        continue
                    config = run_switch_command(host, 'display current-configuration', disable_paging=True, timeout=120)
                    if not config or not re.search(r'(?m)^\s*#\s*$', config.replace('\r','')):
                        logger.error('Could not reliably read config from %s; skipping update', host)
                        continue
                    try:
                        commands = build_plan(
                            config, number, ports, ips,
                            os.environ['PORTAL_IP'], os.environ['HIJACK_DNS_IP'],
                        )
                    except (ValueError, KeyError) as e:
                        logger.error('Refusing ACL change on %s: %s', host, e)
                        continue
                    if not commands:
                        _LAST_CHECKED[host] = (signature, time.monotonic())
                        continue
                    logger.info('AP ingress ACL %s on %s: %d blocked IP(s), AP ports=%s, commands=%s',
                                'DRY RUN' if dry_run else 'UPDATE', host, len(ips), sorted(ports), commands)
                    if dry_run:
                        _LAST_CHECKED[host] = (signature, time.monotonic())
                        continue
                    result = run_switch_command(host, '\n'.join(commands), disable_paging=True, timeout=180)
                    if not result or re.search(r'(?im)^\s*(?:%\s*)?(?:Error|Invalid|Wrong parameter|Too many rules|Failed)\b', result):
                        logger.error('Switch %s may not have accepted AP ACL update; review output: %.1000s', host, result or '')
                        continue
                    # Re-read before calling this successful: SSH helper can return stdout
                    # even after a non-zero SSH exit code, or switch CLI can reject a rule.
                    after = run_switch_command(host, 'display current-configuration', disable_paging=True, timeout=120)
                    try:
                        pending = build_plan(after or '', number, ports, ips,
                                             os.environ['PORTAL_IP'], os.environ['HIJACK_DNS_IP'])
                    except ValueError as e:
                        logger.error('Could not verify ACL update on %s: %s', host, e)
                        continue
                    if pending:
                        logger.error('ACL update on %s incomplete; %d commands still needed', host, len(pending))
                    else:
                        _LAST_CHECKED[host] = (signature, time.monotonic())
                        logger.info('Verified AP ingress ACL %s on %s', number, host)
            finally:
                lock_connection.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': LOCK_ID})
                db.session.remove()


def start_ap_ingress_acl_reconciler(app) -> None:
    """Start optional periodic reconciliation (user changes/leases/port changes)."""
    if not enabled('AP_INGRESS_ACL_ENABLED'):
        logger.info('AP ingress ACL reconciler disabled (AP_INGRESS_ACL_ENABLED=0)')
        return
    interval = max(5, int(os.getenv('AP_INGRESS_ACL_INTERVAL', '15')))
    def worker():
        while True:
            try:
                reconcile_once(app)
            except Exception:
                logger.exception('AP ingress ACL reconciliation failed (will retry)')
            time.sleep(interval)
    threading.Thread(target=worker, name='ap-ingress-acl', daemon=True).start()
    logger.warning('AP ingress ACL reconciler started: dry_run=%s interval=%ss',
                   enabled('AP_INGRESS_ACL_DRY_RUN', '1'), interval)
