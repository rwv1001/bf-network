"""
Admin — Switch Port Management (spec section 12 / CODEBASE section 8).

Routes:
  GET  /admin/switch-ports                list all switch ports
  POST /admin/switch-ports/refresh        re-discover ports from all switches
  POST /admin/switch-ports/update         bulk role update + push to switch
  POST /admin/switch-ports/update-single  AJAX single-port role update
  POST /admin/switch-ports/update-batch   AJAX multi-port role update, one SSH save per switch
"""

import logging
import os
import re

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import text

from extensions import db
from core.auth import permission_required
from core.switch import (
    COMMON_PORT_UNDO_COMMANDS,
    common_port_undo_commands,
    expand_switch_iface_name, find_switch_port_for_mac,
    get_switch_hosts, normalize_switch_mac, persist_switch_port,
    run_switch_command, switch_port_allowed,
    switch_poe_supported,
)
from core.vlan_utils import get_wired_vlan_id, get_management_vlan_id

logger = logging.getLogger(__name__)

switch_ports_bp = Blueprint('switch_ports', __name__)

PORT_ROLES = {
    'ap':              'AP Uplink',
    'cheapap':         'Cheap AP',
    'migration_ap':    'Migration AP',
    'wired':           'Wired Device',
    'pi':              'Pi / Kea',
    'inter_switch':    'Inter-Switch Link',
    'uplink_udm':      'Uplink to Router',
    'fixed_ip':        'Fixed IP device',
    'unknown':         'Unclassified (VLAN 1, no auth)',
}

# Legacy single button. Kept so existing rows still push a VLAN 2 access port.
LEGACY_MIGRATION_WIRED = 'migration_wired'


def _isp_wired_vlan_ids():
    """ISP VLAN ids that get their own 'wired VLAN N' port button."""
    from models import ISPRouter
    ids = []
    seen = set()
    try:
        rows = ISPRouter.query.order_by(ISPRouter.vlan_id).all()
    except Exception as exc:
        logger.warning("Could not load ISP VLANs for wired-VLAN port roles: %s", exc)
        return []
    for row in rows:
        if row.vlan_id is None:
            continue
        try:
            vlan_id = int(row.vlan_id)
        except (TypeError, ValueError):
            continue
        if vlan_id in seen:
            continue
        seen.add(vlan_id)
        ids.append(vlan_id)
    return ids


def wired_vlan_role_key(vlan_id) -> str:
    return f'wired_vlan_{int(vlan_id)}'


def parse_wired_vlan_role(role):
    """Return the access VLAN for a per-ISP wired role, else None.

    migration_wired is the old single button and always meant VLAN 2.
    """
    if role == LEGACY_MIGRATION_WIRED:
        return 2
    match = re.fullmatch(r'wired_vlan_(\d+)', role or '')
    if not match:
        return None
    return int(match.group(1))


def wired_vlan_description(vlan_id) -> str:
    return f'Migration wired VLAN {int(vlan_id)}'


def _isp_wired_roles():
    """(role_key, button label) for each ISP VLAN, in VLAN order."""
    return [
        (wired_vlan_role_key(vlan_id), f'wired VLAN {vlan_id}')
        for vlan_id in _isp_wired_vlan_ids()
    ]


def port_roles_for_ui():
    """Static roles with one wired-VLAN button per ISP VLAN after Wired Device."""
    roles = {}
    for key, label in PORT_ROLES.items():
        roles[key] = label
        if key == 'wired':
            for role_key, role_label in _isp_wired_roles():
                roles[role_key] = role_label
    return roles


def _role_allowed(role: str) -> bool:
    if role in PORT_ROLES:
        return True
    vlan_id = parse_wired_vlan_role(role)
    return vlan_id is not None and vlan_id in set(_isp_wired_vlan_ids())


# switch_poe_supported is imported from core.switch (supports single value or
# comma-separated list matching SWITCH_HOSTS order).


ROLE_PURPOSES = {
    'ap': (
        'UniFi AP uplink. User and ISP VLANs are tagged; the management VLAN '
        'is the untagged native VLAN. MAC authentication and IP source guard '
        'are off, so the AP can bridge every SSID. ' + ('PoE is enabled.' if switch_poe_supported() else 'PoE commands are omitted (SWITCH_POE=no).')
    ),
    'cheapap': (
        'Cheap AP that does not tag VLANs. VLAN 2, the user VLANs, management '
        'and the wired VLAN are all untagged, with the wired VLAN as PVID. '
        'MAC authentication (up to 256 clients) and IP source guard are on. ' + ('PoE is enabled.' if switch_poe_supported() else 'PoE commands are omitted (SWITCH_POE=no).')
    ),
    'migration_ap': (
        'Migration AP. Native VLAN is 2, so a UniFi SSID on VLAN 2 leaves the '
        'port untagged; every other SSID stays tagged. MAC authentication and '
        'IP source guard are off so PVID 2 is not overridden. ' + ('PoE is enabled.' if switch_poe_supported() else 'PoE commands are omitted (SWITCH_POE=no).')
    ),
    'wired': (
        'Normal wired device. Hybrid port with the user VLANs untagged and the '
        'wired unregistered VLAN as PVID and MAC-auth guest VLAN. MAC '
        'authentication (16 clients) and IP source guard are on.'
    ),
    'pi': (
        'Trunk to the Pi running Kea. ISP, user, management and wired VLANs '
        'are tagged. The native VLAN is an unused VLAN so every Pi '
        'subinterface stays tagged. DHCP snooping and ARP detection trust this port.'
    ),
    'inter_switch': (
        'Link to another switch. Trunk carrying the user, management, wired '
        'and ISP VLANs, native VLAN 2. DHCP snooping and ARP detection trust this port.'
    ),
    'uplink_udm': (
        'Uplink toward the router. Trunk permitting VLAN 2 and any external '
        'VLANs; DHCP snooping trusts the port. This role is set on the ISP '
        'routers page, not from here.'
    ),
    'fixed_ip': (
        'Port reserved for a device with a fixed IP. The role and port config '
        'are applied from the Fixed IPs section of the dashboard, not from here.'
    ),
    'unknown': (
        'Unclassified. Clears authentication, VLAN membership and the other '
        'role-specific commands (the common undo block) and leaves the port '
        'on the default VLAN with no MAC authentication.'
    ),
}


def role_purpose(role: str) -> str:
    vlan_id = parse_wired_vlan_role(role)
    if vlan_id is not None:
        return (
            f'Wired access port on ISP VLAN {vlan_id}, with no MAC authentication '
            f'or IP source guard. For a host that is still on that ISP LAN. '
            f'This is what the old Migration Wired button did, for VLAN {vlan_id} '
            f'instead of only VLAN 2.'
        )
    return ROLE_PURPOSES.get(role, role)


def interface_config_preview(role: str) -> str:
    """Interface commands update-single would push for this role.

    Drops the system-view / quit / save force wrapper. Uses GE1/0/x as the
    sample interface name; the real port name is substituted on apply.
    """
    raw = _build_port_config('GE1/0/x', role, '')
    kept = [
        line for line in raw.splitlines()
        if line not in ('system-view', 'quit', 'save force')
    ]
    return '\n'.join(kept)


def role_hints_for_ui(roles):
    hints = {}
    for role in roles:
        try:
            config = interface_config_preview(role)
        except Exception as exc:
            logger.warning('Role preview failed for %s: %s', role, exc)
            config = '(config preview unavailable)'
        hints[role] = {'purpose': role_purpose(role), 'config': config}
    return hints


# ---------------------------------------------------------------------------
# Port discovery helpers
# ---------------------------------------------------------------------------

def _detect_port_role(port_name: str, description: str) -> str:
    """Infer a port role from its name and description using keyword heuristics."""
    desc = (description or '').lower()
    if 'udm' in desc or 'usg' in desc:
        return 'uplink_udm'
    if 'migration' in desc and 'ap' in desc:
        return 'migration_ap'
    if 'migration' in desc and 'wired' in desc:
        vlan_match = re.search(r'vlan\s*(\d+)', desc)
        if vlan_match:
            return wired_vlan_role_key(int(vlan_match.group(1)))
        return wired_vlan_role_key(2)
    if ('unifi' in desc and 'ap' in desc) or \
       desc.endswith(' ap') or ' ap ' in desc or \
       '-ap' in desc or desc.startswith('ap'):
        return 'ap'
    if 'cheap' in desc and 'ap' in desc:
        return 'cheapap'
    if 'pi' in desc or 'kea' in desc or 'portal' in desc:
        return 'pi'
    if 'inter-switch' in desc or 'inter switch' in desc or 'isl' in desc:
        return 'inter_switch'
    if desc.strip():
        return 'wired'
    return 'unknown'


def _discover_switch_ports(switch_host: str) -> list:
    """Discover physical GE/XGE ports from a Comware 7 switch.

    Prefer ``display interface brief``: it lists ports that actually exist,
    including XGE1/0/49-52 on 48+4 models and XGE1/0/25-28 on 24+4
    models, whether or not those ports have saved configuration.

    Older firmware/SSH output that cannot be parsed falls back to targeted
    interface state probes, then obtains the full descriptions as before.
    Discovery is read-only and does not change port roles or switch config.
    """
    def _shorten(name):
        if name.startswith('GigabitEthernet'):
            return 'GE' + name[len('GigabitEthernet'):]
        if name.startswith('Ten-GigabitEthernet'):
            return 'XGE' + name[len('Ten-GigabitEthernet'):]
        return name

    def _expand(name):
        if name.startswith('XGE'):
            return 'Ten-GigabitEthernet' + name[3:]
        if name.startswith('GE'):
            return 'GigabitEthernet' + name[2:]
        return name

    def _iface_sort_key(name):
        short = _shorten(name)
        nums = tuple(int(x) for x in re.findall(r'\d+', short))
        return (1 if short.startswith('XGE') else 0, nums)

    def _link_status(raw):
        state = (raw or 'UNKNOWN').strip().upper()
        if state.startswith('ADM'):
            return 'ADMDOWN'
        if state.startswith('UP'):
            return 'UP'
        if 'DOWN' in state:
            return 'DOWN'
        return state[:10]

    def _split_by_prompts(output):
        parts = re.split(r'<[A-Za-z][^>\n]{0,40}>', output or '')
        sections = []
        for part in parts[1:]:
            lines = part.replace('\r', '').split('\n')
            # The first line after the prompt is the echoed command.
            body = '\n'.join(l for l in lines[1:] if l.strip())
            sections.append(body)
        return sections

    # Parse the *actual interface list* before trying any guessed numbers.
    # Comware normally abbreviates these as GE1/0/1 and XGE1/0/49.
    brief = run_switch_command(switch_host, 'display interface brief',
                               disable_paging=True) or ''
    row = re.compile(
        r'^\s*((?:Ten-GigabitEthernet|GigabitEthernet|XGE|GE)'
        r'\d+/\d+/\d+)\s+(UP|DOWN|ADM|ADMDOWN|STBY)\b',
        re.IGNORECASE,
    )
    existing = {}
    for line in brief.replace('\r', '').splitlines():
        m = row.match(line)
        if m:
            existing[_expand(m.group(1))] = _link_status(m.group(2))

    if not existing:
        # Fallback for a switch that rejects/truncates 'display interface brief'.
        # Include both 24+4 and 48+4 XGE numbering schemes, not just XGE1-4.
        max_slot = int(os.getenv('SWITCH_MAX_SLOT', '8'))
        ge_max = int(os.getenv('SWITCH_GE_MAX', '52'))
        xge_max = int(os.getenv('SWITCH_XGE_MAX', '4'))
        slot_cmds = '\n'.join(
            f'display current-configuration | include interface | include GigabitEthernet{s}/0/1'
            for s in range(1, max_slot + 1)
        )
        slot_output = run_switch_command(switch_host, slot_cmds) or ''
        detected_slots = set()
        for line in slot_output.splitlines():
            m = re.search(r'^\s*interface GigabitEthernet(\d+)/', line)
            if m:
                detected_slots.add(int(m.group(1)))
        if not detected_slots:
            logger.warning('No switch slots detected on %s', switch_host)
            return []

        candidates = []
        xge_numbers = set(range(1, xge_max + 1))
        for base in (24, 48, ge_max):
            xge_numbers.update(range(base + 1, base + xge_max + 1))
        for slot in sorted(detected_slots):
            candidates.extend(f'GigabitEthernet{slot}/0/{n}'
                              for n in range(1, ge_max + 1))
            candidates.extend(f'Ten-GigabitEthernet{slot}/0/{n}'
                              for n in sorted(xge_numbers))
        state_cmds = '\n'.join(
            f'display interface {name} | include state' for name in candidates
        )
        sections = _split_by_prompts(run_switch_command(switch_host, state_cmds) or '')
        for name, section in zip(candidates, sections):
            if '% ' in section or 'Wrong' in section or 'Error' in section:
                continue
            m = re.search(r'Current state:\s*(\S+(?:\s+\S+)?)',
                          section, re.IGNORECASE)
            if m:
                existing[name] = _link_status(m.group(1))

    if not existing:
        logger.warning('No ports found via interface discovery on %s', switch_host)
        return []

    # Full descriptions are queried separately (brief descriptions truncate).
    names = sorted(existing, key=_iface_sort_key)
    commands = '\n'.join(
        f'display interface {name} | include Description' for name in names
    )
    sections = _split_by_prompts(run_switch_command(switch_host, commands) or '')
    ports = []
    for i, name in enumerate(names):
        description = ''
        if i < len(sections):
            for line in sections[i].splitlines():
                if 'Description:' in line:
                    description = line.split('Description:', 1)[1].strip()
                    break
        if description.endswith(' Interface') and 'Ethernet' in description:
            description = ''
        ports.append({
            'port_name': _shorten(name),
            'link_status': existing[name],
            'description': description,
        })

    logger.info('Discovered %d ports on %s', len(ports), switch_host)
    return ports


def refresh_switch_ports() -> dict:
    """
    Discover all switches and upsert ports into switch_ports table.
    Preserves manually-set roles (only auto-assigns when role is 'unknown').
    Returns dict: {switch_host: port_count_or_error_string}
    """
    switch_hosts = get_switch_hosts()
    if not switch_hosts:
        return {}

    results = {}
    for host in switch_hosts:
        ports = _discover_switch_ports(host)
        if not ports:
            results[host] = 'no ports discovered (check SSH)'
            continue
        for p in ports:
            auto_role = _detect_port_role(p['port_name'], p['description'])
            db.session.execute(
                text("""
                    INSERT INTO switch_ports
                        (switch_host, port_name, port_description, port_role,
                         link_status, last_discovered, last_updated)
                    VALUES (:host, :name, :desc, :role, :link, NOW(), NOW())
                    ON CONFLICT (switch_host, port_name) DO UPDATE SET
                        port_description = EXCLUDED.port_description,
                        link_status      = EXCLUDED.link_status,
                        last_discovered  = EXCLUDED.last_discovered,
                        port_role = CASE
                            WHEN switch_ports.port_role = 'unknown'
                            THEN EXCLUDED.port_role
                            ELSE switch_ports.port_role
                        END
                """),
                {
                    'host': host,
                    'name': p['port_name'],
                    'desc': p['description'],
                    'role': auto_role,
                    'link': p['link_status'],
                }
            )
        db.session.commit()
        results[host] = len(ports)

    return results


def _get_locked_ports() -> dict:
    """'switch_host|port_name' -> lock label.

    Roles set on another page cannot be changed here. The host is part of the
    key: GE1/0/47 on switch A is not the ISP uplink just because GE1/0/47 on
    switch B is.
    """
    from models import ISPRouter, Device
    locked = {}
    for r in ISPRouter.query.filter(ISPRouter.switch_port.isnot(None)).all():
        if r.switch_port and r.switch_host:
            locked[f"{r.switch_host}|{r.switch_port}"] = f"ISP {r.name}"
    for d in Device.query.filter(Device.fixed_ip.isnot(None), Device.fixed_ip != '').all():
        if d.switch_iface and d.switch_host:
            locked[f"{d.switch_host}|{d.switch_iface}"] = f"Fixed IP {d.mac_address}"
    return locked


def _build_port_config(port_name: str, role: str, description: str = '', switch_host: str | None = None) -> str:
    """Build the complete HP5130 config command block for a given port role."""
    from models import ISPRouter
    from core.switch import COMMON_PORT_UNDO_COMMANDS, expand_switch_iface_name

    expanded = expand_switch_iface_name(port_name)

    wired_vlan = str(get_wired_vlan_id())
    mgmt_vlan  = str(get_management_vlan_id())

    # VALID_VLANS env var: comma-separated VLAN IDs that may appear on the
    # hybrid or trunk ports (defaults cover all current / future usable VLANs).
    possible_vlans_raw = os.getenv('VALID_VLANS', '10,20,30,40,50,60,70,80,90')
    vlans_list = ' '.join(v for v in possible_vlans_raw.split(',') if v.strip())
    # EXTERNAL_VLANS: upstream-DHCP VLANs carried on trunks / AP uplinks
    external_vlans_raw = os.getenv('EXTERNAL_VLANS', '')
    external_vlans_list = ' '.join(v for v in external_vlans_raw.split(',') if v.strip())
    # ISP_VLANS: VLANs for ISP routers (e.g. old ISP LAN) that should be tagged
    # on AP uplinks so an SSID in that VLAN can still reach the ISP DHCP server.
    isp_vlans_env = [v.strip() for v in os.getenv('ISP_VLANS', '').split(',') if v.strip()]

    CANONICAL_DESC = {
        'ap':              'Uplink to UniFi AP',
        'cheapap':         'Cheap AP',
        'migration_ap':    'Migration AP (VLAN 2 native)',
        'wired':           'wired port',
        'pi':              'TRUNK-TO-PI-Kea',
        'inter_switch':    'Inter-switch link',
        'uplink_udm':      'TRUNK-TO-UDM',
        'unknown':         '',
    }
    wired_vlan_id = parse_wired_vlan_role(role)
    if wired_vlan_id is not None:
        CANONICAL_DESC[role] = wired_vlan_description(wired_vlan_id)
    # Role-specific canonical takes priority; only unknown falls back to existing desc.
    canonical = CANONICAL_DESC.get(role, '')
    desc = canonical if canonical else (description or '').strip()

    head = ['system-view', f'interface {expanded}']

    # Common cleanup. PoE undo is omitted when this switch does not support PoE
    # — Comware rejects 'undo poe enable' on a switch with no PoE.
    body = common_port_undo_commands(switch_host)

    if role == 'wired':
        wired_untagged = vlans_list
        if external_vlans_list:
            wired_untagged = f'{vlans_list} {external_vlans_list}'.strip()
        try:
            isp_untagged = [
                str(r.vlan_id)
                for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()
                if r.vlan_id is not None and int(r.vlan_id) != 2
            ]
        except Exception:
            isp_untagged = []
        if isp_untagged:
            wired_untagged = f'{wired_untagged} {" ".join(isp_untagged)}'.strip()
        body.extend([
            'mac-authentication',
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',
            'undo port hybrid vlan 2',
            f'port hybrid vlan {wired_untagged} untagged',
            f'port hybrid vlan {mgmt_vlan} untagged',
            f'port hybrid vlan {wired_vlan} untagged',
            f'port hybrid pvid vlan {wired_vlan}',
            'mac-vlan enable',
            'mac-authentication',
            'ip verify source ip-address mac-address',
            'mac-authentication max-user 16',
            'mac-authentication domain macauth',
            f'mac-authentication guest-vlan {wired_vlan}',
            'mac-authentication host-mode multi-vlan',            
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
        ])

    elif role == 'ap':
        ap_tagged = vlans_list
        if external_vlans_list:
            ap_tagged = f'{vlans_list} {external_vlans_list}'.strip()
        try:
            isp_tagged = [
                str(r.vlan_id)
                for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()
                if r.vlan_id is not None
            ]
        except Exception:
            isp_tagged = []
        # Always include ISP_VLANS from .env (e.g. '2' for legacy ISP LAN SSID)
        for v in isp_vlans_env:
            if v not in isp_tagged:
                isp_tagged.append(v)
        if isp_tagged:
            ap_tagged = f'{ap_tagged} {" ".join(isp_tagged)}'.strip()
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',
            f'port hybrid vlan {ap_tagged} tagged',
            f'port hybrid vlan {mgmt_vlan} untagged',
            f'port hybrid pvid vlan {mgmt_vlan}',
            'undo mac-vlan enable',
            'undo mac-authentication',
            'undo ip verify source',
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
            'stp edged-port',
            *(['poe enable'] if switch_poe_supported(switch_host) else []),
        ])

    elif role == 'migration_ap':
        # Native VLAN 2 so a UniFi SSID on VLAN 2 is untagged. Other SSIDs
        # stay tagged. No MAC-auth / IPSG so PVID 2 is not overridden.
        ap_tagged = vlans_list
        if external_vlans_list:
            ap_tagged = f'{ap_tagged} {external_vlans_list}'.strip()
        try:
            isp_tagged = [
                str(r.vlan_id)
                for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()
                if r.vlan_id is not None and int(r.vlan_id) != 2
            ]
        except Exception:
            isp_tagged = []
        if isp_tagged:
            ap_tagged = f'{ap_tagged} {" ".join(isp_tagged)}'.strip()
        untagged = []
        if mgmt_vlan and mgmt_vlan != '2' and mgmt_vlan not in untagged:
            untagged.append(mgmt_vlan)
        if wired_vlan and wired_vlan != '2' and wired_vlan not in untagged:
            untagged.append(wired_vlan)
        untagged_str = ' '.join(untagged)
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',
            'undo port hybrid vlan 2',
            f'port hybrid vlan {ap_tagged} tagged',
            f'port hybrid vlan {untagged_str} untagged',
            'port hybrid pvid vlan 2',
            'mac-vlan enable',
            'undo mac-authentication',
            'undo ip verify source',
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
            *(['poe enable'] if switch_poe_supported(switch_host) else []),
        ])

    elif role == 'cheapap':
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',            
            f'port hybrid vlan 2 {vlans_list} {mgmt_vlan} {wired_vlan} untagged',
            f'port hybrid pvid vlan {wired_vlan}',
            'mac-vlan enable',
            'ip verify source ip-address mac-address',
            'mac-authentication',
            'mac-authentication max-user 256',
            'mac-authentication domain macauth',
            f'mac-authentication guest-vlan {wired_vlan}',
            'mac-authentication host-mode multi-vlan',
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
            *(['poe enable'] if switch_poe_supported(switch_host) else []),
        ])

    elif parse_wired_vlan_role(role) is not None:
        # Access port on one ISP VLAN, no MAC-auth. Same as the old
        # migration_wired role, which was hardcoded to VLAN 2.
        access_vlan = parse_wired_vlan_role(role)
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            f'port access vlan {access_vlan}',
            'undo mac-authentication',
            'undo ip verify source',
            'undo mac-vlan',
        ])

    elif role == 'pi':
        try:
            isp_vlan_str = ' '.join(
                str(r.vlan_id)
                for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()
                if r.vlan_id is not None
            )
        except Exception:
            isp_vlan_str = '2'
        if not isp_vlan_str:
            isp_vlan_str = '2'
        # Unused native VLAN so every Pi subinterface stays tagged.
        pi_native = str(os.getenv('PI_TRUNK_NATIVE_VLAN', '1028'))
        body.extend([
            f'vlan {pi_native}',
            f'name pi-trunk-native',
        ])
        pi_cmds = [
            f'interface {expanded}',
            'port link-type access',
            'port link-type trunk',
            'undo port trunk permit vlan 2',
            f'port trunk permit vlan {isp_vlan_str}',
            f'port trunk permit vlan {vlans_list}',
            f'port trunk permit vlan {mgmt_vlan} {wired_vlan}',
            f'port trunk permit vlan {pi_native}',
        ]
        if external_vlans_list:
            pi_cmds.append(f'port trunk permit vlan {external_vlans_list}')
        pi_cmds.extend([
            f'port trunk pvid vlan {pi_native}',
            'arp detection trust',
            'dhcp snooping trust',
        ])
        body.extend(pi_cmds)

    elif role == 'uplink_udm':
        uplink_cmds = [
            f'interface {expanded}',
            'port link-type access',
            'port link-type trunk',
            'port trunk permit vlan 2',
        ]
        if external_vlans_list:
            uplink_cmds.append(f'port trunk permit vlan {external_vlans_list}')
        uplink_cmds.append('dhcp snooping trust')
        body.extend(uplink_cmds)

    elif role == 'inter_switch':
        try:
            isp_vlan_ids = [str(r.vlan_id) for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()]
        except Exception:
            isp_vlan_ids = ['2']
        isp_vlan_str = ' '.join(isp_vlan_ids) if isp_vlan_ids else '2'
        inter_cmds = [
            f'interface {expanded}',
            'port link-type access',
            'port link-type trunk',
            f'port trunk permit vlan {vlans_list}',
            f'port trunk permit vlan {mgmt_vlan} {wired_vlan}',
            f'port trunk permit vlan {isp_vlan_str}',
        ]
        if external_vlans_list:
            inter_cmds.append(f'port trunk permit vlan {external_vlans_list}')
        inter_cmds.extend([
            'port trunk pvid vlan 2',
            'arp detection trust',
            'dhcp snooping trust',
        ])
        body.extend(inter_cmds)

    if desc:
        body.extend([
            f'interface {expanded}',
            f'description {desc}',
        ])
    # unknown role → just apply the common undos + description (if any)
    return '\n'.join(head + body + ['quit', 'quit', 'save force'])

    
def refresh_pi_trunk_vlans() -> None:
    """Re-push every port with role 'pi' so ISP VLANs stay on the Kea trunk."""
    rows = db.session.execute(
        text("""
            SELECT switch_host, port_name, port_description
            FROM switch_ports
            WHERE port_role = 'pi'
        """)
    ).fetchall()
    for host, port_name, desc in rows:
        cmds = _build_port_config(port_name, 'pi', desc or '', switch_host=host)
        result = run_switch_command(host, cmds)
        if result is None:
            logger.warning("Failed to refresh Pi trunk on %s %s", host, port_name)
        else:
            logger.info("Refreshed Pi trunk VLANs on %s %s", host, port_name)



def refresh_ap_poe() -> None:
    """Re-push every AP-role port so PoE enable/disable matches SWITCH_POE in .env.

    Called on web container startup. Changing SWITCH_POE and restarting the
    web container is then sufficient to enable or disable PoE on all AP ports.
    """
    ap_roles = ('ap', 'cheapap', 'migration_ap')
    rows = db.session.execute(
        text("""
            SELECT switch_host, port_name, port_role, port_description
            FROM switch_ports
            WHERE port_role = ANY(:roles)
        """),
        {'roles': list(ap_roles)},
    ).fetchall()
    for host, port_name, role, desc in rows:
        try:
            cmds = _build_port_config(port_name, role, desc or '', switch_host=host)
            result = run_switch_command(host, cmds)
            if result is None:
                logger.warning("Failed to refresh PoE on %s %s (%s)", host, port_name, role)
            else:
                logger.info("Refreshed PoE on %s %s (%s)", host, port_name, role)
        except Exception as exc:
            logger.warning("Error refreshing PoE on %s %s: %s", host, port_name, exc)
    


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@switch_ports_bp.route('/switch-ports')
@login_required
@permission_required('manage_switch_ports')
def list_switch_ports():
    switch_hosts = get_switch_hosts()

    ports_by_switch = {}
    for host in switch_hosts:
        rows = db.session.execute(
            text("""
                SELECT port_name, port_description, port_role, link_status, last_discovered, notes
                FROM switch_ports
                WHERE switch_host = :host
                ORDER BY
                    (CASE WHEN port_name LIKE 'XGE%' THEN 1 ELSE 0 END),
                    split_part(port_name, '/', 1),
                    CAST(NULLIF(split_part(port_name, '/', 2), '') AS INTEGER),
                    CAST(NULLIF(split_part(port_name, '/', 3), '') AS INTEGER)
            """),
            {'host': host}
        ).fetchall()
        ports_by_switch[host] = [
            {
                'port_name':        r[0],
                'port_description': r[1] or '',
                'port_role':        r[2] or 'unknown',
                'link_status':      r[3] or 'unknown',
                'last_discovered':  r[4],
                'notes':            r[5] or '',
            }
            for r in rows
        ]

    return render_template(
        'admin_switch_ports.html',
        ports_by_switch=ports_by_switch,
        switch_hosts=switch_hosts,
        port_roles=port_roles_for_ui(),
        role_hints=role_hints_for_ui(port_roles_for_ui()),
        locked_ports=_get_locked_ports(),
    )


@switch_ports_bp.route('/switch-ports/refresh', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def refresh():
    results = refresh_switch_ports()
    for host, result in results.items():
        if isinstance(result, int):
            flash(f"{host}: discovered {result} ports", 'success')
        else:
            flash(f"{host}: {result}", 'warning')
    return redirect(url_for('admin.switch_ports.list_switch_ports'))


@switch_ports_bp.route('/switch-ports/update', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def update():
    """Save role changes and push canonical descriptions back to the switches."""
    updates = {}
    for key, role in request.form.items():
        if not key.startswith('role_'):
            continue
        m = re.match(r'^role_(\d+\.\d+\.\d+\.\d+)_(.+)$', key)
        if not m:
            continue
        host, port = m.group(1), m.group(2)
        if _role_allowed(role):
            updates[(host, port)] = role

    if not updates:
        flash('No changes submitted.', 'info')
        return redirect(url_for('admin.switch_ports.list_switch_ports'))

    ROLE_DESC = {
        'ap':              'Uplink to UniFi AP',
        'cheapap':         'Cheap AP',
        'migration_ap':    'Migration AP (VLAN 2 native)',
        'wired':           'wired port',
        'pi':              'TRUNK-TO-PI-Kea',
        'inter_switch':    'Inter-switch link',
        'uplink_udm':      'TRUNK-TO-UDM',
        'unknown':         None,
    }
    for vlan_id in _isp_wired_vlan_ids():
        ROLE_DESC[wired_vlan_role_key(vlan_id)] = wired_vlan_description(vlan_id)
    ROLE_DESC[LEGACY_MIGRATION_WIRED] = wired_vlan_description(2)

    changed = 0
    for (host, port_name), role in updates.items():
        existing = db.session.execute(
            text("SELECT port_role FROM switch_ports WHERE switch_host=:h AND port_name=:p"),
            {'h': host, 'p': port_name}
        ).fetchone()
        if existing and existing[0] == role:
            continue

        db.session.execute(
            text("""
                UPDATE switch_ports
                SET port_role = :role, last_updated = NOW()
                WHERE switch_host = :host AND port_name = :name
            """),
            {'role': role, 'host': host, 'name': port_name}
        )
        changed += 1

        desc = ROLE_DESC.get(role)
        if desc:
            expanded = expand_switch_iface_name(port_name)
            cmds = '\n'.join([
                'system-view',
                f'interface {expanded}',
                f'description {desc}',
                'quit',
                'quit',
                'save force',
            ])
            try:
                result = run_switch_command(host, cmds)
                if result is not None:
                    logger.info("Pushed description '%s' → %s %s", desc, host, expanded)
                else:
                    logger.warning("Failed to push description to %s %s", host, port_name)
            except Exception as exc:
                logger.warning("Failed to push description to %s %s: %s", host, port_name, exc)

    db.session.commit()

    if changed:
        flash(f'Updated {changed} port role(s).', 'success')
    else:
        flash('No changes (selected roles already matched).', 'info')

    return redirect(url_for('admin.switch_ports.list_switch_ports'))



def _canonical_description(role: str, existing_desc: str = '') -> str:
    canonical = {
        'ap': 'Uplink to UniFi AP',
        'cheapap': 'Cheap AP',
        'migration_ap': 'Migration AP (VLAN 2 native)',
        'wired': 'wired port',
        'pi': 'TRUNK-TO-PI-Kea',
        'inter_switch': 'Inter-switch link',
        'uplink_udm': 'TRUNK-TO-UDM',
    }
    wired_vlan_id = parse_wired_vlan_role(role)
    if wired_vlan_id is not None:
        canonical[role] = wired_vlan_description(wired_vlan_id)
    return canonical.get(role) or existing_desc or ''


def _interface_block(port_name: str, role: str, description: str = '', switch_host: str | None = None) -> str:
    """Interface commands for one port, without the system-view / save wrapper."""
    lines = _build_port_config(port_name, role, description, switch_host=switch_host).splitlines()
    if lines and lines[0] == 'system-view':
        lines = lines[1:]
    while lines and lines[-1] in ('quit', 'save force'):
        lines.pop()
    lines.append('quit')
    return '\n'.join(lines)


@switch_ports_bp.route('/switch-ports/update-batch', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def update_batch():
    """Apply several staged role changes, one SSH session and save per switch."""
    data = request.get_json(silent=True) or {}
    changes = data.get('changes') or []
    if not isinstance(changes, list) or not changes:
        return jsonify({'success': False, 'error': 'No changes', 'results': []})

    locked = _get_locked_ports()
    prepared = []
    results = []
    for item in changes:
        if not isinstance(item, dict):
            continue
        host = (item.get('host') or '').strip()
        port_name = (item.get('port') or '').strip()
        role = (item.get('role') or '').strip()
        base = {'host': host, 'port': port_name, 'role': role}
        if not host or not port_name or (role and not _role_allowed(role)):
            results.append({**base, 'success': False, 'error': 'Invalid request'})
            continue
        if role and (f"{host}|{port_name}" in locked or role == 'fixed_ip'):
            results.append({**base, 'success': False, 'error': 'Port is locked'})
            continue
        if not role and 'notes' not in item:
            results.append({**base, 'success': False, 'error': 'Invalid request'})
            continue
        row = db.session.execute(
            text("SELECT port_description, port_role FROM switch_ports "
                 "WHERE switch_host=:h AND port_name=:p"),
            {'h': host, 'p': port_name}
        ).fetchone()
        if not row:
            results.append({**base, 'success': False, 'error': 'Port not found in DB'})
            continue
        existing_desc, existing_role = row
        notes = item.get('notes')
        if notes is not None:
            notes = str(notes)[:200]
        if (not role or existing_role == role) and notes is None:
            results.append({**base, 'success': True, 'description': existing_desc or '', 'message': 'No change'})
            continue
        prepared.append({
            'notes': notes,
            'host': host,
            'port': port_name,
            'role': role,
            'existing_desc': existing_desc or '',
        })

    by_host = {}
    for item in prepared:
        by_host.setdefault(item['host'], []).append(item)

    CHUNK_SIZE = 4  # Keep each SSH session short so it finishes well under typical web/proxy timeouts
    for host, items in by_host.items():
        role_items = [item for item in items if item.get('role')]
        notes_only = [item for item in items if not item.get('role') and item.get('notes') is not None]

        # Process role changes in small chunks so a timeout cannot leave a large
        # half-applied config. Each chunk is saved before the next starts.
        for i in range(0, len(role_items), CHUNK_SIZE):
            chunk = role_items[i:i + CHUNK_SIZE]
            blocks = [
                _interface_block(item['port'], item['role'], item['existing_desc'], switch_host=host)
                for item in chunk
            ]
            cmds = '\n'.join(['system-view', *blocks, 'quit', 'save force'])
            pushed = run_switch_command(host, cmds, timeout=180)
            for item in chunk:
                if pushed is None:
                    results.append({
                        'host': host, 'port': item['port'], 'role': item['role'],
                        'success': False, 'error': f'SSH to {host} failed or timed out',
                    })
                    continue
                new_desc = _canonical_description(item['role'], item['existing_desc'])
                sets = ['port_role = :role', 'port_description = :desc', 'last_updated = NOW()']
                params = {'role': item['role'], 'desc': new_desc, 'host': host, 'name': item['port']}
                if item.get('notes') is not None:
                    sets.append('notes = :notes')
                    params['notes'] = item['notes']
                db.session.execute(
                    text(f"""
                        UPDATE switch_ports
                        SET {', '.join(sets)}
                        WHERE switch_host = :host AND port_name = :name
                    """),
                    params,
                )
                results.append({
                    'host': host, 'port': item['port'], 'role': item['role'],
                    'success': True, 'description': new_desc, 'notes': item.get('notes'),
                })
                logger.info("Admin set %s %s role=%s (batch chunk)", host, item['port'], item['role'])
            if pushed is not None:
                db.session.commit()

        # Notes-only updates (no role change) — no SSH needed
        for item in notes_only:
            db.session.execute(
                text("""
                    UPDATE switch_ports
                    SET notes = :notes, last_updated = NOW()
                    WHERE switch_host = :host AND port_name = :name
                """),
                {'notes': item['notes'], 'host': host, 'name': item['port']},
            )
            results.append({
                'host': host, 'port': item['port'], 'role': '',
                'success': True, 'description': item['existing_desc'], 'notes': item['notes'],
            })
            logger.info("Admin set notes on %s %s (batch)", host, item['port'])
        if notes_only:
            db.session.commit()

    return jsonify({'success': all(r.get('success') for r in results), 'results': results})


@switch_ports_bp.route('/switch-ports/update-single', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def update_single():
    """AJAX endpoint: update one port's role and push full config to the switch."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON body'})

    host      = (data.get('host', '') or '').strip()
    port_name = (data.get('port', '') or '').strip()
    role      = (data.get('role', '') or '').strip()

    if not host or not port_name or not _role_allowed(role):
        return jsonify({'success': False, 'error': 'Invalid request'})

    locked = _get_locked_ports()
    lock_key = f"{host}|{port_name}"
    if lock_key in locked:
        label = locked[lock_key]
        if label.startswith('Fixed IP'):
            hint = 'Change it in the dashboard Fixed IPs section.'
        else:
            hint = 'Change it on the ISP Routers page.'
        return jsonify({
            'success': False,
            'error': f'Port is locked ({label}). {hint}',
        })

    if role == 'fixed_ip':
        return jsonify({
            'success': False,
            'error': 'Fixed-IP ports are set on the dashboard Fixed IPs section.',
        })

    row = db.session.execute(
        text("SELECT port_description, port_role FROM switch_ports "
             "WHERE switch_host=:h AND port_name=:p"),
        {'h': host, 'p': port_name}
    ).fetchone()
    if not row:
        return jsonify({'success': False, 'error': 'Port not found in DB'})

    existing_desc, existing_role = row
    if existing_role == role:
        return jsonify({'success': True, 'message': 'No change needed', 'description': existing_desc or '', 'role': role})

    cmds = _build_port_config(port_name, role, existing_desc, switch_host=host)
    result = run_switch_command(host, cmds)
    if result is None:
        return jsonify({'success': False, 'error': f'SSH to {host} failed'})

    _CANONICAL_DESC = {
        'ap': 'Uplink to UniFi AP', 'cheapap': 'Cheap AP',
        'migration_ap': 'Migration AP (VLAN 2 native)',
        'wired': 'wired port',
        'pi': 'TRUNK-TO-PI-Kea', 'inter_switch': 'Inter-switch link',
        'uplink_udm': 'TRUNK-TO-UDM',
    }
    wired_vlan_id = parse_wired_vlan_role(role)
    if wired_vlan_id is not None:
        _CANONICAL_DESC[role] = wired_vlan_description(wired_vlan_id)
    new_desc = _CANONICAL_DESC.get(role) or existing_desc or ''

    db.session.execute(
        text("""
            UPDATE switch_ports
            SET port_role = :role, port_description = :desc, last_updated = NOW()
            WHERE switch_host = :host AND port_name = :name
        """),
        {'role': role, 'desc': new_desc, 'host': host, 'name': port_name}
    )
    db.session.commit()
    logger.info("Admin set %s %s → %s", host, port_name, role)
    return jsonify({'success': True, 'description': new_desc, 'role': role, })