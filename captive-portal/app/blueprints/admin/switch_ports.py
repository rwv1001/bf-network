"""
Admin — Switch Port Management (spec section 12 / CODEBASE section 8).

Routes:
  GET  /admin/switch-ports                list all switch ports
  POST /admin/switch-ports/refresh        re-discover ports from all switches
  POST /admin/switch-ports/update         bulk role update + push to switch
  POST /admin/switch-ports/update-single  AJAX single-port role update
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
    expand_switch_iface_name, find_switch_port_for_mac,
    get_switch_hosts, normalize_switch_mac, persist_switch_port,
    run_switch_command, switch_port_allowed,
)
from core.vlan_utils import get_wired_vlan_id, get_management_vlan_id

logger = logging.getLogger(__name__)

switch_ports_bp = Blueprint('switch_ports', __name__)

PORT_ROLES = {
    'ap':           'AP Uplink',
    'cheapap':      'Cheap AP',
    'wired':        'Wired Device',
    'pi':           'Pi / Kea',
    'inter_switch': 'Inter-Switch Link',
    'uplink_udm':   'Uplink to Router',
    'unknown':      'Unclassified',
}


# ---------------------------------------------------------------------------
# Port discovery helpers
# ---------------------------------------------------------------------------

def _detect_port_role(port_name: str, description: str) -> str:
    """Infer a port role from its name and description using keyword heuristics."""
    desc = (description or '').lower()
    if 'udm' in desc or 'usg' in desc:
        return 'uplink_udm'
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
    """
    SSH to switch_host and return a list of port dicts.

    Three-phase, pagination-safe strategy for HP5130/Comware 7:
    Phase 1 – slot detection
    Phase 2 – port existence & link state
    Phase 3 – descriptions

    Returns: [{'port_name': str, 'link_status': str, 'description': str}]
    """
    def _shorten(name):
        if name.startswith('GigabitEthernet'):
            return 'GE' + name[len('GigabitEthernet'):]
        if name.startswith('Ten-GigabitEthernet'):
            return 'XGE' + name[len('Ten-GigabitEthernet'):]
        return name

    def _iface_sort_key(name):
        nums = [int(x) for x in re.findall(r'\d+', name)]
        return (1 if name.startswith('Ten-') else 0, nums)

    def _split_by_prompts(output):
        parts = re.split(r'<[A-Za-z][^>\n]{0,40}>', output)
        sections = []
        for part in parts[1:]:
            lines = part.replace('\r', '').split('\n')
            body = '\n'.join(l for l in lines[1:] if l.strip())
            sections.append(body)
        return sections

    max_slot = int(os.getenv('SWITCH_MAX_SLOT', '8'))
    ge_max   = int(os.getenv('SWITCH_GE_MAX',   '52'))

    # Phase 1 — slot detection
    slot_cmds = '\n'.join(
        f'display current-configuration | include interface | include GigabitEthernet{s}/0/1'
        for s in range(1, max_slot + 1)
    )
    slot_output = run_switch_command(switch_host, slot_cmds)
    detected_slots = set()
    for line in (slot_output or '').splitlines():
        stripped = line.strip()
        if stripped.startswith('interface GigabitEthernet'):
            m = re.search(r'GigabitEthernet(\d+)/', stripped)
            if m:
                detected_slots.add(int(m.group(1)))

    if not detected_slots:
        logger.warning("No switch slots detected on %s", switch_host)
        return []

    # Phase 2 — port existence & link state
    candidates = []
    for s in sorted(detected_slots):
        for n in range(1, ge_max + 1):
            candidates.append(f'GigabitEthernet{s}/0/{n}')
        for n in range(1, ge_max + 1):
            candidates.append(f'Ten-GigabitEthernet{s}/0/{n}')

    state_cmds = '\n'.join(
        f'display interface {full} | include state'
        for full in candidates
    )
    state_raw = run_switch_command(switch_host, state_cmds) or ''
    state_sections = _split_by_prompts(state_raw)

    existing = {}
    for i, full_name in enumerate(candidates):
        if i >= len(state_sections):
            break
        section = state_sections[i]
        if '% ' in section or 'Wrong' in section or 'Error' in section:
            continue
        m = re.search(r'Current state:\s*(\S+(?:\s+\S+)?)', section, re.IGNORECASE)
        raw = (m.group(1) if m else 'UNKNOWN').upper()
        if 'ADMINISTRATIVELY' in raw:
            link = 'ADMDOWN'
        elif raw.startswith('UP'):
            link = 'UP'
        elif 'DOWN' in raw:
            link = 'DOWN'
        else:
            link = raw[:10]
        existing[full_name] = link

    if not existing:
        logger.warning("No ports found via state probe on %s", switch_host)
        return []

    sorted_existing = sorted(existing.keys(), key=_iface_sort_key)

    # Phase 3 — descriptions
    desc_cmds = '\n'.join(
        f'display interface {full} | include Description'
        for full in sorted_existing
    )
    desc_raw = run_switch_command(switch_host, desc_cmds) or ''
    desc_sections = _split_by_prompts(desc_raw)

    ports = []
    for i, full_name in enumerate(sorted_existing):
        desc = ''
        if i < len(desc_sections):
            section = desc_sections[i]
            if 'Description:' in section:
                raw = [l for l in section.splitlines() if 'Description:' in l]
                if raw:
                    desc = raw[0].split(':', 1)[1].strip()
        if desc.endswith(' Interface') and 'Ethernet' in desc:
            desc = ''
        ports.append({
            'port_name':   _shorten(full_name),
            'link_status': existing[full_name],
            'description': desc,
        })

    logger.info("Discovered %d ports on %s", len(ports), switch_host)
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


def _get_isp_router_locked_ports() -> dict:
    """Return {port_name: router_name} for all ISP routers that have a port assigned."""
    from models import ISPRouter
    return {r.switch_port: r.name
            for r in ISPRouter.query.filter(ISPRouter.switch_port.isnot(None)).all()}


def _build_port_config(port_name: str, role: str, description: str = '') -> str:
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

    CANONICAL_DESC = {
        'ap':           'Uplink to UniFi AP',
        'cheapap':      'Cheap AP',
        'wired':        'wired port',
        'pi':           'TRUNK-TO-PI-Kea',
        'inter_switch': 'Inter-switch link',
        'uplink_udm':   'TRUNK-TO-UDM',
        'unknown':      '',
    }
    # Role-specific canonical takes priority; only unknown falls back to existing desc.
    canonical = CANONICAL_DESC.get(role, '')
    desc = canonical if canonical else (description or '').strip()

    head = ['system-view', f'interface {expanded}']

    # Start with common cleanup commands for all roles
    body = list(COMMON_PORT_UNDO_COMMANDS)

    if role == 'wired':
        body.extend([
            'mac-authentication',
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',
            'undo port hybrid vlan 1',
            f'port hybrid vlan {vlans_list} {mgmt_vlan} untagged',
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
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',
            f'port hybrid vlan {ap_tagged} tagged',
            f'port hybrid vlan 1 {mgmt_vlan} {wired_vlan} untagged',
            'mac-vlan enable',
            'ip verify source ip-address mac-address',
            'mac-authentication',
            'mac-authentication max-user 256',
            'mac-authentication domain macauth',
            f'mac-authentication guest-vlan {wired_vlan}',
            'mac-authentication host-mode multi-vlan',
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
            'poe enable',
        ])

    elif role == 'cheapap':
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            'port link-type hybrid',            
            f'port hybrid vlan 1 {vlans_list} {mgmt_vlan} {wired_vlan} untagged',
            'mac-vlan enable',
            'ip verify source ip-address mac-address',
            'mac-authentication',
            'mac-authentication max-user 256',
            'mac-authentication domain macauth',
            f'mac-authentication guest-vlan {wired_vlan}',
            'mac-authentication host-mode multi-vlan',
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
            'poe enable',
        ])

    elif role == 'pi':
        body.extend([
            f'interface {expanded}',
            'port link-type access',
            'port link-type trunk',
            'port trunk permit vlan 1',
            f'port trunk permit vlan {vlans_list}',
            f'port trunk permit vlan {mgmt_vlan} {wired_vlan}',
            'port trunk pvid vlan 1',
            'arp detection trust',
            'dhcp snooping trust',
        ])

    elif role == 'uplink_udm':
        uplink_cmds = [
            f'interface {expanded}',
            'port link-type access',
            'port link-type trunk',
            'port trunk permit vlan 1',
        ]
        if external_vlans_list:
            uplink_cmds.append(f'port trunk permit vlan {external_vlans_list}')
        uplink_cmds.append('dhcp snooping trust')
        body.extend(uplink_cmds)

    elif role == 'inter_switch':
        try:
            isp_vlan_ids = [str(r.vlan_id) for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()]
        except Exception:
            isp_vlan_ids = ['1']
        isp_vlan_str = ' '.join(isp_vlan_ids) if isp_vlan_ids else '1'
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
            'port trunk pvid vlan 1',
            'arp detection trust',
            'dhcp snooping trust',
        ])
        body.extend(inter_cmds)

    if desc:
        body.append(f'description {desc}')

    # unknown role → just apply the common undos + description (if any)

    return '\n'.join(head + body + ['quit', 'quit', 'save force'])


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
                SELECT port_name, port_description, port_role, link_status, last_discovered
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
            }
            for r in rows
        ]

    return render_template(
        'admin_switch_ports.html',
        ports_by_switch=ports_by_switch,
        switch_hosts=switch_hosts,
        port_roles=PORT_ROLES,
        locked_ports=_get_isp_router_locked_ports(),
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
        if role in PORT_ROLES:
            updates[(host, port)] = role

    if not updates:
        flash('No changes submitted.', 'info')
        return redirect(url_for('admin.switch_ports.list_switch_ports'))

    ROLE_DESC = {
        'ap':           'AP-UPLINK',
        'cheapap':      'CHEAP-AP',
        'wired':        'WIRED-ACCESS',
        'pi':           'PI-TRUNK',
        'inter_switch': 'ISL',
        'uplink_udm':   'UDM-UPLINK',
        'unknown':      None,
    }

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

    if not host or not port_name or role not in PORT_ROLES:
        return jsonify({'success': False, 'error': 'Invalid request'})

    locked = _get_isp_router_locked_ports()
    if port_name in locked:
        return jsonify({
            'success': False,
            'error': f'Port is locked as uplink to router "{locked[port_name]}". '
                     'Change it via ISP Routers page.',
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
        return jsonify({'success': True, 'message': 'No change needed'})

    cmds = _build_port_config(port_name, role, existing_desc)
    result = run_switch_command(host, cmds)
    if result is None:
        return jsonify({'success': False, 'error': f'SSH to {host} failed'})

    _CANONICAL_DESC = {
        'ap': 'Uplink to UniFi AP', 'cheapap': 'Cheap AP', 'wired': 'wired port',
        'pi': 'TRUNK-TO-PI-Kea', 'inter_switch': 'Inter-switch link',
        'uplink_udm': 'TRUNK-TO-UDM',
    }
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
    return jsonify({'success': True})