"""
Admin — Pi-Hole DNS Management (spec section 12 / CODEBASE section 11).

Routes:
  GET/POST /admin/pihole                  Pi-Hole management page
  GET      /admin/pihole/blocked-queries  blocked queries log with user attribution
"""

import logging
import os

from datetime import datetime, timedelta

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import text

from extensions import db
from core.auth import permission_required
from core.pihole_client import (
    pihole_delete, pihole_get, pihole_post, pihole_put, _pihole_base,
    _pihole_headers,
)

logger = logging.getLogger(__name__)

pihole_bp = Blueprint('pihole', __name__)


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


# ---------------------------------------------------------------------------
# Pi-Hole management page
# ---------------------------------------------------------------------------

@pihole_bp.route('/pihole', methods=['GET', 'POST'])
@login_required
@permission_required('manage_pihole')
def admin_pihole():
    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'enable_blocking':
            ok = pihole_post('/api/dns/blocking', {'blocking': 'enabled'})
            flash(
                'Blocking re-enabled.' if ok is not None else 'Failed to communicate with Pi-Hole.',
                'success' if ok is not None else 'error',
            )

        elif action == 'disable_blocking':
            timer = int(request.form.get('timer', 0))
            ok = pihole_post('/api/dns/blocking', {'blocking': 'disabled', 'timer': timer})
            if ok is not None:
                msg = 'Blocking disabled.' if timer == 0 else f'Blocking disabled for {timer // 60} minute(s).'
                flash(msg, 'success')
            else:
                flash('Failed to communicate with Pi-Hole.', 'error')

        elif action in ('add_whitelist', 'add_blacklist'):
            domain = request.form.get('domain', '').strip().lower()
            comment = request.form.get('comment', '').strip()
            dtype = 'allow' if action == 'add_whitelist' else 'deny'
            list_label = 'whitelist' if action == 'add_whitelist' else 'blacklist'
            groups_raw = request.form.getlist('groups')
            groups = [int(g) for g in groups_raw if g.isdigit()]
            if not domain:
                flash('Domain cannot be empty.', 'error')
            else:
                if dtype == 'deny':
                    import re as _re
                    entry_kind   = 'regex'
                    entry_domain = rf'(\.|^){_re.escape(domain)}$'
                    entry_comment = comment or domain
                else:
                    entry_kind    = 'exact'
                    entry_domain  = domain
                    entry_comment = comment
                ok = pihole_post(
                    f'/api/domains/{dtype}/{entry_kind}',
                    {'domain': entry_domain, 'comment': entry_comment,
                     'enabled': True, 'groups': groups if groups else [0]},
                )
                flash(
                    f'"{domain}" added to {list_label}.' if ok is not None
                    else f'Failed to add domain to {list_label}.',
                    'success' if ok is not None else 'error',
                )

        elif action == 'remove_domain':
            from urllib.parse import quote as _quote
            domain = request.form.get('domain', '').strip()
            dtype  = request.form.get('type', 'allow')
            kind   = request.form.get('kind', 'exact')
            if domain:
                ok = pihole_delete(f'/api/domains/{dtype}/{kind}/{_quote(domain, safe="")}')
                flash(
                    f'"{domain}" removed.' if ok else 'Failed to remove domain.',
                    'success' if ok else 'error',
                )

        elif action == 'add_adlist':
            address = request.form.get('address', '').strip()
            comment = request.form.get('comment', '').strip()
            if not address:
                flash('Adlist URL cannot be empty.', 'error')
            else:
                groups_raw = request.form.getlist('groups')
                groups = [int(g) for g in groups_raw if g.isdigit()]
                ok = pihole_post(
                    '/api/lists?type=block',
                    {'address': address, 'comment': comment,
                     'enabled': True, 'groups': groups if groups else [0]},
                )
                flash(
                    'Adlist added. Click "Update Gravity" to activate it.' if ok is not None
                    else 'Failed to add adlist.',
                    'success' if ok is not None else 'error',
                )

        elif action == 'remove_adlist':
            from urllib.parse import quote as _quote
            address = request.form.get('address', '').strip()
            if address:
                ok = pihole_delete(f'/api/lists/{_quote(address, safe="")}?type=block')
                flash(
                    'Adlist removed. Run "Update Gravity" to apply.' if ok
                    else 'Failed to remove adlist.',
                    'success' if ok else 'error',
                )

        elif action == 'update_gravity':
            import requests as _requests
            hdrs = _pihole_headers()
            ok = False
            if hdrs:
                try:
                    r = _requests.post(
                        f'{_pihole_base()}/api/action/gravity',
                        headers=hdrs, timeout=(8, 180), stream=True,
                    )
                    for _ in r.iter_content(chunk_size=4096):
                        pass
                    ok = r.ok
                except Exception as exc:
                    logger.warning('Gravity update request failed: %s', exc)
            flash(
                'Gravity update complete.' if ok else 'Failed to start gravity update.',
                'success' if ok else 'error',
            )

        elif action == 'add_group':
            name    = request.form.get('name', '').strip()
            comment = request.form.get('comment', '').strip()
            if not name:
                flash('Group name cannot be empty.', 'error')
            else:
                ok = pihole_post('/api/groups', {'name': name, 'comment': comment, 'enabled': True})
                flash(
                    f'Group "{name}" created.' if ok is not None else 'Failed to create group.',
                    'success' if ok is not None else 'error',
                )

        elif action == 'remove_group':
            from urllib.parse import quote as _quote
            name = request.form.get('name', '').strip()
            if name == 'Default':
                flash('Cannot delete the Default group.', 'error')
            elif name:
                ok = pihole_delete(f'/api/groups/{_quote(name, safe="")}')
                flash(
                    f'Group "{name}" deleted.' if ok else 'Failed to delete group.',
                    'success' if ok else 'error',
                )

        elif action == 'update_domain_groups':
            from urllib.parse import quote as _quote
            domain     = request.form.get('domain', '').strip()
            dtype      = request.form.get('type', 'allow')
            kind       = request.form.get('kind', 'exact')
            groups_raw = request.form.getlist('groups')
            groups     = [int(g) for g in groups_raw if g.isdigit()]
            if domain:
                ok = pihole_put(
                    f'/api/domains/{dtype}/{kind}/{_quote(domain, safe="")}',
                    {'groups': groups if groups else [0]},
                )
                flash(
                    'Domain groups updated.' if ok is not None else 'Failed to update domain groups.',
                    'success' if ok is not None else 'error',
                )

        elif action == 'update_adlist_groups':
            from urllib.parse import quote as _quote
            address    = request.form.get('address', '').strip()
            groups_raw = request.form.getlist('groups')
            groups     = [int(g) for g in groups_raw if g.isdigit()]
            if address:
                ok = pihole_put(
                    f'/api/lists/{_quote(address, safe="")}?type=block',
                    {'groups': groups},
                )
                flash(
                    'Adlist groups updated.' if ok is not None else 'Failed to update adlist groups.',
                    'success' if ok is not None else 'error',
                )

        elif action == 'set_vlan_client':
            subnet    = request.form.get('subnet', '').strip()
            client_id = request.form.get('client_id', '').strip()
            comment   = request.form.get('comment', '').strip()
            groups_raw = request.form.getlist('groups')
            groups     = [int(g) for g in groups_raw if g.isdigit()]
            if not subnet:
                flash('Subnet cannot be empty.', 'error')
            else:
                if not groups:
                    groups = [0]
                if client_id:
                    ok = pihole_put(
                        f'/api/clients/{client_id}',
                        {'groups': groups, 'comment': comment},
                    )
                else:
                    ok = pihole_post(
                        '/api/clients',
                        {'client': subnet, 'comment': comment,
                         'groups': groups, 'enabled': True},
                    )
                flash(
                    f'Policy for {subnet} updated.' if ok is not None
                    else f'Failed to update policy for {subnet}.',
                    'success' if ok is not None else 'error',
                )

        elif action == 'remove_vlan_client':
            client_id = request.form.get('client_id', '').strip()
            if client_id:
                ok = pihole_delete(f'/api/clients/{client_id}')
                flash(
                    'VLAN policy removed — subnet reverts to Default group.' if ok
                    else 'Failed to remove VLAN policy.',
                    'success' if ok else 'error',
                )

        return redirect(url_for('admin.pihole.admin_pihole'))

    # GET — fetch all data from Pi-Hole
    summary      = pihole_get('/api/stats/summary')
    blocking     = pihole_get('/api/dns/blocking')
    domains_data = pihole_get('/api/domains')
    adlists_data = pihole_get('/api/lists?type=block')
    groups_data  = pihole_get('/api/groups')
    clients_data = pihole_get('/api/clients')

    whitelist, blacklist = [], []
    if domains_data:
        for d in domains_data.get('domains', []):
            (whitelist if d.get('type') == 'allow' else blacklist).append(d)

    adlists = (adlists_data or {}).get('lists', [])
    groups  = (groups_data  or {}).get('groups', [])
    clients = (clients_data or {}).get('clients', [])

    group_content = {}
    for g in groups:
        gid = g['id']
        group_content[gid] = {
            'adlists':   sum(1 for a in adlists   if gid in a.get('groups', [])),
            'whitelist': sum(1 for d in whitelist  if gid in d.get('groups', [])),
            'blacklist': sum(1 for d in blacklist  if gid in d.get('groups', [])),
        }

    vlan_ids = [v.strip() for v in os.getenv('VALID_VLANS', '').split(',') if v.strip().isdigit()]
    vlan_policies = []
    for vlan_id in vlan_ids:
        subnet = f'{_net_word()}.{vlan_id}.0/24'
        entry  = next((c for c in clients if c.get('client') == subnet), None)
        vlan_policies.append({
            'vlan':      vlan_id,
            'subnet':    subnet,
            'client_id': entry['id'] if entry else None,
            'groups':    entry.get('groups', []) if entry else [],
            'comment':   entry.get('comment', '') if entry else '',
        })

    return render_template(
        'admin_pihole.html',
        summary=summary or {},
        blocking=blocking,
        whitelist=whitelist,
        blacklist=blacklist,
        adlists=adlists,
        groups=groups,
        group_content=group_content,
        vlan_policies=vlan_policies,
        pihole_available=(summary is not None),
    )


# ---------------------------------------------------------------------------
# Blocked queries log
# ---------------------------------------------------------------------------

@pihole_bp.route('/pihole/blocked-queries')
@login_required
@permission_required('manage_pihole')
def pihole_blocked_queries():
    page     = request.args.get('page', 1, type=int)
    per_page = 50
    offset   = (page - 1) * per_page

    user_filter      = request.args.get('user_id', '', type=str)
    domain_filter    = request.args.get('domain', '', type=str).strip()
    status_filter    = request.args.get('status', '', type=str).strip()
    client_ip_filter = request.args.get('client_ip', '', type=str).strip()
    mac_filter       = request.args.get('mac', '', type=str).strip()
    date_from_str    = request.args.get('date_from', '', type=str).strip()
    date_to_str      = request.args.get('date_to', '', type=str).strip()

    date_from = None
    date_to   = None
    try:
        if date_from_str:
            date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
    except ValueError:
        date_from_str = ''
    try:
        if date_to_str:
            date_to = datetime.strptime(date_to_str, '%Y-%m-%d').replace(
                hour=23, minute=59, second=59)
    except ValueError:
        date_to_str = ''

    where_clauses = []
    params = {}

    if user_filter.isdigit():
        where_clauses.append("pbq.user_id = :user_id")
        params['user_id'] = int(user_filter)
    if domain_filter:
        where_clauses.append("pbq.domain ILIKE :domain")
        params['domain'] = f"%{domain_filter}%"
    if status_filter:
        where_clauses.append("pbq.status = :status")
        params['status'] = status_filter
    if client_ip_filter:
        where_clauses.append("pbq.client_ip::text ILIKE :client_ip")
        params['client_ip'] = f"%{client_ip_filter}%"
    if mac_filter:
        where_clauses.append("pbq.mac_address ILIKE :mac")
        params['mac'] = f"%{mac_filter}%"
    if date_from:
        where_clauses.append("pbq.blocked_at >= :date_from")
        params['date_from'] = date_from
    if date_to:
        where_clauses.append("pbq.blocked_at <= :date_to")
        params['date_to'] = date_to

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    rows = db.session.execute(text(f"""
        SELECT
            pbq.id,
            pbq.blocked_at,
            pbq.domain,
            pbq.query_type,
            pbq.status,
            pbq.client_ip::text,
            pbq.mac_address,
            d.device_name,
            u.id        AS user_id,
            u.first_name,
            u.last_name,
            u.email
        FROM pihole_blocked_queries pbq
        LEFT JOIN devices d ON pbq.device_id = d.id
        LEFT JOIN users   u ON pbq.user_id   = u.id
        {where_sql}
        ORDER BY pbq.blocked_at DESC
        LIMIT :limit OFFSET :offset
    """), {**params, 'limit': per_page, 'offset': offset}).fetchall()

    total = db.session.execute(
        text(f"SELECT COUNT(*) FROM pihole_blocked_queries pbq {where_sql}"),
        params,
    ).scalar()

    total_pages = max(1, (total + per_page - 1) // per_page)

    users_in_log = db.session.execute(text("""
        SELECT DISTINCT u.id, u.first_name, u.last_name, u.email
        FROM pihole_blocked_queries pbq
        JOIN users u ON pbq.user_id = u.id
        ORDER BY u.last_name, u.first_name
    """)).fetchall()

    all_statuses = [r[0] for r in db.session.execute(text("""
        SELECT DISTINCT status FROM pihole_blocked_queries ORDER BY status
    """)).fetchall()]

    return render_template(
        'admin_pihole_blocked_queries.html',
        rows=rows,
        page=page,
        total_pages=total_pages,
        total=total,
        per_page=per_page,
        user_filter=user_filter,
        domain_filter=domain_filter,
        status_filter=status_filter,
        client_ip_filter=client_ip_filter,
        mac_filter=mac_filter,
        date_from_str=date_from_str,
        date_to_str=date_to_str,
        users_in_log=users_in_log,
        all_statuses=all_statuses,
    )
