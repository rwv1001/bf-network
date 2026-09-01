"""
Admin — Dashboard (spec section 12.1 / 12.2 / 12.3).

Routes:
  GET  /admin                      main dashboard (pending, users, devices, unregistered tabs)
  POST /admin/save-dashboard-prefs save per-admin section visibility preferences
  POST /admin/reset-test           reset test environment (TEST_ENV only)
  POST /admin/domain-policies      add / edit / delete domain policies
  POST /admin/approve/<token>      show approval page for a registration request
  POST /admin/requests/<id>/process process (approve/reject) a registration request
"""

import ipaddress
import json
import logging
import os
import secrets
import threading
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Blueprint, abort, flash, jsonify, redirect,
    render_template, request, url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import text

from extensions import db
from models import (
    Admin, Device, DeviceOwnership, DomainPolicy, IPLease,
    ISPRouter, RegistrationRequest, UnregisteredLease, User, VlanMapping,
)
from core.auth import permission_required
from core.device_utils import (
    clear_unregistered_lease, get_active_iplease, get_active_ownership,
    open_ownership, close_ownership, set_internet_accessible,
    set_internet_blocked, should_have_internet, sync_registration_status,
    upsert_iplease,
)
from core.mac_utils import get_ip_for_mac, load_active_lease_counts, detect_connection_type
from core.network import (
    apply_device_block, apply_device_unblock,
    manage_dns_hijack, manage_switch_acl,
    reset_acl_baseline, reset_acl_queue_files, reset_dns_hijack_rules,
)
from core.user_utils import (
    allowed_vlans_display_items, adoptable_vlans_display_items,
    email_domain, format_allowed_vlans, get_domain_policy_for_user,
    load_domain_policy_map, parse_allowed_vlans,
)
from core.vlan_utils import (
    FIXED_VLAN_STATUSES, POOL_PREFIX_CHOICES, POOL_PREFIX_STATUSES,
    WIRED_UNREGISTERED_STATUS, get_admin_assignable_entries,
    get_vlan_entries, get_vlan_map, get_vlan_prefix_by_id,
    get_wired_unregistered_vlan_id, label_for_vlan,
)
from core.portal_utils import build_unregister_url, set_wifi_confirmation
from email_service import (
    send_admin_notification, send_vlan_mismatch_notification,
    send_wifi_registration_confirmation,
)
import central_client
from kea_integration import get_kea_client
from radius_coa import send_coa_change

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)

KEA_SOCKET = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')


def _get_kea():
    try:
        return get_kea_client(control_socket=KEA_SOCKET)
    except Exception:
        return None


def _is_test_env():
    return os.getenv('TEST_ENV', 'false').strip().lower() in {'1', 'true', 'yes', 'on'}


def _replug_switch_port_for_mac(mac_address):
    try:
        from core.network import replug_switch_port_for_mac
        return replug_switch_port_for_mac(mac_address)
    except Exception as exc:
        logger.warning("replug_switch_port_for_mac failed for %s: %s", mac_address, exc)
        return False


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------

@dashboard_bp.route('', strict_slashes=False)
@login_required
def index():
    """Admin dashboard with pending requests, users, registered devices, unregistered devices."""
    from core.switch import get_switch_hosts
    if not (current_user.can_manage_users or current_user.can_manage_vlans
            or current_user.can_view_traffic or current_user.can_manage_admins):
        return redirect(url_for('admin.manage_admins.no_permissions'))

    if not current_user.can_manage_users:
        if current_user.can_manage_vlans:
            return redirect(url_for('admin.vlans.vlan_config'))
        if current_user.can_view_traffic:
            return redirect(url_for('admin.traffic.traffic'))
        if current_user.can_manage_admins:
            return redirect(url_for('admin.manage_admins.manage_admins'))

    # ── Pagination / search params ────────────────────────────────────────────
    pending_page     = request.args.get('pending_page',     1,    type=int)
    pending_per_page = request.args.get('pending_per_page', 25,   type=int)
    pending_search   = request.args.get('pending_search',   '',   type=str).strip().lower()
    pending_sort     = request.args.get('pending_sort',     'submitted_at')
    pending_order    = request.args.get('pending_order',    'desc')

    users_page     = request.args.get('users_page',     1,    type=int)
    users_per_page = request.args.get('users_per_page', 25,   type=int)
    users_search   = request.args.get('users_search',   '',   type=str).strip().lower()
    users_sort     = request.args.get('users_sort',     'email')
    users_order    = request.args.get('users_order',    'asc')

    devices_page     = request.args.get('devices_page',     1,    type=int)
    devices_per_page = request.args.get('devices_per_page', 25,   type=int)
    devices_search   = request.args.get('devices_search',   '',   type=str).strip().lower()
    devices_sort     = request.args.get('devices_sort',     'first_seen')
    devices_order    = request.args.get('devices_order',    'desc')

    # ── Pending requests ──────────────────────────────────────────────────────
    all_pending = (RegistrationRequest.query
                   .filter_by(status='pending')
                   .order_by(RegistrationRequest.submitted_at.desc())
                   .all())

    grouped = {}
    for req in all_pending:
        mac = req.mac_address
        if mac not in grouped:
            grouped[mac] = {
                'mac_address':    mac,
                'latest_request': req,
                'email':          req.email,
                'first_name':     req.first_name,
                'last_name':      req.last_name,
                'phone_number':   req.phone_number,
                'device_type':    req.device_type,
                'approval_token': req.approval_token,
                'submitted_times': [req.submitted_at],
                'ip_addresses':   [req.ip_address] if req.ip_address else [],
            }
        else:
            grouped[mac]['submitted_times'].append(req.submitted_at)
            if req.ip_address and req.ip_address not in grouped[mac]['ip_addresses']:
                grouped[mac]['ip_addresses'].append(req.ip_address)

    all_pending_list = list(grouped.values())

    if pending_search:
        all_pending_list = [
            r for r in all_pending_list
            if (pending_search in r['email'].lower()
                or pending_search in r['first_name'].lower()
                or pending_search in r['last_name'].lower()
                or pending_search in (r['phone_number'] or '').lower()
                or pending_search in r['mac_address'].lower()
                or pending_search in (r['device_type'] or '').lower())
        ]

    reverse_order = (pending_order == 'desc')
    sort_key_map = {
        'submitted_at': lambda x: x['submitted_times'][0],
        'name':         lambda x: f"{x['first_name']} {x['last_name']}".lower(),
        'email':        lambda x: x['email'].lower(),
        'phone':        lambda x: (x['phone_number'] or '').lower(),
        'device_type':  lambda x: (x['device_type'] or '').lower(),
        'mac_address':  lambda x: x['mac_address'].lower(),
    }
    all_pending_list.sort(key=sort_key_map.get(pending_sort, sort_key_map['submitted_at']),
                          reverse=reverse_order)

    pending_total = len(all_pending_list)
    pending_start = (pending_page - 1) * pending_per_page
    pending_requests = all_pending_list[pending_start:pending_start + pending_per_page]
    pending_pages = max(1, (pending_total + pending_per_page - 1) // pending_per_page)

    # ── Users ─────────────────────────────────────────────────────────────────
    users_query = User.query
    if users_search:
        users_query = users_query.outerjoin(Device).filter(
            db.or_(
                User.email.ilike(f'%{users_search}%'),
                User.first_name.ilike(f'%{users_search}%'),
                User.last_name.ilike(f'%{users_search}%'),
                User.phone_number.ilike(f'%{users_search}%'),
                Device.mac_address.ilike(f'%{users_search}%'),
            )
        )

    valid_user_sorts = ['email', 'first_name', 'last_name', 'begin_date',
                        'expiry_date', 'created_at', 'phone_number']
    if users_sort not in valid_user_sorts:
        users_sort = 'email'

    sort_col = getattr(User, users_sort)
    users_query = users_query.order_by(
        sort_col.desc() if users_order == 'desc' else sort_col.asc()
    )
    if users_search:
        users_query = users_query.distinct()

    users_total = users_query.count()
    users = users_query.offset((users_page - 1) * users_per_page).limit(users_per_page).all()
    users_pages = max(1, (users_total + users_per_page - 1) // users_per_page)

    vlan_map = get_vlan_map()
    domain_policy_map = load_domain_policy_map()
    for user in users:
        domain_policy = domain_policy_map.get(email_domain(user.email))
        user.allowed_vlans_display_items = allowed_vlans_display_items(
            user, vlan_map, domain_policy, include_denied=True)
        user.adoptable_vlans_display_items = adoptable_vlans_display_items(
            user, vlan_map, domain_policy, include_denied=True)

    # ── Registered devices (Table 9 active rows) ──────────────────────────────
    devices_query = (
        db.session.query(DeviceOwnership, Device, User, Admin)
        .join(Device, DeviceOwnership.mac_address == Device.mac_address, isouter=True)
        .outerjoin(User, DeviceOwnership.user_id == User.id)
        .outerjoin(Admin, DeviceOwnership.admin_id == Admin.id)
        .filter(DeviceOwnership.end_datetime.is_(None))
    )

    if devices_search:
        devices_query = devices_query.filter(
            db.or_(
                DeviceOwnership.mac_address.ilike(f'%{devices_search}%'),
                Device.device_name.ilike(f'%{devices_search}%'),
                Device.connection_type.ilike(f'%{devices_search}%'),
                Device.registration_status.ilike(f'%{devices_search}%'),
                User.email.ilike(f'%{devices_search}%'),
                User.first_name.ilike(f'%{devices_search}%'),
                User.last_name.ilike(f'%{devices_search}%'),
                Admin.username.ilike(f'%{devices_search}%'),
                Admin.email.ilike(f'%{devices_search}%'),
            )
        )

    if devices_sort == 'user_name':
        devices_query = devices_query.order_by(
            User.first_name.desc() if devices_order == 'desc' else User.first_name.asc()
        )
    elif devices_sort == 'user_email':
        devices_query = devices_query.order_by(
            User.email.desc() if devices_order == 'desc' else User.email.asc()
        )
    else:
        _dcol = getattr(Device, devices_sort, Device.first_seen)
        devices_query = devices_query.order_by(
            _dcol.desc() if devices_order == 'desc' else _dcol.asc()
        )

    devices_total = devices_query.count()
    devices = devices_query.offset(
        (devices_page - 1) * devices_per_page
    ).limit(devices_per_page).all()
    devices_pages = max(1, (devices_total + devices_per_page - 1) // devices_per_page)

    # ── Unregistered devices (Table 6 rows with no active Table 9 entry) ──────
    active_ownership_macs = (
        db.session.query(DeviceOwnership.mac_address)
        .filter(DeviceOwnership.end_datetime.is_(None))
        .scalar_subquery()
    )
    unregistered_devices = (
        db.session.query(Device)
        .filter(~Device.mac_address.in_(active_ownership_macs))
        .order_by(Device.last_seen.desc())
        .all()
    )
    unregistered_total = len(unregistered_devices)
    fixed_ip_reservations = (
        Device.query
        .filter(Device.fixed_ip.isnot(None), Device.fixed_ip != '')
        .order_by(Device.fixed_ip.asc())
        .all()
    )
    for _d in fixed_ip_reservations:
        _own = get_active_ownership(_d.mac_address)
        if _own and getattr(_own, 'user_id', None):
            _u = User.query.get(_own.user_id)
            _d.owner_label = _u.email if _u else f'user:{_own.user_id}'
            _d.owner_value = f'user:{_own.user_id}'
        elif _own and getattr(_own, 'admin_id', None):
            _a = Admin.query.get(_own.admin_id)
            _d.owner_label = (
                f'admin:{_a.username}' if _a else f'admin:{_own.admin_id}'
            )
            _d.owner_value = f'admin:{_own.admin_id}'
        else:
            _d.owner_label = '—'
            _d.owner_value = ''

    

    # ── Lease stats ───────────────────────────────────────────────────────────
    prefix_by_id = get_vlan_prefix_by_id()
    lease_counts = load_active_lease_counts()
    lease_stats = []
    net_word = os.getenv('NETWORK_WORD', '192.168')
    for entry in get_vlan_entries():
        vlan_id = entry.vlan_id
        if not vlan_id:
            continue
        prefix = prefix_by_id.get(vlan_id, 24)
        try:
            network = ipaddress.IPv4Network(f"{net_word}.{vlan_id}.0/{prefix}", strict=False)
            subnet_cidr = str(network)
        except Exception:
            subnet_cidr = f"{net_word}.{vlan_id}.0/{prefix}"
        display_name = (entry.display_name or entry.status or '').strip() or f"VLAN {vlan_id}"
        lease_stats.append({
            'status':       entry.status,
            'display_name': display_name,
            'vlan_id':      vlan_id,
            'subnet':       subnet_cidr,
            'active_leases': lease_counts.get(vlan_id, 0),
        })
    lease_stats.sort(key=lambda e: e['vlan_id'])

    # ── Domain policies ───────────────────────────────────────────────────────
    domain_policies = DomainPolicy.query.order_by(DomainPolicy.domain.asc()).all()
    for policy in domain_policies:
        policy.allowed_vlans_set  = parse_allowed_vlans(policy.allowed_vlans)
        policy.adoptable_vlans_set = parse_allowed_vlans(policy.adoptable_vlans)

    # ── Dashboard section visibility prefs ────────────────────────────────────
    _dash_settings = {}
    if current_user.traffic_viewer_settings:
        try:
            _dash_settings = json.loads(current_user.traffic_viewer_settings)
        except Exception:
            pass
    dashboard_hidden_sections = set(_dash_settings.get('dashboard_hidden_sections', []))
    _base = [
        {
            'vlan_id': entry.vlan_id,
            'label': label_for_vlan(entry.vlan_id, vlan_map),
            'wired_enabled': bool(entry.wired_enabled),
        }
        for entry in get_admin_assignable_entries()
    ]
    # ISP router VLANs that are not already in the assignable VLAN list.
    # VLAN 1 is added separately as "Upstream Management".
    _seen_vlan_ids = {1} | {c['vlan_id'] for c in _base}
    _isp_vlan_choices = []
    try:
        for router in ISPRouter.query.order_by(ISPRouter.vlan_id.asc()).all():
            if router.vlan_id is None:
                continue
            try:
                vid = int(router.vlan_id)
            except (TypeError, ValueError):
                continue
            if vid in _seen_vlan_ids:
                continue
            _seen_vlan_ids.add(vid)
            router_name = (getattr(router, 'name', None) or '').strip() or f'VLAN {vid}'
            _isp_vlan_choices.append({
                'vlan_id': vid,
                'label': f'ISP {router_name} (VLAN {vid})',
                'wired_enabled': True,
            })
    except Exception:
        logger.warning("Could not load ISP router VLANs for assign dropdown", exc_info=True)

    # ── AJAX partial rendering ────────────────────────────────────────────────
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    template_vars = dict(
        devices=devices,
        devices_page=devices_page, devices_per_page=devices_per_page,
        devices_pages=devices_pages, devices_total=devices_total,
        devices_search=devices_search, devices_sort=devices_sort, devices_order=devices_order,
        fixed_ip_reservations=fixed_ip_reservations,
        users=users,
        users_page=users_page, users_per_page=users_per_page,
        users_pages=users_pages, users_total=users_total,
        users_search=users_search, users_sort=users_sort, users_order=users_order,
        admins=Admin.query.order_by(Admin.username.asc()).all(),
        pending_requests=pending_requests,
        pending_page=pending_page, pending_per_page=pending_per_page,
        pending_pages=pending_pages, pending_total=pending_total,
        pending_search=pending_search, pending_sort=pending_sort, pending_order=pending_order,
        unregistered_devices=unregistered_devices,
        unregistered_total=unregistered_total,
        switch_hosts=get_switch_hosts(),
        vlan_map=vlan_map,
        wired_unregistered_vlan=get_wired_unregistered_vlan_id(),
        wired_vlan_choices=[
            {
                'vlan_id': 1,
                'label': 'Upstream Management (VLAN 1)',
                'wired_enabled': True,
            },
        ] + [c for c in _base if c['vlan_id'] != 1]+ _isp_vlan_choices,
        lease_stats=lease_stats,
        domain_policies=domain_policies,
        test_env=_is_test_env(),
        dashboard_hidden_sections=dashboard_hidden_sections,
        kea_managed_vlan_ids=sorted(_kea_managed_vlan_ids()),
    )

    if is_ajax:
        ajax_table = request.args.get('ajax_table', '')
        if ajax_table == 'pending':
            return render_template('partials/pending_table.html', **template_vars)
        if ajax_table == 'users':
            return render_template('partials/users_table.html', **template_vars)
        if ajax_table == 'devices':
            return render_template('partials/devices_table.html', **template_vars)

    return render_template('admin_dashboard.html', **template_vars)


# ---------------------------------------------------------------------------
# Dashboard preferences
# ---------------------------------------------------------------------------

@dashboard_bp.route('/save-dashboard-prefs', methods=['POST'])
@login_required
def save_dashboard_prefs():
    data = request.get_json(silent=True) or {}
    admin = Admin.query.get(int(current_user.id))
    if not admin:
        return jsonify({'success': False})
    settings = {}
    if admin.traffic_viewer_settings:
        try:
            settings = json.loads(admin.traffic_viewer_settings)
        except Exception:
            pass
    settings['dashboard_hidden_sections'] = data.get('hidden_sections', [])
    admin.traffic_viewer_settings = json.dumps(settings)
    db.session.commit()
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# Test reset
# ---------------------------------------------------------------------------

@dashboard_bp.route('/reset-test', methods=['POST'])
@login_required
@permission_required('manage_users')
def reset_test():
    if not _is_test_env():
        abort(404)

    from core.device_utils import reset_test_data

    try:
        reset_test_data()
    except Exception as exc:
        logger.error("Test reset DB cleanup failed: %s", exc)
        flash('Reset failed while clearing database records.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    reset_acl_queue_files()
    reset_dns_hijack_rules()

    def _background_reset():
        from app import app as _app
        from extensions import db as _db

        logger.info("Test reset: starting background tasks")

        try:
            # 1. Full ACL + PBR + NQA baseline (this is the authoritative path now)
            with _app.app_context():
                reset_acl_baseline()
                _db.session.commit()
            logger.info("Test reset: ACL/PBR/NQA baseline done")

            # 2. Kea restart
            from core.vlan_utils import restart_kea_container
            restart_kea_container()
            logger.info("Test reset: Kea container restarted")

            # 3. Clear MAC auth sessions
            with _app.app_context():
                from core.network import clear_mac_auth_sessions
                clear_mac_auth_sessions()
                _db.session.commit()
            logger.info("Test reset: MAC auth sessions cleared")

            # 4. Reset user ports
            with _app.app_context():
                from core.network import reset_user_ports
                reset_user_ports()
                _db.session.commit()
            logger.info("Test reset: user ports reset")

            logger.info("Test reset: reset complete")

        except Exception as exc:
            logger.error("Test reset background tasks failed: %s", exc, exc_info=True)
        finally:
            try:
                with _app.app_context():
                    _db.session.remove()
            except Exception:
                pass
    
    threading.Thread(target=_background_reset, daemon=True).start()

    flash(
        'Test reset started. Database cleared. Switch ACL baseline, MAC auth, '
        'port reset, and PBR/NQA push are running in the background.',
        'success',
    )
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Domain policies
# ---------------------------------------------------------------------------

@dashboard_bp.route('/domain-policies', methods=['POST'])
@login_required
@permission_required('manage_users')
def domain_policies():
    action = (request.form.get('action') or '').strip().lower()
    domain = (request.form.get('domain') or '').strip().lower()
    policy_id = request.form.get('policy_id')

    if action == 'delete':
        if policy_id:
            policy = DomainPolicy.query.get(policy_id)
            if policy:
                db.session.delete(policy)
                db.session.commit()
                flash(f'Domain policy for {policy.domain} deleted.', 'success')
        return redirect(url_for('admin.dashboard.index'))

    if not domain:
        flash('Domain is required.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    allowed   = parse_allowed_vlans(','.join(request.form.getlist('domain_allowed_vlans')))
    adoptable = parse_allowed_vlans(','.join(request.form.getlist('domain_adoptable_vlans')))

    if policy_id:
        policy = DomainPolicy.query.get(policy_id)
        if not policy:
            flash('Domain policy not found.', 'error')
            return redirect(url_for('admin.dashboard.index'))
        policy.domain          = domain
        policy.allowed_vlans   = format_allowed_vlans(allowed)
        policy.adoptable_vlans = format_allowed_vlans(adoptable)
        db.session.commit()
        flash(f'Domain policy for {domain} updated.', 'success')
        return redirect(url_for('admin.dashboard.index'))

    if DomainPolicy.query.filter_by(domain=domain).first():
        flash('Domain policy already exists. Use edit to update it.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    policy = DomainPolicy(
        domain=domain,
        allowed_vlans=format_allowed_vlans(allowed),
        adoptable_vlans=format_allowed_vlans(adoptable),
    )
    db.session.add(policy)
    db.session.commit()
    flash(f'Domain policy for {domain} added.', 'success')
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Approval workflow
# ---------------------------------------------------------------------------

@dashboard_bp.route('/approve/<token>')
@login_required
@permission_required('manage_users')
def approve_request(token):
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()

    if reg_request.status != 'pending':
        action = 'approved' if reg_request.status == 'approved' else 'rejected'
        processed_info = f"by admin {reg_request.processed_by}" if reg_request.processed_by else ""
        processed_time = (f"at {reg_request.processed_at.strftime('%Y-%m-%d %H:%M:%S')}"
                          if reg_request.processed_at else "")
        flash(f'This request has already been {action} {processed_info} {processed_time}.', 'info')
        return redirect(url_for('admin.dashboard.index'))

    existing_user = User.query.filter_by(email=reg_request.email).first()
    _, detected_vlan, detected_ssid = detect_connection_type(reg_request.ip_address)
    default_vlan = reg_request.requested_vlan or detected_vlan

    existing_user_allowed_display = ''
    if existing_user:
        domain_policy = load_domain_policy_map().get(email_domain(existing_user.email))
        from core.user_utils import format_vlan_items_text
        existing_user_allowed_display = format_vlan_items_text(
            allowed_vlans_display_items(existing_user, get_vlan_map(), domain_policy)
        )

    return render_template(
        'admin_approve_request.html',
        request=reg_request,
        vlan_map=get_vlan_map(),
        existing_user=existing_user,
        existing_user_allowed_display=existing_user_allowed_display,
        detected_vlan=detected_vlan,
        detected_ssid=detected_ssid,
        detected_connection=detect_connection_type(reg_request.ip_address)[0],
        default_vlan=default_vlan,
        today=datetime.utcnow().date().isoformat(),
    )


@dashboard_bp.route('/requests/<int:request_id>/process', methods=['POST'])
@login_required
@permission_required('manage_users')
def process_request(request_id):
    reg_request = RegistrationRequest.query.get_or_404(request_id)

    if reg_request.status != 'pending':
        action_word = 'approved' if reg_request.status == 'approved' else 'rejected'
        processed_info = f"by admin {reg_request.processed_by}" if reg_request.processed_by else ""
        processed_time = (f"at {reg_request.processed_at.strftime('%Y-%m-%d %H:%M:%S')}"
                          if reg_request.processed_at else "")
        flash(f'This request was already {action_word} {processed_info} {processed_time}.', 'warning')
        return redirect(url_for('admin.dashboard.index'))

    action = request.form.get('action')

    if action == 'approve':
        vlan_id_raw = request.form.get('vlan_id')
        notes = request.form.get('notes', '').strip()
        vlan_map = get_vlan_map()
        try:
            target_vlan = int(vlan_id_raw) if vlan_id_raw else None
        except ValueError:
            target_vlan = None
        if not target_vlan:
            target_vlan = reg_request.requested_vlan or vlan_map.get('guests')

        connection_type, detected_vlan, ssid = detect_connection_type(reg_request.ip_address)
        network_mismatch = bool(
            connection_type == 'wifi' and detected_vlan
            and target_vlan and detected_vlan != target_vlan
        )

        existing_user = User.query.filter_by(email=reg_request.email).first()
        if existing_user:
            user = existing_user
            if notes:
                user.notes = f"{user.notes}\n{notes}" if user.notes else notes
        else:
            begin_date_raw = request.form.get('begin_date')
            begin_date = (datetime.strptime(begin_date_raw, '%Y-%m-%d').date()
                          if begin_date_raw else datetime.utcnow().date())
            expiry_date_str = request.form.get('expiry_date', '').strip()
            expiry_date = (datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
                           if expiry_date_str else None)
            user = User(
                email=reg_request.email,
                first_name=reg_request.first_name,
                last_name=reg_request.last_name,
                phone_number=reg_request.phone_number,
                begin_date=begin_date,
                expiry_date=expiry_date,
                notes=notes,
                created_by=current_user.username,
            )
            db.session.add(user)
            db.session.flush()

        device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
        if device:
            device.device_name     = reg_request.device_type or device.device_name or 'unknown'
            device.current_vlan    = target_vlan
            device.connection_type = connection_type
            device.ssid            = ssid
            device.is_wired        = connection_type == 'wired'
            device.wired_target_vlan = target_vlan if connection_type == 'wired' else None
            device.unregister_token = device.unregister_token or secrets.token_urlsafe(32)
        else:
            device = Device(
                mac_address=reg_request.mac_address,
                device_name=reg_request.device_type or 'unknown',
                current_vlan=target_vlan,
                connection_type=connection_type,
                ssid=ssid,
                is_wired=connection_type == 'wired',
                wired_target_vlan=target_vlan if connection_type == 'wired' else None,
                unregister_token=secrets.token_urlsafe(32),
            )
            db.session.add(device)
            db.session.flush()

        device.assigned_vlan     = target_vlan
        device.ownership_validated = True

        existing_ownership = get_active_ownership(device.mac_address)
        if not existing_ownership or existing_ownership.user_id != user.id:
            close_ownership(device.mac_address, commit=False)
            open_ownership(device.mac_address, user.id, commit=False)

        for req in RegistrationRequest.query.filter_by(
                mac_address=reg_request.mac_address, status='pending').all():
            req.status       = 'approved'
            req.processed_at = datetime.now()
            req.processed_by = current_user.username

        db.session.commit()

        kea = _get_kea()
        if connection_type == 'wifi':
            if kea:
                kea.register_mac(
                    mac=device.mac_address, vlan=target_vlan,
                    hostname=f"{(user.first_name or 'device').lower()}-device",
                    ip_address=None,
                )
                if device.ip_address and not network_mismatch:
                    try:
                        kea.force_lease_renewal(device.mac_address, device.ip_address)
                    except Exception as exc:
                        logger.warning("Could not force lease renewal: %s", exc)
        else:
            if kea:
                kea.register_mac(
                    mac=device.mac_address, vlan=target_vlan,
                    hostname=f"{(user.first_name or 'device').lower()}-device",
                    ip_address=None,
                )
            send_coa_change(device.mac_address, target_vlan)
            _replug_switch_port_for_mac(device.mac_address)

        if not network_mismatch:
            if device.ip_address:
                manage_dns_hijack('unhijack', device.ip_address)
            manage_switch_acl('unblock', reg_request.ip_address, detected_vlan)
            set_internet_accessible(device, True)
        else:
            set_internet_accessible(device, False)

        clear_unregistered_lease(device.mac_address)

        unregister_url = build_unregister_url(device.unregister_token)
        if connection_type == 'wired':
            assigned_ssid_display = "Wired Network"
        else:
            assigned_ssid_display = (
                from_vlan := __import__('core.vlan_utils', fromlist=['get_ssid_for_vlan'])
            ).get_ssid_for_vlan(target_vlan) or f"VLAN {target_vlan}"

        if network_mismatch:
            current_ssid_display = (
                device.ssid or
                __import__('core.vlan_utils', fromlist=['get_ssid_for_vlan']).get_ssid_for_vlan(detected_vlan)
                or f"VLAN {detected_vlan}"
            )
            send_vlan_mismatch_notification(
                user.email,
                user.first_name or reg_request.first_name or "there",
                requested_ssid=current_ssid_display,
                assigned_ssid=assigned_ssid_display,
                mac_address=device.mac_address,
                unregister_url=unregister_url,
            )
        else:
            if not device.ownership_validated:
                confirm_url, reject_url, confirm_timeout_sec = set_wifi_confirmation(device)
            else:
                confirm_url = reject_url = confirm_timeout_sec = None
            send_wifi_registration_confirmation(
                user.email,
                user.first_name or reg_request.first_name or "there",
                assigned_ssid_display,
                device.mac_address,
                unregister_url,
                confirm_url=confirm_url,
                reject_url=reject_url,
                confirm_timeout_sec=confirm_timeout_sec,
                registration_details={
                    "email":        user.email,
                    "first_name":   user.first_name or reg_request.first_name,
                    "last_name":    user.last_name  or reg_request.last_name,
                    "phone_number": user.phone_number or reg_request.phone_number,
                    "device_type":  device.device_name,
                    "ip_address":   device.ip_address,
                    "ssid":         assigned_ssid_display,
                },
            )

        central_client.queue_device_registered(device, user)
        flash(f'Request approved and user {user.email} registered', 'success')
        logger.info("Admin approved registration request for %s", user.email)

    elif action == 'reject':
        notes = request.form.get('notes', '').strip()
        if not notes:
            flash('Rejection reason is required.', 'error')
            return redirect(url_for('admin.dashboard.approve_request',
                                    token=reg_request.approval_token))

        reg_request.status       = 'rejected'
        reg_request.processed_at = datetime.now()
        reg_request.processed_by = current_user.username
        reg_request.notes        = notes

        rej_device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
        if rej_device:
            set_internet_blocked(rej_device, True, commit=False)

        db.session.commit()
        flash('Request rejected', 'info')
        logger.info("Admin rejected registration request for %s", reg_request.email)

    return redirect(url_for('admin.dashboard.index'))

def _normalize_mac(raw: str):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', raw or '').lower()
    if len(cleaned) != 12:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))


def _kea_managed_vlan_ids():
    """VLANs Kea actually serves (VALID_VLANS). ISP VLANs are usually excluded."""
    try:
        from core.vlan_utils import parse_valid_vlan_ids
        return {int(v) for v in parse_valid_vlan_ids()}
    except Exception:
        ids = set()
        for raw in (os.getenv('VALID_VLANS') or '').split(','):
            raw = raw.strip()
            if raw.isdigit():
                ids.add(int(raw))
        return ids


def _assignable_vlan_ids():
    """Same VLAN set as the assign / reassign dropdowns."""
    ids = {1}
    try:
        for entry in get_admin_assignable_entries():
            if getattr(entry, 'vlan_id', None) is not None:
                ids.add(int(entry.vlan_id))
    except Exception:
        logger.warning("Could not load admin-assignable VLANs", exc_info=True)
    try:
        for router in ISPRouter.query.all():
            if router.vlan_id is None:
                continue
            try:
                ids.add(int(router.vlan_id))
            except (TypeError, ValueError):
                continue
    except Exception:
        logger.warning("Could not load ISP router VLANs", exc_info=True)
    return ids

def _vlan_id_from_ip(ip: str):
    try:
        return int(str(ip).split('.')[2])
    except (IndexError, ValueError):
        return None

def _hp_mac(mac: str) -> str:
    h = re.sub(r'[^0-9a-f]', '', mac.lower())
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}"


def _set_port_role(host, port_name, role, description=''):
    db.session.execute(
        text("""
            UPDATE switch_ports
            SET port_role = :role, last_updated = NOW()
            WHERE switch_host = :host AND port_name = :name
        """),
        {'role': role, 'host': host, 'name': port_name},
    )


def _push_static_binding(host, port_name, ip, mac, vlan_id, undo=False):
    from core.switch import expand_switch_iface_name, run_switch_command, COMMON_PORT_UNDO_COMMANDS
    iface = expand_switch_iface_name(port_name)
    hp_mac = _hp_mac(mac)
    bind = f'ip source binding ip-address {ip} mac-address {hp_mac}'
    if undo:
        cmds = [
            'system-view',
            f'interface {iface}',
			] + COMMON_PORT_UNDO_COMMANDS + [
            f'interface {iface}',
            f'undo {bind}',
            'undo port hybrid pvid',
            f'undo port hybrid vlan {vlan_id}',
            'quit', 'quit', 'save force',
        ]
    else:
        cmds = [
            'system-view',
            f'interface {iface}',
			] + COMMON_PORT_UNDO_COMMANDS + [
            f'interface {iface}',
            'port link-type hybrid',
            'undo port hybrid vlan 1',
            f'port hybrid vlan {vlan_id} untagged',
            f'port hybrid pvid vlan {vlan_id}',
            bind,
            'quit', 'quit', 'save force',
        ]
    return run_switch_command(host, '\n'.join(cmds))


@dashboard_bp.route('/fixed-ip-reservations', methods=['POST'])
@login_required
@permission_required('manage_users')
def fixed_ip_reservations():
    """Register a static-IP device to an owner + VLAN. Reserve in Kea only when Kea manages that VLAN."""
    action = (request.form.get('action') or 'add').strip().lower()
    mac = _normalize_mac(request.form.get('mac_address') or '')
    ip = (request.form.get('ip') or '').strip()

    if not mac:
        flash('A valid MAC address is required.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    device = Device.query.filter_by(mac_address=mac).first()
    kea = _get_kea()
    kea_vlans = _kea_managed_vlan_ids()

    if action == 'delete':
        old_ip = (device.fixed_ip if device else None) or ip
        vlan_id = (
            (device.assigned_vlan if device else None)
            or (device.current_vlan if device else None)
            or _vlan_id_from_ip(old_ip)
        )
        if kea and old_ip and vlan_id and vlan_id in kea_vlans:
            try:
                kea.clear_fixed_ip(mac, vlan_id)
            except Exception as exc:
                logger.warning("Kea clear_reservation failed for %s: %s", mac, exc)
        if device:
            device.fixed_ip = None
            db.session.commit()
        flash(f'Cleared fixed IP reservation for {mac}.', 'success')
        return redirect(url_for('admin.dashboard.index'))

    owner_raw = (request.form.get('owner') or '').strip()
    if not owner_raw or ':' not in owner_raw:
        flash('An owner (user or admin) is required.', 'error')
        return redirect(url_for('admin.dashboard.index'))
    owner_type, owner_id_str = owner_raw.split(':', 1)
    try:
        owner_id = int(owner_id_str)
    except ValueError:
        flash('Invalid owner.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    new_user = new_admin = None
    if owner_type == 'user':
        new_user = User.query.get(owner_id)
        if not new_user:
            flash('User not found.', 'error')
            return redirect(url_for('admin.dashboard.index'))
    elif owner_type == 'admin':
        new_admin = Admin.query.get(owner_id)
        if not new_admin:
            flash('Admin not found.', 'error')
            return redirect(url_for('admin.dashboard.index'))
    else:
        flash('Invalid owner type.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    try:
        ipaddress.IPv4Address(ip)
    except Exception:
        flash(f'Invalid IP address: {ip}', 'error')
        return redirect(url_for('admin.dashboard.index'))

    try:
        vlan_id = int(request.form.get('vlan_id') or 0)
    except (TypeError, ValueError):
        vlan_id = 0
    if not vlan_id:
        flash('Select a VLAN from the list.', 'error')
        return redirect(url_for('admin.dashboard.index'))
    if vlan_id not in _assignable_vlan_ids():
        flash(f'VLAN {vlan_id} is not in the assignable VLAN list.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    clash = Device.query.filter(Device.fixed_ip == ip, Device.mac_address != mac).first()
    if clash:
        flash(f'{ip} is already reserved for {clash.mac_address}.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    kea_managed = vlan_id in kea_vlans
    kea_warning = None
    if kea_managed:
        if kea:
            try:
                reserved = False
                if hasattr(kea, 'reserve_fixed_ip'):
                    reserved = kea.reserve_fixed_ip(mac, vlan_id, ip)
                elif hasattr(kea, 'register_mac'):
                    reserved = kea.register_mac(
                        mac=mac, vlan=vlan_id, hostname='static', ip_address=ip,
                    )
                if not reserved:
                    flash('Kea rejected the reservation (IP outside subnet or Kea error).', 'error')
                    return redirect(url_for('admin.dashboard.index'))
            except Exception as exc:
                logger.exception("Kea reservation failed for %s -> %s", mac, ip)
                flash(f'Kea reservation failed: {exc}', 'error')
                return redirect(url_for('admin.dashboard.index'))
        else:
            kea_warning = (
                f'VLAN {vlan_id} is Kea-managed but Kea is unavailable; '
                f'{ip} was saved on the device only.'
            )
    else:
        kea_warning = (
            f'VLAN {vlan_id} is not managed by Kea. {ip} was recorded on the device '
            f'but no DHCP reservation was created. The upstream router for this VLAN '
            f'must not hand {ip} to another client.'
        )

    if not device:
        device = Device(mac_address=mac, device_name='static')
        db.session.add(device)
        db.session.flush()

    name = (request.form.get('device_name') or '').strip()
    if name:
        device.device_name = name
    elif not device.device_name:
        device.device_name = 'static'    

    device.fixed_ip = ip
    device.assigned_vlan = vlan_id
    device.current_vlan = vlan_id
    device.wired_target_vlan = vlan_id
    device.is_wired = True
    device.connection_type = device.connection_type or 'wired'
    device.ownership_validated = True
    if hasattr(device, 'stale'):
        device.stale = False
    if device.registration_status in (None, '', 'unregistered', 'wrong_vlan', 'pending'):
        device.registration_status = 'registered'

    close_ownership(mac, commit=False)
    open_ownership(
        mac,
        user_id=new_user.id if new_user else None,
        admin_id=new_admin.id if new_admin else None,
        commit=False,
    )
    try:
        set_internet_accessible(device, True, commit=False)
    except TypeError:
        set_internet_accessible(device, True)

    db.session.commit()

    owner_label = new_user.email if new_user else f'admin:{new_admin.username}'
    flash(f'Reserved {ip} for {mac} on VLAN {vlan_id}, owned by {owner_label}.', 'success')
    if kea_warning:
        flash(kea_warning, 'warning')
    logger.info(
        "Fixed IP reserved: %s -> %s vlan=%s owner=%s kea_managed=%s",
        mac, ip, vlan_id, owner_label, kea_managed,
    )
    return redirect(url_for('admin.dashboard.index'))