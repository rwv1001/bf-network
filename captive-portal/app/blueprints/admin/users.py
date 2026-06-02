"""
Admin — User Management (spec section 12.2).

Routes:
  GET/POST /admin/users/add              add a new user
  GET/POST /admin/users/<id>/edit        edit an existing user
  POST     /admin/users/import           bulk CSV import
  GET      /admin/users/import-template  download CSV template
  POST     /admin/users/<id>/block       block a user (and all their devices)
  POST     /admin/users/<id>/unblock     unblock a user
  POST     /admin/user/<id>/delete       delete a user (only if no active devices)
"""

import csv
import io
import logging
import os
import re
from datetime import datetime

from flask import (
    Blueprint, Response, flash, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from extensions import db
from models import Device, DeviceOwnership, User
from core.auth import permission_required
from core.device_utils import (
    close_ownership, get_active_ownership, open_ownership,
)
from core.network import apply_device_block, apply_device_unblock
from core.user_utils import (
    csv_template_example_value, csv_template_fields,
    default_vlan_for_user, email_domain, format_allowed_vlans,
    get_domain_policy_for_user, get_effective_vlans_for_user,
    load_domain_policy_map, normalize_csv_header, parse_allowed_vlans,
    parse_csv_bool, parse_vlan_override_form,
)
from core.vlan_utils import (
    get_ssid_for_vlan, get_vlan_entries, get_vlan_map,
    WIRED_UNREGISTERED_STATUS,
)
import central_client
from radius_coa import send_coa_change

logger = logging.getLogger(__name__)

users_bp = Blueprint('users', __name__)


def _normalize_mac_input(raw) -> str:
    if not raw:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(raw)).lower()
    if len(cleaned) != 12:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))


# ---------------------------------------------------------------------------
# Add user
# ---------------------------------------------------------------------------

@users_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def add_user():
    if request.method == 'POST':
        email        = request.form.get('email', '').strip().lower()
        first_name   = request.form.get('first_name', '').strip()
        last_name    = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        begin_date_raw = (request.form.get('begin_date') or '').strip()
        begin_date = (datetime.strptime(begin_date_raw, '%Y-%m-%d').date()
                      if begin_date_raw else datetime.utcnow().date())
        require_approval_every_device = bool(request.form.get('require_approval_every_device'))
        expiry_date_str = request.form.get('expiry_date', '').strip()
        expiry_date = (datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
                       if expiry_date_str else None)
        notes = request.form.get('notes', '').strip()

        if not email:
            flash('Email is required', 'error')
            return render_template('admin_add_user.html',
                                   vlan_map=get_vlan_map(),
                                   today=datetime.utcnow().date().isoformat())

        if User.query.filter_by(email=email).first():
            flash('User with this email already exists', 'error')
            return render_template('admin_add_user.html',
                                   vlan_map=get_vlan_map(),
                                   today=datetime.utcnow().date().isoformat())

        vlan_map = get_vlan_map()
        allowed_allow, allowed_deny = parse_vlan_override_form(vlan_map, 'allowed_vlan')
        adopt_allow, adopt_deny     = parse_vlan_override_form(vlan_map, 'adoptable_vlan')

        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            begin_date=begin_date,
            expiry_date=expiry_date,
            notes=notes,
            created_by=current_user.username,
            allowed_vlans_override=format_allowed_vlans(allowed_allow),
            allowed_vlans_deny=format_allowed_vlans(allowed_deny),
            adoptable_vlans_override=format_allowed_vlans(adopt_allow),
            adoptable_vlans_deny=format_allowed_vlans(adopt_deny),
            require_approval_every_device=require_approval_every_device,
        )
        db.session.add(user)
        db.session.commit()

        flash(f'User {email} added successfully', 'success')
        logger.info("Admin added user: %s", email)
        return redirect(url_for('admin.dashboard.index'))

    return render_template('admin_add_user.html',
                           vlan_map=get_vlan_map(),
                           today=datetime.utcnow().date().isoformat())


# ---------------------------------------------------------------------------
# Edit user
# ---------------------------------------------------------------------------

@users_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.first_name   = request.form.get('first_name', '').strip()
        user.last_name    = request.form.get('last_name', '').strip()
        user.phone_number = request.form.get('phone_number', '').strip()
        user.begin_date   = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        user.require_approval_every_device = bool(
            request.form.get('require_approval_every_device'))
        expiry_date_str = request.form.get('expiry_date', '').strip()
        user.expiry_date = (datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
                            if expiry_date_str else None)
        user.notes = request.form.get('notes', '').strip()

        # Network password management
        new_net_pwd    = request.form.get('new_network_password', '').strip()
        confirm_net_pwd = request.form.get('confirm_network_password', '').strip()
        clear_net_pwd  = bool(request.form.get('clear_network_password'))

        if clear_net_pwd:
            user.network_password_hash = None
            user.network_password_approval_mode = None
        elif new_net_pwd:
            if new_net_pwd != confirm_net_pwd:
                flash('Network passwords do not match.', 'error')
                return redirect(url_for('admin.users.edit_user', user_id=user.id))
            if len(new_net_pwd) < 8:
                flash('Network password must be at least 8 characters.', 'error')
                return redirect(url_for('admin.users.edit_user', user_id=user.id))
            user.set_network_password(new_net_pwd)
            user.network_password_approval_mode = 'first_use'

        vlan_map = get_vlan_map()
        allowed_allow, allowed_deny = parse_vlan_override_form(vlan_map, 'allowed_vlan')
        adopt_allow, adopt_deny     = parse_vlan_override_form(vlan_map, 'adoptable_vlan')
        user.allowed_vlans_override   = format_allowed_vlans(allowed_allow)
        user.allowed_vlans_deny       = format_allowed_vlans(allowed_deny)
        user.adoptable_vlans_override = format_allowed_vlans(adopt_allow)
        user.adoptable_vlans_deny     = format_allowed_vlans(adopt_deny)

        db.session.commit()
        central_client.queue_user_updated(user)

        flash(f'User {user.email} updated successfully', 'success')
        logger.info("Admin updated user: %s", user.email)
        return redirect(url_for('admin.dashboard.index'))

    allowed_allow = parse_allowed_vlans(user.allowed_vlans_override)
    allowed_deny  = parse_allowed_vlans(user.allowed_vlans_deny)
    adopt_allow   = parse_allowed_vlans(user.adoptable_vlans_override)
    adopt_deny    = parse_allowed_vlans(user.adoptable_vlans_deny)

    return render_template(
        'admin_edit_user.html',
        user=user,
        vlan_map=get_vlan_map(),
        allowed_vlans_allow=allowed_allow,
        allowed_vlans_deny=allowed_deny,
        adoptable_allow=adopt_allow,
        adoptable_deny=adopt_deny,
    )


# ---------------------------------------------------------------------------
# Block / unblock user
# ---------------------------------------------------------------------------

@users_bp.route('/users/<int:user_id>/block', methods=['POST'])
@login_required
@permission_required('manage_users')
def block_user(user_id):
    """Spec B.a: block all currently-owned devices for a user."""
    user = User.query.get_or_404(user_id)
    user.blocked = True
    db.session.commit()

    active_macs = [
        o.mac_address for o in
        DeviceOwnership.query.filter_by(user_id=user.id, end_datetime=None).all()
    ]
    devices = Device.query.filter(Device.mac_address.in_(active_macs)).all() if active_macs else []
    for device in devices:
        apply_device_block(device, flash_messages=False)

    central_client.queue_user_blocked(user)
    flash(f'User {user.email} blocked. {len(devices)} device(s) blocked.', 'success')
    logger.info("Admin blocked user %s (%d devices)", user.email, len(devices))
    return redirect(url_for('admin.dashboard.index'))


@users_bp.route('/users/<int:user_id>/unblock', methods=['POST'])
@login_required
@permission_required('manage_users')
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.blocked = False
    db.session.commit()

    active_macs = [
        o.mac_address for o in
        DeviceOwnership.query.filter_by(user_id=user.id, end_datetime=None).all()
    ]
    blocked_count = (
        Device.query.filter(
            Device.mac_address.in_(active_macs),
            Device.registration_status == 'blocked',
        ).count()
        if active_macs else 0
    )

    if blocked_count:
        flash(
            f'User {user.email} unblocked. {blocked_count} device(s) still blocked — '
            'unblock each device manually.',
            'info',
        )
    else:
        flash(f'User {user.email} unblocked.', 'success')

    central_client.queue_user_unblocked(user)
    logger.info("Admin unblocked user %s", user.email)
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Delete user
# ---------------------------------------------------------------------------

@users_bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@permission_required('manage_users')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    device_count = DeviceOwnership.query.filter_by(
        user_id=user_id, end_datetime=None
    ).count()
    if device_count > 0:
        flash(
            f'Cannot delete {user.email}: they still own {device_count} device(s). '
            'Delete or reassign them first.',
            'error',
        )
        return redirect(url_for('admin.dashboard.index'))
    db.session.delete(user)
    db.session.commit()
    logger.info("Admin deleted user %s", user.email)
    flash(f'User {user.email} deleted.', 'success')
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------

@users_bp.route('/users/import', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def import_users():
    if request.method == 'GET':
        vlan_map = get_vlan_map()
        base_fields, vlan_fields = csv_template_fields(vlan_map)
        return render_template(
            'admin_import_users.html',
            vlan_map=vlan_map,
            base_fields=base_fields,
            vlan_fields=vlan_fields,
        )

    upload = request.files.get('csv_file')
    if not upload or not upload.filename:
        flash('Please select a CSV file to upload.', 'error')
        return redirect(url_for('admin.users.import_users'))

    content = upload.read().decode('utf-8-sig', errors='replace')
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        flash('CSV file must include a header row.', 'error')
        return redirect(url_for('admin.users.import_users'))

    header_map = {
        normalize_csv_header(name): name
        for name in reader.fieldnames
        if name is not None
    }

    def get_value(row, *names):
        for name in names:
            key = normalize_csv_header(name)
            if key in header_map:
                return row.get(header_map[key])
        return None

    vlan_flag_columns = []
    for name in reader.fieldnames:
        if not name:
            continue
        normalized = re.sub(r'\s+', '', str(name)).lower()
        match = re.match(r'^vlan(\d+)(allowed|adoptable)$', normalized)
        if match:
            vlan_flag_columns.append((int(match.group(1)), match.group(2), name))

    dry_run = bool(request.form.get('dry_run'))
    today = datetime.utcnow().date()
    vlan_map = get_vlan_map()
    domain_policy_map = load_domain_policy_map()
    unregistered_vlan = vlan_map.get('unregistered')

    stats = {
        'rows': 0, 'users_created': 0, 'users_updated': 0,
        'devices_created': 0, 'devices_updated': 0, 'rows_skipped': 0,
    }
    errors = []

    for index, row in enumerate(reader, start=2):
        if not row or not any((v or '').strip() for v in row.values()):
            continue
        stats['rows'] += 1

        email_raw = get_value(row, 'email', 'email address', 'e-mail')
        if not email_raw or not str(email_raw).strip():
            errors.append(f"Row {index}: missing email address")
            stats['rows_skipped'] += 1
            continue

        email = str(email_raw).strip().lower()
        user = User.query.filter_by(email=email).first()
        created = False
        if not user:
            user = User(email=email, begin_date=today, created_by=current_user.username)
            created = True

        first_name   = get_value(row, 'first name', 'firstname')
        last_name    = get_value(row, 'second name', 'last name', 'lastname', 'surname')
        phone_number = get_value(row, 'phone number', 'phone')
        if first_name   and str(first_name).strip():   user.first_name   = str(first_name).strip()
        if last_name    and str(last_name).strip():    user.last_name    = str(last_name).strip()
        if phone_number and str(phone_number).strip(): user.phone_number = str(phone_number).strip()

        allowed_allow = parse_allowed_vlans(user.allowed_vlans_override)
        allowed_deny  = parse_allowed_vlans(user.allowed_vlans_deny)
        adopt_allow   = parse_allowed_vlans(user.adoptable_vlans_override)
        adopt_deny    = parse_allowed_vlans(user.adoptable_vlans_deny)

        for vlan_id, kind, header_name in vlan_flag_columns:
            flag = parse_csv_bool(row.get(header_name))
            if flag is None:
                continue
            if kind == 'allowed':
                if flag:
                    allowed_allow.add(vlan_id); allowed_deny.discard(vlan_id)
                else:
                    allowed_deny.add(vlan_id); allowed_allow.discard(vlan_id)
            else:
                if flag:
                    adopt_allow.add(vlan_id); adopt_deny.discard(vlan_id)
                else:
                    adopt_deny.add(vlan_id); adopt_allow.discard(vlan_id)

        user.allowed_vlans_override   = format_allowed_vlans(allowed_allow)
        user.allowed_vlans_deny       = format_allowed_vlans(allowed_deny)
        user.adoptable_vlans_override = format_allowed_vlans(adopt_allow)
        user.adoptable_vlans_deny     = format_allowed_vlans(adopt_deny)

        if created:
            db.session.add(user)
            db.session.flush()
            stats['users_created'] += 1
        else:
            stats['users_updated'] += 1

        mac_raw = get_value(row, 'mac address', 'mac', 'mac_address')
        if mac_raw and str(mac_raw).strip():
            mac_address = _normalize_mac_input(mac_raw)
            if not mac_address:
                errors.append(f"Row {index}: invalid MAC address '{mac_raw}'")
            else:
                device = Device.query.filter_by(mac_address=mac_address).first()
                if device and device.user_id and device.user_id != user.id:
                    errors.append(
                        f"Row {index}: MAC {mac_address} already belongs to another user"
                    )
                else:
                    if not device:
                        device = Device(mac_address=mac_address)
                        db.session.add(device)
                        stats['devices_created'] += 1
                    else:
                        stats['devices_updated'] += 1

                    close_ownership(mac_address, commit=False)
                    open_ownership(mac_address, user.id, commit=False)

                    device_type = get_value(row, 'device type', 'device')
                    if device_type and str(device_type).strip():
                        device.device_name = str(device_type).strip()[:100]

                    vlan_raw = get_value(row, 'vlan id', 'vlan')
                    target_vlan = None
                    if vlan_raw and str(vlan_raw).strip():
                        try:
                            vlan_id = int(str(vlan_raw).strip())
                            target_vlan = vlan_id
                            device.current_vlan = vlan_id
                            device.ssid = get_ssid_for_vlan(vlan_id)
                        except ValueError:
                            errors.append(f"Row {index}: invalid VLAN ID '{vlan_raw}'")

                    if target_vlan is None:
                        domain_policy = get_domain_policy_for_user(user, domain_policy_map)
                        from core.user_utils import effective_vlan_sets
                        eff_allowed, _, _, _ = effective_vlan_sets(user, domain_policy)
                        default_vlan = default_vlan_for_user(eff_allowed, vlan_map)
                        if device.current_vlan in {None, unregistered_vlan}:
                            target_vlan = default_vlan
                            if target_vlan:
                                device.current_vlan = target_vlan
                                device.ssid = device.ssid or get_ssid_for_vlan(target_vlan)

                    device.registration_status = 'registered'

    if dry_run:
        db.session.rollback()
        flash('Dry run complete. No changes were saved.', 'info')
    else:
        db.session.commit()

    flash(
        "CSV import complete. Rows: {rows}, Users created: {users_created}, "
        "Users updated: {users_updated}, Devices created: {devices_created}, "
        "Devices updated: {devices_updated}, Rows skipped: {rows_skipped}.".format(**stats),
        'success',
    )
    if errors:
        flash(f"CSV import reported {len(errors)} issue(s).", 'warning')

    vlan_map = get_vlan_map()
    base_fields, vlan_fields = csv_template_fields(vlan_map)
    return render_template(
        'admin_import_users.html',
        errors=errors,
        vlan_map=vlan_map,
        base_fields=base_fields,
        vlan_fields=vlan_fields,
    )


@users_bp.route('/users/import-template', methods=['GET'])
@login_required
@permission_required('manage_users')
def import_users_template():
    vlan_map = get_vlan_map()
    base_fields, vlan_fields = csv_template_fields(vlan_map)
    allowed_headers = [header for _, header in (base_fields + vlan_fields)]
    requested = request.args.getlist('field')
    selected = [header for header in allowed_headers if header in requested]
    if not selected:
        selected = [header for _, header in base_fields]
    if 'Email' not in selected:
        selected.insert(0, 'Email')

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(selected)
    writer.writerow([csv_template_example_value(header, 0) for header in selected])
    writer.writerow([csv_template_example_value(header, 1) for header in selected])

    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=users_import_template.csv'
    return response