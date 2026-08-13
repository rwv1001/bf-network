"""
Admin — Registered Device Management (spec section 12.3).

Routes:
  POST /admin/device/<id>/block          block a device
  POST /admin/device/<id>/unblock        unblock a device
  POST /admin/device/<id>/change-vlan    change a wired device's VLAN
  POST /admin/devices/change-vlan        bulk VLAN change for wired devices
  POST /admin/device/<id>/delete         unregister a device
  POST /admin/device/<id>/reassign       reassign a device to a different user
  POST /admin/devices/<id>/disconnect    CoA disconnect
  POST /api/admin/set-fixed-ip           set or clear a fixed IP reservation
"""

import ipaddress
import json
import logging
import os
import secrets
from datetime import datetime

from flask import Blueprint, abort, flash, jsonify, redirect, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import Device, DeviceOwnership, IPLease, RegistrationRequest, User, Admin
from core.auth import permission_required
from core.device_utils import (
    close_ownership, get_active_iplease, get_active_ownership,
    open_ownership, set_internet_accessible, set_internet_blocked,
    sync_registration_status, upsert_iplease,
)
from core.network import (
    apply_device_block, apply_device_unblock,
    cleanup_orphan_hijack_rules, manage_dns_hijack, manage_switch_acl,
)
from core.vlan_utils import (
    get_vlan_map, get_wired_assignable_vlan_ids, is_blocked_pool_ip,
)
import central_client
from kea_integration import get_kea_client
from radius_coa import send_coa_change, send_coa_disconnect

logger = logging.getLogger(__name__)

devices_bp = Blueprint('devices', __name__)

KEA_SOCKET = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')


def _get_kea():
    try:
        return get_kea_client(control_socket=KEA_SOCKET)
    except Exception:
        return None


def _normalize_mac_input(raw) -> str:
    import re
    if not raw:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(raw)).lower()
    if len(cleaned) != 12:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))


def _replug_switch_port_for_mac(mac_address):
    try:
        from core.network import replug_switch_port_for_mac
        return replug_switch_port_for_mac(mac_address)
    except Exception as exc:
        logger.warning("replug_switch_port_for_mac failed for %s: %s", mac_address, exc)
        return False


# ---------------------------------------------------------------------------
# Block / unblock
# ---------------------------------------------------------------------------

@devices_bp.route('/device/<int:device_id>/block', methods=['POST'])
@login_required
def block_device(device_id):
    device = Device.query.get_or_404(device_id)
    apply_device_block(device, flash_messages=True)
    return redirect(url_for('admin.dashboard.index'))


@devices_bp.route('/device/<int:device_id>/unblock', methods=['POST'])
@login_required
def unblock_device(device_id):
    device = Device.query.get_or_404(device_id)
    if device.user and device.user.blocked:
        flash(f'Cannot unblock device: user {device.user.email} is still blocked.', 'error')
        return redirect(url_for('admin.dashboard.index'))
    apply_device_unblock(device, flash_messages=True)
    central_client.queue_device_unblocked(device)
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Change VLAN (single device)
# ---------------------------------------------------------------------------

@devices_bp.route('/device/<int:device_id>/change-vlan', methods=['POST'])
@login_required
def change_device_vlan(device_id):
    device = Device.query.get_or_404(device_id)
    target_raw = (request.form.get('target_vlan') or '').strip()
    try:
        target_vlan = int(target_raw)
    except ValueError:
        target_vlan = None

    if not target_vlan:
        flash('Target VLAN is required.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    if device.connection_type != 'wired':
        flash('Only wired devices can be moved with RADIUS CoA.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    if target_vlan not in get_wired_assignable_vlan_ids():
        flash('Target VLAN is not enabled for wired access.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    device.current_vlan      = target_vlan
    device.is_wired          = True
    device.wired_target_vlan = target_vlan
    device.assigned_vlan     = target_vlan
    db.session.commit()

    send_coa_change(device.mac_address, target_vlan)
    kea = _get_kea()
    if kea:
        try:
            kea.register_mac(mac=device.mac_address, vlan=target_vlan,
                             hostname=device.device_name or 'device', ip_address=None)
        except Exception as exc:
            logger.warning("Kea registration failed for %s: %s", device.mac_address, exc)
    central_client.queue_device_vlan_changed(device)

    flash(f'Device {device.mac_address} moved to VLAN {target_vlan}.', 'success')
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Bulk VLAN change
# ---------------------------------------------------------------------------

@devices_bp.route('/devices/change-vlan', methods=['POST'])
@login_required
def change_devices_vlan():
    import re as _re
    target_raw = (request.form.get('target_vlan') or '').strip()
    macs_raw   = (request.form.get('mac_addresses') or '').strip()
    try:
        target_vlan = int(target_raw)
    except ValueError:
        target_vlan = None

    if not target_vlan or not macs_raw:
        flash('Target VLAN and MAC list are required.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    if target_vlan not in get_wired_assignable_vlan_ids():
        flash('Target VLAN is not enabled for wired access.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    mac_values = _re.split(r'[\s,]+', macs_raw)
    macs = [v for v in (_normalize_mac_input(m) for m in mac_values) if v]

    updated = 0
    skipped = 0
    kea = _get_kea()
    for mac in macs:
        device = Device.query.filter_by(mac_address=mac).first()
        if not device or device.connection_type != 'wired':
            skipped += 1
            continue
        device.current_vlan      = target_vlan
        device.is_wired          = True
        device.wired_target_vlan = target_vlan
        device.assigned_vlan     = target_vlan
        updated += 1
        send_coa_change(device.mac_address, target_vlan)
        if kea:
            try:
                kea.register_mac(mac=device.mac_address, vlan=target_vlan,
                                 hostname=device.device_name or 'device', ip_address=None)
            except Exception as exc:
                logger.warning("Kea registration failed for %s: %s", device.mac_address, exc)
        central_client.queue_device_vlan_changed(device)

    if updated:
        db.session.commit()

    flash(f'Updated {updated} wired device(s). Skipped {skipped}.', 'success')
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Unregister (delete) device — spec C.d
# ---------------------------------------------------------------------------

@devices_bp.route('/device/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    mac_address = device.mac_address
    ip_address  = device.ip_address
    vlan_id     = device.assigned_vlan or device.current_vlan

    # Cut off internet access if device currently has it
    if device.internet_accessible and ip_address and not is_blocked_pool_ip(ip_address):
        from core.device_utils import get_lease_expiry_for_mac, upsert_iplease
        lease_expiry = get_lease_expiry_for_mac(mac_address, subnet_id=vlan_id)
        if lease_expiry and lease_expiry > datetime.utcnow():
            if vlan_id:
                manage_switch_acl('block', ip_address, vlan_id)
            manage_dns_hijack('hijack', ip_address)
            upsert_iplease(
                mac_address=mac_address, ip_address=ip_address, vlan_id=vlan_id,
                lease_start=datetime.utcnow(), lease_expiry=lease_expiry,
                from_blocked_pool=False, dns_hijacked=True,
            )

    kea = _get_kea()
    if kea:
        try:
            kea.unregister_mac(mac_address, vlan_id)
        except Exception as exc:
            logger.warning("Kea unregister failed for %s: %s", mac_address, exc)

    if device.connection_type == 'wired':
        send_coa_disconnect(mac_address)

    close_ownership(mac_address, commit=False)

    device.device_name         = None
    device.assigned_vlan       = None
    device.current_vlan        = None
    device.wired_target_vlan   = None
    device.internet_accessible = None
    device.internet_blocked    = None
    device.ownership_validated = None
    device.stale               = True
    sync_registration_status(device)

    central_client.queue_device_unregistered(mac_address)
    db.session.commit()
    cleanup_orphan_hijack_rules()

    flash(f'Device {mac_address} has been unregistered', 'success')
    logger.info("Admin unregistered device %s", mac_address)
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Reassign device — spec C.a
# ---------------------------------------------------------------------------

@devices_bp.route('/device/<int:device_id>/reassign', methods=['POST'])
@login_required
@permission_required('manage_users')
def reassign_device(device_id):
    device = Device.query.get_or_404(device_id)
    owner_raw = request.form.get('owner', '').strip()
    if not owner_raw or ':' not in owner_raw:
        flash('An owner must be selected.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    owner_type, owner_id_str = owner_raw.split(':', 1)
    try:
        owner_id = int(owner_id_str)
    except ValueError:
        flash('Invalid owner ID.', 'error')
        return redirect(url_for('admin.dashboard.index'))

    new_user = None
    new_admin = None
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

    old_label = device.user.email if device.user else (
        f'admin:{device.admin.username}' if device.admin else 'unowned')
    close_ownership(device.mac_address, commit=False)
    open_ownership(device.mac_address, user_id=new_user.id if new_user else None,
                   admin_id=new_admin.id if new_admin else None, commit=False)
    db.session.commit()

    new_label = new_user.email if new_user else f'admin:{new_admin.username}'
    if new_user:
        central_client.queue_device_registered(device, new_user)
    logger.info("Admin reassigned device %s from %s to %s",
                device.mac_address, old_label, new_label)
    flash(f'Device {device.mac_address} reassigned to {new_label}.', 'success')
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Disconnect device
# ---------------------------------------------------------------------------

@devices_bp.route('/devices/<int:device_id>/disconnect', methods=['POST'])
@login_required
def disconnect_device(device_id):
    device = Device.query.get_or_404(device_id)
    success = send_coa_disconnect(device.mac_address)
    if success:
        vlan_map = get_vlan_map()
        device.registration_status = 'disconnected'
        device.current_vlan = vlan_map['unregistered']
        db.session.commit()
        flash(f'Device {device.mac_address} disconnected', 'success')
    else:
        flash('Failed to disconnect device', 'error')
    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Set fixed IP
# ---------------------------------------------------------------------------

@devices_bp.route('/api/admin/set-fixed-ip', methods=['POST'])
@login_required
@permission_required('manage_users')
def set_fixed_ip():
    data      = request.get_json(silent=True) or {}
    device_id = data.get('device_id')
    ip_raw    = (data.get('ip') or '').strip()

    if not device_id:
        return jsonify({'ok': False, 'error': 'device_id required'}), 400

    device = Device.query.get(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404

    vlan = device.current_vlan or device.assigned_vlan
    if not vlan:
        return jsonify({'ok': False, 'error': 'Device has no VLAN assigned'}), 400

    kea = _get_kea()

    # Clear mode
    if not ip_raw:
        if device.fixed_ip:
            old_ip = device.fixed_ip
            device.fixed_ip = None
            try:
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                return jsonify({'ok': False, 'error': 'Database error'}), 500
            if device.registration_status == 'registered' and kea:
                kea.register_mac(device.mac_address, vlan)
            logger.info('Admin %s cleared fixed IP %s for device %s',
                        current_user.username, old_ip, device.mac_address)
        return jsonify({'ok': True, 'fixed_ip': None})

    # Set mode
    try:
        ip_obj = ipaddress.IPv4Address(ip_raw)
    except ValueError:
        return jsonify({'ok': False, 'error': 'Invalid IP address'}), 400

    # Validate IP is within the device's VLAN subnet
    kea_config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    subnet_net = None
    try:
        with open(kea_config_path, 'r', encoding='utf-8') as _f:
            _kea_cfg = json.load(_f)
        for _subnet in _kea_cfg.get('Dhcp4', {}).get('subnet4', []):
            try:
                if int(_subnet.get('id')) == int(vlan):
                    subnet_net = ipaddress.IPv4Network(_subnet['subnet'], strict=False)
                    break
            except Exception:
                continue
    except Exception as exc:
        logger.warning('set-fixed-ip: could not read KEA config: %s', exc)

    if subnet_net is None:
        net_word = os.getenv('NETWORK_WORD', '192.168')
        subnet_net = ipaddress.IPv4Network(f'{net_word}.{vlan}.0/24', strict=False)

    if ip_obj not in subnet_net:
        return jsonify({
            'ok': False,
            'error': f'IP {ip_raw} is not within VLAN {vlan} subnet {subnet_net}'
        }), 400

    if ip_obj in (subnet_net.network_address, subnet_net.broadcast_address):
        return jsonify({'ok': False, 'error': 'Cannot use network or broadcast address'}), 400

    existing_lease = IPLease.query.filter(
        IPLease.ip_address == ip_raw,
        IPLease.lease_expiry > datetime.utcnow(),
    ).first()
    if existing_lease and existing_lease.mac_address != device.mac_address:
        return jsonify({
            'ok': False,
            'error': f'IP {ip_raw} is currently leased to {existing_lease.mac_address}'
        }), 409

    conflict = Device.query.filter(
        Device.fixed_ip == ip_raw,
        Device.id != device_id,
    ).first()
    if conflict:
        return jsonify({
            'ok': False,
            'error': f'IP {ip_raw} is already the fixed IP for device {conflict.mac_address}'
        }), 409

    if not kea:
        return jsonify({'ok': False, 'error': 'Kea not available'}), 500

    ok = kea.register_mac(device.mac_address, vlan, ip_address=ip_raw)
    if not ok:
        return jsonify({'ok': False, 'error': 'Kea reservation failed — check Kea logs'}), 500

    device.fixed_ip = ip_raw
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({'ok': False, 'error': 'Database error'}), 500

    logger.info('Admin %s set fixed IP %s for device %s (VLAN %s)',
                current_user.username, ip_raw, device.mac_address, vlan)
    return jsonify({'ok': True, 'fixed_ip': ip_raw})