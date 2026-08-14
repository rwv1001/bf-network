"""Admin — Unregistered Devices section (Spec dashboard section A).

Routes:
  GET  /admin/unregistered     redirects to main dashboard (unregistered tab)
  POST /admin/assign-device    assign an unregistered device to a user/admin + VLAN
"""

import logging
import os
import secrets
from datetime import datetime

from flask import Blueprint, flash, redirect, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import (
    Admin, Device, IPLease, RegistrationRequest,
    UnregisteredLease, User, VlanMapping,
)
from core.auth import permission_required
from core.device_utils import (
    close_ownership, get_active_iplease, open_ownership,
    set_internet_accessible, sync_registration_status,
    clear_unregistered_lease,
)
from core.mac_utils import get_ip_for_mac, detect_connection_type
from core.network import manage_dns_hijack, manage_switch_acl
from core.vlan_utils import (
    get_admin_assignable_entries, get_vlan_map, label_for_vlan,
    get_wired_unregistered_vlan_id, is_blocked_pool_ip,
)
from core.portal_utils import build_unregister_url
from email_service import send_wifi_registration_confirmation
import central_client
from kea_integration import get_kea_client
from radius_coa import send_coa_change

logger = logging.getLogger(__name__)

unregistered_bp = Blueprint('unregistered', __name__)

KEA_SOCKET = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')


def _get_kea():
    try:
        return get_kea_client(control_socket=KEA_SOCKET)
    except Exception:
        return None


def _should_hijack_vlan(_vlan_id):
    return True


def _replug_switch_port_for_mac(mac_address):
    try:
        from core.network import replug_switch_port_for_mac
        return replug_switch_port_for_mac(mac_address)
    except Exception as exc:
        logger.warning("replug_switch_port_for_mac failed for %s: %s", mac_address, exc)
        return False


@unregistered_bp.route('/unregistered')
@login_required
@permission_required('manage_users')
def list_unregistered():
    return redirect(url_for('admin.dashboard.index'))


@unregistered_bp.route('/assign-device', methods=['POST'])
@login_required
@permission_required('manage_users')
def assign_device():
    """
    Spec dashboard A: assign an unregistered device to a user + VLAN.
    """
    mac_address = (request.form.get('mac_address') or '').strip().lower()
    owner_raw = (request.form.get('owner') or '').strip()
    device_name = (request.form.get('device_name') or '').strip()
    vlan_id_raw = (request.form.get('vlan_id') or '').strip()

    logger.info(
        "assign_device: ENTRY form mac=%r owner=%r device_name=%r vlan_id_raw=%r "
        "admin=%s all_form=%s",
        mac_address,
        owner_raw,
        device_name,
        vlan_id_raw,
        getattr(current_user, 'username', None),
        dict(request.form),
    )

    if not mac_address or not owner_raw or not vlan_id_raw:
        logger.warning(
            "assign_device: REJECT missing fields mac=%r owner=%r vlan_id_raw=%r",
            mac_address, owner_raw, vlan_id_raw,
        )
        flash('MAC address, owner, and VLAN are required.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    if ':' not in owner_raw:
        logger.warning("assign_device: REJECT bad owner_raw=%r", owner_raw)
        flash('Invalid owner selection.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    owner_type, owner_id_str = owner_raw.split(':', 1)
    try:
        owner_id = int(owner_id_str)
        vlan_id = int(vlan_id_raw)
    except ValueError:
        logger.warning(
            "assign_device: REJECT ValueError owner_id_str=%r vlan_id_raw=%r",
            owner_id_str, vlan_id_raw,
        )
        flash('Invalid owner ID or VLAN ID.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    logger.info(
        "assign_device: parsed mac=%s owner_type=%s owner_id=%s vlan_id=%s",
        mac_address, owner_type, owner_id, vlan_id,
    )

    user = None
    admin_owner = None
    if owner_type == 'user':
        user = User.query.get(owner_id)
        if not user:
            logger.warning("assign_device: REJECT user_id=%s not found", owner_id)
            flash('User not found.', 'error')
            return redirect(url_for('admin.unregistered.list_unregistered'))
    elif owner_type == 'admin':
        admin_owner = Admin.query.get(owner_id)
        if not admin_owner:
            logger.warning("assign_device: REJECT admin_id=%s not found", owner_id)
            flash('Admin not found.', 'error')
            return redirect(url_for('admin.unregistered.list_unregistered'))
    else:
        logger.warning("assign_device: REJECT owner_type=%r", owner_type)
        flash('Invalid owner type.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    vlan_mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    existing_device = Device.query.filter_by(mac_address=mac_address).first()
    logger.info(
        "assign_device: vlan_mapping=%s wired_enabled=%s existing_device_id=%s "
        "existing.assigned_vlan=%s existing.connection_type=%s",
        getattr(vlan_mapping, 'id', None),
        getattr(vlan_mapping, 'wired_enabled', None),
        getattr(existing_device, 'id', None),
        getattr(existing_device, 'assigned_vlan', None),
        getattr(existing_device, 'connection_type', None),
    )

    if (
        existing_device and existing_device.connection_type == 'wired'
        and vlan_mapping and not vlan_mapping.wired_enabled
    ):
        logger.warning(
            "assign_device: REJECT vlan=%s not wired_enabled for wired device %s",
            vlan_id, mac_address,
        )
        flash(f'VLAN {vlan_id} does not allow wired connections.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    ip_lease = get_active_iplease(mac_address)
    ip_address = ip_lease.ip_address if ip_lease else None
    logger.info(
        "assign_device: ip_lease=%s ip_from_lease=%s",
        getattr(ip_lease, 'id', None), ip_address,
    )
    if not ip_address:
        ul = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
        ip_address = ul.ip_address if ul else None
        logger.info("assign_device: ip_from_unregistered_lease=%s", ip_address)
    if not ip_address:
        kea = _get_kea()
        if kea:
            try:
                ip_address = kea.get_lease_ip_for_mac(mac_address, subnet_id=vlan_id)
                logger.info("assign_device: ip_from_kea=%s", ip_address)
            except Exception as exc:
                logger.error("assign_device: Kea lookup failed for %s: %s", mac_address, exc)
    if not ip_address:
        ip_address = get_ip_for_mac(mac_address, subnet_id=vlan_id)
        logger.info("assign_device: ip_from_get_ip_for_mac=%s", ip_address)

    device = Device.query.filter_by(mac_address=mac_address).first()
    created = False
    if not device:
        device = Device(mac_address=mac_address, first_seen=datetime.utcnow())
        db.session.add(device)
        created = True
    logger.info(
        "assign_device: device row created=%s id=%s before_set assigned_vlan=%s",
        created, getattr(device, 'id', None), getattr(device, 'assigned_vlan', None),
    )

    _, detected_vlan, _ = (
        detect_connection_type(ip_address) if ip_address else (None, None, None)
    )
    logger.info(
        "assign_device: detect_connection_type ip=%s → detected_vlan=%s",
        ip_address, detected_vlan,
    )

    _assigned_vlan_mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    _is_wired_assignment = bool(
        _assigned_vlan_mapping and _assigned_vlan_mapping.wired_enabled
    )
    logger.info(
        "assign_device: _is_wired_assignment=%s (mapping_id=%s wired_enabled=%s)",
        _is_wired_assignment,
        getattr(_assigned_vlan_mapping, 'id', None),
        getattr(_assigned_vlan_mapping, 'wired_enabled', None),
    )

    device.device_name = device_name or device.device_name or 'admin-assigned'
    device.assigned_vlan = vlan_id
    device.current_vlan = detected_vlan or vlan_id
    device.wired_target_vlan = (
        vlan_id if (detected_vlan and detected_vlan != vlan_id) else None
    )
    device.ownership_validated = True
    device.stale = False


    if _is_wired_assignment:
        device.connection_type = 'wired'
        device.is_wired = True
    else:
        device.connection_type = device.connection_type or 'unknown'

    if not device.unregister_token:
        device.unregister_token = secrets.token_urlsafe(32)

    logger.info(
        "assign_device: BEFORE commit1 id=%s assigned_vlan=%s current_vlan=%s "
        "wired_target_vlan=%s ownership_validated=%s stale=%s user_id=%s admin_id=%s "
        "connection_type=%s is_wired=%s dirty=%s",
        getattr(device, 'id', None),
        device.assigned_vlan,
        device.current_vlan,
        device.wired_target_vlan,
        device.ownership_validated,
        getattr(device, 'stale', None),
        getattr(device, 'user_id', None),
        getattr(device, 'admin_id', None),
        device.connection_type,
        getattr(device, 'is_wired', None),
        list(db.session.dirty),
    )

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("assign_device: commit1 FAILED: %s", exc)
        flash(f'Database error saving device: {exc}', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    # Re-read from DB so we see what actually persisted
    db.session.expire_all()
    device = Device.query.filter_by(mac_address=mac_address).first()
    logger.info(
        "assign_device: AFTER commit1 re-read id=%s assigned_vlan=%s current_vlan=%s "
        "wired_target_vlan=%s admin_id=%s user_id=%s",
        getattr(device, 'id', None),
        getattr(device, 'assigned_vlan', None),
        getattr(device, 'current_vlan', None),
        getattr(device, 'wired_target_vlan', None),
        getattr(device, 'admin_id', None),
        getattr(device, 'user_id', None),
    )

    logger.info("assign_device: close_ownership / open_ownership mac=%s", mac_address)
    close_ownership(mac_address, commit=True)
    open_ownership(
        mac_address,
        user_id=user.id if user else None,
        admin_id=admin_owner.id if admin_owner else None,
        commit=True,
    )

    db.session.expire_all()
    device = Device.query.filter_by(mac_address=mac_address).first()
    logger.info(
        "assign_device: AFTER ownership assigned_vlan=%s admin_id=%s user_id=%s",
        getattr(device, 'assigned_vlan', None),
        getattr(device, 'admin_id', None),
        getattr(device, 'user_id', None),
    )

    same_vlan = (detected_vlan == vlan_id) if detected_vlan else False
    lease_usable = (
        ip_lease
        and ip_lease.lease_expiry > datetime.utcnow()
        and not ip_lease.from_blocked_pool
    )
    logger.info(
        "assign_device: same_vlan=%s lease_usable=%s ip_address=%s "
        "detected_vlan=%s target_vlan=%s",
        same_vlan, lease_usable, ip_address, detected_vlan, vlan_id,
    )

    if same_vlan and lease_usable and ip_address:
        logger.info("assign_device: PATH same_vlan unblock")
        if _should_hijack_vlan(vlan_id):
            manage_dns_hijack('unhijack', ip_address)
        manage_switch_acl('unblock', ip_address, vlan_id)
        if ip_lease:
            ip_lease.dns_hijacked = False
            db.session.commit()
        set_internet_accessible(device, True, commit=True)
        sync_registration_status(device)
        db.session.commit()
    else:
        logger.info("assign_device: PATH wrong_vlan CoA+replug")
        device.internet_accessible = False
        device.registration_status = 'registered'
        # Re-assert VLAN in case helpers cleared it
        device.assigned_vlan = vlan_id
        if detected_vlan and detected_vlan != vlan_id:
            device.wired_target_vlan = vlan_id
            device.registration_status = 'wrong_vlan'
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.exception("assign_device: commit2 FAILED: %s", exp)
        logger.info(
            "assign_device: AFTER commit2 assigned_vlan=%s registration_status=%s",
            device.assigned_vlan, device.registration_status,
        )
        send_coa_change(mac_address, vlan_id)
        _replug_switch_port_for_mac(mac_address)

    db.session.expire_all()
    device = Device.query.filter_by(mac_address=mac_address).first()
    logger.info(
        "assign_device: AFTER network ops assigned_vlan=%s current_vlan=%s "
        "wired_target=%s",
        getattr(device, 'assigned_vlan', None),
        getattr(device, 'current_vlan', None),
        getattr(device, 'wired_target_vlan', None),
    )

    kea = _get_kea()
    if kea:
        try:
            logger.info(
                "assign_device: Kea register_mac mac=%s vlan=%s ip=%s",
                mac_address, vlan_id, ip_address if same_vlan else None,
            )
            kea.register_mac(
                mac=mac_address,
                vlan=vlan_id,
                hostname=device.device_name or 'admin-assigned',
                ip_address=ip_address if same_vlan else None,
            )
        except Exception as exc:
            logger.error("assign_device: Kea reservation failed for %s: %s", mac_address, exc)

    clear_unregistered_lease(mac_address)

    if user and device.unregister_token:
        unregister_url = build_unregister_url(device.unregister_token)
        ssid_display = get_vlan_map().get(str(vlan_id), '') or f'VLAN {vlan_id}'
        send_wifi_registration_confirmation(
            user.email,
            user.first_name or 'there',
            ssid_display,
            mac_address,
            unregister_url,
            registration_details={
                'email': user.email,
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'phone_number': user.phone_number or '',
                'device_type': device.device_name,
                'ip_address': ip_address,
                'ssid': ssid_display,
            },
        )

    if user:
        central_client.queue_device_registered(device, user)

    owner_label = user.email if user else f'admin:{admin_owner.username}'
    flash(
        f'Device {mac_address} assigned to {owner_label} on VLAN {vlan_id}.',
        'success',
    )

    db.session.expire_all()
    final = Device.query.filter_by(mac_address=mac_address).first()
    logger.info(
        "assign_device: EXIT success admin=%s mac=%s owner=%s vlan=%s "
        "FINAL assigned_vlan=%s current_vlan=%s wired_target=%s admin_id=%s user_id=%s "
        "ownership_validated=%s stale=%s registration_status=%s",
        getattr(current_user, 'username', 'unknown'),
        mac_address,
        owner_label,
        vlan_id,
        getattr(final, 'assigned_vlan', None),
        getattr(final, 'current_vlan', None),
        getattr(final, 'wired_target_vlan', None),
        getattr(final, 'admin_id', None),
        getattr(final, 'user_id', None),
        getattr(final, 'ownership_validated', None),
        getattr(final, 'stale', None),
        getattr(final, 'registration_status', None),
    )
    return redirect(url_for('admin.unregistered.list_unregistered'))