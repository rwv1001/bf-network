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

    Sets ownership_validated=True and, when connectivity conditions allow,
    removes the DNS hijack / ACL block and sets internet_accessible=True.
    """
    mac_address = (request.form.get('mac_address') or '').strip().lower()
    owner_raw = (request.form.get('owner') or '').strip()
    device_name = (request.form.get('device_name') or '').strip()
    vlan_id_raw = (request.form.get('vlan_id') or '').strip()

    if not mac_address or not owner_raw or not vlan_id_raw:
        flash('MAC address, owner, and VLAN are required.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    if ':' not in owner_raw:
        flash('Invalid owner selection.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    owner_type, owner_id_str = owner_raw.split(':', 1)
    try:
        owner_id = int(owner_id_str)
        vlan_id = int(vlan_id_raw)
    except ValueError:
        flash('Invalid owner ID or VLAN ID.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    user = None
    admin_owner = None
    if owner_type == 'user':
        user = User.query.get(owner_id)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin.unregistered.list_unregistered'))
    elif owner_type == 'admin':
        admin_owner = Admin.query.get(owner_id)
        if not admin_owner:
            flash('Admin not found.', 'error')
            return redirect(url_for('admin.unregistered.list_unregistered'))
    else:
        flash('Invalid owner type.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    # Validate VLAN is wired-enabled if device is wired
    vlan_mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    existing_device = Device.query.filter_by(mac_address=mac_address).first()
    if (
        existing_device and existing_device.connection_type == 'wired'
        and vlan_mapping and not vlan_mapping.wired_enabled
    ):
        flash(f'VLAN {vlan_id} does not allow wired connections.', 'error')
        return redirect(url_for('admin.unregistered.list_unregistered'))

    # Resolve current IP for the MAC
    ip_lease = get_active_iplease(mac_address)
    ip_address = ip_lease.ip_address if ip_lease else None
    if not ip_address:
        ul = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
        ip_address = ul.ip_address if ul else None
    if not ip_address:
        kea = _get_kea()
        if kea:
            try:
                ip_address = kea.get_lease_ip_for_mac(mac_address, subnet_id=vlan_id)
            except Exception as exc:
                logger.error("Kea lookup failed for %s: %s", mac_address, exc)
    if not ip_address:
        ip_address = get_ip_for_mac(mac_address, subnet_id=vlan_id)

    # Get or create Device record
    device = Device.query.filter_by(mac_address=mac_address).first()
    if not device:
        device = Device(mac_address=mac_address, first_seen=datetime.utcnow())
        db.session.add(device)

    _, detected_vlan, _ = (
        detect_connection_type(ip_address) if ip_address else (None, None, None)
    )

    _assigned_vlan_mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    _is_wired_assignment = bool(_assigned_vlan_mapping and _assigned_vlan_mapping.wired_enabled)

    device.device_name = device_name or device.device_name or 'admin-assigned'
    device.assigned_vlan = vlan_id
    device.current_vlan = detected_vlan or vlan_id
    device.wired_target_vlan = vlan_id if (detected_vlan and detected_vlan != vlan_id) else None
    device.ownership_validated = True
    if _is_wired_assignment:
        device.connection_type = 'wired'
        device.is_wired = True
    else:
        device.connection_type = device.connection_type or 'unknown'
    if not device.unregister_token:
        device.unregister_token = secrets.token_urlsafe(32)
    db.session.commit()

    # Ensure DeviceOwnership is correct
    close_ownership(mac_address, commit=True)
    open_ownership(mac_address, user_id=user.id if user else None,
                   admin_id=admin_owner.id if admin_owner else None, commit=True)

    # Spec A.a.ii / A.b: determine whether to unblock now
    same_vlan = (detected_vlan == vlan_id) if detected_vlan else False
    lease_usable = (
        ip_lease
        and ip_lease.lease_expiry > datetime.utcnow()
        and not ip_lease.from_blocked_pool
    )

    if same_vlan and lease_usable and ip_address:
        # Remove DNS hijack and ACL block synchronously, then mark accessible
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
        # Wrong VLAN or blocked-pool IP — CoA + replug to force re-auth
        device.internet_accessible = False
        device.registration_status = 'registered'
        db.session.commit()
        send_coa_change(mac_address, vlan_id)
        _replug_switch_port_for_mac(mac_address)

    # Register with Kea
    kea = _get_kea()
    if kea:
        try:
            kea.register_mac(
                mac=mac_address,
                vlan=vlan_id,
                hostname=device.device_name or 'admin-assigned',
                ip_address=ip_address if same_vlan else None,
            )
        except Exception as exc:
            logger.error("Kea reservation failed for %s: %s", mac_address, exc)

    clear_unregistered_lease(mac_address)

    # Send email notification to user (not for admin-owned devices)
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
    logger.info(
        "Admin %s assigned device %s to %s (vlan=%s)",
        getattr(current_user, 'username', 'unknown'),
        mac_address,
        owner_label,
        vlan_id,
    )
    return redirect(url_for('admin.unregistered.list_unregistered'))