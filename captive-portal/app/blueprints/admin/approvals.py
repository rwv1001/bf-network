"""
Admin — Pending Approvals / Registration Requests (spec section 6).

Routes:
  GET  /admin/approve/<token>              show approval page for a request
  POST /admin/requests/<id>/process        approve or reject a request
  GET/POST /admin/set-user-password/<token> admin sets a user's network password
"""

import logging
import os
import secrets
from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import (
    Device, DeviceOwnership, IPLease, RegistrationRequest, User, VlanMapping,
)
from core.auth import permission_required
from core.device_utils import (
    clear_unregistered_lease, get_active_iplease, get_active_ownership,
    open_ownership, close_ownership, set_internet_accessible,
    set_internet_blocked, sync_registration_status,
)
from core.mac_utils import detect_connection_type
from core.network import manage_dns_hijack, manage_switch_acl
from core.portal_utils import build_unregister_url, set_wifi_confirmation
from core.user_utils import (
    allowed_vlans_display_items, email_domain, format_vlan_items_text,
    get_effective_vlans_for_user, load_domain_policy_map,
)
from core.vlan_utils import get_ssid_for_vlan, get_vlan_map
from email_service import (
    send_network_password_set_email,
    send_vlan_mismatch_notification,
    send_wifi_registration_confirmation,
)
import central_client
from kea_integration import get_kea_client
from radius_coa import send_coa_change

logger = logging.getLogger(__name__)

approvals_bp = Blueprint('approvals', __name__)

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


# ---------------------------------------------------------------------------
# Approve request page
# ---------------------------------------------------------------------------

@approvals_bp.route('/approve/<token>')
@login_required
@permission_required('manage_users')
def approve_request(token):
    """Show the approval page for a registration request (spec section 6)."""
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()

    if reg_request.status != 'pending':
        action = 'approved' if reg_request.status == 'approved' else 'rejected'
        processed_info = (
            f"by admin {reg_request.processed_by}" if reg_request.processed_by else ""
        )
        processed_time = (
            f"at {reg_request.processed_at.strftime('%Y-%m-%d %H:%M:%S')}"
            if reg_request.processed_at else ""
        )
        flash(
            f'This request has already been {action} {processed_info} {processed_time}.',
            'info',
        )
        return redirect(url_for('admin.dashboard.index'))

    existing_user = User.query.filter_by(email=reg_request.email).first()
    _, detected_vlan, detected_ssid = detect_connection_type(reg_request.ip_address)
    default_vlan = reg_request.requested_vlan or detected_vlan

    existing_user_allowed_display = ''
    if existing_user:
        domain_policy = load_domain_policy_map().get(email_domain(existing_user.email))
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


# ---------------------------------------------------------------------------
# Process request (approve / reject)
# ---------------------------------------------------------------------------

@approvals_bp.route('/requests/<int:request_id>/process', methods=['POST'])
@login_required
@permission_required('manage_users')
def process_request(request_id):
    """Approve or reject a registration request (spec section 6)."""
    reg_request = RegistrationRequest.query.get_or_404(request_id)

    if reg_request.status != 'pending':
        action_word = 'approved' if reg_request.status == 'approved' else 'rejected'
        processed_info = (
            f"by admin {reg_request.processed_by}" if reg_request.processed_by else ""
        )
        processed_time = (
            f"at {reg_request.processed_at.strftime('%Y-%m-%d %H:%M:%S')}"
            if reg_request.processed_at else ""
        )
        flash(
            f'This request was already {action_word} {processed_info} {processed_time}.',
            'warning',
        )
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
            connection_type == 'wifi'
            and detected_vlan
            and target_vlan
            and detected_vlan != target_vlan
        )

        existing_user = User.query.filter_by(email=reg_request.email).first()
        if existing_user:
            user = existing_user
            if notes:
                user.notes = f"{user.notes}\n{notes}" if user.notes else notes
        else:
            begin_date_raw = request.form.get('begin_date')
            begin_date = (
                datetime.strptime(begin_date_raw, '%Y-%m-%d').date()
                if begin_date_raw else datetime.utcnow().date()
            )
            expiry_date_str = request.form.get('expiry_date', '').strip()
            expiry_date = (
                datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
                if expiry_date_str else None
            )
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
            device.device_name = reg_request.device_type or device.device_name or 'unknown'
            device.current_vlan = target_vlan
            device.connection_type = connection_type
            device.ssid = ssid
            device.is_wired = connection_type == 'wired'
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

        device.assigned_vlan = target_vlan
        device.ownership_validated = True

        existing_ownership = get_active_ownership(device.mac_address)
        if not existing_ownership or existing_ownership.user_id != user.id:
            close_ownership(device.mac_address, commit=False)
            open_ownership(device.mac_address, user.id, commit=False)

        for req in RegistrationRequest.query.filter_by(
                mac_address=reg_request.mac_address, status='pending').all():
            req.status = 'approved'
            req.processed_at = datetime.now()
            req.processed_by = current_user.username

        db.session.commit()

        kea = _get_kea()
        if connection_type == 'wifi':
            if kea:
                kea.register_mac(
                    mac=device.mac_address,
                    vlan=target_vlan,
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
                    mac=device.mac_address,
                    vlan=target_vlan,
                    hostname=f"{(user.first_name or 'device').lower()}-device",
                    ip_address=None,
                )
            send_coa_change(device.mac_address, target_vlan)
            _replug_switch_port_for_mac(device.mac_address)

        if not network_mismatch:
            if device.ip_address and _should_hijack_vlan(target_vlan):
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
                get_ssid_for_vlan(target_vlan) or f"VLAN {target_vlan}"
            )

        if network_mismatch:
            current_ssid_display = (
                device.ssid
                or get_ssid_for_vlan(detected_vlan)
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
            return redirect(url_for(
                'admin.approvals.approve_request',
                token=reg_request.approval_token,
            ))

        reg_request.status = 'rejected'
        reg_request.processed_at = datetime.now()
        reg_request.processed_by = current_user.username
        reg_request.notes = notes

        rej_device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
        if rej_device:
            set_internet_blocked(rej_device, True, commit=False)

        db.session.commit()
        flash('Request rejected', 'info')
        logger.info("Admin rejected registration request for %s", reg_request.email)

    return redirect(url_for('admin.dashboard.index'))


# ---------------------------------------------------------------------------
# Admin sets a user's network password (token-secured, no login required)
# ---------------------------------------------------------------------------

@approvals_bp.route('/set-user-password/<token>', methods=['GET', 'POST'])
def set_user_password(token):
    """
    Admin page (token-secured, no login required) to set a user's network
    password and choose the approval policy for a pending_password request.
    """
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()

    if reg_request.status != 'pending_password':
        return render_template(
            'admin_set_user_password.html',
            already_processed=True,
            already_action=reg_request.status,
            reg_request=reg_request,
        )

    user = User.query.filter_by(email=reg_request.email).first()

    if request.method == 'GET':
        already_has_password = bool(user and user.has_network_password)
        return render_template(
            'admin_set_user_password.html',
            reg_request=reg_request,
            user=user,
            already_has_password=already_has_password,
        )

    # POST — validate and apply
    password = (request.form.get('password') or '').strip()
    confirm  = (request.form.get('confirm_password') or '').strip()

    if not password or len(password) < 8:
        return render_template(
            'admin_set_user_password.html',
            reg_request=reg_request,
            user=user,
            form_error='Password must be at least 8 characters.',
        )
    if password != confirm:
        return render_template(
            'admin_set_user_password.html',
            reg_request=reg_request,
            user=user,
            form_error='Passwords do not match. Please try again.',
        )

    if not user:
        user = User(
            email=reg_request.email,
            first_name=reg_request.first_name,
            last_name=reg_request.last_name,
            phone_number=reg_request.phone_number,
            begin_date=datetime.utcnow().date(),
            notes='Created via admin password setup',
            created_by='admin-password-setup',
        )
        db.session.add(user)
        db.session.flush()

    user.set_network_password(password)
    user.network_password_set_token = None
    user.network_password_set_token_expires = None
    user.network_password_approval_mode = 'first_use'
    db.session.commit()
    central_client.queue_user_updated(user)

    return render_template(
        'admin_set_user_password.html',
        success=True,
        reg_request=reg_request,
        user=user,
    )