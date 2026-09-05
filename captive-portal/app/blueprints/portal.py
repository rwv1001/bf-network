"""
Public captive-portal routes (spec sections 1–5 and 8).

Covers:
  /                           root redirect (spec 4a/4b)
  /register                   device registration form + status page
  /verify                     email verification
  /status                     registration status
  /blocked                    blocked device page
  /login                      user login (spec 4a)
  /user_home                  user home page (spec 5)
  /set-network-password/<t>   user sets their own network password via token
  /forgot-network-password
  /pending-approval
  /request-rejected
  /wrong-vlan
  /registered
  /unregister/<token>         spec 8 — user rejects device via email link
  /confirm/<token>            WiFi ownership confirmation
  /reject/<token>             WiFi ownership rejection
  /adopt                      device adoption (spec 5b)
  /adopt/change-vlan
  /api/device-status          polling endpoint
  /api/registration-status
  /api/block-status
  /api/request-unblock
  /.well-known/captive-portal
  /generate_204  /gen_204  /access-check  /hotspot-detect.html
  /library/test/success.html  /ncsi.txt  /connecttest.txt  /redirect  /portal
"""

import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Blueprint, flash, jsonify, redirect, render_template,
    request, session, url_for,
)

from extensions import db
from models import (
    Device, DeviceOwnership, IPLease, RegistrationRequest,
    UnregisteredLease, User, VlanMapping,
)
from core.device_utils import (
    close_ownership, clear_unregistered_lease, get_active_iplease,
    get_active_ownership, get_lease_expiry_for_mac, normalize_device_status,
    open_ownership, set_internet_accessible, set_internet_blocked,
    should_have_internet, sync_registration_status, upsert_iplease,
    unregister_device,
)
from core.mac_utils import (
    current_user_from_device, detect_connection_type, get_client_ip,
    get_client_mac, get_ip_for_mac, load_adoptable_leases,
)
from core.network import (
    apply_device_unblock, manage_dns_hijack, manage_switch_acl,
)
from core.portal_utils import (
    build_portal_url, build_confirm_url, build_reject_url,
    build_set_password_url, build_unregister_url, enforce_wifi_confirmation,
    get_portal_base_url, portal_host_mismatch, set_wifi_confirmation,
    wifi_confirm_timeout_minutes,
)
from core.user_utils import (
    default_vlan_for_user, get_effective_vlans_for_user,
    load_domain_policy_map,
)
from core.vlan_utils import (
    get_ssid_for_vlan, get_vlan_map, get_wired_assignable_entries,
    get_wired_assignable_vlan_ids, get_wired_unregistered_vlan_id,
    is_blocked_pool_ip, label_for_vlan, vlan_requires_password,
)
from email_service import (
    send_admin_notification, send_admin_unblock_request,
    send_network_password_reset_email, send_network_password_set_email,
    send_vlan_mismatch_notification, send_wifi_registration_confirmation,
)
import central_client
from kea_integration import get_kea_client
from radius_coa import send_coa_change

from security import limiter

logger = logging.getLogger(__name__)

portal_bp = Blueprint('portal', __name__)

KEA_SOCKET = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')

from ipaddress import ip_address as parse_ip

def _is_proxy_or_loopback_ip(value):
    try:
        ip = parse_ip(value)
        return ip.is_loopback or str(ip) == '127.0.0.1'
    except Exception:
        return True


def _effective_device_ip(mac_address, request_ip):
    if request_ip and not _is_proxy_or_loopback_ip(request_ip):
        return request_ip

    lease = get_active_iplease(mac_address)
    if lease and lease.ip_address:
        return lease.ip_address

    lease_ip = get_ip_for_mac(mac_address)
    if lease_ip:
        return lease_ip

    return request_ip


def _hydrate_user_from_central(email, user=None):
    email = (email or '').strip().lower()
    if not email:
        return user, None
    central_user = central_client.lookup_user_at_central(email)
    if not central_user:
        return user, None
    if user is None:
        user = User.query.filter_by(email=email).first()
    if user:
        changed = False
        if central_user.get('first_name') and not user.first_name:
            user.first_name = central_user['first_name']
            changed = True
        if central_user.get('last_name') and not user.last_name:
            user.last_name = central_user['last_name']
            changed = True
        if central_user.get('phone_number') and not user.phone_number:
            user.phone_number = central_user['phone_number']
            changed = True
        if central_user.get('network_password_hash') and not user.network_password_hash:
            user.network_password_hash = central_user['network_password_hash']
            if not user.network_password_approval_mode:
                user.network_password_approval_mode = 'first_use'
            changed = True
        if central_user.get('blocked') and not user.blocked:
            user.blocked = True
            changed = True
        if changed:
            db.session.commit()
    return user, central_user

from ipaddress import ip_address as parse_ip, ip_network as parse_net

def _site_networks():
    nets = []
    extra = (os.getenv('SITE_NETWORKS') or '').strip()
    if extra:
        for part in extra.split(','):
            part = part.strip()
            if part:
                try:
                    nets.append(parse_net(part, strict=False))
                except ValueError:
                    logger.warning("Ignoring invalid SITE_NETWORKS entry: %s", part)
    word = (os.getenv('NETWORK_WORD') or '').strip()
    if word.count('.') == 1:
        nets.append(parse_net(f"{word}.0.0/16", strict=False))
    elif word.count('.') == 2:
        nets.append(parse_net(f"{word}.0/24", strict=False))
    if not nets:
        nets = [
            parse_net('10.0.0.0/8'),
            parse_net('172.16.0.0/12'),
            parse_net('192.168.0.0/16'),
        ]
    return nets

def client_is_on_site():
    raw = get_client_ip()
    try:
        addr = parse_ip(raw)
    except Exception:
        return False
    if addr.is_loopback:
        return True
    return any(addr in net for net in _site_networks())

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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


def _build_prefill_from_request():
    return {
        'email':        request.args.get('email', '').strip(),
        'first_name':   request.args.get('first_name', '').strip(),
        'last_name':    request.args.get('last_name', '').strip(),
        'phone_number': request.args.get('phone_number', '').strip(),
        'device_type':  request.args.get('device_type', '').strip(),
    }


# ---------------------------------------------------------------------------
# Captive-portal OS detection endpoints
# ---------------------------------------------------------------------------

@portal_bp.route('/generate_204')
@portal_bp.route('/gen_204')
def android_captive_portal_detection():
    return redirect(build_portal_url(url_for('portal.register'))), 302


@portal_bp.route('/access-check')
def access_check():
    mac_address = get_client_mac()
    if not mac_address:
        return ('', 409)
    device = Device.query.filter_by(mac_address=mac_address).first()
    ownership = get_active_ownership(mac_address) if device else None
    if device and ownership and device.registration_status == 'registered':
        return ('', 204)
    return ('', 409)


@portal_bp.route('/hotspot-detect.html')
def ios_captive_portal_detection():
    return redirect(build_portal_url(url_for('portal.register'))), 302


@portal_bp.route('/library/test/success.html')
def ios_captive_success():
    return redirect(build_portal_url(url_for('portal.register'))), 302


@portal_bp.route('/ncsi.txt')
@portal_bp.route('/connecttest.txt')
@portal_bp.route('/redirect', methods=['GET', 'POST', 'OPTIONS'])
def windows_captive_portal_detection():
    if request.method == 'OPTIONS':
        resp = portal_bp.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        return resp, 200
    return redirect(build_portal_url(url_for('portal.register'))), 302


@portal_bp.route('/.well-known/captive-portal')
def rfc8908_captive_portal():
    mac_address = get_client_mac()
    portal_url = build_portal_url(url_for('portal.register'))
    captive = True
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device:
            if not device.internet_blocked and device.internet_accessible:
                captive = False
    resp = jsonify({'captive': captive, 'user-portal-url': portal_url})
    resp.headers['Content-Type'] = 'application/captive+json'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


# ---------------------------------------------------------------------------
# Root / portal entry point
# ---------------------------------------------------------------------------

@portal_bp.route('/portal')
@portal_bp.route('/', methods=['GET', 'POST', 'OPTIONS'])
def index():
    if request.method == 'OPTIONS':
        resp = portal_bp.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        return resp, 200

    mac_address = get_client_mac()
    if not mac_address:
        return redirect(build_portal_url(url_for('portal.user_login')))

    device = Device.query.filter_by(mac_address=mac_address).first()
    if device and device.internet_blocked:
        return render_template(
            'blocked.html',
            ip_address=get_client_ip(),
            mac_address=mac_address,
            admin_email=os.getenv('ADMIN_EMAIL', 'admin@example.com'),
        )
    return redirect(build_portal_url(url_for('portal.register')))


# ---------------------------------------------------------------------------
# Blocked page + unblock request API
# ---------------------------------------------------------------------------

@portal_bp.route('/blocked', methods=['GET', 'POST', 'OPTIONS'])
def blocked_page():
    if request.method == 'OPTIONS':
        resp = portal_bp.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        return resp, 200
    if request.method == 'GET' and portal_host_mismatch():
        return redirect(build_portal_url(url_for('portal.blocked_page')))
    return render_template(
        'blocked.html',
        ip_address=get_client_ip(),
        mac_address=get_client_mac(),
        admin_email=os.getenv('ADMIN_EMAIL', 'admin@example.com'),
    )


@portal_bp.route('/api/request-unblock', methods=['POST', 'OPTIONS'])
def api_request_unblock():
    if request.method == 'OPTIONS':
        resp = portal_bp.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        return resp, 200
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    device = Device.query.filter_by(mac_address=mac_address).first() if mac_address else None
    user = device.user if device else None
    try:
        send_admin_unblock_request(
            mac_address or 'Unknown',
            ip_address or 'Unknown',
            user_name=f"{user.first_name} {user.last_name}".strip() if user else None,
            user_email=user.email if user else None,
        )
    except Exception as exc:
        logger.warning("Failed to send unblock request email: %s", exc)
    resp = jsonify({'status': 'ok', 'message': 'Your request has been sent to the administrator.'})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


# ---------------------------------------------------------------------------
# API polling endpoints
# ---------------------------------------------------------------------------

@portal_bp.route('/api/device-status')
def api_device_status():
    logger.debug("=== /api/device-status called ===")

    mac_address = get_client_mac()
    request_ip = get_client_ip()
    ip_address = _effective_device_ip(mac_address, request_ip) if mac_address else request_ip

    logger.debug(f"Detected MAC: {mac_address}, IP: {ip_address}")

    if not mac_address:
        logger.warning("/api/device-status: No MAC address detected")
        return jsonify({'status': 'no_mac'}), 200

    device = Device.query.filter_by(mac_address=mac_address).first()
    ownership = get_active_ownership(mac_address) if device else None

    logger.debug(f"Device found: {bool(device)}, Ownership found: {bool(ownership)}")

    if not device or not ownership:
        logger.debug(f"/api/device-status: Device or ownership missing for MAC {mac_address}")
        return jsonify({'status': 'unregistered'}), 200

    lease = get_active_iplease(mac_address)
    logger.debug(f"Active lease found: {bool(lease)}")

    if device.internet_blocked:
        logger.debug(f"Device {mac_address} is internet_blocked=True")
        return jsonify({'status': 'blocked'})

    _, detected_vlan, detected_ssid = detect_connection_type(ip_address)
    selected_vlan = device.assigned_vlan or detected_vlan
    password_required = vlan_requires_password(selected_vlan) if selected_vlan else False

    logger.debug(f"detected_vlan={detected_vlan}, assigned_vlan={device.assigned_vlan}, "
                 f"selected_vlan={selected_vlan}, password_required={password_required}")

    if password_required and not device.ownership_validated:
        if device.user and not device.user.has_network_password:
            _hydrate_user_from_central(device.user.email, device.user)
        logger.debug(f"Device {mac_address} requires password")
        return jsonify({
            'status': 'need_password',
            'has_password': device.user.has_network_password if device.user else False,
            'selected_vlan': selected_vlan,
        })

    assigned_vlan = device.assigned_vlan

    if assigned_vlan is None:
        logger.debug(f"Device {mac_address} has no assigned_vlan → pending_approval")
        return jsonify({'status': 'pending_approval', 'selected_vlan': selected_vlan})

    if assigned_vlan != detected_vlan:
        logger.info(f"VLAN MISMATCH for {mac_address}: assigned={assigned_vlan}, detected={detected_vlan}")
        return jsonify({
            'status': 'wrong_vlan',
            'assigned_vlan': assigned_vlan,
            'assigned_ssid': get_ssid_for_vlan(assigned_vlan),
            'detected_vlan': detected_vlan,
            'connection_type': device.connection_type,   # helpful for frontend
        })

    if device.internet_accessible is True:
        logger.debug(f"Device {mac_address} has full access (internet_accessible=True)")
        return jsonify({
            'status': 'accessible',
            'user_home_url': build_portal_url(url_for('portal.user_home')),
            'ownership_validated': bool(device.ownership_validated),
        })

    if device.internet_accessible is False:
        logger.debug(f"Device {mac_address} has access_refused")
        return jsonify({
            'status': 'access_refused',
            'notes': getattr(device, 'admin_notes', None),
        })

    # internet_accessible is None — still provisioning
    from_blocked_pool = lease.from_blocked_pool if lease else False
    logger.debug(f"Provisioning in progress. from_blocked_pool={from_blocked_pool}")

    if from_blocked_pool:
        return jsonify({'status': 'blocked_pool', 'assigned_vlan': assigned_vlan})

    # Try to unhijack if conditions are met
    if lease and lease.dns_hijacked and not from_blocked_pool:
        if should_have_internet(device):
            ip_addr = lease.ip_address
            if ip_addr:
                logger.info(f"Unhijacking device {mac_address} on IP {ip_addr}")
                if _should_hijack_vlan(assigned_vlan):
                    manage_dns_hijack('unhijack', ip_addr)
                manage_switch_acl('unblock', ip_addr, assigned_vlan)
            lease.dns_hijacked = False
            db.session.commit()
            set_internet_accessible(device, True, commit=True)

            if not device.ownership_validated and device.user:
                _u = device.user
                _unreg = build_unregister_url(device.unregister_token)
                _curl, _rurl, _ctimeout = set_wifi_confirmation(device)
                send_wifi_registration_confirmation(
                    _u.email, _u.first_name or 'there',
                    get_ssid_for_vlan(assigned_vlan) or 'Network',
                    device.mac_address, _unreg,
                    confirm_url=_curl, reject_url=_rurl,
                    confirm_timeout_sec=_ctimeout,
                    registration_details={},
                )

            resp_data = {
                'status': 'accessible',
                'user_home_url': build_portal_url(url_for('portal.user_home')),
                'ownership_validated': bool(device.ownership_validated),
            }
            if not device.ownership_validated:
                resp_data['confirm_timeout_minutes'] = wifi_confirm_timeout_minutes()
            return jsonify(resp_data)

    logger.debug(f"Device {mac_address} is still in 'pending' state")
    return jsonify({'status': 'pending'})


@portal_bp.route('/api/registration-status', methods=['GET', 'OPTIONS'])
def registration_status():
    origin = request.headers.get('Origin', '')
    allowed_origins = [
        'http://www.msftconnecttest.com', 'http://connectivitycheck.gstatic.com',
        'http://captive.apple.com', 'http://detectportal.firefox.com',
        'http://msftconnecttest.com',
    ]
    acao_value = origin if origin in allowed_origins else '*'

    if request.method == 'OPTIONS':
        resp = portal_bp.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = acao_value
        resp.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        resp.headers['Vary'] = 'Origin'
        return resp, 200

    mac_address = get_client_mac()
    if not mac_address:
        resp = jsonify({'status': 'unknown', 'message': 'Could not detect MAC address'})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp

    device = Device.query.filter_by(mac_address=mac_address).first()
    device = normalize_device_status(device)
    device = enforce_wifi_confirmation(device)

    if device and not get_active_ownership(mac_address):
        if device.internet_blocked:
            payload = {'status': 'blocked', 'message': 'Your device has been blocked.'}
            if device.user and device.user.blocked:
                payload['reason'] = 'The administrator has blocked you from connecting any devices.'
            else:
                rej = RegistrationRequest.query.filter_by(
                    mac_address=mac_address, status='rejected'
                ).order_by(RegistrationRequest.submitted_at.desc()).first()
                if rej and rej.notes:
                    payload['reason'] = rej.notes
            resp = jsonify(payload)
            resp.headers['Access-Control-Allow-Origin'] = '*'
            return resp
        recent = RegistrationRequest.query.filter_by(
            mac_address=mac_address
        ).order_by(RegistrationRequest.submitted_at.desc()).first()
        if recent and recent.status == 'rejected':
            payload = {'status': 'rejected', 'message': 'Your registration request was rejected.'}
            if recent.notes:
                payload['reason'] = recent.notes
            resp = jsonify(payload)
            resp.headers['Access-Control-Allow-Origin'] = '*'
            return resp
        resp = jsonify({'status': 'unregistered', 'message': 'Not registered'})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp

    if device:
        request_ip = get_client_ip()
        current_ip = _effective_device_ip(mac_address, request_ip)
        _, current_vlan, detected_ssid = detect_connection_type(current_ip)
        current_ssid = get_ssid_for_vlan(current_vlan) or detected_ssid
        expected_ssid = get_ssid_for_vlan(device.current_vlan) or device.ssid
        network_mismatch = bool(
            current_vlan and device.current_vlan and current_vlan != device.current_vlan
        )

        _sel_vlan = device.assigned_vlan or current_vlan
        _pw_req = vlan_requires_password(_sel_vlan) if _sel_vlan else False
        if _pw_req and not device.ownership_validated:
            if device.user and not device.user.has_network_password:
                _hydrate_user_from_central(device.user.email, device.user)
            _has_pwd = device.user.has_network_password if device.user else False
            if not _has_pwd:
                pw_resp = jsonify({
                    'status': 'pending_password',
                    'message': 'A network password is required. An email has been sent to set it.',
                })
            else:
                pw_resp = jsonify({
                    'status': 'enter_password',
                    'message': 'Please enter your network password to continue.',
                })
            pw_resp.headers['Access-Control-Allow-Origin'] = '*'
            return pw_resp

        if device.registration_status == 'registered' and not network_mismatch and current_ip:
            if not is_blocked_pool_ip(current_ip):
                if _should_hijack_vlan(current_vlan):
                    manage_dns_hijack('unhijack', current_ip)
                if current_vlan:
                    manage_switch_acl('unblock', current_ip, current_vlan)
                clear_unregistered_lease(device.mac_address)

        payload = {
            'status': device.registration_status,
            'message': f'Device is {device.registration_status}',
            'current_ip': current_ip,
            'current_vlan': current_vlan,
            'current_ssid': current_ssid,
            'expected_vlan': device.assigned_vlan or device.current_vlan,
            'expected_ssid': get_ssid_for_vlan(device.assigned_vlan) or expected_ssid,
            'network_mismatch': network_mismatch,
        }
        if device.registration_status == 'blocked':
            if device.user and device.user.blocked:
                payload['reason'] = 'The administrator has blocked you from connecting any devices.'
            else:
                blk_req = RegistrationRequest.query.filter_by(
                    mac_address=mac_address, status='rejected'
                ).order_by(RegistrationRequest.submitted_at.desc()).first()
                if blk_req and blk_req.notes:
                    payload['reason'] = blk_req.notes
        resp = jsonify(payload)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp

    reg_request = RegistrationRequest.query.filter_by(
        mac_address=mac_address
    ).order_by(RegistrationRequest.submitted_at.desc()).first()
    if reg_request:
        payload = {
            'status': reg_request.status,
            'message': f'Registration request is {reg_request.status}',
        }
        if reg_request.status == 'rejected' and reg_request.notes:
            payload['reason'] = reg_request.notes
        if reg_request.status == 'pending_password':
            pwd_user = User.query.filter_by(email=reg_request.email).first()
            if pwd_user and not pwd_user.has_network_password:
                _hydrate_user_from_central(pwd_user.email, pwd_user)
            if pwd_user and pwd_user.has_network_password:
                payload['status'] = 'enter_password'
                payload['message'] = 'Your administrator has set a network password. Please enter it.'
        resp = jsonify(payload)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp

    resp = jsonify({'status': 'unregistered', 'message': 'Not registered'})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


@portal_bp.route('/api/block-status')
def api_block_status():
    mac_address = get_client_mac()
    if not mac_address:
        return jsonify({'blocked': True, 'message': 'Could not detect MAC address'})
    device = Device.query.filter_by(mac_address=mac_address).first()
    if device and device.registration_status == 'blocked':
        return jsonify({'blocked': True, 'message': 'Device is blocked'})
    return jsonify({'blocked': False, 'message': 'Device is not blocked'})


# ---------------------------------------------------------------------------
# Registration (spec 4b)
# ---------------------------------------------------------------------------

@portal_bp.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def register():
    if request.method == 'GET' and portal_host_mismatch():
        qs = request.query_string.decode('utf-8', errors='ignore')
        target = build_portal_url(url_for('portal.register'))
        if qs:
            target = f"{target}?{qs}"
        return redirect(target)

    if request.method == 'OPTIONS':
        resp = portal_bp.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        return resp, 200

    mac_address = get_client_mac()
    ip_address = get_client_ip()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if not mac_address and request.method == 'GET':
        return render_template(
            'error.html',
            code='Remote Access Not Supported',
            message=(
                'This registration page can only be used when your device is '
                'connected to the local network.'
            ),
        ), 200

    connection_type, detected_vlan, ssid = detect_connection_type(ip_address)
    wired_unregistered_vlan = get_wired_unregistered_vlan_id()
    is_wired_unregistered = (
        connection_type == 'wired' and detected_vlan == wired_unregistered_vlan
    )
    wired_vlan_options = [
        {'vlan_id': e.vlan_id, 'label': label_for_vlan(e.vlan_id, get_vlan_map())}
        for e in get_wired_assignable_entries()
    ]

    # ── GET: show form or status page ────────────────────────────────────────
    if request.method == 'GET' and mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        ownership = get_active_ownership(mac_address) if device else None

        if not ownership and central_client._central_enabled():
            central_data = central_client.lookup_device_at_central(mac_address)
            if central_data:
                device = central_client.import_device_from_central(mac_address, central_data)
                if device:
                    ownership = get_active_ownership(mac_address)

        if device and ownership:
            device = normalize_device_status(device)
            if device.internet_blocked:
                return render_template(
                    'blocked.html',
                    ip_address=ip_address,
                    mac_address=mac_address,
                    admin_email=os.getenv('ADMIN_EMAIL', 'admin@example.com'),
                )
            if ip_address:
                vlan_id = device.current_vlan or device.assigned_vlan
                manage_dns_hijack('unhijack', ip_address)
                if vlan_id:
                    manage_switch_acl('unblock', ip_address, vlan_id)
            _user_pf = device.user
            prefill_data = {
                'email':        _user_pf.email or '' if _user_pf else '',
                'first_name':   _user_pf.first_name or '' if _user_pf else '',
                'last_name':    _user_pf.last_name or '' if _user_pf else '',
                'phone_number': _user_pf.phone_number or '' if _user_pf else '',
                'device_type':  device.device_name or '',
            } if _user_pf else {}
            return render_template(
                'register.html',
                show_status=True,
                device=device,
                prefill=prefill_data,
                detected_mac=mac_address,
                detected_ip=ip_address,
                wired_vlan_required=False,
                wired_vlan_options=wired_vlan_options,
                user_home_url=build_portal_url(url_for('portal.user_home')),
                confirm_timeout_minutes=wifi_confirm_timeout_minutes(),
            )

    prefill = _build_prefill_from_request()

    # ── POST: process registration ────────────────────────────────────────────
    if request.method == 'POST':
        if not mac_address:
            if is_ajax:
                return jsonify({'status': 'error', 'message': 'Unable to determine your MAC address.'}), 400
            flash('Unable to determine your device MAC address.', 'error')
            return redirect(url_for('portal.register'))

        # Step 1 email check (two-step form)
        if (request.form.get('registration_step') or '').strip() == '1':
            email_check = (request.form.get('email') or '').strip().lower()
            if not email_check or '@' not in email_check:
                return jsonify({'status': 'error', 'message': 'A valid email address is required.'}), 400
            existing_user = User.query.filter_by(email=email_check).first()
            if existing_user:
                return jsonify({
                    'status': 'user_found',
                    'prefill': {
                        'first_name':   existing_user.first_name or '',
                        'last_name':    existing_user.last_name or '',
                        'phone_number': existing_user.phone_number or '',
                    },
                })
            _, central_user = _hydrate_user_from_central(email_check)
            if central_user:
                return jsonify({
                    'status': 'user_found',
                    'prefill': {
                        'first_name':   central_user.get('first_name') or '',
                        'last_name':    central_user.get('last_name') or '',
                        'phone_number': central_user.get('phone_number') or '',
                    },
                })
            return jsonify({'status': 'need_details'})

        # Full registration
        email        = (request.form.get('email')        or '').strip().lower()
        first_name   = (request.form.get('first_name')   or '').strip()
        last_name    = (request.form.get('last_name')    or '').strip()
        phone_number = (request.form.get('phone_number') or '').strip()
        device_type  = (request.form.get('device_type')  or '').strip()
        password_input = (request.form.get('network_password') or '').strip()

        wired_vlan_id = None
        if is_wired_unregistered:
            raw = (request.form.get('wired_vlan_id') or '').strip()
            try:
                wired_vlan_id = int(raw)
            except ValueError:
                pass
            if not wired_vlan_id:
                _dev_for_vlan = Device.query.filter_by(mac_address=mac_address).first()
                if _dev_for_vlan and _dev_for_vlan.wired_target_vlan:
                    wired_vlan_id = _dev_for_vlan.wired_target_vlan
            if not wired_vlan_id or wired_vlan_id not in get_wired_assignable_vlan_ids():
                msg = 'Please select a valid wired VLAN.'
                if is_ajax:
                    return jsonify({'status': 'error', 'message': msg}), 400
                flash(msg, 'error')
                return render_template(
                    'register.html', prefill=prefill,
                    detected_mac=mac_address, detected_ip=ip_address,
                    wired_vlan_required=True, wired_vlan_options=wired_vlan_options,
                )

        if not email or '@' not in email:
            msg = 'A valid email address is required.'
            if is_ajax:
                return jsonify({'status': 'error', 'message': msg}), 400
            flash(msg, 'error')
            return render_template(
                'register.html', prefill=prefill,
                detected_mac=mac_address, detected_ip=ip_address,
                wired_vlan_required=is_wired_unregistered,
                wired_vlan_options=wired_vlan_options,
            )

        selected_vlan = wired_vlan_id if is_wired_unregistered else detected_vlan
        _, central_user = _hydrate_user_from_central(email)

        # Profile snapshot for unregister rollback
        existing_user_before = User.query.filter_by(email=email).first()
        profile_snapshot = None
        if existing_user_before:
            profile_snapshot = json.dumps({
                'previous': {
                    'first_name':   existing_user_before.first_name or '',
                    'last_name':    existing_user_before.last_name or '',
                    'phone_number': existing_user_before.phone_number or '',
                },
                'new': {
                    'first_name':   first_name,
                    'last_name':    last_name,
                    'phone_number': phone_number,
                },
            })

        # Upsert User (spec Table 8)
        user = User.query.filter_by(email=email).first()
        if user:
            user.first_name   = first_name or user.first_name
            user.last_name    = last_name or user.last_name
            user.phone_number = phone_number or user.phone_number
            db.session.commit()
        else:
            network_password_hash = central_user.get('network_password_hash') if central_user else None
            user = User(
                email=email, first_name=first_name, last_name=last_name,
                phone_number=phone_number, begin_date=datetime.utcnow().date(),
                network_password_hash=network_password_hash,
                network_password_approval_mode='first_use' if network_password_hash else None,
                created_by='registration',
            )
            db.session.add(user)
            db.session.flush()

        # Upsert Device (spec Table 6)
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            device = Device(mac_address=mac_address, first_seen=datetime.utcnow())
            db.session.add(device)

        network_mismatch = bool(
            connection_type == 'wifi' and detected_vlan
            and device.current_vlan and detected_vlan != device.current_vlan
        )

        device.device_name      = device_type or device.device_name
        device.connection_type  = connection_type
        device.ssid             = ssid
        device.is_wired         = connection_type == 'wired'
        device.current_vlan     = detected_vlan
        device.profile_snapshot = profile_snapshot
        if not device.unregister_token:
            device.unregister_token = secrets.token_urlsafe(32)
        if is_wired_unregistered:
            device.wired_target_vlan = wired_vlan_id
        db.session.commit()

        # Ensure DeviceOwnership (spec Table 9)
        active_ownership = get_active_ownership(mac_address)
        if active_ownership and active_ownership.user_id != user.id:
            close_ownership(mac_address, commit=True)
            active_ownership = None
        if not active_ownership:
            open_ownership(mac_address, user.id, commit=True)

        # Blocked-user check
        if user.blocked:
            device.assigned_vlan = selected_vlan or detected_vlan
            set_internet_blocked(device, True, commit=True)
            _msg = 'The administrator has blocked you from connecting any devices to the internet.'
            if is_ajax:
                return jsonify({'status': 'blocked', 'message': _msg}), 403
            return redirect(url_for('portal.request_rejected', reason=_msg))

        # Password-required VLAN handling (spec 4b.ii.1)
        if selected_vlan and vlan_requires_password(selected_vlan) and not device.ownership_validated:
            if not user.has_network_password:
                if not user.network_password_set_token:
                    user.network_password_set_token = secrets.token_urlsafe(32)
                    user.network_password_set_token_expires = (
                        datetime.utcnow() + timedelta(hours=24)
                    )
                    db.session.commit()
                set_password_url = build_set_password_url(user.network_password_set_token)
                from email_service import send_network_password_set_email
                send_network_password_set_email(
                    email, first_name or 'there', set_password_url,
                    network_name=ssid or 'Wired Network',
                )
                if is_ajax:
                    return jsonify({
                        'status': 'pending_password',
                        'message': 'A network password is required. Please check your email.',
                    })
                return redirect(url_for('portal.pending_approval'))

            if not password_input:
                if is_ajax:
                    return jsonify({'status': 'need_password', 'message': 'Please enter your network password.'})
                return render_template(
                    'register.html', show_password_form=True, prefill=prefill,
                    detected_mac=mac_address, detected_ip=ip_address,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

            if not user.check_network_password(password_input):
                msg = 'Incorrect network password.'
                if is_ajax:
                    return jsonify({'status': 'error', 'message': msg}), 400
                flash(msg, 'error')
                return render_template(
                    'register.html', show_password_form=True, prefill=prefill,
                    detected_mac=mac_address, detected_ip=ip_address,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

            device.ownership_validated = True
            db.session.commit()

        # Approval check (spec steps 4/5)
        domain_policy_map = load_domain_policy_map()
        effective_allowed, _ = get_effective_vlans_for_user(user, domain_policy_map)
        needs_approval = bool(selected_vlan and selected_vlan not in effective_allowed)

        if needs_approval:
            RegistrationRequest.query.filter(
                RegistrationRequest.mac_address == mac_address,
                RegistrationRequest.status == 'pending',
            ).update(
                {'status': 'superseded', 'processed_at': datetime.utcnow(),
                 'processed_by': 'superseded-by-new-submission'},
                synchronize_session=False,
            )
            reg_request = RegistrationRequest(
                mac_address=mac_address, ip_address=ip_address,
                email=email, first_name=first_name, last_name=last_name,
                phone_number=phone_number, device_type=device_type,
                requested_vlan=selected_vlan, status='pending',
                approval_token=secrets.token_urlsafe(32),
            )
            db.session.add(reg_request)
            db.session.commit()

            portal_url = os.getenv('PORTAL_URL')
            if portal_url:
                parsed = urlparse(portal_url)
                approval_url = (
                    f"{parsed.scheme}://{parsed.netloc}"
                    f"{url_for('admin.approvals.approve_request', token=reg_request.approval_token)}"
                )
            else:
                approval_url = url_for(
                    'admin.approvals.approve_request',
                    token=reg_request.approval_token, _external=True,
                )
            send_admin_notification(
                reg_request, approval_url, selected_vlan, ssid or 'Wired Network'
            )

            if is_ajax:
                return jsonify({
                    'status': 'pending',
                    'message': 'Registration request submitted. Waiting for admin approval.',
                    'prefill': {
                        'email': email, 'first_name': first_name,
                        'last_name': last_name, 'phone_number': phone_number,
                        'device_type': device_type,
                    },
                })
            return redirect(url_for('portal.pending_approval'))

        # Auto-approve (spec step 5)
        device.assigned_vlan = selected_vlan
        device.current_vlan  = selected_vlan if not is_wired_unregistered else detected_vlan
        db.session.commit()

        kea = _get_kea()
        if connection_type == 'wifi':
            if kea:
                kea.register_mac(
                    mac=mac_address, vlan=selected_vlan,
                    hostname=f"{(first_name or 'device').lower()}-{(last_name or '').lower()}",
                    ip_address=None,
                )
                if ip_address and not network_mismatch:
                    kea.force_lease_renewal(mac_address, ip_address)
        else:
            if kea:
                kea.register_mac(
                    mac=mac_address, vlan=selected_vlan,
                    hostname=f"{(first_name or 'device').lower()}-{(last_name or '').lower()}",
                    ip_address=None,
                )
            send_coa_change(mac_address, selected_vlan)
            _replug_switch_port_for_mac(mac_address)

        if ip_address and not network_mismatch and not is_blocked_pool_ip(ip_address):
            if _should_hijack_vlan(selected_vlan or detected_vlan):
                manage_dns_hijack('unhijack', ip_address)
            if detected_vlan:
                manage_switch_acl('unblock', ip_address, detected_vlan)
            lease = get_active_iplease(mac_address)
            if lease:
                lease.dns_hijacked = False
                db.session.commit()
            set_internet_accessible(device, True, commit=True)
        else:
            set_internet_accessible(device, None, commit=True)

        clear_unregistered_lease(mac_address)

        RegistrationRequest.query.filter(
            RegistrationRequest.mac_address == mac_address,
            RegistrationRequest.status.in_(['pending', 'pending_password']),
        ).update(
            {'status': 'approved', 'processed_at': datetime.utcnow(),
             'processed_by': 'auto-approved'},
            synchronize_session=False,
        )
        db.session.commit()

        unregister_url = build_unregister_url(device.unregister_token)
        if not device.ownership_validated:
            confirm_url, reject_url, confirm_timeout_sec = set_wifi_confirmation(device)
        else:
            confirm_url = reject_url = confirm_timeout_sec = None

        ssid_display = ssid or 'Wired Network'
        send_wifi_registration_confirmation(
            user.email, user.first_name or first_name or 'there',
            ssid_display, mac_address, unregister_url,
            confirm_url=confirm_url, reject_url=reject_url,
            confirm_timeout_sec=confirm_timeout_sec,
            registration_details={
                'email':        user.email,
                'first_name':   user.first_name or first_name,
                'last_name':    user.last_name or last_name,
                'phone_number': user.phone_number or phone_number,
                'device_type':  device_type,
                'ip_address':   ip_address,
                'ssid':         ssid_display,
            },
        )

        central_client.queue_device_registered(device, user)

        if is_ajax:
            _needs_confirm = not bool(device.ownership_validated)
            _resp = {
                'status': 'registered',
                'message': 'Device registered successfully.',
                'current_vlan':   detected_vlan,
                'current_ssid':   ssid,
                'expected_vlan':  selected_vlan,
                'expected_ssid':  get_ssid_for_vlan(selected_vlan),
                'network_mismatch': network_mismatch,
                'needs_ownership_confirmation': _needs_confirm,
            }
            if _needs_confirm:
                _resp['confirm_timeout_minutes'] = wifi_confirm_timeout_minutes()
            return jsonify(_resp)
        return redirect(url_for('portal.registered_success'))

    # GET — show registration form
    return render_template(
        'register.html',
        prefill=prefill,
        detected_mac=mac_address,
        detected_ip=ip_address,
        wired_vlan_required=is_wired_unregistered,
        wired_vlan_options=wired_vlan_options,
    )






@portal_bp.route('/status')
def status():
    mac_address = get_client_mac()
    if not mac_address:
        return render_template('status.html', device=None)
    device = Device.query.filter_by(mac_address=mac_address).first()
    device = normalize_device_status(device)
    access_label = None
    if device:
        vlan_map = get_vlan_map()
        access_label = label_for_vlan(device.current_vlan, vlan_map) or 'Guest'
    return render_template('status.html', device=device, access_label=access_label)


@portal_bp.route('/pending-approval')
def pending_approval():
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    prefill = _build_prefill_from_request()
    if mac_address:
        reg_request = RegistrationRequest.query.filter_by(
            mac_address=mac_address, status='pending'
        ).order_by(RegistrationRequest.submitted_at.desc()).first()
        if reg_request:
            prefill = {
                'email':        reg_request.email or '',
                'first_name':   reg_request.first_name or '',
                'last_name':    reg_request.last_name or '',
                'phone_number': reg_request.phone_number or '',
                'device_type':  reg_request.device_type or '',
            }
    wants_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or request.args.get('ajax') == '1'
    )
    if wants_ajax:
        html = render_template(
            'partials/pending_approval_content.html',
            prefill=prefill, mac_address=mac_address, ip_address=ip_address,
        )
        return jsonify({
            'header': 'Request Submitted',
            'subheader': 'Please wait for an administrator to approve your request.',
            'html': html,
        })
    return render_template(
        'pending_approval.html',
        prefill=prefill, mac_address=mac_address, ip_address=ip_address,
    )


@portal_bp.route('/request-rejected')
def request_rejected():
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    reason = request.args.get('reason', '').strip()
    prefill = _build_prefill_from_request()
    return render_template(
        'request_rejected.html',
        reason=reason, prefill=prefill,
        mac_address=mac_address, ip_address=ip_address,
    )


@portal_bp.route('/wrong-vlan')
def wrong_vlan_page():
    mac_address = get_client_mac()
    device = Device.query.filter_by(mac_address=mac_address).first() if mac_address else None

    assigned_vlan = (
        (device.assigned_vlan if device else None)
        or request.args.get('assigned_vlan')
        or None
    )

    assigned_ssid = request.args.get('assigned_ssid')
    if not assigned_ssid and assigned_vlan:
        try:
            assigned_ssid = get_ssid_for_vlan(int(assigned_vlan))
        except (TypeError, ValueError):
            assigned_ssid = None

    _, detected_vlan, _ = detect_connection_type(get_client_ip())
    detected_ssid = get_ssid_for_vlan(detected_vlan) if detected_vlan else None

    return render_template(
        'wrong_vlan.html',
        mac_address=mac_address,
        assigned_vlan=assigned_vlan,
        assigned_ssid=assigned_ssid,
        detected_vlan=detected_vlan,
        detected_ssid=detected_ssid,
    )


@portal_bp.route('/registered')
def registered_success():
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    device = None
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        device = normalize_device_status(device)
    if device and device.registration_status == 'registered':
        return render_template(
            'registered.html',
            device=device, ip_address=ip_address, mac_address=mac_address,
        )
    reg_request = None
    if mac_address:
        reg_request = (
            RegistrationRequest.query.filter_by(mac_address=mac_address)
            .order_by(RegistrationRequest.submitted_at.desc()).first()
        )
    if reg_request:
        if reg_request.status == 'pending':
            return redirect(url_for(
                'portal.pending_approval',
                email=reg_request.email,
                first_name=reg_request.first_name,
                last_name=reg_request.last_name,
                phone_number=reg_request.phone_number or '',
                device_type=reg_request.device_type or '',
            ))
        if reg_request.status == 'rejected':
            return redirect(url_for('portal.request_rejected', reason=reg_request.notes or ''))
    return redirect(url_for('portal.register'))


# ---------------------------------------------------------------------------
# Unregister / confirm / reject device (spec 8)
# ---------------------------------------------------------------------------

@portal_bp.route('/unregister/<token>', methods=['GET', 'POST'])
def unregister(token):
    if not token:
        flash('Invalid unregister link', 'error')
        return redirect(url_for('portal.index'))

    device = Device.query.filter_by(unregister_token=token).first()
    if not device:
        return render_template('unregister_confirmation.html', success=False)

    if request.method == 'GET':
        return render_template('unregister_confirmation.html', confirm=True, token=token)

    if request.form.get('js') != '1':
        return render_template('unregister_confirmation.html', confirm=True, token=token)

    mac_address     = device.mac_address
    connection_type = device.connection_type
    vlan_id         = device.current_vlan
    user            = device.user

    # === Get current active IP (best effort) ===
    lease = get_active_iplease(mac_address)
    current_ip = lease.ip_address if lease else device.ip_address

    if not current_ip:
        kea = _get_kea()
        if kea:
            try:
                current_ip = kea.get_lease_ip_for_mac(mac_address)
            except Exception:
                pass

    will_block  = bool(current_ip and not is_blocked_pool_ip(current_ip))
    will_hijack = bool(current_ip and _should_hijack_vlan(vlan_id))

    # Apply ACL block + DNS hijack
    if will_block:
        if vlan_id:
            manage_switch_acl('block', current_ip, vlan_id)
        if will_hijack:
            manage_dns_hijack('hijack', current_ip)

        if lease:
            lease.dns_hijacked = True
            db.session.add(lease)

    # === Kea cleanup ===
    kea = _get_kea()

    if kea:
        try:
            # 1. Unregister the MAC (affects lease assignment)
            if vlan_id:
                kea.unregister_mac(mac=mac_address, vlan=vlan_id)
            
        except Exception as exc:
            logger.warning("Kea cleanup failed during unregistration of %s: %s",
                           mac_address, exc)

    if connection_type == 'wired':
        import os
        # Read directly from docker-compose.yml (WIRED_VLAN=250)
        unregistered_vlan = int(os.getenv('WIRED_VLAN', 250))
        send_coa_change(mac_address, unregistered_vlan)

    # === Portal-side cleanup ===
    close_ownership(mac_address, commit=False)

    device.device_name               = None
    device.assigned_vlan             = None
    device.internet_accessible       = None
    device.internet_blocked          = None
    device.ownership_validated       = None
    device.unregister_token          = None
    device.profile_snapshot          = None
    device.confirmation_confirmed_at = None
    device.confirmation_deadline     = None
    device.stale                     = True

    sync_registration_status(device)
    central_client.queue_device_unregistered(mac_address)
    db.session.commit()

    logger.info(
        "Unregister: mac=%s ip=%s vlan=%s → block=%s hijack=%s (reservation deleted)",
        mac_address, current_ip, vlan_id, will_block, will_hijack
    )

    return render_template('unregister_confirmation.html', success=True)


@portal_bp.route('/confirm/<token>')
def confirm_device(token):
    if not token:
        flash('Invalid confirmation link', 'error')
        return redirect(url_for('portal.index'))
    device = Device.query.filter_by(confirmation_token=token).first()
    if not device:
        flash('Invalid or expired confirmation link', 'error')
        return redirect(url_for('portal.index'))
    if device.registration_status == 'unregistered':
        flash('This device is unregistered.', 'error')
        return render_template('status.html', device=device, unregistered=True)
    device.confirmation_confirmed_at = datetime.utcnow()
    device.confirmation_deadline     = None
    device.ownership_validated       = True
    db.session.commit()
    if device.registration_status == 'blocked':
        apply_device_unblock(device, flash_messages=False)
    flash('Device confirmed. Access restored.', 'success')
    return render_template('status.html', device=device)


@portal_bp.route('/reject/<token>')
def reject_device(token):
    if not token:
        flash('Invalid rejection link', 'error')
        return redirect(url_for('portal.index'))
    device = Device.query.filter_by(confirmation_token=token).first()
    if not device:
        flash('Invalid or expired link', 'error')
        return redirect(url_for('portal.index'))
    if device.registration_status == 'unregistered':
        flash('This device is already unregistered.', 'info')
        return render_template('status.html', device=device, unregistered=True)
    unregister_device(device)
    logger.info("Device %s unregistered via reject link", device.mac_address)
    flash('Device access has been revoked.', 'success')
    return render_template('status.html', device=device)


# ---------------------------------------------------------------------------
# User login and home page (spec 4a, 5)
# ---------------------------------------------------------------------------

@portal_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def user_login():
    if not client_is_on_site():
        session.pop('portal_user_id', None)
        if request.method == 'POST':
            flash('Sign-in is only available on the Blackfriars network.', 'error')
        return render_template('user_login.html', off_site=True)

    if request.method == 'POST':
        email    = (request.form.get('email')    or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        user = User.query.filter_by(email=email).first()
        if user and user.check_network_password(password):
            session['portal_user_id'] = user.id
            return redirect(url_for('portal.user_home'))
        flash('Invalid email or password.', 'error')
        return render_template('user_login.html', prefill_email=email)

    mac_address = get_client_mac()
    if mac_address:
        _dev = Device.query.filter_by(mac_address=mac_address).first()
        if _dev:
            _own = get_active_ownership(mac_address)
            if _own and _own.user_id and _dev.ownership_validated:
                _u = User.query.get(_own.user_id)
                if _u:
                    session['portal_user_id'] = _u.id
                    return redirect(url_for('portal.user_home'))
    return render_template('user_login.html')

@portal_bp.route('/logout')
def logout():
    session.pop('portal_user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('portal.index'))

@portal_bp.route('/user_home', methods=['GET', 'POST'])
def user_home():
    if not client_is_on_site():
        session.pop('portal_user_id', None)
        flash('Device management is only available on the Blackfriars network.', 'error')
        return redirect(url_for('portal.user_login'))
    portal_user_id = session.get('portal_user_id')
    user = None
    calling_device = None

    if portal_user_id:
        user = User.query.get(portal_user_id)

    if not user:
        mac_address = get_client_mac()
        if mac_address:
            calling_device = Device.query.filter_by(mac_address=mac_address).first()
            if calling_device:
                ownership = get_active_ownership(mac_address)
                if ownership and ownership.user_id:
                    user = User.query.get(ownership.user_id)

    if not user:
        return redirect(url_for('portal.user_login'))

    vlan_map = get_vlan_map()
    domain_policy_map = load_domain_policy_map()

    owned_ownerships = DeviceOwnership.query.filter_by(
        user_id=user.id, end_datetime=None
    ).all()
    owned_macs = [o.mac_address for o in owned_ownerships]
    owned_devices = (
        Device.query.filter(Device.mac_address.in_(owned_macs)).all()
        if owned_macs else []
    )

    owned_device_rows = []
    for dev in owned_devices:
        lease = get_active_iplease(dev.mac_address)
        owned_device_rows.append({
            'device':       dev,
            'ip_address':   lease.ip_address if lease else dev.ip_address,
            'lease_expiry': lease.lease_expiry if lease else None,
            'vlan_label':   label_for_vlan(dev.assigned_vlan or dev.current_vlan, vlan_map),
        })

    effective_allowed, effective_adoptable = get_effective_vlans_for_user(user, domain_policy_map)
    wired_unregistered_vlan = get_wired_unregistered_vlan_id()
    all_interaction_vlan_ids = (effective_allowed | effective_adoptable) - {wired_unregistered_vlan}
    adoptable_leases = (
        load_adoptable_leases(all_interaction_vlan_ids)
        if all_interaction_vlan_ids else []
    )

    unregistered_rows = []
    for entry in adoptable_leases:
        mac = entry.get('mac_address')
        if not mac:
            continue
        if get_active_ownership(mac):
            continue
        vlan_id = entry.get('vlan_id')
        unregistered_rows.append({
            'mac_address':    mac,
            'show_mac':       vlan_id in effective_adoptable,
            'ip_address':     entry.get('ip_address'),
            'vlan_id':        vlan_id,
            'vlan_label':     label_for_vlan(vlan_id, vlan_map),
            'first_seen':     entry.get('first_seen'),
            'needs_approval': vlan_id not in effective_adoptable,
        })

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'update_profile':
            user.first_name   = (request.form.get('first_name')   or '').strip() or user.first_name
            user.last_name    = (request.form.get('last_name')    or '').strip() or user.last_name
            user.phone_number = (request.form.get('phone_number') or '').strip() or user.phone_number
            db.session.commit()
            central_client.queue_user_updated(user)
            flash('Profile updated.', 'success')

        elif action == 'change_password':
            current_pw = (request.form.get('current_password') or '').strip()
            new_pw     = (request.form.get('new_password')     or '').strip()
            if not user.check_network_password(current_pw):
                flash('Current password is incorrect.', 'error')
            elif len(new_pw) < 8:
                flash('New password must be at least 8 characters.', 'error')
            else:
                user.set_network_password(new_pw)
                db.session.commit()
                central_client.queue_user_updated(user)
                flash('Password changed.', 'success')

        elif action == 'abandon':
            mac_to_abandon = (request.form.get('mac_address') or '').strip().lower()
            if mac_to_abandon in owned_macs:
                dev_to_abandon = Device.query.filter_by(mac_address=mac_to_abandon).first()
                if dev_to_abandon:
                    lease = get_active_iplease(mac_to_abandon)
                    if lease and not lease.from_blocked_pool:
                        if _should_hijack_vlan(dev_to_abandon.current_vlan):
                            manage_dns_hijack('hijack', lease.ip_address)
                            lease.dns_hijacked = True
                        if dev_to_abandon.current_vlan:
                            manage_switch_acl('block', lease.ip_address, dev_to_abandon.current_vlan)
                    abandon_vlan = dev_to_abandon.current_vlan
                    dev_to_abandon.assigned_vlan      = None
                    dev_to_abandon.current_vlan       = None
                    dev_to_abandon.ownership_validated = None
                    dev_to_abandon.device_name        = None
                    dev_to_abandon.first_seen         = datetime.utcnow()
                    dev_to_abandon.stale              = True
                    dev_to_abandon.unregister_token   = None
                    set_internet_accessible(dev_to_abandon, None, commit=False)
                    set_internet_blocked(dev_to_abandon, None, commit=False)
                    central_client.queue_device_unregistered(mac_to_abandon)
                    db.session.commit()
                close_ownership(mac_to_abandon, commit=True)
                kea = _get_kea()
                if kea and dev_to_abandon:
                    if abandon_vlan:
                        kea.unregister_mac(mac_to_abandon, abandon_vlan)
                    else:
                        from core.vlan_utils import parse_valid_vlan_ids
                        for vid in parse_valid_vlan_ids():
                            kea.unregister_mac(mac_to_abandon, vid)
                flash(f'Device {mac_to_abandon} abandoned.', 'success')

        elif action == 'adopt_request':
            mac_to_adopt = (request.form.get('mac_address') or '').strip().lower()
            vlan_raw     = (request.form.get('vlan_id')     or '').strip()
            try:
                adopt_vlan_id = int(vlan_raw)
            except ValueError:
                flash('Invalid VLAN for adoption request.', 'error')
                return redirect(url_for('portal.user_home'))
            _eff_allowed, _eff_adoptable = get_effective_vlans_for_user(user)
            if adopt_vlan_id not in _eff_allowed:
                flash('You do not have permission to request adoption for that network.', 'error')
                return redirect(url_for('portal.user_home'))
            if adopt_vlan_id in _eff_adoptable:
                flash('You can adopt this device directly without approval.', 'info')
                return redirect(url_for('portal.adopt_devices'))
            _adopt_lease = UnregisteredLease.query.filter_by(mac_address=mac_to_adopt).first()
            _adopt_ip = _adopt_lease.ip_address if _adopt_lease else None
            pending = RegistrationRequest(
                mac_address=mac_to_adopt, ip_address=_adopt_ip,
                email=user.email, first_name=user.first_name or '',
                last_name=user.last_name or '', phone_number=user.phone_number or '',
                device_type='adopted-device', status='pending',
                approval_token=secrets.token_urlsafe(32),
            )
            db.session.add(pending)
            db.session.commit()
            _portal_url = os.getenv('PORTAL_URL')
            if _portal_url:
                parsed = urlparse(_portal_url)
                _approval_url = (
                    f"{parsed.scheme}://{parsed.netloc}"
                    f"{url_for('admin.approvals.approve_request', token=pending.approval_token)}"
                )
            else:
                _approval_url = url_for(
                    'admin.approvals.approve_request',
                    token=pending.approval_token, _external=True,
                )
            send_admin_notification(
                pending, _approval_url, adopt_vlan_id, get_ssid_for_vlan(adopt_vlan_id)
            )
            flash('Your adoption request has been sent to the administrator for approval.', 'info')

        return redirect(url_for('portal.user_home'))

    return render_template(
        'user_home.html',
        user=user,
        owned_devices=owned_device_rows,
        unregistered_devices=unregistered_rows,
        calling_device=calling_device,
    )


# ---------------------------------------------------------------------------
# Network password management
# ---------------------------------------------------------------------------

@portal_bp.route('/set-network-password/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def set_network_password(token):
    user = User.query.filter_by(network_password_set_token=token).first()
    if not user:
        return render_template('set_network_password.html', error='invalid')
    if (
        not user.network_password_set_token_expires
        or datetime.utcnow() > user.network_password_set_token_expires
    ):
        return render_template('set_network_password.html', error='expired')
    if request.method == 'POST':
        password = (request.form.get('password') or '').strip()
        confirm  = (request.form.get('confirm_password') or '').strip()
        if not password or len(password) < 8:
            return render_template(
                'set_network_password.html', token=token, user=user,
                form_error='Password must be at least 8 characters.',
            )
        if password != confirm:
            return render_template(
                'set_network_password.html', token=token, user=user,
                form_error='Passwords do not match.',
            )
        user.set_network_password(password)
        user.network_password_set_token         = None
        user.network_password_set_token_expires = None
        user.network_password_approval_mode     = None
        db.session.commit()
        central_client.queue_user_updated(user)
        return render_template('set_network_password.html', success=True, user=user)
    return render_template('set_network_password.html', token=token, user=user)


@portal_bp.route('/forgot-network-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_network_password():
    email    = (request.form.get('email') or '').strip().lower()
    is_ajax  = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    success_response = {
        'status':  'ok',
        'message': 'If that email address has a network account, a reset link has been sent.',
    }
    if not email:
        if is_ajax:
            return jsonify({'status': 'error', 'message': 'Please enter your email address.'})
        flash('Please enter your email address.', 'error')
        return redirect(url_for('portal.register'))

    user = User.query.filter_by(email=email).first()
    if user:
        user.network_password_set_token = secrets.token_urlsafe(32)
        user.network_password_set_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        set_password_url = build_set_password_url(user.network_password_set_token)
        try:
            if user.has_network_password:
                send_network_password_reset_email(
                    user.email, user.first_name or 'there', set_password_url
                )
            else:
                send_network_password_set_email(
                    user.email, user.first_name or 'there', set_password_url,
                    network_name='Portal',
                )
        except Exception as exc:
            logger.warning('forgot-network-password email failed for %s: %s', email, exc)

        mac_address = get_client_mac()
        ip_address  = get_client_ip()
        if mac_address and ip_address:
            existing_req = RegistrationRequest.query.filter_by(
                mac_address=mac_address, status='pending_password'
            ).first()
            if not existing_req:
                _, detected_vlan, _ = detect_connection_type(ip_address)
                pwd_req = RegistrationRequest(
                    mac_address=mac_address, ip_address=ip_address,
                    email=user.email, first_name=user.first_name or '',
                    last_name=user.last_name or '', phone_number=user.phone_number or '',
                    device_type='unknown', requested_vlan=detected_vlan,
                    status='pending_password', approval_token=secrets.token_urlsafe(32),
                )
                db.session.add(pwd_req)
                db.session.commit()

    if is_ajax:
        return jsonify(success_response)
    flash(success_response['message'], 'info')
    return redirect(url_for('portal.register'))


# ---------------------------------------------------------------------------
# Device adoption (spec 5b)
# ---------------------------------------------------------------------------

@portal_bp.route('/adopt')
def adopt_devices():
    if not client_is_on_site():
        session.pop('portal_user_id', None)
        flash('Device management is only available on the Blackfriars network.', 'error')
        return redirect(url_for('portal.user_login'))
    user, device = current_user_from_device()
    if not user:
        return render_template(
            'adopt_devices.html', user=None, devices=[], registered_devices=[],
            target_vlan_options=[], wired_unregistered_vlan=get_wired_unregistered_vlan_id(),
            error='registered_device',
        )
    if user.require_approval_every_device:
        return render_template(
            'adopt_devices.html', user=user, devices=[], registered_devices=[],
            target_vlan_options=[], wired_unregistered_vlan=get_wired_unregistered_vlan_id(),
            error='approval_required',
        )

    vlan_map = get_vlan_map()
    wired_unregistered_vlan = get_wired_unregistered_vlan_id()
    _, effective_adoptable = get_effective_vlans_for_user(user)
    allowed_vlans = sorted(effective_adoptable)
    target_vlan_ids = [v for v in allowed_vlans if v != wired_unregistered_vlan]
    target_vlan_options = [
        {'vlan_id': v, 'label': label_for_vlan(v, vlan_map)}
        for v in sorted(target_vlan_ids)
    ]
    if not allowed_vlans:
        return render_template(
            'adopt_devices.html', user=user, devices=[], registered_devices=[],
            target_vlan_options=[], wired_unregistered_vlan=wired_unregistered_vlan,
            error='no_permissions',
        )

    candidates = load_adoptable_leases(set(allowed_vlans))

    owned_macs = [
        o.mac_address for o in
        DeviceOwnership.query.filter_by(user_id=user.id, end_datetime=None).all()
    ]
    registered_devices = (
        Device.query.filter(
            Device.mac_address.in_(owned_macs),
            Device.registration_status == 'registered',
        ).order_by(Device.device_name.asc(), Device.mac_address.asc()).all()
        if owned_macs else []
    )

    registered_device_rows = [{
        'device_name':    d.device_name,
        'mac_address':    d.mac_address,
        'ip_address':     d.ip_address,
        'vlan_id':        d.current_vlan,
        'vlan_label':     label_for_vlan(d.current_vlan, vlan_map),
        'connection_type': d.connection_type,
        'device_id':      d.id,
    } for d in registered_devices]

    if not candidates:
        current_ssid = (
            device.ssid or get_ssid_for_vlan(device.current_vlan) or 'current network'
        )
        adoptable_ssids = [get_ssid_for_vlan(v) or f"VLAN {v}" for v in allowed_vlans]
        return render_template(
            'adopt_devices.html', user=user, devices=[],
            registered_devices=registered_device_rows,
            target_vlan_options=target_vlan_options,
            wired_unregistered_vlan=wired_unregistered_vlan,
            error='no_devices', current_ssid=current_ssid,
            adoptable_ssids=', '.join(adoptable_ssids) if adoptable_ssids else 'your adoptable networks',
        )

    def _format_age_delta(delta):
        if not delta:
            return ''
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            total_seconds = 0
        days  = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        return f"{days}d {hours}h" if days else f"{hours}h"

    adoptable_devices = []
    for entry in candidates:
        existing = Device.query.filter_by(
            mac_address=entry['mac_address'], registration_status='registered'
        ).first()
        if existing:
            continue
        first_seen = entry['first_seen']
        age = _format_age_delta(datetime.utcnow() - first_seen) if first_seen else ''
        if entry.get('ip_address') and entry.get('vlan_id'):
            manage_switch_acl('block', entry['ip_address'], entry['vlan_id'])
        adoptable_devices.append({
            'mac_address':          entry['mac_address'],
            'ip_address':           entry['ip_address'],
            'vlan_id':              entry['vlan_id'],
            'vlan_label':           label_for_vlan(entry['vlan_id'], vlan_map),
            'first_seen':           first_seen,
            'last_seen':            entry['last_seen'],
            'age':                  age,
            'requires_target_vlan': entry['vlan_id'] == wired_unregistered_vlan,
            'target_vlan_options':  target_vlan_options,
        })

    return render_template(
        'adopt_devices.html', user=user, devices=adoptable_devices,
        registered_devices=registered_device_rows,
        target_vlan_options=target_vlan_options,
        wired_unregistered_vlan=wired_unregistered_vlan,
        error=None,
    )


@portal_bp.route('/adopt', methods=['POST'])
def adopt_device():
    if not client_is_on_site():
        session.pop('portal_user_id', None)
        flash('Device management is only available on the Blackfriars network.', 'error')
        return redirect(url_for('portal.user_login'))
    user, device = current_user_from_device()
    if not user:
        flash('Please connect from a registered device to adopt devices.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    mac_address      = (request.form.get('mac_address')      or '').strip().lower()
    vlan_id_raw      = (request.form.get('vlan_id')          or '').strip()
    target_vlan_raw  = (request.form.get('target_vlan')      or '').strip()
    device_type_raw  = (request.form.get('device_type')      or '').strip()
    device_type_other = (request.form.get('device_type_other') or '').strip()
    fixed_ip_requested = (
        (request.form.get('fixed_ip') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
    )

    try:
        vlan_id = int(vlan_id_raw)
    except ValueError:
        vlan_id = None
    try:
        target_vlan = int(target_vlan_raw) if target_vlan_raw else None
    except ValueError:
        target_vlan = None

    device_label = ''
    if device_type_raw:
        if device_type_raw.lower() == 'other':
            if not device_type_other:
                flash('Please describe the device type when selecting Other.', 'error')
                return redirect(url_for('portal.adopt_devices'))
            device_label = device_type_other
        else:
            device_label = device_type_raw
    device_label = re.sub(r'\s+', ' ', device_label).strip()[:100]

    if not mac_address or not vlan_id:
        flash('Missing device details for adoption.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    _, effective_adoptable = get_effective_vlans_for_user(user)
    wired_unregistered_vlan = get_wired_unregistered_vlan_id()
    if vlan_id not in effective_adoptable:
        flash('You do not have permission to adopt devices on that VLAN.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    if vlan_id == wired_unregistered_vlan:
        if not target_vlan:
            flash('Please select a VLAN for the wired device.', 'error')
            return redirect(url_for('portal.adopt_devices'))
        if target_vlan not in effective_adoptable:
            flash('You do not have permission to assign that VLAN.', 'error')
            return redirect(url_for('portal.adopt_devices'))
    else:
        target_vlan = vlan_id

    if user.require_approval_every_device:
        pending_request = RegistrationRequest(
            mac_address=mac_address, ip_address=None,
            email=user.email, first_name=user.first_name or '',
            last_name=user.last_name or '', phone_number=user.phone_number or '',
            device_type=device_label or 'adopted-device',
            status='pending', approval_token=secrets.token_urlsafe(32),
        )
        db.session.add(pending_request)
        db.session.commit()
        _portal_url = os.getenv('PORTAL_URL')
        if _portal_url:
            parsed = urlparse(_portal_url)
            _approval_url = (
                f"{parsed.scheme}://{parsed.netloc}"
                f"{url_for('admin.approvals.approve_request', token=pending_request.approval_token)}"
            )
        else:
            _approval_url = url_for(
                'admin.approvals.approve_request',
                token=pending_request.approval_token, _external=True,
            )
        send_admin_notification(
            pending_request, _approval_url, vlan_id, get_ssid_for_vlan(vlan_id)
        )
        flash('Adoption request submitted for approval.', 'info')
        return redirect(url_for('portal.adopt_devices'))

    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    ip_address = lease.ip_address if lease else None
    existing = Device.query.filter_by(mac_address=mac_address).first()
    if not ip_address and existing and existing.ip_address:
        ip_address = existing.ip_address

    reserved_ip = ip_address
    if fixed_ip_requested and not ip_address:
        kea = _get_kea()
        if kea:
            try:
                reserved_ip = (
                    kea.get_lease_ip_for_mac(mac_address, subnet_id=vlan_id)
                    or kea.get_lease_ip_for_mac(mac_address)
                )
            except Exception as exc:
                logger.warning("Failed to lookup lease IP for %s: %s", mac_address, exc)

    if existing and existing.registration_status == 'registered' and existing.user_id != user.id:
        flash('That device is already adopted by another user.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    if fixed_ip_requested and reserved_ip:
        ip_address = reserved_ip

    if existing:
        existing.current_vlan      = target_vlan
        existing.connection_type   = 'wired' if vlan_id == wired_unregistered_vlan else 'wifi'
        existing.ssid              = get_ssid_for_vlan(target_vlan)
        existing.is_wired          = vlan_id == wired_unregistered_vlan
        existing.wired_target_vlan = target_vlan if vlan_id == wired_unregistered_vlan else None
        existing.assigned_vlan     = target_vlan
        existing.ownership_validated = True
        if device_label:
            existing.device_name = device_label
        existing.unregister_token = existing.unregister_token or secrets.token_urlsafe(32)
        db.session.flush()
        adopted_device = existing
    else:
        adopted_device = Device(
            mac_address=mac_address,
            device_name=device_label or 'adopted-device',
            current_vlan=target_vlan,
            connection_type='wired' if vlan_id == wired_unregistered_vlan else 'wifi',
            ssid=get_ssid_for_vlan(target_vlan),
            is_wired=vlan_id == wired_unregistered_vlan,
            wired_target_vlan=target_vlan if vlan_id == wired_unregistered_vlan else None,
            assigned_vlan=target_vlan,
            ownership_validated=True,
            unregister_token=secrets.token_urlsafe(32),
        )
        db.session.add(adopted_device)
        db.session.flush()

    close_ownership(mac_address, commit=False)
    open_ownership(mac_address, user.id, commit=False)
    db.session.commit()

    if ip_address:
        manage_switch_acl('unblock', ip_address, vlan_id)
        manage_dns_hijack('unhijack', ip_address)

    kea = _get_kea()
    if kea:
        try:
            kea.register_mac(
                mac=mac_address, vlan=target_vlan,
                hostname=device_label or 'device',
                ip_address=reserved_ip if fixed_ip_requested else None,
            )
            kea.set_block_status(
                mac_address, target_vlan, False,
                keep_ip=fixed_ip_requested,
                fixed_ip=reserved_ip if fixed_ip_requested else None,
            )
        except Exception as exc:
            logger.warning("Failed to clear Kea block for %s: %s", mac_address, exc)

    if vlan_id == wired_unregistered_vlan:
        send_coa_change(mac_address, target_vlan)

    set_internet_accessible(adopted_device, True)
    clear_unregistered_lease(mac_address)

    unregister_url = build_unregister_url(adopted_device.unregister_token)
    confirm_url = reject_url = confirm_timeout_sec = None
    if not adopted_device.ownership_validated:
        confirm_url, reject_url, confirm_timeout_sec = set_wifi_confirmation(adopted_device)

    ssid_display = (
        "Wired Network" if vlan_id == wired_unregistered_vlan
        else (adopted_device.ssid or get_ssid_for_vlan(target_vlan) or "WiFi Network")
    )
    send_wifi_registration_confirmation(
        user.email, user.first_name or "there", ssid_display, mac_address, unregister_url,
        confirm_url=confirm_url, reject_url=reject_url, confirm_timeout_sec=confirm_timeout_sec,
        registration_details={
            "email":        user.email,
            "first_name":   user.first_name,
            "last_name":    user.last_name,
            "phone_number": user.phone_number,
            "device_type":  adopted_device.device_name,
            "ip_address":   ip_address,
            "ssid":         ssid_display,
        },
    )

    flash(f'Device {mac_address} adopted successfully.', 'success')
    return redirect(url_for('portal.adopt_devices'))


@portal_bp.route('/adopt/change-vlan', methods=['POST'])
def adopt_change_vlan():
    if not client_is_on_site():
        session.pop('portal_user_id', None)
        flash('Device management is only available on the Blackfriars network.', 'error')
        return redirect(url_for('portal.user_login'))
    user, _ = current_user_from_device()
    if not user:
        flash('Please connect from a registered device to manage VLANs.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    device_id_raw = (request.form.get('device_id') or '').strip()
    target_raw    = (request.form.get('target_vlan') or '').strip()
    try:
        device_id = int(device_id_raw)
    except ValueError:
        device_id = None
    try:
        target_vlan = int(target_raw)
    except ValueError:
        target_vlan = None

    if not device_id or not target_vlan:
        flash('Device and target VLAN are required.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    device = Device.query.get(device_id)
    if device and not DeviceOwnership.query.filter_by(
            mac_address=device.mac_address, user_id=user.id, end_datetime=None).first():
        device = None
    if not device:
        flash('Device not found.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    if device.connection_type != 'wired':
        flash('Only wired devices can be moved to a different VLAN.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    _, effective_adoptable = get_effective_vlans_for_user(user)
    wired_unregistered_vlan = get_wired_unregistered_vlan_id()
    if target_vlan == wired_unregistered_vlan or target_vlan not in effective_adoptable:
        flash('You do not have permission to assign that VLAN.', 'error')
        return redirect(url_for('portal.adopt_devices'))

    device.current_vlan      = target_vlan
    device.is_wired          = True
    device.wired_target_vlan = target_vlan
    db.session.commit()

    send_coa_change(device.mac_address, target_vlan)
    kea = _get_kea()
    if kea:
        try:
            kea.register_mac(
                mac=device.mac_address, vlan=target_vlan,
                hostname=device.device_name or 'device', ip_address=None,
            )
        except Exception as exc:
            logger.warning("Kea registration failed for %s: %s", device.mac_address, exc)

    flash(f'Device {device.mac_address} moved to VLAN {target_vlan}.', 'success')
    return redirect(url_for('portal.adopt_devices'))