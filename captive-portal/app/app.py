"""
Captive Portal Application
Main Flask application for network device registration
"""

import os
import logging
import subprocess
import time
import re
import shlex
import shutil
import json
import csv
import ipaddress
import io
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, Response, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import text
import secrets

from models import db, Admin, User, Device, RegistrationRequest, VlanMapping, ISPRouter, Setting, UnregisteredLease, DomainPolicy
from radius_coa import send_coa_disconnect, send_coa_change
from email_service import (
    send_verification_email,
    send_admin_notification,
    send_admin_password_setup_email,
    send_wifi_registration_confirmation,
    send_user_blocked_device_notice,
    send_admin_password_reset_email,
    send_network_password_set_email,
    send_network_password_reset_email,
)
from kea_integration import get_kea_client
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://portal_user:password@db:5432/captive_portal')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


@app.context_processor
def inject_institution_url():
    return {
        'institution_url': os.getenv('INSTITUTION_URL', '').strip(),
        'institution_button_text': os.getenv('INSTITUTION_BUTTON_TEXT', '').strip(),
        'usage_policy_text': os.getenv('USAGE_POLICY_TEXT', '').strip(),
        'portal_url': os.getenv('PORTAL_URL', '').strip(),
        'portal_poll_url': os.getenv('PORTAL_POLL_URL', '').strip()
    }


def _get_portal_base_url():
    portal_url = os.getenv('PORTAL_URL', '').strip()
    return portal_url.rstrip('/') if portal_url else ''


def _build_portal_url(path):
    base = _get_portal_base_url()
    if base:
        return f"{base}{path}"
    return path


def _build_unregister_url(token):
    portal_url = _get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('unregister', token=token)}"
    return url_for('unregister', token=token, _external=True)


def _build_confirm_url(token):
    portal_url = _get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('confirm_device', token=token)}"
    return url_for('confirm_device', token=token, _external=True)


def _build_set_password_url(token):
    portal_url = _get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('set_network_password', token=token)}"
    return url_for('set_network_password', token=token, _external=True)


def _build_admin_set_password_url(approval_token):
    portal_url = _get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('admin_set_user_password', token=approval_token)}"
    return url_for('admin_set_user_password', token=approval_token, _external=True)


def _portal_host_mismatch():
    portal_url = _get_portal_base_url()
    if not portal_url:
        return False
    try:
        portal_host = urlparse(portal_url).netloc
    except Exception:
        return False
    return portal_host and portal_host != request.host


def _wifi_confirm_timeout_sec():
    raw = os.getenv('WIFI_CONFIRM_TIMEOUT_SEC', '120').strip()
    try:
        value = int(raw)
    except ValueError:
        value = 120
    return value if value > 0 else 120


def _wifi_confirm_sweep_interval_sec():
    raw = os.getenv('WIFI_CONFIRM_SWEEP_INTERVAL_SEC', '30').strip()
    try:
        value = int(raw)
    except ValueError:
        value = 30
    return value if value > 0 else 30


def _set_wifi_confirmation(device):
    timeout_sec = _wifi_confirm_timeout_sec()
    device.confirmation_token = secrets.token_urlsafe(32)
    device.confirmation_confirmed_at = None
    device.confirmation_deadline = datetime.utcnow() + timedelta(seconds=timeout_sec)
    db.session.commit()
    return _build_confirm_url(device.confirmation_token), timeout_sec


def _enforce_wifi_confirmation(device):
    if not device:
        return device
    if device.registration_status != 'registered':
        return device
    if not device.confirmation_deadline or device.confirmation_confirmed_at:
        return device
    if datetime.utcnow() < device.confirmation_deadline:
        return device
    logger.info("WiFi confirmation expired for %s; blocking device", device.mac_address)
    apply_device_block(device, flash_messages=False)
    return device


def _sweep_expired_wifi_confirmations():
    if not _env_truthy('WIFI_CONFIRM_SWEEP_ENABLED', True):
        return
    interval = _wifi_confirm_sweep_interval_sec()
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                expired = Device.query.filter(
                    Device.registration_status == 'registered',
                    Device.confirmation_deadline.isnot(None),
                    Device.confirmation_confirmed_at.is_(None),
                    Device.confirmation_deadline <= now,
                ).all()
                for device in expired:
                    logger.info("WiFi confirmation expired for %s; blocking device", device.mac_address)
                    apply_device_block(device, flash_messages=False)
        except Exception as exc:
            logger.warning("WiFi confirmation sweep failed: %s", exc)
        time.sleep(interval)


def _start_wifi_confirmation_sweeper():
    if not _env_truthy('WIFI_CONFIRM_SWEEP_ENABLED', True):
        return
    thread = threading.Thread(target=_sweep_expired_wifi_confirmations, daemon=True)
    thread.start()


def get_vlan_ssid_map():
    """Parse VLAN->SSID map from database."""
    mapping = {}
    try:
        entries = VlanMapping.query.all()
    except Exception:
        entries = []
    for entry in entries:
        if entry.vlan_id and entry.ssid:
            mapping[entry.vlan_id] = entry.ssid.strip()
    return mapping


def get_ssid_for_vlan(vlan_id):
    return get_vlan_ssid_map().get(vlan_id)


def _parse_allowed_vlans(raw):
    if not raw:
        return set()
    allowed = set()
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        try:
            allowed.add(int(entry))
        except ValueError:
            continue
    return allowed


def _normalize_mac_input(raw):
    if not raw:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(raw)).lower()
    if len(cleaned) != 12:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))


def _parse_csv_bool(value):
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text in {'y', 'yes', '1', 'true', 'allow', 'allowed'}:
        return True
    if text in {'n', 'no', '0', 'false', 'deny', 'denied'}:
        return False
    return None


def _normalize_csv_header(value):
    if value is None:
        return ''
    return re.sub(r'\s+', ' ', str(value)).strip().lower()


def _csv_template_fields(vlan_map):
    base_fields = [
        ('email', 'Email'),
        ('first_name', 'First Name'),
        ('last_name', 'Second Name'),
        ('phone_number', 'Phone Number'),
        ('mac_address', 'MAC Address'),
        ('device_type', 'Device Type'),
        ('vlan_id', 'VLAN ID'),
    ]
    vlan_fields = []
    entries = get_vlan_entries()
    for entry in entries:
        if entry.status in {'restricted', 'unregistered'}:
            continue
        vlan_id = entry.vlan_id
        if not vlan_id:
            continue
        vlan_fields.append((f'vlan{vlan_id}_allowed', f'VLAN{vlan_id}Allowed'))
        vlan_fields.append((f'vlan{vlan_id}_adoptable', f'VLAN{vlan_id}Adoptable'))
    return base_fields, vlan_fields


def _csv_template_example_value(header, row_index):
    examples = {
        'Email': ('robert@example.com', 'jane@example.com'),
        'First Name': ('Robert', 'Jane'),
        'Second Name': ('Verrill', 'Doe'),
        'Phone Number': ('555-0100', '555-0199'),
        'MAC Address': ('AA:BB:CC:DD:EE:FF', ''),
        'Device Type': ('laptop', 'phone'),
        'VLAN ID': ('20', '10'),
    }
    if header in examples:
        return examples[header][row_index]

    match = re.match(r'^VLAN(\d+)(Allowed|Adoptable)$', header)
    if match:
        return 'Y' if row_index == 0 else 'N'

    return ''


def _email_domain(email):
    if not email or '@' not in email:
        return ''
    return email.split('@', 1)[1].strip().lower()


def _load_domain_policy_map():
    policies = DomainPolicy.query.all()
    return {policy.domain.lower(): policy for policy in policies}


def _effective_vlan_sets(user, domain_policy):
    domain_allowed = _parse_allowed_vlans(domain_policy.allowed_vlans) if domain_policy else set()
    domain_adoptable = _parse_allowed_vlans(domain_policy.adoptable_vlans) if domain_policy else set()

    user_allow = _parse_allowed_vlans(user.allowed_vlans_override)
    user_deny = _parse_allowed_vlans(user.allowed_vlans_deny)
    user_adopt_allow = _parse_allowed_vlans(user.adoptable_vlans_override)
    user_adopt_deny = _parse_allowed_vlans(user.adoptable_vlans_deny)

    effective_allowed = (domain_allowed | user_allow) - user_deny
    effective_adoptable = (domain_adoptable | user_adopt_allow) - user_adopt_deny

    domain_allowed_only = domain_allowed - user_allow - user_deny
    domain_adoptable_only = domain_adoptable - user_adopt_allow - user_adopt_deny

    return effective_allowed, effective_adoptable, domain_allowed_only, domain_adoptable_only


def _format_vlan_display_items(vlans, domain_based, denied, user_override, vlan_map):
    items = []
    denied = denied or set()
    user_override = user_override or set()
    for vlan_id in sorted(vlans):
        items.append({
            'label': _label_for_vlan(vlan_id, vlan_map),
            'domain_based': vlan_id in domain_based,
            'denied': vlan_id in denied,
            'user_override': vlan_id in user_override,
        })
    return items


def _format_vlan_items_text(items):
    if not items:
        return ''
    return ', '.join(item['label'] for item in items if not item.get('denied'))


def _get_domain_policy_for_user(user, domain_policy_map=None):
    if not user or not user.email:
        return None
    if domain_policy_map is None:
        domain_policy_map = _load_domain_policy_map()
    return domain_policy_map.get(_email_domain(user.email))


def _get_effective_vlans_for_user(user, domain_policy_map=None):
    domain_policy = _get_domain_policy_for_user(user, domain_policy_map)
    effective_allowed, effective_adoptable, _, _ = _effective_vlan_sets(user, domain_policy)
    return effective_allowed, effective_adoptable


def _parse_vlan_override_form(vlan_map, prefix):
    allow = set()
    deny = set()
    for status, vlan_id in vlan_map.items():
        if status in {'unregistered', 'restricted'}:
            continue
        value = (request.form.get(f'{prefix}_{vlan_id}') or '').strip().lower()
        if value == 'allow':
            allow.add(vlan_id)
        elif value == 'deny':
            deny.add(vlan_id)
    return allow, deny


def _format_allowed_vlans(vlans):
    if not vlans:
        return ''
    return ','.join(str(vlan) for vlan in sorted(vlans))


def _default_vlan_for_user(allowed_vlans, vlan_map):
    if allowed_vlans:
        return sorted(allowed_vlans)[0]
    return None


def _label_for_vlan(vlan_id, vlan_map):
    if not vlan_id:
        return ''
    meta = get_vlan_meta_by_id().get(vlan_id)
    if meta:
        display_name = (meta.get('display_name') or '').strip()
        status = meta.get('status')
        if display_name:
            return f"{display_name} (VLAN {vlan_id})"
        if status:
            return f"{status.title()} (VLAN {vlan_id})"
    return f"VLAN {vlan_id}"


def _allowed_vlans_display_items(user, vlan_map, domain_policy, include_denied=False):
    effective_allowed, _, _, _ = _effective_vlan_sets(user, domain_policy)
    user_allow = _parse_allowed_vlans(user.allowed_vlans_override)
    user_deny = _parse_allowed_vlans(user.allowed_vlans_deny)
    domain_allowed = _parse_allowed_vlans(domain_policy.allowed_vlans) if domain_policy else set()
    denied_vlans = user_deny if include_denied else set()
    display_vlans = effective_allowed | denied_vlans
    if not display_vlans:
        return []
    return _format_vlan_display_items(display_vlans, domain_allowed, denied_vlans, user_allow, vlan_map)


def _adoptable_vlans_display_items(user, vlan_map, domain_policy, include_denied=False):
    _, effective_adoptable, _, _ = _effective_vlan_sets(user, domain_policy)
    user_allow = _parse_allowed_vlans(user.adoptable_vlans_override)
    user_deny = _parse_allowed_vlans(user.adoptable_vlans_deny)
    domain_adoptable = _parse_allowed_vlans(domain_policy.adoptable_vlans) if domain_policy else set()
    denied_vlans = user_deny if include_denied else set()
    display_vlans = effective_adoptable | denied_vlans
    if not display_vlans:
        return []
    return _format_vlan_display_items(display_vlans, domain_adoptable, denied_vlans, user_allow, vlan_map)


def _should_hijack_vlan(vlan_id):
    return True


POOL_PREFIX_CHOICES = [24, 23, 22, 21]
POOL_PREFIX_STATUSES = ['friars', 'staff', 'students', 'guests', 'contractors', 'volunteers', 'iot']
WIRED_UNREGISTERED_STATUS = 'wired_unregistered'
FIXED_VLAN_STATUSES = [
    'friars',
    'staff',
    'students',
    'guests',
    'contractors',
    'volunteers',
    'iot',
    'restricted',
    'unregistered',
    WIRED_UNREGISTERED_STATUS,
]


def _parse_valid_vlan_ids():
    raw = os.getenv('VALID_VLANS', '').strip()
    if not raw:
        return []
    vlan_ids = []
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        try:
            vlan_ids.append(int(entry))
        except ValueError:
            continue
    return sorted(set(vlan_ids))


def _get_wired_unregistered_vlan_id():
    vlan_map = get_vlan_map()
    wired_vlan = vlan_map.get(WIRED_UNREGISTERED_STATUS)
    if wired_vlan:
        return wired_vlan
    return 250


def _get_wired_assignable_entries():
    entries = []
    for entry in get_vlan_entries():
        if not entry.vlan_id:
            continue
        if entry.status in {'restricted', 'unregistered', WIRED_UNREGISTERED_STATUS}:
            continue
        if entry.wired_enabled:
            entries.append(entry)
    return entries


def _get_wired_assignable_vlan_ids():
    return {entry.vlan_id for entry in _get_wired_assignable_entries()}


def _vlan_requires_password(vlan_id):
    """Return True if the given VLAN ID requires a network password for registration."""
    if not vlan_id:
        return False
    mapping = VlanMapping.query.filter_by(vlan_id=vlan_id).first()
    return bool(mapping and mapping.require_password)


def _get_admin_assignable_entries():
    """Get all VLANs that admins with manage_users permission can assign devices to.
    Unlike _get_wired_assignable_entries(), this doesn't require wired_enabled to be True.
    Admins can assign devices to any VLAN except restricted/unregistered."""
    entries = []
    for entry in get_vlan_entries():
        if not entry.vlan_id:
            continue
        # Only exclude truly restricted VLANs - admins can assign to any other VLAN
        if entry.status in {'restricted', 'unregistered', WIRED_UNREGISTERED_STATUS}:
            continue
        entries.append(entry)
    return entries


def get_vlan_entries():
    mappings = VlanMapping.query.order_by(VlanMapping.vlan_id.asc()).all()
    if mappings:
        return mappings

    return []


def get_vlan_meta_by_id():
    meta = {}
    for entry in get_vlan_entries():
        if entry.vlan_id:
            meta[entry.vlan_id] = {
                'status': entry.status,
                'display_name': entry.display_name,
                'ssid': entry.ssid,
            }
    return meta


def _get_vlan_prefix_map():
    prefix_map = {}
    for status in POOL_PREFIX_STATUSES:
        raw = Setting.get_value(f'vlan_prefix_{status}', 24)
        try:
            prefix = int(raw)
        except (TypeError, ValueError):
            prefix = 24
        if prefix not in POOL_PREFIX_CHOICES:
            prefix = 24
        prefix_map[status] = prefix
    return prefix_map


def _ip_from_offset(network, offset):
    return str(ipaddress.IPv4Address(int(network.network_address) + offset))


def _build_pools_for_vlan(vlan_id, prefix):
    network = ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{prefix}", strict=False)
    total = network.num_addresses
    block_size = 40 * (2 ** (24 - prefix))
    block_start = total - block_size
    block_end = total - 1
    registered_start = 5
    registered_end = block_start - 1

    if registered_end < registered_start:
        raise ValueError(f"Pool size too small for VLAN {vlan_id} /{prefix}")

    reserved_start_ip = ipaddress.IPv4Address(f"192.168.{vlan_id}.1")
    reserved_end_ip = ipaddress.IPv4Address(f"192.168.{vlan_id}.4")
    reserved_in_network = reserved_start_ip in network and reserved_end_ip in network
    reserved_start_offset = int(reserved_start_ip) - int(network.network_address)
    reserved_end_offset = int(reserved_end_ip) - int(network.network_address)

    registered_pools = []
    if reserved_in_network and not (reserved_end_offset < registered_start or reserved_start_offset > registered_end):
        if reserved_start_offset > registered_start:
            registered_pools.append(
                f"{_ip_from_offset(network, registered_start)} - {_ip_from_offset(network, reserved_start_offset - 1)}"
            )
        if reserved_end_offset < registered_end:
            registered_pools.append(
                f"{_ip_from_offset(network, reserved_end_offset + 1)} - {_ip_from_offset(network, registered_end)}"
            )
    else:
        registered_pools.append(
            f"{_ip_from_offset(network, registered_start)} - {_ip_from_offset(network, registered_end)}"
        )

    if not registered_pools:
        raise ValueError(f"Pool size too small for VLAN {vlan_id} /{prefix}")

    blocked_pool = f"{_ip_from_offset(network, block_start)} - {_ip_from_offset(network, block_end)}"

    return str(network), registered_pools, blocked_pool


def _pool_bounds_for_prefix(prefix):
    total = 2 ** (32 - prefix)
    block_size = 40 * (2 ** (24 - prefix))
    registered_start = 5
    registered_end = total - block_size - 1
    blocked_start = registered_end + 1
    blocked_end = total - 1
    return registered_start, registered_end, blocked_start, blocked_end


def _get_vlan_prefix_by_id():
    vlan_map = get_vlan_map()
    prefix_map = _get_vlan_prefix_map()
    prefix_by_id = {}
    for status, vlan_id in vlan_map.items():
        if status in prefix_map:
            prefix_by_id[vlan_id] = prefix_map[status]
        else:
            prefix_by_id[vlan_id] = 24
    return prefix_by_id


def _update_kea_config(vlan_prefix_by_id):
    config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Kea config not found at {config_path}")

    with open(config_path, 'r', encoding='utf-8') as handle:
        config = json.load(handle)

    subnets = config.get('Dhcp4', {}).get('subnet4', [])
    updated = 0

    for subnet in subnets:
        vlan_id = subnet.get('id')
        if vlan_id not in vlan_prefix_by_id:
            continue
        prefix = vlan_prefix_by_id[vlan_id]
        subnet_cidr, registered_pools, blocked_pool = _build_pools_for_vlan(vlan_id, prefix)
        subnet['subnet'] = subnet_cidr
        subnet['pools'] = [{'pool': pool} for pool in registered_pools] + [
            {
                'pool': blocked_pool,
                'client-classes': ['BLOCKED'],
            },
        ]
        updated += 1

    if not updated:
        raise ValueError("No matching VLAN subnets updated in Kea config")

    with open(config_path, 'w', encoding='utf-8') as handle:
        json.dump(config, handle, indent=2)
        handle.write('\n')


def _restart_kea_container():
    commands = [
        ['sudo', 'docker', 'compose', '-f', '/kea/docker-compose.yml', 'restart', 'kea'],
        ['sudo', 'docker-compose', '-f', '/kea/docker-compose.yml', 'restart', 'kea'],
        ['sudo', 'docker', 'restart', 'kea'],
    ]

    for command in commands:
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
            return True, result.stdout.strip()
        except Exception:
            continue

    return False, 'Unable to restart Kea via docker commands.'




# Initialize database
db.init_app(app)


@app.after_request
def add_cors_headers(response):
    # List of paths needing CORS (add more as needed)
    cors_paths = ['/api/registration-status', '/register']  # e.g., add '/api/other' if exists
    
    if request.path in cors_paths:
        origin = request.headers.get('Origin', '')
        
        
        # Whitelist: Add expected origins (e.g., connectivity checks)
        allowed_origins = [
            'http://www.msftconnecttest.com',
            'http://connectivitycheck.gstatic.com',
            'http://captive.apple.com',
            'http://detectportal.firefox.com',
            # Add your portal's domain if self-calls occur: 'http://bf-network.duckdns.org'
        ]
        
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            # Fallback: Deny or log unexpected origins
            logger.warning(f"Unexpected Origin: {origin}")
            # Optionally return 403 or omit header to block
        
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'  # For caching
        
    return response

# Initialize Kea client for WiFi registrations
KEA_SOCKET = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
kea_client = None

# Cache for per-device Kea reservation self-healing checks.
# Prevents repeated reservation-get calls from captive portal detection probes.
# Key: (mac, vlan_id), Value: last-check epoch float
_kea_reservation_check_cache: dict = {}
_kea_reservation_check_lock = threading.Lock()
KEA_RESERVATION_CHECK_TTL_SEC = int(os.getenv('KEA_RESERVATION_CHECK_TTL_SEC', '300'))

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# Enforcement: redirect admins who need MFA setup or password change
_AUTH_EXEMPT_ENDPOINTS = {
    'admin_login',
    'admin_logout',
    'admin_mfa_setup',
    'admin_mfa_verify',
    'admin_mfa_disable',
    'admin_change_own_password',
    'admin_forgot_password',
    'admin_reset_password',
    'static',
}

@app.before_request
def enforce_mfa_setup():
    """Redirect authenticated admins to MFA setup or forced password change as needed."""
    from flask_login import current_user
    endpoint = request.endpoint
    # Only enforce on admin endpoints
    if not endpoint or not endpoint.startswith('admin_'):
        return
    # Skip exempt endpoints
    if endpoint in _AUTH_EXEMPT_ENDPOINTS:
        return
    # Only enforce for authenticated users
    if not current_user or not current_user.is_authenticated:
        return
    # Forced password change takes priority
    if getattr(current_user, 'must_change_password', False):
        return redirect(url_for('admin_change_own_password'))
    # Redirect if MFA is not enabled
    if not getattr(current_user, 'mfa_enabled', False):
        return redirect(url_for('admin_mfa_setup'))

# VLAN configuration - load from database with fallback to env vars
def get_vlan_map():
    """Get VLAN mappings from database"""
    mappings = VlanMapping.query.all()
    if mappings:
        return {m.status: m.vlan_id for m in mappings}
    
    # Fallback to environment variables if database is empty
    return {
        'friars': 10,
        'staff': 20,
        'students': 30,
        'guests': 40,
        'contractors': 50,
        'volunteers': 60,
        'iot': 70,
        'restricted': 90,
        'unregistered': 99,
        WIRED_UNREGISTERED_STATUS: 250,
    }

# Admin user (simple single admin - extend for multiple admins)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', generate_password_hash('admin123'))


def is_test_env():
    return os.getenv('TEST_ENV', 'false').strip().lower() in {'1', 'true', 'yes', 'on'}


def _env_truthy(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


_start_wifi_confirmation_sweeper()


class AdminUser:
    """Admin user class for Flask-Login with role-based permissions"""
    def __init__(self, admin_id, username, can_manage_users=True, can_manage_vlans=False, 
                 can_view_traffic=False, can_manage_admins=False, traffic_viewer_settings=None, 
                 mfa_enabled=False, must_change_password=False, can_manage_switch_ports=False,
                 can_manage_isp_routers=False):
        self.id = str(admin_id)  # Flask-Login requires string ID
        self.username = username
        self.can_manage_users = can_manage_users
        self.can_manage_vlans = can_manage_vlans
        self.can_view_traffic = can_view_traffic
        self.can_manage_admins = can_manage_admins
        self.can_manage_switch_ports = can_manage_switch_ports
        self.can_manage_isp_routers = can_manage_isp_routers
        self.traffic_viewer_settings = traffic_viewer_settings
        self.mfa_enabled = mfa_enabled
        self.must_change_password = must_change_password
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self.id
    
    @property
    def is_super_admin(self):
        """Super admin = can manage admins"""
        return self.can_manage_admins


@login_manager.user_loader
def load_user(user_id):
    """Load admin user by ID"""
    try:
        admin_id = int(user_id)
        admin = Admin.query.get(admin_id)
        if admin:
            return AdminUser(
                admin.id,
                admin.username,
                admin.can_manage_users,
                admin.can_manage_vlans,
                admin.can_view_traffic,
                admin.can_manage_admins,
                admin.traffic_viewer_settings,
                admin.mfa_enabled,
                getattr(admin, 'must_change_password', False),
                getattr(admin, 'can_manage_switch_ports', False),
                getattr(admin, 'can_manage_isp_routers', False)
            )
    except (ValueError, TypeError):
        pass
    return None


# Permission decorators for route protection
def permission_required(permission):
    """Decorator to check if current admin has specific permission"""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('admin_login'))
            
            # Check if user has the required permission
            if permission == 'manage_users' and not current_user.can_manage_users:
                flash('You do not have permission to manage users and devices.', 'error')
                return redirect(url_for('admin_dashboard'))
            elif permission == 'manage_vlans' and not current_user.can_manage_vlans:
                flash('You do not have permission to manage VLANs.', 'error')
                return redirect(url_for('admin_dashboard'))
            elif permission == 'view_traffic' and not current_user.can_view_traffic:
                flash('You do not have permission to view traffic.', 'error')
                return redirect(url_for('admin_dashboard'))
            elif permission == 'manage_admins' and not current_user.can_manage_admins:
                flash('You do not have permission to manage admins.', 'error')
                return redirect(url_for('admin_dashboard'))
            elif permission == 'manage_switch_ports' and not current_user.can_manage_switch_ports:
                flash('You do not have permission to manage switch ports.', 'error')
                return redirect(url_for('admin_dashboard'))
            elif permission == 'manage_isp_routers' and not current_user.can_manage_isp_routers:
                flash('You do not have permission to manage ISP routers.', 'error')
                return redirect(url_for('admin_dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_client_mac():
    """
    Extract MAC address from Kea lease database based on client IP.
    This works for both WiFi and wired connections.
    """
    # Try common headers set by captive portal redirects first
    mac = request.headers.get('X-Client-MAC')
    if not mac:
        mac = request.args.get('mac')
    if not mac:
        mac = request.form.get('mac')
    
    # If not in headers/params, query Kea lease database
    if not mac:
        ip_address = get_client_ip()
        if ip_address:
            try:
                # Read Kea lease file directly (CSV format)
                # Format: address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
                # Only use the current lease file, not backups
                lease_file = '/kea/leases/kea-leases4.csv'
                
                # Collect all matching entries (there may be duplicates for same IP)
                matching_macs = []
                
                try:
                    with open(lease_file, 'r') as f:
                        for line in f:
                            # Skip header line
                            if line.startswith('address,'):
                                continue
                                
                            fields = line.strip().split(',')
                            if len(fields) >= 2:
                                lease_ip = fields[0]
                                lease_hwaddr = fields[1]
                                
                                # Check if IP matches
                                if lease_ip == ip_address:
                                    matching_macs.append(lease_hwaddr)
                    
                    # Use the LAST matching MAC (most recent entry)
                    if matching_macs:
                        mac = matching_macs[-1]
                        
                            
                except FileNotFoundError:
                    logger.debug(f"Kea lease file not found: {lease_file}")
                except Exception as e:
                    logger.error(f"Error reading Kea lease file {lease_file}: {e}")
                
                # If not found in lease file, try querying Kea control socket directly
                if not mac:
                    try:
                        kea = get_kea()
                        if kea:
                            lease = kea.get_lease(ip_address)
                            if lease:
                                mac = lease.get('hw-address')
                                if mac:
                                    logger.info(f"Found MAC {mac} for IP {ip_address} via Kea control socket")
                    except Exception as e:
                        logger.error(f"Error querying Kea control socket: {e}")
                        
            except Exception as e:
                logger.error(f"Error looking up MAC address: {e}")
    
    # Normalize MAC address format
    if mac:
        mac = mac.lower().replace('-', '').replace(':', '')
        if len(mac) == 12:
            # Format as xx:xx:xx:xx:xx:xx
            mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
    
    return mac


def get_ip_for_mac(mac_address, subnet_id=None):
    """
    Find the most recent IP address for a MAC address from the Kea lease file.
    """
    if not mac_address:
        return None

    normalized = mac_address.lower().replace('-', ':')
    lease_file = '/kea/leases/kea-leases4.csv'
    matching_ips = []

    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue

                fields = line.strip().split(',')
                if len(fields) >= 2:
                    lease_ip = fields[0]
                    lease_hwaddr = fields[1].lower()
                    if lease_hwaddr == normalized:
                        matching_ips.append(lease_ip)

        if matching_ips:
            ip_address = matching_ips[-1]
            logger.info(f"Found IP {ip_address} for MAC {normalized} in Kea lease file")
            return ip_address

    except FileNotFoundError:
        logger.debug(f"Kea lease file not found: {lease_file}")
    except Exception as e:
        logger.error(f"Error reading Kea lease file {lease_file}: {e}")

    # Fallback to Kea control socket when lease file is unavailable
    try:
        kea = get_kea()
        if kea:
            lease_ip = kea.get_lease_ip_for_mac(normalized, subnet_id=subnet_id)
            if lease_ip:
                logger.info(f"Found IP {lease_ip} for MAC {normalized} via Kea control socket")
                return lease_ip
    except Exception as e:
        logger.error(f"Error querying Kea for MAC {normalized}: {e}")

    return None


def _vlan_from_ip(ip_address):
    if not ip_address:
        return None
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return None

    prefix_by_id = _get_vlan_prefix_by_id()
    for vlan_id, prefix in prefix_by_id.items():
        if vlan_id == 99:
            continue
        try:
            network = ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{prefix}", strict=False)
        except Exception:
            continue
        if ip in network:
            return vlan_id
    return None


def _vlan_from_ip_any(ip_address, prefix_by_id=None):
    if not ip_address:
        return None
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return None

    if prefix_by_id is None:
        prefix_by_id = _get_vlan_prefix_by_id()

    for vlan_id, prefix in prefix_by_id.items():
        try:
            network = ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{prefix}", strict=False)
        except Exception:
            continue
        if ip in network:
            return vlan_id
    return None


def _load_active_lease_counts():
    lease_file = '/kea/leases/kea-leases4.csv'
    counts = {}
    seen_by_vlan = {}
    now = datetime.utcnow()
    prefix_by_id = _get_vlan_prefix_by_id()

    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue
                fields = line.strip().split(',')
                if len(fields) < 5:
                    continue
                ip_address = fields[0]
                expire_raw = fields[4].strip()
                expires_at = None
                if expire_raw:
                    try:
                        expires_at = datetime.utcfromtimestamp(int(expire_raw))
                    except Exception:
                        expires_at = None
                if expires_at and expires_at < now:
                    continue

                vlan_id = None
                if len(fields) > 5 and fields[5].strip().isdigit():
                    vlan_id = int(fields[5].strip())
                if vlan_id is None:
                    vlan_id = _vlan_from_ip_any(ip_address, prefix_by_id)
                if not vlan_id:
                    continue

                seen = seen_by_vlan.setdefault(vlan_id, set())
                if ip_address in seen:
                    continue
                seen.add(ip_address)
                counts[vlan_id] = counts.get(vlan_id, 0) + 1
    except FileNotFoundError:
        logger.warning("Kea lease file not found for lease counts: %s", lease_file)
    except Exception as exc:
        logger.error("Failed to read lease counts: %s", exc)

    return counts


def _load_adoptable_leases(vlan_ids):
    if not vlan_ids:
        return []

    lease_file = '/kea/leases/kea-leases4.csv'
    now = datetime.utcnow()
    adoptable_by_mac = {}
    existing_leases = {
        lease.mac_address: lease
        for lease in UnregisteredLease.query.all()
    }

    try:
        with open(lease_file, 'r') as f:
            for line in f:
                if line.startswith('address,'):
                    continue
                fields = line.strip().split(',')
                if len(fields) < 5:
                    continue
                ip_address = fields[0]
                mac_address = fields[1].lower()
                vlan_id = _vlan_from_ip(ip_address)
                if not vlan_id or vlan_id not in vlan_ids:
                    continue

                expire_raw = fields[4].strip() if len(fields) > 4 else ''
                expires_at = None
                if expire_raw:
                    try:
                        expires_at = datetime.utcfromtimestamp(int(expire_raw))
                    except Exception:
                        expires_at = None
                if not expires_at:
                    expires_at = now + timedelta(hours=1)

                upsert_unregistered_lease(
                    mac_address,
                    ip_address,
                    expires_at,
                    commit=False,
                )

                existing = existing_leases.get(mac_address)
                first_seen = existing.created_at if existing else now
                last_seen = existing.updated_at if existing else now

                current = adoptable_by_mac.get(mac_address)
                if current:
                    current['first_seen'] = min(current['first_seen'], first_seen)
                    current['last_seen'] = max(current['last_seen'], last_seen)
                    if expires_at and (not current['expires_at'] or expires_at > current['expires_at']):
                        current['expires_at'] = expires_at
                        current['ip_address'] = ip_address
                        current['vlan_id'] = vlan_id
                    continue

                adoptable_by_mac[mac_address] = {
                    'mac_address': mac_address,
                    'ip_address': ip_address,
                    'vlan_id': vlan_id,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'expires_at': expires_at,
                }
    except FileNotFoundError:
        logger.warning("Kea lease file not found for adoptable scan: %s", lease_file)
    except Exception as exc:
        logger.error("Failed to read adoptable leases: %s", exc)

    db.session.commit()
    return list(adoptable_by_mac.values())


def _current_user_from_device():
    mac_address = get_client_mac()
    if not mac_address:
        return None, None
    device = Device.query.filter_by(mac_address=mac_address).first()
    if not device or device.registration_status != 'registered':
        return None, None
    if not device.user or device.user.blocked or not device.user.is_active:
        return None, None
    return device.user, device


def get_client_ip():
    """Get client IP address"""
    # Check X-Real-IP first (set by nginx proxy manager)
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    # Then check X-Forwarded-For
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def _build_prefill_from_request():
    return {
        'email': request.args.get('email', '').strip(),
        'first_name': request.args.get('first_name', '').strip(),
        'last_name': request.args.get('last_name', '').strip(),
        'phone_number': request.args.get('phone_number', '').strip(),
        'device_type': request.args.get('device_type', '').strip(),
    }


def normalize_device_status(device):
    if not device:
        return device

    updated = False
    if device.registration_status in {'active', 'approved'}:
        device.registration_status = 'registered'
        updated = True
    elif device.registration_status == 'restricted':
        device.registration_status = 'blocked'
        updated = True

    if updated:
        db.session.commit()

    return device


def detect_connection_type(ip_address):
    """
    Detect if connection is WiFi or wired based on source IP/VLAN.
    
    Wired connections: VLAN 99 (registration VLAN for wired MAC auth)
    WiFi connections: All other VLANs (10, 20, 30, 40, 50, 60, 70)
    
    Args:
        ip_address: Client IP address
        
    Returns:
        tuple: (connection_type, vlan_id, ssid)
    """
    if not ip_address:
        return ('unknown', None, None)
    
    vlan_id = _vlan_from_ip(ip_address)
    if not vlan_id:
        return ('unknown', None, None)

    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
    if vlan_id in {99, wired_unregistered_vlan}:
        return ('wired', vlan_id, None)

    ssid = get_ssid_for_vlan(vlan_id)
    if ssid:
        return ('wifi', vlan_id, ssid)
    return ('unknown', vlan_id, None)


def get_kea():
    """Get or initialize Kea client"""
    global kea_client
    if kea_client is None:
        try:
            kea_client = get_kea_client(control_socket=KEA_SOCKET)
        except Exception as e:
            logger.error(f"Failed to initialize Kea client: {e}")
            kea_client = None
    return kea_client


def manage_dns_hijack(action, ip_address):
    """
    Manage DNS hijacking for unregistered devices.
    
    Args:
        action: 'hijack' to enable DNS redirect, 'unhijack' to remove it
        ip_address: Device IP address
        
    Returns:
        bool: True if successful, False otherwise
    """
    script_path = '/scripts/dns-hijack.sh'
    
    try:
        result = subprocess.run(
            [script_path, action, ip_address],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0:
            logger.info(f"DNS {action} successful for {ip_address}: {result.stdout.strip()}")
            return True
        else:
            logger.error(f"DNS {action} failed for {ip_address}: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"DNS {action} timed out for {ip_address}")
        return False
    except Exception as e:
        logger.error(f"DNS {action} error for {ip_address}: {e}")
        return False


def get_lease_expiry_for_mac(mac_address, subnet_id=None):
    kea = get_kea()
    if not kea:
        return None

    lease = kea.get_lease_by_mac(mac_address, subnet_id=subnet_id)
    if not lease:
        return None

    try:
        if lease.get("expire"):
            return datetime.utcfromtimestamp(int(lease["expire"]))
        cltt = lease.get("cltt")
        valid_lft = lease.get("valid-lft")
        if cltt and valid_lft:
            return datetime.utcfromtimestamp(int(cltt) + int(valid_lft))
    except Exception:
        return None

    return None


def reset_dns_hijack_rules():
    """Remove all per-IP hijack rules and restore blocked pool ranges."""
    base_cmd = _get_iptables_base_cmd()
    result = subprocess.run(
        base_cmd + ["-t", "nat", "-S", "PREROUTING"],
        capture_output=True,
        text=True,
        timeout=15
    )
    if result.returncode != 0:
        logger.error("Failed to read iptables rules: %s", result.stderr.strip())
        return False

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING"):
            continue
        if "DNAT" not in line:
            continue
        if (
            "--to-destination 192.168.99.5:53" not in line
            and "--to-destination 192.168.99.4:8080" not in line
        ):
            continue

        delete_parts = shlex.split(line)
        delete_parts[0] = "-D"
        delete_cmd = base_cmd + ["-t", "nat"] + delete_parts
        subprocess.run(delete_cmd, capture_output=True, text=True, timeout=15)

    # Re-add blocked pool DNS hijack ranges
    script_path = '/scripts/dns-hijack.sh'
    subprocess.run([script_path, "hijack-blocked-pools"], capture_output=True, text=True, timeout=15)
    return True


def reset_acl_baseline():
    """Re-apply baseline ACLs on the switch."""
    script_path = os.getenv('ACL_BASELINE_SCRIPT', '/scripts/hp5130-acl-baseline.sh')
    if not os.path.isfile(script_path):
        logger.error("ACL baseline script not found: %s", script_path)
        return False

    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"

    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        stdout = (result.stdout or '').strip()
        logger.error(
            "ACL baseline failed (exit=%s). stderr=%s stdout=%s",
            result.returncode,
            stderr or '<empty>',
            stdout or '<empty>',
        )
        return False
    return True


def clear_mac_auth_sessions():
    """Clear all MAC authentication sessions on the switch to force re-authentication."""
    script_path = os.getenv('CLEAR_MAC_AUTH_SCRIPT', '/scripts/hp5130-clear-mac-auth.sh')
    if not os.path.isfile(script_path):
        logger.warning("MAC auth clear script not found: %s", script_path)
        return False

    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"

    result = subprocess.run([script_path], capture_output=True, text=True, timeout=60, env=env)
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        stdout = (result.stdout or '').strip()
        logger.error(
            "MAC auth clear failed (exit=%s). stderr=%s stdout=%s",
            result.returncode,
            stderr or '<empty>',
            stdout or '<empty>',
        )
        return False
    return True


def reset_user_ports():
    """Reset and reconfigure user device ports on the switch."""
    script_path = os.getenv('RESET_USER_PORTS_SCRIPT', '/scripts/hp5130-reset-user-ports.sh')
    if not os.path.isfile(script_path):
        logger.warning("Reset user ports script not found: %s", script_path)
        return False

    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"

    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        stdout = (result.stdout or '').strip()
        logger.error(
            "Reset user ports failed (exit=%s). stderr=%s stdout=%s",
            result.returncode,
            stderr or '<empty>',
            stdout or '<empty>',
        )
        return False
    return True


def reset_vlan_interface_masks(vlan_ids):
    """Update HP5130 VLAN interface masks for specific VLAN IDs."""
    vlan_ids = [str(vlan_id) for vlan_id in vlan_ids if vlan_id]
    if not vlan_ids:
        return True

    script_path = os.getenv('VLAN_INTERFACE_SCRIPT', '/scripts/hp5130-vlan-interface.sh')
    if not os.path.isfile(script_path):
        logger.error("VLAN interface script not found: %s", script_path)
        return False

    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"
    env["VLAN_LIST"] = " ".join(vlan_ids)

    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        stdout = (result.stdout or '').strip()
        logger.error(
            "VLAN interface update failed (exit=%s). stderr=%s stdout=%s",
            result.returncode,
            stderr or '<empty>',
            stdout or '<empty>',
        )
        return False
    return True


def reset_pi_network_masks(vlan_ids):
    """Update Pi VLAN interface masks for specific VLAN IDs."""
    vlan_ids = [str(vlan_id) for vlan_id in vlan_ids if vlan_id]
    if not vlan_ids:
        return True

    script_path = os.getenv('PI_NETWORK_SCRIPT', '/scripts/pi-network-update.sh')
    if not os.path.isfile(script_path):
        logger.error("Pi network script not found: %s", script_path)
        return False

    env = os.environ.copy()
    env["VLAN_LIST"] = " ".join(vlan_ids)
    if env.get("PI_NETWORK_DIR"):
        env["NETWORK_DIR"] = env["PI_NETWORK_DIR"]

    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        stdout = (result.stdout or '').strip()
        logger.error(
            "Pi network update failed (exit=%s). stderr=%s stdout=%s",
            result.returncode,
            stderr or '<empty>',
            stdout or '<empty>',
        )
        return False
    return True


def reset_acl_queue_files():
    queue_base = os.getenv('ACL_QUEUE_DIR') or ('/acl-queue' if os.path.isdir('/acl-queue') else '/shared/acl-queue')
    try:
        if os.path.isdir(queue_base):
            for name in os.listdir(queue_base):
                if name.startswith(".dedup-") or name in {"hp5130-acl.queue", "hp5130-acl.pid", "hp5130-acl.lock"}:
                    path = os.path.join(queue_base, name)
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        try:
                            os.remove(path)
                            logger.info("ACL queue file cleared successfully: %s", path)
                        except FileNotFoundError:
                            pass
    except Exception as exc:
        logger.warning("Failed to clear ACL queue files: %s", exc)


def reset_test_data():
    """Remove all users/devices/requests, Kea host/lease data, and NAT/DNS logs."""
    kea = None
    if os.path.exists(KEA_SOCKET):
        kea = get_kea()
    else:
        logger.warning("Kea control socket missing, skipping reservation cleanup")

    devices = Device.query.all()
    if kea and devices:
        for device in devices:
            vlan_id = device.wired_target_vlan or device.current_vlan
            if not vlan_id:
                continue
            try:
                kea.unregister_mac(device.mac_address, vlan_id)
            except Exception as exc:
                logger.warning("Kea unregister failed for %s vlan %s: %s", device.mac_address, vlan_id, exc)

    db.session.query(RegistrationRequest).delete(synchronize_session=False)
    db.session.query(Device).delete(synchronize_session=False)
    db.session.query(User).delete(synchronize_session=False)
    db.session.query(UnregisteredLease).delete(synchronize_session=False)
    db.session.commit()

    # Clear Kea tables
    db.session.execute(text("DELETE FROM hosts"))
    db.session.execute(text("DELETE FROM lease4"))
    
    # Clear NAT and DNS logging tables
    db.session.execute(text("DELETE FROM nat_sessions"))
    db.session.execute(text("DELETE FROM dns_resolutions"))
    db.session.execute(text("DELETE FROM mac_port_cache"))
    db.session.commit()


def upsert_unregistered_lease(mac_address, ip_address, expires_at, commit=True):
    if not mac_address or not ip_address or not expires_at:
        return

    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    if lease:
        lease.ip_address = ip_address
        lease.expires_at = expires_at
    else:
        lease = UnregisteredLease(
            mac_address=mac_address,
            ip_address=ip_address,
            expires_at=expires_at
        )
        db.session.add(lease)
    if commit:
        db.session.commit()


def clear_unregistered_lease(mac_address):
    if not mac_address:
        return
    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    if lease:
        db.session.delete(lease)
        db.session.commit()


def _get_iptables_base_cmd():
    if os.geteuid() == 0:
        return ["iptables"]
    if shutil.which("sudo"):
        return ["sudo", "iptables"]
    return ["iptables"]


def _is_blocked_pool_ip(ip_address):
    if not ip_address:
        return False
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return False

    prefix_by_id = _get_vlan_prefix_by_id()
    for vlan_id, prefix in prefix_by_id.items():
        try:
            network = ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{prefix}", strict=False)
        except Exception:
            continue
        if ip not in network:
            continue
        _, _, blocked_start, blocked_end = _pool_bounds_for_prefix(prefix)
        offset = int(ip) - int(network.network_address)
        return blocked_start <= offset <= blocked_end

    return False


def cleanup_orphan_hijack_rules():
    """Remove DNS/portal DNAT rules for IPs not assigned to any device."""
    try:
        active_ips = {
            d.ip_address
            for d in Device.query.filter(Device.ip_address.isnot(None)).all()
            if d.ip_address
        }
        now = datetime.utcnow()
        active_unregistered_ips = {
            lease.ip_address
            for lease in UnregisteredLease.query.filter(UnregisteredLease.ip_address.isnot(None)).all()
            if lease.ip_address and (not lease.expires_at or lease.expires_at >= now)
        }
        active_ips |= active_unregistered_ips
    except Exception as e:
        logger.error(f"Failed to load device IPs for cleanup: {e}")
        return 0

    base_cmd = _get_iptables_base_cmd()
    result = subprocess.run(
        base_cmd + ["-t", "nat", "-S", "PREROUTING"],
        capture_output=True,
        text=True,
        timeout=15
    )
    if result.returncode != 0:
        logger.error(f"Failed to read iptables rules: {result.stderr.strip()}")
        return 0

    removed = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING"):
            continue
        if "DNAT" not in line:
            continue
        if (
            "--to-destination 192.168.99.5:53" not in line
            and "--to-destination 192.168.99.4:8080" not in line
        ):
            continue

        match = re.search(r"-s (\d+\.\d+\.\d+\.\d+)/32", line)
        if not match:
            continue

        ip_address = match.group(1)
        if ip_address in active_ips:
            continue
        if _is_blocked_pool_ip(ip_address):
            continue

        delete_parts = shlex.split(line)
        delete_parts[0] = "-D"
        delete_cmd = base_cmd + ["-t", "nat"] + delete_parts
        delete_result = subprocess.run(
            delete_cmd,
            capture_output=True,
            text=True,
            timeout=15
        )
        if delete_result.returncode == 0:
            removed += 1
            logger.info(f"Removed orphan DNAT rule for {ip_address}")
        else:
            logger.warning(
                "Failed to remove orphan DNAT rule for %s: %s",
                ip_address,
                delete_result.stderr.strip()
            )

    return removed


def manage_switch_acl(action, ip_address, vlan_id):
    """
    Manage HP5130 ACL rules for blocking/unblocking specific IPs using SSH.
    
    Args:
        action: 'block' to deny traffic, 'unblock' to remove deny rule
        ip_address: Device IP address to block/unblock
        vlan_id: VLAN ID (e.g., 10)
        
    Returns:
        bool: True if successful, False otherwise
    """
    acl_script = os.getenv('ACL_QUEUE_SCRIPT', '/scripts/hp5130-acl.sh')
    use_acl_script = os.getenv('USE_ACL_QUEUE', '1') != '0'

    if use_acl_script and os.path.isfile(acl_script):
        try:
            result = subprocess.run(
                [acl_script, action, ip_address],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                logger.info("ACL %s queued for %s via %s", action, ip_address, acl_script)
                return True
            logger.warning(
                "ACL queue script failed for %s: %s",
                ip_address,
                (result.stderr or result.stdout).strip()
            )
        except Exception as exc:
            logger.warning("ACL queue script error for %s: %s", ip_address, exc)

    # Fallback: apply ACL directly via SSH
    switch_host = os.getenv('SWITCH_HOST', '192.168.99.2')

    if not vlan_id and ip_address:
        try:
            vlan_id = int(ip_address.split('.')[2])
        except (IndexError, ValueError):
            vlan_id = None

    if not vlan_id:
        logger.error("Unable to determine VLAN ID for ACL update")
        return False

    acl_num = 3000 + (vlan_id * 10)
    try:
        host_octet = int(ip_address.split('.')[3])
    except (IndexError, ValueError):
        logger.error("Unable to determine host octet for ACL rule")
        return False

    rule_num = 1000 + host_octet

    if action == 'block':
        logger.info(f"Adding ACL deny rule for {ip_address} on VLAN {vlan_id} via SSH")
        commands = [
            "system-view",
            f"acl advanced {acl_num}",
            f"rule {rule_num} deny ip source {ip_address} 0",
            "quit", "quit", "save force"
        ]
    elif action == 'unblock':
        logger.info(f"Removing ACL deny rule for {ip_address} on VLAN {vlan_id} via SSH")
        commands = [
            "system-view",
            f"acl advanced {acl_num}",
            f"undo rule {rule_num}",
            "quit", "quit", "save force"
        ]
    else:
        logger.error(f"Invalid action: {action}")
        return False

    try:
        output = _run_switch_command(switch_host, '\n'.join(commands))
        if output is not None:
            if output:
                logger.debug(f"SSH ACL output: {output}")
            logger.info(f"ACL {action} successful for {ip_address} on VLAN {vlan_id} via SSH")
            return True
        logger.error(f"Switch ACL {action} failed for {ip_address}: no response")
        return False
    except Exception as e:
        logger.error(f"Switch ACL {action} failed for {ip_address}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def _normalize_switch_mac(mac_address):
    if not mac_address:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(mac_address))
    if len(cleaned) != 12:
        return None
    return '-'.join(cleaned[i:i + 2] for i in range(0, 12, 2)).upper()


def _expand_switch_iface_name(iface):
    if iface.startswith('GE') and not iface.startswith('GigabitEthernet'):
        return f"GigabitEthernet{iface[2:]}"
    if iface.startswith('XGE') and not iface.startswith('Ten-GigabitEthernet'):
        return f"Ten-GigabitEthernet{iface[3:]}"
    return iface


def _switch_port_allowed(iface):
    deny_pattern = os.getenv('SWITCH_REPLUG_DENY_PATTERN', '').strip()
    if deny_pattern and re.search(deny_pattern, iface):
        return False
    allowed_raw = os.getenv('SWITCH_REPLUG_ALLOWED_PREFIXES', 'GigabitEthernet,GE')
    allowed = [entry.strip() for entry in allowed_raw.split(',') if entry.strip()]
    if not allowed:
        return True
    return any(iface.startswith(prefix) for prefix in allowed)


def _get_switch_ssh_client():
    """Retained for backward compat; returns a host string instead of a paramiko client.
    All callers have been updated to use _run_switch_command() directly."""
    return os.getenv('SWITCH_HOST', '192.168.99.2')


def _find_switch_port_for_mac(client_or_host, mac_address):
    """Find which physical switch port a MAC is on.
    client_or_host is either the SWITCH_HOST string or legacy paramiko client (ignored).
    Uses _run_switch_command via subprocess ssh, matching hp5130-port-lookup.sh behaviour.
    """
    switch_host = os.getenv('SWITCH_HOST', '192.168.99.2')

    normalized = _normalize_switch_mac(mac_address)
    if not normalized:
        return None

    iface_pattern = re.compile(
        r"\b(?P<iface>(?:GigabitEthernet|Ten-GigabitEthernet|GE|XGE|Ethernet|Bridge-Aggregation)\S+)\b",
        re.IGNORECASE
    )

    for command in [
        f"display mac-address | include {normalized}",
        f"display mac-address dynamic | include {normalized}",
    ]:
        output = _run_switch_command(switch_host, command)
        if not output:
            continue
        for line in output.splitlines():
            if normalized not in line.upper():
                continue
            match = iface_pattern.search(line)
            if match:
                return _expand_switch_iface_name(match.group('iface'))

    return None


def _persist_switch_port(mac_address, iface):
    """Persist a confirmed switch port->MAC mapping at registration time.
    Updates both mac_port_cache (all devices) and devices.switch_iface."""
    if not mac_address or not iface:
        return
    try:
        switch_host = os.getenv('SWITCH_HOST', '')
        db.session.execute(
            text("""
                INSERT INTO mac_port_cache (mac_address, switch_iface, switch_host, last_seen)
                VALUES (:mac, :iface, :host, NOW())
                ON CONFLICT (mac_address) DO UPDATE SET
                    switch_iface = EXCLUDED.switch_iface,
                    switch_host  = EXCLUDED.switch_host,
                    last_seen    = EXCLUDED.last_seen
            """),
            {"mac": mac_address, "iface": iface, "host": switch_host},
        )
        db.session.execute(
            text("""
                UPDATE devices
                SET switch_iface = :iface,
                    switch_iface_seen_at = NOW()
                WHERE mac_address = :mac
            """),
            {"iface": iface, "mac": mac_address},
        )
        db.session.commit()
        logger.info("Cached switch port %s for %s", iface, mac_address)
    except Exception as exc:
        logger.warning("Failed to persist switch port for %s: %s", mac_address, exc)
        try:
            db.session.rollback()
        except Exception:
            pass


def replug_switch_port_for_mac(mac_address):
    if not _env_truthy('SWITCH_REPLUG_ENABLED', False):
        logger.info("Switch replug disabled; skipping for %s", mac_address)
        return False

    replug_script = os.getenv('SWITCH_REPLUG_SCRIPT', '/scripts/hp5130-replug.sh')
    logger.info("Switch replug requested for %s using script=%s", mac_address, replug_script)
    if os.path.isfile(replug_script):
        try:
            delay = os.getenv('SWITCH_REPLUG_DELAY_SEC', '3')
            result = subprocess.run(
                [replug_script, mac_address, delay],
                capture_output=True,
                text=True,
                timeout=30,
            )
            logger.info(
                "Replug script finished for %s status=%s",
                mac_address,
                result.returncode,
            )
            if result.returncode == 0:
                logger.info("Replug script succeeded for %s", mac_address)
                return True
            logger.warning(
                "Replug script failed for %s: %s",
                mac_address,
                (result.stderr or result.stdout).strip(),
            )
        except Exception as exc:
            logger.warning("Replug script error for %s: %s", mac_address, exc)

    client = _get_switch_ssh_client()
    if not client:
        return False

    try:
        port = _find_switch_port_for_mac(client, mac_address)
        if not port:
            logger.warning("Unable to locate switch port for %s", mac_address)
            return False
        if not _switch_port_allowed(port):
            logger.warning("Switch replug blocked for port %s", port)
            return False

        _persist_switch_port(mac_address, port)

        logger.info("Replugging %s on port %s", mac_address, port)
        switch_host = os.getenv('SWITCH_HOST', '192.168.99.2')
        delay_raw = os.getenv('SWITCH_REPLUG_DELAY_SEC', '3')
        try:
            delay_sec = max(1, int(delay_raw))
        except ValueError:
            delay_sec = 3

        cmds_down = f"system-view\ninterface {port}\nshutdown\nquit\nquit"
        cmds_up   = f"system-view\ninterface {port}\nundo shutdown\nquit\nquit"

        _run_switch_command(switch_host, cmds_down)
        time.sleep(delay_sec)
        _run_switch_command(switch_host, cmds_up)
        logger.info("Replug complete for %s on port %s", mac_address, port)
        return True
    except Exception as exc:
        logger.error("Switch replug failed for %s: %s", mac_address, exc)
        return False


def apply_device_block(device, flash_messages=False):
    """Block a device (DB status, Kea, ACL, DNS hijack)."""
    device.registration_status = 'blocked'
    db.session.commit()
    clear_unregistered_lease(device.mac_address)

    kea = get_kea()
    if kea and device.current_vlan:
        kea.set_block_status(device.mac_address, device.current_vlan, True, blocked_ip=device.ip_address)
        if device.ip_address:
            kea.force_lease_renewal(device.mac_address, device.ip_address)
        new_ip = kea.get_lease_ip_for_mac(device.mac_address, subnet_id=device.current_vlan)
        if new_ip and new_ip != device.ip_address:
            device.ip_address = new_ip
            db.session.commit()

    latest_ip = get_ip_for_mac(device.mac_address, subnet_id=device.current_vlan)
    if latest_ip and latest_ip != device.ip_address:
        device.ip_address = latest_ip
        db.session.commit()

    if device.ip_address and device.current_vlan:
        acl_success = manage_switch_acl('block', device.ip_address, device.current_vlan)
        if _should_hijack_vlan(device.current_vlan):
            manage_dns_hijack('hijack', device.ip_address)
        if flash_messages:
            if acl_success:
                flash(f'Device {device.mac_address} blocked. Internet access denied.', 'success')
            else:
                flash(f'Device {device.mac_address} marked as blocked, but ACL update failed.', 'warning')
        logger.info(f"Blocked device {device.mac_address} at {device.ip_address} (acl_success={acl_success})")
    else:
        if flash_messages:
            flash(f'Device {device.mac_address} marked as blocked, but no IP/VLAN found.', 'warning')
        logger.warning(f"No IP/VLAN for device {device.mac_address}, cannot apply ACL")

    cleanup_orphan_hijack_rules()


def apply_device_unblock(device, flash_messages=False):
    """Unblock a device (DB status, Kea, ACL, DNS hijack)."""
    device.registration_status = 'registered'
    db.session.commit()
    clear_unregistered_lease(device.mac_address)

    kea = get_kea()
    blocked_ip = None
    if kea and device.current_vlan:
        blocked_ip = kea.get_blocked_ip_from_reservation(device.mac_address, device.current_vlan)
        kea.set_block_status(device.mac_address, device.current_vlan, False)
        new_ip = kea.get_lease_ip_for_mac(device.mac_address, subnet_id=device.current_vlan)
        if new_ip and new_ip != device.ip_address:
            device.ip_address = new_ip
            db.session.commit()

    latest_ip = get_ip_for_mac(device.mac_address, subnet_id=device.current_vlan)
    if latest_ip and latest_ip != device.ip_address:
        device.ip_address = latest_ip
        db.session.commit()

    if device.ip_address and device.current_vlan:
        acl_success = manage_switch_acl('unblock', device.ip_address, device.current_vlan)
        if _should_hijack_vlan(device.current_vlan):
            manage_dns_hijack('unhijack', device.ip_address)
        if blocked_ip and blocked_ip != device.ip_address:
            manage_switch_acl('unblock', blocked_ip, device.current_vlan)
            if _should_hijack_vlan(device.current_vlan):
                manage_dns_hijack('unhijack', blocked_ip)

        if flash_messages:
            if acl_success:
                flash(f'Device {device.mac_address} unblocked. Internet access restored.', 'success')
            else:
                flash(f'Device {device.mac_address} marked as registered, but ACL removal failed.', 'warning')
        logger.info(f"Unblocked device {device.mac_address} at {device.ip_address} (acl_success={acl_success})")
    else:
        if flash_messages:
            flash(f'Device {device.mac_address} marked as registered, but no IP/VLAN found.', 'warning')
        logger.warning(f"No IP/VLAN for device {device.mac_address}")

    cleanup_orphan_hijack_rules()


@app.route('/', methods=['GET', 'POST', 'OPTIONS'])
def index():
    origin = request.headers.get('Origin', '')  # Get the request's Origin
    
    
    # Optional: Validate against a whitelist (add expected origins)
    allowed_origins = [
        'http://www.msftconnecttest.com',
        'http://connectivitycheck.gstatic.com',
        'http://captive.apple.com',
        # Add others as needed
    ]
    if origin and origin not in allowed_origins:
        origin = ''  # Deny if not allowed; fallback to no ACAO or '*'
    
    if request.method == 'OPTIONS':
        response = app.make_response('')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'  # Fallback
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'
        return response, 200

    """Landing page - check if device is blocked, otherwise redirect to registration"""
    ip_address = request.remote_addr
    mac_address = get_client_mac()
    
    # Check if device is blocked
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device and device.registration_status == 'blocked':
            return redirect(_build_portal_url(url_for('blocked_page')))

        if device and device.registration_status == 'registered' and device.user:
            if not device.user.require_approval_every_device:
                return redirect(_build_portal_url(url_for('adopt_devices')))
    
    return redirect(_build_portal_url(url_for('register')))


@app.route('/blocked', methods=['GET', 'POST', 'OPTIONS'])
def blocked_page():
    origin = request.headers.get('Origin', '')  # Get the request's Origin
    
    
    # Optional: Validate against a whitelist (add expected origins)
    allowed_origins = [
        'http://www.msftconnecttest.com',
        'http://connectivitycheck.gstatic.com',
        'http://captive.apple.com',
        # Add others as needed
    ]
    if origin and origin not in allowed_origins:
        origin = ''  # Deny if not allowed; fallback to no ACAO or '*'
    
    if request.method == 'OPTIONS':
        response = app.make_response('')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'  # Fallback
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'
        return response, 200

    """Show blocked device page"""
    ip_address = get_client_ip()
    mac_address = get_client_mac()
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    
    if request.method == 'GET' and _portal_host_mismatch():
        return redirect(_build_portal_url(url_for('blocked_page')))

    return render_template('blocked.html', 
                         ip_address=ip_address,
                         mac_address=mac_address,
                         admin_email=admin_email)


# Captive portal detection endpoints
@app.route('/generate_204')
@app.route('/gen_204')
def android_captive_portal_detection():
    """Android captive portal detection - return 302 to show portal"""
    mac_address = get_client_mac()
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device and device.registration_status == 'blocked':
            return redirect(_build_portal_url(url_for('blocked_page'))), 302
    return redirect(_build_portal_url(url_for('register'))), 302


@app.route('/access-check')
def access_check():
    """Return 204 when a registered device should have full access."""
    user, device = _current_user_from_device()
    if user and device and device.registration_status == 'registered':
        return ('', 204)
    return ('', 409)

@app.route('/hotspot-detect.html')
def ios_captive_portal_detection():
    """iOS captive portal detection - MUST NOT return Success or iOS won't show portal"""
    mac_address = get_client_mac()
    
    # Check if device is already registered
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device and device.registration_status == 'registered':
            return redirect(_build_portal_url(url_for('status'))), 302
        elif device and device.registration_status == 'blocked':
            # Device is blocked - show blocked page
            return redirect(_build_portal_url(url_for('blocked_page'))), 302
    
    # Device not registered - redirect to portal (triggers iOS captive portal UI)
    return redirect(_build_portal_url(url_for('register'))), 302

@app.route('/library/test/success.html')
def ios_captive_success():
    """iOS success check after authentication"""
    return redirect(_build_portal_url(url_for('status'))), 302

@app.route('/ncsi.txt')
@app.route('/connecttest.txt')
@app.route('/redirect', methods=['GET', 'POST', 'OPTIONS'])
def windows_captive_portal_detection():
    origin = request.headers.get('Origin', '')  # Get the request's Origin

    
    
    # Optional: Validate against a whitelist (add expected origins)
    allowed_origins = [
        'http://www.msftconnecttest.com',
        'http://connectivitycheck.gstatic.com',
        'http://captive.apple.com',
        # Add others as needed
    ]
    if origin and origin not in allowed_origins:
        origin = ''  # Deny if not allowed; fallback to no ACAO or '*'
    
    if request.method == 'OPTIONS':
        response = app.make_response('')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'  # Fallback
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'
        return response, 200

    """Windows captive portal detection"""
    mac_address = get_client_mac()
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device and device.registration_status == 'blocked':
            return redirect(_build_portal_url(url_for('blocked_page'))), 302
    return redirect(_build_portal_url(url_for('register'))), 302


@app.route('/portal')

@app.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def register():
    if request.method == 'GET' and _portal_host_mismatch():
        qs = request.query_string.decode('utf-8', errors='ignore')
        target = _build_portal_url(url_for('register'))
        if qs:
            target = f"{target}?{qs}"
        return redirect(target)

    logger.info("Test message")
    logger.warning(f"Full headers: {request.headers}")
    origin = request.headers.get('Origin', '')  # Get the request's Origin
    
    
    # Optional: Validate against a whitelist (add expected origins)
    allowed_origins = [
        'http://www.msftconnecttest.com',
        'http://connectivitycheck.gstatic.com',
        'http://captive.apple.com',
        # Add others as needed
    ]
    if origin and origin not in allowed_origins:
        origin = ''  # Deny if not allowed; fallback to no ACAO or '*'
    
    if request.method == 'OPTIONS':
        response = app.make_response('')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'  # Fallback
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'
        return response, 200
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    detected_mac = mac_address
    detected_ip = ip_address
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    prefill = _build_prefill_from_request()  # Use your existing function for GET prefill
    current_connection, current_vlan, current_ssid = detect_connection_type(ip_address)
    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
    is_wired_unregistered = bool(current_connection == 'wired' and current_vlan == wired_unregistered_vlan)
    wired_vlan_options = [
        {
            'vlan_id': entry.vlan_id,
            'label': _label_for_vlan(entry.vlan_id, get_vlan_map()),
        }
        for entry in _get_wired_assignable_entries()
    ]

    if request.method == 'GET' and mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        device = normalize_device_status(device)
        if device and device.registration_status == 'registered' and device.user:
            if device.user.is_active and not device.user.blocked:
                vlan_map = get_vlan_map()
                access_label = _label_for_vlan(device.current_vlan, vlan_map) or 'network access'

                current_ip = detected_ip
                current_connection, current_vlan, _ = detect_connection_type(current_ip)
                network_mismatch = bool(
                    current_connection == 'wifi'
                    and current_vlan
                    and device.current_vlan
                    and current_vlan != device.current_vlan
                )

                if current_ip and not network_mismatch and not _is_blocked_pool_ip(current_ip):
                    if _should_hijack_vlan(current_vlan or device.current_vlan):
                        manage_dns_hijack('unhijack', current_ip)
                    if current_vlan or device.current_vlan:
                        manage_switch_acl('unblock', current_ip, current_vlan or device.current_vlan)

                if current_connection == 'wifi' and device.current_vlan:
                    _cache_key = (device.mac_address, device.current_vlan)
                    _now = time.monotonic()
                    with _kea_reservation_check_lock:
                        _last = _kea_reservation_check_cache.get(_cache_key, 0)
                        _due = (_now - _last) >= KEA_RESERVATION_CHECK_TTL_SEC
                        if _due:
                            _kea_reservation_check_cache[_cache_key] = _now
                    if _due:
                        kea = get_kea()
                        if kea:
                            try:
                                reservation = kea.get_reservation(device.mac_address, device.current_vlan)
                                if not reservation:
                                    hostname = device.device_name or 'device'
                                    success = kea.register_mac(
                                        mac=device.mac_address,
                                        vlan=device.current_vlan,
                                        hostname=hostname,
                                        ip_address=None,
                                    )
                                    if success and current_ip:
                                        kea.force_lease_renewal(device.mac_address, current_ip)
                            except Exception as exc:
                                with _kea_reservation_check_lock:
                                    _kea_reservation_check_cache.pop(_cache_key, None)
                                logger.warning(
                                    "Kea reservation check failed for %s: %s",
                                    device.mac_address,
                                    exc,
                                )

                clear_unregistered_lease(device.mac_address)

                return render_template(
                    'register.html',
                    show_wait=True,
                    detected_mac=detected_mac,
                    detected_ip=detected_ip,
                    access_label=access_label,
                    device=device,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        first_name = request.form.get('first_name').strip()
        last_name = request.form.get('last_name').strip()
        phone_number = request.form.get('phone_number').strip()
        device_type = request.form.get('device_type').strip()
        wired_vlan_raw = (request.form.get('wired_vlan_id') or '').strip()
        wired_vlan_id = None
        if wired_vlan_raw:
            try:
                wired_vlan_id = int(wired_vlan_raw)
            except ValueError:
                wired_vlan_id = None

        # Validate required fields (your existing logic)
        if not all([email, first_name, last_name, device_type]):
            if is_ajax:
                return jsonify({'status': 'error', 'message': 'All required fields must be filled'})
            else:
                flash('All required fields must be filled', 'error')
                prefill = {
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'phone_number': phone_number,
                    'device_type': device_type
                }
                return render_template(
                    'register.html',
                    prefill=prefill,
                    detected_mac=detected_mac,
                    detected_ip=detected_ip,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

        if is_wired_unregistered:
            wired_assignable = _get_wired_assignable_vlan_ids()
            if not wired_vlan_id or wired_vlan_id not in wired_assignable:
                message = 'Please select a valid wired VLAN.'
                if is_ajax:
                    return jsonify({'status': 'error', 'message': message})
                flash(message, 'error')
                return render_template(
                    'register.html',
                    prefill=prefill,
                    detected_mac=detected_mac,
                    detected_ip=detected_ip,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

        # Check if user exists (your existing logic)
        user = User.query.filter_by(email=email).first()

        if user:
            # Existing user - register device immediately unless VLAN requires approval
            vlan_map = get_vlan_map()
            connection_type, detected_vlan, ssid = detect_connection_type(ip_address)
            wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
            is_wired_unregistered = bool(connection_type == 'wired' and detected_vlan == wired_unregistered_vlan)
            current_ssid = ssid or (get_ssid_for_vlan(detected_vlan) if detected_vlan else None)

            domain_policy_map = _load_domain_policy_map()
            allowed_vlans, _ = _get_effective_vlans_for_user(user, domain_policy_map)
            default_vlan = _default_vlan_for_user(allowed_vlans, vlan_map)

            vlan_allowed = bool(detected_vlan and detected_vlan in allowed_vlans)
            needs_approval = bool(user.require_approval_every_device)

            if is_wired_unregistered:
                target_vlan = wired_vlan_id if wired_vlan_id in allowed_vlans and not user.require_approval_every_device else None
                expected_ssid = None
                network_mismatch = False
                if not target_vlan:
                    needs_approval = True
            elif connection_type == 'wifi' and detected_vlan:
                if not allowed_vlans:
                    network_mismatch = False
                    expected_ssid = get_ssid_for_vlan(detected_vlan)
                    needs_approval = True
                    target_vlan = None
                else:
                    network_mismatch = not vlan_allowed
                    expected_ssid = get_ssid_for_vlan(detected_vlan if vlan_allowed else default_vlan)
                    if not vlan_allowed:
                        needs_approval = True
                    target_vlan = detected_vlan if vlan_allowed and not user.require_approval_every_device else None
            else:
                target_vlan = default_vlan if not user.require_approval_every_device else None
                expected_ssid = get_ssid_for_vlan(target_vlan) if target_vlan else None
                network_mismatch = False
                if not target_vlan:
                    needs_approval = True
            existing_device = Device.query.filter_by(mac_address=mac_address).first()
            previous_profile = {
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "phone_number": user.phone_number or ""
            }
            new_profile = {
                "first_name": first_name or user.first_name or "",
                "last_name": last_name or user.last_name or "",
                "phone_number": phone_number or user.phone_number or ""
            }
            profile_changed = previous_profile != new_profile
            if profile_changed:
                user.first_name = new_profile["first_name"] or None
                user.last_name = new_profile["last_name"] or None
                user.phone_number = new_profile["phone_number"] or None
            profile_snapshot = json.dumps({
                "previous": previous_profile,
                "new": new_profile
            }) if profile_changed else None

            # If the VLAN requires a network password and the user already has one set,
            # bypass the needs_approval flow so the password-check section handles it.
            # We save original_needs_approval so that after a correct password entry the
            # normal VLAN-based approval logic can still be applied (unless this is the
            # first use of a freshly admin-set password, which is always auto-approved).
            _pwd_check_vlan = target_vlan or detected_vlan
            original_needs_approval = needs_approval
            if needs_approval and _vlan_requires_password(_pwd_check_vlan) and user.has_network_password:
                needs_approval = False
                if not target_vlan:
                    target_vlan = _pwd_check_vlan  # ensure downstream code has a non-None VLAN

            if needs_approval:
                pending_request = (
                    RegistrationRequest.query.filter_by(
                        mac_address=mac_address,
                        email=email,
                        status='pending'
                    )
                    .order_by(RegistrationRequest.submitted_at.desc())
                    .first()
                )
                if pending_request:
                    pending_request.first_name = first_name
                    pending_request.last_name = last_name
                    pending_request.phone_number = phone_number
                    pending_request.device_type = device_type
                    pending_request.ip_address = ip_address
                    if is_wired_unregistered:
                        pending_request.requested_vlan = wired_vlan_id
                    pending_request.submitted_at = datetime.utcnow()
                    reg_request = pending_request
                else:
                    reg_request = RegistrationRequest(
                        mac_address=mac_address,
                        ip_address=ip_address,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        device_type=device_type,
                        requested_vlan=wired_vlan_id if is_wired_unregistered else None,
                        status='pending',
                        approval_token=secrets.token_urlsafe(32)
                    )
                    db.session.add(reg_request)

                domain_policy = _load_domain_policy_map().get(_email_domain(user.email))
                allowed_items = _allowed_vlans_display_items(user, vlan_map, domain_policy)
                note_parts = [
                    f"Existing user allowed VLANs: {_format_vlan_items_text(allowed_items) or 'none'}",
                    f"Detected VLAN: {detected_vlan}",
                    f"Detected SSID: {current_ssid or 'unknown'}"
                ]
                if is_wired_unregistered and wired_vlan_id:
                    note_parts.append(f"Requested VLAN: {wired_vlan_id}")
                reg_request.notes = " | ".join(note_parts)

                if profile_changed:
                    user.first_name = new_profile["first_name"] or None
                    user.last_name = new_profile["last_name"] or None
                    user.phone_number = new_profile["phone_number"] or None
                db.session.commit()

                portal_url = os.getenv('PORTAL_URL')
                if portal_url:
                    parsed = urlparse(portal_url)
                    approval_url = f"{parsed.scheme}://{parsed.netloc}{url_for('admin_approve_request', token=reg_request.approval_token)}"
                else:
                    approval_url = url_for('admin_approve_request', token=reg_request.approval_token, _external=True)

                send_admin_notification(reg_request, approval_url, detected_vlan, current_ssid)

                if is_ajax:
                    return jsonify({
                        'status': 'pending',
                        'message': 'Registration request submitted for review.',
                        'prefill': {
                            'email': email,
                            'first_name': first_name,
                            'last_name': last_name,
                            'phone_number': phone_number,
                            'device_type': device_type
                        }
                    })
                return redirect(url_for('pending_approval'))

            # --- Network password check for password-required VLANs (existing user) ---
            vlan_pwd_required = _vlan_requires_password(target_vlan)
            if vlan_pwd_required:
                if not user.has_network_password:
                    # User has no password yet - needs admin to set one first
                    pending_pwd_request = (
                        RegistrationRequest.query.filter_by(
                            mac_address=mac_address,
                            email=email,
                            status='pending_password'
                        )
                        .order_by(RegistrationRequest.submitted_at.desc())
                        .first()
                    )
                    # Generate or refresh set-password token for the user
                    user.network_password_set_token = secrets.token_urlsafe(32)
                    user.network_password_set_token_expires = datetime.utcnow() + timedelta(hours=24)
                    if not pending_pwd_request:
                        pending_pwd_request = RegistrationRequest(
                            mac_address=mac_address,
                            ip_address=ip_address,
                            email=email,
                            first_name=first_name,
                            last_name=last_name,
                            phone_number=phone_number,
                            device_type=device_type,
                            requested_vlan=target_vlan,
                            status='pending_password',
                            approval_token=secrets.token_urlsafe(32)
                        )
                        db.session.add(pending_pwd_request)
                        db.session.commit()
                        portal_url = os.getenv('PORTAL_URL')
                        if portal_url:
                            parsed = urlparse(portal_url)
                            approval_url = f"{parsed.scheme}://{parsed.netloc}{url_for('admin_approve_request', token=pending_pwd_request.approval_token)}"
                        else:
                            approval_url = url_for('admin_approve_request', token=pending_pwd_request.approval_token, _external=True)
                        admin_set_pwd_url = _build_admin_set_password_url(pending_pwd_request.approval_token)
                        send_admin_password_setup_email(pending_pwd_request, admin_set_pwd_url, target_vlan, current_ssid)
                    else:
                        db.session.commit()
                    # Send the user an email with their set-password link
                    set_password_url = _build_set_password_url(user.network_password_set_token)
                    send_network_password_set_email(
                        user.email,
                        user.first_name or first_name or 'there',
                        set_password_url,
                        network_name=current_ssid or 'Wired Network',
                    )
                    if is_ajax:
                        return jsonify({
                            'status': 'pending_password',
                            'message': 'A network password is required to access this network. Please check your email for a link to set your password.'
                        })
                    return redirect(url_for('pending_approval'))
                else:
                    # User has a password - verify it before registering
                    network_password = (request.form.get('network_password') or '').strip()
                    if not network_password:
                        if is_ajax:
                            return jsonify({'status': 'password_required'})
                        return render_template(
                            'register.html',
                            prefill={
                                'email': email,
                                'first_name': first_name,
                                'last_name': last_name,
                                'phone_number': phone_number,
                                'device_type': device_type,
                            },
                            show_password_field=True,
                            detected_mac=detected_mac,
                            detected_ip=detected_ip,
                            wired_vlan_required=is_wired_unregistered,
                            wired_vlan_options=wired_vlan_options,
                        )
                    if not user.check_network_password(network_password):
                        if is_ajax:
                            return jsonify({'status': 'error', 'message': 'Incorrect network password. Please try again.'})
                        flash('Incorrect network password.', 'error')
                        return render_template(
                            'register.html',
                            prefill={
                                'email': email,
                                'first_name': first_name,
                                'last_name': last_name,
                                'phone_number': phone_number,
                                'device_type': device_type,
                            },
                            show_password_field=True,
                            detected_mac=detected_mac,
                            detected_ip=detected_ip,
                            wired_vlan_required=is_wired_unregistered,
                            wired_vlan_options=wired_vlan_options,
                        )
                    # Password correct.
                    # 'first_use': first device registered after an admin set the password –
                    # always auto-register regardless of VLAN rules, then clear the flag.
                    if user.network_password_approval_mode == 'first_use':
                        user.network_password_approval_mode = None
                        db.session.commit()
                        # fall through to registration below
                    elif original_needs_approval:
                        # Password correct, but normal VLAN rules say this user/VLAN still
                        # needs admin approval – send the standard approval email.
                        _admin_req = RegistrationRequest(
                            mac_address=mac_address,
                            ip_address=ip_address,
                            email=email,
                            first_name=first_name,
                            last_name=last_name,
                            phone_number=phone_number,
                            device_type=device_type,
                            requested_vlan=target_vlan,
                            status='pending',
                            approval_token=secrets.token_urlsafe(32),
                            notes='Password verified; awaiting admin approval'
                        )
                        db.session.add(_admin_req)
                        db.session.commit()
                        _portal_url = os.getenv('PORTAL_URL')
                        if _portal_url:
                            _parsed = urlparse(_portal_url)
                            _appr_url = f"{_parsed.scheme}://{_parsed.netloc}{url_for('admin_approve_request', token=_admin_req.approval_token)}"
                        else:
                            _appr_url = url_for('admin_approve_request', token=_admin_req.approval_token, _external=True)
                        send_admin_notification(_admin_req, _appr_url, detected_vlan, current_ssid)
                        # Close the pending_password request for this MAC now that the
                        # password has been verified and an admin-approval request raised.
                        RegistrationRequest.query.filter_by(
                            mac_address=mac_address, status='pending_password'
                        ).update(
                            {'status': 'approved', 'processed_at': datetime.utcnow(),
                             'processed_by': 'user-portal-verified'},
                            synchronize_session=False
                        )
                        db.session.commit()
                        if is_ajax:
                            return jsonify({
                                'status': 'pending',
                                'message': 'Password accepted. Your registration has been submitted for admin approval.',
                                'prefill': {'email': email, 'first_name': first_name, 'last_name': last_name,
                                            'phone_number': phone_number, 'device_type': device_type}
                            })
                        return redirect(url_for('pending_approval'))
                    # else: VLAN is auto-approved for this user – fall through to registration below

            if existing_device:
                existing_device.user_id = user.id
                existing_device.device_name = device_type
                existing_device.ip_address = ip_address
                existing_device.registration_status = 'registered'
                existing_device.current_vlan = target_vlan
                existing_device.connection_type = connection_type
                existing_device.ssid = ssid
                existing_device.is_wired = connection_type == 'wired'
                existing_device.wired_target_vlan = target_vlan if connection_type == 'wired' else None
                existing_device.unregister_token = existing_device.unregister_token or secrets.token_urlsafe(32)
                existing_device.profile_snapshot = profile_snapshot
                device = existing_device
            else:
                device = Device(
                    mac_address=mac_address,
                    user_id=user.id,
                    device_name=device_type,
                    ip_address=ip_address,
                    registration_status='registered',
                    current_vlan=target_vlan,
                    connection_type=connection_type,
                    ssid=ssid,
                    is_wired=connection_type == 'wired',
                    wired_target_vlan=target_vlan if connection_type == 'wired' else None,
                    unregister_token=secrets.token_urlsafe(32),
                    profile_snapshot=profile_snapshot
                )
                db.session.add(device)

            db.session.commit()

            # Close any pending_password request for this MAC – the user has now
            # verified their password on the portal and the device is being registered.
            RegistrationRequest.query.filter_by(
                mac_address=mac_address, status='pending_password'
            ).update(
                {'status': 'approved', 'processed_at': datetime.utcnow(),
                 'processed_by': 'user-portal-registered'},
                synchronize_session=False
            )
            db.session.commit()

            # Register in network (your existing logic)
            if connection_type == 'wifi':
                kea = get_kea()
                if kea:
                    kea.register_mac(mac=mac_address, vlan=target_vlan, hostname=f"{first_name.lower()}-{last_name.lower()}-{device_type}", ip_address=None)
                    if ip_address and not network_mismatch:
                        kea.force_lease_renewal(mac_address, ip_address)
            else:
                send_coa_change(mac_address, target_vlan)
                replug_switch_port_for_mac(mac_address)

            if ip_address and not network_mismatch and _should_hijack_vlan(target_vlan or detected_vlan):
                manage_dns_hijack('unhijack', ip_address)
            clear_unregistered_lease(mac_address)
            if ip_address and detected_vlan and not network_mismatch:
                manage_switch_acl('unblock', ip_address, detected_vlan)

            unregister_url = _build_unregister_url(device.unregister_token)
            confirm_url = None
            confirm_timeout_sec = None
            confirm_url, confirm_timeout_sec = _set_wifi_confirmation(device)

            ssid_display = ssid or "Wired Network"
            send_wifi_registration_confirmation(
                user.email,
                user.first_name or first_name,
                ssid_display,
                mac_address,
                unregister_url,
                confirm_url=confirm_url,
                confirm_timeout_sec=confirm_timeout_sec,
                registration_details={
                    "email": user.email,
                    "first_name": new_profile["first_name"],
                    "last_name": new_profile["last_name"],
                    "phone_number": new_profile["phone_number"],
                    "device_type": device_type,
                    "ip_address": ip_address,
                    "ssid": ssid_display
                }
            )


            if is_ajax:
                return jsonify({
                    'status': 'registered',
                    'message': 'Device registered successfully',
                    'current_vlan': detected_vlan,
                    'current_ssid': current_ssid,
                    'expected_vlan': target_vlan,
                    'expected_ssid': expected_ssid,
                    'network_mismatch': network_mismatch
                })
            else:
                return redirect(url_for('registered'))

        else:
            # New user - auto-approve if domain allows, otherwise create pending request
            vlan_map = get_vlan_map()
            connection_type, detected_vlan, ssid = detect_connection_type(ip_address)
            wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
            is_wired_unregistered = bool(connection_type == 'wired' and detected_vlan == wired_unregistered_vlan)
            domain_policy = _load_domain_policy_map().get(_email_domain(email))
            allowed_vlans = _parse_allowed_vlans(domain_policy.allowed_vlans) if domain_policy else set()
            default_vlan = _default_vlan_for_user(allowed_vlans, vlan_map)

            if is_wired_unregistered:
                vlan_allowed = bool(wired_vlan_id and wired_vlan_id in allowed_vlans)
                can_auto_approve = bool(allowed_vlans) and vlan_allowed
            else:
                vlan_allowed = bool(detected_vlan and detected_vlan in allowed_vlans)
                can_auto_approve = bool(allowed_vlans) and (
                    connection_type != 'wifi' or vlan_allowed
                )

            if can_auto_approve:
                if is_wired_unregistered:
                    target_vlan = wired_vlan_id
                else:
                    target_vlan = detected_vlan if connection_type == 'wifi' else default_vlan

                # Check if target VLAN requires a network password (new user, auto-approve domain)
                if _vlan_requires_password(target_vlan):
                    # Create the user now (domain policy allows them) but hold off on device
                    new_user = User(
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        begin_date=datetime.utcnow().date(),
                        notes='Auto-approved via domain policy – awaiting network password',
                        created_by='domain-policy',
                        network_password_set_token=secrets.token_urlsafe(32),
                        network_password_set_token_expires=datetime.utcnow() + timedelta(hours=24),
                    )
                    db.session.add(new_user)
                    db.session.flush()  # get new_user.id without committing
                    reg_request = RegistrationRequest(
                        mac_address=mac_address,
                        ip_address=ip_address,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        device_type=device_type,
                        requested_vlan=target_vlan,
                        status='pending_password',
                        approval_token=secrets.token_urlsafe(32)
                    )
                    db.session.add(reg_request)
                    db.session.commit()
                    # Send user the set-password email
                    set_password_url = _build_set_password_url(new_user.network_password_set_token)
                    send_network_password_set_email(
                        email,
                        first_name or 'there',
                        set_password_url,
                        network_name=ssid or 'Wired Network',
                    )
                    # Also notify admin with the set-password-for-user link
                    admin_set_pwd_url = _build_admin_set_password_url(reg_request.approval_token)
                    send_admin_password_setup_email(reg_request, admin_set_pwd_url, target_vlan, ssid)
                    if is_ajax:
                        return jsonify({
                            'status': 'pending_password',
                            'message': 'A network password is required to access this network. Please check your email for a link to set your password.'
                        })
                    return redirect(url_for('pending_approval'))

                user = User(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    phone_number=phone_number,
                    begin_date=datetime.utcnow().date(),
                    notes='Auto-approved via domain policy',
                    created_by='domain-policy'
                )
                db.session.add(user)
                db.session.flush()

                device = Device(
                    mac_address=mac_address,
                    user_id=user.id,
                    device_name=device_type,
                    ip_address=ip_address,
                    registration_status='registered',
                    current_vlan=target_vlan,
                    connection_type=connection_type,
                    ssid=ssid,
                    is_wired=connection_type == 'wired',
                    wired_target_vlan=target_vlan if connection_type == 'wired' else None,
                    unregister_token=secrets.token_urlsafe(32)
                )
                db.session.add(device)
                db.session.commit()

                if connection_type == 'wifi':
                    kea = get_kea()
                    if kea:
                        kea.register_mac(
                            mac=mac_address,
                            vlan=target_vlan,
                            hostname=f"{first_name.lower()}-{last_name.lower()}-{device_type}",
                            ip_address=None,
                        )
                        if ip_address:
                            kea.force_lease_renewal(mac_address, ip_address)
                else:
                    send_coa_change(mac_address, target_vlan)
                    replug_switch_port_for_mac(mac_address)

                if ip_address and _should_hijack_vlan(target_vlan or detected_vlan):
                    manage_dns_hijack('unhijack', ip_address)
                clear_unregistered_lease(mac_address)
                if ip_address and detected_vlan:
                    manage_switch_acl('unblock', ip_address, detected_vlan)

                unregister_url = _build_unregister_url(device.unregister_token)
                confirm_url = None
                confirm_timeout_sec = None
                confirm_url, confirm_timeout_sec = _set_wifi_confirmation(device)
                ssid_display = ssid or "Wired Network"
                send_wifi_registration_confirmation(
                    user.email,
                    user.first_name or first_name or "there",
                    ssid_display,
                    mac_address,
                    unregister_url,
                    confirm_url=confirm_url,
                    confirm_timeout_sec=confirm_timeout_sec,
                    registration_details={
                        "email": user.email,
                        "first_name": user.first_name or first_name,
                        "last_name": user.last_name or last_name,
                        "phone_number": user.phone_number or phone_number,
                        "device_type": device_type,
                        "ip_address": ip_address,
                        "ssid": ssid_display
                    }
                )

                if is_ajax:
                    return jsonify({
                        'status': 'registered',
                        'message': 'Device registered successfully',
                        'current_vlan': detected_vlan,
                        'current_ssid': ssid,
                        'expected_vlan': target_vlan,
                        'expected_ssid': get_ssid_for_vlan(target_vlan)
                    })
                return redirect(url_for('registered'))

            # If the VLAN this user needs requires a network password, flag as pending_password
            # This applies even when admin approval is required (not just auto-approve domains)
            _vlan_for_pw_check = wired_vlan_id if is_wired_unregistered else detected_vlan
            _request_needs_password = bool(_vlan_for_pw_check and _vlan_requires_password(_vlan_for_pw_check))
            _request_status = 'pending_password' if _request_needs_password else 'pending'

            reg_request = RegistrationRequest(
                mac_address=mac_address,
                ip_address=ip_address,
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                device_type=device_type,
                requested_vlan=wired_vlan_id if is_wired_unregistered else (detected_vlan if _request_needs_password else None),
                status=_request_status,
                approval_token=secrets.token_urlsafe(32)
            )
            db.session.add(reg_request)
            db.session.commit()
            portal_url = os.getenv('PORTAL_URL')
            if portal_url:
                parsed = urlparse(portal_url)
                approval_url = f"{parsed.scheme}://{parsed.netloc}{url_for('admin_approve_request', token=reg_request.approval_token)}"
            else:
                approval_url = url_for('admin_approve_request', token=reg_request.approval_token, _external=True)

            prefill_data = {
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'phone_number': phone_number,
                'device_type': device_type
            }

            if _request_needs_password:
                admin_set_pwd_url = _build_admin_set_password_url(reg_request.approval_token)
                send_admin_password_setup_email(reg_request, admin_set_pwd_url, detected_vlan, ssid)
                # Also send the registering user a direct set-password email so they don't
                # need to wait for an admin action before they can set their own password.
                from models import User as _RegUser
                _pwd_user = _RegUser.query.filter_by(email=email).first()
                if not _pwd_user:
                    _pwd_user = _RegUser(
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        begin_date=datetime.utcnow().date(),
                        notes='Created via pending_password registration',
                        created_by='registration',
                    )
                    db.session.add(_pwd_user)
                    db.session.flush()
                _pwd_user.network_password_set_token = secrets.token_urlsafe(32)
                _pwd_user.network_password_set_token_expires = datetime.utcnow() + timedelta(hours=24)
                db.session.commit()
                send_network_password_set_email(
                    email,
                    first_name or 'there',
                    _build_set_password_url(_pwd_user.network_password_set_token),
                    network_name=ssid or 'Wired Network',
                )
            else:
                send_admin_notification(reg_request, approval_url, detected_vlan, ssid)

            if is_ajax:
                if _request_needs_password:
                    return jsonify({
                        'status': 'pending_password',
                        'message': 'This network requires a network password. '
                                   'An administrator has been notified and will be in touch to help get you set up.',
                    })
                return jsonify({
                    'status': 'pending',
                    'message': 'Registration request submitted. Waiting for approval...',
                    'prefill': prefill_data
                })
            else:
                return redirect(url_for('pending_approval'))

    # GET request (your existing logic)
    return render_template(
        'register.html',
        prefill=prefill,
        detected_mac=detected_mac,
        detected_ip=detected_ip,
        wired_vlan_required=is_wired_unregistered,
        wired_vlan_options=wired_vlan_options,
    )

@app.route('/verify')
def verify():
    """Email verification endpoint"""
    token = request.args.get('token')
    
    if not token:
        flash('Invalid verification link', 'error')
        return redirect(url_for('register'))
    
    device = Device.query.filter_by(verification_token=token).first()
    
    if not device:
        flash('Invalid or expired verification token', 'error')
        return redirect(url_for('register'))
    
    if device.verification_expires_at < datetime.now():
        # Token expired - move to restricted VLAN
        vlan_map = get_vlan_map()
        device.registration_status = 'blocked'
        device.current_vlan = vlan_map['restricted']
        db.session.commit()
        
        send_coa_change(device.mac_address, vlan_map['restricted'])
        
        flash('Verification link has expired. Your device has been blocked. Please contact the administrator.', 'error')
        return redirect(url_for('status'))
    
    # Verification successful
    user = device.user
    if user:
        vlan_map = get_vlan_map()
        allowed_vlans, _ = _get_effective_vlans_for_user(user)
        target_vlan = _default_vlan_for_user(allowed_vlans, vlan_map) or device.current_vlan
        device.registration_status = 'registered'
        device.current_vlan = target_vlan
        device.verification_token = None
        device.verification_expires_at = None
        db.session.commit()
        
        # Send RADIUS CoA
        success = send_coa_change(device.mac_address, target_vlan)
        
        if success:
            access_label = _label_for_vlan(target_vlan, vlan_map) or 'network access'
            flash(f'Email verified! You now have {access_label}.', 'success')
            logger.info(
                "Device %s verified and moved to VLAN %s",
                device.mac_address,
                target_vlan,
            )
        else:
            flash('Verification successful, but there was an issue updating network access. Please contact support.', 'warning')

        clear_unregistered_lease(device.mac_address)
    
    return redirect(url_for('status'))


@app.route('/status')
def status():
    """Show registration status"""
    mac_address = get_client_mac()
    
    if not mac_address:
        return render_template('status.html', device=None)
    
    device = Device.query.filter_by(mac_address=mac_address).first()
    device = normalize_device_status(device)
    access_label = None
    if device:
        vlan_map = get_vlan_map()
        access_label = _label_for_vlan(device.current_vlan, vlan_map) or 'Guest'
    return render_template('status.html', device=device, access_label=access_label)


def _format_age_delta(delta):
    if not delta:
        return ''
    total_seconds = int(delta.total_seconds())
    if total_seconds < 0:
        total_seconds = 0
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    if days:
        return f"{days}d {hours}h"
    return f"{hours}h"


def _log_kea_host_reservation(mac_address, vlan_id, label):
    if not mac_address or not vlan_id:
        return
    try:
        row = db.session.execute(
            text(
                "SELECT ipv4_address, host(inet '0.0.0.0' + ipv4_address) AS ip "
                "FROM hosts "
                "WHERE dhcp4_subnet_id = :subnet_id "
                "AND dhcp_identifier = decode(replace(:mac, ':', ''), 'hex')"
            ),
            {"subnet_id": vlan_id, "mac": mac_address},
        ).fetchone()
        if row:
            logger.info(
                "Kea hosts table %s for %s vlan %s: ipv4_address=%s ip=%s",
                label,
                mac_address,
                vlan_id,
                row.ipv4_address,
                row.ip,
            )
        else:
            logger.info(
                "Kea hosts table %s for %s vlan %s: no row",
                label,
                mac_address,
                vlan_id,
            )
    except Exception as exc:
        logger.warning(
            "Kea hosts table check failed for %s vlan %s: %s",
            mac_address,
            vlan_id,
            exc,
        )


def _is_registered_pool_ip(ip_address, vlan_id):
    if not ip_address or not vlan_id:
        return False
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except Exception:
        return False

    if int(vlan_id) == 99:
        return False

    prefix_by_id = _get_vlan_prefix_by_id()
    prefix = prefix_by_id.get(int(vlan_id), 24)
    try:
        network = ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{prefix}", strict=False)
    except Exception:
        return False
    if ip not in network:
        return False

    registered_start, registered_end, _, _ = _pool_bounds_for_prefix(prefix)
    offset = int(ip) - int(network.network_address)
    return registered_start <= offset <= registered_end


@app.route('/adopt')
def adopt_devices():
    user, device = _current_user_from_device()
    if not user:
        return render_template(
            'adopt_devices.html',
            user=None,
            devices=[],
            registered_devices=[],
            target_vlan_options=[],
            wired_unregistered_vlan=_get_wired_unregistered_vlan_id(),
            error='registered_device',
        )

    if user.require_approval_every_device:
        return render_template(
            'adopt_devices.html',
            user=user,
            devices=[],
            registered_devices=[],
            target_vlan_options=[],
            wired_unregistered_vlan=_get_wired_unregistered_vlan_id(),
            error='approval_required',
        )

    vlan_map = get_vlan_map()
    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()

    _, effective_adoptable = _get_effective_vlans_for_user(user)
    allowed_vlans = sorted(effective_adoptable)
    target_vlan_ids = [vlan_id for vlan_id in allowed_vlans if vlan_id != wired_unregistered_vlan]
    target_vlan_options = [
        {
            'vlan_id': vlan_id,
            'label': _label_for_vlan(vlan_id, vlan_map),
        }
        for vlan_id in sorted(target_vlan_ids)
    ]
    if not allowed_vlans:
        return render_template(
            'adopt_devices.html',
            user=user,
            devices=[],
            registered_devices=[],
            target_vlan_options=[],
            wired_unregistered_vlan=_get_wired_unregistered_vlan_id(),
            error='no_permissions',
        )

    candidates = _load_adoptable_leases(set(allowed_vlans))

    registered_devices = Device.query.filter_by(
        user_id=user.id,
        registration_status='registered',
    ).order_by(Device.device_name.asc(), Device.mac_address.asc()).all()

    registered_device_rows = []
    for entry in registered_devices:
        registered_device_rows.append({
            'device_name': entry.device_name,
            'mac_address': entry.mac_address,
            'ip_address': entry.ip_address,
            'vlan_id': entry.current_vlan,
            'vlan_label': _label_for_vlan(entry.current_vlan, vlan_map),
            'connection_type': entry.connection_type,
            'device_id': entry.id,
        })

    if not candidates:
        current_ssid = device.ssid or get_ssid_for_vlan(device.current_vlan) or 'current network'
        adoptable_ssids = [
            get_ssid_for_vlan(vlan_id) or f"VLAN {vlan_id}"
            for vlan_id in allowed_vlans
        ]
        adoptable_ssids_display = ', '.join(adoptable_ssids) if adoptable_ssids else 'your adoptable networks'
        return render_template(
            'adopt_devices.html',
            user=user,
            devices=[],
            registered_devices=registered_device_rows,
            target_vlan_options=target_vlan_options,
            wired_unregistered_vlan=wired_unregistered_vlan,
            error='no_devices',
            current_ssid=current_ssid,
            adoptable_ssids=adoptable_ssids_display,
        )

    adoptable_devices = []
    for entry in candidates:
        existing = Device.query.filter_by(
            mac_address=entry['mac_address'],
            registration_status='registered',
        ).first()
        if existing:
            continue

        first_seen = entry['first_seen']
        last_seen = entry['last_seen']
        age = _format_age_delta(datetime.utcnow() - first_seen) if first_seen else ''

        if entry.get('ip_address') and entry.get('vlan_id'):
            manage_switch_acl('block', entry['ip_address'], entry['vlan_id'])

        adoptable_devices.append({
            'mac_address': entry['mac_address'],
            'ip_address': entry['ip_address'],
            'vlan_id': entry['vlan_id'],
            'first_seen': first_seen,
            'last_seen': last_seen,
            'age': age,
            'requires_target_vlan': entry['vlan_id'] == wired_unregistered_vlan,
            'target_vlan_options': target_vlan_options,
        })

    for item in adoptable_devices:
        item['vlan_label'] = _label_for_vlan(item['vlan_id'], vlan_map)

    return render_template(
        'adopt_devices.html',
        user=user,
        devices=adoptable_devices,
        registered_devices=registered_device_rows,
        target_vlan_options=target_vlan_options,
        wired_unregistered_vlan=wired_unregistered_vlan,
        error=None,
    )


@app.route('/adopt', methods=['POST'])
def adopt_device():
    user, device = _current_user_from_device()
    if not user:
        flash('Please connect from a registered device to adopt devices.', 'error')
        return redirect(url_for('adopt_devices'))

    mac_address = (request.form.get('mac_address') or '').strip().lower()
    vlan_id_raw = (request.form.get('vlan_id') or '').strip()
    target_vlan_raw = (request.form.get('target_vlan') or '').strip()
    device_type_raw = (request.form.get('device_type') or '').strip()
    device_type_other = (request.form.get('device_type_other') or '').strip()
    fixed_ip_requested = (request.form.get('fixed_ip') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
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
                return redirect(url_for('adopt_devices'))
            device_label = device_type_other
        else:
            device_label = device_type_raw
    device_label = re.sub(r'\s+', ' ', device_label).strip()
    if len(device_label) > 100:
        device_label = device_label[:100]

    if not mac_address or not vlan_id:
        flash('Missing device details for adoption.', 'error')
        return redirect(url_for('adopt_devices'))

    _, effective_adoptable = _get_effective_vlans_for_user(user)
    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
    if vlan_id not in effective_adoptable:
        flash('You do not have permission to adopt devices on that VLAN.', 'error')
        return redirect(url_for('adopt_devices'))

    if vlan_id == wired_unregistered_vlan:
        if not target_vlan:
            flash('Please select a VLAN for the wired device.', 'error')
            return redirect(url_for('adopt_devices'))
        if target_vlan not in effective_adoptable:
            flash('You do not have permission to assign that VLAN.', 'error')
            return redirect(url_for('adopt_devices'))
    else:
        target_vlan = vlan_id

    if user.require_approval_every_device:
        pending_request = RegistrationRequest(
            mac_address=mac_address,
            ip_address=None,
            email=user.email,
            first_name=user.first_name or '',
            last_name=user.last_name or '',
            phone_number=user.phone_number or '',
            device_type=device_label or 'adopted-device',
            status='pending',
            approval_token=secrets.token_urlsafe(32)
        )
        db.session.add(pending_request)
        db.session.commit()

        current_ssid = get_ssid_for_vlan(vlan_id)
        portal_url = os.getenv('PORTAL_URL')
        if portal_url:
            parsed = urlparse(portal_url)
            approval_url = f"{parsed.scheme}://{parsed.netloc}{url_for('admin_approve_request', token=pending_request.approval_token)}"
        else:
            approval_url = url_for('admin_approve_request', token=pending_request.approval_token, _external=True)

        send_admin_notification(pending_request, approval_url, vlan_id, current_ssid)
        flash('Adoption request submitted for approval.', 'info')
        return redirect(url_for('adopt_devices'))

    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    ip_address = lease.ip_address if lease else None

    existing = Device.query.filter_by(mac_address=mac_address).first()
    if not ip_address and existing and existing.ip_address:
        ip_address = existing.ip_address

    reserved_ip = ip_address
    if fixed_ip_requested and not ip_address:
        kea = get_kea()
        if kea:
            try:
                reserved_ip = kea.get_lease_ip_for_mac(mac_address, subnet_id=vlan_id) or \
                    kea.get_lease_ip_for_mac(mac_address)
            except Exception as exc:
                logger.warning("Failed to lookup lease IP for %s: %s", mac_address, exc)

    if fixed_ip_requested and reserved_ip and not _is_registered_pool_ip(reserved_ip, target_vlan):
        kea = get_kea()
        if kea:
            try:
                reserved_ip = kea.get_available_registered_ip(target_vlan)
            except Exception as exc:
                logger.warning("Failed to allocate registered IP for %s: %s", mac_address, exc)

    if fixed_ip_requested and not reserved_ip:
        flash('Cannot fix IP because no current lease was found.', 'error')
        return redirect(url_for('adopt_devices'))
    if existing and existing.registration_status == 'registered' and existing.user_id != user.id:
        flash('That device is already adopted by another user.', 'error')
        return redirect(url_for('adopt_devices'))

    if fixed_ip_requested and reserved_ip:
        ip_address = reserved_ip

    if existing:
        existing.user_id = user.id
        existing.registration_status = 'registered'
        existing.current_vlan = target_vlan
        existing.connection_type = 'wired' if vlan_id == wired_unregistered_vlan else 'wifi'
        existing.ssid = get_ssid_for_vlan(target_vlan)
        existing.is_wired = vlan_id == wired_unregistered_vlan
        existing.wired_target_vlan = target_vlan if vlan_id == wired_unregistered_vlan else None
        if device_label:
            existing.device_name = device_label
        if ip_address:
            existing.ip_address = ip_address
        existing.unregister_token = existing.unregister_token or secrets.token_urlsafe(32)
        db.session.commit()
        adopted_device = existing
    else:
        adopted_device = Device(
            mac_address=mac_address,
            user_id=user.id,
            device_name=device_label or 'adopted-device',
            ip_address=ip_address,
            registration_status='registered',
            current_vlan=target_vlan,
            connection_type='wired' if vlan_id == wired_unregistered_vlan else 'wifi',
            ssid=get_ssid_for_vlan(target_vlan),
            is_wired=vlan_id == wired_unregistered_vlan,
            wired_target_vlan=target_vlan if vlan_id == wired_unregistered_vlan else None,
            unregister_token=secrets.token_urlsafe(32),
        )
        db.session.add(adopted_device)
        db.session.commit()

    if ip_address:
        manage_switch_acl('unblock', ip_address, vlan_id)
        manage_dns_hijack('unhijack', ip_address)

    kea = get_kea()
    if kea:
        try:
            hostname = device_label or 'device'
            reserved_ip = reserved_ip if fixed_ip_requested else None
            success = kea.register_mac(mac=mac_address, vlan=target_vlan, hostname=hostname, ip_address=reserved_ip)
            if fixed_ip_requested:
                _log_kea_host_reservation(mac_address, target_vlan, 'after reservation-add')
            if not success:
                flash('Adopted device, but Kea reservation failed. Please re-try or check Kea logs.', 'warning')
            kea.set_block_status(
                mac_address,
                target_vlan,
                False,
                keep_ip=fixed_ip_requested,
                fixed_ip=reserved_ip if fixed_ip_requested else None,
            )
            if fixed_ip_requested:
                _log_kea_host_reservation(mac_address, target_vlan, 'after unblock')
        except Exception as exc:
            logger.warning("Failed to clear Kea block for %s: %s", mac_address, exc)

    if vlan_id == wired_unregistered_vlan:
        send_coa_change(mac_address, target_vlan)

    clear_unregistered_lease(mac_address)

    unregister_url = _build_unregister_url(adopted_device.unregister_token)
    confirm_url = None
    confirm_timeout_sec = None
    confirm_url, confirm_timeout_sec = _set_wifi_confirmation(adopted_device)
    if vlan_id == wired_unregistered_vlan:
        ssid_display = "Wired Network"
    else:
        ssid_display = adopted_device.ssid or get_ssid_for_vlan(target_vlan) or "WiFi Network"
    send_wifi_registration_confirmation(
        user.email,
        user.first_name or "there",
        ssid_display,
        mac_address,
        unregister_url,
        confirm_url=confirm_url,
        confirm_timeout_sec=confirm_timeout_sec,
        registration_details={
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number,
            "device_type": adopted_device.device_name,
            "ip_address": ip_address,
            "ssid": ssid_display
        }
    )

    flash(
        f'Device {mac_address} adopted successfully. ACL block and DNS hijack removed.',
        'success',
    )
    return redirect(url_for('adopt_devices'))


@app.route('/adopt/change-vlan', methods=['POST'])
def adopt_change_vlan():
    user, _ = _current_user_from_device()
    if not user:
        flash('Please connect from a registered device to manage VLANs.', 'error')
        return redirect(url_for('adopt_devices'))

    device_id_raw = (request.form.get('device_id') or '').strip()
    target_raw = (request.form.get('target_vlan') or '').strip()
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
        return redirect(url_for('adopt_devices'))

    device = Device.query.filter_by(id=device_id, user_id=user.id).first()
    if not device:
        flash('Device not found.', 'error')
        return redirect(url_for('adopt_devices'))

    if device.connection_type != 'wired':
        flash('Only wired devices can be moved to a different VLAN.', 'error')
        return redirect(url_for('adopt_devices'))

    _, effective_adoptable = _get_effective_vlans_for_user(user)
    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
    if target_vlan == wired_unregistered_vlan or target_vlan not in effective_adoptable:
        flash('You do not have permission to assign that VLAN.', 'error')
        return redirect(url_for('adopt_devices'))

    device.current_vlan = target_vlan
    device.is_wired = True
    device.wired_target_vlan = target_vlan
    db.session.commit()

    send_coa_change(device.mac_address, target_vlan)
    kea = get_kea()
    if kea:
        try:
            kea.register_mac(mac=device.mac_address, vlan=target_vlan, hostname=device.device_name or 'device', ip_address=None)
        except Exception as exc:
            logger.warning("Kea registration failed for %s: %s", device.mac_address, exc)

    flash(f'Device {device.mac_address} moved to VLAN {target_vlan}.', 'success')
    return redirect(url_for('adopt_devices'))


@app.route('/admin/set-user-password/<token>', methods=['GET', 'POST'])
def admin_set_user_password(token):
    """Admin page (token-secured, no login required) to set a user's network password
    and choose the approval policy for this pending_password registration request."""
    from models import User as _User

    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()

    if reg_request.status != 'pending_password':
        already_action = reg_request.status
        return render_template('admin_set_user_password.html',
                               already_processed=True,
                               already_action=already_action,
                               reg_request=reg_request)

    user = _User.query.filter_by(email=reg_request.email).first()

    if request.method == 'GET':
        already_has_password = bool(user and user.has_network_password)
        return render_template('admin_set_user_password.html',
                               reg_request=reg_request,
                               user=user,
                               already_has_password=already_has_password)

    # POST – validate and apply
    password = (request.form.get('password') or '').strip()
    confirm = (request.form.get('confirm_password') or '').strip()

    if not password or len(password) < 8:
        return render_template('admin_set_user_password.html', reg_request=reg_request, user=user,
                               form_error='Password must be at least 8 characters.')
    if password != confirm:
        return render_template('admin_set_user_password.html', reg_request=reg_request, user=user,
                               form_error='Passwords do not match. Please try again.')

    # Create user if this is a brand-new registration (e.g. pending_password from non-auto-approve path)
    if not user:
        user = _User(
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

    # Set the password on the user
    user.set_network_password(password)
    user.network_password_set_token = None
    user.network_password_set_token_expires = None

    # All modes: just persist the password and the approval policy.
    # The pending_password request(s) remain as-is.  The registration-status API
    # now returns 'enter_password' for this MAC once it sees the password hash is set,
    # causing the portal to stop showing "waiting" and instead show a password field.
    # Device registration happens when the user enters the correct password on their device.
    # 'first_use' means the next device registered by this user on a password-protected
    # VLAN will be auto-approved, regardless of VLAN rules.  After that the normal
    # VLAN-based approval logic takes over.
    user.network_password_approval_mode = 'first_use'
    db.session.commit()

    return render_template('admin_set_user_password.html', success=True,
                           reg_request=reg_request, user=user)


@app.route('/set-network-password/<token>', methods=['GET', 'POST'])
def set_network_password(token):
    """Allow a user to set their network password via emailed token."""
    from models import User as _User
    user = _User.query.filter_by(network_password_set_token=token).first()
    if not user:
        return render_template('set_network_password.html', error='invalid')
    if not user.network_password_set_token_expires or datetime.utcnow() > user.network_password_set_token_expires:
        return render_template('set_network_password.html', error='expired')

    if request.method == 'POST':
        password = (request.form.get('password') or '').strip()
        confirm = (request.form.get('confirm_password') or '').strip()
        if not password or len(password) < 8:
            return render_template('set_network_password.html', token=token, user=user,
                                   form_error='Password must be at least 8 characters.')
        if password != confirm:
            return render_template('set_network_password.html', token=token, user=user,
                                   form_error='Passwords do not match. Please try again.')

        # Store the password and clear the token.
        # Do NOT register devices here – the portal will detect the password is now set
        # (registration-status returns 'enter_password') and prompt the user to enter it.
        # Domain-policy approval logic in the register route then decides whether to
        # auto-register or send an admin approval request.
        # Clear network_password_approval_mode so that the normal domain-policy/VLAN
        # approval logic applies when the user next submits their password on the portal.
        # This prevents a previously admin-set 'first_use' flag from bypassing approval.
        user.set_network_password(password)
        user.network_password_set_token = None
        user.network_password_set_token_expires = None
        user.network_password_approval_mode = None
        db.session.commit()

        return render_template('set_network_password.html', success=True, user=user)

    return render_template('set_network_password.html', token=token, user=user)


@app.route('/forgot-network-password', methods=['POST'])
def forgot_network_password():
    """Send a password-reset link to a user who has a network password but has forgotten it."""
    from models import User as _User
    email = (request.form.get('email') or '').strip().lower()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    # Always respond success to avoid user enumeration
    success_response = {'status': 'ok', 'message': 'If that email address has a network account, a reset link has been sent.'}

    if not email:
        if is_ajax:
            return jsonify({'status': 'error', 'message': 'Please enter your email address.'})
        flash('Please enter your email address.', 'error')
        return redirect(url_for('register'))

    user = _User.query.filter_by(email=email).first()
    if user and user.has_network_password:
        # Generate / refresh reset token
        user.network_password_set_token = secrets.token_urlsafe(32)
        user.network_password_set_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        set_password_url = _build_set_password_url(user.network_password_set_token)
        try:
            send_network_password_reset_email(
                user.email,
                user.first_name or 'there',
                set_password_url,
            )
        except Exception as exc:
            logger.warning('forgot-network-password email failed for %s: %s', email, exc)

        # Ensure a pending_password RegistrationRequest exists for this device so that:
        # (a) the registration-status API returns 'enter_password' once the new password
        #     is set, causing the portal to show the password prompt again, and
        # (b) set_network_password can register the device when the user submits their
        #     new password via the email link.
        mac_address = get_client_mac()
        ip_address = get_client_ip()
        if mac_address and ip_address:
            existing_req = RegistrationRequest.query.filter_by(
                mac_address=mac_address, status='pending_password'
            ).first()
            if not existing_req:
                _, detected_vlan, _ = detect_connection_type(ip_address)
                pwd_req = RegistrationRequest(
                    mac_address=mac_address,
                    ip_address=ip_address,
                    email=user.email,
                    first_name=user.first_name or '',
                    last_name=user.last_name or '',
                    phone_number=user.phone_number or '',
                    device_type='unknown',
                    requested_vlan=detected_vlan,
                    status='pending_password',
                    approval_token=secrets.token_urlsafe(32),
                )
                db.session.add(pwd_req)
                db.session.commit()
                logger.info(
                    'Created pending_password request for %s (forgot-password flow)', mac_address
                )

    if is_ajax:
        return jsonify(success_response)
    flash(success_response['message'], 'info')
    return redirect(url_for('register'))


@app.route('/pending-approval')
def pending_approval():
    """Pending approval page for registrations requiring admin review."""
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    prefill = _build_prefill_from_request()
    if mac_address:
        reg_request = RegistrationRequest.query.filter_by(
            mac_address=mac_address,
            status='pending'
        ).order_by(RegistrationRequest.submitted_at.desc()).first()
        if reg_request:
            prefill = {
                'email': reg_request.email or '',
                'first_name': reg_request.first_name or '',
                'last_name': reg_request.last_name or '',
                'phone_number': reg_request.phone_number or '',
                'device_type': reg_request.device_type or ''
            }

    wants_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
    if wants_ajax:
        html = render_template(
            'partials/pending_approval_content.html',
            prefill=prefill,
            mac_address=mac_address,
            ip_address=ip_address
        )
        return jsonify({
            'header': 'Request Submitted',
            'subheader': 'Please wait for an administrator to approve your request.',
            'html': html
        })
    return render_template(
        'pending_approval.html',
        prefill=prefill,
        mac_address=mac_address,
        ip_address=ip_address,
    )


@app.route('/request-rejected')
def request_rejected():
    """Rejected request page with optional reason."""
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    reason = request.args.get('reason', '').strip()
    prefill = _build_prefill_from_request()
    return render_template(
        'request_rejected.html',
        reason=reason,
        prefill=prefill,
        mac_address=mac_address,
        ip_address=ip_address,
    )


@app.route('/registered')
def registered_success():
    """Registration success page."""
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    device = None
    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        device = normalize_device_status(device)
    if device and device.registration_status == 'registered':
        return render_template('registered.html', device=device, ip_address=ip_address, mac_address=mac_address)

    reg_request = None
    if mac_address:
        reg_request = (
            RegistrationRequest.query.filter_by(mac_address=mac_address)
            .order_by(RegistrationRequest.submitted_at.desc())
            .first()
        )
    if reg_request:
        if reg_request.status == 'pending':
            return redirect(url_for(
                'pending_approval',
                email=reg_request.email,
                first_name=reg_request.first_name,
                last_name=reg_request.last_name,
                phone_number=reg_request.phone_number or '',
                device_type=reg_request.device_type or ''
            ))
        if reg_request.status == 'rejected':
            reason = reg_request.notes or ''
            return redirect(url_for('request_rejected', reason=reason))

    return redirect(url_for('register'))


@app.route('/api/registration-status', methods=['GET', 'OPTIONS'])
def registration_status():
    logger.info(f"Full headers: {request.headers}")
    origin = request.headers.get('Origin', '')
    
    
    # Whitelist: Add expected origins (expand based on browser Network tab if mismatch)
    allowed_origins = [
        'http://www.msftconnecttest.com',
        'http://connectivitycheck.gstatic.com',
        'http://captive.apple.com',
        'http://detectportal.firefox.com',
        # Variations: Add without www or with trailing / if seen in Network tab
        'http://msftconnecttest.com',
        'http://www.msftconnecttest.com/',
        # Your portal if self-calls: 'http://bf-network.duckdns.org'
    ]
    
    acao_value = origin if origin in allowed_origins else '*'
    
    if request.method == 'OPTIONS':
        response = app.make_response('')
        response.headers['Access-Control-Allow-Origin'] = acao_value
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.headers['Vary'] = 'Origin'
        return response, 200
    """API endpoint for checking registration status via AJAX"""
    mac_address = get_client_mac()
    
    if not mac_address:
        response = jsonify({'status': 'unknown', 'message': 'Could not detect MAC address'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    # Check if device is registered
    device = Device.query.filter_by(mac_address=mac_address).first()
    device = normalize_device_status(device)
    device = _enforce_wifi_confirmation(device)
    if device:
        current_ip = get_client_ip()
        current_connection, current_vlan, detected_ssid = detect_connection_type(current_ip)
        current_ssid = get_ssid_for_vlan(current_vlan) or detected_ssid
        expected_ssid = get_ssid_for_vlan(device.current_vlan) or device.ssid
        network_mismatch = bool(current_connection == 'wifi' and current_vlan and device.current_vlan and current_vlan != device.current_vlan)

        if device.registration_status == 'registered' and not network_mismatch and current_ip:
            if not _is_blocked_pool_ip(current_ip):
                if _should_hijack_vlan(current_vlan):
                    manage_dns_hijack('unhijack', current_ip)
                if current_vlan:
                    manage_switch_acl('unblock', current_ip, current_vlan)

                if current_connection == 'wifi' and device.current_vlan:
                    _cache_key = (device.mac_address, device.current_vlan)
                    _now = time.monotonic()
                    with _kea_reservation_check_lock:
                        _last = _kea_reservation_check_cache.get(_cache_key, 0)
                        _due = (_now - _last) >= KEA_RESERVATION_CHECK_TTL_SEC
                        if _due:
                            _kea_reservation_check_cache[_cache_key] = _now
                    if _due:
                        kea = get_kea()
                        if kea:
                            try:
                                reservation = kea.get_reservation(device.mac_address, device.current_vlan)
                                if not reservation:
                                    hostname = device.device_name or 'device'
                                    success = kea.register_mac(
                                        mac=device.mac_address,
                                        vlan=device.current_vlan,
                                        hostname=hostname,
                                        ip_address=None,
                                    )
                                    if success:
                                        kea.force_lease_renewal(device.mac_address, current_ip)
                            except Exception as exc:
                                with _kea_reservation_check_lock:
                                    _kea_reservation_check_cache.pop(_cache_key, None)
                                logger.warning("Kea reservation check failed for %s: %s", device.mac_address, exc)

                clear_unregistered_lease(device.mac_address)
        response = jsonify({
            'status': device.registration_status,
            'message': f'Device is {device.registration_status}',
            'current_ip': current_ip,
            'current_vlan': current_vlan,
            'current_ssid': current_ssid,
            'expected_vlan': device.current_vlan,
            'expected_ssid': expected_ssid,
            'network_mismatch': network_mismatch
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    # Check if there's a pending registration request
    reg_request = RegistrationRequest.query.filter_by(mac_address=mac_address).order_by(RegistrationRequest.submitted_at.desc()).first()
    if reg_request:
        payload = {
            'status': reg_request.status,
            'message': f'Registration request is {reg_request.status}'
        }
        if reg_request.status == 'rejected' and reg_request.notes:
            payload['reason'] = reg_request.notes
        # If the VLAN requires a password and the admin has now set one, tell the portal
        # to stop showing "waiting" and instead prompt the user to enter the password.
        if reg_request.status == 'pending_password':
            _pwd_user = User.query.filter_by(email=reg_request.email).first()
            if _pwd_user and _pwd_user.has_network_password:
                payload['status'] = 'enter_password'
                payload['message'] = 'Your administrator has set a network password for your account. Please enter it to continue.'
        response = jsonify(payload)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    response = jsonify({'status': 'unregistered', 'message': 'Not registered'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@app.route('/api/block-status')
def api_block_status():
    """API endpoint for checking if device is still blocked"""
    mac_address = get_client_mac()
    
    if not mac_address:
        return jsonify({'blocked': True, 'message': 'Could not detect MAC address'})
    
    device = Device.query.filter_by(mac_address=mac_address).first()
    
    if device and device.registration_status == 'blocked':
        return jsonify({'blocked': True, 'message': 'Device is blocked'})
    
    return jsonify({'blocked': False, 'message': 'Device is not blocked'})


@app.route('/unregister/<token>')
def unregister(token):
    """
    Unregister a device via email token.
    
    This removes the device from the registered pool and returns it to
    the walled garden (unregistered pool) with restricted access.
    """
    if not token:
        flash('Invalid unregister link', 'error')
        return redirect(url_for('index'))
    
    # Find device by unregister token
    device = Device.query.filter_by(unregister_token=token).first()
    
    if not device:
        flash('Invalid or expired unregister token', 'error')
        return redirect(url_for('index'))
    
    mac_address = device.mac_address
    connection_type = device.connection_type
    vlan_id = device.current_vlan
    user = device.user
    user_email = user.email if user else 'Unknown'

    if user and device.profile_snapshot:
        try:
            snapshot = json.loads(device.profile_snapshot)
        except Exception:
            snapshot = None

        if snapshot:
            previous = snapshot.get("previous") or {}
            new = snapshot.get("new") or {}

            current_profile = {
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "phone_number": user.phone_number or ""
            }

            if current_profile == {
                "first_name": new.get("first_name", ""),
                "last_name": new.get("last_name", ""),
                "phone_number": new.get("phone_number", "")
            }:
                user.first_name = previous.get("first_name") or None
                user.last_name = previous.get("last_name") or None
                user.phone_number = previous.get("phone_number") or None
    
    # Remove device registration
    if connection_type == 'wifi':
        # Remove from Kea
        kea = get_kea()
        if kea and vlan_id:
            success = kea.unregister_mac(mac=mac_address, vlan=vlan_id)
            if success:
                logger.info(f"WiFi device {mac_address} unregistered from VLAN {vlan_id}")
            else:
                logger.warning(f"Failed to unregister WiFi device {mac_address} from Kea")
    
    elif connection_type == 'wired':
        # Send RADIUS CoA to move to unregistered VLAN
        vlan_map = get_vlan_map()
        success = send_coa_change(mac_address, vlan_map['unregistered'])
        if success:
            logger.info(f"Wired device {mac_address} moved to unregistered VLAN")
        else:
            logger.warning(f"Failed to send CoA for wired device {mac_address}")
    
    # Update device status in database
    device.registration_status = 'unregistered'
    device.unregister_token = None  # Invalidate token
    device.user_id = None  # Remove user association
    device.profile_snapshot = None
    db.session.commit()

    # Keep DNS hijack + ACL block active while the current lease is valid
    if device.ip_address and not _is_blocked_pool_ip(device.ip_address):
        lease_expiry = get_lease_expiry_for_mac(mac_address, subnet_id=vlan_id)
        if not lease_expiry:
            lease_expiry = datetime.utcnow() + timedelta(minutes=5)

        upsert_unregistered_lease(mac_address, device.ip_address, lease_expiry)

        if vlan_id:
            manage_switch_acl('block', device.ip_address, vlan_id)

        if _should_hijack_vlan(vlan_id):
            manage_dns_hijack('hijack', device.ip_address)
            logger.info(
                "DNS hijacked/ACL blocked for unregistered device %s at %s until %s",
                mac_address,
                device.ip_address,
                lease_expiry,
            )
        else:
            logger.info(
                "ACL blocked for unregistered device %s at %s until %s",
                mac_address,
                device.ip_address,
                lease_expiry,
            )
    
    flash(f'Device {mac_address} has been unregistered successfully. Access has been restricted.', 'success')
    logger.info(f"Device {mac_address} (user: {user_email}) unregistered via email token")
    
    return render_template('status.html', device=device, unregistered=True)


@app.route('/confirm/<token>')
def confirm_device(token):
    if not token:
        flash('Invalid confirmation link', 'error')
        return redirect(url_for('index'))

    device = Device.query.filter_by(confirmation_token=token).first()
    if not device:
        flash('Invalid or expired confirmation link', 'error')
        return redirect(url_for('index'))

    if device.registration_status == 'unregistered':
        flash('This device is unregistered. Please contact the administrator.', 'error')
        return render_template('status.html', device=device, unregistered=True)

    device.confirmation_confirmed_at = datetime.utcnow()
    device.confirmation_deadline = None
    db.session.commit()

    if device.registration_status == 'blocked':
        apply_device_unblock(device, flash_messages=False)

    flash('Device confirmed. Access restored.', 'success')
    return render_template('status.html', device=device)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Try to find admin in database
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and admin.check_password(password):
            # If MFA is enabled, redirect to MFA verification
            if admin.mfa_enabled and admin.mfa_secret:
                # Store admin_id in session temporarily for MFA verification
                session['mfa_admin_id'] = admin.id
                return redirect(url_for('admin_mfa_verify'))
            
            # Update last login time
            admin.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create AdminUser object for Flask-Login
            user = AdminUser(
                admin.id,
                admin.username,
                admin.can_manage_users,
                admin.can_manage_vlans,
                admin.can_view_traffic,
                admin.can_manage_admins,
                admin.traffic_viewer_settings,
                admin.mfa_enabled,
                can_manage_switch_ports=getattr(admin, 'can_manage_switch_ports', False),
                can_manage_isp_routers=getattr(admin, 'can_manage_isp_routers', False)
            )
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            # Legacy fallback: check environment variables
            # This allows migration from old system
            if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
                # Create admin user in database if it doesn't exist
                if not admin:
                    admin = Admin(username=username)
                    admin.set_password(password)
                    admin.can_manage_users = True
                    admin.can_manage_vlans = True
                    admin.can_view_traffic = True
                    admin.can_manage_admins = True
                    admin.can_manage_switch_ports = True
                    admin.can_manage_isp_routers = True
                    db.session.add(admin)
                    db.session.commit()
                    logger.info(f"Migrated legacy admin '{username}' to database")
                
                # Log in with full permissions
                user = AdminUser(admin.id, admin.username, True, True, True, True, can_manage_switch_ports=True, can_manage_isp_routers=True)
                login_user(user)
                return redirect(url_for('admin_dashboard'))
            
            flash('Invalid credentials', 'error')
    
    return render_template('admin_login.html')


@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    """Admin forgot-password page — request a reset link via email."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if email:
            admin = Admin.query.filter(
                db.func.lower(Admin.email) == email
            ).first()
            if admin:
                token = secrets.token_urlsafe(32)
                admin.password_reset_token = token
                admin.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()
                reset_url = url_for('admin_reset_password', token=token, _external=True)
                try:
                    send_admin_password_reset_email(admin.email, admin.username, reset_url)
                    logger.info(f"Password reset email sent to admin '{admin.username}'")
                except Exception as e:
                    logger.error(f"Failed to send password reset email to admin '{admin.username}': {e}")
        # Always show the same message regardless of whether the email matched
        flash('If that email address is registered, you will receive a password reset link shortly.', 'info')
        return redirect(url_for('admin_forgot_password'))
    return render_template('admin_forgot_password.html')


@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):
    """Admin password reset form — validate token and accept new password."""
    admin = Admin.query.filter_by(password_reset_token=token).first()
    if not admin or not admin.password_reset_expires or admin.password_reset_expires < datetime.utcnow():
        flash('This password reset link is invalid or has expired.', 'error')
        return redirect(url_for('admin_forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('admin_reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('admin_reset_password.html', token=token)
        admin.set_password(password)
        admin.password_reset_token = None
        admin.password_reset_expires = None
        db.session.commit()
        logger.info(f"Admin '{admin.username}' reset their password via email link")
        flash('Password reset successfully. You can now log in.', 'success')
        return redirect(url_for('admin_login'))

    return render_template('admin_reset_password.html', token=token)


@app.route('/admin/logout')
@login_required
def admin_logout():
    """Admin logout"""
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin/mfa/verify', methods=['GET', 'POST'])
def admin_mfa_verify():
    """MFA verification page during login"""
    import pyotp
    
    if 'mfa_admin_id' not in session:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('admin_login'))
    
    admin_id = session.get('mfa_admin_id')
    admin = Admin.query.get(admin_id)
    
    if not admin or not admin.mfa_enabled or not admin.mfa_secret:
        session.pop('mfa_admin_id', None)
        flash('MFA not configured for this account.', 'error')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip().replace(' ', '')
        
        if not code:
            flash('Please enter the verification code.', 'error')
            return render_template('admin_mfa_verify.html')
        
        # Verify TOTP code
        totp = pyotp.TOTP(admin.mfa_secret)
        if totp.verify(code, valid_window=1):  # Allow 1 time step before/after
            # Clear MFA session data
            session.pop('mfa_admin_id', None)
            
            # Update last login time
            admin.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log in the user
            user = AdminUser(
                admin.id,
                admin.username,
                admin.can_manage_users,
                admin.can_manage_vlans,
                admin.can_view_traffic,
                admin.can_manage_admins,
                admin.traffic_viewer_settings,
                admin.mfa_enabled,
                can_manage_switch_ports=getattr(admin, 'can_manage_switch_ports', False),
                can_manage_isp_routers=getattr(admin, 'can_manage_isp_routers', False)
            )
            login_user(user)
            logger.info(f"Admin '{admin.username}' logged in with MFA")
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return render_template('admin_mfa_verify.html')
    
    return render_template('admin_mfa_verify.html')


@app.route('/admin/mfa/setup', methods=['GET', 'POST'])
@login_required
def admin_mfa_setup():
    """MFA setup page for admins to enable MFA"""
    import pyotp
    import qrcode
    import io
    import base64
    
    admin = Admin.query.get(int(current_user.id))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'enable':
            # Generate new secret
            secret = pyotp.random_base32()
            
            # Store in session temporarily until verified
            session['mfa_setup_secret'] = secret
            session['mfa_setup_admin_id'] = admin.id
            
            # Generate QR code
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=admin.username,
                issuer_name='BF-Network Admin Portal'
            )
            
            # Create QR code image
            qr =  qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64 for display
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return render_template('admin_mfa_setup.html',
                                 admin=admin,
                                 mfa_enabled=admin.mfa_enabled,
                                 setup_mode='verify',
                                 show_qr=True,
                                 secret=secret,
                                 qr_code=qr_code_base64)
        
        elif action == 'add_device':
            # Show existing QR code so user can add another authenticator device
            if not admin.mfa_secret:
                flash('MFA is not fully configured. Please set up MFA first.', 'error')
                return redirect(url_for('admin_mfa_setup'))
            secret = admin.mfa_secret
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=admin.username,
                issuer_name='BF-Network Admin Portal'
            )
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            return render_template('admin_mfa_setup.html',
                                 admin=admin,
                                 mfa_enabled=True,
                                 show_qr=True,
                                 secret=secret,
                                 qr_code=qr_code_base64)
        
        elif action == 'verify':
            # Verify the setup code
            code = request.form.get('code', '').strip().replace(' ', '')
            secret = session.get('mfa_setup_secret')
            setup_admin_id = session.get('mfa_setup_admin_id')
            
            if not secret or setup_admin_id != admin.id:
                flash('Setup session expired. Please try again.', 'error')
                session.pop('mfa_setup_secret', None)
                session.pop('mfa_setup_admin_id', None)
                return redirect(url_for('admin_mfa_setup'))
            
            if not code:
                flash('Please enter the verification code.', 'error')
                # Re-generate QR code with the same secret
                import qrcode
                totp = pyotp.TOTP(secret)
                provisioning_uri = totp.provisioning_uri(
                    name=admin.username,
                    issuer_name='BF-Network Admin Portal'
                )
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                buffer.seek(0)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                
                return render_template('admin_mfa_setup.html',
                                     admin=admin,
                                     mfa_enabled=admin.mfa_enabled,
                                     setup_mode='verify',
                                     show_qr=True,
                                     secret=secret,
                                     qr_code=qr_code_base64)
            
            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                # Save MFA settings to database
                admin.mfa_enabled = True
                admin.mfa_secret = secret
                db.session.commit()
                
                # Clear session data
                session.pop('mfa_setup_secret', None)
                session.pop('mfa_setup_admin_id', None)
                
                # Update current_user session
                current_user.mfa_enabled = True
                
                logger.info(f"Admin '{admin.username}' enabled MFA")
                flash('MFA has been enabled successfully! You will need to use your authenticator app for future logins.', 'success')
                return redirect(url_for('admin_mfa_setup'))
            else:
                flash('Invalid verification code. Please try again.', 'error')
                # Re-generate QR code with the same secret for retry
                import qrcode
                totp = pyotp.TOTP(secret)
                provisioning_uri = totp.provisioning_uri(
                    name=admin.username,
                    issuer_name='BF-Network Admin Portal'
                )
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                buffer.seek(0)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                
                return render_template('admin_mfa_setup.html',
                                     admin=admin,
                                     mfa_enabled=admin.mfa_enabled,
                                     setup_mode='verify',
                                     show_qr=True,
                                     secret=secret,
                                     qr_code=qr_code_base64)
    
    # GET request - show current status
    return render_template('admin_mfa_setup.html',
                         admin=admin,
                         mfa_enabled=admin.mfa_enabled,
                         show_qr=False,
                         setup_mode='status')


@app.route('/admin/mfa/disable', methods=['POST'])
@login_required
def admin_mfa_disable():
    """Disable MFA for current admin"""
    import pyotp
    
    admin = Admin.query.get(int(current_user.id))
    
    if not admin.mfa_enabled:
        flash('MFA is not enabled for your account.', 'info')
        return redirect(url_for('admin_mfa_setup'))
    
    # Require current MFA code or password to disable
    code_or_password = request.form.get('code', '').strip()
    
    if not code_or_password:
        flash('Please enter your current MFA code or password.', 'error')
        return redirect(url_for('admin_mfa_setup'))
    
    # Try as MFA code first
    if admin.mfa_secret:
        totp = pyotp.TOTP(admin.mfa_secret)
        if totp.verify(code_or_password, valid_window=1):
            admin.mfa_enabled = False
            admin.mfa_secret = None
            db.session.commit()
            current_user.mfa_enabled = False
            logger.info(f"Admin '{admin.username}' disabled MFA")
            flash('MFA has been disabled.', 'success')
            return redirect(url_for('admin_mfa_setup'))
    
    # Try as password
    if admin.check_password(code_or_password):
        admin.mfa_enabled = False
        admin.mfa_secret = None
        db.session.commit()
        current_user.mfa_enabled = False
        logger.info(f"Admin '{admin.username}' disabled MFA using password")
        flash('MFA has been disabled.', 'success')
        return redirect(url_for('admin_mfa_setup'))
    
    flash('Invalid code or password.', 'error')
    return redirect(url_for('admin_mfa_setup'))


@app.route('/admin/change-password', methods=['GET', 'POST'])
@login_required
def admin_change_own_password():
    """Forced password change on first login"""
    admin = Admin.query.get(int(current_user.id))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not new_password:
            flash('Please enter a new password.', 'error')
            return render_template('admin_change_own_password.html')

        if len(new_password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('admin_change_own_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('admin_change_own_password.html')

        if admin.check_password(new_password):
            flash('New password must be different from your current password.', 'error')
            return render_template('admin_change_own_password.html')

        admin.set_password(new_password)
        admin.must_change_password = False
        db.session.commit()
        current_user.must_change_password = False

        logger.info(f"Admin '{admin.username}' changed their password on first login")
        flash('Password changed successfully. Welcome!', 'success')
        return redirect(url_for('admin_mfa_setup'))

    return render_template('admin_change_own_password.html')


@app.route('/admin/manage-admins/<int:admin_id>/reset-mfa', methods=['POST'])
@login_required
@permission_required('manage_admins')
def admin_reset_mfa(admin_id):
    """Reset MFA for a specific admin (super admin only)"""
    admin = Admin.query.get_or_404(admin_id)
    
    if not admin.mfa_enabled:
        flash(f'MFA is not enabled for "{admin.username}".', 'info')
        return redirect(url_for('admin_manage_admins'))
    
    # Reset MFA
    admin.mfa_enabled = False
    admin.mfa_secret = None
    db.session.commit()
    
    logger.info(f"Super admin '{current_user.username}' reset MFA for admin '{admin.username}'")
    flash(f'MFA has been reset for "{admin.username}". They will need to set it up again.', 'success')
    return redirect(url_for('admin_manage_admins'))


@app.route('/admin/no-permissions')
@login_required
def admin_no_permissions():
    """Page shown when admin has no permissions"""
    # Find first super admin with email
    super_admin = Admin.query.filter(
        Admin.can_manage_admins == True,
        Admin.email != None,
        Admin.email != ''
    ).order_by(Admin.id.asc()).first()
    
    contact_email = super_admin.email if super_admin else None
    contact_name = super_admin.username if super_admin else None
    
    return render_template('admin_no_permissions.html', 
                         contact_email=contact_email,
                         contact_name=contact_name)


@app.route('/admin/manage-admins')
@login_required
@permission_required('manage_admins')
def admin_manage_admins():
    """Super admin page for managing other admins"""
    all_admins = Admin.query.order_by(Admin.username.asc()).all()
    
    # Count super admins
    super_admin_count = sum(1 for admin in all_admins if admin.is_super_admin)
    
    # Prepare admin data
    admin_list = []
    for admin in all_admins:
        is_current = (str(admin.id) == current_user.id)
        is_only_super = is_current and admin.is_super_admin and super_admin_count == 1
        
        admin_list.append({
            'id': admin.id,
            'username': admin.username,
            'email': admin.email,
            'can_manage_users': admin.can_manage_users,
            'can_manage_vlans': admin.can_manage_vlans,
            'can_view_traffic': admin.can_view_traffic,
            'can_manage_admins': admin.can_manage_admins,
            'can_manage_switch_ports': admin.can_manage_switch_ports,
            'can_manage_isp_routers': getattr(admin, 'can_manage_isp_routers', False),
            'created_at': admin.created_at,
            'last_login': admin.last_login,
            'is_current': is_current,
            'is_only_super': is_only_super,
            'mfa_enabled': admin.mfa_enabled
        })
    
    return render_template('admin_manage_admins.html', admins=admin_list)


@app.route('/admin/manage-admins/create', methods=['POST'])
@login_required
@permission_required('manage_admins')
def admin_create_admin():
    """Create a new admin user"""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    can_manage_users = bool(request.form.get('can_manage_users'))
    can_manage_vlans = bool(request.form.get('can_manage_vlans'))
    can_view_traffic = bool(request.form.get('can_view_traffic'))
    can_manage_admins = bool(request.form.get('can_manage_admins'))
    can_manage_switch_ports = bool(request.form.get('can_manage_switch_ports'))
    can_manage_isp_routers = bool(request.form.get('can_manage_isp_routers'))
    must_change_password = bool(request.form.get('must_change_password'))  # checkbox: present=True, absent=False
    
    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('admin_manage_admins'))
    
    if len(password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('admin_manage_admins'))
    
    # Check if username already exists
    existing = Admin.query.filter_by(username=username).first()
    if existing:
        flash(f'Username "{username}" already exists.', 'error')
        return redirect(url_for('admin_manage_admins'))
    
    # Create new admin
    admin = Admin(username=username, email=email if email else None)
    admin.set_password(password)
    admin.can_manage_users = can_manage_users
    admin.can_manage_vlans = can_manage_vlans
    admin.can_view_traffic = can_view_traffic
    admin.can_manage_admins = can_manage_admins
    admin.can_manage_switch_ports = can_manage_switch_ports
    admin.can_manage_isp_routers = can_manage_isp_routers
    admin.must_change_password = must_change_password
    admin.created_by = int(current_user.id)
    db.session.add(admin)
    db.session.commit()
    
    logger.info(f"Admin '{username}' created by {current_user.username}")
    flash(f'Admin "{username}" created successfully.', 'success')
    return redirect(url_for('admin_manage_admins'))


@app.route('/admin/manage-admins/<int:admin_id>/update', methods=['POST'])
@login_required
@permission_required('manage_admins')
def admin_update_admin_permissions(admin_id):
    """Update admin permissions"""
    admin = Admin.query.get_or_404(admin_id)
    
    can_manage_users = bool(request.form.get('can_manage_users'))
    can_manage_vlans = bool(request.form.get('can_manage_vlans'))
    can_view_traffic = bool(request.form.get('can_view_traffic'))
    can_manage_admins = bool(request.form.get('can_manage_admins'))
    can_manage_switch_ports = bool(request.form.get('can_manage_switch_ports'))
    can_manage_isp_routers = bool(request.form.get('can_manage_isp_routers'))
    
    # Check if this would remove the last super admin
    if admin.can_manage_admins and not can_manage_admins:
        super_admin_count = Admin.query.filter_by(can_manage_admins=True).count()
        if super_admin_count <= 1:
            flash('Cannot remove the last super admin. There must always be at least one super admin.', 'error')
            return redirect(url_for('admin_manage_admins'))
    
    admin.can_manage_users = can_manage_users
    admin.can_manage_vlans = can_manage_vlans
    admin.can_view_traffic = can_view_traffic
    admin.can_manage_admins = can_manage_admins
    admin.can_manage_switch_ports = can_manage_switch_ports
    admin.can_manage_isp_routers = can_manage_isp_routers
    db.session.commit()
    
    logger.info(f"Admin '{admin.username}' permissions updated by {current_user.username}")
    flash(f'Permissions updated for "{admin.username}".', 'success')
    return redirect(url_for('admin_manage_admins'))


@app.route('/admin/manage-admins/<int:admin_id>/delete', methods=['POST'])
@login_required
@permission_required('manage_admins')
def admin_delete_admin(admin_id):
    """Delete an admin user"""
    admin = Admin.query.get_or_404(admin_id)
    
    # Prevent deleting self
    if str(admin.id) == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_manage_admins'))
    
    # Check if this would remove the last super admin
    if admin.can_manage_admins:
        super_admin_count = Admin.query.filter_by(can_manage_admins=True).count()
        if super_admin_count <= 1:
            flash('Cannot delete the last super admin. There must always be at least one super admin.', 'error')
            return redirect(url_for('admin_manage_admins'))
    
    username = admin.username
    db.session.delete(admin)
    db.session.commit()
    
    logger.info(f"Admin '{username}' deleted by {current_user.username}")
    flash(f'Admin "{username}" deleted successfully.', 'success')
    return redirect(url_for('admin_manage_admins'))


@app.route('/admin/manage-admins/<int:admin_id>/change-password', methods=['POST'])
@login_required
@permission_required('manage_admins')
def admin_change_admin_password(admin_id):
    """Change admin password"""
    admin = Admin.query.get_or_404(admin_id)
    
    new_password = request.form.get('new_password', '').strip()
    
    if not new_password:
        flash('Password cannot be empty.', 'error')
        return redirect(url_for('admin_manage_admins'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('admin_manage_admins'))
    
    admin.set_password(new_password)
    db.session.commit()
    
    logger.info(f"Password changed for admin '{admin.username}' by {current_user.username}")
    flash(f'Password updated for "{admin.username}".', 'success')
    return redirect(url_for('admin_manage_admins'))


@app.route('/admin/manage-admins/<int:admin_id>/update-email', methods=['POST'])
@login_required
@permission_required('manage_admins')
def admin_update_admin_email(admin_id):
    """Update admin email"""
    admin = Admin.query.get_or_404(admin_id)
    
    new_email = request.form.get('email', '').strip().lower()
    
    admin.email = new_email if new_email else None
    db.session.commit()
    
    logger.info(f"Email updated for admin '{admin.username}' by {current_user.username}")
    flash(f'Email updated for "{admin.username}".', 'success')
    return redirect(url_for('admin_manage_admins'))


@app.route('/admin/reset-test', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_reset_test():
    """Reset test environment data and network rules."""
    if not is_test_env():
        abort(404)

    try:
        reset_test_data()
    except Exception as exc:
        logger.error("Test reset DB cleanup failed: %s", exc)
        flash('Reset failed while clearing database records.', 'error')
        return redirect(url_for('admin_dashboard'))

    reset_acl_queue_files()
    reset_dns_hijack_rules()
    acl_ok = reset_acl_baseline()
    mac_auth_cleared = clear_mac_auth_sessions()
    ports_reset = reset_user_ports()

    if acl_ok and mac_auth_cleared and ports_reset:
        flash('Test reset complete. Database cleared (users, devices, NAT sessions, DNS resolutions), ACL baseline restored, DNS hijack rules restored, MAC auth sessions cleared, and user ports reset.', 'success')
    elif acl_ok and mac_auth_cleared:
        flash('Test reset complete (including NAT/DNS logs), but user port reset failed.', 'warning')
    elif acl_ok:
        flash('Test reset complete (including NAT/DNS logs), but MAC auth session clearing or port reset failed.', 'warning')
    else:
        flash('Test reset complete (including NAT/DNS logs), but ACL baseline, MAC auth clearing, or port reset failed.', 'warning')

    return redirect(url_for('admin_dashboard'))


# ---------------------------------------------------------------------------
# ISP Routers Management
# ---------------------------------------------------------------------------

@app.route('/admin/isp-routers', methods=['GET', 'POST'])
@login_required
@permission_required('manage_isp_routers')
def admin_isp_routers():
    """ISP router management page."""
    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'add':
            name = request.form.get('name', '').strip()
            vlan_id_raw = request.form.get('vlan_id', '').strip()
            switch_port = request.form.get('switch_port', '').strip() or None
            if not name or not vlan_id_raw:
                flash('Name and VLAN ID are required.', 'error')
                return redirect(url_for('admin_isp_routers'))
            try:
                vlan_id = int(vlan_id_raw)
            except ValueError:
                flash('VLAN ID must be an integer.', 'error')
                return redirect(url_for('admin_isp_routers'))
            subnet = f'192.168.{vlan_id}.0/24'
            dhcp_trust = (vlan_id == 1)
            if ISPRouter.query.filter_by(name=name).first():
                flash(f'A router named "{name}" already exists.', 'error')
                return redirect(url_for('admin_isp_routers'))
            router = ISPRouter(name=name, subnet=subnet, vlan_id=vlan_id,
                               switch_port=switch_port,
                               dhcp_snooping_trust=dhcp_trust)
            db.session.add(router)
            db.session.commit()
            _apply_isp_router_to_switches(router)
            _update_isl_trunk_vlan(router.vlan_id, add=True)
            if switch_port:
                _set_isp_router_port(switch_port, router)
            flash(
                f'ISP router "{name}" added. '
                f'⚠ Set the router LAN IP to {router.gateway_ip} and add a '
                f'static route: Target 192.168.0.0 / Mask 255.255.0.0 / '
                f'Gateway 192.168.{vlan_id}.2 on the router.',
                'success'
            )
            return redirect(url_for('admin_isp_routers'))

        elif action == 'update':
            router = ISPRouter.query.get_or_404(request.form.get('router_id'))
            old_port = router.switch_port
            old_vlan_id = router.vlan_id
            old_pbr_name = router.pbr_name
            router.name = request.form.get('name', router.name).strip()
            # VLAN 1 (default gateway) is locked — never allow changing it
            if router.vlan_id != 1:
                try:
                    new_vlan_id = int(request.form.get('vlan_id', router.vlan_id))
                    if 2 <= new_vlan_id <= 7:
                        router.vlan_id = new_vlan_id
                except (ValueError, TypeError):
                    pass
            # Always derive subnet from VLAN ID
            router.subnet = f'192.168.{router.vlan_id}.0/24'
            new_port = request.form.get('switch_port', '').strip() or None
            router.switch_port = new_port
            router.dhcp_snooping_trust = (router.vlan_id == 1)
            db.session.commit()
            # If name changed, remove the old PBR entries from all switches
            if old_pbr_name != router.pbr_name:
                _remove_isp_router_pbr_from_switches(old_pbr_name)
            # If VLAN ID changed, explicitly undo the old next-hop in the PBR
            # permit node before rebuilding, then remove the stale VLAN/interface
            vlan_changed = old_vlan_id != router.vlan_id
            if vlan_changed:
                old_gateway_ip = f'192.168.{old_vlan_id}.1'
                switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
                switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
                for host in switch_hosts:
                    _run_switch_command(host, _build_pbr_undo_next_hop(router.pbr_name, old_gateway_ip))
                _remove_isp_router_vlan_from_switches(old_vlan_id)
            # Clear the old port if it changed
            if old_port and old_port != new_port:
                _clear_isp_router_port(old_port)
            # Create the new VLAN/interface/PBR BEFORE configuring the port,
            # so that 'port access vlan N' succeeds on an existing VLAN
            _apply_isp_router_to_switches(router)
            # Now configure the port
            if new_port and new_port != old_port:
                _set_isp_router_port(new_port, router)
            elif new_port and new_port == old_port:
                if vlan_changed:
                    # The old VLAN removal leaves a stale port-security sticky MAC
                    # entry bound to the old VLAN.  Reset the port first to clear
                    # it, then re-apply the config with the new VLAN.
                    sw_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
                    sw_hosts = [h.strip() for h in sw_hosts_raw.split() if h.strip()]
                    for host in sw_hosts:
                        _run_switch_command(host, _build_reset_port_config(new_port))
                _set_isp_router_port(new_port, router)
            if vlan_changed:
                _update_isl_trunk_vlan(old_vlan_id, add=False)
            _update_isl_trunk_vlan(router.vlan_id, add=True)
            flash(f'ISP router "{router.name}" updated.', 'success')
            return redirect(url_for('admin_isp_routers'))

        elif action == 'delete':
            router = ISPRouter.query.get_or_404(request.form.get('router_id'))
            vlan_to_remove = router.vlan_id
            if router.switch_port:
                _clear_isp_router_port(router.switch_port)
            _remove_isp_router_from_switches(router)
            _update_isl_trunk_vlan(vlan_to_remove, add=False)
            db.session.delete(router)
            db.session.commit()
            flash(f'ISP router "{router.name}" deleted.', 'success')
            return redirect(url_for('admin_isp_routers'))

    routers = ISPRouter.query.order_by(ISPRouter.id).all()
    used_vlan_ids = {r.vlan_id for r in routers}
    # Populate port dropdown from the primary switch (first of SWITCH_HOSTS)
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    primary_host = switch_hosts[0] if switch_hosts else ''
    switch_ports_list = []
    if primary_host:
        rows = db.session.execute(
            text("""
                SELECT port_name FROM switch_ports
                WHERE switch_host = :host
                ORDER BY
                    (CASE WHEN port_name LIKE 'XGE%' THEN 1 ELSE 0 END),
                    split_part(port_name, '/', 1),
                    CAST(NULLIF(split_part(port_name, '/', 2), '') AS INTEGER),
                    CAST(NULLIF(split_part(port_name, '/', 3), '') AS INTEGER)
            """),
            {'host': primary_host}
        ).fetchall()
        switch_ports_list = [r[0] for r in rows]
    return render_template('admin_isp_routers.html', routers=routers,
                           switch_ports=switch_ports_list,
                           used_vlan_ids=used_vlan_ids)


@app.route('/admin/vlan-config', methods=['GET', 'POST'])
@login_required
@permission_required('manage_vlans')
def admin_vlan_config():
    """VLAN configuration page"""
    if request.method == 'POST':
        valid_vlan_ids = set(_parse_valid_vlan_ids())
        statuses = request.form.getlist('vlan_status')
        names = request.form.getlist('vlan_name')
        vlan_ids = request.form.getlist('vlan_id')
        ssids = request.form.getlist('vlan_ssid')
        wired_statuses = set(request.form.getlist('vlan_wired'))
        password_statuses = set(request.form.getlist('vlan_require_password'))
        remove_statuses = set(request.form.getlist('vlan_remove'))
        isp_router_ids = request.form.getlist('vlan_isp_router')  # positional, matches statuses

        warnings = []
        errors = []
        seen_statuses = set()
        seen_vlan_ids = set()
        pbr_changes = []  # list of (vlan_id, old_pbr_name_or_None, new_pbr_name_or_None)

        for index, status_raw in enumerate(statuses):
            status = (status_raw or '').strip().lower()
            if not status:
                continue

            if status in seen_statuses:
                warnings.append(f"Duplicate VLAN key skipped: {status}")
                continue
            seen_statuses.add(status)

            # wired_unregistered is hardcoded to VLAN 250 and must not be modified here
            if status == WIRED_UNREGISTERED_STATUS:
                continue

            if status in remove_statuses:
                mapping = VlanMapping.query.filter_by(status=status).first()
                if mapping:
                    db.session.delete(mapping)
                continue

            vlan_id_raw = vlan_ids[index] if index < len(vlan_ids) else ''
            try:
                vlan_id = int(vlan_id_raw)
            except (TypeError, ValueError):
                warnings.append(f"Invalid VLAN ID for {status}: {vlan_id_raw}")
                continue

            if valid_vlan_ids and vlan_id not in valid_vlan_ids:
                warnings.append(f"VLAN {vlan_id} not in VALID_VLANS; skipped {status}.")
                continue

            if vlan_id in seen_vlan_ids:
                errors.append(f"Duplicate VLAN ID {vlan_id} used by {status}.")
                continue
            seen_vlan_ids.add(vlan_id)

            display_name = (names[index] if index < len(names) else '').strip()
            if not display_name:
                display_name = status.title()

            ssid = (ssids[index] if index < len(ssids) else '').strip() or None
            wired_enabled = status in wired_statuses
            require_password = status in password_statuses

            # ISP router assignment
            isp_router_id_raw = isp_router_ids[index] if index < len(isp_router_ids) else ''
            new_isp_router_id = int(isp_router_id_raw) if isp_router_id_raw.strip().isdigit() else None

            mapping = VlanMapping.query.filter_by(status=status).first()
            if mapping:
                old_isp_router = mapping.isp_router
                new_isp_router = ISPRouter.query.get(new_isp_router_id) if new_isp_router_id else None
                if (mapping.isp_router_id or None) != (new_isp_router_id or None):
                    pbr_changes.append((
                        vlan_id,
                        old_isp_router.pbr_name if old_isp_router else None,
                        new_isp_router.pbr_name if new_isp_router else None,
                    ))
                mapping.vlan_id = vlan_id
                mapping.display_name = display_name
                mapping.ssid = ssid
                mapping.wired_enabled = wired_enabled
                mapping.require_password = require_password
                mapping.isp_router_id = new_isp_router_id
            else:
                mapping = VlanMapping(
                    status=status,
                    vlan_id=vlan_id,
                    display_name=display_name,
                    ssid=ssid,
                    wired_enabled=wired_enabled,
                    require_password=require_password,
                    isp_router_id=new_isp_router_id,
                )
                db.session.add(mapping)

        prefix_by_status = {}
        prefix_changed = False
        changed_statuses = []
        for status in POOL_PREFIX_STATUSES:
            previous_raw = Setting.get_value(f'vlan_prefix_{status}', '24')
            try:
                previous_prefix = int(previous_raw)
            except (TypeError, ValueError):
                previous_prefix = 24
            if previous_prefix not in POOL_PREFIX_CHOICES:
                previous_prefix = 24
            raw = request.form.get(f'prefix_{status}', '24')
            try:
                prefix = int(raw)
            except (TypeError, ValueError):
                prefix = 24
            if prefix not in POOL_PREFIX_CHOICES:
                prefix = 24
            if prefix != previous_prefix:
                prefix_changed = True
                changed_statuses.append(status)
            Setting.set_value(f'vlan_prefix_{status}', str(prefix))
            prefix_by_status[status] = prefix

        if errors:
            db.session.rollback()
            for message in errors:
                flash(message, 'error')
            return redirect(url_for('admin_vlan_config'))

        db.session.commit()

        # Push PBR changes to all switches
        if pbr_changes:
            switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
            switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
            for (pbr_vlan_id, old_pbr, new_pbr) in pbr_changes:
                for host in switch_hosts:
                    if new_pbr:
                        # _build_vlan_pbr_assign already issues 'undo ip policy-based-route'
                        # before the assign, so a separate remove call is not needed.
                        _run_switch_command(host, _build_vlan_pbr_assign(pbr_vlan_id, new_pbr))
                    elif old_pbr:
                        # Router removed entirely — just undo with the known name.
                        _run_switch_command(host, _build_vlan_pbr_remove(pbr_vlan_id, old_pbr))
            flash('ISP router PBR assignments pushed to switches.', 'success')

        vlan_map = get_vlan_map()
        vlan_prefix_by_id = {}
        changed_vlan_ids = []
        for status, prefix in prefix_by_status.items():
            vlan_id = vlan_map.get(status)
            if vlan_id:
                vlan_prefix_by_id[vlan_id] = prefix
                if status in changed_statuses:
                    changed_vlan_ids.append(vlan_id)

        warnings = warnings or []
        try:
            _update_kea_config(vlan_prefix_by_id)
            restarted, message = _restart_kea_container()
            if restarted:
                flash('VLAN configuration updated and Kea restarted.', 'success')
            else:
                flash('VLAN configuration updated, but Kea restart failed.', 'warning')
                warnings.append(message)
        except Exception as exc:
            flash('VLAN configuration updated, but Kea config update failed.', 'warning')
            warnings.append(str(exc))

        if prefix_changed:
            acl_ok = reset_acl_baseline()
            if acl_ok:
                flash('Switch ACL baseline updated for new subnet sizes.', 'success')
            else:
                flash('Switch ACL baseline update failed.', 'warning')

            iface_ok = reset_vlan_interface_masks(changed_vlan_ids)
            if iface_ok:
                flash('Switch VLAN interface masks updated.', 'success')
            else:
                flash('Switch VLAN interface mask update failed.', 'warning')

            pi_ok = reset_pi_network_masks(changed_vlan_ids)
            if pi_ok:
                flash('Pi VLAN interface masks updated.', 'success')
            else:
                flash('Pi VLAN interface mask update failed.', 'warning')

        for message in warnings:
            flash(message, 'warning')

        logger.info("Admin updated VLAN configuration")

        return redirect(url_for('admin_vlan_config'))
    
    # Load current configuration
    vlan_map = get_vlan_map()
    prefix_map = _get_vlan_prefix_map()
    vlan_entries = [e for e in get_vlan_entries() if e.status != WIRED_UNREGISTERED_STATUS]
    valid_vlan_ids = _parse_valid_vlan_ids()
    isp_routers = ISPRouter.query.order_by(ISPRouter.id).all()
    return render_template(
        'admin_vlan_config.html',
        vlan_map=vlan_map,
        vlan_entries=vlan_entries,
        valid_vlan_ids=valid_vlan_ids,
        fixed_statuses=FIXED_VLAN_STATUSES,
        prefix_map=prefix_map,
        prefix_choices=POOL_PREFIX_CHOICES,
        prefix_statuses=POOL_PREFIX_STATUSES,
        isp_routers=isp_routers,
    )


@app.route('/admin', strict_slashes=False)
@login_required
def admin_dashboard():
    """Admin dashboard with MAC address management, pagination, and search"""
    # Check if user has any permissions
    if not current_user.can_manage_users and not current_user.can_manage_vlans and not current_user.can_view_traffic and not current_user.can_manage_admins:
        return redirect(url_for('admin_no_permissions'))
    
    # If user doesn't have manage_users permission, redirect to appropriate page
    if not current_user.can_manage_users:
        if current_user.can_manage_vlans:
            return redirect(url_for('admin_vlan_config'))
        elif current_user.can_view_traffic:
            return redirect(url_for('admin_traffic'))
        elif current_user.can_manage_admins:
            return redirect(url_for('admin_manage_admins'))
    
    # Get pagination and search parameters
    pending_page = request.args.get('pending_page', 1, type=int)
    pending_per_page = request.args.get('pending_per_page', 25, type=int)
    pending_search = request.args.get('pending_search', '', type=str).strip().lower()
    pending_sort = request.args.get('pending_sort', 'submitted_at')
    pending_order = request.args.get('pending_order', 'desc')
    
    users_page = request.args.get('users_page', 1, type=int)
    users_per_page = request.args.get('users_per_page', 25, type=int)
    users_search = request.args.get('users_search', '', type=str).strip().lower()
    users_sort = request.args.get('users_sort', 'email')
    users_order = request.args.get('users_order', 'asc')
    
    devices_page = request.args.get('devices_page', 1, type=int)
    devices_per_page = request.args.get('devices_per_page', 25, type=int)
    devices_search = request.args.get('devices_search', '', type=str).strip().lower()
    devices_sort = request.args.get('devices_sort', 'first_seen')
    devices_order = request.args.get('devices_order', 'desc')
    
    # Get pending registration requests grouped by MAC address
    all_pending = RegistrationRequest.query.filter_by(status='pending')\
        .order_by(RegistrationRequest.submitted_at.desc()).all()
    
    # Group requests by MAC address
    grouped_requests = {}
    for req in all_pending:
        mac = req.mac_address
        if mac not in grouped_requests:
            grouped_requests[mac] = {
                'mac_address': mac,
                'latest_request': req,  # Most recent due to ordering
                'email': req.email,
                'first_name': req.first_name,
                'last_name': req.last_name,
                'phone_number': req.phone_number,
                'device_type': req.device_type,
                'approval_token': req.approval_token,
                'submitted_times': [req.submitted_at],
                'ip_addresses': [req.ip_address] if req.ip_address else []
            }
        else:
            # Add additional submission times and IPs
            grouped_requests[mac]['submitted_times'].append(req.submitted_at)
            if req.ip_address and req.ip_address not in grouped_requests[mac]['ip_addresses']:
                grouped_requests[mac]['ip_addresses'].append(req.ip_address)
    
    # Convert to list
    all_pending_list = list(grouped_requests.values())
    
    # Filter pending requests by search
    if pending_search:
        all_pending_list = [r for r in all_pending_list if 
                           pending_search in r['email'].lower() or
                           pending_search in r['first_name'].lower() or
                           pending_search in r['last_name'].lower() or
                           pending_search in (r['phone_number'] or '').lower() or
                           pending_search in r['mac_address'].lower() or
                           pending_search in (r['device_type'] or '').lower()]
    
    # Sort pending requests
    reverse_order = (pending_order == 'desc')
    if pending_sort == 'submitted_at':
        all_pending_list.sort(key=lambda x: x['submitted_times'][0], reverse=reverse_order)
    elif pending_sort == 'name':
        all_pending_list.sort(key=lambda x: f"{x['first_name']} {x['last_name']}".lower(), reverse=reverse_order)
    elif pending_sort == 'email':
        all_pending_list.sort(key=lambda x: x['email'].lower(), reverse=reverse_order)
    elif pending_sort == 'phone':
        all_pending_list.sort(key=lambda x: (x['phone_number'] or '').lower(), reverse=reverse_order)
    elif pending_sort == 'device_type':
        all_pending_list.sort(key=lambda x: (x['device_type'] or '').lower(), reverse=reverse_order)
    elif pending_sort == 'mac_address':
        all_pending_list.sort(key=lambda x: x['mac_address'].lower(), reverse=reverse_order)
    
    # Paginate pending requests
    pending_total = len(all_pending_list)
    pending_start = (pending_page - 1) * pending_per_page
    pending_end = pending_start + pending_per_page
    pending_requests = all_pending_list[pending_start:pending_end]
    pending_pages = (pending_total + pending_per_page - 1) // pending_per_page if pending_per_page > 0 else 0
    
    # Get all users with search filter
    users_query = User.query
    if users_search:
        # Search in user fields OR in their devices' MAC addresses
        users_query = users_query.outerjoin(Device).filter(
            db.or_(
                User.email.ilike(f'%{users_search}%'),
                User.first_name.ilike(f'%{users_search}%'),
                User.last_name.ilike(f'%{users_search}%'),
                User.phone_number.ilike(f'%{users_search}%'),
                User.allowed_vlans_override.ilike(f'%{users_search}%'),
                User.allowed_vlans_deny.ilike(f'%{users_search}%'),
                User.adoptable_vlans_override.ilike(f'%{users_search}%'),
                User.adoptable_vlans_deny.ilike(f'%{users_search}%'),
                Device.mac_address.ilike(f'%{users_search}%')
            )
        )
    
    # Apply sorting to users - must be before distinct() to work properly
    # Validate sort column exists on User model
    valid_user_sorts = ['email', 'first_name', 'last_name', 'begin_date', 'expiry_date', 'created_at', 'phone_number']
    if users_sort not in valid_user_sorts:
        users_sort = 'email'
    
    sort_column = getattr(User, users_sort)
    if users_order == 'desc':
        users_query = users_query.order_by(sort_column.desc())
    else:
        users_query = users_query.order_by(sort_column.asc())
    
    # Apply distinct after ordering
    if users_search:
        users_query = users_query.distinct()
    
    users_total = users_query.count()
    users = users_query.offset((users_page - 1) * users_per_page).limit(users_per_page).all()
    users_pages = (users_total + users_per_page - 1) // users_per_page if users_per_page > 0 else 0

    vlan_map = get_vlan_map()
    prefix_by_id = _get_vlan_prefix_by_id()
    lease_counts = _load_active_lease_counts()
    lease_stats = []
    for entry in get_vlan_entries():
        vlan_id = entry.vlan_id
        if not vlan_id:
            continue
        prefix = prefix_by_id.get(vlan_id, 24)
        try:
            network = ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{prefix}", strict=False)
            subnet_cidr = str(network)
        except Exception:
            subnet_cidr = f"192.168.{vlan_id}.0/{prefix}"
        display_name = (entry.display_name or entry.status or '').strip()
        if not display_name:
            display_name = f"VLAN {vlan_id}"
        lease_stats.append({
            'status': entry.status,
            'display_name': display_name,
            'vlan_id': vlan_id,
            'subnet': subnet_cidr,
            'active_leases': lease_counts.get(vlan_id, 0),
        })
    lease_stats.sort(key=lambda entry: entry['vlan_id'])
    domain_policy_map = _load_domain_policy_map()
    for user in users:
        domain_policy = domain_policy_map.get(_email_domain(user.email))
        user.allowed_vlans_display_items = _allowed_vlans_display_items(user, vlan_map, domain_policy, include_denied=True)
        user.adoptable_vlans_display_items = _adoptable_vlans_display_items(user, vlan_map, domain_policy, include_denied=True)
    
    # Get devices with their users for display with search filter
    devices_query = db.session.query(Device, User).join(User, Device.user_id == User.id, isouter=True)
    
    if devices_search:
        devices_query = devices_query.filter(
            db.or_(
                Device.mac_address.ilike(f'%{devices_search}%'),
                Device.device_name.ilike(f'%{devices_search}%'),
                Device.connection_type.ilike(f'%{devices_search}%'),
                Device.ssid.ilike(f'%{devices_search}%'),
                Device.registration_status.ilike(f'%{devices_search}%'),
                User.email.ilike(f'%{devices_search}%'),
                User.first_name.ilike(f'%{devices_search}%'),
                User.last_name.ilike(f'%{devices_search}%')
            )
        )
    
    # Apply sorting to devices
    if devices_sort == 'user_name':
        # Sort by user's first name
        if devices_order == 'desc':
            devices_query = devices_query.order_by(User.first_name.desc())
        else:
            devices_query = devices_query.order_by(User.first_name.asc())
    elif devices_sort == 'user_email':
        # Sort by user's email
        if devices_order == 'desc':
            devices_query = devices_query.order_by(User.email.desc())
        else:
            devices_query = devices_query.order_by(User.email.asc())
    else:
        # Sort by device field
        sort_column = getattr(Device, devices_sort, Device.first_seen)
        if devices_order == 'desc':
            devices_query = devices_query.order_by(sort_column.desc())
        else:
            devices_query = devices_query.order_by(sort_column.asc())
    
    devices_total = devices_query.count()
    devices = devices_query.offset((devices_page - 1) * devices_per_page).limit(devices_per_page).all()

    # Refresh IPs from Kea lease file for devices on the current page
    ip_updated = False
    kea = get_kea()
    for row in devices:
        device = row
        # Unwrap SQLAlchemy Row (Device, User) tuples
        if not hasattr(device, "mac_address"):
            try:
                device = row[0]
            except Exception:
                device = row

        if device and getattr(device, "mac_address", None):
            latest_ip = None
            if kea:
                try:
                    latest_ip = kea.get_lease_ip_for_mac(device.mac_address, subnet_id=device.current_vlan)
                    logger.info(
                        "Dashboard IP refresh (Kea socket): MAC=%s lease_ip=%s",
                        device.mac_address,
                        latest_ip,
                    )
                except Exception as e:
                    logger.error(f"Error querying Kea lease for {device.mac_address}: {e}")
            if not latest_ip:
                latest_ip = get_ip_for_mac(device.mac_address, subnet_id=device.current_vlan)
                logger.info(
                    "Dashboard IP refresh (fallback): MAC=%s lease_ip=%s",
                    device.mac_address,
                    latest_ip,
                )
            if latest_ip and latest_ip != device.ip_address:
                device.ip_address = latest_ip
                ip_updated = True
    if ip_updated:
        db.session.commit()
        cleanup_orphan_hijack_rules()
    devices_pages = (devices_total + devices_per_page - 1) // devices_per_page if devices_per_page > 0 else 0

    unregistered_leases = UnregisteredLease.query.order_by(UnregisteredLease.expires_at.asc()).all()
    unregistered_total = len(unregistered_leases)
    
    # Check if this is an AJAX request
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Common template variables
    domain_policies = DomainPolicy.query.order_by(DomainPolicy.domain.asc()).all()
    for policy in domain_policies:
        policy.allowed_vlans_set = _parse_allowed_vlans(policy.allowed_vlans)
        policy.adoptable_vlans_set = _parse_allowed_vlans(policy.adoptable_vlans)

    # Load dashboard section visibility preferences
    _dash_settings = {}
    if current_user.traffic_viewer_settings:
        try:
            _dash_settings = json.loads(current_user.traffic_viewer_settings)
        except Exception:
            pass
    dashboard_hidden_sections = set(_dash_settings.get('dashboard_hidden_sections', []))

    template_vars = dict(
        devices=devices,
        devices_page=devices_page,
        devices_per_page=devices_per_page,
        devices_pages=devices_pages,
        devices_total=devices_total,
        devices_search=devices_search,
        devices_sort=devices_sort,
        devices_order=devices_order,
        users=users,
        users_page=users_page,
        users_per_page=users_per_page,
        users_pages=users_pages,
        users_total=users_total,
        users_search=users_search,
        users_sort=users_sort,
        users_order=users_order,
        pending_requests=pending_requests,
        pending_page=pending_page,
        pending_per_page=pending_per_page,
        pending_pages=pending_pages,
        pending_total=pending_total,
        pending_search=pending_search,
        pending_sort=pending_sort,
        pending_order=pending_order,
        unregistered_leases=unregistered_leases,
        unregistered_total=unregistered_total,
        vlan_map=vlan_map,
        wired_vlan_choices=[
            {
                'vlan_id': entry.vlan_id,
                'label': _label_for_vlan(entry.vlan_id, vlan_map),
            }
            for entry in _get_admin_assignable_entries()
        ],
        lease_stats=lease_stats,
        domain_policies=domain_policies,
        test_env=is_test_env(),
        dashboard_hidden_sections=dashboard_hidden_sections
    )
    
    # For AJAX requests, determine which table section to render
    if is_ajax:
        # Check which table is being sorted based on ajax_table parameter
        ajax_table = request.args.get('ajax_table', '')
        if ajax_table == 'pending':
            return render_template('partials/pending_table.html', **template_vars)
        elif ajax_table == 'users':
            return render_template('partials/users_table.html', **template_vars)
        elif ajax_table == 'devices':
            return render_template('partials/devices_table.html', **template_vars)
    
    # For regular requests, render the full page
    return render_template('admin_dashboard.html', **template_vars)


@app.route('/admin/save-dashboard-prefs', methods=['POST'])
@login_required
def admin_save_dashboard_prefs():
    """Save per-admin dashboard section visibility preferences."""
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
# Switch Port Management
# ---------------------------------------------------------------------------

PORT_ROLES = {
    'ap':           'AP Uplink',
    'wired':        'Wired Device',
    'pi':           'Pi / Kea',
    'inter_switch': 'Inter-Switch Link',
    'uplink_udm':   'Uplink to Router',
    'unknown':      'Unclassified',
}


def _run_switch_command(host, command):
    """Run a single command on an HP5130 switch via the system ssh binary.
    Uses the same SSH options as hp5130-port-lookup.sh / hp5130-replug.sh so
    the old RSA host-key algorithms negotiate correctly.
    Returns the command output as a string, or None on failure.
    """
    import subprocess

    switch_user = os.getenv('SWITCH_USER', 'robert')
    switch_port = os.getenv('SWITCH_SSH_PORT', '22')
    switch_key  = os.getenv('SWITCH_KEY_PATH', '')

    ssh_args = [
        'ssh',
        '-tt',
        '-i', switch_key,
        '-p', switch_port,
        '-o', 'HostKeyAlgorithms=+ssh-rsa',
        '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=5',
        '-o', 'ServerAliveCountMax=3',
        f'{switch_user}@{host}',
    ]

    try:
        result = subprocess.run(
            ssh_args,
            input=f'{command}\nquit\n',
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode != 0:
            logger.warning("SSH to %s exited %d: %s", host, result.returncode,
                           result.stderr.strip()[:200])
        return result.stdout if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        logger.warning("SSH command timed out for %s", host)
        return None
    except Exception as e:
        logger.warning("SSH command failed for %s: %s", host, e)
        return None


def _get_switch_ssh_client_for_host(host):
    """Push a multi-line config command block to a switch.
    Wraps _run_switch_command for callers that previously used paramiko.
    Returns a simple object with an exec_command-style interface, or None.
    """
    # Return a thin wrapper so existing call-sites in admin_switch_ports_update
    # can be replaced without touching the call-sites.  New code should call
    # _run_switch_command() directly.
    class _SshWrapper:
        def __init__(self, h): self._host = h
        def send_commands(self, cmds):
            """cmds: list of str"""
            block = '\n'.join(cmds)
            return _run_switch_command(self._host, block)
        def close(self): pass

    # Quick connectivity check
    if _run_switch_command(host, 'display version') is None:
        return None
    return _SshWrapper(host)


def _detect_port_role(port_name, description):
    """Infer a port role from its name and description using keyword heuristics."""
    desc = (description or '').lower()
    name = (port_name or '').upper()

    if 'udm' in desc or 'usg' in desc:
        return 'uplink_udm'
    # "Uplink to UniFi AP", "AP-uplink", " AP" suffix, etc.
    if ('unifi' in desc and 'ap' in desc) or \
       desc.endswith(' ap') or ' ap ' in desc or \
       '-ap' in desc or desc.startswith('ap'):
        return 'ap'
    if 'pi' in desc or 'kea' in desc or 'portal' in desc:
        return 'pi'
    # Only classify as inter-switch if the description explicitly says so
    if 'inter-switch' in desc or 'inter switch' in desc or 'isl' in desc:
        return 'inter_switch'
    # Ports with a non-empty description that didn't match above → wired
    if desc.strip():
        return 'wired'
    # No description (including XGE ports) → unclassified
    return 'unknown'


def _discover_switch_ports(switch_host):
    """SSH to switch_host and return a list of port dicts.

    Three-phase, pagination-safe strategy for HP5130/Comware 7:

    Phase 1 – slot detection (1 SSH call, ≤8 one-liner queries, never paginates):
      'display current-configuration | include interface | include GigabitEthernetN/0/1'
      for N=1..8.  Even if the port list paginates, at least one line comes back before
      '---- More ----', so we can identify which slots exist.

    Phase 2 – port existence & link state (1 SSH call):
      'display interface GigabitEthernetN/0/n | include current state'
      Each command returns exactly 1 result line (or an error).  Result lines are
      self-identifying (they contain the full port name), so no alignment needed.

    Phase 3 – descriptions (1 SSH call, existing ports only):
      'display interface GigabitEthernetN/0/n | include Description'
      Ports with no configured description return *no* output for this filter.
      We split the raw output on prompt patterns to get per-command sections and
      map them back to the ordered port list.

    Returns: [{'port_name': str, 'link_status': str, 'description': str}]
    """
    import re

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
        """Split raw -tt SSH output into one section per command sent.
        Each section contains the output lines produced by that command
        (the command echo itself is stripped).
        Returns a list of strings (one element per command).
        """
        # Prompts look like '<AccessSW-01>' – split on them
        parts = re.split(r'<[A-Za-z][^>\n]{0,40}>', output)
        sections = []
        for part in parts[1:]:   # parts[0] is the initial banner
            lines = part.replace('\r', '').split('\n')
            # lines[0] is the command echo; the rest is command output
            body = '\n'.join(l for l in lines[1:] if l.strip())
            sections.append(body)
        return sections

    max_slot = int(os.getenv('SWITCH_MAX_SLOT', '8'))
    ge_max   = int(os.getenv('SWITCH_GE_MAX',   '52'))
    xge_max  = int(os.getenv('SWITCH_XGE_MAX',  '4'))

    # ------------------------------------------------------------------ Phase 1
    # Detect which slots have GE ports.  Each query returns ≤12 lines (port X,
    # X0..X9) so will never hit the '---- More ----' limit.
    slot_cmds = '\n'.join(
        f'display current-configuration | include interface | include GigabitEthernet{s}/0/1'
        for s in range(1, max_slot + 1)
    )
    slot_output = _run_switch_command(switch_host, slot_cmds)
    detected_slots = set()
    for line in (slot_output or '').splitlines():
        # Only match actual config lines, not the echoed command itself
        # Real lines look like: "interface GigabitEthernet3/0/1"
        # Echoed command lines look like: "<SW>display ... GigabitEthernet3/0/1"
        stripped = line.strip()
        if stripped.startswith('interface GigabitEthernet'):
            m = re.search(r'GigabitEthernet(\d+)/', stripped)
            if m:
                detected_slots.add(int(m.group(1)))

    if not detected_slots:
        logger.warning("No switch slots detected on %s", switch_host)
        return []

    logger.info("Detected slots on %s: %s", switch_host, sorted(detected_slots))

    # ------------------------------------------------------------------ Phase 2
    # Probe every candidate port with '| include state' (single-word filter;
    # HP5130 rejects multi-word patterns like 'current state').
    # Existing ports return  "Current state: UP/DOWN/…"
    # Non-existent ports     return  "% Wrong parameter found…"
    # We split raw SSH output on prompt lines to align sections with candidates.
    candidates = []
    for s in sorted(detected_slots):
        for n in range(1, ge_max + 1):
            candidates.append(f'GigabitEthernet{s}/0/{n}')
        # HP5130 numbers XGE ports in the same range as GE (e.g. 25-28 on a 24-port
        # model, 49-52 on a 48-port model) so we must probe up to ge_max.
        # Non-existent ports are already skipped via the '% Wrong' error check.
        for n in range(1, ge_max + 1):
            candidates.append(f'Ten-GigabitEthernet{s}/0/{n}')

    state_cmds = '\n'.join(
        f'display interface {full} | include state'
        for full in candidates
    )
    state_raw = _run_switch_command(switch_host, state_cmds) or ''
    state_sections = _split_by_prompts(state_raw)

    existing = {}   # full_name -> link_status string
    for i, full_name in enumerate(candidates):
        if i >= len(state_sections):
            break
        section = state_sections[i]
        if '% ' in section or 'Wrong' in section or 'Error' in section:
            continue  # port does not exist on this switch
        m = re.search(r'Current state:\s*(\S+)', section, re.IGNORECASE)
        link = m.group(1).upper() if m else 'UNKNOWN'
        existing[full_name] = link

    if not existing:
        logger.warning("No ports found via state probe on %s", switch_host)
        return []

    sorted_existing = sorted(existing.keys(), key=_iface_sort_key)
    logger.info("Found %d physical ports on %s", len(sorted_existing), switch_host)

    # ------------------------------------------------------------------ Phase 3
    # Fetch descriptions for existing ports.  Ports with no configured description
    # return *nothing* from '| include Description', so we split on prompts to
    # get per-command output sections and map them back by position.
    desc_cmds = '\n'.join(
        f'display interface {full} | include Description'
        for full in sorted_existing
    )
    desc_raw = _run_switch_command(switch_host, desc_cmds) or ''
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
        # Drop uninformative Comware default "GigabitEthernetX/Y/Z Interface"
        if desc.endswith(' Interface') and 'Ethernet' in desc:
            desc = ''
        ports.append({
            'port_name':   _shorten(full_name),
            'link_status': existing[full_name],
            'description': desc,
        })

    logger.info("Discovered %d ports on %s", len(ports), switch_host)
    return ports


def _refresh_switch_ports():
    """Discover all switches and upsert ports into switch_ports table.
    Preserves manually-set roles (only auto-assigns when role is 'unknown').
    Returns dict: {switch_host: port_count_or_error_string}
    """
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    if not switch_hosts:
        return {}

    results = {}
    with app.app_context():
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
                            -- Preserve a manually-set role; only auto-update 'unknown'
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


def _startup_switch_discovery():
    """Trigger switch port discovery in a background thread shortly after startup.
    Uses a postgres advisory lock so only one gunicorn worker does the work.
    Skips if the switch_ports table already has data less than 24 h old.
    """
    import threading
    import time as _time

    def _run():
        # Stagger workers slightly using PID to reduce the startup race window.
        _time.sleep(5 + (os.getpid() % 4))
        with app.app_context():
            try:
                # Only one worker across all gunicorn processes should run discovery.
                lock_acquired = db.session.execute(
                    text("SELECT pg_try_advisory_lock(99001)")
                ).scalar()
                if not lock_acquired:
                    logger.info("Switch discovery lock held by another worker, skipping")
                    return
                cutoff = datetime.utcnow() - timedelta(hours=24)
                fresh = db.session.execute(
                    text("SELECT 1 FROM switch_ports WHERE last_discovered > :cutoff LIMIT 1"),
                    {'cutoff': cutoff}
                ).fetchone()
                if fresh:
                    logger.info("Switch port discovery skipped – data is already fresh")
                    db.session.execute(text("SELECT pg_advisory_unlock(99001)"))
                    db.session.commit()
                    return
            except Exception:
                pass   # table might not exist yet; proceed anyway
        logger.info("Background switch port discovery starting…")
        try:
            results = _refresh_switch_ports()
            for host, result in results.items():
                logger.info("Switch discovery %s: %s", host, result)
        except Exception as e:
            logger.warning("Background switch port discovery error: %s", e)
        finally:
            try:
                with app.app_context():
                    db.session.execute(text("SELECT pg_advisory_unlock(99001)"))
                    db.session.commit()
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()


@app.route('/admin/switch-ports')
@login_required
@permission_required('manage_switch_ports')
def admin_switch_ports():
    """Switch port management page."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]

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


@app.route('/admin/switch-ports/refresh', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def admin_switch_ports_refresh():
    """Re-discover ports from all switches and redirect back."""
    results = _refresh_switch_ports()
    for host, result in results.items():
        if isinstance(result, int):
            flash(f"{host}: discovered {result} ports", 'success')
        else:
            flash(f"{host}: {result}", 'warning')
    return redirect(url_for('admin_switch_ports'))


def _build_port_config(port_name, role, description=''):
    """Build the complete HP5130 config command block for a given port role.
    Uses the existing description if provided, otherwise falls back to a
    canonical default for the role.
    Returns a newline-joined string ready to pass to _run_switch_command().
    """
    expanded = _expand_switch_iface_name(port_name)

    CANONICAL_DESC = {
        'ap':           'Uplink to UniFi AP',
        'wired':        'wired port',
        'pi':           'TRUNK-TO-PI-Kea',
        'inter_switch': 'Inter-switch link',
        'uplink_udm':   'TRUNK-TO-UDM',
        'unknown':      '',
    }
    desc = (description or '').strip() or CANONICAL_DESC.get(role, '')

    head = ['system-view', f'interface {expanded}']
    if desc:
        head.append(f'description {desc}')

    if role == 'wired':
        body = [
            'port link-type hybrid',
            'undo port hybrid vlan 1',
            'port hybrid vlan 10 20 30 40 50 60 70 80 90 99 untagged',
            'port hybrid vlan 250 untagged',
            'port hybrid pvid vlan 250',
            'mac-vlan enable',
            'ip verify source ip-address mac-address',
            'mac-authentication max-user 16',
            'mac-authentication domain macauth',
            'mac-authentication guest-vlan 250',
            'mac-authentication host-mode multi-vlan',
            'port-security port-mode mac-authentication',
            'dhcp snooping binding record',
            'dhcp snooping check mac-address',
        ]
    elif role == 'ap':
        body = [
            'port link-type hybrid',
            'port hybrid vlan 10 20 30 40 50 60 70 99 tagged',
            'port hybrid vlan 1 untagged',
            'mac-authentication max-user 256',
            'mac-authentication domain macauth',
            'mac-authentication host-mode multi-vlan',
            'dhcp snooping check mac-address',
        ]
    elif role == 'pi':
        body = [
            'port link-type trunk',
            'undo port trunk permit vlan 1',
            'port trunk permit vlan 10 20 30 40 50 60 70 80 90 99',
            'port trunk permit vlan 250',
            'port trunk pvid vlan 1028',
            'arp detection trust',
            'dhcp snooping trust',
        ]
    elif role == 'uplink_udm':
        body = [
            'dhcp snooping trust',
        ]
    elif role == 'inter_switch':
        # ISP router VLANs go on their own permit line (separate from user VLANs)
        try:
            isp_vlan_ids = [str(r.vlan_id) for r in ISPRouter.query.order_by(ISPRouter.vlan_id).all()]
        except Exception:
            isp_vlan_ids = ['1']
        isp_vlan_str = ' '.join(isp_vlan_ids) if isp_vlan_ids else '1'
        body = [
            'port link-type trunk',
            'port trunk permit vlan 10 20 30 40 50 60 70 80 90',
            'port trunk permit vlan 99 250',
            f'port trunk permit vlan {isp_vlan_str}',
            'port trunk pvid vlan 1028',
            'arp detection trust',
            'dhcp snooping trust',
        ]
    else:  # unknown – description only
        body = []

    return '\n'.join(head + body + ['quit', 'quit', 'save force'])


# ---------------------------------------------------------------------------
# ISP Router HP5130 Config Helpers
# ---------------------------------------------------------------------------

def _build_isp_router_switch_config(router, switch_host):
    """Generate HP5130 config for an ISP router uplink VLAN, interface, and PBR."""
    last_octet = switch_host.split('.')[-1]
    host_ip = f"192.168.{router.vlan_id}.{last_octet}"
    pbr_name = router.pbr_name
    name_upper = router.name.upper().replace(' ', '_')
    lines = [
        'system-view',
        f'vlan {router.vlan_id}',
        f' description UPLINK-TO-{name_upper}',
        'quit',
        f'dhcp snooping enable vlan {router.vlan_id}',
        f'interface Vlan-interface{router.vlan_id}',
        f' description UPLINK-TO-{name_upper}',
        f' ip address {host_ip} 255.255.255.0',
        'quit',
        'acl advanced 3001',
        ' description PBR-local-traffic-normal-routing',
        ' rule 10 permit ip any 192.168.0.0 0.0.255.255',
        'quit',
        # Undo the whole PBR first so stale nodes/next-hops don't accumulate
        f'undo policy-based-route {pbr_name}',
        f'policy-based-route {pbr_name} deny node 5',
        ' if-match acl 3001',
        'quit',
        f'policy-based-route {pbr_name} permit node 10',
        f' apply next-hop {router.gateway_ip}',
        'quit',
        'quit',
        'save force',
    ]
    return '\n'.join(lines)


def _build_vlan_pbr_assign(vlan_id, pbr_name):
    """Add a PBR to a user VLAN interface on the switch.
    Always undoes any existing PBR first — HP5130 requires this before
    assigning a different (or the same) PBR.
    """
    return '\n'.join([
        'system-view',
        f'interface Vlan-interface{vlan_id}',
        ' undo ip policy-based-route',
        f' ip policy-based-route {pbr_name}',
        'quit',
        'quit',
        'save force',
    ])


def _build_vlan_pbr_remove(vlan_id, pbr_name):
    """Remove a PBR from a user VLAN interface on the switch."""
    return '\n'.join([
        'system-view',
        f'interface Vlan-interface{vlan_id}',
        f' undo ip policy-based-route {pbr_name}',
        'quit',
        'quit',
        'save force',
    ])


def _build_isp_router_port_config(port_name, router):
    """Configure an HP5130 port as a dedicated access uplink to an ISP router.
    Uses access mode (single VLAN) — no trunk needed for a point-to-point uplink.
    """
    expanded = _expand_switch_iface_name(port_name)
    name_upper = router.name.upper().replace(' ', '_')
    lines = [
        'system-view',
        f'interface {expanded}',
        f' description UPLINK-TO-{name_upper}',
        ' undo ip verify source',
        ' port link-type access',
        ' undo port access vlan',
        f' port access vlan {router.vlan_id}',
        ' dhcp snooping check mac-address',
        ' port-security max-mac-count 1',
        ' port-security port-mode autolearn',
        ' port-security intrusion-mode blockmac',
        ' port-security enable',
        'quit',
        'quit',
        'save force',
    ]
    return '\n'.join(lines)


def _build_remove_isp_router_pbr(pbr_name):
    """Undo the two PBR nodes for a given PBR name (used when router is renamed)."""
    return '\n'.join([
        'system-view',
        f'undo policy-based-route {pbr_name}',
        'quit',
        'save force',
    ])


def _build_pbr_undo_next_hop(pbr_name, old_gateway_ip):
    """Explicitly undo the apply next-hop within permit node 10 of a PBR.
    Required on HP5130 when the VLAN ID (and thus gateway IP) changes — the
    old next-hop must be removed before the new one is applied, even when the
    whole PBR will be rebuilt immediately after.
    """
    return '\n'.join([
        'system-view',
        f'policy-based-route {pbr_name} permit node 10',
        f' undo apply next-hop {old_gateway_ip}',
        'quit',
        'quit',
        'save force',
    ])


def _remove_isp_router_pbr_from_switches(pbr_name):
    """Push PBR removal for an old PBR name to all switches (e.g. after rename)."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    for host in switch_hosts:
        _run_switch_command(host, _build_remove_isp_router_pbr(pbr_name))


def _build_remove_isp_router_vlan(vlan_id):
    """Remove a stale ISP router VLAN and its Vlan-interface from the switch."""
    return '\n'.join([
        'system-view',
        f'undo interface Vlan-interface{vlan_id}',
        f'undo vlan {vlan_id}',
        f'undo dhcp snooping enable vlan {vlan_id}',
        'quit',
        'save force',
    ])


def _build_remove_isp_router_full(router):
    """Remove all switch config for an ISP router: PBR, Vlan-interface, VLAN."""
    pbr_name = router.pbr_name
    return '\n'.join([
        'system-view',
        f'undo policy-based-route {pbr_name}',
        f'undo interface Vlan-interface{router.vlan_id}',
        f'undo vlan {router.vlan_id}',
        f'undo dhcp snooping enable vlan {router.vlan_id}',
        'quit',
        'save force',
    ])


def _remove_isp_router_from_switches(router):
    """Push full ISP router removal config (PBR + VLAN + interface) to all switches."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    for host in switch_hosts:
        _run_switch_command(host, _build_remove_isp_router_full(router))


def _remove_isp_router_vlan_from_switches(old_vlan_id):
    """Remove a stale VLAN and its Vlan-interface from all switches."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    for host in switch_hosts:
        _run_switch_command(host, _build_remove_isp_router_vlan(old_vlan_id))


def _apply_isp_router_to_switches(router):
    """Push ISP router VLAN/interface/PBR config to all configured switches."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    failed = []
    for host in switch_hosts:
        cfg = _build_isp_router_switch_config(router, host)
        if _run_switch_command(host, cfg) is None:
            failed.append(host)
    if failed:
        flash(f'Switch config push failed for: {", ".join(failed)}', 'warning')


def _set_isp_router_port(port_name, router):
    """Mark switch port(s) as uplink_udm and push port config on all switches."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    for host in switch_hosts:
        db.session.execute(text("""
            UPDATE switch_ports
            SET port_role = 'uplink_udm', last_updated = NOW()
            WHERE switch_host = :host AND port_name = :port
        """), {'host': host, 'port': port_name})
        cfg = _build_isp_router_port_config(port_name, router)
        _run_switch_command(host, cfg)
    db.session.commit()


def _build_reset_port_config(port_name):
    """Reset an ISP router uplink port back to a plain default state."""
    expanded = _expand_switch_iface_name(port_name)
    return '\n'.join([
        'system-view',
        f'interface {expanded}',
        ' undo description',
        ' undo port access vlan',        
        ' undo port-security port-mode',
        ' undo port-security intrusion-mode',
        ' undo port-security max-mac-count',
        'quit',
        'quit',
        'save force',
    ])


def _build_isl_trunk_add_vlan(isl_port, vlan_id):
    """Add a VLAN to the inter-switch trunk port permit list."""
    return '\n'.join([
        'system-view',
        f'interface {isl_port}',
        f' port trunk permit vlan {vlan_id}',
        'quit',
        'quit',
        'save force',
    ])


def _build_isl_trunk_remove_vlan(isl_port, vlan_id):
    """Remove a VLAN from the inter-switch trunk port permit list."""
    return '\n'.join([
        'system-view',
        f'interface {isl_port}',
        f' undo port trunk permit vlan {vlan_id}',
        'quit',
        'quit',
        'save force',
    ])


def _update_isl_trunk_vlan(vlan_id, add=True):
    """Push ISL trunk VLAN add or remove to every switch, using the port
    recorded as inter_switch in the switch_ports table for that host."""
    rows = db.session.execute(text("""
        SELECT switch_host, port_name
        FROM switch_ports
        WHERE port_role = 'inter_switch'
    """)).fetchall()
    for switch_host, port_name in rows:
        expanded = _expand_switch_iface_name(port_name)
        cfg = (_build_isl_trunk_add_vlan(expanded, vlan_id)
               if add else _build_isl_trunk_remove_vlan(expanded, vlan_id))
        _run_switch_command(switch_host, cfg)


def _clear_isp_router_port(port_name):
    """Revert a switch port that was an ISP router uplink back to unknown and reset it on the switch."""
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    for host in switch_hosts:
        db.session.execute(text("""
            UPDATE switch_ports
            SET port_role = 'unknown', last_updated = NOW()
            WHERE switch_host = :host AND port_name = :port
              AND port_role = 'uplink_udm'
        """), {'host': host, 'port': port_name})
        _run_switch_command(host, _build_reset_port_config(port_name))
    db.session.commit()


def _get_isp_router_locked_ports():
    """Return {port_name: router_name} for all ISP routers that have a port assigned."""
    return {r.switch_port: r.name
            for r in ISPRouter.query.filter(ISPRouter.switch_port.isnot(None)).all()}


@app.route('/admin/switch-ports/update-single', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def admin_switch_ports_update_single():
    """AJAX endpoint: update one port's role and push full config to the switch."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON body'})

    host      = (data.get('host', '') or '').strip()
    port_name = (data.get('port', '') or '').strip()
    role      = (data.get('role', '') or '').strip()

    if not host or not port_name or role not in PORT_ROLES:
        return jsonify({'success': False, 'error': 'Invalid request'})

    # Block updates to ports locked as ISP router uplinks
    locked = _get_isp_router_locked_ports()
    if port_name in locked:
        return jsonify({'success': False,
                        'error': f'Port is locked as uplink to router "{locked[port_name]}". Change it via ISP Routers page.'})
    row = db.session.execute(
        text("SELECT port_description, port_role FROM switch_ports WHERE switch_host=:h AND port_name=:p"),
        {'h': host, 'p': port_name}
    ).fetchone()
    if not row:
        return jsonify({'success': False, 'error': 'Port not found in DB'})

    existing_desc, existing_role = row
    if existing_role == role:
        return jsonify({'success': True, 'message': 'No change needed'})

    cmds = _build_port_config(port_name, role, existing_desc)
    logger.info("Pushing config to %s %s (role=%s):\n%s", host, port_name, role, cmds)

    result = _run_switch_command(host, cmds)
    if result is None:
        return jsonify({'success': False, 'error': f'SSH to {host} failed'})

    db.session.execute(
        text("""
            UPDATE switch_ports
            SET port_role = :role, last_updated = NOW()
            WHERE switch_host = :host AND port_name = :name
        """),
        {'role': role, 'host': host, 'name': port_name}
    )
    db.session.commit()
    logger.info("Admin set %s %s → %s", host, port_name, role)
    return jsonify({'success': True})
@login_required
@permission_required('manage_switch_ports')
def admin_switch_ports_update():
    """Save role changes and push canonical descriptions back to the switches."""
    # Each radio button is named: role_<switch_host>_<port_name>
    # e.g.  role_192.168.99.2_GE1/0/17
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
        return redirect(url_for('admin_switch_ports'))

    # Canonical description pushed to the switch when role is set
    ROLE_DESC = {
        'ap':           'AP-UPLINK',
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
            continue  # no change

        db.session.execute(
            text("""
                UPDATE switch_ports
                SET port_role = :role, last_updated = NOW()
                WHERE switch_host = :host AND port_name = :name
            """),
            {'role': role, 'host': host, 'name': port_name}
        )
        changed += 1

        # Push canonical description to the switch
        desc = ROLE_DESC.get(role)
        if desc:
            expanded = _expand_switch_iface_name(port_name)
            cmds = '\n'.join([
                'system-view',
                f'interface {expanded}',
                f'description {desc}',
                'quit',
                'save force',
            ])
            try:
                result = _run_switch_command(host, cmds)
                if result is not None:
                    logger.info("Pushed description '%s' → %s %s", desc, host, expanded)
                else:
                    logger.warning("Failed to push description to %s %s", host, port_name)
            except Exception as e:
                logger.warning("Failed to push description to %s %s: %s", host, port_name, e)

    db.session.commit()

    if changed:
        flash(f'Updated {changed} port role(s).', 'success')
        logger.info("Admin updated %d switch port roles", changed)
    else:
        flash('No changes (selected roles already matched).', 'info')

    return redirect(url_for('admin_switch_ports'))


# ---------------------------------------------------------------------------

@app.route('/admin/traffic')
@login_required
@permission_required('view_traffic')
def admin_traffic():
    """Admin traffic viewer with NAT sessions enriched data"""
    import json
    
    # Available columns in nat_sessions_enriched view
    ALL_COLUMNS = [
        ('session_id', 'Session ID'),
        ('session_start', 'Start Time'),
        ('session_end', 'End Time'),
        ('src_ip', 'Source IP'),
        ('src_port', 'Source Port'),
        ('user_email', 'User Email'),
        ('user_first_name', 'First Name'),
        ('user_last_name', 'Last Name'),
        ('registration_status', 'Status'),
        ('dst_ip', 'Destination IP'),
        ('dst_port', 'Dest Port'),
        ('domain_name', 'Domain'),
        ('dns_query_count', 'DNS Queries'),
        ('packet_count', 'Packets'),
        ('duration_seconds', 'Duration (s)'),
        ('switch_iface', 'Switch Port'),
        ('src_mac', 'MAC Address'),
        ('switch_host', 'Switch IP'),
    ]
    
    valid_column_names = {col[0] for col in ALL_COLUMNS}
    
    # Load saved settings for current admin
    saved_settings = {}
    if current_user.traffic_viewer_settings:
        try:
            saved_settings = json.loads(current_user.traffic_viewer_settings)
        except Exception:
            saved_settings = {}
    
    # Check if we have query parameters (user is filtering/customizing)
    has_query_params = bool(
        request.args.get('columns') or 
        request.args.get('sort') or 
        request.args.get('order') or 
        request.args.get('per_page') or
        any(request.args.get(f'filter_{col[0]}') for col in ALL_COLUMNS)
    )
    
    # Get selected columns (priority: query params > saved settings > defaults)
    default_columns = ['session_start', 'src_ip', 'user_email', 'user_first_name', 'dst_ip', 'domain_name', 'packet_count', 'duration_seconds']
    if has_query_params:
        selected_columns = request.args.getlist('columns') or default_columns
    else:
        selected_columns = saved_settings.get('columns', default_columns)
    
    # Validate selected columns
    selected_columns = [col for col in selected_columns if col in valid_column_names]
    if not selected_columns:
        selected_columns = default_columns
    
    # Get filters for each column (priority: query params > saved settings)
    filters = {}
    for col_name, _ in ALL_COLUMNS:
        if has_query_params:
            filter_value = request.args.get(f'filter_{col_name}', '').strip()
        else:
            filter_value = saved_settings.get('filters', {}).get(col_name, '')
        if filter_value:
            filters[col_name] = filter_value
    
    # Pagination (priority: query params > saved settings > defaults)
    page = request.args.get('page', 1, type=int)
    if has_query_params and 'per_page' in request.args:
        per_page = request.args.get('per_page', 50, type=int)
    else:
        per_page = saved_settings.get('per_page', 50)
    per_page = min(max(per_page, 10), 500)  # Limit between 10 and 500
    
    # Sorting (priority: query params > saved settings > defaults)
    if has_query_params and ('sort' in request.args or 'order' in request.args):
        sort_col = request.args.get('sort', 'session_start')
        sort_order = request.args.get('order', 'desc')
    else:
        sort_col = saved_settings.get('sort_col', 'session_start')
        sort_order = saved_settings.get('sort_order', 'desc')
    
    if sort_col not in valid_column_names:
        sort_col = 'session_start'
    if sort_order not in ['asc', 'desc']:
        sort_order = 'desc'
    
    # Save current settings if we have query parameters
    if has_query_params:
        current_settings = {
            'columns': selected_columns,
            'filters': filters,
            'per_page': per_page,
            'sort_col': sort_col,
            'sort_order': sort_order
        }
        try:
            # Update the actual Admin model in database
            admin = Admin.query.get(int(current_user.id))
            if admin:
                admin.traffic_viewer_settings = json.dumps(current_settings)
                db.session.commit()
                # Update the current_user session object too
                current_user.traffic_viewer_settings = admin.traffic_viewer_settings
        except Exception as e:
            logger.warning(f"Failed to save traffic viewer settings: {e}")
    
    # Build SQL query
    # Always include session_id for uniqueness
    select_cols = ['session_id'] + [col for col in selected_columns if col != 'session_id']
    select_clause = ', '.join(select_cols)
    
    # Build WHERE clause from filters
    where_clauses = []
    params = {}
    param_counter = 0
    
    def _parse_date(s):
        """Parse a date string (YYYY-MM-DD or YYYY-MM-DD HH:MM) into a datetime object."""
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
            try:
                return datetime.strptime(s.strip(), fmt)
            except ValueError:
                continue
        return None

    for col_name, filter_value in filters.items():
        # Handle date range syntax: "2024-01-01 to 2024-01-31" or ">2024-01-01" or "<2024-01-01"
        if col_name in ['session_start', 'session_end']:
            if ' to ' in filter_value.lower():
                parts = filter_value.lower().split(' to ')
                if len(parts) == 2:
                    start_dt = _parse_date(parts[0])
                    end_dt = _parse_date(parts[1])
                    if start_dt and end_dt:
                        param_counter += 1
                        where_clauses.append(f"{col_name} >= :date_start_{param_counter}")
                        params[f'date_start_{param_counter}'] = start_dt
                        param_counter += 1
                        where_clauses.append(f"{col_name} < :date_end_{param_counter}")
                        params[f'date_end_{param_counter}'] = end_dt + timedelta(days=1)
            elif filter_value.startswith('>'):
                date_dt = _parse_date(filter_value[1:])
                if date_dt:
                    param_counter += 1
                    where_clauses.append(f"{col_name} > :date_{param_counter}")
                    params[f'date_{param_counter}'] = date_dt
            elif filter_value.startswith('<'):
                date_dt = _parse_date(filter_value[1:])
                if date_dt:
                    param_counter += 1
                    where_clauses.append(f"{col_name} < :date_{param_counter}")
                    params[f'date_{param_counter}'] = date_dt
            else:
                # Exact date match: cover the whole day
                date_dt = _parse_date(filter_value)
                if date_dt:
                    param_counter += 1
                    where_clauses.append(f"{col_name} >= :date_start_{param_counter}")
                    params[f'date_start_{param_counter}'] = date_dt
                    param_counter += 1
                    where_clauses.append(f"{col_name} < :date_end_{param_counter}")
                    params[f'date_end_{param_counter}'] = date_dt + timedelta(days=1)
        else:
            # Text filter with % wildcard support
            param_counter += 1
            param_name = f'filter_{param_counter}'
            if '%' in filter_value:
                where_clauses.append(f"CAST({col_name} AS TEXT) ILIKE :{param_name}")
                params[param_name] = filter_value
            else:
                where_clauses.append(f"CAST({col_name} AS TEXT) ILIKE :{param_name}")
                params[param_name] = f'%{filter_value}%'
    
    where_clause = ' AND '.join(where_clauses) if where_clauses else '1=1'
    
    # Count total matching rows
    count_query = text(f"SELECT COUNT(*) FROM nat_sessions_enriched WHERE {where_clause}")
    total = db.session.execute(count_query, params).scalar()
    
    # Fetch paginated results
    offset = (page - 1) * per_page
    order_clause = f"{sort_col} {sort_order.upper()}"
    
    data_query = text(f"""
        SELECT {select_clause}
        FROM nat_sessions_enriched
        WHERE {where_clause}
        ORDER BY {order_clause}
        LIMIT :limit OFFSET :offset
    """)
    
    params['limit'] = per_page
    params['offset'] = offset
    
    result = db.session.execute(data_query, params)
    rows = [dict(row._mapping) for row in result]
    
    # Calculate pagination
    total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0
    
    return render_template(
        'admin_traffic.html',
        all_columns=ALL_COLUMNS,
        selected_columns=selected_columns,
        filters=filters,
        rows=rows,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        sort_col=sort_col,
        sort_order=sort_order,
    )


@app.route('/admin/domain-policies', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_domain_policies():
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
        return redirect(url_for('admin_dashboard'))

    if not domain:
        flash('Domain is required.', 'error')
        return redirect(url_for('admin_dashboard'))

    allowed = _parse_allowed_vlans(','.join(request.form.getlist('domain_allowed_vlans')))
    adoptable = _parse_allowed_vlans(','.join(request.form.getlist('domain_adoptable_vlans')))

    if policy_id:
        policy = DomainPolicy.query.get(policy_id)
        if not policy:
            flash('Domain policy not found.', 'error')
            return redirect(url_for('admin_dashboard'))
        policy.domain = domain
        policy.allowed_vlans = _format_allowed_vlans(allowed)
        policy.adoptable_vlans = _format_allowed_vlans(adoptable)
        db.session.commit()
        flash(f'Domain policy for {domain} updated.', 'success')
        return redirect(url_for('admin_dashboard'))

    existing = DomainPolicy.query.filter_by(domain=domain).first()
    if existing:
        flash('Domain policy already exists. Use edit to update it.', 'error')
        return redirect(url_for('admin_dashboard'))

    policy = DomainPolicy(
        domain=domain,
        allowed_vlans=_format_allowed_vlans(allowed),
        adoptable_vlans=_format_allowed_vlans(adoptable),
    )
    db.session.add(policy)
    db.session.commit()
    flash(f'Domain policy for {domain} added.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def admin_add_user():
    """Add new authorized user"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        begin_date_raw = (request.form.get('begin_date') or '').strip()
        if begin_date_raw:
            begin_date = datetime.strptime(begin_date_raw, '%Y-%m-%d').date()
        else:
            begin_date = datetime.utcnow().date()
        require_approval_every_device = bool(request.form.get('require_approval_every_device'))
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        notes = request.form.get('notes', '').strip()
        
        if not email:
            flash('Email is required', 'error')
            return render_template('admin_add_user.html', vlan_map=get_vlan_map(), today=datetime.utcnow().date().isoformat())
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'error')
            return render_template('admin_add_user.html', vlan_map=get_vlan_map(), today=datetime.utcnow().date().isoformat())
        
        vlan_map = get_vlan_map()
        allowed_vlans_allow, allowed_vlans_deny = _parse_vlan_override_form(vlan_map, 'allowed_vlan')
        adoptable_allow, adoptable_deny = _parse_vlan_override_form(vlan_map, 'adoptable_vlan')

        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            begin_date=begin_date,
            expiry_date=expiry_date,
            notes=notes,
            created_by=current_user.username,
            allowed_vlans_override=_format_allowed_vlans(allowed_vlans_allow),
            allowed_vlans_deny=_format_allowed_vlans(allowed_vlans_deny),
            adoptable_vlans_override=_format_allowed_vlans(adoptable_allow),
            adoptable_vlans_deny=_format_allowed_vlans(adoptable_deny),
            require_approval_every_device=require_approval_every_device
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User {email} added successfully', 'success')
        logger.info(f"Admin added user: {email}")
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_add_user.html', vlan_map=get_vlan_map(), today=datetime.utcnow().date().isoformat())


@app.route('/admin/users/import', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def admin_import_users():
    if request.method == 'GET':
        vlan_map = get_vlan_map()
        base_fields, vlan_fields = _csv_template_fields(vlan_map)
        return render_template(
            'admin_import_users.html',
            vlan_map=vlan_map,
            base_fields=base_fields,
            vlan_fields=vlan_fields,
        )

    upload = request.files.get('csv_file')
    if not upload or not upload.filename:
        flash('Please select a CSV file to upload.', 'error')
        return redirect(url_for('admin_import_users'))

    content = upload.read().decode('utf-8-sig', errors='replace')
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        flash('CSV file must include a header row.', 'error')
        return redirect(url_for('admin_import_users'))

    header_map = {
        _normalize_csv_header(name): name
        for name in reader.fieldnames
        if name is not None
    }

    def get_value(row, *names):
        for name in names:
            key = _normalize_csv_header(name)
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
    domain_policy_map = _load_domain_policy_map()
    unregistered_vlan = vlan_map.get('unregistered')

    stats = {
        'rows': 0,
        'users_created': 0,
        'users_updated': 0,
        'devices_created': 0,
        'devices_updated': 0,
        'rows_skipped': 0,
    }
    errors = []

    for index, row in enumerate(reader, start=2):
        if not row or not any((value or '').strip() for value in row.values()):
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

        first_name = get_value(row, 'first name', 'firstname')
        last_name = get_value(row, 'second name', 'last name', 'lastname', 'surname')
        phone_number = get_value(row, 'phone number', 'phone')
        if first_name and str(first_name).strip():
            user.first_name = str(first_name).strip()
        if last_name and str(last_name).strip():
            user.last_name = str(last_name).strip()
        if phone_number and str(phone_number).strip():
            user.phone_number = str(phone_number).strip()

        allowed_allow = _parse_allowed_vlans(user.allowed_vlans_override)
        allowed_deny = _parse_allowed_vlans(user.allowed_vlans_deny)
        adopt_allow = _parse_allowed_vlans(user.adoptable_vlans_override)
        adopt_deny = _parse_allowed_vlans(user.adoptable_vlans_deny)

        for vlan_id, kind, header_name in vlan_flag_columns:
            flag = _parse_csv_bool(row.get(header_name))
            if flag is None:
                continue
            if kind == 'allowed':
                if flag:
                    allowed_allow.add(vlan_id)
                    allowed_deny.discard(vlan_id)
                else:
                    allowed_deny.add(vlan_id)
                    allowed_allow.discard(vlan_id)
            else:
                if flag:
                    adopt_allow.add(vlan_id)
                    adopt_deny.discard(vlan_id)
                else:
                    adopt_deny.add(vlan_id)
                    adopt_allow.discard(vlan_id)

        user.allowed_vlans_override = _format_allowed_vlans(allowed_allow)
        user.allowed_vlans_deny = _format_allowed_vlans(allowed_deny)
        user.adoptable_vlans_override = _format_allowed_vlans(adopt_allow)
        user.adoptable_vlans_deny = _format_allowed_vlans(adopt_deny)

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

                    device.user_id = user.id
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
                        domain_policy = _get_domain_policy_for_user(user, domain_policy_map)
                        effective_allowed, _, _, _ = _effective_vlan_sets(user, domain_policy)
                        default_vlan = _default_vlan_for_user(effective_allowed, vlan_map)
                        if device.current_vlan in {None, unregistered_vlan}:
                            target_vlan = default_vlan
                            if target_vlan:
                                device.current_vlan = target_vlan
                                device.ssid = device.ssid or get_ssid_for_vlan(target_vlan)
                        else:
                            target_vlan = device.current_vlan

                    device.registration_status = 'registered'

    if dry_run:
        db.session.rollback()
        flash('Dry run complete. No changes were saved.', 'info')
    else:
        db.session.commit()

    flash(
        "CSV import complete. Rows: {rows}, Users created: {users_created}, Users updated: {users_updated}, "
        "Devices created: {devices_created}, Devices updated: {devices_updated}, Rows skipped: {rows_skipped}.".format(**stats),
        'success',
    )

    if errors:
        flash(f"CSV import reported {len(errors)} issue(s).", 'warning')

    vlan_map = get_vlan_map()
    base_fields, vlan_fields = _csv_template_fields(vlan_map)
    return render_template(
        'admin_import_users.html',
        errors=errors,
        vlan_map=vlan_map,
        base_fields=base_fields,
        vlan_fields=vlan_fields,
    )


@app.route('/admin/users/import-template', methods=['GET'])
@login_required
@permission_required('manage_users')
def admin_import_users_template():
    vlan_map = get_vlan_map()
    base_fields, vlan_fields = _csv_template_fields(vlan_map)
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
    writer.writerow([_csv_template_example_value(header, 0) for header in selected])
    writer.writerow([_csv_template_example_value(header, 1) for header in selected])

    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=users_import_template.csv'
    return response


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def admin_edit_user(user_id):
    """Edit existing user"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.first_name = request.form.get('first_name', '').strip()
        user.last_name = request.form.get('last_name', '').strip()
        user.phone_number = request.form.get('phone_number', '').strip()
        user.begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        require_approval_every_device = bool(request.form.get('require_approval_every_device'))
        apply_status_to_devices = False
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        user.expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        user.notes = request.form.get('notes', '').strip()

        # --- Network password settings ---
        new_net_pwd = request.form.get('new_network_password', '').strip()
        confirm_net_pwd = request.form.get('confirm_network_password', '').strip()
        clear_net_pwd = bool(request.form.get('clear_network_password'))

        if clear_net_pwd:
            user.network_password_hash = None
            user.network_password_approval_mode = None
        elif new_net_pwd:
            if new_net_pwd != confirm_net_pwd:
                flash('Network passwords do not match.', 'error')
                return redirect(url_for('admin_edit_user', user_id=user.id))
            if len(new_net_pwd) < 8:
                flash('Network password must be at least 8 characters.', 'error')
                return redirect(url_for('admin_edit_user', user_id=user.id))
            user.set_network_password(new_net_pwd)
            # Mark as 'first_use' so the next device registered is always auto-approved
            user.network_password_approval_mode = 'first_use'

        vlan_map = get_vlan_map()
        allowed_vlans_allow, allowed_vlans_deny = _parse_vlan_override_form(vlan_map, 'allowed_vlan')
        adoptable_allow, adoptable_deny = _parse_vlan_override_form(vlan_map, 'adoptable_vlan')
        user.allowed_vlans_override = _format_allowed_vlans(allowed_vlans_allow)
        user.allowed_vlans_deny = _format_allowed_vlans(allowed_vlans_deny)
        user.adoptable_vlans_override = _format_allowed_vlans(adoptable_allow)
        user.adoptable_vlans_deny = _format_allowed_vlans(adoptable_deny)
        user.require_approval_every_device = require_approval_every_device
        
        db.session.commit()
        
        if apply_status_to_devices:
            target_vlan = _default_vlan_for_user(allowed_vlans_allow, vlan_map)
            devices = Device.query.filter_by(user_id=user.id, registration_status='registered').all()

            for device in devices:
                device.current_vlan = target_vlan
                send_coa_change(device.mac_address, target_vlan)

            db.session.commit()
        
        flash(f'User {user.email} updated successfully', 'success')
        logger.info(f"Admin updated user: {user.email}")
        
        return redirect(url_for('admin_dashboard'))
    
    allowed_vlans_allow = _parse_allowed_vlans(user.allowed_vlans_override)
    allowed_vlans_deny = _parse_allowed_vlans(user.allowed_vlans_deny)
    adoptable_allow = _parse_allowed_vlans(user.adoptable_vlans_override)
    adoptable_deny = _parse_allowed_vlans(user.adoptable_vlans_deny)
    return render_template(
        'admin_edit_user.html',
        user=user,
        vlan_map=get_vlan_map(),
        allowed_vlans_allow=allowed_vlans_allow,
        allowed_vlans_deny=allowed_vlans_deny,
        adoptable_allow=adoptable_allow,
        adoptable_deny=adoptable_deny,
    )


@app.route('/admin/users/<int:user_id>/block', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_block_user(user_id):
    """Block all devices for a user"""
    user = User.query.get_or_404(user_id)
    user.blocked = True
    db.session.commit()

    devices = Device.query.filter_by(user_id=user.id).all()
    for device in devices:
        apply_device_block(device, flash_messages=False)

    flash(f'User {user.email} blocked. {len(devices)} device(s) blocked.', 'success')
    logger.info(f"Admin blocked user {user.email} ({len(devices)} devices)")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/<int:user_id>/unblock', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_unblock_user(user_id):
    """Unblock all devices for a user"""
    user = User.query.get_or_404(user_id)
    user.blocked = False
    db.session.commit()

    devices = Device.query.filter_by(user_id=user.id).all()
    for device in devices:
        apply_device_unblock(device, flash_messages=False)

    flash(f'User {user.email} unblocked. {len(devices)} device(s) unblocked.', 'success')
    logger.info(f"Admin unblocked user {user.email} ({len(devices)} devices)")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/assign-device', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_assign_device():
    """Assign an unregistered device to a specific user"""
    mac_address = request.form.get('mac_address', '').strip().lower()
    user_id = request.form.get('user_id', '').strip()
    device_name = request.form.get('device_name', '').strip()
    vlan_id = request.form.get('vlan_id', '').strip()
    
    if not mac_address or not user_id or not vlan_id:
        flash('MAC address, user, and VLAN are required.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        user_id = int(user_id)
        vlan_id = int(vlan_id)
    except ValueError:
        flash('Invalid user ID or VLAN ID.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Check if MAC already registered
    existing = Device.query.filter_by(mac_address=mac_address).first()
    if existing and existing.registration_status == 'registered':
        flash(f'Device {mac_address} is already registered to {existing.user.email if existing.user else "another user"}.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get current lease/IP for the MAC
    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    ip_address = lease.ip_address if lease else None
    
    if not ip_address:
        # Try to get from Kea
        kea = get_kea()
        if kea:
            try:
                ip_address = kea.get_lease_ip_for_mac(mac_address, subnet_id=vlan_id)
            except Exception as e:
                logger.error(f"Error querying Kea for {mac_address}: {e}")
        
        # Fallback to database lease table
        if not ip_address:
            ip_address = get_ip_for_mac(mac_address, subnet_id=vlan_id)
    
    # Create or update device
    if existing:
        existing.user_id = user.id
        existing.registration_status = 'registered'
        existing.current_vlan = vlan_id
        if device_name:
            existing.device_name = device_name
        if ip_address:
            existing.ip_address = ip_address
        if not existing.unregister_token:
            existing.unregister_token = secrets.token_urlsafe(32)
        db.session.commit()
        device = existing
    else:
        device = Device(
            mac_address=mac_address,
            user_id=user.id,
            device_name=device_name or 'admin-assigned',
            ip_address=ip_address,
            registration_status='registered',
            current_vlan=vlan_id,
            connection_type='unknown',
            unregister_token=secrets.token_urlsafe(32)
        )
        db.session.add(device)
        db.session.commit()
    
    # Remove ACL block and DNS hijack
    if ip_address:
        manage_switch_acl('unblock', ip_address, vlan_id)
        manage_dns_hijack('unhijack', ip_address)
    
    # Add Kea reservation
    kea = get_kea()
    if kea and ip_address:
        try:
            kea.register_mac(mac=mac_address, vlan=vlan_id, fixed_ip=ip_address)
            logger.info(f"Admin assigned device {mac_address} to user {user.email} with IP {ip_address}")
        except Exception as exc:
            logger.error(f"Kea reservation failed for admin-assigned device {mac_address}: {exc}")
    
    # Clear unregistered lease
    clear_unregistered_lease(mac_address)
    
    flash(f'Device {mac_address} successfully assigned to {user.email}.', 'success')
    logger.info(f"Admin assigned device {mac_address} to user {user.email}")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/approve/<token>')
@login_required
@permission_required('manage_users')
def admin_approve_request(token):
    """Approve registration request from email link"""
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()
    
    if reg_request.status != 'pending':
        # Request already processed - show who processed it
        action = 'approved' if reg_request.status == 'approved' else 'rejected'
        processed_info = f"by admin {reg_request.processed_by}" if reg_request.processed_by else ""
        processed_time = f"at {reg_request.processed_at.strftime('%Y-%m-%d %H:%M:%S')}" if reg_request.processed_at else ""
        flash(f'This request has already been {action} {processed_info} {processed_time}.', 'info')
        return redirect(url_for('admin_dashboard'))
    
    existing_user = User.query.filter_by(email=reg_request.email).first()
    detected_connection, detected_vlan, detected_ssid = detect_connection_type(reg_request.ip_address)
    default_vlan = reg_request.requested_vlan or detected_vlan
    existing_user_allowed_display = ''
    if existing_user:
        domain_policy = _load_domain_policy_map().get(_email_domain(existing_user.email))
        existing_user_allowed_display = _format_vlan_items_text(
            _allowed_vlans_display_items(existing_user, get_vlan_map(), domain_policy)
        )
    return render_template(
        'admin_approve_request.html',
        request=reg_request,
        vlan_map=get_vlan_map(),
        existing_user=existing_user,
        existing_user_allowed_display=existing_user_allowed_display,
        detected_vlan=detected_vlan,
        detected_ssid=detected_ssid,
        detected_connection=detected_connection,
        default_vlan=default_vlan,
        today=datetime.utcnow().date().isoformat()
    )


@app.route('/admin/requests/<int:request_id>/process', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_process_request(request_id):
    """Process (approve/reject) a registration request"""
    reg_request = RegistrationRequest.query.get_or_404(request_id)
    
    # Check if already processed (concurrent access protection)
    if reg_request.status != 'pending':
        action_word = 'approved' if reg_request.status == 'approved' else 'rejected'
        processed_info = f"by admin {reg_request.processed_by}" if reg_request.processed_by else ""
        processed_time = f"at {reg_request.processed_at.strftime('%Y-%m-%d %H:%M:%S')}" if reg_request.processed_at else ""
        flash(f'This request was already {action_word} {processed_info} {processed_time}.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
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

        # Detect connection type from IP address
        connection_type, detected_vlan, ssid = detect_connection_type(reg_request.ip_address)
        network_mismatch = bool(connection_type == 'wifi' and detected_vlan and target_vlan and detected_vlan != target_vlan)

        existing_user = User.query.filter_by(email=reg_request.email).first()
        if existing_user:
            user = existing_user
            if notes:
                user.notes = f"{user.notes}\n{notes}" if user.notes else notes

            device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
            if device:
                device.user_id = user.id
                device.device_name = reg_request.device_type or device.device_name or 'unknown'
                device.ip_address = reg_request.ip_address
                device.registration_status = 'registered'
                device.current_vlan = target_vlan
                device.connection_type = connection_type
                device.ssid = ssid
                device.is_wired = connection_type == 'wired'
                device.wired_target_vlan = target_vlan if connection_type == 'wired' else None
                device.unregister_token = device.unregister_token or secrets.token_urlsafe(32)
            else:
                device = Device(
                    mac_address=reg_request.mac_address,
                    user_id=user.id,
                    device_name=reg_request.device_type or 'unknown',
                    ip_address=reg_request.ip_address,
                    registration_status='registered',
                    current_vlan=target_vlan,
                    connection_type=connection_type,
                    ssid=ssid,
                    is_wired=connection_type == 'wired',
                    wired_target_vlan=target_vlan if connection_type == 'wired' else None,
                    unregister_token=secrets.token_urlsafe(32)
                )
                db.session.add(device)

            # No bulk updates; allowed VLANs control future auto-approvals.
        else:
            begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
            expiry_date_str = request.form.get('expiry_date', '').strip()
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None

            user = User(
                email=reg_request.email,
                first_name=reg_request.first_name,
                last_name=reg_request.last_name,
                phone_number=reg_request.phone_number,
                begin_date=begin_date,
                expiry_date=expiry_date,
                notes=notes,
                created_by=current_user.username
            )
            db.session.add(user)
            db.session.flush()

            device = Device(
                mac_address=reg_request.mac_address,
                user_id=user.id,
                device_name=reg_request.device_type or 'unknown',
                ip_address=reg_request.ip_address,
                registration_status='registered',
                current_vlan=target_vlan,
                connection_type=connection_type,
                ssid=ssid,
                is_wired=connection_type == 'wired',
                wired_target_vlan=target_vlan if connection_type == 'wired' else None,
                unregister_token=secrets.token_urlsafe(32)
            )
            db.session.add(device)
        
        # Mark ALL pending requests for this MAC as approved
        all_mac_requests = RegistrationRequest.query.filter_by(
            mac_address=reg_request.mac_address, 
            status='pending'
        ).all()
        
        for req in all_mac_requests:
            req.status = 'approved'
            req.processed_at = datetime.now()
            req.processed_by = current_user.username
        
        db.session.commit()
        
        # Register in network based on connection type
        if device.connection_type == 'wifi':
            # WiFi: Register MAC in Kea DHCP
            kea = get_kea()
            if kea:
                success = kea.register_mac(
                    mac=device.mac_address,
                    vlan=target_vlan,
                    hostname=f"{user.first_name.lower()}-{user.last_name.lower()}-device",
                    ip_address=None  # Let Kea assign from registered pool
                )
                if success and device.ip_address:
                    # Delete the old lease to force device to get new IP from registered pool
                    try:
                        if not network_mismatch:
                            kea.force_lease_renewal(device.mac_address, device.ip_address)
                    except Exception as e:
                        logger.warning(f"Could not force lease renewal: {e}")
                if not success:
                    logger.error(f"Failed to register MAC {device.mac_address} in Kea after approval")
                    # Still unhijack even if Kea registration fails (might already be registered)
                    if device.ip_address and not network_mismatch and _should_hijack_vlan(target_vlan):
                        manage_dns_hijack('unhijack', device.ip_address)
                else:
                    # Successfully registered, remove DNS hijacking
                    if device.ip_address and not network_mismatch and _should_hijack_vlan(target_vlan):
                        manage_dns_hijack('unhijack', device.ip_address)
            else:
                logger.error("Kea client unavailable for WiFi device registration")
                # Unhijack anyway if we have an IP
                if device.ip_address and not network_mismatch and _should_hijack_vlan(target_vlan):
                    manage_dns_hijack('unhijack', device.ip_address)
        else:
            # Wired: Use RADIUS CoA
            send_coa_change(device.mac_address, target_vlan)
            replug_switch_port_for_mac(device.mac_address)
            # Remove DNS hijacking for wired devices too
            if device.ip_address and _should_hijack_vlan(target_vlan):
                manage_dns_hijack('unhijack', device.ip_address)

        clear_unregistered_lease(device.mac_address)
        
        # NEW: Unblock the original IP address from the unregistered VLAN
        if not network_mismatch:
            manage_switch_acl('unblock', reg_request.ip_address, detected_vlan)

        unregister_url = _build_unregister_url(device.unregister_token)
        confirm_url = None
        confirm_timeout_sec = None
        confirm_url, confirm_timeout_sec = _set_wifi_confirmation(device)
        if device.connection_type == 'wired':
            ssid_display = "Wired Network"
        else:
            ssid_display = device.ssid or get_ssid_for_vlan(target_vlan) or "WiFi Network"
        send_wifi_registration_confirmation(
            user.email,
            user.first_name or reg_request.first_name or "there",
            ssid_display,
            device.mac_address,
            unregister_url,
            confirm_url=confirm_url,
            confirm_timeout_sec=confirm_timeout_sec,
            registration_details={
                "email": user.email,
                "first_name": user.first_name or reg_request.first_name,
                "last_name": user.last_name or reg_request.last_name,
                "phone_number": user.phone_number or reg_request.phone_number,
                "device_type": device.device_name,
                "ip_address": device.ip_address,
                "ssid": ssid_display
            }
        )
        
        flash(f'Request approved and user {user.email} created', 'success')
        logger.info(f"Admin approved registration request for {user.email}")
        
    elif action == 'reject':
        notes = request.form.get('notes', '').strip()
        if not notes:
            flash('Rejection reason is required.', 'error')
            return redirect(url_for('admin_approve_request', token=reg_request.approval_token))

        reg_request.status = 'rejected'
        reg_request.processed_at = datetime.now()
        reg_request.processed_by = current_user.username
        reg_request.notes = notes
        
        db.session.commit()
        
        flash('Request rejected', 'info')
        logger.info(f"Admin rejected registration request for {reg_request.email}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/devices/<int:device_id>/disconnect', methods=['POST'])
@login_required
def admin_disconnect_device(device_id):
    """Disconnect a device from the network"""
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
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/block', methods=['POST'])
@login_required
def admin_block_device(device_id):
    """Block a device via HP5130 ACL for immediate effect"""
    device = Device.query.get_or_404(device_id)

    apply_device_block(device, flash_messages=True)
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/unblock', methods=['POST'])
@login_required
def admin_unblock_device(device_id):
    """Unblock a device by removing switch ACL rule"""
    device = Device.query.get_or_404(device_id)

    apply_device_unblock(device, flash_messages=True)
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/change-vlan', methods=['POST'])
@login_required
def admin_change_device_vlan(device_id):
    device = Device.query.get_or_404(device_id)
    target_raw = (request.form.get('target_vlan') or '').strip()
    try:
        target_vlan = int(target_raw)
    except ValueError:
        target_vlan = None

    if not target_vlan:
        flash('Target VLAN is required.', 'error')
        return redirect(url_for('admin_dashboard'))

    if device.connection_type != 'wired':
        flash('Only wired devices can be moved with RADIUS CoA.', 'error')
        return redirect(url_for('admin_dashboard'))

    if target_vlan not in _get_wired_assignable_vlan_ids():
        flash('Target VLAN is not enabled for wired access.', 'error')
        return redirect(url_for('admin_dashboard'))

    device.current_vlan = target_vlan
    device.is_wired = True
    device.wired_target_vlan = target_vlan
    db.session.commit()

    send_coa_change(device.mac_address, target_vlan)
    kea = get_kea()
    if kea:
        try:
            kea.register_mac(mac=device.mac_address, vlan=target_vlan, hostname=device.device_name or 'device', ip_address=None)
        except Exception as exc:
            logger.warning("Kea registration failed for %s: %s", device.mac_address, exc)

    flash(f'Device {device.mac_address} moved to VLAN {target_vlan}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/devices/change-vlan', methods=['POST'])
@login_required
def admin_change_devices_vlan():
    target_raw = (request.form.get('target_vlan') or '').strip()
    macs_raw = (request.form.get('mac_addresses') or '').strip()
    try:
        target_vlan = int(target_raw)
    except ValueError:
        target_vlan = None

    if not target_vlan or not macs_raw:
        flash('Target VLAN and MAC list are required.', 'error')
        return redirect(url_for('admin_dashboard'))

    if target_vlan not in _get_wired_assignable_vlan_ids():
        flash('Target VLAN is not enabled for wired access.', 'error')
        return redirect(url_for('admin_dashboard'))

    mac_values = re.split(r'[\s,]+', macs_raw)
    macs = [value for value in (_normalize_mac_input(mac) for mac in mac_values) if value]

    updated = 0
    skipped = 0
    kea = get_kea()
    for mac in macs:
        device = Device.query.filter_by(mac_address=mac).first()
        if not device or device.connection_type != 'wired':
            skipped += 1
            continue
        device.current_vlan = target_vlan
        device.is_wired = True
        device.wired_target_vlan = target_vlan
        updated += 1
        send_coa_change(device.mac_address, target_vlan)
        if kea:
            try:
                kea.register_mac(mac=device.mac_address, vlan=target_vlan, hostname=device.device_name or 'device', ip_address=None)
            except Exception as exc:
                logger.warning("Kea registration failed for %s: %s", device.mac_address, exc)

    if updated:
        db.session.commit()

    flash(f'Updated {updated} wired device(s). Skipped {skipped}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/delete', methods=['POST'])
@login_required
def admin_delete_device(device_id):
    """Delete a device registration"""
    device = Device.query.get_or_404(device_id)
    mac_address = device.mac_address
    ip_address = device.ip_address
    vlan_id = device.current_vlan
    
    # Remove any ACL/DNS hijack tied to the device IP before deletion
    if ip_address and vlan_id:
        manage_switch_acl('unblock', ip_address, vlan_id)
        if _should_hijack_vlan(vlan_id):
            manage_dns_hijack('unhijack', ip_address)

    # Unregister from network first
    if device.connection_type == 'wifi':
        kea = get_kea()
        if kea:
            kea.unregister_mac(device.mac_address, device.current_vlan)
    elif device.connection_type == 'wired':
        send_coa_disconnect(device.mac_address)

    # For deleted devices, keep DNS hijack + ACL while lease is active
    if ip_address and not _is_blocked_pool_ip(ip_address):
        lease_expiry = get_lease_expiry_for_mac(mac_address, subnet_id=vlan_id)
        if not lease_expiry:
            lease_expiry = datetime.utcnow() + timedelta(minutes=5)

        upsert_unregistered_lease(mac_address, ip_address, lease_expiry)

        if vlan_id:
            manage_switch_acl('block', ip_address, vlan_id)

        if _should_hijack_vlan(vlan_id):
            manage_dns_hijack('hijack', ip_address)
            logger.info(
                "DNS hijacked/ACL blocked for deleted device %s at %s until %s",
                mac_address,
                ip_address,
                lease_expiry,
            )
        else:
            logger.info(
                "ACL blocked for deleted device %s at %s until %s",
                mac_address,
                ip_address,
                lease_expiry,
            )
    
    db.session.delete(device)
    db.session.commit()

    cleanup_orphan_hijack_rules()
    
    flash(f'Device {mac_address} has been deleted', 'success')
    logger.info(f"Admin deleted device {mac_address}")
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_delete_user(user_id):
    """Delete a user — only allowed if they own no devices."""
    user = User.query.get_or_404(user_id)
    device_count = Device.query.filter_by(user_id=user_id).count()
    if device_count > 0:
        flash(f'Cannot delete {user.email}: they still own {device_count} device(s). Delete or reassign them first.', 'error')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    logger.info(f"Admin deleted user {user.email}")
    flash(f'User {user.email} deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/reassign', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_reassign_device(device_id):
    """Reassign a registered device to a different user."""
    device = Device.query.get_or_404(device_id)
    user_id = request.form.get('user_id', '').strip()
    if not user_id:
        flash('A user must be selected.', 'error')
        return redirect(url_for('admin_dashboard'))
    try:
        user_id = int(user_id)
    except ValueError:
        flash('Invalid user ID.', 'error')
        return redirect(url_for('admin_dashboard'))
    new_user = User.query.get(user_id)
    if not new_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    old_email = device.user.email if device.user else 'unowned'
    device.user_id = new_user.id
    db.session.commit()
    logger.info(f"Admin reassigned device {device.mac_address} from {old_email} to {new_user.email}")
    flash(f'Device {device.mac_address} reassigned to {new_user.email}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        # Check database connection
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'healthy'}), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500


# Trigger port discovery on every worker start (gunicorn spawns multiple workers;
# the fresh-data check inside ensures only the first worker actually does the work).
_startup_switch_discovery()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
