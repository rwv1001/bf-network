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


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')

from models import db, Admin, User, Device, RegistrationRequest, VlanMapping, ISPRouter, Setting, UnregisteredLease, DomainPolicy, DeviceOwnership, IPLease, CentralOutboundEvent
from radius_coa import send_coa_disconnect, send_coa_change
from email_service import (
    send_verification_email,
    send_admin_notification,
    send_admin_password_setup_email,
    send_wifi_registration_confirmation,
    send_vlan_mismatch_notification,
    send_user_blocked_device_notice,
    send_admin_password_reset_email,
    send_network_password_set_email,
    send_network_password_reset_email,
    send_admin_unblock_request,
)
from flask_wtf.csrf import CSRFProtect
from kea_integration import get_kea_client
from urllib.parse import urlparse
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://portal_user:password@db:5432/captive_portal')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Detect and recycle stale connections after a container/DB restart.
# pool_pre_ping issues a lightweight "SELECT 1" before handing out each
# connection; if it fails the connection is discarded and a fresh one opened.
# pool_recycle discards connections older than 5 minutes regardless.
# pool_reset_on_return=None suppresses the ROLLBACK SQLAlchemy normally issues
# when returning a connection to the pool during session teardown — this
# prevents OperationalError log spam when Postgres restarts mid-request and
# the teardown rollback hits a dead connection.
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_reset_on_return': None,
}
# Make csrf_token() available in all templates without enforcing
# automatic token checking on every POST (many existing routes don't
# carry a token field and would break if enforcement were on).
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
csrf = CSRFProtect(app)


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


def _build_reject_url(token):
    portal_url = _get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('reject_device', token=token)}"
    return url_for('reject_device', token=token, _external=True)


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


def _wifi_confirm_timeout_minutes():
    """Return the WiFi confirmation timeout rounded up to whole minutes."""
    return max(1, int((_wifi_confirm_timeout_sec() + 59) / 60))


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
    confirm_url = _build_confirm_url(device.confirmation_token)
    reject_url = _build_reject_url(device.confirmation_token)
    return confirm_url, reject_url, timeout_sec


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


def _sweep_expired_ip_leases():
    """Background thread: clean up DNS hijacks/ACLs for expired IPLease rows.

    Per spec: remove all per-IP hijacks and HP5130 ACL blocks once a lease
    expires, unconditionally.  The block/hijack is IP-scoped, not MAC-scoped:
    - the IP is freed and may be reassigned to a different device
    - a still-blocked device will re-DHCP into the blocked pool, which already
      has blanket range-level rules, so the old per-IP rule is redundant
    Also sweeps expired leases that were never dns_hijacked to catch any
    HP5130 per-IP rules that were added without a corresponding hijack.
    """
    interval = int(os.getenv('IP_LEASE_SWEEP_INTERVAL', '20'))
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                # All expired leases — not just dns_hijacked ones.
                # We always unblock the IP on the switch; unhijack is a no-op
                # if no iptables rule exists for that IP.
                expired = IPLease.query.filter(
                    IPLease.lease_expiry <= now,
                ).all()
                changed = False
                for lease in expired:
                    try:
                        if lease.dns_hijacked:
                            manage_dns_hijack('unhijack', lease.ip_address)
                            lease.dns_hijacked = False
                        # Always attempt ACL removal — harmless if rule absent.
                        if lease.vlan_id and not lease.from_blocked_pool:
                            manage_switch_acl('unblock', lease.ip_address, lease.vlan_id)
                        logger.info(
                            "Lease sweep: cleaned up %s (VLAN %s) — lease expired at %s",
                            lease.ip_address, lease.vlan_id, lease.lease_expiry,
                        )
                        changed = True
                    except Exception as exc:
                        logger.warning("Lease sweep cleanup failed for %s: %s", lease.ip_address, exc)
                if changed:
                    db.session.commit()

                # Spec: set internet_accessible=null for any MAC in devices that
                # has no active (non-expired) leases.
                try:
                    now2 = datetime.utcnow()
                    active_mac_ids = {
                        row[0]
                        for row in db.session.query(IPLease.mac_address).filter(
                            IPLease.lease_expiry > now2
                        ).all()
                    }
                    stale = Device.query.filter(
                        Device.internet_accessible.isnot(None),
                        Device.internet_blocked.isnot(True),
                    ).all()
                    changed = 0
                    for dev in stale:
                        if dev.mac_address not in active_mac_ids:
                            dev.internet_accessible = None
                            changed += 1
                    if changed:
                        db.session.commit()
                        logger.debug("Lease sweep: cleared internet_accessible for %d MAC(s) with no active lease", changed)
                except Exception as exc:
                    logger.warning("Lease sweep: internet_accessible cleanup failed: %s", exc)
        except Exception as exc:
            logger.warning("IP lease sweep failed: %s", exc)
        time.sleep(interval)


def _start_ip_lease_sweeper():
    thread = threading.Thread(target=_sweep_expired_ip_leases, daemon=True)
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
    network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
    total = network.num_addresses
    block_size = 40 * (2 ** (24 - prefix))
    registered_start = 1
    registered_end = total - block_size - 1
    block_start = registered_end + 1
    block_end = total - 1

    if registered_end < registered_start:
        raise ValueError(f"Pool size too small for VLAN {vlan_id} /{prefix}")

    registered_pools = [
        f"{_ip_from_offset(network, registered_start)} - {_ip_from_offset(network, registered_end)}"
    ]
    blocked_pool = f"{_ip_from_offset(network, block_start)} - {_ip_from_offset(network, block_end)}"

    return str(network), registered_pools, blocked_pool


def _pool_bounds_for_prefix(prefix):
    total = 2 ** (32 - prefix)
    block_size = 40 * (2 ** (24 - prefix))
    registered_start = 1
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

    # Write the prefix map so generate-kea-config.py picks it up on next
    # container restart instead of the stale VLAN_PREFIX_MAP env var.
    prefix_map_path = os.path.join(os.path.dirname(config_path), 'vlan-prefix-map.txt')
    prefix_map_str = ','.join(f"{vid}:{pfx}" for vid, pfx in sorted(vlan_prefix_by_id.items()))
    with open(prefix_map_path, 'w', encoding='utf-8') as handle:
        handle.write(prefix_map_str + '\n')


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

# Initialize central sync client (no-op if env vars not set)
import central_client
with app.app_context():
    central_client.init_central_client(app, db, CentralOutboundEvent)


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
            # Add PORTAL_URL from captive-portal/.env to allowed_origins if self-calls occur
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
_start_ip_lease_sweeper()


class AdminUser:
    """Admin user class for Flask-Login with role-based permissions"""
    def __init__(self, admin_id, username, can_manage_users=True, can_manage_vlans=False, 
                 can_view_traffic=False, can_manage_admins=False, traffic_viewer_settings=None, 
                 mfa_enabled=False, must_change_password=False, can_manage_switch_ports=False,
                 can_manage_isp_routers=False, can_manage_firmware=False,
                 can_manage_pihole=False):
        self.id = str(admin_id)  # Flask-Login requires string ID
        self.username = username
        self.can_manage_users = can_manage_users
        self.can_manage_vlans = can_manage_vlans
        self.can_view_traffic = can_view_traffic
        self.can_manage_admins = can_manage_admins
        self.can_manage_switch_ports = can_manage_switch_ports
        self.can_manage_isp_routers = can_manage_isp_routers
        self.can_manage_firmware = can_manage_firmware
        self.can_manage_pihole = can_manage_pihole
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
                getattr(admin, 'can_manage_isp_routers', False),
                getattr(admin, 'can_manage_firmware', False),
                can_manage_pihole=getattr(admin, 'can_manage_pihole', False)
            )
    except (ValueError, TypeError):
        pass
    except Exception:
        # DB connection was lost (e.g. container/postgres just restarted).
        # Roll back the broken transaction so the pool can recover, then
        # return None — flask-login will treat the user as anonymous and
        # redirect to the login page instead of raising a 500.
        try:
            db.session.rollback()
        except Exception:
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
            elif permission == 'manage_firmware' and not current_user.can_manage_firmware:
                flash('You do not have permission to manage firmware.', 'error')
                return redirect(url_for('admin_dashboard'))
            elif permission == 'manage_pihole' and not current_user.can_manage_pihole:
                flash('You do not have permission to manage Pi-Hole DNS.', 'error')
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

                # Final fallback: look up our own ip_leases table (covers the
                # window after lease4-del but before the device renews DHCP).
                if not mac:
                    try:
                        lease_row = IPLease.query.filter_by(ip_address=ip_address).order_by(IPLease.lease_expiry.desc()).first()
                        if lease_row and lease_row.mac_address:
                            mac = lease_row.mac_address
                            logger.info(f"Found MAC {mac} for IP {ip_address} via ip_leases DB fallback")
                    except Exception as e:
                        logger.error(f"Error querying ip_leases for MAC lookup: {e}")
                        
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
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
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
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
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

    # Pre-load the VLAN prefix map once so _vlan_from_ip_any doesn't hit the DB
    # once per line (the CSV can have tens of thousands of historical entries).
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
                mac_address = fields[1].lower()
                # Skip expired and declined leases (state field index 9; 0=active).
                # This avoids processing tens of thousands of historical rows.
                expire_raw = fields[4].strip() if len(fields) > 4 else ''
                try:
                    if expire_raw and int(expire_raw) < now.timestamp():
                        continue
                except (ValueError, TypeError):
                    pass
                vlan_id = _vlan_from_ip_any(ip_address, prefix_by_id)
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
    if not device:
        return None, None
    # Accept either the new ownership-based check or the legacy registration_status
    ownership = _get_active_ownership(mac_address)
    if not ownership and device.registration_status != 'registered':
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
            f"--to-destination {os.environ['HIJACK_DNS_IP']}:53" not in line
            and f"--to-destination {os.environ['PORTAL_IP']}:8080" not in line
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
    """Re-apply baseline walled-garden ACLs on ALL configured switches.

    The walled-garden ACL (ACL 30xx per VLAN) is applied inbound on each
    switch's VLAN SVI, so it must exist on every switch in SWITCH_HOSTS.
    Runs the baseline script once per switch host.
    """
    script_path = os.getenv('ACL_BASELINE_SCRIPT', '/scripts/hp5130-acl-baseline.sh')
    if not os.path.isfile(script_path):
        logger.error("ACL baseline script not found: %s", script_path)
        return False

    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    if not switch_hosts:
        logger.error("reset_acl_baseline: no SWITCH_HOSTS configured")
        return False

    all_ok = True
    for host in switch_hosts:
        env = os.environ.copy()
        env['SWITCH_HOST'] = host
        if not env.get("SWITCH_KEY_PATH"):
            env["SWITCH_KEY_PATH"] = "/keys/id_rsa"

        result = subprocess.run([script_path], capture_output=True, text=True,
                                timeout=120, env=env)
        if result.returncode != 0:
            stderr = (result.stderr or '').strip()
            stdout = (result.stdout or '').strip()
            logger.error(
                "ACL baseline failed for %s (exit=%s). stderr=%s stdout=%s",
                host, result.returncode,
                stderr or '<empty>',
                stdout or '<empty>',
            )
            all_ok = False
        else:
            logger.info("ACL baseline pushed to %s", host)
    return all_ok


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
    """Update HP5130 VLAN interface masks for specific VLAN IDs on all switches."""
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
    # Pass all switch hosts — the script loops over them.
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    env["SWITCH_HOSTS"] = switch_hosts_raw

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
                path = os.path.join(queue_base, name)
                # Clear dedup markers, queue files, PID files, and lock dirs
                # for both the legacy single-host names and the current
                # per-host names (hp5130-acl-<host>.queue etc.).
                is_dedup = name.startswith('.dedup-')
                is_acl_file = (
                    name.startswith('hp5130-acl') and
                    (name.endswith('.queue') or name.endswith('.pid') or name.endswith('.lock'))
                )
                is_acl_lock_dir = name.startswith('hp5130-acl') and name.endswith('.lock') and os.path.isdir(path)
                if is_dedup or is_acl_file or is_acl_lock_dir:
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        try:
                            os.remove(path)
                            logger.info("ACL queue file cleared: %s", path)
                        except FileNotFoundError:
                            pass
    except Exception as exc:
        logger.warning("Failed to clear ACL queue files: %s", exc)


def reset_test_data():
    """Remove all users/devices/requests, Kea host/lease data, and NAT/DNS logs.

    This function only performs fast synchronous work (DB deletes + file truncation).
    The Kea container restart is intentionally excluded here; callers that want it
    should call _restart_kea_container() separately (e.g. in a background thread).
    """
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
    db.session.query(DeviceOwnership).delete(synchronize_session=False)
    db.session.query(IPLease).delete(synchronize_session=False)
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

    # Truncate the Kea CSV lease file so Kea's in-memory allocator starts
    # fresh and re-issues IPs from .1 rather than skipping historical addresses.
    lease_file = '/kea/leases/kea-leases4.csv'
    try:
        with open(lease_file, 'w') as _f:
            _f.write(
                'address,hwaddr,client_id,valid_lifetime,expire,'
                'subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n'
            )
        logger.info("Kea CSV lease file truncated: %s", lease_file)
    except Exception as exc:
        logger.warning("Failed to truncate Kea lease file %s: %s", lease_file, exc)


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


# ── Spec Table 9 helpers (DeviceOwnership) ────────────────────────────────────

def _get_active_ownership(mac_address):
    """Return the active DeviceOwnership row for mac_address, or None."""
    return DeviceOwnership.query.filter_by(
        mac_address=mac_address, end_datetime=None
    ).first()


def _close_ownership(mac_address, commit=True):
    """Close the active DeviceOwnership for mac_address (set end_datetime=now)."""
    o = _get_active_ownership(mac_address)
    if o:
        o.end_datetime = datetime.utcnow()
        if commit:
            db.session.commit()
    return o


def _open_ownership(mac_address, user_id, commit=True):
    """Open a new DeviceOwnership row for mac_address/user_id."""
    o = DeviceOwnership(
        mac_address=mac_address,
        user_id=user_id,
        start_datetime=datetime.utcnow(),
    )
    db.session.add(o)
    if commit:
        db.session.commit()
    return o


# ── Spec Table 7 helpers (IPLease) ────────────────────────────────────────────

def _get_active_iplease(mac_address):
    """Return the most recent non-expired IPLease for mac_address, or None."""
    return (
        IPLease.query
        .filter(
            IPLease.mac_address == mac_address,
            IPLease.lease_expiry > datetime.utcnow(),
        )
        .order_by(IPLease.lease_start.desc())
        .first()
    )


def _upsert_iplease(mac_address, ip_address, vlan_id, lease_start, lease_expiry,
                    from_blocked_pool=False, dns_hijacked=False, commit=True):
    """Create or update an IPLease row for (mac_address, ip_address)."""
    lease = IPLease.query.filter_by(
        mac_address=mac_address, ip_address=ip_address
    ).first()
    if lease:
        lease.vlan_id = vlan_id
        lease.lease_start = lease_start
        lease.lease_expiry = lease_expiry
        lease.from_blocked_pool = from_blocked_pool
        lease.dns_hijacked = dns_hijacked
    else:
        lease = IPLease(
            ip_address=ip_address,
            vlan_id=vlan_id,
            mac_address=mac_address,
            lease_start=lease_start,
            lease_expiry=lease_expiry,
            from_blocked_pool=from_blocked_pool,
            dns_hijacked=dns_hijacked,
        )
        db.session.add(lease)
    if commit:
        db.session.commit()
    return lease


def _expire_iplease(mac_address, ip_address, commit=True):
    """Mark a specific IPLease as expired (set lease_expiry to now)."""
    lease = IPLease.query.filter_by(
        mac_address=mac_address, ip_address=ip_address
    ).first()
    if lease:
        lease.lease_expiry = datetime.utcnow()
        if commit:
            db.session.commit()
    return lease


# ── Spec Table 6 state helpers ────────────────────────────────────────────────

def _sync_registration_status(device):
    """Keep registration_status consistent with the new orthogonal fields.

    Rules:
    - internet_blocked=True  → 'blocked'
    - internet_accessible=True and assigned_vlan set → 'registered'
    - internet_accessible=False and assigned_vlan set → 'wrong_vlan'
    - anything else → 'pending'
    """
    if device.internet_blocked:
        device.registration_status = 'blocked'
    elif device.internet_accessible and device.assigned_vlan:
        device.registration_status = 'registered'
    elif device.internet_accessible is False and device.assigned_vlan:
        device.registration_status = 'wrong_vlan'
    else:
        device.registration_status = 'pending'


def _set_internet_accessible(device, value, commit=True):
    """Set internet_accessible and keep registration_status in sync."""
    device.internet_accessible = value
    _sync_registration_status(device)
    if commit:
        db.session.commit()


def _set_internet_blocked(device, value, commit=True):
    """Set internet_blocked and keep registration_status in sync."""
    device.internet_blocked = value
    if value:
        device.internet_accessible = None
    _sync_registration_status(device)
    if commit:
        db.session.commit()


def _should_have_internet(device):
    """Return True if all conditions are met for the device to have internet access.

    Conditions (spec 4b.ii.2.a.ii):
    - device.assigned_vlan is set
    - device.current_vlan == device.assigned_vlan
    - if the VLAN requires a password, ownership_validated must be True
    """
    if not device.assigned_vlan:
        return False
    if device.current_vlan != device.assigned_vlan:
        return False
    if _vlan_requires_password(device.assigned_vlan) and not device.ownership_validated:
        return False
    return True


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
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
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
            f"--to-destination {os.environ['HIJACK_DNS_IP']}:53" not in line
            and f"--to-destination {os.environ['PORTAL_IP']}:8080" not in line
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


def _switch_host_for_port(port_name):
    """Return the switch_host for the given port by looking it up in switch_ports.
    Falls back to the first SWITCH_HOSTS entry if the port is not found.
    """
    if port_name:
        row = db.session.execute(
            text("SELECT switch_host FROM switch_ports WHERE port_name = :p LIMIT 1"),
            {'p': port_name}
        ).fetchone()
        if row:
            return row[0]
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    return hosts[0] if hosts else None


def _get_switch_host_for_isp_router(router):
    """Return the switch host (management IP) for the HP5130 that physically hosts
    this ISP router's uplink port.  Uses ISPRouter.switch_host when set; falls back
    to the first entry in SWITCH_HOSTS (preserving pre-migration behaviour).
    """
    if router and router.switch_host:
        return router.switch_host
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    return hosts[0] if hosts else ''


def _get_switch_host_for_vlan(vlan_id):
    """Return the HP5130 switch_host that hosts the ISP router for the given
    device VLAN.  The ISP router's switch is the choke point for internet
    traffic: blocking there is sufficient regardless of which physical switch
    the device is connected to.

    Resolves via VlanMapping.isp_router_id -> ISPRouter.switch_host.
    Falls back to first SWITCH_HOSTS entry if the mapping is not configured.
    """
    if vlan_id:
        try:
            mapping = VlanMapping.query.filter_by(vlan_id=int(vlan_id)).first()
            if mapping and mapping.isp_router and mapping.isp_router.switch_host:
                return mapping.isp_router.switch_host
        except Exception:
            pass
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    return hosts[0] if hosts else ''


def manage_switch_acl(action, ip_address, vlan_id):
    """
    Manage HP5130 ACL rules for blocking/unblocking specific IPs using SSH.

    For 'block': targets only the ISP router's switch for the VLAN.  That
    switch is the internet choke point — all traffic destined for the internet
    must pass through it regardless of which physical switch the device is on.

    For 'unblock': targets ALL switches in SWITCH_HOSTS to defensively remove
    any stale deny rules left from previous behaviour or device moves.

    Args:
        action: 'block' to deny traffic, 'unblock' to remove deny rule
        ip_address: Device IP address to block/unblock
        vlan_id: VLAN ID (e.g., 10)

    Returns:
        bool: True if all targeted switches succeeded
    """
    # Derive VLAN ID from IP third octet if not provided (scheme: 192.168.<vlan>.x)
    if not vlan_id and ip_address:
        try:
            vlan_id = int(ip_address.split('.')[2])
        except (IndexError, ValueError):
            vlan_id = None

    if not vlan_id:
        logger.error("Unable to determine VLAN ID for ACL update")
        return False

    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    all_switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    if not all_switch_hosts:
        logger.error("manage_switch_acl: no SWITCH_HOSTS configured")
        return False

    if action == 'block':
        # Target only the ISP router's switch for this VLAN.
        isp_switch = _get_switch_host_for_vlan(vlan_id)
        if isp_switch:
            switch_hosts = [isp_switch]
            logger.info("manage_switch_acl block: targeting ISP router switch %s for VLAN %s",
                        isp_switch, vlan_id)
        else:
            switch_hosts = all_switch_hosts
            logger.warning("manage_switch_acl block: ISP router switch not found for VLAN %s,"
                           " falling back to all switches", vlan_id)
    else:
        # Unblock: hit all switches to remove any stale rules.
        switch_hosts = all_switch_hosts

    acl_num = 3000 + (vlan_id * 10)
    try:
        host_octet = int(ip_address.split('.')[3])
    except (IndexError, ValueError):
        logger.error("Unable to determine host octet for ACL rule")
        return False

    rule_num = 1000 + host_octet

    acl_script = os.getenv('ACL_QUEUE_SCRIPT', '/scripts/hp5130-acl.sh')
    use_acl_script = os.getenv('USE_ACL_QUEUE', '1') != '0'

    all_ok = True
    for switch_host in switch_hosts:
        if use_acl_script and os.path.isfile(acl_script):
            try:
                env = os.environ.copy()
                env['SWITCH_HOST'] = switch_host
                result = subprocess.run(
                    [acl_script, action, ip_address],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=env,
                )
                if result.returncode == 0:
                    logger.info("ACL %s queued for %s on %s via %s",
                                action, ip_address, switch_host, acl_script)
                    continue
                logger.warning(
                    "ACL queue script failed for %s on %s: %s",
                    ip_address, switch_host,
                    (result.stderr or result.stdout).strip()
                )
            except Exception as exc:
                logger.warning("ACL queue script error for %s on %s: %s",
                               ip_address, switch_host, exc)

        # Fallback: apply directly via SSH
        if action == 'block':
            logger.info("Adding ACL deny rule for %s on VLAN %s via SSH to %s",
                        ip_address, vlan_id, switch_host)
            commands = [
                "system-view",
                f"acl advanced {acl_num}",
                f"rule {rule_num} deny ip source {ip_address} 0",
                "quit", "quit", "save force"
            ]
        elif action == 'unblock':
            logger.info("Removing ACL deny rule for %s on VLAN %s via SSH to %s",
                        ip_address, vlan_id, switch_host)
            commands = [
                "system-view",
                f"acl advanced {acl_num}",
                f"undo rule {rule_num}",
                "quit", "quit", "save force"
            ]
        else:
            logger.error("Invalid action: %s", action)
            return False

        try:
            output = _run_switch_command(switch_host, '\n'.join(commands))
            if output is not None:
                if output:
                    logger.debug("SSH ACL output (%s): %s", switch_host, output)
            else:
                logger.error("Switch ACL %s failed for %s on %s: no response",
                             action, ip_address, switch_host)
                all_ok = False
        except Exception as e:
            logger.error("Switch ACL %s failed for %s on %s: %s",
                         action, ip_address, switch_host, e)
            all_ok = False

    return all_ok


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
    return os.environ['SWITCH_HOST']


def _find_switch_port_for_mac(client_or_host, mac_address):
    """Find which physical switch port a MAC is on.
    client_or_host is either the SWITCH_HOST string or legacy paramiko client (ignored).
    Uses _run_switch_command via subprocess ssh, matching hp5130-port-lookup.sh behaviour.
    """
    switch_host = os.environ['SWITCH_HOST']

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
        switch_host = os.environ['SWITCH_HOST']
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
    """Block a device per spec B/C: set internet_blocked=True, internet_accessible=null,
    apply DNS hijack and ACL block to the device's current IP.

    If the device's current IP is in the blocked pool, Kea's block-status is still
    set so future leases will also come from the blocked pool.  No new hijack/ACL is
    needed in that case because blocked-pool IPs always have blanket rules.
    """
    _set_internet_blocked(device, True, commit=False)
    db.session.commit()
    clear_unregistered_lease(device.mac_address)

    # Ask Kea to flag this MAC for the blocked pool so future renewals land there.
    kea = get_kea()
    if kea and device.current_vlan:
        kea.set_block_status(device.mac_address, device.current_vlan, True,
                             blocked_ip=device.ip_address)
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
        # Only apply per-IP rules if the IP is NOT already in the blocked pool
        # (blocked-pool IPs are covered by blanket ranges).
        acl_success = True
        if not _is_blocked_pool_ip(device.ip_address):
            manage_dns_hijack('hijack', device.ip_address)
            acl_success = manage_switch_acl('block', device.ip_address, device.current_vlan)
            # Update IPLease record
            lease = _get_active_iplease(device.mac_address)
            if lease:
                lease.dns_hijacked = True
                db.session.commit()
        if flash_messages:
            if acl_success:
                flash(f'Device {device.mac_address} blocked. Internet access denied.', 'success')
            else:
                flash(f'Device {device.mac_address} marked as blocked, but ACL update failed.', 'warning')
        logger.info("Blocked device %s at %s (acl_success=%s)", device.mac_address,
                    device.ip_address, acl_success)
    else:
        if flash_messages:
            flash(f'Device {device.mac_address} marked as blocked (no active IP found).', 'warning')
        logger.warning("Block: no IP/VLAN for device %s", device.mac_address)

    cleanup_orphan_hijack_rules()
    central_client.queue_device_blocked(device)


def apply_device_unblock(device, flash_messages=False):
    """Unblock a device per spec B/C:
    - Clear internet_blocked.
    - If conditions for internet access are met (correct VLAN, ownership validated),
      remove DNS hijack and ACL block, then set internet_accessible=True.
    - Otherwise set internet_accessible=False (wrong VLAN or unvalidated password VLAN).
    """
    # An admin unblock is an explicit grant: accept the device on whatever VLAN it is
    # currently on.  Update assigned_vlan → current_vlan so that _should_have_internet()
    # succeeds regardless of any prior VLAN mismatch.
    if device.current_vlan and _get_active_ownership(device.mac_address):
        if not device.assigned_vlan or device.assigned_vlan != device.current_vlan:
            device.assigned_vlan = device.current_vlan

    _set_internet_blocked(device, None, commit=False)
    db.session.commit()
    clear_unregistered_lease(device.mac_address)

    # Ask Kea to remove the block-pool flag so future leases come from the main pool.
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

    lease = _get_active_iplease(device.mac_address)
    ip_in_blocked_pool = (
        _is_blocked_pool_ip(device.ip_address) or
        (lease and lease.from_blocked_pool)
    )

    if _should_have_internet(device) and not ip_in_blocked_pool:
        # Remove DNS hijack and ACL block synchronously, then mark accessible.
        acl_success = True
        if device.ip_address and device.current_vlan:
            if _should_hijack_vlan(device.current_vlan):
                manage_dns_hijack('unhijack', device.ip_address)
            acl_success = manage_switch_acl('unblock', device.ip_address, device.current_vlan)
            if blocked_ip and blocked_ip != device.ip_address:
                manage_switch_acl('unblock', blocked_ip, device.current_vlan)
                if _should_hijack_vlan(device.current_vlan):
                    manage_dns_hijack('unhijack', blocked_ip)
            # Update IPLease
            if lease:
                lease.dns_hijacked = False
                db.session.commit()
        _set_internet_accessible(device, True, commit=True)
        if flash_messages:
            if acl_success:
                flash(f'Device {device.mac_address} unblocked. Internet access restored.', 'success')
            else:
                flash(f'Device {device.mac_address} unblocked, but ACL removal failed.', 'warning')
        logger.info("Unblocked device %s at %s", device.mac_address, device.ip_address)
    else:
        # Can't grant internet yet: wrong VLAN, unvalidated password, or blocked pool.
        _set_internet_accessible(device, False if device.assigned_vlan else None, commit=True)
        if flash_messages:
            if ip_in_blocked_pool:
                flash(
                    f'Device {device.mac_address} unblocked. '
                    'It is in the blocked pool — disconnect and reconnect to regain access.',
                    'info',
                )
            else:
                flash(
                    f'Device {device.mac_address} unblocked, but it is on the wrong VLAN '
                    f'or still needs password validation.',
                    'info',
                )
        logger.info("Unblocked device %s: conditions not yet met for internet access", device.mac_address)

    # Supersede any rejected registration request so the user can re-register if needed.
    RegistrationRequest.query.filter_by(
        mac_address=device.mac_address, status='rejected'
    ).update(
        {'status': 'superseded', 'processed_at': datetime.utcnow(),
         'processed_by': 'superseded-by-admin-unblock'},
        synchronize_session=False,
    )
    db.session.commit()

    cleanup_orphan_hijack_rules()




@app.route('/', methods=['GET', 'POST', 'OPTIONS'])
def index():
    """Spec section 4: captive portal root page.

    4a – No MAC found → not on local network → redirect to /login.
    4b – MAC found → check ownership/access state and redirect accordingly.
    """
    if request.method == 'OPTIONS':
        response = app.make_response('')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'
        return response, 200

    mac_address = get_client_mac()

    # Spec 4a: device not on local network → redirect to login
    if not mac_address:
        return redirect(_build_portal_url(url_for('user_login')))

    # Spec 4b: device is on local network
    device    = Device.query.filter_by(mac_address=mac_address).first()
    ownership = _get_active_ownership(mac_address) if device else None

    # Blocked device — render inline without redirecting to /blocked
    if device and device.internet_blocked:
        return render_template('blocked.html',
                               ip_address=get_client_ip(),
                               mac_address=mac_address,
                               admin_email=os.getenv('ADMIN_EMAIL', 'admin@example.com'))

    # No active ownership → show registration form (spec 4b.i)
    if not ownership:
        return redirect(_build_portal_url(url_for('register')))

    # Active ownership → show register route which renders the status page (spec 4b.ii)
    return redirect(_build_portal_url(url_for('register')))


@app.route('/api/device-status')
def api_device_status():
    """Polling endpoint for the captive portal status page (spec 4b.ii).

    Returns JSON describing the current internet-access state for the calling
    device so the client-side JS can update its UI without a full page reload.
    """
    mac_address = get_client_mac()
    if not mac_address:
        return jsonify({'status': 'no_mac'}), 200

    device    = Device.query.filter_by(mac_address=mac_address).first()
    ownership = _get_active_ownership(mac_address) if device else None

    if not device or not ownership:
        return jsonify({'status': 'unregistered'}), 200

    # Get latest active lease for blocked-pool and dns_hijacked info.
    lease = _get_active_iplease(mac_address)

    # Spec B: internet_blocked takes priority over everything else — check first
    # so a blocked user never sees a password prompt or approval wait.
    if device.internet_blocked:
        return jsonify({'status': 'blocked'})

    # Determine selected/detected VLAN and password requirements.
    ip_address  = get_client_ip()
    _, detected_vlan, _ = detect_connection_type(ip_address)
    selected_vlan = device.assigned_vlan or detected_vlan
    password_required  = _vlan_requires_password(selected_vlan) if selected_vlan else False

    # Spec 4b.ii.1: password VLAN, not yet ownership_validated
    if password_required and not device.ownership_validated:
        return jsonify({
            'status':            'need_password',
            'has_password':      device.user.has_network_password if device.user else False,
            'selected_vlan':     selected_vlan,
        })

    # Spec 4b.ii.2
    assigned_vlan = device.assigned_vlan

    if assigned_vlan is None:
        return jsonify({
            'status':        'pending_approval',
            'selected_vlan': selected_vlan,
        })

    if assigned_vlan != detected_vlan:
        from models import VlanMapping as _VM
        assigned_ssid = get_ssid_for_vlan(assigned_vlan)
        return jsonify({
            'status':         'wrong_vlan',
            'assigned_vlan':  assigned_vlan,
            'assigned_ssid':  assigned_ssid,
            'detected_vlan':  detected_vlan,
        })

    # assigned_vlan == detected_vlan
    if device.internet_accessible is True:
        user_home_url = _build_portal_url(url_for('user_home'))
        return jsonify({
            'status':              'accessible',
            'user_home_url':       user_home_url,
            'ownership_validated': bool(device.ownership_validated),
        })

    if device.internet_accessible is False:
        return jsonify({
            'status': 'access_refused',
            'notes':  getattr(device, 'admin_notes', None),
        })

    # internet_accessible is None: provisioning in progress
    from_blocked_pool = lease.from_blocked_pool if lease else False
    if from_blocked_pool:
        return jsonify({'status': 'blocked_pool', 'assigned_vlan': assigned_vlan})

    # None + not blocked pool + dns_hijacked → should we auto-complete the grant?
    # Perform the unhijack here if conditions are met (spec 4b.ii.2.a.ii.3c).
    if lease and lease.dns_hijacked and not from_blocked_pool:
        if _should_have_internet(device):
            ip_addr = lease.ip_address
            if ip_addr:
                if _should_hijack_vlan(assigned_vlan):
                    manage_dns_hijack('unhijack', ip_addr)
                manage_switch_acl('unblock', ip_addr, assigned_vlan)
            lease.dns_hijacked = False
            db.session.commit()
            _set_internet_accessible(device, True, commit=True)
            # spec 4b.ii.2.a.ii.1.c.i: send ownership-confirmation email if
            # ownership has not yet been validated via a password.
            if not device.ownership_validated and device.user:
                _u = device.user
                _unreg = _build_unregister_url(device.unregister_token)
                _curl, _rurl, _ctimeout = _set_wifi_confirmation(device)
                send_wifi_registration_confirmation(
                    _u.email,
                    _u.first_name or 'there',
                    get_ssid_for_vlan(assigned_vlan) or 'Network',
                    device.mac_address,
                    _unreg,
                    confirm_url=_curl,
                    reject_url=_rurl,
                    confirm_timeout_sec=_ctimeout,
                    registration_details={},
                )
            _accessible_resp = {
                'status':              'accessible',
                'user_home_url':       _build_portal_url(url_for('user_home')),
                'ownership_validated': bool(device.ownership_validated),
            }
            if not device.ownership_validated:
                _accessible_resp['confirm_timeout_minutes'] = _wifi_confirm_timeout_minutes()
            return jsonify(_accessible_resp)

    return jsonify({'status': 'pending'})




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
@app.route('/api/request-unblock', methods=['POST', 'OPTIONS'])
def api_request_unblock():
    """Send an unblock request email to all manage_users admins on behalf of the
    connecting device (spec 4b.ii.2.a.i — blocked device contact-admin link)."""
    if request.method == 'OPTIONS':
        resp = app.make_response('')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        return resp, 200

    mac_address = get_client_mac()
    ip_address  = get_client_ip()
    device = Device.query.filter_by(mac_address=mac_address).first() if mac_address else None
    user   = device.user if device else None

    try:
        send_admin_unblock_request(
            mac_address  or 'Unknown',
            ip_address   or 'Unknown',
            user_name    = f"{user.first_name} {user.last_name}".strip() if user else None,
            user_email   = user.email if user else None,
        )
    except Exception as exc:
        logger.warning("Failed to send unblock request email: %s", exc)

    response = jsonify({'status': 'ok', 'message': 'Your request has been sent to the administrator.'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@app.route('/.well-known/captive-portal')
def rfc8908_captive_portal():
    """RFC 8908 Captive Portal API endpoint.

    Probed natively by iOS 14+ and Android 11+ before legacy detection methods.
    Returns JSON indicating whether the device is captive and the portal URL.
    """
    mac_address = get_client_mac()
    portal_url = _build_portal_url(url_for('register'))
    captive = True  # default: assume captive if we can't identify the device

    if mac_address:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device:
            if device.internet_blocked:
                portal_url = _build_portal_url(url_for('register'))
            elif device.internet_accessible:
                captive = False

    response = jsonify({
        'captive': captive,
        'user-portal-url': portal_url,
    })
    response.headers['Content-Type'] = 'application/captive+json'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/generate_204')
@app.route('/gen_204')
def android_captive_portal_detection():
    """Android captive portal detection - return 302 to show portal"""
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
    """iOS captive portal detection - return 302 to show portal"""
    return redirect(_build_portal_url(url_for('register'))), 302


@app.route('/library/test/success.html')
def ios_captive_success():
    """iOS captive portal success check"""
    return redirect(_build_portal_url(url_for('register'))), 302

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
    return redirect(_build_portal_url(url_for('register'))), 302


@app.route('/portal')

@app.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def register():
    """Spec section 4b: captive portal reached from a device on the local network.

    GET  – Show registration form (unregistered device) or status page
           (owned device that doesn't yet have internet access).
    POST – Handle form submission per spec 4b.i.
    """
    if request.method == 'GET' and _portal_host_mismatch():
        qs = request.query_string.decode('utf-8', errors='ignore')
        target = _build_portal_url(url_for('register'))
        if qs:
            target = f"{target}?{qs}"
        return redirect(target)

    # ── OPTIONS pre-flight ────────────────────────────────────────────────────
    if request.method == 'OPTIONS':
        response = app.make_response('')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        response.headers['Vary'] = 'Origin'
        return response, 200

    mac_address = get_client_mac()
    ip_address  = get_client_ip()
    is_ajax     = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    # Remote access guard: no MAC means device is not on the local network.
    if not mac_address and request.method == 'GET':
        return render_template(
            'error.html',
            code='Remote Access Not Supported',
            message=(
                'This registration page can only be used when your device is '
                'connected to the local network.  Please connect to the Wi-Fi '
                'or plug in an Ethernet cable, then visit this page again.'
            )
        ), 200

    detected_mac = mac_address
    detected_ip  = ip_address

    # Detect connection / VLAN
    connection_type, detected_vlan, ssid = detect_connection_type(ip_address)
    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
    is_wired_unregistered   = (connection_type == 'wired' and
                                detected_vlan == wired_unregistered_vlan)
    wired_vlan_options = [
        {
            'vlan_id': entry.vlan_id,
            'label':   _label_for_vlan(entry.vlan_id, get_vlan_map()),
        }
        for entry in _get_wired_assignable_entries()
    ]

    # ── GET: determine whether to show form or status ─────────────────────────
    if request.method == 'GET' and mac_address:
        device    = Device.query.filter_by(mac_address=mac_address).first()
        ownership = _get_active_ownership(mac_address) if device else None

        # Unknown device: check central before showing the registration form.
        # If central knows this device (registered at another premises), import
        # it locally so the user gets seamless access (or sees a block message)
        # without having to re-register.
        if not ownership and central_client._central_enabled():
            central_data = central_client.lookup_device_at_central(mac_address)
            if central_data:
                device = central_client.import_device_from_central(mac_address, central_data)
                if device:
                    ownership = _get_active_ownership(mac_address)

        # Device IS registered (has an active ownership record)
        if device and ownership:
            device = normalize_device_status(device)
            # Blocked device (device or user) — render inline without a redirect
            if device.internet_blocked:
                return render_template('blocked.html',
                                       ip_address=ip_address,
                                       mac_address=mac_address,
                                       admin_email=os.getenv('ADMIN_EMAIL', 'admin@example.com'))
            # Build prefill from the device's user so the hidden form fields
            # carry valid data when the JS password-entry prompt submits.
            _user_pf = device.user
            prefill_data = {
                'email':        _user_pf.email        or '' if _user_pf else '',
                'first_name':   _user_pf.first_name   or '' if _user_pf else '',
                'last_name':    _user_pf.last_name    or '' if _user_pf else '',
                'phone_number': _user_pf.phone_number or '' if _user_pf else '',
                'device_type':  device.device_name    or '',
            } if _user_pf else {}
            user_home_url = _build_portal_url(url_for('user_home'))
            return render_template(
                'register.html',
                show_status=True,
                device=device,
                prefill=prefill_data,
                detected_mac=detected_mac,
                detected_ip=detected_ip,
                wired_vlan_required=False,
                wired_vlan_options=wired_vlan_options,
                user_home_url=user_home_url,
                confirm_timeout_minutes=_wifi_confirm_timeout_minutes(),
            )

    # Fall through to registration form for GET (unregistered) or POST.
    prefill = _build_prefill_from_request()

    # ── POST: process registration form submission ────────────────────────────
    if request.method == 'POST':
        if not mac_address:
            if is_ajax:
                return jsonify({'status': 'error', 'message': 'Unable to determine your MAC address.'}), 400
            flash('Unable to determine your device MAC address. Please ensure you are on the local network.', 'error')
            return redirect(url_for('register'))

        # ── Two-step form: step 1 just checks whether the email exists ──────────
        # The front-end sends registration_step=1 on the first submit.  We check
        # if the email belongs to a known user and return their name/phone so the
        # client can skip the details page.  Anything other than "1" falls through
        # to the normal full-registration logic below.
        if (request.form.get('registration_step') or '').strip() == '1':
            email_check = (request.form.get('email') or '').strip().lower()
            if not email_check or '@' not in email_check:
                return jsonify({'status': 'error', 'message': 'A valid email address is required.'}), 400
            existing_user = User.query.filter_by(email=email_check).first()
            if existing_user:
                return jsonify({
                    'status': 'user_found',
                    'prefill': {
                        'first_name':   existing_user.first_name   or '',
                        'last_name':    existing_user.last_name    or '',
                        'phone_number': existing_user.phone_number or '',
                    },
                })
            return jsonify({'status': 'need_details'})

        # ── Field extraction ──────────────────────────────────────────────────
        email        = (request.form.get('email')        or '').strip().lower()
        first_name   = (request.form.get('first_name')   or '').strip()
        last_name    = (request.form.get('last_name')    or '').strip()
        phone_number = (request.form.get('phone_number') or '').strip()
        device_type  = (request.form.get('device_type')  or '').strip()
        password_input = (request.form.get('network_password') or '').strip()

        # Wired VLAN selection (only applies when device is on wired_unregistered VLAN)
        wired_vlan_id = None
        if is_wired_unregistered:
            raw = (request.form.get('wired_vlan_id') or '').strip()
            try:
                wired_vlan_id = int(raw)
            except ValueError:
                pass
            # Fallback: for password re-submission the dropdown isn't present;
            # use the VLAN the device chose on its original registration.
            if not wired_vlan_id:
                _dev_for_vlan = Device.query.filter_by(mac_address=mac_address).first()
                if _dev_for_vlan and _dev_for_vlan.wired_target_vlan:
                    wired_vlan_id = _dev_for_vlan.wired_target_vlan
            if not wired_vlan_id or wired_vlan_id not in _get_wired_assignable_vlan_ids():
                msg = 'Please select a valid wired VLAN.'
                if is_ajax:
                    return jsonify({'status': 'error', 'message': msg}), 400
                flash(msg, 'error')
                return render_template(
                    'register.html', prefill=prefill,
                    detected_mac=detected_mac, detected_ip=detected_ip,
                    wired_vlan_required=True, wired_vlan_options=wired_vlan_options,
                )

        # ── Basic validation ──────────────────────────────────────────────────
        if not email or '@' not in email:
            msg = 'A valid email address is required.'
            if is_ajax:
                return jsonify({'status': 'error', 'message': msg}), 400
            flash(msg, 'error')
            return render_template(
                'register.html', prefill=prefill,
                detected_mac=detected_mac, detected_ip=detected_ip,
                wired_vlan_required=is_wired_unregistered,
                wired_vlan_options=wired_vlan_options,
            )

        # The VLAN the user wants to join.
        selected_vlan = wired_vlan_id if is_wired_unregistered else detected_vlan

        # ── Profile snapshot for unregister rollback ──────────────────────────
        existing_user_before = User.query.filter_by(email=email).first()
        profile_snapshot = None
        if existing_user_before:
            profile_snapshot = json.dumps({
                'previous': {
                    'first_name':   existing_user_before.first_name or '',
                    'last_name':    existing_user_before.last_name  or '',
                    'phone_number': existing_user_before.phone_number or '',
                },
                'new': {
                    'first_name':   first_name,
                    'last_name':    last_name,
                    'phone_number': phone_number,
                },
            })

        # ── Spec step 1/2: upsert User (Table 8) ─────────────────────────────
        user = User.query.filter_by(email=email).first()
        if user:
            # Update name/phone but not email or registration date.
            user.first_name   = first_name   or user.first_name
            user.last_name    = last_name    or user.last_name
            user.phone_number = phone_number or user.phone_number
            db.session.commit()
        else:
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                begin_date=datetime.utcnow().date(),
                created_by='registration',
            )
            db.session.add(user)
            db.session.flush()

        # ── Spec step 3: get/upsert Device (Table 6) ─────────────────────────
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            device = Device(
                mac_address=mac_address,
                first_seen=datetime.utcnow(),
            )
            db.session.add(device)

        network_mismatch = bool(
            connection_type == 'wifi'
            and detected_vlan
            and device.current_vlan
            and detected_vlan != device.current_vlan
        )

        device.device_name      = device_type or device.device_name
        device.user_id          = user.id
        device.ip_address       = ip_address
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

        # ── Spec step 6: ensure DeviceOwnership (Table 9) is active ──────────
        # Open new ownership if none exists or if previously owned by a different user.
        active_ownership = _get_active_ownership(mac_address)
        if active_ownership and active_ownership.user_id != user.id:
            _close_ownership(mac_address, commit=True)
            active_ownership = None
        if not active_ownership:
            _open_ownership(mac_address, user.id, commit=True)

        # ── Blocked-user check ────────────────────────────────────────────────
        # If the user account is blocked, register the device under their name but
        # immediately set internet_blocked=True so they cannot gain internet access.
        if user.blocked:
            device.assigned_vlan = selected_vlan or detected_vlan
            _set_internet_blocked(device, True, commit=True)
            _msg = 'The administrator has blocked you from connecting any devices to the internet.'
            if is_ajax:
                return jsonify({'status': 'blocked', 'message': _msg}), 403
            return redirect(url_for('request_rejected', reason=_msg))

        # ── Password-required VLAN handling (spec 4b.ii.1) ───────────────────
        if selected_vlan and _vlan_requires_password(selected_vlan) and not device.ownership_validated:
            if not user.has_network_password:
                # No password set yet – send set-password email and wait.
                if not user.network_password_set_token:
                    user.network_password_set_token = secrets.token_urlsafe(32)
                    user.network_password_set_token_expires = (
                        datetime.utcnow() + timedelta(hours=24)
                    )
                    db.session.commit()
                set_password_url = _build_set_password_url(user.network_password_set_token)
                send_network_password_set_email(
                    email, first_name or 'there', set_password_url,
                    network_name=ssid or 'Wired Network',
                )
                if is_ajax:
                    return jsonify({
                        'status': 'pending_password',
                        'message': 'A network password is required for this VLAN. '
                                   'Please check your email for a link to set your password.',
                    })
                return redirect(url_for('pending_approval'))

            # Password exists – check submitted password.
            if not password_input:
                # Form didn't include a password; show the password entry page.
                if is_ajax:
                    return jsonify({
                        'status': 'need_password',
                        'message': 'Please enter your network password.',
                    })
                return render_template(
                    'register.html',
                    show_password_form=True,
                    prefill=prefill,
                    detected_mac=detected_mac,
                    detected_ip=detected_ip,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

            if not user.check_network_password(password_input):
                msg = 'Incorrect network password.'
                if is_ajax:
                    return jsonify({'status': 'error', 'message': msg}), 400
                flash(msg, 'error')
                return render_template(
                    'register.html',
                    show_password_form=True,
                    prefill=prefill,
                    detected_mac=detected_mac,
                    detected_ip=detected_ip,
                    wired_vlan_required=is_wired_unregistered,
                    wired_vlan_options=wired_vlan_options,
                )

            # Correct password: mark ownership validated.
            device.ownership_validated = True
            db.session.commit()

        # ── Spec steps 4/5: determine approval requirement ────────────────────
        # Auto-approve when the selected VLAN is in the user's effective_allowed set.
        domain_policy_map = _load_domain_policy_map()
        effective_allowed, _ = _get_effective_vlans_for_user(user, domain_policy_map)
        needs_approval = bool(selected_vlan and selected_vlan not in effective_allowed)

        if needs_approval:
            # ── Needs admin approval (spec step 4) ────────────────────────────
            # assigned_vlan stays null until admin approves.
            # Close any stale pending request for this MAC first.
            RegistrationRequest.query.filter(
                RegistrationRequest.mac_address == mac_address,
                RegistrationRequest.status == 'pending',
            ).update(
                {'status': 'superseded', 'processed_at': datetime.utcnow(),
                 'processed_by': 'superseded-by-new-submission'},
                synchronize_session=False,
            )
            reg_request = RegistrationRequest(
                mac_address=mac_address,
                ip_address=ip_address,
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                device_type=device_type,
                requested_vlan=selected_vlan,
                status='pending',
                approval_token=secrets.token_urlsafe(32),
            )
            db.session.add(reg_request)
            db.session.commit()

            portal_url = os.getenv('PORTAL_URL')
            if portal_url:
                parsed = urlparse(portal_url)
                approval_url = (
                    f"{parsed.scheme}://{parsed.netloc}"
                    f"{url_for('admin_approve_request', token=reg_request.approval_token)}"
                )
            else:
                approval_url = url_for(
                    'admin_approve_request',
                    token=reg_request.approval_token,
                    _external=True,
                )
            send_admin_notification(reg_request, approval_url, selected_vlan,
                                    ssid or 'Wired Network')

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
            return redirect(url_for('pending_approval'))

        # ── Auto-approve (spec step 5) ─────────────────────────────────────────
        # Set assigned_vlan, remove hijack/ACL, set internet_accessible=True.
        device.assigned_vlan = selected_vlan
        device.current_vlan  = selected_vlan if not is_wired_unregistered else detected_vlan

        db.session.commit()

        # Network changes
        if connection_type == 'wifi':
            kea = get_kea()
            if kea:
                kea.register_mac(
                    mac=mac_address,
                    vlan=selected_vlan,
                    hostname=f"{(first_name or 'device').lower()}-{(last_name or '').lower()}",
                    ip_address=None,
                )
                if ip_address and not network_mismatch:
                    kea.force_lease_renewal(mac_address, ip_address)
        else:
            send_coa_change(mac_address, selected_vlan)
            replug_switch_port_for_mac(mac_address)

        # Remove DNS hijack and ACL block (synchronous) then mark accessible.
        if ip_address and not network_mismatch and not _is_blocked_pool_ip(ip_address):
            if _should_hijack_vlan(selected_vlan or detected_vlan):
                manage_dns_hijack('unhijack', ip_address)
            if detected_vlan:
                manage_switch_acl('unblock', ip_address, detected_vlan)
            # Update IPLease record.
            lease = _get_active_iplease(mac_address)
            if lease:
                lease.dns_hijacked = False
                db.session.commit()
            _set_internet_accessible(device, True, commit=True)
        else:
            # Blocked-pool IP or VLAN mismatch – can't grant access yet.
            _set_internet_accessible(device, None, commit=True)

        clear_unregistered_lease(mac_address)

        # Close any outstanding registration requests for this MAC.
        RegistrationRequest.query.filter(
            RegistrationRequest.mac_address == mac_address,
            RegistrationRequest.status.in_(['pending', 'pending_password']),
        ).update(
            {'status': 'approved', 'processed_at': datetime.utcnow(),
             'processed_by': 'auto-approved'},
            synchronize_session=False,
        )
        db.session.commit()

        # Confirmation email
        unregister_url = _build_unregister_url(device.unregister_token)
        # spec 4b.ii.2.a.ii.1.c.i: the ownership-confirmation email ("please confirm
        # this acceptance") is only sent when ownership_validated is False.  If the
        # user entered the correct VLAN password above, ownership_validated is already
        # True — no confirmation timer or confirm link should be started.
        if not device.ownership_validated:
            confirm_url, reject_url, confirm_timeout_sec = _set_wifi_confirmation(device)
        else:
            confirm_url = None
            reject_url = None
            confirm_timeout_sec = None
        ssid_display = ssid or 'Wired Network'
        send_wifi_registration_confirmation(
            user.email,
            user.first_name or first_name or 'there',
            ssid_display,
            mac_address,
            unregister_url,
            confirm_url=confirm_url,
            reject_url=reject_url,
            confirm_timeout_sec=confirm_timeout_sec,
            registration_details={
                'email':        user.email,
                'first_name':   user.first_name or first_name,
                'last_name':    user.last_name  or last_name,
                'phone_number': user.phone_number or phone_number,
                'device_type':  device_type,
                'ip_address':   ip_address,
                'ssid':         ssid_display,
            },
        )

        # Notify central server of the new registration (queued, non-blocking)
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
                _resp['confirm_timeout_minutes'] = _wifi_confirm_timeout_minutes()
            return jsonify(_resp)
        return redirect(url_for('registered'))

    # ── GET: show registration form ───────────────────────────────────────────
    return render_template(
        'register.html',
        prefill=prefill,
        detected_mac=detected_mac,
        detected_ip=detected_ip,
        wired_vlan_required=is_wired_unregistered,
        wired_vlan_options=wired_vlan_options,
    )

# END register()


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
        network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
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
        existing.current_vlan = target_vlan
        existing.connection_type = 'wired' if vlan_id == wired_unregistered_vlan else 'wifi'
        existing.ssid = get_ssid_for_vlan(target_vlan)
        existing.is_wired = vlan_id == wired_unregistered_vlan
        existing.wired_target_vlan = target_vlan if vlan_id == wired_unregistered_vlan else None
        existing.assigned_vlan = target_vlan
        existing.ownership_validated = True
        if device_label:
            existing.device_name = device_label
        if ip_address:
            existing.ip_address = ip_address
        existing.unregister_token = existing.unregister_token or secrets.token_urlsafe(32)
        db.session.flush()
        adopted_device = existing
    else:
        adopted_device = Device(
            mac_address=mac_address,
            user_id=user.id,
            device_name=device_label or 'adopted-device',
            ip_address=ip_address,
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

    # Create DeviceOwnership record
    _close_ownership(mac_address, commit=False)
    _open_ownership(mac_address, user.id, commit=False)
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

    _set_internet_accessible(adopted_device, True)
    clear_unregistered_lease(mac_address)

    unregister_url = _build_unregister_url(adopted_device.unregister_token)
    confirm_url = None
    reject_url = None
    confirm_timeout_sec = None
    if not adopted_device.ownership_validated:
        confirm_url, reject_url, confirm_timeout_sec = _set_wifi_confirmation(adopted_device)
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
        reject_url=reject_url,
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


# ── User-facing login and home page (spec 4a, 5) ──────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    """Spec 4a: Users who access the portal from outside the local network.

    Presents an email + password login form.  On success, redirects to /user_home.
    """
    if request.method == 'POST':
        email    = (request.form.get('email')    or '').strip().lower()
        password = (request.form.get('password') or '').strip()

        user = User.query.filter_by(email=email).first()
        if user and user.check_network_password(password):
            # Store user id in session so user_home can identify the caller.
            session['portal_user_id'] = user.id
            return redirect(url_for('user_home'))

        flash('Invalid email or password.', 'error')
        return render_template('user_login.html', prefill_email=email)

    # If coming from local network, try device-based auto-auth scoped to this session.
    mac_address = get_client_mac()
    if mac_address:
        _dev = Device.query.filter_by(mac_address=mac_address).first()
        if _dev:
            _own = _get_active_ownership(mac_address)
            if _own and _own.user_id and _dev.ownership_validated:
                _u = User.query.get(_own.user_id)
                if _u:
                    session['portal_user_id'] = _u.id
                    return redirect(url_for('user_home'))

    return render_template('user_login.html')


@app.route('/user_home', methods=['GET', 'POST'])
def user_home():
    """Spec section 5: user home page.

    The user can reach this page:
    - From outside the local network (session['portal_user_id'] set after login).
    - From inside the local network when their device has internet access
      (ownership_validated=True for the calling device).
    """
    # Determine the user from session or from the calling device.
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
                ownership = _get_active_ownership(mac_address)
                if ownership and ownership.user_id:
                    user = User.query.get(ownership.user_id)

    if not user:
        return redirect(url_for('user_login'))

    vlan_map = get_vlan_map()
    domain_policy_map = _load_domain_policy_map()

    # Owned devices (active ownerships for this user)
    owned_ownerships = DeviceOwnership.query.filter_by(
        user_id=user.id, end_datetime=None
    ).all()
    owned_macs = [o.mac_address for o in owned_ownerships]
    owned_devices = Device.query.filter(Device.mac_address.in_(owned_macs)).all() if owned_macs else []

    owned_device_rows = []
    for dev in owned_devices:
        lease = _get_active_iplease(dev.mac_address)
        owned_device_rows.append({
            'device': dev,
            'ip_address':   lease.ip_address if lease else dev.ip_address,
            'lease_expiry': lease.lease_expiry if lease else None,
            'vlan_label':   _label_for_vlan(dev.assigned_vlan or dev.current_vlan, vlan_map),
        })

    # Unregistered devices the user may adopt (spec 5).
    # effective_adoptable: VLANs adoptable without admin approval (show MAC).
    # effective_allowed:   VLANs adoptable only with admin approval (hide MAC).
    effective_allowed, effective_adoptable = _get_effective_vlans_for_user(user, domain_policy_map)
    wired_unregistered_vlan = _get_wired_unregistered_vlan_id()
    all_interaction_vlan_ids = (effective_allowed | effective_adoptable) - {wired_unregistered_vlan}
    adoptable_leases = _load_adoptable_leases(all_interaction_vlan_ids) if all_interaction_vlan_ids else []

    # Filter out devices that are already owned by someone.
    unregistered_rows = []
    for entry in adoptable_leases:
        mac = entry.get('mac_address')
        if not mac:
            continue
        if _get_active_ownership(mac):
            continue
        vlan_id = entry.get('vlan_id')
        unregistered_rows.append({
            'mac_address':    mac,
            'show_mac':       vlan_id in effective_adoptable,
            'ip_address':     entry.get('ip_address'),
            'vlan_id':        vlan_id,
            'vlan_label':     _label_for_vlan(vlan_id, vlan_map),
            'first_seen':     entry.get('first_seen'),
            'needs_approval': vlan_id not in effective_adoptable,
        })

    if request.method == 'POST':
        action = request.form.get('action', '')

        # ── Profile update ────────────────────────────────────────────────────
        if action == 'update_profile':
            user.first_name   = (request.form.get('first_name')   or '').strip() or user.first_name
            user.last_name    = (request.form.get('last_name')    or '').strip() or user.last_name
            user.phone_number = (request.form.get('phone_number') or '').strip() or user.phone_number
            db.session.commit()
            flash('Profile updated.', 'success')

        # ── Password change ───────────────────────────────────────────────────
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
                flash('Password changed.', 'success')

        # ── Abandon a device (spec 5a) ─────────────────────────────────────────
        elif action == 'abandon':
            mac_to_abandon = (request.form.get('mac_address') or '').strip().lower()
            if mac_to_abandon in owned_macs:
                dev_to_abandon = Device.query.filter_by(mac_address=mac_to_abandon).first()
                if dev_to_abandon:
                    # Block the device before abandoning.
                    lease = _get_active_iplease(mac_to_abandon)
                    if lease and not lease.from_blocked_pool:
                        if _should_hijack_vlan(dev_to_abandon.current_vlan):
                            manage_dns_hijack('hijack', lease.ip_address)
                            lease.dns_hijacked = True
                        if dev_to_abandon.current_vlan:
                            manage_switch_acl('block', lease.ip_address, dev_to_abandon.current_vlan)
                    # Reset Table 6 fields.
                    dev_to_abandon.user_id            = None
                    dev_to_abandon.assigned_vlan      = None
                    dev_to_abandon.ownership_validated = None
                    dev_to_abandon.device_name        = None
                    dev_to_abandon.first_seen         = datetime.utcnow()
                    _set_internet_accessible(dev_to_abandon, None, commit=False)
                    _set_internet_blocked(dev_to_abandon, None, commit=False)
                    db.session.commit()
                # Close ownership.
                _close_ownership(mac_to_abandon, commit=True)
                # Remove from RADIUS for wired devices.
                kea = get_kea()
                if kea and dev_to_abandon and dev_to_abandon.current_vlan:
                    kea.unregister_mac(mac_to_abandon, dev_to_abandon.current_vlan)
                flash(f'Device {mac_to_abandon} abandoned.', 'success')

        # ── Adopt request (spec 5b — admin approval required) ─────────────────
        elif action == 'adopt_request':
            mac_to_adopt = (request.form.get('mac_address') or '').strip().lower()
            vlan_raw     = (request.form.get('vlan_id')     or '').strip()
            try:
                adopt_vlan_id = int(vlan_raw)
            except ValueError:
                flash('Invalid VLAN for adoption request.', 'error')
                return redirect(url_for('user_home'))

            _eff_allowed, _eff_adoptable = _get_effective_vlans_for_user(user)
            if adopt_vlan_id not in _eff_allowed:
                flash('You do not have permission to request adoption for that network.', 'error')
                return redirect(url_for('user_home'))
            if adopt_vlan_id in _eff_adoptable:
                flash('You can adopt this device directly without approval.', 'info')
                return redirect(url_for('adopt_devices'))

            # Look up current lease IP if available.
            _adopt_lease = UnregisteredLease.query.filter_by(mac_address=mac_to_adopt).first()
            _adopt_ip = _adopt_lease.ip_address if _adopt_lease else None

            pending = RegistrationRequest(
                mac_address=mac_to_adopt,
                ip_address=_adopt_ip,
                email=user.email,
                first_name=user.first_name or '',
                last_name=user.last_name or '',
                phone_number=user.phone_number or '',
                device_type='adopted-device',
                status='pending',
                approval_token=secrets.token_urlsafe(32),
            )
            db.session.add(pending)
            db.session.commit()

            _portal_url = os.getenv('PORTAL_URL')
            if _portal_url:
                _parsed = urlparse(_portal_url)
                _approval_url = f"{_parsed.scheme}://{_parsed.netloc}{url_for('admin_approve_request', token=pending.approval_token)}"
            else:
                _approval_url = url_for('admin_approve_request', token=pending.approval_token, _external=True)

            send_admin_notification(pending, _approval_url, adopt_vlan_id,
                                    get_ssid_for_vlan(adopt_vlan_id))
            flash('Your adoption request has been sent to the administrator for approval.', 'info')

        return redirect(url_for('user_home'))

    return render_template(
        'user_home.html',
        user=user,
        owned_devices=owned_device_rows,
        unregistered_devices=unregistered_rows,
        calling_device=calling_device,
    )


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
    """Send a password-set/reset link to any registered user, whether or not they
    already have a network password.  Used from the /login page."""
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
    if user:
        # Generate / refresh token regardless of whether a password exists.
        user.network_password_set_token = secrets.token_urlsafe(32)
        user.network_password_set_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        set_password_url = _build_set_password_url(user.network_password_set_token)
        try:
            if user.has_network_password:
                send_network_password_reset_email(
                    user.email,
                    user.first_name or 'there',
                    set_password_url,
                )
            else:
                send_network_password_set_email(
                    user.email,
                    user.first_name or 'there',
                    set_password_url,
                    network_name='Portal',
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


@app.route('/wrong-vlan')
def wrong_vlan_page():
    """Shown when the admin has assigned the user to a different VLAN (spec 4b.ii.2.c)."""
    mac_address = get_client_mac()
    device = Device.query.filter_by(mac_address=mac_address).first() if mac_address else None
    assigned_vlan = (device.assigned_vlan if device else None) or request.args.get('assigned_vlan')
    assigned_ssid = get_ssid_for_vlan(int(assigned_vlan)) if assigned_vlan else request.args.get('assigned_ssid')
    _, detected_vlan, _ = detect_connection_type(get_client_ip())
    detected_ssid = get_ssid_for_vlan(detected_vlan) if detected_vlan else None
    return render_template(
        'wrong_vlan.html',
        assigned_vlan=assigned_vlan,
        assigned_ssid=assigned_ssid,
        detected_ssid=detected_ssid,
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
        # Add PORTAL_URL from captive-portal/.env to allowed_origins if self-calls occur
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
    # Per spec: a device is only considered registered when there is an active
    # Table 9 (device_ownership) entry with end_datetime IS NULL.
    # A devices row created solely by the Kea DHCP hook (no ownership) must
    # still be treated as unregistered so the registration form is shown.
    if device and not _get_active_ownership(mac_address):
        # Check if the device was explicitly blocked by an admin — if so, report
        # immediately so the waiting-for-approval page can update in-place.
        if device.internet_blocked:
            _blocked_payload = {'status': 'blocked', 'message': 'Your device has been blocked from accessing the internet.'}
            # Check if blocked due to user account block first.
            if device.user and device.user.blocked:
                _blocked_payload['reason'] = 'The administrator has blocked you from connecting any devices to the internet.'
            else:
                # Fall back to rejection reason from most recent rejected request.
                _rej_req = RegistrationRequest.query.filter_by(
                    mac_address=mac_address, status='rejected'
                ).order_by(RegistrationRequest.submitted_at.desc()).first()
                if _rej_req and _rej_req.notes:
                    _blocked_payload['reason'] = _rej_req.notes
            _resp = jsonify(_blocked_payload)
            _resp.headers['Access-Control-Allow-Origin'] = '*'
            return _resp
        # Check if the most recent registration request for this MAC was rejected —
        # if so return 'rejected' so pending_approval.html can update accordingly.
        _recent_req = RegistrationRequest.query.filter_by(
            mac_address=mac_address
        ).order_by(RegistrationRequest.submitted_at.desc()).first()
        if _recent_req and _recent_req.status == 'rejected':
            _payload = {'status': 'rejected', 'message': 'Your registration request was rejected.'}
            if _recent_req.notes:
                _payload['reason'] = _recent_req.notes
            _resp = jsonify(_payload)
            _resp.headers['Access-Control-Allow-Origin'] = '*'
            return _resp
        response = jsonify({'status': 'unregistered', 'message': 'Not registered'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    if device:
        current_ip = get_client_ip()
        current_connection, current_vlan, detected_ssid = detect_connection_type(current_ip)
        current_ssid = get_ssid_for_vlan(current_vlan) or detected_ssid
        expected_ssid = get_ssid_for_vlan(device.current_vlan) or device.ssid
        network_mismatch = bool(current_connection == 'wifi' and current_vlan and device.current_vlan and current_vlan != device.current_vlan)

        # ── Spec 4b.ii.1: password-VLAN state check ──────────────────────────
        # If the selected VLAN requires a password and ownership_validated is
        # not yet set, return the password state regardless of registration_status
        # so the captive portal shows the correct UI (not "Awaiting approval").
        _selected_vlan_r = device.assigned_vlan or current_vlan
        _pw_required_r = _vlan_requires_password(_selected_vlan_r) if _selected_vlan_r else False
        if _pw_required_r and not device.ownership_validated:
            _has_pwd_r = device.user.has_network_password if device.user else False
            if not _has_pwd_r:
                _pw_resp = jsonify({
                    'status': 'pending_password',
                    'message': (
                        'A network password is required for this network. '
                        'An email has been sent to you with a link to set your password.'
                    ),
                })
            else:
                _pw_resp = jsonify({
                    'status': 'enter_password',
                    'message': 'Please enter your network password to continue.',
                })
            _pw_resp.headers['Access-Control-Allow-Origin'] = '*'
            return _pw_resp

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
        _reg_status_payload = {
            'status': device.registration_status,
            'message': f'Device is {device.registration_status}',
            'current_ip': current_ip,
            'current_vlan': current_vlan,
            'current_ssid': current_ssid,
            'expected_vlan': device.assigned_vlan or device.current_vlan,
            'expected_ssid': get_ssid_for_vlan(device.assigned_vlan) or expected_ssid,
            'network_mismatch': network_mismatch
        }
        if device.registration_status == 'blocked':
            if device.user and device.user.blocked:
                _reg_status_payload['reason'] = 'The administrator has blocked you from connecting any devices to the internet.'
            else:
                _block_req = RegistrationRequest.query.filter_by(
                    mac_address=mac_address, status='rejected'
                ).order_by(RegistrationRequest.submitted_at.desc()).first()
                if _block_req and _block_req.notes:
                    _reg_status_payload['reason'] = _block_req.notes
        response = jsonify(_reg_status_payload)
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


@app.route('/unregister/<token>', methods=['GET', 'POST'])
def unregister(token):
    """Unregister a device via email token (spec 8).

    GET  – show a confirmation page (safe for email scanner pre-fetch).
    POST – perform the actual unregister.

    Closes the DeviceOwnership record, resets Device Table-6 fields, removes
    the Kea/RADIUS entry, and (if the device currently has internet access and
    a usable lease) applies hijack/ACL so the user loses access for the
    remainder of the lease.
    """
    if not token:
        flash('Invalid unregister link', 'error')
        return redirect(url_for('index'))

    device = Device.query.filter_by(unregister_token=token).first()
    if not device:
        return render_template('unregister_confirmation.html', success=False)

    # GET: just show the confirmation page — do NOT perform any action yet.
    if request.method == 'GET':
        return render_template('unregister_confirmation.html', confirm=True, token=token)

    # POST: only accept requests that came from the JS button (not form scanners).
    if request.form.get('js') != '1':
        return render_template('unregister_confirmation.html', confirm=True, token=token)

    mac_address = device.mac_address
    connection_type = device.connection_type
    vlan_id = device.current_vlan
    user = device.user
    user_email = user.email if user else 'Unknown'

    # Optionally roll back any profile changes stored in snapshot
    if user and device.profile_snapshot:
        try:
            snapshot = json.loads(device.profile_snapshot)
        except Exception:
            snapshot = None
        if snapshot:
            previous = snapshot.get("previous") or {}
            new_snap = snapshot.get("new") or {}
            current_profile = {
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "phone_number": user.phone_number or "",
            }
            if current_profile == {
                "first_name": new_snap.get("first_name", ""),
                "last_name": new_snap.get("last_name", ""),
                "phone_number": new_snap.get("phone_number", ""),
            }:
                user.first_name = previous.get("first_name") or None
                user.last_name = previous.get("last_name") or None
                user.phone_number = previous.get("phone_number") or None

    # Cut off internet access if the device currently has it
    ip_address = device.ip_address
    if device.internet_accessible and ip_address and not _is_blocked_pool_ip(ip_address):
        lease_expiry = get_lease_expiry_for_mac(mac_address, subnet_id=vlan_id)
        if lease_expiry and lease_expiry > datetime.utcnow():
            if vlan_id:
                manage_switch_acl('block', ip_address, vlan_id)
            if _should_hijack_vlan(vlan_id):
                manage_dns_hijack('hijack', ip_address)
            _upsert_iplease(
                mac_address=mac_address, ip_address=ip_address, vlan_id=vlan_id,
                lease_start=datetime.utcnow(), lease_expiry=lease_expiry,
                from_blocked_pool=False,
                dns_hijacked=bool(_should_hijack_vlan(vlan_id)),
            )
            logger.info(
                "Blocked %s at %s until %s after self-unregister",
                mac_address, ip_address, lease_expiry,
            )

    # Unregister from Kea / RADIUS (only if device actually has an active reservation)
    if connection_type == 'wifi' and device.internet_accessible:
        kea = get_kea()
        if kea and vlan_id:
            if not kea.unregister_mac(mac=mac_address, vlan=vlan_id):
                logger.warning("Kea unregister failed for %s", mac_address)
    elif connection_type == 'wired':
        vlan_map = get_vlan_map()
        if not send_coa_change(mac_address, vlan_map['unregistered']):
            logger.warning("CoA failed for wired device %s on unregister", mac_address)

    # Close DeviceOwnership record
    _close_ownership(mac_address, commit=False)

    # Reset Table-6 fields
    device.user_id = None
    device.device_name = None
    device.assigned_vlan = None
    device.internet_accessible = None
    device.internet_blocked = None
    device.ownership_validated = None
    device.unregister_token = None
    device.profile_snapshot = None
    _sync_registration_status(device)
    db.session.commit()

    logger.info("Device %s (user: %s) unregistered via email token", mac_address, user_email)

    return render_template('unregister_confirmation.html', success=True)


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
    device.ownership_validated = True
    db.session.commit()

    if device.registration_status == 'blocked':
        apply_device_unblock(device, flash_messages=False)

    flash('Device confirmed. Access restored.', 'success')
    return render_template('status.html', device=device)


@app.route('/reject/<token>')
def reject_device(token):
    if not token:
        flash('Invalid rejection link', 'error')
        return redirect(url_for('index'))

    device = Device.query.filter_by(confirmation_token=token).first()
    if not device:
        flash('Invalid or expired link', 'error')
        return redirect(url_for('index'))

    if device.registration_status == 'unregistered':
        flash('This device is already unregistered.', 'info')
        return render_template('status.html', device=device, unregistered=True)

    device.confirmation_confirmed_at = None
    device.confirmation_deadline = None
    db.session.commit()
    apply_device_block(device, flash_messages=False)
    logger.info("Device %s blocked via reject link in email", device.mac_address)

    flash('Device access has been blocked.', 'success')
    return render_template('status.html', device=device)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if current_user and current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
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
                can_manage_isp_routers=getattr(admin, 'can_manage_isp_routers', False),
                can_manage_firmware=getattr(admin, 'can_manage_firmware', False),
                can_manage_pihole=getattr(admin, 'can_manage_pihole', False)
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
                    admin.can_manage_firmware = True
                    admin.can_manage_pihole = True
                    db.session.add(admin)
                    db.session.commit()
                    logger.info(f"Migrated legacy admin '{username}' to database")
                
                # Log in with full permissions
                user = AdminUser(admin.id, admin.username, True, True, True, True, can_manage_switch_ports=True, can_manage_isp_routers=True, can_manage_firmware=True, can_manage_pihole=True)
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
                can_manage_isp_routers=getattr(admin, 'can_manage_isp_routers', False),
                can_manage_firmware=getattr(admin, 'can_manage_firmware', False),
                can_manage_pihole=getattr(admin, 'can_manage_pihole', False)
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
            'can_manage_firmware': getattr(admin, 'can_manage_firmware', False),
            'can_manage_pihole': getattr(admin, 'can_manage_pihole', False),
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
    can_manage_firmware = bool(request.form.get('can_manage_firmware'))
    can_manage_pihole = bool(request.form.get('can_manage_pihole'))
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
    admin.can_manage_firmware = can_manage_firmware
    admin.can_manage_pihole = can_manage_pihole
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
    can_manage_firmware = bool(request.form.get('can_manage_firmware'))
    can_manage_pihole = bool(request.form.get('can_manage_pihole'))
    
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
    admin.can_manage_firmware = can_manage_firmware
    admin.can_manage_pihole = can_manage_pihole
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
    """Reset test environment data and network rules.

    The DB cleanup happens synchronously so it is complete before we redirect.
    The slow switch/Kea operations (ACL baseline, MAC auth clear, port reset,
    PBR/NQA push) run in a background thread so the browser gets a response
    immediately rather than hitting a 504 gateway timeout.
    """
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

    def _background_reset():
        with app.app_context():
            try:
                # Run ACL baseline first, while dhcp4.json is stable.
                # Kea restart regenerates dhcp4.json asynchronously; if we ran
                # the baseline after the restart docker command returned but
                # before the entrypoint finished writing the file, the Python
                # subnet parser would fail and every switch would fall back to
                # a hardcoded /24 mask.
                acl_ok = reset_acl_baseline()

                # Now restart Kea to clear its in-memory lease cache.
                try:
                    _restart_kea_container()
                    logger.info("Test reset: Kea container restarted")
                except Exception as exc:
                    logger.warning("Test reset: Kea restart failed: %s", exc)

                mac_auth_cleared = clear_mac_auth_sessions()
                ports_reset = reset_user_ports()
                nqa_ok = push_pbr_nqa_to_switches()
                if acl_ok and mac_auth_cleared and ports_reset and nqa_ok:
                    logger.info("Test reset: background switch tasks complete (all OK)")
                else:
                    logger.warning(
                        "Test reset: background switch tasks finished with errors "
                        "(acl=%s mac_auth=%s ports=%s nqa=%s)",
                        acl_ok, mac_auth_cleared, ports_reset, nqa_ok,
                    )
            except Exception as exc:
                logger.error("Test reset: background switch tasks raised: %s", exc)

    t = threading.Thread(target=_background_reset, daemon=True)
    t.start()

    flash(
        'Test reset started. Database cleared (users, devices, NAT sessions, '
        'DNS resolutions). Switch ACL baseline, MAC auth, port reset, and '
        'PBR/NQA push are running in the background — check server logs for results.',
        'success',
    )
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/push-pbr-nqa', methods=['POST'])
@login_required
@permission_required('manage_isp_routers')
def admin_push_pbr_nqa():
    """Push PBR + NQA tracking config for all ISP routers to all HP5130 switches."""
    ok = push_pbr_nqa_to_switches()
    if ok:
        flash('PBR/NQA config pushed to all switches successfully.', 'success')
    else:
        flash('PBR/NQA push failed for one or more switches — check logs.', 'warning')
    return redirect(url_for('admin_isp_routers'))


def reapply_all_ip_blocks():
    """Re-push every current per-device IP block to all switches.

    Iterates through active IPLeases (non-expired, not from blocked pool) for
    devices that are not fully accessible, and re-adds the ACL deny rule to
    all switches.  Also re-sends the block for IPs that should be hijacked.

    This is idempotent and safe to call after changing switch configuration
    or adding a new switch — it brings all switches' ACL 30xx rules up to date.

    Returns (pushed_count, failed_count).
    """
    from datetime import datetime as _dt
    now = _dt.utcnow()

    pushed = 0
    failed = 0

    # Get all active non-blocked-pool leases for devices that are not internet_accessible=True
    leases = IPLease.query.filter(
        IPLease.lease_expiry > now,
        IPLease.from_blocked_pool == False,  # noqa: E712
    ).all()

    for lease in leases:
        device = Device.query.filter_by(mac_address=lease.mac_address).first()
        if not device:
            continue
        # Only re-push if the device should currently be blocked at the switch
        if device.internet_accessible is True:
            continue
        vlan_id = lease.vlan_id or device.current_vlan
        if not vlan_id or not lease.ip_address:
            continue
        ok = manage_switch_acl('block', lease.ip_address, vlan_id)
        if ok:
            pushed += 1
        else:
            failed += 1
            logger.warning("reapply_all_ip_blocks: failed to block %s on VLAN %s",
                           lease.ip_address, vlan_id)

    logger.info("reapply_all_ip_blocks: pushed=%d failed=%d", pushed, failed)
    return pushed, failed


@app.route('/admin/reapply-acl-blocks', methods=['POST'])
@login_required
@permission_required('manage_isp_routers')
def admin_reapply_acl_blocks():
    """Re-push ACL baseline + all current per-device blocks to all switches.

    Use this after adding a new switch or changing a router's switch_host,
    to bring the new switch's ACLs up to date without a full test reset.
    """
    baseline_ok = reset_acl_baseline()
    pushed, failed = reapply_all_ip_blocks()
    if baseline_ok and failed == 0:
        flash(
            f'ACL baseline pushed and {pushed} IP block(s) re-applied to all switches.',
            'success',
        )
    elif not baseline_ok:
        flash(
            f'ACL baseline push failed on one or more switches. '
            f'{pushed} IP block(s) re-applied ({failed} failed). Check logs.',
            'warning',
        )
    else:
        flash(
            f'ACL baseline pushed. {pushed} IP block(s) re-applied but {failed} failed. Check logs.',
            'warning',
        )
    return redirect(url_for('admin_isp_routers'))


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
            switch_host_form = _switch_host_for_port(switch_port)
            if not name or not vlan_id_raw:
                flash('Name and VLAN ID are required.', 'error')
                return redirect(url_for('admin_isp_routers'))
            try:
                vlan_id = int(vlan_id_raw)
            except ValueError:
                flash('VLAN ID must be an integer.', 'error')
                return redirect(url_for('admin_isp_routers'))
            subnet = f'{_net_word()}.{vlan_id}.0/24'
            if ISPRouter.query.filter_by(name=name).first():
                flash(f'A router named "{name}" already exists.', 'error')
                return redirect(url_for('admin_isp_routers'))
            nat_logger_type = request.form.get('nat_logger_type', 'none').strip()
            if nat_logger_type not in ('none', 'udm', 'openwrt'):
                nat_logger_type = 'none'
            router = ISPRouter(name=name, subnet=subnet, vlan_id=vlan_id,
                               switch_port=switch_port,
                               switch_host=switch_host_form,
                               dhcp_snooping_trust=True,
                               nat_logger_type=nat_logger_type)
            db.session.add(router)
            db.session.commit()
            _apply_isp_router_to_switches(router)
            _update_isl_trunk_vlan(router.vlan_id, add=True)
            if switch_port:
                _set_isp_router_port(switch_port, router)
            reset_acl_baseline()
            reapply_all_ip_blocks()
            flash(
                f'ISP router "{name}" added. '
                f'⚠ Set the router LAN IP to {router.gateway_ip} and add a '
                f'static route: Target {_net_word()}.0.0 / Mask 255.255.0.0 / '
                f'Gateway {_net_word()}.{vlan_id}.2 on the router.',
                'success'
            )
            return redirect(url_for('admin_isp_routers'))

        elif action == 'update':
            router = ISPRouter.query.get_or_404(request.form.get('router_id'))
            old_port = router.switch_port
            old_switch_host = router.switch_host
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
            router.subnet = f'{_net_word()}.{router.vlan_id}.0/24'
            new_port = request.form.get('switch_port', '').strip() or None
            router.switch_port = new_port
            router.switch_host = _switch_host_for_port(new_port)
            router.dhcp_snooping_trust = True
            new_nat_logger_type = request.form.get('nat_logger_type', router.nat_logger_type).strip()
            if new_nat_logger_type in ('none', 'udm', 'openwrt'):
                router.nat_logger_type = new_nat_logger_type
            db.session.commit()
            # If name changed, remove the old PBR entries from all switches
            if old_pbr_name != router.pbr_name:
                _remove_isp_router_pbr_from_switches(old_pbr_name)
            # If VLAN ID changed, explicitly undo the old next-hop in the PBR
            # permit node before rebuilding, then remove the stale VLAN/interface
            vlan_changed = old_vlan_id != router.vlan_id
            if vlan_changed:
                old_gateway_ip = f'{_net_word()}.{old_vlan_id}.1'
                switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
                switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
                for host in switch_hosts:
                    _run_switch_command(host, _build_pbr_undo_next_hop(router.pbr_name, old_gateway_ip))
                _remove_isp_router_vlan_from_switches(old_vlan_id)
            # Clear the old port if it changed (use old_switch_host since the old port
            # is on the switch the router was previously assigned to)
            if old_port and old_port != new_port:
                _clear_isp_router_port(old_port, old_switch_host)
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
            # Reapply ACL baseline and current IP blocks to all switches so that
            # any new switch (or changed switch_host) is immediately up to date.
            baseline_ok = reset_acl_baseline()
            pushed, blk_failed = reapply_all_ip_blocks()
            msg = f'ISP router "{router.name}" updated.'
            if baseline_ok and blk_failed == 0:
                msg += f' ACL baseline pushed and {pushed} block(s) re-applied to all switches.'
                flash(msg, 'success')
            else:
                msg += f' ACL baseline or block reapply had errors (pushed={pushed} failed={blk_failed}) — check logs.'
                flash(msg, 'warning')
            return redirect(url_for('admin_isp_routers'))

        elif action == 'delete':
            router = ISPRouter.query.get_or_404(request.form.get('router_id'))
            vlan_to_remove = router.vlan_id
            if router.switch_port:
                _clear_isp_router_port(router.switch_port, router.switch_host)
            _remove_isp_router_from_switches(router)
            _update_isl_trunk_vlan(vlan_to_remove, add=False)
            db.session.delete(router)
            db.session.commit()
            flash(f'ISP router "{router.name}" deleted.', 'success')
            return redirect(url_for('admin_isp_routers'))

    routers = ISPRouter.query.order_by(ISPRouter.id).all()
    used_vlan_ids = {r.vlan_id for r in routers}
    # Collect ports per switch for the port dropdowns
    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    # switch_ports_by_host: list of (host, port_name) tuples across all switches
    switch_ports_by_host = []
    for host in switch_hosts:
        rows = db.session.execute(
            text("""
                SELECT switch_host, port_name FROM switch_ports
                WHERE switch_host = :host
                ORDER BY
                    (CASE WHEN port_name LIKE 'XGE%' THEN 1 ELSE 0 END),
                    split_part(port_name, '/', 1),
                    CAST(NULLIF(split_part(port_name, '/', 2), '') AS INTEGER),
                    CAST(NULLIF(split_part(port_name, '/', 3), '') AS INTEGER)
            """),
            {'host': host}
        ).fetchall()
        for r in rows:
            switch_ports_by_host.append((r[0], r[1]))
    # For backwards compat keep switch_ports as a flat list from primary switch
    primary_host = switch_hosts[0] if switch_hosts else ''
    switch_ports_list = [p for h, p in switch_ports_by_host if h == primary_host]
    return render_template('admin_isp_routers.html', routers=routers,
                           switch_ports=switch_ports_list,
                           switch_ports_by_host=switch_ports_by_host,
                           switch_hosts=switch_hosts,
                           used_vlan_ids=used_vlan_ids,
                           network_word=_net_word())


# ---------------------------------------------------------------------------
# Firmware Management
# ---------------------------------------------------------------------------

def _run_firmware_script(action, stream=False, extra_args=None):
    """Run the firmware-manager.sh script for the given action.

    The git repo ($GIT_REPO_DIR) and docker compose plugin are mounted into
    the container at their real host paths, so git/docker compose work natively.
    """
    git_repo_dir = os.environ['GIT_REPO_DIR']
    script_path = '/scripts/firmware-manager.sh'
    cmd = ['/bin/bash', script_path, action] + (extra_args or [])
    env = dict(os.environ)
    env['GIT_REPO_DIR'] = git_repo_dir

    if stream:
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env
        )
    else:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env
        )


def _load_commit_manifest(tree_hash, file_hash):
    """Load the migration manifest that describes what to do when leaving
    file_hash and arriving at tree_hash.

    Convention:
      - The JSON file is named  <file_hash>.json  (the commit being LEFT)
      - It is committed inside  <tree_hash>       (the commit being ARRIVED AT)

    So for an UPDATE  from current → next: tree_hash=next_full,    file_hash=current_full
       for a ROLLBACK from current → prev: tree_hash=current_full, file_hash=prev_full

    Returns the parsed dict, or None if no manifest exists.
    """
    if not tree_hash or not file_hash:
        return None
    git_repo_dir = os.environ['GIT_REPO_DIR']
    # Try short hash (7 chars, conventional naming) first, then full hash as fallback.
    candidates = [file_hash[:7], file_hash]
    for name in candidates:
        blob_path = f'captive-portal/commit-migrations/{name}.json'
        try:
            result = subprocess.run(
                ['git', '-C', git_repo_dir, 'show', f'{tree_hash}:{blob_path}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
    return None


def _read_env_file():
    """Parse the captive-portal .env file and return a dict of current values."""
    git_repo_dir = os.environ['GIT_REPO_DIR']
    env_path = os.path.join(git_repo_dir, 'captive-portal', '.env')
    result = {}
    if not os.path.exists(env_path):
        return result
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                result[key.strip()] = val.strip()
    return result


def _write_env_vars(new_vars):
    """Add or update key=value pairs in the captive-portal .env file.
    Existing lines are updated in place; new keys are appended.
    """
    if not new_vars:
        return
    git_repo_dir = os.environ['GIT_REPO_DIR']
    env_path = os.path.join(git_repo_dir, 'captive-portal', '.env')
    lines = []
    if os.path.exists(env_path):
        with open(env_path) as f:
            lines = f.readlines()

    updated = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in new_vars:
                new_lines.append(f'{key}={new_vars[key]}\n')
                updated.add(key)
                continue
        new_lines.append(line)

    for key, value in new_vars.items():
        if key not in updated:
            new_lines.append(f'{key}={value}\n')

    with open(env_path, 'w') as f:
        f.writelines(new_lines)


def _remove_env_vars(keys):
    """Remove a list of keys from the captive-portal .env file.
    Lines whose key matches are deleted; all other lines are preserved.
    """
    keys = set(keys)
    if not keys:
        return
    git_repo_dir = os.environ['GIT_REPO_DIR']
    env_path = os.path.join(git_repo_dir, 'captive-portal', '.env')
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in keys:
                continue  # drop this line
        new_lines.append(line)
    with open(env_path, 'w') as f:
        f.writelines(new_lines)


@app.route('/admin/firmware')
@login_required
@permission_required('manage_firmware')
def admin_firmware():
    """Firmware management page — shows current/next/prev git commits with
    migration status badges for each direction of travel."""
    status = {}
    error = None
    next_manifest = None
    current_manifest = None
    try:
        result = _run_firmware_script('status')
        if result.returncode == 0:
            status = json.loads(result.stdout)
            # Load manifests using the (tree, file) convention:
            #   update badge:   <current>.json read from next's tree
            #   rollback badge: <prev>.json    read from current's tree
            next_manifest    = _load_commit_manifest(status.get('next_full'),    status.get('current_full'))
            current_manifest = _load_commit_manifest(status.get('current_full'), status.get('prev_full'))
        else:
            error = (result.stderr or result.stdout or 'Script returned non-zero exit').strip()
    except Exception as e:
        error = str(e)
    return render_template(
        'admin_firmware.html',
        status=status,
        error=error,
        next_manifest=next_manifest,
        current_manifest=current_manifest,
        last_op=session.get('firmware_last_op'),
        test_enabled=os.getenv('FIRMWARE_TEST_ENABLED', '').lower() not in ('', '0', 'false', 'no'),
        commits_ahead_count=len(status.get('commits_ahead', [])),
    )


@app.route('/admin/firmware/preflight/<action>', methods=['GET', 'POST'])
@login_required
@permission_required('manage_firmware')
def admin_firmware_preflight(action):
    """Show (GET) or process (POST) the pre-flight checklist before an
    update or rollback: collect any new env vars, warn about DB changes.
    """
    if action not in ('update', 'rollback', 'update-latest'):
        return jsonify({'error': 'Invalid action'}), 400

    # Fetch current git status
    status_result = _run_firmware_script('status')
    if status_result.returncode != 0:
        flash('Could not read git status — is the repo accessible?', 'danger')
        return redirect(url_for('admin_firmware'))
    status = json.loads(status_result.stdout)

    # For update        → manifest of the NEXT commit (what we're moving TO)
    # For rollback      → manifest of CURRENT commit (what we're undoing)
    # For update-latest → aggregated manifest from all commits ahead
    if action == 'update':
        target_hash = status.get('next_full')
        target_short = status.get('next_short')
        target_subject = status.get('next_subject')
        if not target_hash:
            flash('Already on the latest commit — nothing to update.', 'warning')
            return redirect(url_for('admin_firmware'))
        # <current>.json lives inside the next commit's tree
        manifest = _load_commit_manifest(target_hash, status.get('current_full'))
    elif action == 'update-latest':
        commits_ahead = status.get('commits_ahead', [])
        target_hash = status.get('latest_full')
        target_short = status.get('latest_short')
        target_subject = status.get('latest_subject')
        if not commits_ahead or not target_hash:
            flash('Already on the latest commit — nothing to update.', 'warning')
            return redirect(url_for('admin_firmware'))
        # Aggregate env.add/remove from all intermediate manifests
        agg_add, agg_remove = {}, {}
        migration_count = 0
        for commit in commits_ahead:
            m = _load_commit_manifest(commit['full'], commit['from_full'])
            if not m:
                continue
            for entry in (m.get('env') or {}).get('add', []):
                k = entry.get('key', '')
                if k and k not in agg_add:
                    agg_add[k] = entry
            for entry in (m.get('env') or {}).get('remove', []):
                if isinstance(entry, dict):
                    k = entry.get('key', '')
                    if k and k not in agg_remove:
                        agg_remove[k] = entry
            if (m.get('db') or {}).get('up'):
                migration_count += 1
        manifest = {
            'description': f'Update {len(commits_ahead)} commit(s) to {target_short}: {target_subject}',
            'env': {'add': list(agg_add.values()), 'remove': list(agg_remove.values())},
            'db': {'up': f'({migration_count} migration script(s) will run in sequence)'} if migration_count else None,
        }
    else:  # rollback
        target_hash = status.get('current_full')
        target_short = status.get('current_short')
        target_subject = status.get('current_subject')
        if not status.get('prev_full'):
            flash('Already on the first commit — cannot roll back.', 'warning')
            return redirect(url_for('admin_firmware'))
        # <prev>.json lives inside the current commit's tree
        manifest = _load_commit_manifest(target_hash, status.get('prev_full'))
    current_env = _read_env_file()

    if request.method == 'POST':
        # Collect submitted env vars
        new_vars = {}
        errors = []
        if manifest and action in ('update', 'update-latest'):
            for entry in manifest.get('env', {}).get('add', []):
                key = entry['key']
                val = request.form.get(f'env_{key}', '').strip()
                if not val and entry.get('required'):
                    # Allow keeping existing value if already set
                    if key in current_env:
                        val = current_env[key]
                    else:
                        errors.append(f'{key} is required.')
                if val:
                    new_vars[key] = val

        if manifest and action == 'rollback':
            # Vars that were removed by this commit need to be re-entered so
            # they exist in .env once docker-compose.yml references them again.
            for entry in manifest.get('env', {}).get('remove', []):
                if not isinstance(entry, dict):
                    continue
                key = entry.get('key', '')
                if not key:
                    continue
                val = request.form.get(f'env_restore_{key}', '').strip()
                if not val:
                    # Keep existing value if somehow already present
                    if key in current_env:
                        val = current_env[key]
                    elif entry.get('required'):
                        errors.append(f'{key} is required for rollback.')
                if val:
                    new_vars[key] = val

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template(
                'admin_firmware_preflight.html',
                action=action,
                status=status,
                manifest=manifest,
                target_hash=target_hash,
                target_short=target_short,
                target_subject=target_subject,
                current_env=current_env,
            )

        # Write env vars before containers start
        if new_vars:
            try:
                _write_env_vars(new_vars)
                logger.info("Firmware preflight wrote %d env var(s): %s",
                            len(new_vars), ', '.join(new_vars.keys()))
            except Exception as exc:
                flash(f'Failed to write .env: {exc}', 'danger')
                return redirect(url_for('admin_firmware'))

        # Store approval in session so the stream endpoint knows preflight passed
        session['firmware_preflight_approved'] = action
        session['firmware_preflight_hash'] = target_hash
        return redirect(url_for('admin_firmware_do', action=action))

    # GET
    return render_template(
        'admin_firmware_preflight.html',
        action=action,
        status=status,
        manifest=manifest,
        target_hash=target_hash,
        target_short=target_short,
        target_subject=target_subject,
        current_env=current_env,
    )


@app.route('/admin/firmware/do/<action>')
@login_required
@permission_required('manage_firmware')
def admin_firmware_do(action):
    """Render the streaming page for an update/rollback that has passed preflight."""
    if action not in ('update', 'rollback', 'update-latest'):
        return redirect(url_for('admin_firmware'))
    approved = session.get('firmware_preflight_approved')
    if approved != action:
        flash('Please complete the pre-flight checklist first.', 'warning')
        return redirect(url_for('admin_firmware_preflight', action=action))
    return render_template('admin_firmware_do.html', action=action)


@app.route('/admin/firmware/stream/<action>')
@login_required
@permission_required('manage_firmware')
def admin_firmware_stream(action):
    """SSE endpoint: orchestrate the full update/rollback sequence and stream
    output line-by-line.  The sequence is:

    UPDATE:
      1. git checkout <next_hash>
      2. Run db 'up' migration from manifest (if any) — script is now in new tree
      3. docker compose restart affected stacks (captive-portal last)

    ROLLBACK:
      1. Run db 'down' migration from manifest of CURRENT commit (still in tree)
      2. git checkout HEAD^
      3. docker compose restart affected stacks (captive-portal last)
    """
    if action not in ('update', 'rollback', 'update-latest'):
        return jsonify({'error': 'Invalid action'}), 400

    # Check preflight was approved
    if session.get('firmware_preflight_approved') != action:
        def _denied():
            yield "data: ERROR: Pre-flight not completed. Please use the Update/Rollback buttons.\n\n"
            yield "data: __EXIT__:1\n\n"
        from flask import stream_with_context, Response as FlaskResponse
        return FlaskResponse(stream_with_context(_denied()),
                             mimetype='text/event-stream',
                             headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    # Clear session approval — one-shot
    session.pop('firmware_preflight_approved', None)
    session.pop('firmware_preflight_hash', None)

    from flask import stream_with_context, Response as FlaskResponse

    def generate():
        git_repo_dir = os.environ['GIT_REPO_DIR']
        script_env = dict(os.environ)
        script_env['GIT_REPO_DIR'] = git_repo_dir

        def emit(line):
            app.logger.info(f'[firmware/{action}] {line}')
            return f"data: {line}\n\n"

        def stream_proc(cmd, cwd=None, env=None):
            """Run a command, yielding SSE lines; returns exit code."""
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd, env=(env or script_env)
            )
            for ln in proc.stdout:
                yield emit(ln.rstrip())
            proc.wait()
            return proc.returncode

        try:
            # --- Get current status ---
            status_result = _run_firmware_script('status')
            if status_result.returncode != 0:
                yield emit("ERROR: Could not read git status.")
                yield emit("__EXIT__:1")
                return
            status = json.loads(status_result.stdout)
            app.logger.info(f'[firmware/{action}] Starting — current={status.get("current_short")} '
                            f'next={status.get("next_short")} prev={status.get("prev_short")} '
                            f'forward_dirs={status.get("forward_dirs")} back_dirs={status.get("back_dirs")}')

            if action == 'update':
                next_hash    = status.get('next_full')
                changed_dirs = status.get('forward_dirs', [])
                if not next_hash:
                    yield emit("ERROR: No next commit available.")
                    yield emit("__EXIT__:1")
                    return

                # Step 1 — git checkout
                yield emit(f"=== Step 1/3: Checking out {status.get('next_short')} — "
                           f"{status.get('next_subject')} ===")
                rc = yield from stream_proc(
                    ['git', '-C', git_repo_dir, 'checkout', '-f', next_hash])
                if rc != 0:
                    yield emit("ERROR: git checkout failed — aborting.")
                    yield emit("__EXIT__:1")
                    return
                yield emit("")

                # Step 2 — db migration: <current>.json from next's tree
                current_hash_for_manifest = status.get('current_full')
                manifest = _load_commit_manifest(next_hash, current_hash_for_manifest)

                # Remove .env vars made redundant by this update (listed in env.remove).
                # Each entry may be a plain string (legacy) or {"key": ..., "default": ...}.
                def _remove_keys(entries):
                    return [e['key'] if isinstance(e, dict) else e
                            for e in (entries or []) if e]

                env_remove_entries = (manifest or {}).get('env', {}).get('remove', [])
                env_remove_keys = _remove_keys(env_remove_entries)
                if env_remove_keys:
                    yield emit(f"Removing obsolete .env var(s): {', '.join(env_remove_keys)}")
                    try:
                        _remove_env_vars(env_remove_keys)
                    except Exception as exc:
                        yield emit(f"WARNING: Could not remove .env var(s): {exc}")

                db_script = (manifest or {}).get('db', {}).get('up')
                if db_script:
                    script_path = os.path.join(
                        git_repo_dir, 'captive-portal', db_script)
                    yield emit(f"=== Step 2/3: Running database migration: {db_script} ===")
                    if not os.path.exists(script_path):
                        yield emit(f"ERROR: Migration script not found: {script_path}")
                        yield emit("__EXIT__:1")
                        return
                    rc = yield from stream_proc(
                        ['/bin/bash', script_path],
                        cwd=os.path.join(git_repo_dir, 'captive-portal'))
                    if rc != 0:
                        yield emit(f"ERROR: Migration script {db_script} failed — aborting.")
                        yield emit("__EXIT__:1")
                        return
                    yield emit("")
                else:
                    yield emit("=== Step 2/3: No database migration needed ===")
                    yield emit("")

            elif action == 'rollback':
                changed_dirs    = status.get('back_dirs', [])
                current_hash    = status.get('current_full')
                current_short   = status.get('current_short')
                current_subject = status.get('current_subject')
                if not status.get('prev_full'):
                    yield emit("ERROR: Already on the first commit — cannot roll back.")
                    yield emit("__EXIT__:1")
                    return

                # Step 1 — db down migration: <prev>.json from current's tree (still checked out)
                manifest = _load_commit_manifest(current_hash, status.get('prev_full'))
                db_script = (manifest or {}).get('db', {}).get('down')
                if db_script:
                    script_path = os.path.join(
                        git_repo_dir, 'captive-portal', db_script)
                    yield emit(f"=== Step 1/3: Running rollback database migration: {db_script} ===")
                    if not os.path.exists(script_path):
                        yield emit(f"ERROR: Migration script not found: {script_path}")
                        yield emit("__EXIT__:1")
                        return
                    rc = yield from stream_proc(
                        ['/bin/bash', script_path],
                        cwd=os.path.join(git_repo_dir, 'captive-portal'))
                    if rc != 0:
                        yield emit(f"ERROR: Rollback migration {db_script} failed — aborting.")
                        yield emit("__EXIT__:1")
                        return
                    yield emit("")
                else:
                    yield emit("=== Step 1/3: No database rollback migration needed ===")
                    yield emit("")

                # Step 2 — git checkout HEAD^
                yield emit(f"=== Step 2/3: Rolling back from {current_short} — "
                           f"{current_subject} ===")
                rc = yield from stream_proc(
                    ['git', '-C', git_repo_dir, 'checkout', '-f', 'HEAD^'])
                if rc != 0:
                    yield emit("ERROR: git checkout HEAD^ failed — aborting.")
                    yield emit("__EXIT__:1")
                    return

                # Remove .env vars that were introduced by the now-rolled-back commit
                # (listed in env.add — docker-compose.yml no longer declares them
                # after the git checkout above).
                env_added = [e['key'] for e in (manifest or {}).get('env', {}).get('add', []) if e.get('key')]
                if env_added:
                    yield emit(f"Removing .env var(s) added by rolled-back commit: {', '.join(env_added)}")
                    try:
                        _remove_env_vars(env_added)
                    except Exception as exc:
                        yield emit(f"WARNING: Could not remove .env var(s): {exc}")
                # Note: env.remove vars are restored via the preflight form — already in .env.

                yield emit("")

            elif action == 'update-latest':
                # Apply each commit in sequence: checkout → env.remove → db.up
                # Then restart the union of all affected dirs in one shot.
                commits_ahead = status.get('commits_ahead', [])
                all_changed_dirs = status.get('latest_dirs', [])
                latest_hash = status.get('latest_full')
                if not commits_ahead or not latest_hash:
                    yield emit("ERROR: No commits ahead — nothing to update.")
                    yield emit("__EXIT__:1")
                    return

                def _rk(entries):
                    return [e['key'] if isinstance(e, dict) else e
                            for e in (entries or []) if e]

                total_commits = len(commits_ahead)
                for i, commit in enumerate(commits_ahead):
                    step = i + 1
                    commit_hash    = commit['full']
                    commit_short   = commit['short']
                    commit_subject = commit['subject']
                    from_full      = commit['from_full']

                    yield emit(f"=== Commit {step}/{total_commits}: {commit_short} — {commit_subject} ===")
                    rc = yield from stream_proc(
                        ['git', '-C', git_repo_dir, 'checkout', '-f', commit_hash])
                    if rc != 0:
                        yield emit("ERROR: git checkout failed — aborting.")
                        yield emit("__EXIT__:1")
                        return
                    yield emit("")

                    # Load manifest from the newly checked-out tree
                    step_manifest = _load_commit_manifest(commit_hash, from_full)

                    # Apply env.remove for this step
                    rm_keys = _rk((step_manifest or {}).get('env', {}).get('remove', []))
                    if rm_keys:
                        yield emit(f"  Removing .env var(s): {', '.join(rm_keys)}")
                        try:
                            _remove_env_vars(rm_keys)
                        except Exception as exc:
                            yield emit(f"  WARNING: Could not remove .env var(s): {exc}")

                    # Run db.up if present
                    db_script = (step_manifest or {}).get('db', {}).get('up')
                    if db_script:
                        sp = os.path.join(git_repo_dir, 'captive-portal', db_script)
                        yield emit(f"  DB migration: {db_script}")
                        if not os.path.exists(sp):
                            yield emit(f"ERROR: Migration script not found: {sp}")
                            yield emit("__EXIT__:1")
                            return
                        rc = yield from stream_proc(
                            ['/bin/bash', sp],
                            cwd=os.path.join(git_repo_dir, 'captive-portal'))
                        if rc != 0:
                            yield emit(f"ERROR: Migration {db_script} failed — aborting.")
                            yield emit("__EXIT__:1")
                            return
                    else:
                        yield emit("  No DB migration for this commit.")
                    yield emit("")

                # Restart all stacks affected by any commit in the chain
                if all_changed_dirs:
                    yield emit(f"=== Restarting affected stacks: {', '.join(all_changed_dirs)} ===")
                    rc = yield from stream_proc(
                        ['/bin/bash', '/scripts/firmware-manager.sh',
                         'restart-dirs'] + all_changed_dirs,
                        env=script_env)
                    if rc != 0:
                        yield emit("ERROR: Stack restart failed.")
                        yield emit("__EXIT__:1")
                        return
                else:
                    yield emit("=== No containers to restart ===")

                yield emit("")
                yield emit("=" * 50)
                yield emit(f"UPDATE TO LATEST COMPLETE — now at {latest_hash[:7]}")
                session['firmware_last_op'] = 'update'
                session.modified = True
                yield emit("__EXIT__:0")
                return

            # Step 3 — restart affected stacks (common to update and rollback)
            if changed_dirs:
                yield emit(f"=== Step 3/3: Restarting affected stacks: "
                           f"{', '.join(changed_dirs)} ===")
                rc = yield from stream_proc(
                    ['/bin/bash', '/scripts/firmware-manager.sh',
                     'restart-dirs'] + changed_dirs,
                    env=script_env)
                if rc != 0:
                    yield emit("ERROR: Stack restart failed.")
                    yield emit("__EXIT__:1")
                    return
            else:
                yield emit("=== Step 3/3: No containers to restart ===")

            op = "UPDATE" if action == 'update' else "ROLLBACK"
            yield emit(f"")
            yield emit(f"{'='*50}")
            yield emit(f"{op} COMPLETE")
            # Record the completed operation before yielding exit so session is
            # saved when the generator is exhausted (non-self-restart path).
            session['firmware_last_op'] = action
            session.modified = True
            yield emit("__EXIT__:0")

        except Exception as exc:
            yield emit(f"ERROR: {exc}")
            yield emit("__EXIT__:1")

    return FlaskResponse(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


# ---------------------------------------------------------------------------
# Firmware — pre-flight test endpoint
# ---------------------------------------------------------------------------

def _run_db_verify_check(check):
    """Execute one schema verification entry from a manifest's verify_up / verify_down list.

    Supported check types:
      column        — the column exists in the named table
      column_absent — the column does NOT exist in the named table
      table         — the table exists in the database
      table_absent  — the table does NOT exist in the database

    Returns a dict: {category, name, pass, detail}
    """
    ctype = check.get('type', '')
    try:
        if ctype in ('column', 'column_absent'):
            tbl = check.get('table', '')
            col = check.get('column', '')
            exists = bool(db.session.execute(
                text("""SELECT COUNT(*) FROM information_schema.columns
                        WHERE table_name = :t AND column_name = :c"""),
                {'t': tbl, 'c': col}
            ).scalar())
            want_present = (ctype == 'column')
            passed = exists if want_present else not exists
            ok = '\u2713'  # ✓
            fail = '\u2717'  # ✗
            if want_present:
                detail = f"Column {tbl}.{col} exists {ok}" if passed else f"Column {tbl}.{col} MISSING {fail}"
            else:
                detail = f"Column {tbl}.{col} absent {ok}" if passed else f"Column {tbl}.{col} still present {fail}"
            return {'category': 'db', 'name': f"{tbl}.{col}", 'pass': passed, 'detail': detail}

        elif ctype in ('table', 'table_absent'):
            name = check.get('name', '')
            exists = bool(db.session.execute(
                text("""SELECT COUNT(*) FROM information_schema.tables
                        WHERE table_name = :n"""),
                {'n': name}
            ).scalar())
            want_present = (ctype == 'table')
            passed = exists if want_present else not exists
            ok = '\u2713'  # ✓
            fail = '\u2717'  # ✗
            if want_present:
                detail = f"Table {name} exists {ok}" if passed else f"Table {name} MISSING {fail}"
            else:
                detail = f"Table {name} absent {ok}" if passed else f"Table {name} still present {fail}"
            return {'category': 'db', 'name': name, 'pass': passed, 'detail': detail}

        else:
            return {'category': 'db', 'name': ctype, 'pass': False,
                    'detail': f"Unknown check type: {ctype!r}"}

    except Exception as exc:
        return {'category': 'db', 'name': str(check.get('name', check)),
                'pass': False, 'detail': f"Error running check: {exc}"}


@app.route('/admin/firmware/mark-done/<action>', methods=['POST'])
@login_required
@permission_required('manage_firmware')
def admin_firmware_mark_done(action):
    """Called by the streaming page JS after a successful update/rollback.
    Records the completed operation in the session so the verify button on
    the firmware page knows which direction to test.
    """
    if action in ('update', 'rollback', 'update-latest'):
        session['firmware_last_op'] = 'update' if action == 'update-latest' else action
        session.modified = True
    return jsonify({'ok': True})


@app.route('/admin/firmware/verify-last')
@login_required
@permission_required('manage_firmware')
def admin_firmware_verify_last():
    """AJAX endpoint: verify that the last firmware operation succeeded.

    Reads session['firmware_last_op'] to know which direction was performed:
      update   — loads manifest for current→prev transition, runs verify_up
                 checks + validates env.add vars are present.
      rollback — loads manifest for next→current transition, runs verify_down
                 checks + validates env.remove vars are restored (present).

    Only accessible when FIRMWARE_TEST_ENABLED env var is set.

    Returns JSON:
      { ok: bool, has_manifest: bool, last_op: str, checks: [{category, name, pass, detail}] }
    """
    if os.getenv('FIRMWARE_TEST_ENABLED', '').lower() in ('', '0', 'false', 'no'):
        return jsonify({'ok': False, 'error': 'Test mode not enabled (FIRMWARE_TEST_ENABLED not set)'}), 403

    last_op = session.get('firmware_last_op')
    if not last_op:
        return jsonify({'ok': False, 'error': 'No operation recorded in session — perform an update or rollback first.'})

    status_result = _run_firmware_script('status')
    if status_result.returncode != 0:
        return jsonify({'ok': False, 'error': 'Could not read git status — is the repo accessible?'})
    status = json.loads(status_result.stdout)

    checks = []
    manifest = None
    current_env = _read_env_file()

    if last_op == 'update':
        # We are now at the updated commit (current_full = B, prev_full = A).
        # Manifest about A→B: <A>.json from B's tree.
        manifest = _load_commit_manifest(status.get('current_full'), status.get('prev_full'))
        if manifest:
            # DB schema checks: verify_up
            for chk in (manifest.get('db') or {}).get('verify_up', []):
                checks.append(_run_db_verify_check(chk))
            # Env checks: all env.add entries should now be present in .env
            for entry in (manifest.get('env') or {}).get('add', []):
                key = entry['key']
                value = current_env.get(key, '').strip()
                present = bool(value)
                required = entry.get('required', False)
                if present:
                    display = '(set)' if entry.get('sensitive') else repr(value[:40])
                    detail = f'Present: {display}'
                    passed = True
                elif required:
                    detail = 'MISSING — required env var not set'
                    passed = False
                else:
                    detail = 'Not set (optional — has default)'
                    passed = True
                checks.append({
                    'category': 'env', 'name': key,
                    'description': entry.get('description', ''),
                    'pass': passed, 'detail': detail,
                })
            # Env checks: all env.remove entries should now be ABSENT from .env
            for entry in (manifest.get('env') or {}).get('remove', []):
                key = entry['key'] if isinstance(entry, dict) else entry
                if not key:
                    continue
                absent = key not in current_env
                desc = entry.get('description', '') if isinstance(entry, dict) else ''
                checks.append({
                    'category': 'env', 'name': key,
                    'description': desc,
                    'pass': absent,
                    'detail': 'Absent \u2713' if absent else 'Still present \u2717 \u2014 should have been removed by update',
                })

    else:  # rollback
        # We are now at the rolled-back commit (current_full = A, next_full = B).
        # Manifest about A→B: <A>.json from B's tree.
        manifest = _load_commit_manifest(status.get('next_full'), status.get('current_full'))
        if manifest:
            # DB schema checks: verify_down (things added by upgrade should be gone)
            for chk in (manifest.get('db') or {}).get('verify_down', []):
                checks.append(_run_db_verify_check(chk))
            # Env: vars listed in env.add should now be ABSENT from .env after rollback
            for entry in (manifest.get('env') or {}).get('add', []):
                key = entry['key'] if isinstance(entry, dict) else entry
                if not key:
                    continue
                absent = key not in current_env
                desc = entry.get('description', '') if isinstance(entry, dict) else ''
                checks.append({
                    'category': 'env', 'name': key,
                    'description': desc,
                    'pass': absent,
                    'detail': 'Absent \u2713' if absent else 'Still present \u2717 \u2014 should have been removed by rollback',
                })
            # Env: vars listed in env.remove should be restored (present) after rollback —
            # the admin re-entered them via the rollback preflight form.
            for entry in (manifest.get('env') or {}).get('remove', []):
                key = entry['key'] if isinstance(entry, dict) else entry
                if not key:
                    continue
                present = key in current_env
                checks.append({
                    'category': 'env', 'name': key,
                    'description': 'Should be restored by rollback preflight form',
                    'pass': present,
                    'detail': 'Present \u2713' if present else 'MISSING \u2717 \u2014 was not re-entered on rollback preflight',
                })

    overall_ok = all(c['pass'] for c in checks)
    return jsonify({
        'ok': overall_ok,
        'has_manifest': manifest is not None,
        'last_op': last_op,
        'checks': checks,
    })


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

        # Capture all data needed by the background worker before the request
        # context is torn down.
        _pbr_changes      = list(pbr_changes)
        _prefix_changed   = prefix_changed
        _changed_statuses = list(changed_statuses)
        _vlan_map         = get_vlan_map()
        _vlan_prefix_by_id = {}
        _changed_vlan_ids  = []
        for _status, _prefix in prefix_by_status.items():
            _vid = _vlan_map.get(_status)
            if _vid:
                _vlan_prefix_by_id[_vid] = _prefix
                if _status in _changed_statuses:
                    _changed_vlan_ids.append(_vid)

        _push_job_id = secrets.token_hex(16)
        session['vlan_push_job_id'] = _push_job_id

        def _background_vlan_push():
            """Run all slow switch/Kea work outside the HTTP request."""
            _errors = []
            try:
                _r = _pihole_redis()
                _r.set(f'vlan_push_job:{_push_job_id}', json.dumps({'state': 'running'}), ex=300)
            except Exception:
                pass  # Redis unavailable — polling will just show nothing

            # SQLAlchemy and app-context-dependent helpers require an app context.
            with app.app_context():
                try:
                    # 1. Ensure all PBR/NQA definitions are current on the switches
                    #    (creates PBR-TEL etc.) BEFORE assigning them to VLAN interfaces.
                    push_pbr_nqa_to_switches()

                    # 2. Assign changed PBR policies to VLAN interfaces
                    if _pbr_changes:
                        from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac
                        switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
                        switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
                        pbr_tasks = []
                        for (pbr_vlan_id, old_pbr, new_pbr) in _pbr_changes:
                            for host in switch_hosts:
                                if new_pbr:
                                    pbr_tasks.append((host, _build_vlan_pbr_assign(pbr_vlan_id, new_pbr)))
                                elif old_pbr:
                                    pbr_tasks.append((host, _build_vlan_pbr_remove(pbr_vlan_id, old_pbr)))
                        if pbr_tasks:
                            with _TPE(max_workers=len(pbr_tasks)) as _ex:
                                for _f in _ac([_ex.submit(_run_switch_command, h, c) for h, c in pbr_tasks]):
                                    try:
                                        _f.result()
                                    except Exception as _e:
                                        logger.warning('BG PBR assign SSH error: %s', _e)
                                        _errors.append(str(_e))

                    # 3. Write new Kea config (dhcp4.json + vlan-prefix-map.txt).
                    # ACL baseline runs BEFORE restarting Kea so it reads the
                    # freshly-written dhcp4.json rather than a file that Kea's
                    # entrypoint may not have finished regenerating yet.
                    try:
                        _update_kea_config(_vlan_prefix_by_id)
                    except Exception as exc:
                        logger.warning('BG Kea config write failed: %s', exc)
                        _errors.append(f'Kea config: {exc}')

                    # 4. ACL baseline + interface masks if prefix changed.
                    # Runs here so it reads the just-written dhcp4.json, not
                    # the post-restart regenerated one (which may lag behind).
                    if _prefix_changed:
                        ok = reset_acl_baseline()
                        if not ok:
                            _errors.append('ACL baseline push failed')
                        reset_vlan_interface_masks(_changed_vlan_ids)
                        reset_pi_network_masks(_changed_vlan_ids)

                    # 5. Restart Kea to pick up the new pool/subnet config.
                    try:
                        _restart_kea_container()
                    except Exception as exc:
                        logger.warning('BG Kea restart failed: %s', exc)
                        _errors.append(f'Kea restart: {exc}')

                except Exception as exc:
                    logger.error('BG VLAN push raised: %s', exc)
                    _errors.append(str(exc))

                try:
                    _r = _pihole_redis()
                    _r.set(
                        f'vlan_push_job:{_push_job_id}',
                        json.dumps({'state': 'done', 'ok': not _errors, 'errors': _errors}),
                        ex=120,
                    )
                except Exception:
                    pass

        import threading as _threading
        _t = _threading.Thread(target=_background_vlan_push, daemon=True)
        _t.start()

        flash('VLAN configuration saved. Switch and Kea updates are being applied in the background.', 'success')
        for message in warnings:
            flash(message, 'warning')

        logger.info("Admin updated VLAN configuration (background push started)")

        return redirect(url_for('admin_vlan_config'))
    
    # Load current configuration
    vlan_map = get_vlan_map()
    prefix_map = _get_vlan_prefix_map()
    vlan_entries = [e for e in get_vlan_entries() if e.status != WIRED_UNREGISTERED_STATUS]
    valid_vlan_ids = _parse_valid_vlan_ids()
    isp_routers = ISPRouter.query.order_by(ISPRouter.id).all()

    kea_config_json = None
    kea_config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    try:
        with open(kea_config_path, 'r', encoding='utf-8') as _f:
            kea_config_json = _f.read()
    except OSError:
        pass

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
        kea_config_json=kea_config_json,
        vlan_push_job_id=session.get('vlan_push_job_id'),
    )


@app.route('/api/admin/vlan-push-status')
@login_required
def admin_vlan_push_status():
    """Return the status of the most recent background VLAN push job."""
    job_id = session.get('vlan_push_job_id')
    if not job_id:
        return jsonify({'state': 'none'})
    try:
        raw = _pihole_redis().get(f'vlan_push_job:{job_id}')
        if not raw:
            return jsonify({'state': 'expired'})
        return jsonify(json.loads(raw))
    except Exception:
        return jsonify({'state': 'error'})


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
            network = ipaddress.IPv4Network(f"{_net_word()}.{vlan_id}.0/{prefix}", strict=False)
            subnet_cidr = str(network)
        except Exception:
            subnet_cidr = f"{_net_word()}.{vlan_id}.0/{prefix}"
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
    
    # Spec Section C: Registered devices — entries in device_ownership (Table 9) with active ownership
    # Active = end_datetime IS NULL, joined with Device (Table 6) and User
    devices_query = db.session.query(DeviceOwnership, Device, User)\
        .join(Device, DeviceOwnership.mac_address == Device.mac_address, isouter=True)\
        .outerjoin(User, DeviceOwnership.user_id == User.id)\
        .filter(DeviceOwnership.end_datetime.is_(None))

    if devices_search:
        devices_query = devices_query.filter(
            db.or_(
                DeviceOwnership.mac_address.ilike(f'%{devices_search}%'),
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
        if devices_order == 'desc':
            devices_query = devices_query.order_by(User.first_name.desc())
        else:
            devices_query = devices_query.order_by(User.first_name.asc())
    elif devices_sort == 'user_email':
        if devices_order == 'desc':
            devices_query = devices_query.order_by(User.email.desc())
        else:
            devices_query = devices_query.order_by(User.email.asc())
    else:
        sort_column = getattr(Device, devices_sort, Device.first_seen)
        if devices_order == 'desc':
            devices_query = devices_query.order_by(sort_column.desc())
        else:
            devices_query = devices_query.order_by(sort_column.asc())

    devices_total = devices_query.count()
    devices = devices_query.offset((devices_page - 1) * devices_per_page).limit(devices_per_page).all()

    # Refresh IPs from Kea for registered devices on the current page
    # Each row is a (DeviceOwnership, Device, User) tuple
    ip_updated = False
    kea = get_kea()
    for row in devices:
        try:
            device = row[1]  # Device is the second element of (DeviceOwnership, Device, User)
        except (TypeError, IndexError):
            device = row if hasattr(row, "mac_address") else None

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

    # Spec Section A: Unregistered devices — Device rows with no active device_ownership entry
    active_ownership_macs = db.session.query(DeviceOwnership.mac_address).filter(
        DeviceOwnership.end_datetime.is_(None)
    ).subquery()
    unregistered_devices = db.session.query(Device).filter(
        ~Device.mac_address.in_(active_ownership_macs)
    ).order_by(Device.last_seen.desc()).all()
    unregistered_total = len(unregistered_devices)
    
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
        unregistered_devices=unregistered_devices,
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
    """Generate HP5130 config for an ISP router uplink VLAN, interface, PBR, and NQA tracking."""
    last_octet = switch_host.split('.')[-1]
    host_ip = f"{_net_word()}.{router.vlan_id}.{last_octet}"
    pbr_name = router.pbr_name
    # NQA entry name derived from pbr_name (e.g. 'PBR-TEL' -> 'pbr-tel')
    # NQA operation tags must be alphanumeric — hyphens cause "Invalid operation tag"
    nqa_name = pbr_name.lower().replace('-', '').replace(' ', '_')
    # Track ID is the router's database primary key — stable and unique per router
    track_id = router.id
    name_upper = router.name.upper().replace(' ', '_')
    lines = [
        'system-view',
        f'vlan {router.vlan_id}',
        f' description UPLINK-TO-{name_upper}',
        'quit',
        f'dhcp snooping enable vlan {router.vlan_id}',
        f'vlan {router.vlan_id}',
        ' dhcp snooping binding record',
        'quit',
        f'interface Vlan-interface{router.vlan_id}',
        f' description UPLINK-TO-{name_upper}',
        f' ip address {host_ip} 255.255.255.0',
        'quit',
        'acl advanced 3001',
        ' description PBR-local-traffic-normal-routing',
        f' rule 10 permit ip any {_net_word()}.0.0 0.0.255.255',
        'quit',
        # Undo the whole PBR first (removes track reference so undo track is safe)
        f'undo policy-based-route {pbr_name}',
        # Rebuild NQA probe and track object (undo first for idempotency)
        f'undo track {track_id}',
        f'undo nqa schedule admin {nqa_name}',
        f'undo nqa entry admin {nqa_name}',
        f'nqa entry admin {nqa_name}',
        ' type icmp-echo',
        f' destination ip {router.gateway_ip}',
        ' frequency 5',
        ' probe-count 3',
        ' timeout 2000',
        ' interval milliseconds 2000',
        'quit',
        f'nqa schedule admin {nqa_name} start-time now lifetime forever',
        f'track {track_id} nqa admin {nqa_name} probe-pass',
        # Rebuild PBR with NQA track — next-hop is only active when probe passes.
        # Node 20 is a catch-all discard: if the track is DOWN (router unreachable),
        # node 10 is deactivated and traffic falls to node 20 which drops it,
        # preventing fallback to the switch's static default route (UDM).
        f'policy-based-route {pbr_name} deny node 5',
        ' if-match acl 3001',
        'quit',
        f'policy-based-route {pbr_name} permit node 10',
        f' apply next-hop {router.gateway_ip} track {track_id}',
        'quit',
        f'policy-based-route {pbr_name} permit node 20',
        ' apply discard',
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
        ' dhcp snooping trust',
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


def _build_isp_router_block_acl(acl_number, router, excluded_subnets):
    """Build an outbound ACL for this ISP router's uplink SVI to block source
    traffic from VLANs that are assigned to a different ISP router.

    This prevents silent internet fallback via this router when a VLAN's own
    ISP router goes down and PBR falls back to normal IP routing.

    acl_number:        ACL number to use (e.g. 3951 for router.id=1)
    excluded_subnets:  list of (network_address_str, wildcard_str) tuples
    Always returns a non-None command string — when excluded_subnets is empty,
    generates cleanup commands to remove any stale ACL and packet-filter so that
    stale deny rules do not persist after a VLAN switches to this router.
    """
    if not excluded_subnets:
        # No foreign VLANs to block — remove stale ACL and packet-filter if present.
        return '\n'.join([
            'system-view',
            f'interface Vlan-interface{router.vlan_id}',
            f' undo packet-filter {acl_number} outbound',
            'quit',
            f'undo acl advanced {acl_number}',
            'quit',
            'save force',
        ])
    lines = [
        'system-view',
        f'undo acl advanced {acl_number}',
        f'acl advanced {acl_number}',
        f' description ISP-{router.pbr_name}-block-foreign-VLANs',
    ]
    for i, (network, wildcard) in enumerate(excluded_subnets):
        rule_num = 10 + i * 10
        lines.append(f' rule {rule_num} deny ip source {network} {wildcard}')
    lines.append(' rule 500 permit ip')
    lines.append('quit')
    lines.append(f'interface Vlan-interface{router.vlan_id}')
    lines.append(f' packet-filter {acl_number} outbound')
    lines.append('quit')
    lines.append('quit')
    lines.append('save force')
    return '\n'.join(lines)


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


def push_pbr_nqa_to_switches():
    """Push full ISP router PBR + NQA tracking config for all routers to all switches.

    Also applies egress block ACLs on each ISP uplink SVI to deny source traffic
    from VLANs assigned to a different ISP router.  This is the reliable backstop
    that prevents internet fallback via UDM (or any other ISP) when a tracked
    next-hop goes DOWN — because Comware 7 PBR falls through to normal IP routing
    when a track-bound node becomes invalid, bypassing any subsequent PBR nodes.

    ACL numbers used: 3950 + router.id  (e.g. 3951 for UDM id=1, 3952 for TEL id=2)

    Idempotent — safe to call on reset or after config changes.  Returns True
    if every switch/router combination succeeded, False if any failed.
    """
    import ipaddress as _ipaddress

    switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
    switch_hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
    if not switch_hosts:
        logger.warning("push_pbr_nqa_to_switches: no SWITCH_HOSTS configured")
        return True  # nothing to do — not treated as a failure

    routers = ISPRouter.query.all()
    if not routers:
        return True

    # Build router_id → [(network_addr, wildcard), ...] for all assigned VLANs
    router_subnets = {}  # router.id -> list of (network_addr_str, wildcard_str)
    for vlan in VlanMapping.query.filter(VlanMapping.isp_router_id.isnot(None)).all():
        prefix_raw = Setting.get_value(f'vlan_prefix_{vlan.status}', '24')
        try:
            prefix = int(prefix_raw)
        except (TypeError, ValueError):
            prefix = 24
        try:
            net = _ipaddress.IPv4Network(
                f'{_net_word()}.{vlan.vlan_id}.0/{prefix}', strict=False)
            network_addr = str(net.network_address)
            wildcard = str(_ipaddress.IPv4Address(int(net.hostmask)))
        except ValueError:
            logger.warning("push_pbr_nqa_to_switches: bad subnet for VLAN %s", vlan.vlan_id)
            continue
        router_subnets.setdefault(vlan.isp_router_id, []).append((network_addr, wildcard))

    # Build all (label, host, config) tasks up front — all DB access happens here
    # in the main thread before any parallelism, keeping SQLAlchemy sessions safe.
    tasks = []  # list of (label, host, config_str)
    for router in routers:
        for host in switch_hosts:
            cfg = _build_isp_router_switch_config(router, host)
            tasks.append((f'{host}/{router.pbr_name}', host, cfg))

        # Egress block ACL: deny VLANs on OTHER routers from leaking through this
        # router's uplink SVI when PBR falls back to normal routing.
        # Push to ALL switches — the uplink Vlan-interface exists on every switch.
        excluded = []
        for other_router in routers:
            if other_router.id != router.id:
                excluded.extend(router_subnets.get(other_router.id, []))
        acl_number = 3950 + router.id
        block_cfg = _build_isp_router_block_acl(acl_number, router, excluded)
        for host in switch_hosts:
            tasks.append((f'{host}/{router.pbr_name}/block-acl', host, block_cfg))

    # Run all SSH pushes in parallel — safe because _run_switch_command is pure
    # subprocess with no SQLAlchemy access.
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    failed = []
    with ThreadPoolExecutor(max_workers=len(tasks) or 1) as executor:
        future_to_label = {
            executor.submit(_run_switch_command, host, cfg): label
            for label, host, cfg in tasks
        }
        for future in _as_completed(future_to_label):
            label = future_to_label[future]
            try:
                result = future.result()
            except Exception as exc:
                result = None
                logger.warning("push_pbr_nqa_to_switches: exception for %s: %s", label, exc)
            if result is None:
                failed.append(label)
                logger.warning("push_pbr_nqa_to_switches: failed %s", label)

    return len(failed) == 0


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
    """Mark switch port as uplink_udm and push port config to the router's switch only."""
    host = _get_switch_host_for_isp_router(router)
    if not host:
        return
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


def _clear_isp_router_port(port_name, switch_host=None):
    """Revert a switch port that was an ISP router uplink back to unknown and reset it.

    switch_host should be the management IP of the HP5130 that hosts the port.  When
    omitted the first SWITCH_HOST is used (pre-migration fallback).
    """
    if not switch_host:
        switch_hosts_raw = os.getenv('SWITCH_HOSTS', os.getenv('SWITCH_HOST', ''))
        hosts = [h.strip() for h in switch_hosts_raw.split() if h.strip()]
        switch_host = hosts[0] if hosts else ''
    if not switch_host:
        return
    db.session.execute(text("""
        UPDATE switch_ports
        SET port_role = 'unknown', last_updated = NOW()
        WHERE switch_host = :host AND port_name = :port
          AND port_role = 'uplink_udm'
    """), {'host': switch_host, 'port': port_name})
    _run_switch_command(switch_host, _build_reset_port_config(port_name))
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
        
        # Propagate profile and VLAN-override changes to central (which fans out to other sites)
        central_client.queue_user_updated(user)

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
    """Spec B.a: block all currently-owned devices for a user."""
    user = User.query.get_or_404(user_id)
    user.blocked = True
    db.session.commit()

    # Only block devices with active ownership (end_datetime is null).
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
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/<int:user_id>/unblock', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_unblock_user(user_id):
    """Unblock a user. Devices remain blocked and must be unblocked individually."""
    user = User.query.get_or_404(user_id)
    user.blocked = False
    db.session.commit()

    active_macs = [
        o.mac_address for o in
        DeviceOwnership.query.filter_by(user_id=user.id, end_datetime=None).all()
    ]
    blocked_count = Device.query.filter(
        Device.mac_address.in_(active_macs),
        Device.registration_status == 'blocked',
    ).count() if active_macs else 0

    if blocked_count:
        flash(
            f'User {user.email} unblocked. {blocked_count} device(s) still blocked — unblock each device manually.',
            'info',
        )
    else:
        flash(f'User {user.email} unblocked.', 'success')
    central_client.queue_user_unblocked(user)
    logger.info("Admin unblocked user %s (devices remain blocked individually)", user.email)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/assign-device', methods=['POST'])
@login_required
@permission_required('manage_users')
def admin_assign_device():
    """Spec dashboard A: assign an unregistered device to a user + VLAN.

    Sets ownership_validated=True and, when connectivity conditions allow,
    removes the DNS hijack / ACL block and sets internet_accessible=True.
    """
    mac_address = (request.form.get('mac_address') or '').strip().lower()
    user_id_raw = (request.form.get('user_id')     or '').strip()
    device_name = (request.form.get('device_name') or '').strip()
    vlan_id_raw = (request.form.get('vlan_id')     or '').strip()

    if not mac_address or not user_id_raw or not vlan_id_raw:
        flash('MAC address, user, and VLAN are required.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        user_id = int(user_id_raw)
        vlan_id = int(vlan_id_raw)
    except ValueError:
        flash('Invalid user ID or VLAN ID.', 'error')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Resolve current IP for the MAC.
    ip_lease = _get_active_iplease(mac_address)
    ip_address = ip_lease.ip_address if ip_lease else None
    if not ip_address:
        ul = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
        ip_address = ul.ip_address if ul else None
    if not ip_address:
        kea = get_kea()
        if kea:
            try:
                ip_address = kea.get_lease_ip_for_mac(mac_address, subnet_id=vlan_id)
            except Exception as exc:
                logger.error("Kea lookup failed for %s: %s", mac_address, exc)
    if not ip_address:
        ip_address = get_ip_for_mac(mac_address, subnet_id=vlan_id)

    # Get/create Device record.
    device = Device.query.filter_by(mac_address=mac_address).first()
    if not device:
        device = Device(
            mac_address=mac_address,
            first_seen=datetime.utcnow(),
        )
        db.session.add(device)

    # Detect which VLAN the device is currently on.
    _, detected_vlan, _ = detect_connection_type(ip_address) if ip_address else (None, None, None)

    device.user_id           = user.id
    device.device_name       = device_name or device.device_name or 'admin-assigned'
    device.ip_address        = ip_address
    device.assigned_vlan     = vlan_id
    device.current_vlan      = detected_vlan or vlan_id
    device.ownership_validated = True  # Admin-assigned devices are considered validated.
    device.connection_type   = device.connection_type or 'unknown'
    if not device.unregister_token:
        device.unregister_token = secrets.token_urlsafe(32)
    db.session.commit()

    # Ensure DeviceOwnership is correct.
    _close_ownership(mac_address, commit=True)
    _open_ownership(mac_address, user.id, commit=True)

    # Spec A.a.ii / A.b: determine whether to unblock now.
    same_vlan = (detected_vlan == vlan_id) if detected_vlan else False
    lease_usable = (
        ip_lease and ip_lease.lease_expiry > datetime.utcnow()
        and not ip_lease.from_blocked_pool
    )

    if same_vlan and lease_usable and ip_address:
        # Remove DNS hijack and ACL block synchronously, then mark accessible.
        if _should_hijack_vlan(vlan_id):
            manage_dns_hijack('unhijack', ip_address)
        manage_switch_acl('unblock', ip_address, vlan_id)
        if ip_lease:
            ip_lease.dns_hijacked = False
            db.session.commit()
        _set_internet_accessible(device, True, commit=True)
        _sync_registration_status(device)
        db.session.commit()
    else:
        # Wrong VLAN or blocked-pool IP — device will get access when it reconnects.
        _set_internet_accessible(device, False if vlan_id else None, commit=True)
        _sync_registration_status(device)
        db.session.commit()

    # Register with Kea for WiFi, or update RADIUS for wired.
    kea = get_kea()
    if kea:
        try:
            kea.register_mac(mac=mac_address, vlan=vlan_id,
                              hostname=device.device_name or 'admin-assigned',
                              ip_address=ip_address if same_vlan else None)
        except Exception as exc:
            logger.error("Kea reservation failed for %s: %s", mac_address, exc)

    clear_unregistered_lease(mac_address)

    # Send email notification to user.
    if device.unregister_token:
        unregister_url = _build_unregister_url(device.unregister_token)
        send_wifi_registration_confirmation(
            user.email,
            user.first_name or 'there',
            get_ssid_for_vlan(vlan_id) or 'Network',
            mac_address,
            unregister_url,
            registration_details={
                'email':        user.email,
                'first_name':   user.first_name or '',
                'last_name':    user.last_name  or '',
                'phone_number': user.phone_number or '',
                'device_type':  device.device_name,
                'ip_address':   ip_address,
                'ssid':         get_ssid_for_vlan(vlan_id) or 'Network',
            },
        )

    # Propagate assignment to central (also updates existing device ownership/vlan)
    central_client.queue_device_registered(device, user)

    flash(f'Device {mac_address} assigned to {user.email} on VLAN {vlan_id}.', 'success')
    logger.info("Admin assigned device %s to user %s (vlan=%s)", mac_address, user.email, vlan_id)
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
                created_by=current_user.username,
            )
            db.session.add(user)
            db.session.flush()

        # Get or create Device row (Table 6)
        device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
        if device:
            device.user_id = user.id
            device.device_name = reg_request.device_type or device.device_name or 'unknown'
            device.ip_address = reg_request.ip_address
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
                current_vlan=target_vlan,
                connection_type=connection_type,
                ssid=ssid,
                is_wired=connection_type == 'wired',
                wired_target_vlan=target_vlan if connection_type == 'wired' else None,
                unregister_token=secrets.token_urlsafe(32),
            )
            db.session.add(device)
            db.session.flush()

        # Spec: admin approval sets assigned_vlan; ownership_validated = True
        device.assigned_vlan = target_vlan
        device.ownership_validated = True

        # Ensure DeviceOwnership record exists
        existing_ownership = _get_active_ownership(device.mac_address)
        if not existing_ownership or existing_ownership.user_id != user.id:
            _close_ownership(device.mac_address, commit=False)
            _open_ownership(device.mac_address, user.id, commit=False)

        # Mark ALL pending requests for this MAC as approved
        for req in RegistrationRequest.query.filter_by(mac_address=reg_request.mac_address, status='pending').all():
            req.status = 'approved'
            req.processed_at = datetime.now()
            req.processed_by = current_user.username

        db.session.commit()

        # Network registration
        if device.connection_type == 'wifi':
            kea = get_kea()
            if kea:
                success = kea.register_mac(
                    mac=device.mac_address,
                    vlan=target_vlan,
                    hostname=f"{(user.first_name or 'device').lower()}-device",
                    ip_address=None,
                )
                if success and device.ip_address and not network_mismatch:
                    try:
                        kea.force_lease_renewal(device.mac_address, device.ip_address)
                    except Exception as exc:
                        logger.warning("Could not force lease renewal: %s", exc)
        else:
            send_coa_change(device.mac_address, target_vlan)
            replug_switch_port_for_mac(device.mac_address)

        # Unhijack / unblock only if device is currently on the right VLAN
        if not network_mismatch:
            if device.ip_address and _should_hijack_vlan(target_vlan):
                manage_dns_hijack('unhijack', device.ip_address)
            manage_switch_acl('unblock', reg_request.ip_address, detected_vlan)
            _set_internet_accessible(device, True)
        else:
            # device on wrong VLAN — will get access when it reconnects to target_vlan
            _set_internet_accessible(device, False)

        clear_unregistered_lease(device.mac_address)

        unregister_url = _build_unregister_url(device.unregister_token)
        if device.connection_type == 'wired':
            assigned_ssid_display = "Wired Network"
        else:
            assigned_ssid_display = get_ssid_for_vlan(target_vlan) or f"VLAN {target_vlan}"

        if network_mismatch:
            # Spec 4b.ii.2.c: admin granted a different VLAN — send mismatch email
            current_ssid_display = device.ssid or get_ssid_for_vlan(detected_vlan) or f"VLAN {detected_vlan}"
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
                confirm_url, reject_url, confirm_timeout_sec = _set_wifi_confirmation(device)
            else:
                confirm_url = None
                reject_url = None
                confirm_timeout_sec = None
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
                    "email": user.email,
                    "first_name": user.first_name or reg_request.first_name,
                    "last_name": user.last_name or reg_request.last_name,
                    "phone_number": user.phone_number or reg_request.phone_number,
                    "device_type": device.device_name,
                    "ip_address": device.ip_address,
                    "ssid": assigned_ssid_display,
                },
            )

        # Notify central server of the new registration (queued, non-blocking)
        central_client.queue_device_registered(device, user)

        flash(f'Request approved and user {user.email} registered', 'success')
        logger.info("Admin approved registration request for %s", user.email)
        
    elif action == 'reject':
        notes = request.form.get('notes', '').strip()
        if not notes:
            flash('Rejection reason is required.', 'error')
            return redirect(url_for('admin_approve_request', token=reg_request.approval_token))

        reg_request.status = 'rejected'
        reg_request.processed_at = datetime.now()
        reg_request.processed_by = current_user.username
        reg_request.notes = notes

        # Flag the device so the captive-portal polling page detects the rejection
        # immediately via the internet_blocked field rather than relying on
        # RegistrationRequest status queries.
        _rej_device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
        if _rej_device:
            _set_internet_blocked(_rej_device, True, commit=False)

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

    # Cannot unblock a device whose user is still blocked.
    if device.user and device.user.blocked:
        flash(f'Cannot unblock device: user {device.user.email} is still blocked.', 'error')
        return redirect(url_for('admin_dashboard'))

    apply_device_unblock(device, flash_messages=True)
    central_client.queue_device_unblocked(device)
    
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
    """Unregister a device (admin-side spec C.d).

    The Device row is kept (Table 6 stays) but all ownership/access fields are
    reset.  If the device currently has internet access (internet_accessible=True)
    and has a usable IP lease, a DNS hijack + ACL block is applied so the user
    loses access immediately for the remainder of the lease.
    """
    device = Device.query.get_or_404(device_id)
    mac_address = device.mac_address
    ip_address = device.ip_address
    vlan_id = device.current_vlan

    # Step 1: If device currently has internet → cut off access immediately
    if device.internet_accessible and ip_address and not _is_blocked_pool_ip(ip_address):
        lease_expiry = get_lease_expiry_for_mac(mac_address, subnet_id=vlan_id)
        if lease_expiry and lease_expiry > datetime.utcnow():
            if vlan_id:
                manage_switch_acl('block', ip_address, vlan_id)
            if _should_hijack_vlan(vlan_id):
                manage_dns_hijack('hijack', ip_address)
            _upsert_iplease(
                mac_address=mac_address, ip_address=ip_address, vlan_id=vlan_id,
                lease_start=datetime.utcnow(), lease_expiry=lease_expiry,
                from_blocked_pool=False, dns_hijacked=bool(_should_hijack_vlan(vlan_id)),
            )
            logger.info(
                "Admin unregistered %s — blocked at %s until %s",
                mac_address, ip_address, lease_expiry,
            )

    # Step 2: Unregister from Kea/RADIUS
    kea = get_kea()
    if kea:
        try:
            kea.unregister_mac(mac_address, vlan_id)
        except Exception as exc:
            logger.warning("Kea unregister failed for %s: %s", mac_address, exc)

    if device.connection_type == 'wired':
        send_coa_disconnect(mac_address)

    # Step 3: Close active DeviceOwnership
    _close_ownership(mac_address, commit=False)

    # Step 4: Reset Table-6 fields (keep mac_address / ip_address / current_vlan row)
    device.user_id = None
    device.device_name = None
    device.assigned_vlan = None
    device.internet_accessible = None
    device.internet_blocked = None
    device.ownership_validated = None
    device.first_seen = device.first_seen  # unchanged
    _sync_registration_status(device)
    db.session.commit()

    cleanup_orphan_hijack_rules()

    flash(f'Device {mac_address} has been unregistered', 'success')
    logger.info("Admin unregistered device %s", mac_address)

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
    """Reassign a registered device to a different user (spec C.a)."""
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

    # Update ownership history
    _close_ownership(device.mac_address, commit=False)
    _open_ownership(device.mac_address, new_user.id, commit=False)

    # Update convenience foreign key; keep assigned_vlan / internet_accessible unchanged
    device.user_id = new_user.id
    db.session.commit()

    # Propagate reassignment to central — updates user_email on the central device record
    central_client.queue_device_registered(device, new_user)

    logger.info(
        "Admin reassigned device %s from %s to %s",
        device.mac_address, old_email, new_user.email,
    )
    flash(f'Device {device.mac_address} reassigned to {new_user.email}.', 'success')
    return redirect(url_for('admin_dashboard'))


# ─── Pi-Hole v6 API client ────────────────────────────────────────────────────
# All API calls originate server-side; the admin never needs to know the
# PIHOLE_WEBPASSWORD.  Session tokens are stored in Redis so all gunicorn
# workers share a single Pi-Hole session (avoids exhausting max_sessions).

import redis as _redis_module

_pihole_redis_lock = threading.Lock()
_pihole_redis_client = None


def _pihole_redis():
    """Return a Redis client (lazily created, shared within the process)."""
    global _pihole_redis_client
    if _pihole_redis_client is None:
        with _pihole_redis_lock:
            if _pihole_redis_client is None:
                url = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
                _pihole_redis_client = _redis_module.from_url(url, decode_responses=True)
    return _pihole_redis_client


_PIHOLE_SID_KEY = 'pihole:sid'
_PIHOLE_EXP_KEY = 'pihole:expires'
_PIHOLE_LOCK_KEY = 'pihole:auth_lock'


def _pihole_base():
    host = os.getenv('PIHOLE_HOST', os.environ['PORTAL_IP'])
    port = os.getenv('PIHOLE_PORT', '8055')
    return f'http://{host}:{port}'


def _pihole_auth(old_sid=None):
    """Authenticate with Pi-Hole, optionally logging out old_sid first."""
    password = os.getenv('PIHOLE_WEBPASSWORD', '')
    base = _pihole_base()
    # Explicitly logout the old session to free a seat
    if old_sid:
        try:
            requests.delete(f'{base}/api/auth',
                            headers={'X-FTL-SID': old_sid}, timeout=3)
        except Exception:
            pass
    try:
        r = requests.post(f'{base}/api/auth', json={'password': password}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            sid = data.get('session', {}).get('sid')
            validity = int(data.get('session', {}).get('validity', 300))
            expires = time.time() + validity - 30
            rdb = _pihole_redis()
            rdb.set(_PIHOLE_SID_KEY, sid, ex=int(validity))
            rdb.set(_PIHOLE_EXP_KEY, str(expires), ex=int(validity))
            return sid
    except Exception as exc:
        logger.warning('Pi-Hole auth failed: %s', exc)
    return None


def _pihole_headers():
    """Return auth headers, using a Redis-shared session across all workers."""
    try:
        rdb = _pihole_redis()
        sid = rdb.get(_PIHOLE_SID_KEY)
        exp = rdb.get(_PIHOLE_EXP_KEY)
        if sid and exp and time.time() < float(exp):
            return {'X-FTL-SID': sid}
        # Use a short Redis lock to prevent all workers re-authing simultaneously
        lock = rdb.set('pihole:auth_lock', '1', nx=True, ex=10)
        if lock:
            sid = _pihole_auth(old_sid=sid)
        else:
            # Another worker is authing — wait briefly then re-read
            time.sleep(0.5)
            sid = rdb.get(_PIHOLE_SID_KEY)
    except Exception as exc:
        logger.warning('Pi-Hole Redis session lookup failed: %s', exc)
        sid = _pihole_auth()
    return {'X-FTL-SID': sid} if sid else None


def _pihole_retry(fn, path, **kwargs):
    """Call fn(url, headers, **kwargs), retry once on 401."""
    hdrs = _pihole_headers()
    if hdrs is None:
        return None
    try:
        r = fn(f'{_pihole_base()}{path}', headers=hdrs, timeout=8, **kwargs)
        if r.status_code == 401:
            # Invalidate the cached session and force re-auth
            try:
                rdb = _pihole_redis()
                old_sid = rdb.get(_PIHOLE_SID_KEY)
                rdb.delete(_PIHOLE_SID_KEY, _PIHOLE_EXP_KEY)
            except Exception:
                old_sid = None
            hdrs = _pihole_headers()
            if hdrs is None:
                return None
            r = fn(f'{_pihole_base()}{path}', headers=hdrs, timeout=8, **kwargs)
        return r
    except Exception as exc:
        logger.warning('Pi-Hole request to %s failed: %s', path, exc)
        return None


def pihole_get(path):
    r = _pihole_retry(requests.get, path)
    if r and r.ok:
        return r.json()
    return None


def pihole_post(path, body=None):
    r = _pihole_retry(requests.post, path, json=body)
    if r and r.ok:
        return r.json() if r.content else {}
    return None


def pihole_delete(path):
    r = _pihole_retry(requests.delete, path)
    return r is not None and r.status_code in (200, 204)


def pihole_put(path, body=None):
    r = _pihole_retry(requests.put, path, json=body)
    if r and r.ok:
        return r.json() if r.content else {}
    return None


# ─── Pi-Hole admin route ──────────────────────────────────────────────────────

@app.route('/admin/pihole', methods=['GET', 'POST'])
@login_required
@permission_required('manage_pihole')
def admin_pihole():
    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'enable_blocking':
            ok = pihole_post('/api/dns/blocking', {'blocking': 'enabled'})
            flash('Blocking re-enabled.' if ok is not None else 'Failed to communicate with Pi-Hole.', 'success' if ok is not None else 'error')

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
                    entry_kind = 'regex'
                    entry_domain = rf'(\.|^){_re.escape(domain)}$'
                    entry_comment = comment or domain
                else:
                    entry_kind = 'exact'
                    entry_domain = domain
                    entry_comment = comment
                ok = pihole_post(f'/api/domains/{dtype}/{entry_kind}',
                                 {'domain': entry_domain, 'comment': entry_comment, 'enabled': True,
                                  'groups': groups if groups else [0]})
                flash(f'"{domain}" added to {list_label}.' if ok is not None
                      else f'Failed to add domain to {list_label}.', 'success' if ok is not None else 'error')

        elif action == 'remove_domain':
            from urllib.parse import quote as _quote
            domain = request.form.get('domain', '').strip()
            dtype = request.form.get('type', 'allow')
            kind = request.form.get('kind', 'exact')
            if domain:
                ok = pihole_delete(f'/api/domains/{dtype}/{kind}/{_quote(domain, safe="")}')
                flash(f'"{domain}" removed.' if ok else 'Failed to remove domain.', 'success' if ok else 'error')

        elif action == 'add_adlist':
            address = request.form.get('address', '').strip()
            comment = request.form.get('comment', '').strip()
            if not address:
                flash('Adlist URL cannot be empty.', 'error')
            else:
                groups_raw = request.form.getlist('groups')
                groups = [int(g) for g in groups_raw if g.isdigit()]
                ok = pihole_post('/api/lists?type=block',
                                 {'address': address, 'comment': comment,
                                  'enabled': True,
                                  'groups': groups if groups else [0]})
                flash('Adlist added. Click "Update Gravity" to activate it.' if ok is not None
                      else 'Failed to add adlist.', 'success' if ok is not None else 'error')

        elif action == 'remove_adlist':
            from urllib.parse import quote as _quote
            address = request.form.get('address', '').strip()
            if address:
                ok = pihole_delete(f'/api/lists/{_quote(address, safe="")}?type=block')
                flash('Adlist removed. Run "Update Gravity" to apply.' if ok
                      else 'Failed to remove adlist.', 'success' if ok else 'error')

        elif action == 'update_gravity':
            # Gravity streams text/plain progress — consume entire body to wait for completion
            hdrs = _pihole_headers()
            ok = False
            if hdrs:
                try:
                    r = requests.post(f'{_pihole_base()}/api/action/gravity',
                                      headers=hdrs, timeout=(8, 180), stream=True)
                    for _ in r.iter_content(chunk_size=4096):
                        pass
                    ok = r.ok
                except Exception as exc:
                    logger.warning('Gravity update request failed: %s', exc)
            flash('Gravity update complete.' if ok
                  else 'Failed to start gravity update.', 'success' if ok else 'error')

        elif action == 'add_group':
            name = request.form.get('name', '').strip()
            comment = request.form.get('comment', '').strip()
            if not name:
                flash('Group name cannot be empty.', 'error')
            else:
                ok = pihole_post('/api/groups', {'name': name, 'comment': comment, 'enabled': True})
                flash(f'Group "{name}" created.' if ok is not None else 'Failed to create group.',
                      'success' if ok is not None else 'error')

        elif action == 'remove_group':
            from urllib.parse import quote as _quote
            name = request.form.get('name', '').strip()
            if name == 'Default':
                flash('Cannot delete the Default group.', 'error')
            elif name:
                ok = pihole_delete(f'/api/groups/{_quote(name, safe="")}')
                flash(f'Group "{name}" deleted.' if ok else 'Failed to delete group.',
                      'success' if ok else 'error')

        elif action == 'update_domain_groups':
            from urllib.parse import quote as _quote
            domain = request.form.get('domain', '').strip()
            dtype = request.form.get('type', 'allow')
            kind = request.form.get('kind', 'exact')
            groups_raw = request.form.getlist('groups')
            groups = [int(g) for g in groups_raw if g.isdigit()]
            if domain:
                ok = pihole_put(f'/api/domains/{dtype}/{kind}/{_quote(domain, safe="")}',
                                {'groups': groups if groups else [0]})
                flash('Domain groups updated.' if ok is not None else 'Failed to update domain groups.',
                      'success' if ok is not None else 'error')

        elif action == 'update_adlist_groups':
            from urllib.parse import quote as _quote
            address = request.form.get('address', '').strip()
            groups_raw = request.form.getlist('groups')
            groups = [int(g) for g in groups_raw if g.isdigit()]
            if address:
                ok = pihole_put(f'/api/lists/{_quote(address, safe="")}?type=block', {'groups': groups})
                flash('Adlist groups updated.' if ok is not None else 'Failed to update adlist groups.',
                      'success' if ok is not None else 'error')

        elif action == 'set_vlan_client':
            subnet = request.form.get('subnet', '').strip()
            client_id = request.form.get('client_id', '').strip()
            comment = request.form.get('comment', '').strip()
            groups_raw = request.form.getlist('groups')
            groups = [int(g) for g in groups_raw if g.isdigit()]
            if not subnet:
                flash('Subnet cannot be empty.', 'error')
            else:
                if not groups:
                    groups = [0]
                if client_id:
                    ok = pihole_put(f'/api/clients/{client_id}',
                                    {'groups': groups, 'comment': comment})
                else:
                    ok = pihole_post('/api/clients',
                                     {'client': subnet, 'comment': comment,
                                      'groups': groups, 'enabled': True})
                flash(f'Policy for {subnet} updated.' if ok is not None
                      else f'Failed to update policy for {subnet}.',
                      'success' if ok is not None else 'error')

        elif action == 'remove_vlan_client':
            client_id = request.form.get('client_id', '').strip()
            if client_id:
                ok = pihole_delete(f'/api/clients/{client_id}')
                flash('VLAN policy removed — subnet reverts to Default group.' if ok
                      else 'Failed to remove VLAN policy.', 'success' if ok else 'error')

        return redirect(url_for('admin_pihole'))

    # GET — fetch all data from Pi-Hole
    summary = pihole_get('/api/stats/summary')
    blocking = pihole_get('/api/dns/blocking')
    domains_data = pihole_get('/api/domains')
    adlists_data = pihole_get('/api/lists?type=block')
    groups_data = pihole_get('/api/groups')
    clients_data = pihole_get('/api/clients')

    whitelist, blacklist = [], []
    if domains_data:
        for d in domains_data.get('domains', []):
            (whitelist if d.get('type') == 'allow' else blacklist).append(d)

    adlists = (adlists_data or {}).get('lists', [])
    groups = (groups_data or {}).get('groups', [])
    clients = (clients_data or {}).get('clients', [])

    # Build per-group content summary for display in the Groups section
    group_content = {}
    for g in groups:
        gid = g['id']
        group_content[gid] = {
            'adlists':   sum(1 for a in adlists   if gid in a.get('groups', [])),
            'whitelist': sum(1 for d in whitelist  if gid in d.get('groups', [])),
            'blacklist': sum(1 for d in blacklist  if gid in d.get('groups', [])),
        }

    # Build per-VLAN policy data keyed to VALID_VLANS env var
    vlan_ids = [v.strip() for v in os.getenv('VALID_VLANS', '').split(',') if v.strip().isdigit()]
    vlan_policies = []
    for vlan_id in vlan_ids:
        subnet = f'{_net_word()}.{vlan_id}.0/24'
        entry = next((c for c in clients if c.get('client') == subnet), None)
        vlan_policies.append({
            'vlan': vlan_id,
            'subnet': subnet,
            'client_id': entry['id'] if entry else None,
            'groups': entry.get('groups', []) if entry else [],
            'comment': entry.get('comment', '') if entry else '',
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


@app.route('/admin/pihole/blocked-queries')
@login_required
@permission_required('manage_pihole')
def admin_pihole_blocked_queries():
    """Show the Pi-Hole blocked queries log with user attribution."""
    from sqlalchemy import text

    from datetime import datetime as _dt

    page      = request.args.get('page', 1, type=int)
    per_page  = 50
    offset    = (page - 1) * per_page

    user_filter      = request.args.get('user_id', '', type=str)
    domain_filter    = request.args.get('domain', '', type=str).strip()
    status_filter    = request.args.get('status', '', type=str).strip()
    client_ip_filter = request.args.get('client_ip', '', type=str).strip()
    mac_filter       = request.args.get('mac', '', type=str).strip()
    date_from_str    = request.args.get('date_from', '', type=str).strip()
    date_to_str      = request.args.get('date_to', '', type=str).strip()

    # Parse date strings into datetime objects (dates are inclusive)
    date_from = None
    date_to   = None
    try:
        if date_from_str:
            date_from = _dt.strptime(date_from_str, '%Y-%m-%d')
    except ValueError:
        date_from_str = ''
    try:
        if date_to_str:
            # Include the entire end day
            date_to = _dt.strptime(date_to_str, '%Y-%m-%d').replace(
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

    total = db.session.execute(text(f"""
        SELECT COUNT(*) FROM pihole_blocked_queries pbq {where_sql}
    """), params).scalar()

    total_pages = max(1, (total + per_page - 1) // per_page)

    # User list for filter dropdown (only users who appear in the log)
    users_in_log = db.session.execute(text("""
        SELECT DISTINCT u.id, u.first_name, u.last_name, u.email
        FROM pihole_blocked_queries pbq
        JOIN users u ON pbq.user_id = u.id
        ORDER BY u.last_name, u.first_name
    """)).fetchall()

    # Status list for filter dropdown
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


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/admin'):
        return render_template('error.html', code=404,
                               message="Page not found."), 404
    return render_template('error.html', code=404,
                           message="Page not found."), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error("500 error: %s", e)
    return render_template('error.html', code=500,
                           message="Something went wrong on the server. "
                                   "If the system is updating it will be back shortly."), 500


@app.errorhandler(Exception)
def unhandled_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    logger.exception("Unhandled exception: %s", e)
    return render_template('error.html', code=500,
                           message="An unexpected error occurred. "
                                   "If the system is updating it will be back shortly."), 500


def _startup_write_prefix_map():
    """Write vlan-prefix-map.txt from the DB so generate-kea-config.py uses
    the correct prefix sizes on the next kea container restart, regardless of
    whether the admin has saved the VLAN config form since the last deploy.
    Uses an advisory lock so only one gunicorn worker writes the file.
    """
    import threading

    def _run():
        with app.app_context():
            try:
                lock_acquired = db.session.execute(
                    text("SELECT pg_try_advisory_lock(99002)")
                ).scalar()
                if not lock_acquired:
                    return
                prefix_by_id = _get_vlan_prefix_by_id()
                if not prefix_by_id:
                    return
                config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
                prefix_map_path = os.path.join(os.path.dirname(config_path), 'vlan-prefix-map.txt')
                prefix_map_str = ','.join(f"{vid}:{pfx}" for vid, pfx in sorted(prefix_by_id.items()))
                with open(prefix_map_path, 'w', encoding='utf-8') as f:
                    f.write(prefix_map_str + '\n')
                logger.info("Wrote vlan-prefix-map.txt: %s", prefix_map_str)
            except Exception as exc:
                logger.warning("Could not write vlan-prefix-map.txt: %s", exc)
            finally:
                try:
                    db.session.execute(text("SELECT pg_advisory_unlock(99002)"))
                    db.session.commit()
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True).start()


# Trigger port discovery on every worker start (gunicorn spawns multiple workers;
# the fresh-data check inside ensures only the first worker actually does the work).
_startup_switch_discovery()
_startup_write_prefix_map()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
