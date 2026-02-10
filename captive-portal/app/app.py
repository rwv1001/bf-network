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
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import text
import secrets

from models import db, User, Device, RegistrationRequest, VlanMapping, Setting, UnregisteredLease, DomainPolicy
from radius_coa import send_coa_disconnect, send_coa_change
from email_service import (
    send_verification_email,
    send_admin_notification,
    send_wifi_registration_confirmation,
    send_user_blocked_device_notice
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


def _portal_host_mismatch():
    portal_url = _get_portal_base_url()
    if not portal_url:
        return False
    try:
        portal_host = urlparse(portal_url).netloc
    except Exception:
        return False
    return portal_host and portal_host != request.host


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

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

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


class AdminUser:
    """Simple admin user class for Flask-Login"""
    def __init__(self, username):
        self.id = username
        self.username = username
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(user_id):
    if user_id == ADMIN_USERNAME:
        return AdminUser(user_id)
    return None


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
    """Remove all users/devices/requests and Kea host/lease data."""
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

    db.session.execute(text("DELETE FROM hosts"))
    db.session.execute(text("DELETE FROM lease4"))
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

    try:
        import paramiko
    except ImportError:
        logger.error("paramiko not installed - cannot manage switch ACLs")
        return False

    switch_host = os.getenv('SWITCH_HOST', '192.168.99.1')
    switch_user = os.getenv('SWITCH_USER', 'admin')
    switch_pass = os.getenv('SWITCH_PASS', '')
    switch_key = os.getenv('SWITCH_KEY_PATH', '')
    switch_ssh_port = int(os.getenv('SWITCH_SSH_PORT', '22'))

    if not switch_pass and not switch_key:
        logger.error("SWITCH_PASS or SWITCH_KEY_PATH must be configured")
        return False

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
            "quit",
            "quit",
            "save force"
        ]
    elif action == 'unblock':
        logger.info(f"Removing ACL deny rule for {ip_address} on VLAN {vlan_id} via SSH")
        commands = [
            "system-view",
            f"acl advanced {acl_num}",
            f"undo rule {rule_num}",
            "quit",
            "quit",
            "save force"
        ]
    else:
        logger.error(f"Invalid action: {action}")
        return False

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": switch_host,
            "port": switch_ssh_port,
            "username": switch_user,
            "allow_agent": False,
            "look_for_keys": False,
            "timeout": 10,
            "disabled_algorithms": {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}
        }

        if switch_key:
            connect_kwargs["key_filename"] = switch_key
        else:
            connect_kwargs["password"] = switch_pass

        client.connect(**connect_kwargs)
        chan = client.invoke_shell()
        output = ""

        for cmd in commands:
            chan.send(cmd + "\n")
            time.sleep(1)
            if chan.recv_ready():
                output += chan.recv(65535).decode("utf-8", errors="ignore")

        chan.close()
        client.close()

        if output:
            logger.debug(f"SSH ACL output: {output}")

        logger.info(f"ACL {action} successful for {ip_address} on VLAN {vlan_id} via SSH")
        return True

    except Exception as e:
        logger.error(f"Switch ACL {action} failed for {ip_address}: {e}")
        import traceback
        logger.error(traceback.format_exc())
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
                            logger.warning(
                                "Kea registration check failed for %s: %s",
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

            # Register in network (your existing logic)
            if connection_type == 'wifi':
                kea = get_kea()
                if kea:
                    kea.register_mac(mac=mac_address, vlan=target_vlan, hostname=f"{first_name.lower()}-{last_name.lower()}-{device_type}", ip_address=None)
                    if ip_address and not network_mismatch:
                        kea.force_lease_renewal(mac_address, ip_address)
            else:
                send_coa_change(mac_address, target_vlan)

            if ip_address and not network_mismatch and _should_hijack_vlan(target_vlan or detected_vlan):
                manage_dns_hijack('unhijack', ip_address)
            clear_unregistered_lease(mac_address)
            if ip_address and detected_vlan and not network_mismatch:
                manage_switch_acl('unblock', ip_address, detected_vlan)

            unregister_url = _build_unregister_url(device.unregister_token)

            ssid_display = ssid or "Wired Network"
            send_wifi_registration_confirmation(
                user.email,
                user.first_name or first_name,
                ssid_display,
                mac_address,
                unregister_url,
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

                if ip_address and _should_hijack_vlan(target_vlan or detected_vlan):
                    manage_dns_hijack('unhijack', ip_address)
                clear_unregistered_lease(mac_address)
                if ip_address and detected_vlan:
                    manage_switch_acl('unblock', ip_address, detected_vlan)

                unregister_url = _build_unregister_url(device.unregister_token)
                ssid_display = ssid or "Wired Network"
                send_wifi_registration_confirmation(
                    user.email,
                    user.first_name or first_name or "there",
                    ssid_display,
                    mac_address,
                    unregister_url,
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
            db.session.commit()
            portal_url = os.getenv('PORTAL_URL')
            if portal_url:
                parsed = urlparse(portal_url)
                approval_url = f"{parsed.scheme}://{parsed.netloc}{url_for('admin_approve_request', token=reg_request.approval_token)}"
            else:
                approval_url = url_for('admin_approve_request', token=reg_request.approval_token, _external=True)

            send_admin_notification(reg_request, approval_url, detected_vlan, ssid)

            prefill_data = {
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'phone_number': phone_number,
                'device_type': device_type
            }

            if is_ajax:
                return jsonify({
                    'status': 'pending',
                    'message': 'Registration request submitted. Waiting for approval...',
                    'prefill': prefill_data  # Send back for client to display/prefill on resubmit
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
                            logger.warning("Kea registration check failed for %s: %s", device.mac_address, exc)

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


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            user = AdminUser(username)
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('admin_login.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    """Admin logout"""
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin/reset-test', methods=['POST'])
@login_required
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

    if acl_ok:
        flash('Test reset complete. ACL baseline and blocked-pool DNS hijack rules restored.', 'success')
    else:
        flash('Test reset complete, but ACL baseline update failed.', 'warning')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/vlan-config', methods=['GET', 'POST'])
@login_required
def admin_vlan_config():
    """VLAN configuration page"""
    if request.method == 'POST':
        valid_vlan_ids = set(_parse_valid_vlan_ids())
        statuses = request.form.getlist('vlan_status')
        names = request.form.getlist('vlan_name')
        vlan_ids = request.form.getlist('vlan_id')
        ssids = request.form.getlist('vlan_ssid')
        wired_statuses = set(request.form.getlist('vlan_wired'))
        remove_statuses = set(request.form.getlist('vlan_remove'))

        warnings = []
        errors = []
        seen_statuses = set()
        seen_vlan_ids = set()

        for index, status_raw in enumerate(statuses):
            status = (status_raw or '').strip().lower()
            if not status:
                continue

            if status in seen_statuses:
                warnings.append(f"Duplicate VLAN key skipped: {status}")
                continue
            seen_statuses.add(status)

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

            mapping = VlanMapping.query.filter_by(status=status).first()
            if mapping:
                mapping.vlan_id = vlan_id
                mapping.display_name = display_name
                mapping.ssid = ssid
                mapping.wired_enabled = wired_enabled
            else:
                mapping = VlanMapping(
                    status=status,
                    vlan_id=vlan_id,
                    display_name=display_name,
                    ssid=ssid,
                    wired_enabled=wired_enabled,
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
    vlan_entries = get_vlan_entries()
    valid_vlan_ids = _parse_valid_vlan_ids()
    return render_template(
        'admin_vlan_config.html',
        vlan_map=vlan_map,
        vlan_entries=vlan_entries,
        valid_vlan_ids=valid_vlan_ids,
        fixed_statuses=FIXED_VLAN_STATUSES,
        prefix_map=prefix_map,
        prefix_choices=POOL_PREFIX_CHOICES,
        prefix_statuses=POOL_PREFIX_STATUSES,
    )


@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard with MAC address management, pagination, and search"""
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
            for entry in _get_wired_assignable_entries()
        ],
        lease_stats=lease_stats,
        domain_policies=domain_policies,
        test_env=is_test_env()
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


@app.route('/admin/domain-policies', methods=['POST'])
@login_required
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


@app.route('/admin/approve/<token>')
@login_required
def admin_approve_request(token):
    """Approve registration request from email link"""
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()
    
    if reg_request.status != 'pending':
        flash('This request has already been processed', 'info')
        return redirect(url_for('admin_dashboard'))
    
    existing_user = User.query.filter_by(email=reg_request.email).first()
    detected_connection, detected_vlan, detected_ssid = detect_connection_type(reg_request.ip_address)
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
        today=datetime.utcnow().date().isoformat()
    )


@app.route('/admin/requests/<int:request_id>/process', methods=['POST'])
@login_required
def admin_process_request(request_id):
    """Process (approve/reject) a registration request"""
    reg_request = RegistrationRequest.query.get_or_404(request_id)
    
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
            # Remove DNS hijacking for wired devices too
            if device.ip_address and _should_hijack_vlan(target_vlan):
                manage_dns_hijack('unhijack', device.ip_address)

        clear_unregistered_lease(device.mac_address)
        
        # NEW: Unblock the original IP address from the unregistered VLAN
        if not network_mismatch:
            manage_switch_acl('unblock', reg_request.ip_address, detected_vlan)

        unregister_url = _build_unregister_url(device.unregister_token)
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
