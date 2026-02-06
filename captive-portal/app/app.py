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
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import text
import secrets

from models import db, User, Device, RegistrationRequest, VlanMapping, Setting, UnregisteredLease
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
    """Parse VLAN->SSID map from VLAN_SSID_MAP env (e.g. 10:SSID,20:SSID)."""
    mapping = {}
    raw = os.getenv('VLAN_SSID_MAP', '').strip()
    if not raw:
        return mapping
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        if ':' not in entry:
            continue
        vlan_str, ssid = entry.split(':', 1)
        try:
            vlan_id = int(vlan_str.strip())
        except ValueError:
            continue
        ssid = ssid.strip()
        if ssid:
            mapping[vlan_id] = ssid
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


def _format_allowed_vlans(vlans):
    if not vlans:
        return ''
    return ','.join(str(vlan) for vlan in sorted(vlans))


def _default_vlan_for_user(allowed_vlans, vlan_map):
    if allowed_vlans:
        return sorted(allowed_vlans)[0]
    return vlan_map.get('guests')


def _label_for_vlan(vlan_id, vlan_map):
    if not vlan_id:
        return ''
    reverse_map = {mapped_vlan: status for status, mapped_vlan in vlan_map.items()}
    status = reverse_map.get(vlan_id)
    if status:
        return f"{status.title()} (VLAN {vlan_id})"
    return f"VLAN {vlan_id}"


def _allowed_vlans_display(user, vlan_map):
    allowed = _parse_allowed_vlans(user.allowed_vlans)
    if not allowed:
        return ''
    labels = []
    for vlan_id in sorted(allowed):
        labels.append(_label_for_vlan(vlan_id, vlan_map))
    return ', '.join(labels)


def _adoptable_vlans_display(user, vlan_map):
    adoptable = _parse_allowed_vlans(user.adoptable_vlans)
    if not adoptable:
        return ''
    labels = []
    for vlan_id in sorted(adoptable):
        labels.append(_label_for_vlan(vlan_id, vlan_map))
    return ', '.join(labels)


def get_adoptable_vlans():
    raw = os.getenv('ADOPTABLE_VLANS', '').strip()
    return _parse_allowed_vlans(raw)


def _should_hijack_vlan(vlan_id):
    if not vlan_id:
        return True
    return vlan_id not in get_adoptable_vlans()




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
        'friars': int(os.getenv('VLAN_FRIARS', 10)),
        'staff': int(os.getenv('VLAN_STAFF', 20)),
        'students': int(os.getenv('VLAN_STUDENTS', 30)),
        'guests': int(os.getenv('VLAN_GUESTS', 40)),
        'contractors': int(os.getenv('VLAN_CONTRACTORS', 50)),
        'volunteers': int(os.getenv('VLAN_VOLUNTEERS', 60)),
        'iot': int(os.getenv('VLAN_IOT', 70)),
        'restricted': int(os.getenv('VLAN_RESTRICTED', 90)),
        'unregistered': int(os.getenv('VLAN_UNREGISTERED', 99)),
    }

def get_auto_approve_vlans():
    """Get list of VLANs that auto-approve from settings"""
    auto_approve_str = Setting.get_value('auto_approve_vlans', '40,30,60')
    return [int(v.strip()) for v in auto_approve_str.split(',') if v.strip()]

def get_admin_approval_vlans():
    """Get list of VLANs that require admin approval from settings"""
    admin_approval_str = Setting.get_value('admin_approval_vlans', '10,20,50')
    return [int(v.strip()) for v in admin_approval_str.split(',') if v.strip()]

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
        parts = [int(p) for p in ip_address.split('.')]
        if len(parts) != 4:
            return None
        if parts[0] != 192 or parts[1] != 168:
            return None
        return parts[2]
    except Exception:
        return None


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
    WiFi connections: All other VLANs (10, 20, 30, 40, 50, 60, 70, 90)
    
    Args:
        ip_address: Client IP address
        
    Returns:
        tuple: (connection_type, vlan_id, ssid)
    """
    if not ip_address:
        return ('unknown', None, None)
    
    # Extract VLAN from IP (192.168.XX.YYY)
    parts = ip_address.split('.')
    if len(parts) == 4:
        try:
            vlan_id = int(parts[2])
            
            # VLAN 99 = wired (registration VLAN)
            if vlan_id == 99:
                return ('wired', vlan_id, None)
            
            # Map VLAN to SSID (WiFi)
            ssid_map = {
                10: 'Blackfriars-Friars',
                20: 'Blackfriars-Staff',
                30: 'Blackfriars-Students',
                40: 'Blackfriars-Guests',
                50: 'Blackfriars-Contractors',
                60: 'Blackfriars-Volunteers',
                70: 'Blackfriars-IoT',
                90: 'Blackfriars-Restricted'
            }
            
            if vlan_id in ssid_map:
                return ('wifi', vlan_id, ssid_map[vlan_id])
        except ValueError:
            pass
    
    return ('unknown', None, None)


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
        logger.error("ACL baseline failed: %s", (result.stderr or result.stdout).strip())
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
    try:
        parts = [int(p) for p in ip_address.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] != 192 or parts[1] != 168:
            return False
        if parts[2] not in {10, 20, 30, 40, 50, 60, 70, 90}:
            return False
        return 214 <= parts[3] <= 254
    except Exception:
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
            user_adoptable = _parse_allowed_vlans(device.user.adoptable_vlans)
            adoptable_global = get_adoptable_vlans()
            if user_adoptable & adoptable_global:
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

    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        first_name = request.form.get('first_name').strip()
        last_name = request.form.get('last_name').strip()
        phone_number = request.form.get('phone_number').strip()
        device_type = request.form.get('device_type').strip()

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
                return render_template('register.html', prefill=prefill, detected_mac=detected_mac, detected_ip=detected_ip)

        # Check if user exists (your existing logic)
        user = User.query.filter_by(email=email).first()

        if user:
            # Existing user - register device immediately unless VLAN requires approval
            vlan_map = get_vlan_map()
            connection_type, detected_vlan, ssid = detect_connection_type(ip_address)
            current_ssid = ssid or (get_ssid_for_vlan(detected_vlan) if detected_vlan else None)

            allowed_vlans = _parse_allowed_vlans(user.allowed_vlans)
            if not allowed_vlans:
                default_vlan = vlan_map.get('guests')
                if default_vlan:
                    allowed_vlans = {default_vlan}
                    user.allowed_vlans = _format_allowed_vlans(allowed_vlans)
                    db.session.commit()

            default_vlan = _default_vlan_for_user(allowed_vlans, vlan_map)

            if connection_type == 'wifi' and detected_vlan:
                if detected_vlan not in allowed_vlans:
                    network_mismatch = True
                    expected_ssid = get_ssid_for_vlan(default_vlan)
                else:
                    network_mismatch = False
                    expected_ssid = get_ssid_for_vlan(detected_vlan)
                target_vlan = detected_vlan if detected_vlan in allowed_vlans else None
            else:
                target_vlan = default_vlan
                expected_ssid = get_ssid_for_vlan(target_vlan)
                network_mismatch = False
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

            if network_mismatch and connection_type == 'wifi':
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
                        status='pending',
                        approval_token=secrets.token_urlsafe(32)
                    )
                    db.session.add(reg_request)

                note_parts = [
                    f"Existing user allowed VLANs: {_allowed_vlans_display(user, vlan_map) or 'none'}",
                    f"Detected VLAN: {detected_vlan}",
                    f"Detected SSID: {current_ssid or 'unknown'}"
                ]
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

            portal_url = os.getenv('PORTAL_URL')
            if portal_url:
                parsed = urlparse(portal_url)
                unregister_url = f"{parsed.scheme}://{parsed.netloc}{url_for('unregister', token=device.unregister_token)}"
            else:
                unregister_url = url_for('unregister', token=device.unregister_token, _external=True)

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
            # New user - create pending request (your existing logic)
            reg_request = RegistrationRequest(
                mac_address=mac_address,
                ip_address=ip_address,
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                device_type=device_type,
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
            
            connection_type, detected_vlan, ssid = detect_connection_type(ip_address)
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
    return render_template('register.html', prefill=prefill, detected_mac=detected_mac, detected_ip=detected_ip)

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
        allowed_vlans = _parse_allowed_vlans(user.allowed_vlans)
        target_vlan = _default_vlan_for_user(allowed_vlans, vlan_map)
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
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    try:
        return int(parts[2]) == int(vlan_id) and 5 <= int(parts[3]) <= 213
    except ValueError:
        return False


@app.route('/adopt')
def adopt_devices():
    user, device = _current_user_from_device()
    if not user:
        return render_template(
            'adopt_devices.html',
            user=None,
            devices=[],
            registered_devices=[],
            error='registered_device',
        )

    adoptable_global = get_adoptable_vlans()
    user_adoptable = _parse_allowed_vlans(user.adoptable_vlans)
    allowed_vlans = sorted(adoptable_global & user_adoptable)
    if not allowed_vlans:
        return render_template(
            'adopt_devices.html',
            user=user,
            devices=[],
            registered_devices=[],
            error='no_permissions',
        )

    candidates = _load_adoptable_leases(set(allowed_vlans))

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
        })

    vlan_map = get_vlan_map()
    for item in adoptable_devices:
        item['vlan_label'] = _label_for_vlan(item['vlan_id'], vlan_map)

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
        })

    return render_template(
        'adopt_devices.html',
        user=user,
        devices=adoptable_devices,
        registered_devices=registered_device_rows,
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
    device_type_raw = (request.form.get('device_type') or '').strip()
    device_type_other = (request.form.get('device_type_other') or '').strip()
    fixed_ip_requested = (request.form.get('fixed_ip') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
    try:
        vlan_id = int(vlan_id_raw)
    except ValueError:
        vlan_id = None

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

    adoptable_global = get_adoptable_vlans()
    user_adoptable = _parse_allowed_vlans(user.adoptable_vlans)
    if vlan_id not in adoptable_global or vlan_id not in user_adoptable:
        flash('You do not have permission to adopt devices on that VLAN.', 'error')
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

    if fixed_ip_requested and reserved_ip and not _is_registered_pool_ip(reserved_ip, vlan_id):
        kea = get_kea()
        if kea:
            try:
                reserved_ip = kea.get_available_registered_ip(vlan_id)
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
        existing.current_vlan = vlan_id
        existing.connection_type = 'wifi'
        existing.ssid = get_ssid_for_vlan(vlan_id)
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
            current_vlan=vlan_id,
            connection_type='wifi',
            ssid=get_ssid_for_vlan(vlan_id),
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
            success = kea.register_mac(mac=mac_address, vlan=vlan_id, hostname=hostname, ip_address=reserved_ip)
            if fixed_ip_requested:
                _log_kea_host_reservation(mac_address, vlan_id, 'after reservation-add')
            if not success:
                flash('Adopted device, but Kea reservation failed. Please re-try or check Kea logs.', 'warning')
            kea.set_block_status(
                mac_address,
                vlan_id,
                False,
                keep_ip=fixed_ip_requested,
                fixed_ip=reserved_ip if fixed_ip_requested else None,
            )
            if fixed_ip_requested:
                _log_kea_host_reservation(mac_address, vlan_id, 'after unblock')
        except Exception as exc:
            logger.warning("Failed to clear Kea block for %s: %s", mac_address, exc)

    clear_unregistered_lease(mac_address)

    flash(
        f'Device {mac_address} adopted successfully. ACL block and DNS hijack removed.',
        'success',
    )
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
        # Update VLAN mappings
        for status in ['friars', 'staff', 'students', 'guests', 'contractors', 'volunteers', 'iot', 'restricted', 'unregistered']:
            vlan_id = request.form.get(f'vlan_{status}')
            if vlan_id:
                mapping = VlanMapping.query.filter_by(status=status).first()
                if mapping:
                    mapping.vlan_id = int(vlan_id)
                else:
                    mapping = VlanMapping(status=status, vlan_id=int(vlan_id))
                    db.session.add(mapping)
        
        # Update auto-approve VLANs
        auto_approve_vlans = []
        for status in ['friars', 'staff', 'students', 'guests', 'contractors', 'volunteers', 'iot']:
            if request.form.get(f'auto_approve_{status}'):
                vlan_id = request.form.get(f'vlan_{status}')
                if vlan_id:
                    auto_approve_vlans.append(vlan_id)
        
        Setting.set_value('auto_approve_vlans', ','.join(auto_approve_vlans))
        
        # Update admin approval VLANs (inverse of auto-approve)
        vlan_map = get_vlan_map()
        admin_approval_vlans = []
        for status in ['friars', 'staff', 'students', 'guests', 'contractors', 'volunteers', 'iot']:
            vlan_id = str(vlan_map.get(status, ''))
            if vlan_id and vlan_id not in auto_approve_vlans:
                admin_approval_vlans.append(vlan_id)
        
        Setting.set_value('admin_approval_vlans', ','.join(admin_approval_vlans))
        
        db.session.commit()
        
        flash('VLAN configuration updated successfully', 'success')
        logger.info(f"Admin updated VLAN configuration")
        
        return redirect(url_for('admin_vlan_config'))
    
    # Load current configuration
    vlan_map = get_vlan_map()
    auto_approve_vlans = get_auto_approve_vlans()
    
    return render_template('admin_vlan_config.html', 
                         vlan_map=vlan_map,
                         auto_approve_vlans=auto_approve_vlans)


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
                User.allowed_vlans.ilike(f'%{users_search}%'),
                User.adoptable_vlans.ilike(f'%{users_search}%'),
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
    for user in users:
        user.allowed_vlans_display = _allowed_vlans_display(user, vlan_map)
        user.adoptable_vlans_display = _adoptable_vlans_display(user, vlan_map)
    
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
        auto_approve_vlans=get_auto_approve_vlans(),
        admin_approval_vlans=get_admin_approval_vlans(),
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


@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    """Add new authorized user"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        allowed_vlans_input = request.form.getlist('allowed_vlans')
        adoptable_vlans_input = request.form.getlist('adoptable_vlans')
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        notes = request.form.get('notes', '').strip()
        
        if not email:
            flash('Email is required', 'error')
            return render_template('admin_add_user.html', vlan_map=get_vlan_map())
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'error')
            return render_template('admin_add_user.html', vlan_map=get_vlan_map())
        
        vlan_map = get_vlan_map()
        allowed_vlans = _parse_allowed_vlans(','.join(allowed_vlans_input))
        if not allowed_vlans:
            default_vlan = vlan_map.get('guests')
            if default_vlan:
                allowed_vlans.add(default_vlan)

        adoptable_vlans = _parse_allowed_vlans(','.join(adoptable_vlans_input))

        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            begin_date=begin_date,
            expiry_date=expiry_date,
            notes=notes,
            created_by=current_user.username,
            allowed_vlans=_format_allowed_vlans(allowed_vlans),
            adoptable_vlans=_format_allowed_vlans(adoptable_vlans)
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User {email} added successfully', 'success')
        logger.info(f"Admin added user: {email}")
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_add_user.html', vlan_map=get_vlan_map())


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
        allowed_vlans_input = request.form.getlist('allowed_vlans')
        adoptable_vlans_input = request.form.getlist('adoptable_vlans')
        apply_status_to_devices = False
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        user.expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        user.notes = request.form.get('notes', '').strip()

        allowed_vlans = _parse_allowed_vlans(','.join(allowed_vlans_input))
        if not allowed_vlans:
            default_vlan = get_vlan_map().get('guests')
            if default_vlan:
                allowed_vlans.add(default_vlan)
        user.allowed_vlans = _format_allowed_vlans(allowed_vlans)

        adoptable_vlans = _parse_allowed_vlans(','.join(adoptable_vlans_input))
        user.adoptable_vlans = _format_allowed_vlans(adoptable_vlans)
        
        db.session.commit()
        
        if apply_status_to_devices:
            vlan_map = get_vlan_map()
            target_vlan = _default_vlan_for_user(allowed_vlans, vlan_map)
            devices = Device.query.filter_by(user_id=user.id, registration_status='registered').all()

            for device in devices:
                device.current_vlan = target_vlan
                send_coa_change(device.mac_address, target_vlan)

            db.session.commit()
        
        flash(f'User {user.email} updated successfully', 'success')
        logger.info(f"Admin updated user: {user.email}")
        
        return redirect(url_for('admin_dashboard'))
    
    allowed_vlans = _parse_allowed_vlans(user.allowed_vlans)
    adoptable_vlans = _parse_allowed_vlans(user.adoptable_vlans)
    return render_template(
        'admin_edit_user.html',
        user=user,
        vlan_map=get_vlan_map(),
        allowed_vlans=allowed_vlans,
        adoptable_vlans=adoptable_vlans,
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
        existing_user_allowed_display = _allowed_vlans_display(existing_user, get_vlan_map())
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
            target_vlan = vlan_map.get('guests')

        # Detect connection type from IP address
        connection_type, detected_vlan, ssid = detect_connection_type(reg_request.ip_address)
        network_mismatch = bool(connection_type == 'wifi' and detected_vlan and target_vlan and detected_vlan != target_vlan)

        existing_user = User.query.filter_by(email=reg_request.email).first()
        if existing_user:
            user = existing_user
            if notes:
                user.notes = f"{user.notes}\n{notes}" if user.notes else notes

            allowed_vlans = _parse_allowed_vlans(user.allowed_vlans)
            if target_vlan:
                allowed_vlans.add(target_vlan)
                user.allowed_vlans = _format_allowed_vlans(allowed_vlans)

            device = Device.query.filter_by(mac_address=reg_request.mac_address).first()
            if device:
                device.user_id = user.id
                device.device_name = reg_request.device_type or device.device_name or 'unknown'
                device.ip_address = reg_request.ip_address
                device.registration_status = 'registered'
                device.current_vlan = target_vlan
                device.connection_type = connection_type
                device.ssid = ssid
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
                created_by=current_user.username,
                allowed_vlans=_format_allowed_vlans({target_vlan} if target_vlan else set())
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
