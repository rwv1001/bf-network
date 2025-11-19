"""
Captive Portal Application
Main Flask application for network device registration
"""

import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets

from models import db, User, Device, RegistrationRequest, VlanMapping, Setting
from radius_coa import send_coa_disconnect, send_coa_change
from email_service import send_verification_email, send_admin_notification, send_wifi_registration_confirmation
from kea_integration import get_kea_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://portal_user:password@db:5432/captive_portal')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

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
                lease_files = [
                    '/kea/leases/kea-leases4.csv',
                    '/kea/leases/kea-leases4.csv.2',
                    '/kea/leases/kea-leases4.csv.1'
                ]
                
                # Try each lease file until we find the MAC
                for lease_file in lease_files:
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
                                        # MAC address is in fields[1] in format xx:xx:xx:xx:xx:xx
                                        mac = lease_hwaddr
                                        logger.info(f"Found MAC {mac} for IP {ip_address} in Kea lease file {lease_file}")
                                        break
                        
                        # If we found the MAC, stop searching other files
                        if mac:
                            break
                            
                    except FileNotFoundError:
                        logger.debug(f"Kea lease file not found: {lease_file}")
                        continue
                    except Exception as e:
                        logger.error(f"Error reading Kea lease file {lease_file}: {e}")
                        continue
                        
            except Exception as e:
                logger.error(f"Error looking up MAC address: {e}")
    
    # Normalize MAC address format
    if mac:
        mac = mac.lower().replace('-', '').replace(':', '')
        if len(mac) == 12:
            # Format as xx:xx:xx:xx:xx:xx
            mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
    
    return mac


def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


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


@app.route('/')
def index():
    """Landing page - redirect to registration"""
    return redirect(url_for('register'))


# Captive portal detection endpoints
@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/ncsi.txt')
@app.route('/connecttest.txt')
@app.route('/hotspot-detect.html')
@app.route('/library/test/success.html')
def captive_portal_detection():
    """Respond to captive portal detection probes"""
    # Return HTTP 200 with redirect to trigger captive portal login
    return redirect(url_for('register')), 302


@app.route('/portal')
@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration form"""
    mac_address = get_client_mac()
    ip_address = get_client_ip()
    
    logger.info(f"Registration page accessed from IP: {ip_address}, MAC: {mac_address}")
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        device_type = request.form.get('device_type', '').strip()
        
        if not email or not first_name or not last_name or not device_type:
            flash('Please fill in all required fields', 'error')
            return render_template('register.html', detected_mac=mac_address, detected_ip=ip_address)
        
        if not mac_address:
            flash('Could not detect your device MAC address. Please contact the administrator.', 'error')
            return render_template('register.html')
        
        # Check if this device is already registered
        existing_device = Device.query.filter_by(mac_address=mac_address).first()
        if existing_device and existing_device.registration_status == 'active':
            flash('This device is already registered and active.', 'info')
            return redirect(url_for('status'))
        
        # Check if user exists in pre-authorized list
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Scenario 1: User is pre-authorized
            today = datetime.now().date()
            
            if user.begin_date > today:
                flash(f'Your access begins on {user.begin_date}. Please try again after that date.', 'warning')
                return render_template('register.html')
            
            if user.expiry_date < today:
                flash('Your access has expired. Please contact the administrator.', 'error')
                return render_template('register.html')
            
            # Update user info if provided
            if phone_number and not user.phone_number:
                user.phone_number = phone_number
            if first_name:
                user.first_name = first_name
            if last_name:
                user.last_name = last_name
            
            # Create or update device record
            device = existing_device or Device(mac_address=mac_address)
            device.user_id = user.id
            device.device_name = device_type
            device.ip_address = ip_address
            device.last_seen = datetime.now()
            
            # Detect connection type
            connection_type, vlan_id, ssid = detect_connection_type(ip_address)
            device.connection_type = connection_type
            device.ssid = ssid
            device.current_vlan = vlan_id
            
            logger.info(f"Connection type: {connection_type}, VLAN: {vlan_id}, SSID: {ssid}")
            
            # Check if email verification is required
            email_verification_required = Setting.get_value('email_verification_required', 'false') == 'true'
            
            if email_verification_required:
                # Generate verification token
                device.verification_token = secrets.token_urlsafe(32)
                timeout_minutes = int(Setting.get_value('verification_timeout_minutes', '15'))
                device.verification_expires_at = datetime.now() + timedelta(minutes=timeout_minutes)
                device.registration_status = 'pending'
                
                # Send verification email
                verification_url = f"{os.getenv('PORTAL_URL')}/verify?token={device.verification_token}"
                send_verification_email(email, first_name, verification_url, timeout_minutes)
                
                if not existing_device:
                    db.session.add(device)
                db.session.commit()
                
                flash(f'A verification email has been sent to {email}. Please click the link within {timeout_minutes} minutes to complete registration.', 'info')
            else:
                # Immediately activate
                device.registration_status = 'active'
                
                # Generate unregister token for WiFi devices
                if connection_type == 'wifi':
                    device.unregister_token = secrets.token_urlsafe(32)
                
                if not existing_device:
                    db.session.add(device)
                db.session.commit()
                
                # Handle registration based on connection type
                if connection_type == 'wifi':
                    # WiFi: Register in Kea DHCP
                    kea = get_kea()
                    if kea:
                        success = kea.register_mac(
                            mac=mac_address,
                            vlan=vlan_id,
                            hostname=f"{first_name.lower()}-{last_name.lower()}-device"
                        )
                        
                        if success:
                            # Send WiFi confirmation email with unregister link
                            unregister_url = f"{os.getenv('PORTAL_URL')}/unregister/{device.unregister_token}"
                            send_wifi_registration_confirmation(
                                user_email=email,
                                first_name=first_name,
                                ssid=ssid,
                                mac_address=mac_address,
                                unregister_url=unregister_url
                            )
                            
                            flash(f'Registration successful! Connecting you to {ssid}... (wait 30 seconds)', 'success')
                            logger.info(f"WiFi device {mac_address} registered for {email} on VLAN {vlan_id}")
                        else:
                            flash('Registration saved, but there was an issue with DHCP setup. Please contact support.', 'warning')
                    else:
                        flash('DHCP service unavailable. Please contact support.', 'error')
                        
                elif connection_type == 'wired':
                    # Wired: Use RADIUS CoA
                    vlan_map = get_vlan_map()
                    target_vlan = vlan_map.get(user.status, vlan_map['guests'])
                    device.current_vlan = target_vlan
                    db.session.commit()
                    
                    success = send_coa_change(mac_address, target_vlan)
                    
                    if success:
                        flash(f'Registration successful! You now have {user.status} access.', 'success')
                        logger.info(f"Wired device {mac_address} registered for {email} on VLAN {target_vlan}")
                    else:
                        flash('Registration saved, but there was an issue updating your network access. Please contact support.', 'warning')
                else:
                    flash('Registration saved, but connection type could not be determined. Please contact support.', 'warning')
            
            db.session.commit()
            return redirect(url_for('status'))
            
        else:
            # Scenario 2: User not pre-authorized - create registration request OR auto-approve
            connection_type, vlan_id, ssid = detect_connection_type(ip_address)
            
            # Check if this VLAN allows auto-approval
            auto_approve_vlans = get_auto_approve_vlans()
            if vlan_id in auto_approve_vlans:
                # Auto-approve: Create user and device immediately
                logger.info(f"Auto-approving registration for {email} on VLAN {vlan_id} (auto-approve VLAN)")
                
                # Create new user with guest status
                user = User(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    phone_number=phone_number,
                    status='guests',  # Default status for auto-approved users
                    begin_date=datetime.now().date(),
                    expiry_date=datetime.now().date() + timedelta(days=30)  # 30 days access
                )
                db.session.add(user)
                db.session.flush()  # Get user.id
                
                # Create device
                device = Device(
                    mac_address=mac_address,
                    user_id=user.id,
                    device_name=device_type,
                    ip_address=ip_address,
                    registration_status='active',
                    current_vlan=vlan_id,
                    connection_type=connection_type,
                    ssid=ssid,
                    last_seen=datetime.now()
                )
                
                # Generate unregister token for WiFi
                if connection_type == 'wifi':
                    device.unregister_token = secrets.token_urlsafe(32)
                
                db.session.add(device)
                db.session.commit()
                
                # Register in Kea DHCP for WiFi
                if connection_type == 'wifi':
                    kea = get_kea()
                    if kea:
                        success = kea.register_mac(
                            mac=mac_address,
                            vlan=vlan_id,
                            hostname=f"{first_name.lower()}-{last_name.lower()}-device"
                        )
                        
                        if success:
                            # Send WiFi confirmation email
                            unregister_url = f"{os.getenv('PORTAL_URL')}/unregister/{device.unregister_token}"
                            send_wifi_registration_confirmation(
                                user_email=email,
                                first_name=first_name,
                                ssid=ssid,
                                mac_address=mac_address,
                                unregister_url=unregister_url
                            )
                            
                            flash(f'Registration successful! You now have guest access. Reconnecting... (wait 30 seconds)', 'success')
                            logger.info(f"Auto-approved WiFi device {mac_address} for {email} on VLAN {vlan_id}")
                        else:
                            flash('Registration saved, but there was an issue with DHCP setup. Please contact support.', 'warning')
                    else:
                        flash('DHCP service unavailable. Please contact support.', 'error')
                else:
                    # Wired connection - use RADIUS CoA
                    success = send_coa_change(mac_address, vlan_id)
                    if success:
                        flash(f'Registration successful! You now have guest access.', 'success')
                        logger.info(f"Auto-approved wired device {mac_address} for {email} on VLAN {vlan_id}")
                    else:
                        flash('Registration saved, but there was an issue updating network access. Please contact support.', 'warning')
                
                return redirect(url_for('status'))
            
            else:
                # Admin approval required
                logger.info(f"Creating registration request for {email} on VLAN {vlan_id} (admin approval required)")
                
                reg_request = RegistrationRequest(
                    mac_address=mac_address,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    phone_number=phone_number,
                    device_type=device_type,
                    ip_address=ip_address,
                    user_agent=request.headers.get('User-Agent', ''),
                    approval_token=secrets.token_urlsafe(32)
                )
                
                db.session.add(reg_request)
                db.session.commit()
                
                # Send notification to admin
                approval_url = f"{os.getenv('PORTAL_URL')}/admin/approve/{reg_request.approval_token}"
                send_admin_notification(reg_request, approval_url)
                
                flash('Your registration request has been submitted. An administrator will review it shortly and contact you.', 'info')
                logger.info(f"Registration request submitted for {email} from MAC {mac_address}")
                
                return redirect(url_for('status'))
    
    return render_template('register.html', detected_mac=mac_address, detected_ip=ip_address)


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
        device.registration_status = 'restricted'
        device.current_vlan = vlan_map['restricted']
        db.session.commit()
        
        send_coa_change(device.mac_address, vlan_map['restricted'])
        
        flash('Verification link has expired. Your device has been placed on a restricted network. Please contact the administrator.', 'error')
        return redirect(url_for('status'))
    
    # Verification successful
    user = device.user
    if user:
        vlan_map = get_vlan_map()
        target_vlan = vlan_map.get(user.status, vlan_map['guests'])
        device.registration_status = 'active'
        device.current_vlan = target_vlan
        device.verification_token = None
        device.verification_expires_at = None
        db.session.commit()
        
        # Send RADIUS CoA
        success = send_coa_change(device.mac_address, target_vlan)
        
        if success:
            flash(f'Email verified! You now have {user.status} access.', 'success')
            logger.info(f"Device {device.mac_address} verified and moved to VLAN {target_vlan}")
        else:
            flash('Verification successful, but there was an issue updating network access. Please contact support.', 'warning')
    
    return redirect(url_for('status'))


@app.route('/status')
def status():
    """Show registration status"""
    mac_address = get_client_mac()
    
    if not mac_address:
        return render_template('status.html', device=None)
    
    device = Device.query.filter_by(mac_address=mac_address).first()
    return render_template('status.html', device=device)


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
    user_email = device.user.email if device.user else 'Unknown'
    
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
    db.session.commit()
    
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
                User.status.ilike(f'%{users_search}%'),
                Device.mac_address.ilike(f'%{users_search}%')
            )
        )
    
    # Apply sorting to users - must be before distinct() to work properly
    # Validate sort column exists on User model
    valid_user_sorts = ['email', 'first_name', 'last_name', 'status', 'begin_date', 'expiry_date', 'created_at', 'phone_number']
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
    devices_pages = (devices_total + devices_per_page - 1) // devices_per_page if devices_per_page > 0 else 0
    
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
        vlan_map=get_vlan_map(),
        auto_approve_vlans=get_auto_approve_vlans(),
        admin_approval_vlans=get_admin_approval_vlans()
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
        status = request.form.get('status')
        begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        notes = request.form.get('notes', '').strip()
        
        if not email or not status:
            flash('Email and status are required', 'error')
            return render_template('admin_add_user.html', vlan_map=get_vlan_map())
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'error')
            return render_template('admin_add_user.html', vlan_map=get_vlan_map())
        
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            status=status,
            begin_date=begin_date,
            expiry_date=expiry_date,
            notes=notes,
            created_by=current_user.username
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
        user.status = request.form.get('status')
        user.begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        user.expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        user.notes = request.form.get('notes', '').strip()
        
        db.session.commit()
        
        # Update all active devices for this user
        vlan_map = get_vlan_map()
        target_vlan = vlan_map.get(user.status, vlan_map['guests'])
        devices = Device.query.filter_by(user_id=user.id, registration_status='active').all()
        
        for device in devices:
            device.current_vlan = target_vlan
            send_coa_change(device.mac_address, target_vlan)
        
        db.session.commit()
        
        flash(f'User {user.email} updated successfully', 'success')
        logger.info(f"Admin updated user: {user.email}")
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_edit_user.html', user=user, vlan_map=get_vlan_map())


@app.route('/admin/approve/<token>')
@login_required
def admin_approve_request(token):
    """Approve registration request from email link"""
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()
    
    if reg_request.status != 'pending':
        flash('This request has already been processed', 'info')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_approve_request.html', request=reg_request, vlan_map=get_vlan_map())


@app.route('/admin/requests/<int:request_id>/process', methods=['POST'])
@login_required
def admin_process_request(request_id):
    """Process (approve/reject) a registration request"""
    reg_request = RegistrationRequest.query.get_or_404(request_id)
    
    action = request.form.get('action')
    
    if action == 'approve':
        status = request.form.get('status')
        begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        
        # Expiry date is optional - None means no expiration
        expiry_date_str = request.form.get('expiry_date', '').strip()
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        
        notes = request.form.get('notes', '').strip()
        
        # Create user
        user = User(
            email=reg_request.email,
            first_name=reg_request.first_name,
            last_name=reg_request.last_name,
            phone_number=reg_request.phone_number,
            status=status,
            begin_date=begin_date,
            expiry_date=expiry_date,
            notes=notes,
            created_by=current_user.username
        )
        db.session.add(user)
        db.session.flush()
        
        # Create device
        vlan_map = get_vlan_map()
        device = Device(
            mac_address=reg_request.mac_address,
            user_id=user.id,
            device_name=reg_request.device_type or 'unknown',
            registration_status='active',
            current_vlan=vlan_map.get(status, vlan_map['guests'])
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
        
        # Send CoA
        send_coa_change(device.mac_address, device.current_vlan)
        
        flash(f'Request approved and user {user.email} created', 'success')
        logger.info(f"Admin approved registration request for {user.email}")
        
    elif action == 'reject':
        reg_request.status = 'rejected'
        reg_request.processed_at = datetime.now()
        reg_request.processed_by = current_user.username
        reg_request.notes = request.form.get('notes', '').strip()
        
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
    """Block a device"""
    device = Device.query.get_or_404(device_id)
    
    vlan_map = get_vlan_map()
    device.registration_status = 'blocked'
    device.current_vlan = vlan_map['restricted']  # Move to restricted VLAN
    db.session.commit()
    
    # Disconnect from network if WiFi
    if device.connection_type == 'wifi':
        kea = get_kea()
        if kea:
            kea.unregister_mac(device.mac_address, device.current_vlan)
    elif device.connection_type == 'wired':
        send_coa_disconnect(device.mac_address)
    
    flash(f'Device {device.mac_address} has been blocked', 'success')
    logger.info(f"Admin blocked device {device.mac_address}")
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/unblock', methods=['POST'])
@login_required
def admin_unblock_device(device_id):
    """Unblock a device"""
    device = Device.query.get_or_404(device_id)
    user = User.query.get(device.user_id)
    
    device.registration_status = 'active'
    
    # Determine target VLAN based on user status
    vlan_map = get_vlan_map()
    if user:
        device.current_vlan = vlan_map.get(user.status, vlan_map['guests'])
    else:
        device.current_vlan = vlan_map['guests']
    
    db.session.commit()
    
    # Re-register in network
    if device.connection_type == 'wifi':
        kea = get_kea()
        if kea:
            kea.register_mac(device.mac_address, device.current_vlan)
    elif device.connection_type == 'wired':
        send_coa_change(device.mac_address, device.current_vlan)
    
    flash(f'Device {device.mac_address} has been unblocked', 'success')
    logger.info(f"Admin unblocked device {device.mac_address}")
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/device/<int:device_id>/delete', methods=['POST'])
@login_required
def admin_delete_device(device_id):
    """Delete a device registration"""
    device = Device.query.get_or_404(device_id)
    mac_address = device.mac_address
    
    # Unregister from network first
    if device.connection_type == 'wifi':
        kea = get_kea()
        if kea:
            kea.unregister_mac(device.mac_address, device.current_vlan)
    elif device.connection_type == 'wired':
        send_coa_disconnect(device.mac_address)
    
    db.session.delete(device)
    db.session.commit()
    
    flash(f'Device {mac_address} has been deleted', 'success')
    logger.info(f"Admin deleted device {mac_address}")
    
    return redirect(url_for('admin_dashboard'))


@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        return jsonify({'status': 'healthy'}), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
