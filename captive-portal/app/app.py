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
from email_service import send_verification_email, send_admin_notification

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

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# VLAN configuration
VLAN_MAP = {
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
    """Extract MAC address from request - may need adjustment based on your setup"""
    # Try common headers set by captive portal redirects
    mac = request.headers.get('X-Client-MAC')
    if not mac:
        mac = request.args.get('mac')
    if not mac:
        mac = request.form.get('mac')
    
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


@app.route('/')
def index():
    """Landing page - redirect to registration"""
    return redirect(url_for('register'))


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
        
        if not email or not first_name or not last_name:
            flash('Please fill in all required fields', 'error')
            return render_template('register.html')
        
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
            device.ip_address = ip_address
            device.last_seen = datetime.now()
            
            # Check if email verification is required
            email_verification_required = Setting.get_value('email_verification_required', 'false') == 'true'
            
            if email_verification_required:
                # Generate verification token
                device.verification_token = secrets.token_urlsafe(32)
                timeout_minutes = int(Setting.get_value('verification_timeout_minutes', '15'))
                device.verification_expires_at = datetime.now() + timedelta(minutes=timeout_minutes)
                device.registration_status = 'pending'
                device.current_vlan = VLAN_MAP['unregistered']
                
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
                target_vlan = VLAN_MAP.get(user.status, VLAN_MAP['guests'])
                device.current_vlan = target_vlan
                
                if not existing_device:
                    db.session.add(device)
                db.session.commit()
                
                # Send RADIUS CoA to move device to correct VLAN
                success = send_coa_change(mac_address, target_vlan)
                
                if success:
                    flash(f'Registration successful! You now have {user.status} access.', 'success')
                    logger.info(f"Device {mac_address} registered for user {email} on VLAN {target_vlan}")
                else:
                    flash('Registration saved, but there was an issue updating your network access. Please contact support.', 'warning')
                
            db.session.commit()
            return redirect(url_for('status'))
            
        else:
            # Scenario 2: User not pre-authorized - create registration request
            reg_request = RegistrationRequest(
                mac_address=mac_address,
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
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
    
    return render_template('register.html')


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
        device.registration_status = 'restricted'
        device.current_vlan = VLAN_MAP['restricted']
        db.session.commit()
        
        send_coa_change(device.mac_address, VLAN_MAP['restricted'])
        
        flash('Verification link has expired. Your device has been placed on a restricted network. Please contact the administrator.', 'error')
        return redirect(url_for('status'))
    
    # Verification successful
    user = device.user
    if user:
        target_vlan = VLAN_MAP.get(user.status, VLAN_MAP['guests'])
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


@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    users = User.query.order_by(User.email).all()
    devices = Device.query.order_by(Device.registered_at.desc()).limit(50).all()
    pending_requests = RegistrationRequest.query.filter_by(status='pending').order_by(RegistrationRequest.submitted_at.desc()).all()
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         devices=devices, 
                         pending_requests=pending_requests,
                         vlan_map=VLAN_MAP)


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
        expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date()
        notes = request.form.get('notes', '').strip()
        
        if not email or not status:
            flash('Email and status are required', 'error')
            return render_template('admin_add_user.html', vlan_map=VLAN_MAP)
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'error')
            return render_template('admin_add_user.html', vlan_map=VLAN_MAP)
        
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
    
    return render_template('admin_add_user.html', vlan_map=VLAN_MAP)


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
        user.expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date()
        user.notes = request.form.get('notes', '').strip()
        
        db.session.commit()
        
        # Update all active devices for this user
        target_vlan = VLAN_MAP.get(user.status, VLAN_MAP['guests'])
        devices = Device.query.filter_by(user_id=user.id, registration_status='active').all()
        
        for device in devices:
            device.current_vlan = target_vlan
            send_coa_change(device.mac_address, target_vlan)
        
        db.session.commit()
        
        flash(f'User {user.email} updated successfully', 'success')
        logger.info(f"Admin updated user: {user.email}")
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_edit_user.html', user=user, vlan_map=VLAN_MAP)


@app.route('/admin/approve/<token>')
@login_required
def admin_approve_request(token):
    """Approve registration request from email link"""
    reg_request = RegistrationRequest.query.filter_by(approval_token=token).first_or_404()
    
    if reg_request.status != 'pending':
        flash('This request has already been processed', 'info')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_approve_request.html', request=reg_request, vlan_map=VLAN_MAP)


@app.route('/admin/requests/<int:request_id>/process', methods=['POST'])
@login_required
def admin_process_request(request_id):
    """Process (approve/reject) a registration request"""
    reg_request = RegistrationRequest.query.get_or_404(request_id)
    
    action = request.form.get('action')
    
    if action == 'approve':
        status = request.form.get('status')
        begin_date = datetime.strptime(request.form.get('begin_date'), '%Y-%m-%d').date()
        expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date()
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
        device = Device(
            mac_address=reg_request.mac_address,
            user_id=user.id,
            registration_status='active',
            current_vlan=VLAN_MAP.get(status, VLAN_MAP['guests'])
        )
        db.session.add(device)
        
        # Update request
        reg_request.status = 'approved'
        reg_request.processed_at = datetime.now()
        reg_request.processed_by = current_user.username
        
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
        device.registration_status = 'disconnected'
        device.current_vlan = VLAN_MAP['unregistered']
        db.session.commit()
        flash(f'Device {device.mac_address} disconnected', 'success')
    else:
        flash('Failed to disconnect device', 'error')
    
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
