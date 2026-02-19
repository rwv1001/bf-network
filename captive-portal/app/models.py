"""
Database models for Captive Portal
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Admin(db.Model):
    """Admin users with role-based permissions"""
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    can_manage_users = db.Column(db.Boolean, default=True, nullable=False)
    can_manage_vlans = db.Column(db.Boolean, default=False, nullable=False)
    can_view_traffic = db.Column(db.Boolean, default=False, nullable=False)
    can_manage_admins = db.Column(db.Boolean, default=False, nullable=False)  # Super admin flag
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)
    last_login = db.Column(db.DateTime)
    traffic_viewer_settings = db.Column(db.Text, nullable=True)  # JSON string for saved filters/columns
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)  # TOTP secret (base32 encoded)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_super_admin(self):
        """Super admin = can manage admins"""
        return self.can_manage_admins
    
    def __repr__(self):
        return f'<Admin {self.username}>'


class User(db.Model):
    """Authorized users with network access"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    allowed_vlans = db.Column(db.Text)  # Comma-separated VLAN IDs allowed without approval
    adoptable_vlans = db.Column(db.Text)  # Comma-separated VLAN IDs user can adopt
    allowed_vlans_override = db.Column(db.Text)  # Explicitly allowed VLAN IDs
    allowed_vlans_deny = db.Column(db.Text)  # Explicitly denied VLAN IDs
    adoptable_vlans_override = db.Column(db.Text)  # Explicitly adoptable VLAN IDs
    adoptable_vlans_deny = db.Column(db.Text)  # Explicitly denied adoptable VLAN IDs
    require_approval_every_device = db.Column(db.Boolean, default=False, nullable=False)
    begin_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)  # NULL means no expiration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='admin')
    notes = db.Column(db.Text)
    blocked = db.Column(db.Boolean, default=False, nullable=False, index=True)
    
    # Relationships
    devices = db.relationship('Device', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def is_active(self):
        today = datetime.now().date()
        # No expiry date means permanent access
        if self.expiry_date is None:
            return self.begin_date <= today
        return self.begin_date <= today <= self.expiry_date


class Device(db.Model):
    """Registered network devices"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    device_name = db.Column(db.String(100))
    current_vlan = db.Column(db.Integer)
    registration_status = db.Column(db.String(50), default='pending', index=True)
    verification_token = db.Column(db.String(255))
    verification_expires_at = db.Column(db.DateTime)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # For pool assignment
    last_seen = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))
    
    # WiFi-specific fields
    connection_type = db.Column(db.String(10), default='unknown')  # 'wifi' or 'wired'
    ssid = db.Column(db.String(100))  # WiFi SSID (e.g., 'Blackfriars-Guests')
    is_wired = db.Column(db.Boolean, default=False, nullable=False)
    wired_target_vlan = db.Column(db.Integer)
    unregister_token = db.Column(db.String(255), unique=True, index=True)  # For email unregister link
    confirmation_token = db.Column(db.String(255), unique=True, index=True)
    confirmation_deadline = db.Column(db.DateTime)
    confirmation_confirmed_at = db.Column(db.DateTime)
    profile_snapshot = db.Column(db.Text)  # JSON: previous/new user profile details
    switch_iface = db.Column(db.String(100), nullable=True)  # Switch port, e.g. GigabitEthernet1/0/5
    switch_iface_seen_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f'<Device {self.mac_address}>'
    
    def get_pool_assignment(self):
        """
        Determine which DHCP pool this device should be in.
        
        Returns:
            str: 'registered', 'newly_unregistered', or 'old_unregistered'
        """
        if self.registration_status == 'registered':
            return 'registered'
        
        # Check how long ago device was first seen
        if self.first_seen:
            time_since_first_seen = datetime.utcnow() - self.first_seen
            if time_since_first_seen < timedelta(minutes=30):
                return 'newly_unregistered'
        
        return 'old_unregistered'


class RegistrationRequest(db.Model):
    """Pending registration requests from unknown users"""
    __tablename__ = 'registration_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    device_type = db.Column(db.String(50))  # laptop, phone, tablet, etc.
    ip_address = db.Column(db.String(45))
    requested_vlan = db.Column(db.Integer)
    user_agent = db.Column(db.Text)
    status = db.Column(db.String(50), default='pending')
    approval_token = db.Column(db.String(255))
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    processed_by = db.Column(db.String(100))
    notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<RegistrationRequest {self.email}>'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()


class VlanMapping(db.Model):
    """VLAN mappings for different user statuses"""
    __tablename__ = 'vlan_mappings'
    
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), unique=True, nullable=False)
    vlan_id = db.Column(db.Integer, nullable=False)
    display_name = db.Column(db.String(100))
    ssid = db.Column(db.String(100))
    wired_enabled = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.Text)
    
    def __repr__(self):
        return f'<VlanMapping {self.status} -> VLAN {self.vlan_id}>'


class DomainPolicy(db.Model):
    """Domain-based VLAN allowances and adoption rules."""
    __tablename__ = 'domain_policies'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    allowed_vlans = db.Column(db.Text)
    adoptable_vlans = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<DomainPolicy {self.domain}>'


class Setting(db.Model):
    """Application settings"""
    __tablename__ = 'settings'
    
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Setting {self.key}={self.value}>'
    
    @staticmethod
    def get_value(key, default=None):
        """Get setting value with fallback to default"""
        setting = Setting.query.get(key)
        return setting.value if setting else default
    
    @staticmethod
    def set_value(key, value):
        """Set or update setting value"""
        setting = Setting.query.get(key)
        if setting:
            setting.value = value
        else:
            setting = Setting(key=key, value=value)
            db.session.add(setting)
        db.session.commit()


class UnregisteredLease(db.Model):
    """Track unregistered devices with temporary lease/IP mappings."""
    __tablename__ = 'unregistered_leases'

    mac_address = db.Column(db.String(17), primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<UnregisteredLease {self.mac_address} {self.ip_address}>'
