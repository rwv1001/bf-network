"""
Database models for Captive Portal
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

db = SQLAlchemy()


class User(db.Model):
    """Authorized users with network access"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    status = db.Column(db.String(50), nullable=False)  # friars, staff, students, etc.
    begin_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='admin')
    notes = db.Column(db.Text)
    
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
    unregister_token = db.Column(db.String(255), unique=True, index=True)  # For email unregister link
    
    def __repr__(self):
        return f'<Device {self.mac_address}>'
    
    def get_pool_assignment(self):
        """
        Determine which DHCP pool this device should be in.
        
        Returns:
            str: 'registered', 'newly_unregistered', or 'old_unregistered'
        """
        if self.registration_status == 'approved':
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
    ip_address = db.Column(db.String(45))
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
    description = db.Column(db.Text)
    
    def __repr__(self):
        return f'<VlanMapping {self.status} -> VLAN {self.vlan_id}>'


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
