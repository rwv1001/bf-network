"""
Database models for Captive Portal
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os

db = SQLAlchemy()


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


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
    can_manage_switch_ports = db.Column(db.Boolean, default=False, nullable=False)
    can_manage_isp_routers = db.Column(db.Boolean, default=False, nullable=False)
    can_manage_firmware = db.Column(db.Boolean, default=False, nullable=False)
    can_manage_pihole = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)
    last_login = db.Column(db.DateTime)
    traffic_viewer_settings = db.Column(db.Text, nullable=True)  # JSON string for saved filters/columns
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)  # TOTP secret (base32 encoded)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    password_reset_token = db.Column(db.String(255), nullable=True, index=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
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
    network_password_hash = db.Column(db.String(255), nullable=True)  # bcrypt hash of user's network password
    network_password_set_token = db.Column(db.String(255), nullable=True, index=True)  # token for user to set their own network password
    network_password_set_token_expires = db.Column(db.DateTime, nullable=True)
    # How future correct-password registrations are handled:
    #   None / 'always'    → auto-approve on correct password
    #   'admin_required'   → correct password still needs admin approval in portal
    network_password_approval_mode = db.Column(db.String(20), nullable=True)
    begin_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)  # NULL means no expiration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='admin')
    notes = db.Column(db.Text)
    blocked = db.Column(db.Boolean, default=False, nullable=False, index=True)
    
    def __repr__(self):
        return f'<User {self.email}>'

    @property
    def devices(self):
        """Spec Table 9: Device records currently owned by this user (active device_ownership)."""
        owned_macs = [
            o.mac_address for o in
            DeviceOwnership.query.filter_by(user_id=self.id, end_datetime=None).all()
        ]
        if not owned_macs:
            return []
        return Device.query.filter(Device.mac_address.in_(owned_macs)).all()
    
    def set_network_password(self, password):
        """Hash and store the user's network (portal) password."""
        self.network_password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_network_password(self, password):
        """Verify the user's network (portal) password."""
        if not self.network_password_hash:
            return False
        return check_password_hash(self.network_password_hash, password)

    @property
    def has_network_password(self):
        return bool(self.network_password_hash)

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
    device_name = db.Column(db.String(100))
    current_vlan = db.Column(db.Integer)
    registration_status = db.Column(db.String(50), default='pending', index=True)
    verification_token = db.Column(db.String(255))
    verification_expires_at = db.Column(db.DateTime)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # For pool assignment
    last_seen = db.Column(db.DateTime)

    # Spec Table 6 fields: orthogonal internet access state
    internet_accessible = db.Column(db.Boolean, nullable=True)   # True/False/None
    internet_blocked = db.Column(db.Boolean, nullable=True)      # True means admin-blocked
    assigned_vlan = db.Column(db.Integer, nullable=True)         # VLAN admin/auto-approved
    ownership_validated = db.Column(db.Boolean, nullable=True)   # Password confirmed by user
    
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
    fixed_ip = db.Column(db.String(45), nullable=True)  # Admin-assigned fixed IP reservation

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

    @property
    def user_id(self):
        """Spec Table 6: no user_id column — current owner is resolved via Table 9 (device_ownership)."""
        o = DeviceOwnership.query.filter_by(mac_address=self.mac_address, end_datetime=None).first()
        return o.user_id if o else None

    @property
    def user(self):
        """Current owner (User) resolved via Table 9 (device_ownership)."""
        uid = self.user_id
        return User.query.get(uid) if uid else None

    @property
    def ip_address(self):
        """Spec Table 7: IP is tracked in ip_leases. Returns current active lease IP."""
        lease = IPLease.query.filter(
            IPLease.mac_address == self.mac_address,
            IPLease.lease_expiry > datetime.utcnow(),
        ).order_by(IPLease.lease_start.desc()).first()
        return lease.ip_address if lease else None


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


class ISPRouter(db.Model):
    """ISP routers — one row per upstream gateway (e.g. UDM, Teltonika)."""
    __tablename__ = 'isp_routers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)   # e.g. "UDM"
    subnet = db.Column(db.String(50), nullable=False)               # e.g. "192.168.1.0/24"
    vlan_id = db.Column(db.Integer, nullable=False)                 # uplink VLAN
    switch_port = db.Column(db.String(100), nullable=True)          # e.g. "GigabitEthernet1/0/24"
    switch_host = db.Column(db.String(50), nullable=True)           # e.g. "192.168.99.2" — which HP5130 this router is on
    dhcp_snooping_trust = db.Column(db.Boolean, default=True, nullable=False)
    nat_logger_type = db.Column(db.String(20), nullable=False, default='none')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # VLANs routed via this ISP
    vlan_mappings = db.relationship('VlanMapping', backref='isp_router', lazy=True,
                                    foreign_keys='VlanMapping.isp_router_id')

    @property
    def pbr_name(self):
        """PBR route-map name, e.g. PBR-UDM"""
        return f"PBR-{self.name.upper().replace(' ', '_')}"

    @property
    def gateway_ip(self):
        """LAN IP of the router: <NETWORK_WORD>.<vlan_id>.1"""
        return f"{_net_word()}.{self.vlan_id}.1"

    def switch_host_ip(self, switch_host):
        """Per-switch VLAN interface IP based on the last octet of switch_host."""
        last_octet = switch_host.split('.')[-1]
        return f"{_net_word()}.{self.vlan_id}.{last_octet}"

    def __repr__(self):
        return f'<ISPRouter {self.name} vlan={self.vlan_id}>'


class VlanMapping(db.Model):
    """VLAN mappings for different user statuses"""
    __tablename__ = 'vlan_mappings'
    
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), unique=True, nullable=False)
    vlan_id = db.Column(db.Integer, nullable=False)
    display_name = db.Column(db.String(100))
    ssid = db.Column(db.String(100))
    wired_enabled = db.Column(db.Boolean, default=False, nullable=False)
    require_password = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.Text)
    isp_router_id = db.Column(db.Integer, db.ForeignKey('isp_routers.id',
                              ondelete='SET NULL'), nullable=True)
    # Comma-separated list of VLAN IDs this VLAN is allowed to reach at IP layer.
    # NULL / empty string = unrestricted (all inter-VLAN traffic permitted).
    visible_vlans = db.Column(db.Text, nullable=True)

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


class DeviceOwnership(db.Model):
    """Spec Table 9 — historical record of which user owns which MAC address.

    An active ownership is a row where end_datetime IS NULL.  When a device is
    reassigned or unregistered, end_datetime is set to the current time and a
    new row (or no row) is created as appropriate.
    """
    __tablename__ = 'device_ownership'

    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    start_datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_datetime = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref=db.backref('ownerships', lazy=True))

    def __repr__(self):
        return f'<DeviceOwnership mac={self.mac_address} user={self.user_id} active={self.end_datetime is None}>'


class IPLease(db.Model):
    """Spec Table 7 — IP address lease tracking with blocked-pool and DNS-hijack state.

    One row per (mac_address, ip_address) pair.  Multiple rows may exist for the
    same MAC if the device has held different IPs over time; the most recent
    non-expired row represents the current lease.
    """
    __tablename__ = 'ip_leases'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    vlan_id = db.Column(db.Integer, nullable=True)
    mac_address = db.Column(db.String(17), nullable=True, index=True)
    lease_start = db.Column(db.DateTime, nullable=False)
    lease_expiry = db.Column(db.DateTime, nullable=False, index=True)
    from_blocked_pool = db.Column(db.Boolean, nullable=False, default=False)
    dns_hijacked = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<IPLease {self.ip_address} mac={self.mac_address} blocked={self.from_blocked_pool}>'


class CentralOutboundEvent(db.Model):
    """Events queued for delivery to the central sync server.

    Items with status='pending' are picked up by central_client's outbound
    worker thread and sent to central's POST /api/v1/event endpoint.
    Retried on failure; status becomes 'sent' once central acknowledges.
    """
    __tablename__ = 'central_outbound_events'

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.JSON, nullable=False)
    status = db.Column(db.String(32), default='pending', nullable=False, index=True)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_attempt_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<CentralOutboundEvent {self.event_type} status={self.status}>'
