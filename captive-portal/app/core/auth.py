"""
Authentication and authorisation helpers.

Contains:
- AdminUser class (Flask-Login user object)
- load_user() callback
- permission_required() decorator
- enforce_mfa_setup() before_request hook
"""

import logging
from functools import wraps

from flask import redirect, url_for, flash, request
from flask_login import current_user

from extensions import login_manager, db
from models import Admin

logger = logging.getLogger(__name__)

# Endpoints that are exempt from MFA / password-change enforcement
_AUTH_EXEMPT_ENDPOINTS = {
    'admin.manage_admins.login',
    'admin.manage_admins.logout',
    'admin.manage_admins.mfa_setup',
    'admin.manage_admins.mfa_verify',
    'admin.manage_admins.mfa_disable',
    'admin.manage_admins.change_own_password',
    'admin.manage_admins.forgot_password',
    'admin.manage_admins.reset_password',
    'static',
}


class AdminUser:
    """Flask-Login user object for admin accounts."""

    def __init__(
        self,
        admin_id,
        username,
        can_manage_users=True,
        can_manage_vlans=False,
        can_view_traffic=False,
        can_manage_admins=False,
        traffic_viewer_settings=None,
        mfa_enabled=False,
        must_change_password=False,
        can_manage_switch_ports=False,
        can_manage_isp_routers=False,
        can_manage_firmware=False,
        can_manage_pihole=False,
    ):
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

    # ── Flask-Login interface ─────────────────────────────────────────────────

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
        return self.can_manage_admins


def make_admin_user(admin: Admin) -> AdminUser:
    """Build an AdminUser from an Admin ORM row."""
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
        can_manage_pihole=getattr(admin, 'can_manage_pihole', False),
    )


@login_manager.user_loader
def load_user(user_id):
    """Load admin user by ID for Flask-Login."""
    try:
        admin_id = int(user_id)
        admin = Admin.query.get(admin_id)
        if admin:
            return make_admin_user(admin)
    except (ValueError, TypeError):
        pass
    except Exception:
        # DB connection lost — roll back so the pool can recover.
        try:
            db.session.rollback()
        except Exception:
            pass
    return None


def permission_required(permission):
    """Decorator: check that the current admin has a specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('admin.manage_admins.login'))

            _perm_map = {
                'manage_users':        (current_user.can_manage_users,        'manage users and devices'),
                'manage_vlans':        (current_user.can_manage_vlans,        'manage VLANs'),
                'view_traffic':        (current_user.can_view_traffic,        'view traffic'),
                'manage_admins':       (current_user.can_manage_admins,       'manage admins'),
                'manage_switch_ports': (current_user.can_manage_switch_ports, 'manage switch ports'),
                'manage_isp_routers':  (current_user.can_manage_isp_routers,  'manage ISP routers'),
                'manage_firmware':     (current_user.can_manage_firmware,     'manage firmware'),
                'manage_pihole':       (current_user.can_manage_pihole,       'manage Pi-Hole DNS'),
                'manage_devices':      (current_user.can_manage_users,        'manage devices'),
            }

            allowed, label = _perm_map.get(permission, (False, permission))
            if not allowed:
                flash(f'You do not have permission to {label}.', 'error')
                return redirect(url_for('admin.dashboard.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def enforce_mfa_setup():
    """
    before_request hook: redirect authenticated admins to MFA setup or
    forced password change when required.
    Register this with app.before_request in create_app().
    """
    endpoint = request.endpoint
    if not endpoint or not endpoint.startswith('admin.'):
        return
    if endpoint in _AUTH_EXEMPT_ENDPOINTS:
        return
    if not current_user or not current_user.is_authenticated:
        return
    if getattr(current_user, 'must_change_password', False):
        return redirect(url_for('admin.manage_admins.change_own_password'))
    if not getattr(current_user, 'mfa_enabled', False):
        return redirect(url_for('admin.manage_admins.mfa_setup'))
