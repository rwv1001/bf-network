"""
Admin — Manage Admins + Auth (spec section 12 / CODEBASE section 13).

Routes:
  GET/POST /admin/login
  GET      /admin/logout
  GET/POST /admin/forgot-password
  GET/POST /admin/reset-password/<token>
  GET/POST /admin/change-password          (forced change on first login)
  GET/POST /admin/mfa/setup
  GET/POST /admin/mfa/verify
  POST     /admin/mfa/disable
  GET      /admin/no-permissions
  GET      /admin/manage-admins
  POST     /admin/manage-admins/create
  POST     /admin/manage-admins/<id>/update
  POST     /admin/manage-admins/<id>/delete
  POST     /admin/manage-admins/<id>/change-password
  POST     /admin/manage-admins/<id>/update-email
  POST     /admin/manage-admins/<id>/reset-mfa
"""

import logging
import os
import secrets
from datetime import datetime, timedelta

from flask import (
    Blueprint, flash, redirect, render_template, request, session, url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from extensions import db, login_manager
from models import Admin
from core.auth import AdminUser, make_admin_user, permission_required
from email_service import send_admin_password_reset_email
from security import limiter

logger = logging.getLogger(__name__)

manage_admins_bp = Blueprint('manage_admins', __name__)

# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user and current_user.is_authenticated:
        return redirect(url_for('admin.dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        logger.info(f"[LOGIN] Attempt for username: {username}")

        admin = Admin.query.filter_by(username=username).first()

        logger.info(f"[LOGIN] Admin found in DB: {admin is not None}")
        if admin:
            logger.info(f"[LOGIN] admin.mfa_enabled = {admin.mfa_enabled}, has_mfa_secret = {bool(admin.mfa_secret)}")

        if admin and admin.check_password(password):
            logger.info("[LOGIN] Password correct")

            if admin.mfa_enabled and admin.mfa_secret:
                logger.info("[LOGIN] → Taking MFA path")
                session['mfa_admin_id'] = admin.id
                session.permanent = True
                session.modified = True
                logger.info(f"[LOGIN] Redirecting to mfa_verify. Session keys: {list(session.keys())}")
                return redirect(url_for('admin.manage_admins.mfa_verify'))

            # Normal login (no MFA)
            logger.info("[LOGIN] → Normal login (no MFA)")
            admin.last_login = datetime.utcnow()
            db.session.commit()
            login_user(make_admin_user(admin))
            return redirect(url_for('admin.dashboard.index'))

        else:
            logger.info("[LOGIN] Password incorrect or admin not found")
            flash('Invalid credentials', 'error')
            return render_template('admin_login.html')

        # Legacy env-var fallback
        from werkzeug.security import check_password_hash, generate_password_hash
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_password_hash = os.getenv(
            'ADMIN_PASSWORD_HASH',
            generate_password_hash('admin123'),
        )
        if username == admin_username and check_password_hash(admin_password_hash, password):
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
                logger.info("Migrated legacy admin '%s' to database", username)
            login_user(make_admin_user(admin))
            return redirect(url_for('admin.dashboard.index'))

        flash('Invalid credentials', 'error')

    return render_template('admin_login.html')


@manage_admins_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin.manage_admins.login'))


# ---------------------------------------------------------------------------
# Forgot / reset password
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
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
                reset_url = url_for(
                    'admin.manage_admins.reset_password', token=token, _external=True
                )
                try:
                    send_admin_password_reset_email(admin.email, admin.username, reset_url)
                    logger.info("Password reset email sent to admin '%s'", admin.username)
                except Exception as exc:
                    logger.error(
                        "Failed to send password reset email to admin '%s': %s",
                        admin.username, exc,
                    )
        flash(
            'If that email address is registered, you will receive a password reset link shortly.',
            'info',
        )
        return redirect(url_for('admin.manage_admins.forgot_password'))
    return render_template('admin.manage_admins.forgot_password.html')


@manage_admins_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    admin = Admin.query.filter_by(password_reset_token=token).first()
    if (
        not admin
        or not admin.password_reset_expires
        or admin.password_reset_expires < datetime.utcnow()
    ):
        flash('This password reset link is invalid or has expired.', 'error')
        return redirect(url_for('admin.manage_admins.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm  = request.form.get('confirm_password', '').strip()
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
        logger.info("Admin '%s' reset their password via email link", admin.username)
        flash('Password reset successfully. You can now log in.', 'success')
        return redirect(url_for('admin.manage_admins.login'))

    return render_template('admin_reset_password.html', token=token)


# ---------------------------------------------------------------------------
# Forced password change (first login)
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_own_password():
    admin = Admin.query.get(int(current_user.id))

    if request.method == 'POST':
        new_password     = request.form.get('new_password', '').strip()
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
        logger.info("Admin '%s' changed their password on first login", admin.username)
        flash('Password changed successfully. Welcome!', 'success')
        return redirect(url_for('admin.manage_admins.mfa_setup'))

    return render_template('admin_change_own_password.html')


# ---------------------------------------------------------------------------
# MFA setup / verify / disable
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    import pyotp
    import qrcode
    import io
    import base64

    admin = Admin.query.get(int(current_user.id))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'enable':
            secret = pyotp.random_base32()
            session['mfa_setup_secret'] = secret
            session['mfa_setup_admin_id'] = admin.id
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=admin.username, issuer_name='BF-Network Admin Portal'
            )
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer)
            buffer.seek(0)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            return render_template(
                'admin_mfa_setup.html',
                admin=admin,
                mfa_enabled=admin.mfa_enabled,
                setup_mode='verify',
                show_qr=True,
                secret=secret,
                qr_code=qr_code_base64,
            )

        elif action == 'add_device':
            if not admin.mfa_secret:
                flash('MFA is not fully configured. Please set up MFA first.', 'error')
                return redirect(url_for('admin.manage_admins.mfa_setup'))
            secret = admin.mfa_secret
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=admin.username, issuer_name='BF-Network Admin Portal'
            )
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer)
            buffer.seek(0)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            return render_template(
                'admin_mfa_setup.html',
                admin=admin,
                mfa_enabled=True,
                show_qr=True,
                secret=secret,
                qr_code=qr_code_base64,
            )

        elif action == 'verify':
            code   = request.form.get('code', '').strip().replace(' ', '')
            secret = session.get('mfa_setup_secret')
            setup_admin_id = session.get('mfa_setup_admin_id')

            if not secret or setup_admin_id != admin.id:
                flash('Setup session expired. Please try again.', 'error')
                session.pop('mfa_setup_secret', None)
                session.pop('mfa_setup_admin_id', None)
                return redirect(url_for('admin.manage_admins.mfa_setup'))

            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):                
                admin.mfa_enabled = True
                admin.mfa_secret  = secret
                db.session.commit()
                session.pop('mfa_setup_secret', None)
                session.pop('mfa_setup_admin_id', None)
                current_user.mfa_enabled = True
                logger.info("Admin '%s' enabled MFA", admin.username)
                
                session.modified = True
                flash(
                    'MFA has been enabled successfully! '
                    'You will need to use your authenticator app for future logins.',
                    'success',
                )
                return redirect(url_for('admin.manage_admins.mfa_setup'))
            else:
                flash('Invalid verification code. Please try again.', 'error')
                # Re-generate QR for retry
                totp2 = pyotp.TOTP(secret)
                provisioning_uri = totp2.provisioning_uri(
                    name=admin.username, issuer_name='BF-Network Admin Portal'
                )
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer)
                buffer.seek(0)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                return render_template(
                    'admin_mfa_setup.html',
                    admin=admin,
                    mfa_enabled=admin.mfa_enabled,
                    setup_mode='verify',
                    show_qr=True,
                    secret=secret,
                    qr_code=qr_code_base64,
                )

    return render_template(
        'admin_mfa_setup.html',
        admin=admin,
        mfa_enabled=admin.mfa_enabled,
        show_qr=False,
        setup_mode='status',
    )


@manage_admins_bp.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    import pyotp

    logger.info("[MFA_VERIFY] Page reached")
    logger.info(f"[MFA_VERIFY] Session keys: {list(session.keys())}")
    logger.info(f"[MFA_VERIFY] mfa_admin_id present: {'mfa_admin_id' in session}")

    if 'mfa_admin_id' not in session:
        logger.warning("[MFA_VERIFY] No mfa_admin_id in session — redirecting to login")
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('admin.manage_admins.login'))

    admin_id = session.get('mfa_admin_id')
    admin = Admin.query.get(admin_id)

    if not admin or not admin.mfa_enabled or not admin.mfa_secret:
        session.pop('mfa_admin_id', None)
        flash('MFA not configured for this account.', 'error')
        return redirect(url_for('admin.manage_admins.login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip().replace(' ', '')
        if not code:
            flash('Please enter the verification code.', 'error')
            return render_template('admin_mfa_verify.html')

        totp = pyotp.TOTP(admin.mfa_secret)
        if totp.verify(code, valid_window=1):
            session.pop('mfa_admin_id', None)
            admin.last_login = datetime.utcnow()
            db.session.commit()
            login_user(make_admin_user(admin))
            logger.info("Admin '%s' logged in with MFA", admin.username)
            return redirect(url_for('admin.dashboard.index'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return render_template('admin_mfa_verify.html')

    return render_template('admin_mfa_verify.html')


@manage_admins_bp.route('/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    import pyotp

    admin = Admin.query.get(int(current_user.id))
    if not admin.mfa_enabled:
        flash('MFA is not enabled for your account.', 'info')
        return redirect(url_for('admin.manage_admins.mfa_setup'))

    code_or_password = request.form.get('code', '').strip()
    if not code_or_password:
        flash('Please enter your current MFA code or password.', 'error')
        return redirect(url_for('admin.manage_admins.mfa_setup'))

    if admin.mfa_secret:
        totp = pyotp.TOTP(admin.mfa_secret)
        if totp.verify(code_or_password, valid_window=1):
            admin.mfa_enabled = False
            admin.mfa_secret  = None
            db.session.commit()
            current_user.mfa_enabled = False
            logger.info("Admin '%s' disabled MFA", admin.username)
            flash('MFA has been disabled.', 'success')
            return redirect(url_for('admin.manage_admins.mfa_setup'))

    if admin.check_password(code_or_password):
        admin.mfa_enabled = False
        admin.mfa_secret  = None
        db.session.commit()
        current_user.mfa_enabled = False
        logger.info("Admin '%s' disabled MFA using password", admin.username)
        flash('MFA has been disabled.', 'success')
        return redirect(url_for('admin.manage_admins.mfa_setup'))

    flash('Invalid code or password.', 'error')
    return redirect(url_for('admin.manage_admins.mfa_setup'))


# ---------------------------------------------------------------------------
# No-permissions page
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/no-permissions')
@login_required
def no_permissions():
    super_admin = Admin.query.filter(
        Admin.can_manage_admins == True,
        Admin.email != None,
        Admin.email != '',
    ).order_by(Admin.id.asc()).first()
    return render_template(
        'admin_no_permissions.html',
        contact_email=super_admin.email if super_admin else None,
        contact_name=super_admin.username if super_admin else None,
    )


# ---------------------------------------------------------------------------
# Manage admins list
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins')
@login_required
@permission_required('manage_admins')
def manage_admins():
    all_admins = Admin.query.order_by(Admin.username.asc()).all()
    super_admin_count = sum(1 for a in all_admins if a.is_super_admin)
    admin_list = []
    for admin in all_admins:
        is_current    = (str(admin.id) == current_user.id)
        is_only_super = is_current and admin.is_super_admin and super_admin_count == 1
        admin_list.append({
            'id':                    admin.id,
            'username':              admin.username,
            'email':                 admin.email,
            'can_manage_users':      admin.can_manage_users,
            'can_manage_vlans':      admin.can_manage_vlans,
            'can_view_traffic':      admin.can_view_traffic,
            'can_manage_admins':     admin.can_manage_admins,
            'can_manage_switch_ports': admin.can_manage_switch_ports,
            'can_manage_isp_routers':  getattr(admin, 'can_manage_isp_routers', False),
            'can_manage_firmware':     getattr(admin, 'can_manage_firmware', False),
            'can_manage_pihole':       getattr(admin, 'can_manage_pihole', False),
            'created_at':            admin.created_at,
            'last_login':            admin.last_login,
            'is_current':            is_current,
            'is_only_super':         is_only_super,
            'mfa_enabled':           admin.mfa_enabled,
        })
    return render_template('admin_manage_admins.html', admins=admin_list)


# ---------------------------------------------------------------------------
# Create admin
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins/create', methods=['POST'])
@login_required
@permission_required('manage_admins')
def create_admin():
    username              = request.form.get('username', '').strip()
    email                 = request.form.get('email', '').strip().lower()
    password              = request.form.get('password', '').strip()
    can_manage_users      = bool(request.form.get('can_manage_users'))
    can_manage_vlans      = bool(request.form.get('can_manage_vlans'))
    can_view_traffic      = bool(request.form.get('can_view_traffic'))
    can_manage_admins     = bool(request.form.get('can_manage_admins'))
    can_manage_switch_ports = bool(request.form.get('can_manage_switch_ports'))
    can_manage_isp_routers  = bool(request.form.get('can_manage_isp_routers'))
    can_manage_firmware     = bool(request.form.get('can_manage_firmware'))
    can_manage_pihole       = bool(request.form.get('can_manage_pihole'))
    must_change_password    = bool(request.form.get('must_change_password'))

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('admin.manage_admins.manage_admins'))
    if len(password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('admin.manage_admins.manage_admins'))
    if Admin.query.filter_by(username=username).first():
        flash(f'Username "{username}" already exists.', 'error')
        return redirect(url_for('admin.manage_admins.manage_admins'))

    admin = Admin(username=username, email=email if email else None)
    admin.set_password(password)
    admin.can_manage_users       = can_manage_users
    admin.can_manage_vlans       = can_manage_vlans
    admin.can_view_traffic       = can_view_traffic
    admin.can_manage_admins      = can_manage_admins
    admin.can_manage_switch_ports = can_manage_switch_ports
    admin.can_manage_isp_routers  = can_manage_isp_routers
    admin.can_manage_firmware     = can_manage_firmware
    admin.can_manage_pihole       = can_manage_pihole
    admin.must_change_password    = must_change_password
    admin.created_by = int(current_user.id)
    db.session.add(admin)
    db.session.commit()
    logger.info("Admin '%s' created by %s", username, current_user.username)
    flash(f'Admin "{username}" created successfully.', 'success')
    return redirect(url_for('admin.manage_admins.manage_admins'))


# ---------------------------------------------------------------------------
# Update admin permissions
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins/<int:admin_id>/update', methods=['POST'])
@login_required
@permission_required('manage_admins')
def update_admin_permissions(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    can_manage_admins = bool(request.form.get('can_manage_admins'))

    if admin.can_manage_admins and not can_manage_admins:
        super_admin_count = Admin.query.filter_by(can_manage_admins=True).count()
        if super_admin_count <= 1:
            flash(
                'Cannot remove the last super admin. '
                'There must always be at least one super admin.',
                'error',
            )
            return redirect(url_for('admin.manage_admins.manage_admins'))

    admin.can_manage_users        = bool(request.form.get('can_manage_users'))
    admin.can_manage_vlans        = bool(request.form.get('can_manage_vlans'))
    admin.can_view_traffic        = bool(request.form.get('can_view_traffic'))
    admin.can_manage_admins       = can_manage_admins
    admin.can_manage_switch_ports = bool(request.form.get('can_manage_switch_ports'))
    admin.can_manage_isp_routers  = bool(request.form.get('can_manage_isp_routers'))
    admin.can_manage_firmware     = bool(request.form.get('can_manage_firmware'))
    admin.can_manage_pihole       = bool(request.form.get('can_manage_pihole'))
    db.session.commit()
    logger.info("Admin '%s' permissions updated by %s", admin.username, current_user.username)
    flash(f'Permissions updated for "{admin.username}".', 'success')
    return redirect(url_for('admin.manage_admins.manage_admins'))


# ---------------------------------------------------------------------------
# Delete admin
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins/<int:admin_id>/delete', methods=['POST'])
@login_required
@permission_required('manage_admins')
def delete_admin(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    if str(admin.id) == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin.manage_admins.manage_admins'))
    if admin.can_manage_admins:
        super_admin_count = Admin.query.filter_by(can_manage_admins=True).count()
        if super_admin_count <= 1:
            flash(
                'Cannot delete the last super admin. '
                'There must always be at least one super admin.',
                'error',
            )
            return redirect(url_for('admin.manage_admins.manage_admins'))
    username = admin.username
    db.session.delete(admin)
    db.session.commit()
    logger.info("Admin '%s' deleted by %s", username, current_user.username)
    flash(f'Admin "{username}" deleted successfully.', 'success')
    return redirect(url_for('admin.manage_admins.manage_admins'))


# ---------------------------------------------------------------------------
# Change admin password
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins/<int:admin_id>/change-password', methods=['POST'])
@login_required
@permission_required('manage_admins')
def change_admin_password(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    new_password = request.form.get('new_password', '').strip()
    if not new_password:
        flash('Password cannot be empty.', 'error')
        return redirect(url_for('admin.manage_admins.manage_admins'))
    if len(new_password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('admin.manage_admins.manage_admins'))
    admin.set_password(new_password)
    db.session.commit()
    logger.info(
        "Password changed for admin '%s' by %s", admin.username, current_user.username
    )
    flash(f'Password updated for "{admin.username}".', 'success')
    return redirect(url_for('admin.manage_admins.manage_admins'))


# ---------------------------------------------------------------------------
# Update admin email
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins/<int:admin_id>/update-email', methods=['POST'])
@login_required
@permission_required('manage_admins')
def update_admin_email(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    new_email = request.form.get('email', '').strip().lower()
    admin.email = new_email if new_email else None
    db.session.commit()
    logger.info(
        "Email updated for admin '%s' by %s", admin.username, current_user.username
    )
    flash(f'Email updated for "{admin.username}".', 'success')
    return redirect(url_for('admin.manage_admins.manage_admins'))


# ---------------------------------------------------------------------------
# Reset MFA for another admin
# ---------------------------------------------------------------------------

@manage_admins_bp.route('/manage-admins/<int:admin_id>/reset-mfa', methods=['POST'])
@login_required
@permission_required('manage_admins')
def reset_mfa(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    if not admin.mfa_enabled:
        flash(f'MFA is not enabled for "{admin.username}".', 'info')
        return redirect(url_for('admin.manage_admins.manage_admins'))
    admin.mfa_enabled = False
    admin.mfa_secret  = None
    db.session.commit()
    logger.info(
        "Super admin '%s' reset MFA for admin '%s'",
        current_user.username, admin.username,
    )
    flash(
        f'MFA has been reset for "{admin.username}". They will need to set it up again.',
        'success',
    )
    return redirect(url_for('admin.manage_admins.manage_admins'))
