"""
Captive Portal Application — slim application factory.

All routes live in blueprints:
  blueprints/portal.py          — public captive-portal / user-facing routes
  blueprints/admin/__init__.py  — admin blueprint (registers all sub-blueprints)

Shared helpers live in core/:
  core/auth.py          core/device_utils.py  core/mac_utils.py
  core/network.py       core/pihole_client.py core/portal_utils.py
  core/sweepers.py      core/switch.py        core/user_utils.py
  core/vlan_utils.py
"""

import hmac as _hmac
import json
import logging
import os
import threading
import time

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from extensions import csrf, db, login_manager
from models import (
    Admin, CentralOutboundEvent, Device, DeviceOwnership, IPLease,
    RegistrationRequest, UnregisteredLease, User, VlanMapping,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)

    # ── Core config ───────────────────────────────────────────────────────────
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql://portal_user:password@db:5432/captive_portal',
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping':      True,
        'pool_recycle':       300,
        'pool_reset_on_return': 'rollback',
    }
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'admin.manage_admins.login'

    # ── Context processors ────────────────────────────────────────────────────
    @app.context_processor
    def inject_globals():
        return {
            'institution_url':        os.getenv('INSTITUTION_URL', '').strip(),
            'institution_button_text': os.getenv('INSTITUTION_BUTTON_TEXT', '').strip(),
            'usage_policy_text':      os.getenv('USAGE_POLICY_TEXT', '').strip(),
            'portal_url':             os.getenv('PORTAL_URL', '').strip(),
            'portal_poll_url':        os.getenv('PORTAL_POLL_URL', '').strip(),
        }

    # ── Before-request: MFA / forced-password-change enforcement ─────────────
    from core.auth import enforce_mfa_setup
    app.before_request(enforce_mfa_setup)

    # ── Register blueprints ───────────────────────────────────────────────────
    from blueprints.portal import portal_bp
    from blueprints.admin import admin_bp

    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp)

    # ── Central sync client ───────────────────────────────────────────────────
    # NOTE: do NOT wrap this in app.app_context(). init_central_client only
    # stores references and spawns a daemon thread. The thread creates its own
    # fresh app context each iteration via `with _app.app_context():`. If we
    # push a context here and it is popped when the `with` block exits, the
    # spawned thread is left holding a reference to a dead context, which causes
    # the "SQLAlchemy instance not registered" error on every subsequent loop.
    import central_client
    central_client.init_central_client(app, db, CentralOutboundEvent)

    # ── Central inbound push endpoint ─────────────────────────────────────────
    @app.route('/api/v1/push', methods=['POST'])
    def central_inbound_push():
        push_secret = os.getenv('CENTRAL_PUSH_SECRET', '').strip()
        if not push_secret:
            return jsonify({'error': 'Push not configured on this site'}), 503
        provided = request.headers.get('X-Push-Secret', '')
        if not _hmac.compare_digest(push_secret, provided):
            return jsonify({'error': 'Forbidden'}), 403
        body = request.get_json(silent=True) or {}
        event_type = body.get('event_type', '').strip()
        data = body.get('data') or {}
        if not event_type:
            return jsonify({'error': 'event_type required'}), 400
        try:
            central_client._apply_inbound(event_type, data)
        except Exception as exc:
            logger.error('central push apply error: %s', exc)
            return jsonify({'error': 'internal error'}), 500
        return jsonify({'status': 'ok'})

    # ── Health endpoint ───────────────────────────────────────────────────────
    @app.route('/health')
    def health():
        db_ok = True
        db_error = None
        try:
            db.session.execute(text('SELECT 1'))
        except Exception as exc:
            logger.error('Health check DB failed: %s', exc)
            db_ok = False
            db_error = str(exc)

        from core.sweepers import check_heartbeats
        max_stale = max(
            int(os.getenv('IP_LEASE_SWEEP_INTERVAL', '20')),
            int(os.getenv('WIFI_CONFIRM_SWEEP_INTERVAL_SEC', '30')),
            int(os.getenv('CENTRAL_POLL_INTERVAL_SEC', '10')),
        ) * 3
        threads = check_heartbeats(max_stale)
        threads_ok = all(v in ('ok', 'unknown') for v in threads.values())
        overall_ok = db_ok and threads_ok

        payload = {
            'status': 'healthy' if overall_ok else 'unhealthy',
            'db':     'ok' if db_ok else f'error: {db_error}',
            'threads': threads,
        }
        return jsonify(payload), 200 if overall_ok else 500

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html', code=404, message='Page not found.'), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error('500 error: %s', e)
        return render_template(
            'error.html', code=500,
            message=(
                'Something went wrong on the server. '
                'If the system is updating it will be back shortly.'
            ),
        ), 500

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return e
        logger.exception('Unhandled exception: %s', e)
        return render_template(
            'error.html', code=500,
            message=(
                'An unexpected error occurred. '
                'If the system is updating it will be back shortly.'
            ),
        ), 500

    # ── Background threads ────────────────────────────────────────────────────
    from core.sweepers import (
        start_ip_lease_sweeper,
        start_wifi_confirmation_sweeper,
        startup_acl_baseline,
        startup_switch_discovery,
        startup_write_prefix_map,
    )
    start_wifi_confirmation_sweeper(app)
    start_ip_lease_sweeper(app)
    startup_switch_discovery(app)
    startup_write_prefix_map(app)

    # Run the potentially slow ACL baseline push in a background thread
    # so it doesn't block Gunicorn master/worker creation under --preload
    threading.Thread(target=startup_acl_baseline, args=(app,), daemon=True).start()

    return app


# ---------------------------------------------------------------------------
# Legacy env-var admin migration (runs once at first login — kept here so
# the login blueprint can call it without importing app.py)
# ---------------------------------------------------------------------------

def ensure_legacy_admin(username: str, password: str) -> Admin:
    """
    Create an Admin row from legacy ADMIN_USERNAME / ADMIN_PASSWORD_HASH env vars
    if one does not already exist.  Returns the Admin row.
    """
    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        admin = Admin(username=username)
        admin.set_password(password)
        for perm in (
            'can_manage_users', 'can_manage_vlans', 'can_view_traffic',
            'can_manage_admins', 'can_manage_switch_ports', 'can_manage_isp_routers',
            'can_manage_firmware', 'can_manage_pihole',
        ):
            setattr(admin, perm, True)
        db.session.add(admin)
        db.session.commit()
        logger.info("Migrated legacy admin '%s' to database", username)
    return admin


# ---------------------------------------------------------------------------
# WSGI entry point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
# Test comment added on $(date)
