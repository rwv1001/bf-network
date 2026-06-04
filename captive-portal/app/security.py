import re
from flask import request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Malicious path blocking ────────────────────────────────────────────────
BLOCKED_PATHS = [
    '/boaform',
    '/adminform',
    '/formLogin',
    '/formPing',
    '/cgi-bin',
    '/manager',
    '/shell',
    '/phpmyadmin',
]

limiter = Limiter(
    get_remote_address,
    default_limits=["200 per hour", "50 per minute"],
    storage_uri="memory://",          # Change to "redis://redis:6379" later if desired
)


def init_security(app):
    limiter.init_app(app)

    # Block known exploit paths
    @app.before_request
    def block_malicious_requests():
        path = request.path.lower()
        for bad in BLOCKED_PATHS:
            if path.startswith(bad):
                abort(404)

    # ── Optional: Tighter limits on sensitive routes ───────────────────────
    # You can apply these decorators on your login/registration views later.
    # Example:
    # @limiter.limit("5 per minute")
    # def login():
    #     ...