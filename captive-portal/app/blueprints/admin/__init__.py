"""
Admin blueprints package.

Registers all admin sub-blueprints onto a single 'admin' Blueprint so that
every admin URL is prefixed with /admin and every endpoint name is prefixed
with admin.<sub_blueprint>.<function>.
"""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Import and register each sub-blueprint.
from blueprints.admin.unregistered import unregistered_bp   # noqa: E402
from blueprints.admin.dashboard import dashboard_bp          # noqa: E402
from blueprints.admin.users import users_bp                  # noqa: E402
from blueprints.admin.devices import devices_bp              # noqa: E402
from blueprints.admin.approvals import approvals_bp          # noqa: E402
from blueprints.admin.vlans import vlans_bp                  # noqa: E402
from blueprints.admin.manage_admins import manage_admins_bp  # noqa: E402

admin_bp.register_blueprint(unregistered_bp)
admin_bp.register_blueprint(dashboard_bp)
admin_bp.register_blueprint(users_bp)
admin_bp.register_blueprint(devices_bp)
admin_bp.register_blueprint(approvals_bp)
admin_bp.register_blueprint(vlans_bp)
admin_bp.register_blueprint(manage_admins_bp)

# Additional sub-blueprints will be appended here as Phase 2 progresses.