"""
Admin blueprints package.

Registers all admin sub-blueprints onto a single 'admin' Blueprint so that
every admin URL is prefixed with /admin and every endpoint name is prefixed
with admin.<sub_blueprint>.<function>.
"""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Import and register each sub-blueprint.
# Additional sub-blueprints will be appended here as Phase 2 progresses.
from blueprints.admin.unregistered import unregistered_bp  # noqa: E402

admin_bp.register_blueprint(unregistered_bp)