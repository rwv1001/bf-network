"""
Shared Flask extensions — instantiated here, initialised in create_app().
Import from this module to avoid circular imports.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
socketio = SocketIO(
    async_mode="threading",
    cors_allowed_origins=[],
)