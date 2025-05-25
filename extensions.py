import os
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask import Blueprint
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # Updated to use blueprint route
login_manager.login_message_category = 'info'

# Environment variable helpers
def get_env_var(name, default=None):
    """Get environment variable with logging for missing critical values"""
    value = os.environ.get(name, default)
    if value is None:
        logger.warning(f"Environment variable {name} not set!")
    return value