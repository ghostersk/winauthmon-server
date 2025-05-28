from extensions import db
from datetime import datetime
from flask import current_app
import pytz

# Import models for direct relationship references
import sys
import os
# Add the parent directory to path for imports to work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from auth.models import Company, ApiKey
from utils.toolbox import get_current_timestamp

def get_current_time_with_timezone():
    """Return current time with the configured timezone"""
    return get_current_timestamp()

class Log(db.Model):
    __tablename__ = 'api_logs'
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(20), nullable=False)
    user_name = db.Column(db.String(50), nullable=False)
    computer_name = db.Column(db.String(50), nullable=False)
    local_ip = db.Column(db.String(45), nullable=True)  # Increased size to support IPv6, made nullable
    public_ip = db.Column(db.String(45), nullable=True)  # New field for public IP, nullable
    timestamp = db.Column(db.DateTime, nullable=False, default=get_current_time_with_timezone)
    retry = db.Column(db.Integer, default=0, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('app_auth_companies.id'), nullable=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('app_auth_api_keys.id'), nullable=True)
    
    # Relationships
    company = db.relationship(Company, backref='logs', foreign_keys=[company_id])
    api_key = db.relationship(ApiKey, backref='logs', foreign_keys=[api_key_id])

class ErrorLog(db.Model):
    """Model for storing application error logs"""
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)
    logger_name = db.Column(db.String(100), nullable=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    pathname = db.Column(db.String(255), nullable=True)
    lineno = db.Column(db.Integer, nullable=True)
    request_id = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('app_auth_users.id', ondelete='SET NULL'), nullable=True)
    remote_addr = db.Column(db.String(50), nullable=True)
    exception = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<ErrorLog {self.id}: {self.level} - {self.message[:50]}>'

# API-specific models
# Note: ApiKey model is in auth/models.py as it's related to user authentication