from flask_login import UserMixin
from extensions import db
from datetime import datetime
import secrets
import pyotp

class Settings(db.Model):
    __tablename__ = 'app_auth_settings'
    id = db.Column(db.Integer, primary_key=True)
    allow_registration = db.Column(db.Boolean, default=False)
    restrict_email_domains = db.Column(db.Boolean, default=False)
    
    # Password strength requirements
    password_min_length = db.Column(db.Integer, default=10)
    password_require_numbers_mixed_case = db.Column(db.Boolean, default=True)
    password_require_special_chars = db.Column(db.Boolean, default=True)
    password_safe_special_chars = db.Column(db.String(100), default='!@#$%^&*()_+-=[]{}|;:,.<>?')
    
    # MFA requirements
    require_mfa_for_all_users = db.Column(db.Boolean, default=False)
    
    # Database logging configuration
    log_level = db.Column(db.String(20), default='WARNING')

# New Company model
class Company(db.Model):
    __tablename__ = 'app_auth_companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Relationships
    users = db.relationship('UserCompany', back_populates='company')
    api_keys = db.relationship('ApiKey', backref='company', lazy=True)

# User-Company association table
class UserCompany(db.Model):
    __tablename__ = 'app_auth_user_companies'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('app_auth_users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('app_auth_companies.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='User')  # Role specific to this company: 'User', 'CompanyAdmin'
    
    # Relationships
    user = db.relationship('User', back_populates='companies')
    company = db.relationship('Company', back_populates='users')

class User(db.Model, UserMixin):
    __tablename__ = 'app_auth_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='User')  # Global role: 'User', 'Admin', 'GlobalAdmin'
    is_active = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_required = db.Column(db.Boolean, default=None)  # None=inherit from global, True=required, False=not required
    api_keys = db.relationship('ApiKey', backref='user', lazy=True)
    # User-company relationship
    companies = db.relationship('UserCompany', back_populates='user')

    def get_mfa_uri(self):
        if self.mfa_secret:
            return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
                name=self.email,
                issuer_name="Domain Logon Monitor"
            )
        return None

    def verify_mfa_code(self, code):
        if not self.mfa_secret or not code:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(code)

    def is_mfa_required(self):
        """Check if MFA is required for this user based on global and per-user settings"""
        # GlobalAdmin accounts are exempt when global setting is ON
        if self.role == 'GlobalAdmin':
            return False
        
        # Check per-user setting first
        if self.mfa_required is not None:
            return self.mfa_required
        
        # Fall back to global setting
        settings = Settings.query.first()
        return settings.require_mfa_for_all_users if settings else False

    def generate_mfa_secret(self):
        self.mfa_secret = pyotp.random_base32()
        return self.mfa_secret

    def is_company_admin(self, company_id):
        """Check if user is an admin for a specific company"""
        for uc in self.companies:
            if uc.company_id == company_id and uc.role == 'CompanyAdmin':
                return True
        return False
        
    def is_global_admin(self):
        """Check if user is a global administrator"""
        return self.role == 'GlobalAdmin'
        
    def is_admin(self):
        """Check if user is an admin (but not global admin)"""
        return self.role == 'Admin'
        
    def get_companies(self):
        """Get all companies this user has access to"""
        return [uc.company for uc in self.companies]

class ApiKey(db.Model):
    __tablename__ = 'app_auth_api_keys'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)  # New field to control API key status
    user_id = db.Column(db.Integer, db.ForeignKey('app_auth_users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('app_auth_companies.id'), nullable=True)

    @staticmethod
    def generate_key():
        return secrets.token_hex(32)

class AllowedDomain(db.Model):
    __tablename__ = 'app_auth_allowed_domains'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(100), unique=True, nullable=False)
