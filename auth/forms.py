from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from email_validator import validate_email, EmailNotValidError
from .models import User, Settings, AllowedDomain
from extensions import db
import re

def validate_password_strength(password):
    """Validate password based on current settings"""
    settings = Settings.query.first()
    if not settings:
        return  # No settings found, allow any password
    
    errors = []
    
    # Check minimum length
    if len(password) < settings.password_min_length:
        errors.append(f'Password must be at least {settings.password_min_length} characters long.')
    
    # Check for numbers and mixed case if required
    if settings.password_require_numbers_mixed_case:
        if not re.search(r'[0-9]', password):
            errors.append('Password must contain at least one number.')
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter.')
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter.')
    
    # Check for special characters if required
    if settings.password_require_special_chars:
        safe_chars = settings.password_safe_special_chars or '!@#$%^&*()_+-=[]{}|;:,.<>?'
        if not any(char in safe_chars for char in password):
            errors.append(f'Password must contain at least one special character from: {safe_chars}')
    
    if errors:
        raise ValidationError(' '.join(errors))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), validate_password_strength])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter(db.func.lower(User.username) == username.data.lower()).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        try:
            validate_email(email.data)
        except EmailNotValidError:
            raise ValidationError('Invalid email address.')

        settings = Settings.query.first()
        if settings and settings.restrict_email_domains:
            domain = '@' + email.data.split('@')[1].lower()
            if not AllowedDomain.query.filter_by(domain=domain).first():
                raise ValidationError('Registration is not allowed for this email domain.')

        user = User.query.filter(db.func.lower(User.email) == email.data.lower()).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), validate_password_strength])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ApiKeyForm(FlaskForm):
    submit = SubmitField('Generate New API Key')
