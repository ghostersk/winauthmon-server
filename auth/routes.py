from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, current_user, login_required
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from sqlalchemy import or_
from wtforms.validators import ValidationError
from .models import User, Settings, AllowedDomain, ApiKey, Company, UserCompany
from api.models import Log
from .forms import RegistrationForm, LoginForm, ChangePasswordForm, FlaskForm
from extensions import db, bcrypt
import pyotp
import qrcode
import base64
from io import BytesIO
import os
import zipfile
import tempfile
import configparser
import logging
from utils.toolbox import get_current_timestamp

print(get_current_timestamp())

auth = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

auth_bp = auth

@auth.route('/register', methods=['GET', 'POST'])
def register():
    try:
        settings = Settings.query.first()
        if not settings.allow_registration:
            abort(403)
        if current_user.is_authenticated:
            return redirect(url_for('frontend.index'))
        form = RegistrationForm()
        if form.validate_on_submit():
            if not is_allowed_email_domain(form.email.data):
                # Log failed registration due to domain restriction
                logger.warning(
                    "Registration failed for email %s from IP %s - domain not allowed",
                    form.email.data.lower(),
                    request.remote_addr,
                    extra={
                        'ip_address': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent'),
                        'email': form.email.data.lower(),
                        'username': form.username.data.lower(),
                        'failure_reason': 'domain_not_allowed'
                    }
                )
                flash('Registration is not allowed for this email domain.', 'danger')
                return render_template('auth/register.html', title='Register', form=form)
            
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data.lower(), email=form.email.data.lower(), password=hashed_password)
            db.session.add(user)
            db.session.commit()
            
            # Log successful registration
            logger.info(
                "User successfully registered: %s (email: %s, ID: %s) from IP %s",
                user.username,
                user.email,
                user.id,
                request.remote_addr,
                extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'action': 'registration_success'
                }
            )
            
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('auth.login'))
        else:
            # Log failed registration due to form validation errors
            if request.method == 'POST':
                form_errors = []
                for field_name, errors in form.errors.items():
                    form_errors.extend([f"{field_name}: {error}" for error in errors])
                
                logger.warning(
                    "Registration failed for %s from IP %s - form validation errors: %s",
                    form.email.data.lower() if form.email.data else 'unknown',
                    request.remote_addr,
                    "; ".join(form_errors),
                    extra={
                        'ip_address': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent'),
                        'email': form.email.data.lower() if form.email.data else None,
                        'username': form.username.data.lower() if form.username.data else None,
                        'failure_reason': 'form_validation_errors',
                        'form_errors': form_errors
                    }
                )
        return render_template('auth/register.html', title='Register', form=form)
    except Exception as e:
        logger.exception("Error in register function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'form_data': getattr(form, 'data', {}) if 'form' in locals() else None,
            'error': str(e)
        })
        flash('An error occurred during registration. Please try again.', 'danger')
        return render_template('auth/register.html', title='Register', form=RegistrationForm())

@auth.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('frontend.index'))
        form = LoginForm()
        error_message = None
        if form.validate_on_submit():
            # Case-insensitive login - search by email or username
            login_identifier = form.email.data.lower()
            user = User.query.filter(
                (db.func.lower(User.email) == login_identifier) |
                (db.func.lower(User.username) == login_identifier)
            ).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                if not user.is_active:
                    message = 'Account awaiting activation by administrator'
                    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'error': message}), 401
                    error_message = message
                else:
                    # Check if MFA is required but not set up
                    if user.is_mfa_required() and not user.mfa_enabled:
                        session['mfa_setup_user_id'] = user.id
                        session['mfa_setup_remember'] = form.remember.data
                        return jsonify({'require_mfa_setup': True})
                    elif user.mfa_enabled:
                        session['mfa_user_id'] = user.id
                        session['mfa_remember'] = form.remember.data
                        return jsonify({'require_mfa': True})
                    
                    # Log successful login
                    logger.info(
                        "User successfully logged in: %s (ID: %s) from IP %s",
                        user.username,
                        user.id,
                        request.remote_addr,
                        extra={
                            'ip_address': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent'),
                            'user_id': user.id,
                            'username': user.username,
                            'login_method': 'password',
                            'remember_me': form.remember.data
                        }
                    )
                    
                    login_user(user, remember=form.remember.data)
                    next_page = request.args.get('next')
                    return jsonify({'redirect': next_page or url_for('frontend.index')})
            else:
                # Log failed login attempt - wrong password or user not found
                logger.warning(
                    "Failed login attempt for identifier '%s' from IP %s - invalid credentials",
                    login_identifier,
                    request.remote_addr,
                    extra={
                        'ip_address': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent'),
                        'login_identifier': login_identifier,
                        'user_exists': user is not None,
                        'failure_reason': 'wrong_password' if user else 'user_not_found'
                    }
                )
                
                message = 'Invalid Username or Password'
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': message}), 401
                error_message = message
        return render_template('auth/login.html', title='Login', form=form, error_message=error_message)
    except Exception as e:
        logger.exception("Error in login function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'login_identifier': form.email.data.lower() if 'form' in locals() and form.email.data else None,
            'is_json_request': request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest',
            'error': str(e)
        })
        error_msg = 'An error occurred during login. Please try again.'
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': error_msg}), 500
        flash(error_msg, 'danger')
        return render_template('auth/login.html', title='Login', form=LoginForm(), error_message=error_msg)

@auth.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    try:
        if 'mfa_user_id' not in session:
            return jsonify({'error': 'Invalid session'}), 401
        
        user = User.query.get(session['mfa_user_id'])
        code = request.form.get('mfa_code')
        
        if user and user.verify_mfa_code(code):
            # Log successful MFA verification
            logger.info(
                "User successfully completed MFA verification: %s (ID: %s) from IP %s",
                user.username,
                user.id,
                request.remote_addr,
                extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': user.id,
                    'username': user.username,
                    'login_method': 'mfa'
                }
            )
            
            login_user(user, remember=session.get('mfa_remember', False))
            session.pop('mfa_user_id', None)
            session.pop('mfa_remember', None)
            return jsonify({'redirect': url_for('frontend.index')})
        
        # Log failed MFA attempt
        if user:
            logger.warning(
                "Failed MFA verification for user %s (ID: %s) from IP %s - invalid MFA code",
                user.username,
                user.id,
                request.remote_addr,
                extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': user.id,
                    'username': user.username,
                    'failure_reason': 'wrong_mfa_code',
                    'has_mfa_code': bool(code)
                }
            )
        
        return jsonify({'error': 'Invalid MFA code'}), 401
    except Exception as e:
        logger.exception("Error in verify_mfa function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': session.get('mfa_user_id'),
            'has_mfa_code': bool(request.form.get('mfa_code')),
            'error': str(e)
        })
        return jsonify({'error': 'An error occurred during MFA verification. Please try again.'}), 500

@auth.route('/profile')
@login_required
def profile():
    try:
        change_password_form = ChangePasswordForm()
        mfa_action_form = FlaskForm()
        return render_template('auth/profile.html', title='Profile', change_password_form=change_password_form, mfa_action_form=mfa_action_form)
    except Exception as e:
        logger.exception("Error in profile function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': current_user.id if current_user.is_authenticated else None,
            'username': current_user.username if current_user.is_authenticated else None,
            'error': str(e)
        })
        flash('An error occurred loading your profile. Please try again.', 'danger')
        return redirect(url_for('frontend.index'))

@auth.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    try:
        # Check if user is already logged in or if this is a forced setup during login
        forced_setup = 'mfa_setup_user_id' in session
        if not current_user.is_authenticated and not forced_setup:
            return redirect(url_for('auth.login'))
        
        # Get the user (either current user or the one being forced to set up MFA)
        if forced_setup:
            user = User.query.get(session['mfa_setup_user_id'])
            if not user:
                session.pop('mfa_setup_user_id', None)
                session.pop('mfa_setup_remember', None)
                return redirect(url_for('auth.login'))
        else:
            user = current_user
        
        # Create a form just for CSRF protection
        form = FlaskForm()
        
        if request.method == 'POST':
            if not form.validate_on_submit():
                flash('CSRF validation failed. Please try again.', 'danger')
                return redirect(url_for('auth.setup_mfa'))
                
            code = request.form.get('verification_code')
            temp_secret = session.get('temp_mfa_secret')
            if temp_secret:
                totp = pyotp.TOTP(temp_secret)
                if totp.verify(code):
                    user.mfa_secret = temp_secret
                    user.mfa_enabled = True
                    db.session.commit()
                    session.pop('temp_mfa_secret', None)
                    
                    if forced_setup:
                        # Complete login process after forced MFA setup
                        remember_me = session.pop('mfa_setup_remember', False)
                        session.pop('mfa_setup_user_id', None)
                        login_user(user, remember=remember_me)
                        flash('Two-factor authentication has been enabled. You are now logged in.', 'success')
                        return redirect(url_for('frontend.index'))
                    else:
                        flash('Two-factor authentication has been enabled.', 'success')
                        return redirect(url_for('auth.profile'))
                flash('Invalid verification code.', 'danger')
                return redirect(url_for('auth.setup_mfa'))
            flash('MFA setup session expired. Please try again.', 'danger')
            if forced_setup:
                session.pop('mfa_setup_user_id', None)
                session.pop('mfa_setup_remember', None)
                return redirect(url_for('auth.login'))
            return redirect(url_for('auth.profile'))

        # Generate new secret for setup
        temp_secret = pyotp.random_base32()
        session['temp_mfa_secret'] = temp_secret
        
        # Generate QR code
        totp = pyotp.TOTP(temp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="Domain Logon Monitor"
        )
        
        qr = qrcode.QRCode(version=1, box_size=6, border=4)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = BytesIO()
        img.save(buffered)
        qr_code = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode()}"
        
        return render_template('auth/mfa_setup.html', 
                             qr_code=qr_code,
                             secret=temp_secret,
                             uri=provisioning_uri,
                             form=form,
                             forced_setup=forced_setup)
    except Exception as e:
        logger.exception("Error in setup_mfa function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': current_user.id if current_user.is_authenticated else session.get('mfa_setup_user_id'),
            'username': current_user.username if current_user.is_authenticated else None,
            'forced_setup': 'mfa_setup_user_id' in session,
            'method': request.method,
            'has_temp_secret': 'temp_mfa_secret' in session,
            'error': str(e)
        })
        # Clean up session on error
        session.pop('temp_mfa_secret', None)
        if 'mfa_setup_user_id' in session:
            session.pop('mfa_setup_user_id', None)
            session.pop('mfa_setup_remember', None)
            flash('An error occurred during MFA setup. Please try logging in again.', 'danger')
            return redirect(url_for('auth.login'))
        else:
            flash('An error occurred during MFA setup. Please try again.', 'danger')
            return redirect(url_for('auth.profile'))

@auth.route('/toggle_mfa', methods=['POST'])
@login_required
def toggle_mfa():
    try:
        # Check if user is trying to disable MFA when it's required
        if current_user.mfa_enabled and current_user.is_mfa_required():
            # GlobalAdmin can always disable their own MFA
            if current_user.role != 'GlobalAdmin':
                flash('MFA cannot be disabled because it is required by your account settings. Please contact your administrator.', 'warning')
                return redirect(url_for('auth.profile'))
        
        current_user.mfa_enabled = not current_user.mfa_enabled
        db.session.commit()
        state = "enabled" if current_user.mfa_enabled else "disabled"
        flash(f'Two-factor authentication has been {state}.', 'success')
        return redirect(url_for('auth.profile'))
    except Exception as e:
        logger.exception("Error in toggle_mfa function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': current_user.id if current_user.is_authenticated else None,
            'username': current_user.username if current_user.is_authenticated else None,
            'current_mfa_enabled': current_user.mfa_enabled if current_user.is_authenticated else None,
            'error': str(e)
        })
        flash('An error occurred while toggling MFA. Please try again.', 'danger')
        return redirect(url_for('auth.profile'))

@auth.route('/reset_mfa', methods=['POST'])
@login_required
def reset_mfa():
    try:
        current_user.mfa_secret = None
        current_user.mfa_enabled = False
        db.session.commit()
        flash('Two-factor authentication has been reset.', 'success')
        return redirect(url_for('auth.profile'))
    except Exception as e:
        logger.exception("Error in reset_mfa function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': current_user.id if current_user.is_authenticated else None,
            'username': current_user.username if current_user.is_authenticated else None,
            'error': str(e)
        })
        flash('An error occurred while resetting MFA. Please try again.', 'danger')
        return redirect(url_for('auth.profile'))

@auth.route('/admin/user/<int:user_id>/reset_mfa', methods=['POST'])
@login_required
def admin_reset_mfa(user_id):
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    
    # Only Global Admins can reset MFA for Admin or Global Admin accounts
    if (user.role == 'Admin' or user.role == 'GlobalAdmin') and not current_user.is_global_admin():
        flash('You do not have permission to reset MFA for admin accounts', 'danger')
        return redirect(url_for('auth.manage_users'))
        
    user.mfa_secret = None
    user.mfa_enabled = False
    db.session.commit()
    flash(f'Two-factor authentication has been reset for {user.username}.', 'success')
    return redirect(url_for('auth.manage_users'))

@auth.route('/logout')
def logout():
    try:
        user_info = {
            'user_id': current_user.id if current_user.is_authenticated else None,
            'username': current_user.username if current_user.is_authenticated else None
        }
        
        # Log successful logout before actually logging out
        if current_user.is_authenticated:
            logger.info(
                "User successfully logged out: %s (ID: %s) from IP %s",
                current_user.username,
                current_user.id,
                request.remote_addr,
                extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': current_user.id,
                    'username': current_user.username,
                    'action': 'logout_success'
                }
            )
        
        logout_user()
        return redirect(url_for('frontend.index'))
    except Exception as e:
        user_info = user_info if 'user_info' in locals() else {}
        logger.exception("Error in logout function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': user_info.get('user_id'),
            'username': user_info.get('username'),
            'error': str(e)
        })
        # Even if logout fails, try to clear session and redirect
        try:
            logout_user()
        except:
            pass
        return redirect(url_for('frontend.index'))

@auth.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    try:
        # Only GlobalAdmin and Admin can access user management
        if not current_user.is_global_admin() and current_user.role != 'Admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('frontend.index'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            is_active = 'is_active' in request.form
            
            # Restrict role creation based on current user permissions
            if not current_user.is_global_admin():
                # Regular Admin users cannot create GlobalAdmin or Admin accounts
                if role in ['GlobalAdmin', 'Admin']:
                    flash('You do not have permission to create admin accounts.', 'danger')
                    return redirect(url_for('auth.manage_users'))
            
            # Check if username or email already exists
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                flash('A user with that username or email already exists.', 'danger')
            else:
                # Validate password strength
                try:
                    from .forms import validate_password_strength
                    validate_password_strength(password)
                except ValidationError as e:
                    logger.warning(f'Password validation failed for user creation: {str(e)}', extra={
                        'username': username,
                        'email': email,
                        'role': role,
                        'remote_addr': request.remote_addr,
                        'current_user_id': current_user.id
                    })
                    flash(f'Password validation failed: {str(e)}', 'danger')
                    return redirect(url_for('auth.manage_users'))
                
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                user = User(username=username, email=email, password=hashed_password,
                           role=role, is_active=is_active)
                db.session.add(user)
                db.session.commit()
                flash('User has been created!', 'success')
                
                # If user is added successfully and is not a GlobalAdmin, add them to the default company
                if role != 'GlobalAdmin':
                    default_company = Company.query.filter_by(name='Default Company').first()
                    if default_company:
                        # If Admin, add as CompanyAdmin, otherwise as regular User
                        company_role = 'CompanyAdmin' if role == 'Admin' else 'User'
                        user_company = UserCompany(
                            user_id=user.id,
                            company_id=default_company.id,
                            role=company_role
                        )
                        db.session.add(user_company)
                        db.session.commit()
            
            return redirect(url_for('auth.manage_users'))
        
        # Filter users based on current user's role and permissions
        if current_user.is_global_admin():
            # Global admins can see all users
            users = User.query.all()
        else:
            # Regular Admin users can only see:
            # 1. Users from companies they belong to
            # 2. Cannot see GlobalAdmin accounts
            # 3. Cannot see Admin accounts from other companies
            
            # Get company IDs that the current admin belongs to
            admin_company_ids = [uc.company_id for uc in current_user.companies]
            
            if admin_company_ids:
                # Get users who belong to the same companies as the current admin
                # and exclude GlobalAdmin accounts
                user_ids_in_same_companies = db.session.query(UserCompany.user_id).filter(
                    UserCompany.company_id.in_(admin_company_ids)
                ).distinct().subquery()
                
                # Also get users who have no company associations (newly created users)
                user_ids_with_no_companies = db.session.query(User.id).outerjoin(UserCompany).filter(
                    UserCompany.user_id.is_(None),
                    User.role != 'GlobalAdmin'
                ).subquery()
                
                users = User.query.filter(
                    or_(
                        User.id.in_(user_ids_in_same_companies),
                        User.id.in_(user_ids_with_no_companies)
                    ),
                    User.role != 'GlobalAdmin'
                ).all()
            else:
                # If admin doesn't belong to any company, they can only see themselves
                # and users with no company associations (newly created users)
                user_ids_with_no_companies = db.session.query(User.id).outerjoin(UserCompany).filter(
                    UserCompany.user_id.is_(None),
                    User.role != 'GlobalAdmin'
                ).subquery()
                
                users = User.query.filter(
                    or_(
                        User.id == current_user.id,
                        User.id.in_(user_ids_with_no_companies)
                    ),
                    User.role != 'GlobalAdmin'
                ).all()
        
        # Get companies that the current user can assign users to
        if current_user.is_global_admin():
            # GlobalAdmin can see all companies
            available_companies = Company.query.all()
        else:
            # Regular Admin can only see companies they belong to
            admin_company_ids = [uc.company_id for uc in current_user.companies]
            available_companies = Company.query.filter(Company.id.in_(admin_company_ids)).all()
        
        # For Admin users, filter each user's company associations to only show 
        # companies that the Admin also has access to
        if not current_user.is_global_admin():
            admin_company_ids = [uc.company_id for uc in current_user.companies]
            for user in users:
                # Filter user's companies to only those the Admin can access
                user.filtered_companies = [uc for uc in user.companies if uc.company_id in admin_company_ids]
        else:
            # GlobalAdmin can see all companies for all users
            for user in users:
                user.filtered_companies = user.companies
        
        return render_template('auth/manage_users.html', 
                             title='Manage Users', 
                             users=users, 
                             available_companies=available_companies)
    except Exception as e:
        logger.exception("Error in manage_users function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'user_id': current_user.id if current_user.is_authenticated else None,
            'username': current_user.username if current_user.is_authenticated else None,
            'role': current_user.role if current_user.is_authenticated else None,
            'method': request.method,
            'form_data': dict(request.form) if request.method == 'POST' else None,
            'error': str(e)
        })
        flash('An error occurred while managing users. Please try again.', 'danger')
        return redirect(url_for('frontend.index'))

@auth.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
        
    user = User.query.get_or_404(user_id)
    
    # Global admins can edit anyone
    if current_user.is_global_admin():
        pass  # No restrictions
    else:
        # Regular Admin users have restrictions
        # 1. Cannot edit GlobalAdmin accounts
        if user.role == 'GlobalAdmin':
            flash('You do not have permission to edit GlobalAdmin accounts.', 'danger')
            return redirect(url_for('auth.manage_users'))
        
        # 2. Cannot edit Admin accounts unless they are in the same company
        if user.role == 'Admin':
            # Check if both users share at least one company
            current_user_companies = {uc.company_id for uc in current_user.companies}
            target_user_companies = {uc.company_id for uc in user.companies}
            
            if not current_user_companies.intersection(target_user_companies):
                flash('You do not have permission to edit admin accounts from other companies.', 'danger')
                return redirect(url_for('auth.manage_users'))
        
        # 3. Can only edit regular Users who belong to the same company
        elif user.role == 'User':
            current_user_companies = {uc.company_id for uc in current_user.companies}
            target_user_companies = {uc.company_id for uc in user.companies}
            
            if not current_user_companies.intersection(target_user_companies):
                flash('You do not have permission to edit users from other companies.', 'danger')
                return redirect(url_for('auth.manage_users'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        if form.password.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
        db.session.commit()
        flash('User has been updated!', 'success')
        return redirect(url_for('auth.manage_users'))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
    return render_template('auth/register.html', title='Edit User', form=form)

@auth.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    try:
        if not current_user.is_global_admin() and current_user.role != 'Admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('frontend.index'))
            
        user = User.query.get_or_404(user_id)
        
        # Prevent self-deletion
        if user.id == current_user.id:
            flash('You cannot delete your own account.', 'warning')
            return redirect(url_for('auth.manage_users'))
        
        # Global admins can delete anyone (except themselves)
        if current_user.is_global_admin():
            pass  # No restrictions
        else:
            # Regular Admin users have restrictions
            # 1. Cannot delete GlobalAdmin accounts
            if user.role == 'GlobalAdmin':
                flash('You do not have permission to delete GlobalAdmin accounts.', 'danger')
                return redirect(url_for('auth.manage_users'))
            
            # 2. Cannot delete Admin accounts unless they are in the same company
            if user.role == 'Admin':
                current_user_companies = {uc.company_id for uc in current_user.companies}
                target_user_companies = {uc.company_id for uc in user.companies}
                
                if not current_user_companies.intersection(target_user_companies):
                    flash('You do not have permission to delete admin accounts from other companies.', 'danger')
                    return redirect(url_for('auth.manage_users'))
            
            # 3. Can only delete regular Users who belong to the same company
            elif user.role == 'User':
                current_user_companies = {uc.company_id for uc in current_user.companies}
                target_user_companies = {uc.company_id for uc in user.companies}
                
                if not current_user_companies.intersection(target_user_companies):
                    flash('You do not have permission to delete users from other companies.', 'danger')
                    return redirect(url_for('auth.manage_users'))
            
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted!', 'success')
        return redirect(url_for('auth.manage_users'))
    except Exception as e:
        logger.exception("Error in delete_user function", extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'current_user_id': current_user.id if current_user.is_authenticated else None,
            'current_username': current_user.username if current_user.is_authenticated else None,
            'current_user_role': current_user.role if current_user.is_authenticated else None,
            'target_user_id': user_id,
            'target_username': user.username if 'user' in locals() else None,
            'target_user_role': user.role if 'user' in locals() else None,
            'error': str(e)
        })
        flash('An error occurred while deleting the user. Please try again.', 'danger')
        return redirect(url_for('auth.manage_users'))

@auth.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if not current_user.is_global_admin():
        abort(403)
    settings = Settings.query.first()
    if request.method == 'POST':
        settings.allow_registration = 'allow_registration' in request.form
        settings.restrict_email_domains = 'restrict_email_domains' in request.form
        
        # Update MFA requirement setting
        settings.require_mfa_for_all_users = 'require_mfa_for_all_users' in request.form
        
        # Update password strength settings
        password_min_length = request.form.get('password_min_length', type=int)
        if password_min_length and password_min_length >= 6:  # Minimum 6 characters
            settings.password_min_length = password_min_length
        
        settings.password_require_numbers_mixed_case = 'password_require_numbers_mixed_case' in request.form
        settings.password_require_special_chars = 'password_require_special_chars' in request.form
        
        safe_special_chars = request.form.get('password_safe_special_chars', '').strip()
        if safe_special_chars:
            settings.password_safe_special_chars = safe_special_chars
        
        # Update database logging level
        log_level = request.form.get('log_level')
        if log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            settings.log_level = log_level
            
            # Update the logging level immediately
            from utils.db_logging import update_logging_level
            from flask import current_app
            update_logging_level(current_app)
            
            logger.info(
                "Database logging level changed to %s by GlobalAdmin %s from IP %s",
                log_level,
                current_user.username,
                request.remote_addr,
                extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': current_user.id,
                    'username': current_user.username,
                    'action': 'log_level_change',
                    'new_log_level': log_level
                }
            )
        
        db.session.commit()
        flash('Settings updated successfully!', 'success')
    allowed_domains = AllowedDomain.query.all()
    
    # Get available log levels for the dropdown
    from utils.db_logging import get_available_log_levels
    available_log_levels = get_available_log_levels()
    
    return render_template('auth/admin_settings.html', 
                         settings=settings, 
                         allowed_domains=allowed_domains,
                         available_log_levels=available_log_levels)

@auth.route('/admin/domain/add', methods=['POST'])
@login_required
def add_allowed_domain():
    if not current_user.is_global_admin():
        abort(403)
    domain = request.form.get('domain').strip().lower()
    
    # Remove leading @ if it exists since we'll add it back later
    if domain.startswith('@'):
        domain = domain[1:]
        
    # Validate domain pattern
    import re
    # RFC 1035-compliant domain validation pattern
    # - Labels must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen
    # - Labels must be 63 characters or less
    # - Domain must be 253 characters or less total
    domain_pattern = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
    )
    
    if not domain_pattern.match(domain):
        flash(f'Invalid domain name format. Please enter a valid domain (e.g. example.com).', 'danger')
        return redirect(url_for('auth.admin_settings'))
    
    # Add @ prefix back for storage
    domain = '@' + domain
    
    if not AllowedDomain.query.filter_by(domain=domain).first():
        new_domain = AllowedDomain(domain=domain)
        db.session.add(new_domain)
        db.session.commit()
        flash(f'Domain {domain} added successfully!', 'success')
    else:
        flash(f'Domain {domain} already exists!', 'warning')
        
    return redirect(url_for('auth.admin_settings'))

@auth.route('/admin/domain/<int:domain_id>/delete', methods=['POST'])
@login_required
def delete_allowed_domain(domain_id):
    if not current_user.is_global_admin():
        abort(403)
    domain = AllowedDomain.query.get_or_404(domain_id)
    db.session.delete(domain)
    db.session.commit()
    flash('Domain removed successfully!', 'success')
    return redirect(url_for('auth.admin_settings'))

@auth.route('/admin/generate_api_key', methods=['POST'])
@login_required
def generate_api_key():
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        abort(403)
    current_user.generate_api_key()
    db.session.commit()
    return jsonify({'api_key': current_user.api_key})

@auth.route('/admin/user/<int:user_id>/toggle_status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    
    # Global admins can modify anyone
    if current_user.is_global_admin():
        pass  # No restrictions
    else:
        # Regular Admin users have restrictions
        # 1. Cannot modify GlobalAdmin accounts
        if user.role == 'GlobalAdmin':
            return jsonify({'error': 'You do not have permission to modify GlobalAdmin accounts'}), 403
        
        # 2. Cannot modify Admin accounts unless they are in the same company
        if user.role == 'Admin':
            current_user_companies = {uc.company_id for uc in current_user.companies}
            target_user_companies = {uc.company_id for uc in user.companies}
            
            if not current_user_companies.intersection(target_user_companies):
                return jsonify({'error': 'You do not have permission to modify admin accounts from other companies'}), 403
        
        # 3. Can only modify regular Users who belong to the same company
        elif user.role == 'User':
            current_user_companies = {uc.company_id for uc in current_user.companies}
            target_user_companies = {uc.company_id for uc in user.companies}
            
            if not current_user_companies.intersection(target_user_companies):
                return jsonify({'error': 'You do not have permission to modify users from other companies'}), 403
    
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'status': user.is_active})

@auth.route('/admin/user/<int:user_id>/reset_password', methods=['POST'])
@login_required
def reset_user_password(user_id):
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    
    # Global admins can reset anyone's password
    if current_user.is_global_admin():
        pass  # No restrictions
    else:
        # Regular Admin users have restrictions
        # 1. Cannot reset GlobalAdmin passwords
        if user.role == 'GlobalAdmin':
            flash('You do not have permission to reset GlobalAdmin passwords', 'danger')
            return redirect(url_for('auth.manage_users'))
        
        # 2. Cannot reset Admin passwords unless they are in the same company
        if user.role == 'Admin':
            current_user_companies = {uc.company_id for uc in current_user.companies}
            target_user_companies = {uc.company_id for uc in user.companies}
            
            if not current_user_companies.intersection(target_user_companies):
                flash('You do not have permission to reset admin passwords from other companies', 'danger')
                return redirect(url_for('auth.manage_users'))
        
        # 3. Can only reset passwords for regular Users who belong to the same company
        elif user.role == 'User':
            current_user_companies = {uc.company_id for uc in current_user.companies}
            target_user_companies = {uc.company_id for uc in user.companies}
            
            if not current_user_companies.intersection(target_user_companies):
                flash('You do not have permission to reset passwords for users from other companies', 'danger')
                return redirect(url_for('auth.manage_users'))
        
    new_password = request.form.get('new_password')
    if new_password:
        # Validate password strength
        try:
            from .forms import validate_password_strength
            validate_password_strength(new_password)
        except ValidationError as e:
            logger.warning(f'Password validation failed for password reset: {str(e)}', extra={
                'target_user_id': user_id,
                'target_username': user.username,
                'current_user_id': current_user.id,
                'remote_addr': request.remote_addr
            })
            flash(f'Password validation failed: {str(e)}', 'danger')
            return redirect(url_for('auth.manage_users'))
        
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Password has been reset!', 'success')
    return redirect(url_for('auth.manage_users'))

@auth.route('/admin/user/<int:user_id>/change_role', methods=['POST'])
@login_required
def change_user_role(user_id):
    # Only Global Admins can change user roles
    if not current_user.is_global_admin():
        return jsonify({'error': 'You do not have permission to change user roles'}), 403
    
    # Prevent changing own role
    if user_id == current_user.id:
        return jsonify({'error': 'You cannot change your own role'}), 400
    
    user = User.query.get_or_404(user_id)
    
    # Get the new role from the request
    data = request.get_json()
    new_role = data.get('role')
    
    # Validate the role
    if new_role not in ['User', 'Admin', 'GlobalAdmin']:
        return jsonify({'error': 'Invalid role specified'}), 400
    
    # Update the user's role
    user.role = new_role
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User role changed to {new_role}'}), 200

def is_allowed_email_domain(email):
    settings = Settings.query.first()
    if not settings.restrict_email_domains:
        return True
    domain = '@' + email.split('@')[1].lower()
    return AllowedDomain.query.filter_by(domain=domain).first() is not None

# API-style user management endpoints
@auth.route('/api/users', methods=['GET'])
@login_required
def api_get_users():
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'is_active': user.is_active
    } for user in users])

@auth.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def api_get_user(user_id):
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get(user_id)
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'is_active': user.is_active
    })

# Company management routes
@auth.route('/manage_companies', methods=['GET'])
@login_required
def manage_companies():
    if not current_user.is_global_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    companies = Company.query.all()
    return render_template('auth/manage_companies.html', companies=companies)

@auth.route('/company/create', methods=['GET', 'POST'])
@login_required
def create_company():
    if not current_user.is_global_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if Company.query.filter_by(name=name).first():
            flash('Company with this name already exists.', 'danger')
            return redirect(url_for('auth.create_company'))
        
        company = Company(name=name, description=description)
        db.session.add(company)
        db.session.flush()  # Flush to get the company ID
        
        # Automatically create the first API key for this company
        default_api_key = ApiKey(
            key=ApiKey.generate_key(),
            description="HO",  # Changed from "Default Site" to "HO"
            user_id=current_user.id,
            company_id=company.id,
            is_active=True
        )
        db.session.add(default_api_key)
        db.session.commit()
        
        flash(f'Company has been created with a default API key!', 'success')
        return redirect(url_for('auth.manage_companies'))
    
    return render_template('auth/create_company.html')

@auth.route('/company/<int:company_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_company(company_id):
    if not current_user.is_global_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    company = Company.query.get_or_404(company_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        # Check if another company already uses this name
        existing = Company.query.filter_by(name=name).first()
        if existing and existing.id != company_id:
            flash('Company name already in use.', 'danger')
            return redirect(url_for('auth.edit_company', company_id=company_id))
        
        company.name = name
        company.description = description
        db.session.commit()
        
        flash('Company has been updated!', 'success')
        return redirect(url_for('auth.manage_companies'))
    
    return render_template('auth/edit_company.html', company=company)

@auth.route('/company/<int:company_id>/delete', methods=['POST'])
@login_required
def delete_company(company_id):
    if not current_user.is_global_admin():
        abort(403)
    
    company = Company.query.get_or_404(company_id)
    
    # Check if company has any logs
    if Log.query.filter_by(company_id=company_id).first():
        flash('Cannot delete company with existing logs.', 'danger')
        return redirect(url_for('auth.manage_companies'))
    
    # Delete all user associations
    UserCompany.query.filter_by(company_id=company_id).delete()
    
    # Delete all API keys
    ApiKey.query.filter_by(company_id=company_id).delete()
    
    # Delete the company
    db.session.delete(company)
    db.session.commit()
    
    flash('Company has been deleted!', 'success')
    return redirect(url_for('auth.manage_companies'))

@auth.route('/company/<int:company_id>/users', methods=['GET'])
@login_required
def company_users(company_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    user_companies = UserCompany.query.filter_by(company_id=company_id).all()
    return render_template('auth/company_users.html', company=company, user_companies=user_companies)

@auth.route('/company/<int:company_id>/user/add', methods=['GET', 'POST'])
@login_required
def add_company_user(company_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        role = request.form.get('role')
        
        # Validate user visibility for company admins
        if not current_user.is_global_admin():
            # For company admins, verify they have permission to add this user
            user_company_ids = [uc.company_id for uc in current_user.companies]
            user_access = UserCompany.query.filter_by(user_id=user_id).filter(
                UserCompany.company_id.in_(user_company_ids)).first()
            
            if not user_access:
                flash('You do not have permission to add this user.', 'danger')
                return redirect(url_for('auth.company_users', company_id=company_id))
        
        # Validate role based on current user's permissions
        if not current_user.is_global_admin() and role == 'CompanyAdmin':
            # Allow company admins to designate other company admins (new functionality)
            pass
        
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.add_company_user', company_id=company_id))
        
        # Check if user is already in company
        existing = UserCompany.query.filter_by(user_id=user_id, company_id=company_id).first()
        if existing:
            flash('User is already associated with this company.', 'warning')
            return redirect(url_for('auth.company_users', company_id=company_id))
        
        user_company = UserCompany(user_id=user_id, company_id=company_id, role=role)
        db.session.add(user_company)
        db.session.commit()
        
        flash(f'User {user.username} has been added to the company!', 'success')
        return redirect(url_for('auth.company_users', company_id=company_id))
    
    # Get users not already in this company
    subquery = db.session.query(UserCompany.user_id).filter_by(company_id=company_id).subquery()
    
    if current_user.is_global_admin():
        # Global admins can see all users
        available_users = User.query.filter(~User.id.in_(subquery)).all()
    else:
        # Company admins can only see users from companies they belong to
        user_company_ids = [uc.company_id for uc in current_user.companies]
        
        # Get users who are in the same companies as the current user and not already in this company
        user_ids_shared_companies = db.session.query(UserCompany.user_id).filter(
            UserCompany.company_id.in_(user_company_ids)).distinct().subquery()
        
        available_users = User.query.filter(
            User.id.in_(user_ids_shared_companies),
            ~User.id.in_(subquery),
            User.id != current_user.id  # Exclude the current user
        ).all()
    
    return render_template('auth/add_company_user.html', company=company, users=available_users)

@auth.route('/company/<int:company_id>/user/<int:user_id>/role', methods=['POST'])
@login_required
def change_company_user_role(company_id, user_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        abort(403)
    
    user_company = UserCompany.query.filter_by(user_id=user_id, company_id=company_id).first_or_404()
    
    new_role = request.form.get('role')
    if new_role not in ['User', 'CompanyAdmin']:
        abort(400)
    
    # Allow company admins to designate other users as company admins (new functionality)
    # We've removed the global admin restriction
    
    user_company.role = new_role
    db.session.commit()
    
    flash('User role has been updated!', 'success')
    return redirect(url_for('auth.company_users', company_id=company_id))

@auth.route('/company/<int:company_id>/user/<int:user_id>/remove', methods=['POST'])
@login_required
def remove_company_user(company_id, user_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        abort(403)
    
    user_company = UserCompany.query.filter_by(user_id=user_id, company_id=company_id).first_or_404()
    
    # Only global admin can remove company admin (unless they're a company admin themselves)
    if user_company.role == 'CompanyAdmin' and not current_user.is_global_admin():
        flash('Only global administrators can remove company admins.', 'danger')
        return redirect(url_for('auth.company_users', company_id=company_id))
    
    db.session.delete(user_company)
    db.session.commit()
    
    flash('User has been removed from the company!', 'success')
    return redirect(url_for('auth.company_users', company_id=company_id))

@auth.route('/company/<int:company_id>/user/create', methods=['GET', 'POST'])
@login_required
def create_company_user(company_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions - only company admins and global admins can create users
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('A user with that username or email already exists.', 'danger')
            return redirect(url_for('auth.create_company_user', company_id=company_id))
        
        # Email domain validation if configured
        if not is_allowed_email_domain(email):
            flash('Registration is not allowed for this email domain.', 'danger')
            return redirect(url_for('auth.create_company_user', company_id=company_id))
        
        # Validate password strength
        try:
            from .forms import validate_password_strength
            validate_password_strength(password)
        except ValidationError as e:
            logger.warning(f'Password validation failed for company user creation: {str(e)}', extra={
                'username': username,
                'email': email,
                'company_id': company_id,
                'company_name': company.name,
                'current_user_id': current_user.id,
                'remote_addr': request.remote_addr
            })
            flash(f'Password validation failed: {str(e)}', 'danger')
            return redirect(url_for('auth.create_company_user', company_id=company_id))
        
        # Create new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            role='User',  # Default to regular user
            is_active=True  # Automatically activate the user
        )
        db.session.add(user)
        db.session.flush()  # Flush to get the user ID
        
        # Associate user with the company
        user_company = UserCompany(
            user_id=user.id,
            company_id=company_id,
            role='User'  # Default to regular user in the company
        )
        db.session.add(user_company)
        db.session.commit()
        
        flash(f'User {username} has been created and added to {company.name}!', 'success')
        return redirect(url_for('auth.company_users', company_id=company_id))
    
    return render_template('auth/create_company_user.html', company=company)

# Company API Keys Management
@auth.route('/company/<int:company_id>/api_keys', methods=['GET'])
@login_required
def company_api_keys(company_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('frontend.index'))
    
    api_keys = ApiKey.query.filter_by(company_id=company_id).all()
    return render_template('auth/company_api_keys.html', company=company, api_keys=api_keys)

@auth.route('/company/<int:company_id>/api_key/create', methods=['POST'])
@login_required
def create_company_api_key(company_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        abort(403)
    
    description = request.form.get('description')
    api_key = ApiKey(
        key=ApiKey.generate_key(),
        description=description,
        user_id=current_user.id,
        company_id=company_id
    )
    db.session.add(api_key)
    db.session.commit()
    
    flash('New company API key has been generated!', 'success')
    return redirect(url_for('auth.company_api_keys', company_id=company_id))

@auth.route('/company/<int:company_id>/api_key/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_company_api_key(company_id, key_id):
    company = Company.query.get_or_404(company_id)
    
    # Check permissions
    if not current_user.is_global_admin() and not current_user.is_company_admin(company_id):
        abort(403)
    
    api_key = ApiKey.query.filter_by(id=key_id, company_id=company_id).first_or_404()
    db.session.delete(api_key)
    db.session.commit()
    
    flash('API key has been deleted!', 'success')
    return redirect(url_for('auth.company_api_keys', company_id=company_id))

@auth.route('/company/<int:company_id>/download_agent', methods=['GET', 'POST'])
@login_required
def download_agent(company_id):
    # Check if user has access to this company
    user_company = UserCompany.query.filter_by(user_id=current_user.id, company_id=company_id).first()
    if not user_company and current_user.role != 'Admin' and current_user.role != 'GlobalAdmin':
        abort(403)
    
    company = Company.query.get_or_404(company_id)
    api_keys = ApiKey.query.filter_by(company_id=company_id).all()
    
    if request.method == 'POST':
        api_key_id = request.form.get('api_key')
        server_url = request.form.get('server_url')
        install_dir = request.form.get('install_dir')
        
        # Get the selected API key
        selected_api_key = ApiKey.query.get(api_key_id)
        if not selected_api_key or selected_api_key.company_id != company_id:
            flash('Invalid API key selected', 'danger')
            return redirect(url_for('auth.download_agent', company_id=company_id))
        
        # Create a ZIP file with pre-configured agent
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create config.ini file
            from flask import current_app
            
            # Get timezone from the application configuration
            app_timezone = current_app.config.get('TIMEZONE', 'UTC')
            
            config = configparser.ConfigParser()
            config['API'] = {
                'api_key': selected_api_key.key,
                'server_url': server_url,
                'debug_logs': 'false',
                'timezone': app_timezone,
                'install_dir': install_dir if install_dir else r"C:\ProgramData\UserSessionMon"
            }
            # Settings for Log retention for agent - it is in MB ( max 20 MB, 0 is No log)
            config['Logging'] = {
                'session_log_rotation_size_mb': 5,
                'error_log_rotation_size_mb': 5,
                'event_log_rotation_size_mb': 5
            }
            
            config_path = os.path.join(tmp_dir, 'config.ini')
            with open(config_path, 'w') as f:
                config.write(f)
                
            # Path to the pre-compiled agent executable
            agent_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                     'windows_agent', 'winagentUSM.exe')
            
            install_dir_display = install_dir if install_dir else r"C:\ProgramData\UserSessionMon"
            # Create installation batch script
            install_script_path = os.path.join(tmp_dir, 'install_service.bat')
            with open(install_script_path, 'w') as f:
                # Get the current directory for the config path
                f.write(f"""@echo off
REM User Session Monitor Agent Installation Script
REM This script must be run as Administrator

echo Installing User Session Monitor Agent as Windows Service...
echo.

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
) else (
    echo ERROR: This script must be run as Administrator!
    echo Right-click on this file and select "Run as administrator"
    pause
    exit /b 1
)

REM Get the current directory where the script is located
set SCRIPT_DIR=%~dp0
set CONFIG_PATH=%SCRIPT_DIR%config.ini

echo Script directory: %SCRIPT_DIR%
echo Config file path: %CONFIG_PATH%
echo.

REM Check if the executable exists
if not exist "%SCRIPT_DIR%winagentUSM.exe" (
    echo ERROR: winagentUSM.exe not found in current directory!
    pause
    exit /b 1
)

REM Check if config file exists
if not exist "%CONFIG_PATH%" (
    echo ERROR: config.ini not found in current directory!
    pause
    exit /b 1
)

REM Install the service with config file path
echo Installing service...
"%SCRIPT_DIR%winagentUSM.exe" -service install -config "%CONFIG_PATH%"
pause 2
sc query UserSessionMonService
echo -----------------------------------------------------------------
echo To uninstall the app run uninstaller script:
echo {install_dir_display}\\uninstall.bat
pause
""")
            
            # Create README file with instructions
            readme_path = os.path.join(tmp_dir, 'README.txt')
            with open(readme_path, 'w') as f:
                f.write(f"""USER SESSION MONITOR AGENT INSTALLATION INSTRUCTIONS

AUTOMATIC INSTALLATION (RECOMMENDED):
1. Extract the contents of this ZIP file to a folder on your Windows computer.
2. Right-click on "install_service.bat" and select "Run as administrator".
3. The script will automatically install and start the service.

MANUAL INSTALLATION:
1. Extract the contents of this ZIP file to a folder on your Windows computer.
2. Right-click on winagentUSM.exe and select "Run as administrator".
3. To install the agent as a Windows service, run:
   winagentUSM.exe -service install -config "path\\to\\config.ini"
   
4. The service will automatically start after installation.

Configuration:
- The agent is pre-configured with API key for {company.name}
- Server URL: {server_url}
- Timezone: {app_timezone}
- Installation directory: {install_dir_display}
- Config file will be created at: {install_dir_display}\\config.ini

Service Management:
- Start service: sc start "User Session Monitor"
- Stop service: sc stop "User Session Monitor"  
- Check status: sc query "User Session Monitor"
- Uninstall service: winagentUSM.exe -service uninstall

If you need to change settings later, edit the config file or use the command line:
- winagentUSM.exe --api-key <key> 
- winagentUSM.exe --url <url>
- winagentUSM.exe --debug true|false
- winagentUSM.exe --timezone <timezone>
""")
            
            # Create the ZIP file
            zip_path = os.path.join(tmp_dir, f'{company.name.replace(" ", "_")}_agent.zip')
            with zipfile.ZipFile(zip_path, 'w') as zip_file:
                # If agent executable exists, add it
                if os.path.exists(agent_path):
                    zip_file.write(agent_path, arcname='winagentUSM.exe')
                else:
                    flash('Pre-compiled agent not found. Please contact administrator.', 'danger')
                    return redirect(url_for('auth.download_agent', company_id=company_id))
                
                zip_file.write(config_path, arcname='config.ini')
                zip_file.write(readme_path, arcname='README.txt')
                zip_file.write(install_script_path, arcname='install_service.bat')
            
            # Send the ZIP file to the user
            return send_file(
                zip_path,
                as_attachment=True,
                download_name=f'{company.name.replace(" ", "_")}_agent.zip',
                mimetype='application/zip'
            )
    
    # Default server URL is the current request URL's base
    default_url = request.url_root.rstrip('/')
    
    return render_template(
        'auth/download_agent.html', 
        company=company, 
        api_keys=api_keys,
        default_url=default_url
    )

# User-Company Management Routes for manage_users page
@auth.route('/admin/user/<int:user_id>/companies/add', methods=['POST'])
@login_required
def add_user_to_company(user_id):
    """Add a user to a company from the manage_users page"""
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        return jsonify({'error': 'You do not have permission to manage user companies'}), 403
    
    user = User.query.get_or_404(user_id)
    company_id = request.json.get('company_id')
    company_role = request.json.get('role', 'User')
    
    # Validate company role
    if company_role not in ['User', 'CompanyAdmin']:
        return jsonify({'error': 'Invalid company role'}), 400
    
    # Permission checks
    if not current_user.is_global_admin():
        # Regular Admin users have restrictions
        # 1. Cannot modify GlobalAdmin accounts
        if user.role == 'GlobalAdmin':
            return jsonify({'error': 'You do not have permission to modify GlobalAdmin accounts'}), 403
        
        # 2. Can only add users to companies they belong to
        admin_company_ids = [uc.company_id for uc in current_user.companies]
        if company_id not in admin_company_ids:
            return jsonify({'error': 'You can only add users to companies you belong to'}), 403
        
        # 3. Cannot assign CompanyAdmin role (only GlobalAdmin can)
        if company_role == 'CompanyAdmin':
            return jsonify({'error': 'You do not have permission to assign CompanyAdmin role'}), 403
    
    # Check if company exists
    company = Company.query.get(company_id)
    if not company:
        return jsonify({'error': 'Company not found'}), 404
    
    # Check if user is already in the company
    existing = UserCompany.query.filter_by(user_id=user_id, company_id=company_id).first()
    if existing:
        return jsonify({'error': 'User is already in this company'}), 400
    
    # Add user to company
    user_company = UserCompany(user_id=user_id, company_id=company_id, role=company_role)
    db.session.add(user_company)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'User added to {company.name} as {company_role}',
        'company_name': company.name,
        'role': company_role
    })

@auth.route('/admin/user/<int:user_id>/companies/<int:company_id>/remove', methods=['POST'])
@login_required
def remove_user_from_company(user_id, company_id):
    """Remove a user from a company from the manage_users page"""
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        return jsonify({'error': 'You do not have permission to manage user companies'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Permission checks
    if not current_user.is_global_admin():
        # Regular Admin users have restrictions
        # 1. Cannot modify GlobalAdmin accounts
        if user.role == 'GlobalAdmin':
            return jsonify({'error': 'You do not have permission to modify GlobalAdmin accounts'}), 403
        
        # 2. Can only remove users from companies they belong to
        admin_company_ids = [uc.company_id for uc in current_user.companies]
        if company_id not in admin_company_ids:
            return jsonify({'error': 'You can only remove users from companies you belong to'}), 403
    
    # Find the user-company association
    user_company = UserCompany.query.filter_by(user_id=user_id, company_id=company_id).first()
    if not user_company:
        return jsonify({'error': 'User is not in this company'}), 404
    
    company_name = user_company.company.name
    
    # Remove user from company
    db.session.delete(user_company)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'User removed from {company_name}'
    })

@auth.route('/admin/user/<int:user_id>/companies/<int:company_id>/role', methods=['POST'])
@login_required
def change_user_company_role(user_id, company_id):
    """Change a user's role in a company from the manage_users page"""
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        return jsonify({'error': 'You do not have permission to manage user companies'}), 403
    
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    # Validate role
    if new_role not in ['User', 'CompanyAdmin']:
        return jsonify({'error': 'Invalid company role'}), 400
    
    # Permission checks
    if not current_user.is_global_admin():
        # Regular Admin users have restrictions
        # 1. Cannot modify GlobalAdmin accounts
        if user.role == 'GlobalAdmin':
            return jsonify({'error': 'You do not have permission to modify GlobalAdmin accounts'}), 403
        
        # 2. Can only modify users in companies they belong to
        admin_company_ids = [uc.company_id for uc in current_user.companies]
        if company_id not in admin_company_ids:
            return jsonify({'error': 'You can only modify users in companies you belong to'}), 403
        
        # 3. Cannot assign CompanyAdmin role (only GlobalAdmin can)
        if new_role == 'CompanyAdmin':
            return jsonify({'error': 'You do not have permission to assign CompanyAdmin role'}), 403
    
    # Find the user-company association
    user_company = UserCompany.query.filter_by(user_id=user_id, company_id=company_id).first()
    if not user_company:
        return jsonify({'error': 'User is not in this company'}), 404
    
    # Update role
    user_company.role = new_role
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'User role changed to {new_role} in {user_company.company.name}'
    })

@auth.route('/admin/companies/create', methods=['POST'])
@login_required
def create_company_from_manage_users():
    """Create a new company from the manage_users page (GlobalAdmin only)"""
    if not current_user.is_global_admin():
        return jsonify({'error': 'Only GlobalAdmin can create new companies'}), 403
    
    company_name = request.json.get('name', '').strip()
    company_description = request.json.get('description', '').strip()
    
    if not company_name:
        return jsonify({'error': 'Company name is required'}), 400
    
    # Check if company already exists
    existing = Company.query.filter_by(name=company_name).first()
    if existing:
        return jsonify({'error': 'A company with this name already exists'}), 400
    
    # Create new company
    company = Company(name=company_name, description=company_description)
    db.session.add(company)
    db.session.flush()  # Flush to get the company ID
    
    # Automatically create the first API key for this company named "HO"
    default_api_key = ApiKey(
        key=ApiKey.generate_key(),
        description="HO",  # Use "HO" instead of "Default Site"
        user_id=current_user.id,
        company_id=company.id,
        is_active=True
    )
    db.session.add(default_api_key)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Company "{company_name}" created successfully with default API key',
        'company_id': company.id,
        'company_name': company.name
    })

@auth.route('/admin/companies/list', methods=['GET'])
@login_required
def get_companies_for_user_management():
    """Get list of companies that the current user can assign users to"""
    if not current_user.is_global_admin() and current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if current_user.is_global_admin():
        # GlobalAdmin can see all companies
        companies = Company.query.all()
    else:
        # Regular Admin can only see companies they belong to
        admin_company_ids = [uc.company_id for uc in current_user.companies]
        companies = Company.query.filter(Company.id.in_(admin_company_ids)).all()
    
    return jsonify({
        'companies': [
            {
                'id': company.id,
                'name': company.name,
                'description': company.description or ''
            }
            for company in companies
        ]
    })

# Add per-user MFA requirement management routes
@auth.route('/admin/user/<int:user_id>/mfa_requirement', methods=['POST'])
@login_required
def update_user_mfa_requirement(user_id):
    """Update MFA requirement for a specific user (GlobalAdmin only)"""
    if not current_user.is_global_admin():
        return jsonify({'error': 'Only GlobalAdmin can modify per-user MFA requirements'}), 403
    
    user = User.query.get_or_404(user_id)
    mfa_required = request.json.get('mfa_required')
    
    # Validate input
    if mfa_required not in [None, True, False]:
        return jsonify({'error': 'Invalid MFA requirement value'}), 400
    
    user.mfa_required = mfa_required
    db.session.commit()
    
    # Return appropriate message
    if mfa_required is None:
        message = f'MFA requirement for {user.username} set to inherit from global setting'
    elif mfa_required:
        message = f'MFA requirement enabled for {user.username}'
    else:
        message = f'MFA requirement disabled for {user.username}'
    
    return jsonify({'success': True, 'message': message})

# Error logs management for GlobalAdmins
@auth.route('/admin/error_logs')
@login_required
def view_error_logs():
    """View application error logs (GlobalAdmin only)"""
    if not current_user.is_global_admin():
        flash('Access denied. GlobalAdmin privileges required.', 'danger')
        return redirect(url_for('frontend.index'))
    
    from api.models import ErrorLog
    from datetime import datetime, timedelta
    
    # Get date range from request parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    level_filter = request.args.get('level', '')
    
    # Default to last 7 days if no dates provided
    if not start_date:
        start_date = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
    if not end_date:
        end_date = datetime.utcnow().strftime('%Y-%m-%d')
    
    # Build query
    query = ErrorLog.query
    
    # Apply date filters
    try:
        start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
        end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(ErrorLog.timestamp >= start_datetime, ErrorLog.timestamp < end_datetime)
    except ValueError:
        logger.warning(f'Invalid date format in error log view: start_date={start_date}, end_date={end_date}', extra={
            'current_user_id': current_user.id,
            'remote_addr': request.remote_addr
        })
        flash('Invalid date format. Using default last 7 days.', 'warning')
        start_date = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
        end_date = datetime.utcnow().strftime('%Y-%m-%d')
        start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
        end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(ErrorLog.timestamp >= start_datetime, ErrorLog.timestamp < end_datetime)
    
    # Apply level filter
    if level_filter:
        query = query.filter(ErrorLog.level == level_filter)
    
    # Order by most recent first
    error_logs = query.order_by(ErrorLog.timestamp.desc()).all()
    
    # Get available log levels for filter dropdown
    available_levels = db.session.query(ErrorLog.level).distinct().all()
    available_levels = [level[0] for level in available_levels]
    
    return render_template('auth/error_logs.html', 
                         error_logs=error_logs,
                         start_date=start_date,
                         end_date=end_date,
                         level_filter=level_filter,
                         available_levels=available_levels)

@auth.route('/admin/error_logs/<int:log_id>')
@login_required
def view_error_log_detail(log_id):
    """View detailed error log (GlobalAdmin only)"""
    if not current_user.is_global_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    from api.models import ErrorLog
    error_log = ErrorLog.query.get_or_404(log_id)
    
    return jsonify({
        'id': error_log.id,
        'level': error_log.level,
        'logger_name': error_log.logger_name,
        'message': error_log.message,
        'timestamp': error_log.timestamp.isoformat(),
        'pathname': error_log.pathname,
        'lineno': error_log.lineno,
        'request_id': error_log.request_id,
        'user_id': error_log.user_id,
        'remote_addr': error_log.remote_addr,
        'exception': error_log.exception
    })

@auth.route('/admin/error_logs/clear', methods=['POST'])
@login_required
def clear_error_logs():
    """Clear old error logs (GlobalAdmin only)"""
    if not current_user.is_global_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    from api.models import ErrorLog
    from datetime import datetime, timedelta
    
    # Get the cutoff date (default: clear logs older than 30 days)
    days_to_keep = request.json.get('days_to_keep', 30)
    
    try:
        days_to_keep = int(days_to_keep)
        if days_to_keep < 0:
            return jsonify({'error': 'Days to keep cannot be negative'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid days_to_keep value'}), 400
    
    # Handle clearing all logs when days_to_keep is 0
    if days_to_keep == 0:
        # Clear all error logs
        deleted_count = ErrorLog.query.delete()
        db.session.commit()
        
        # Log the administrative action for clearing all logs
        logger.info(f'Admin {current_user.username} (ID: {current_user.id}) cleared ALL {deleted_count} error logs', extra={
            'current_user_id': current_user.id,
            'current_username': current_user.username,
            'action': 'clear_all_error_logs',
            'deleted_count': deleted_count,
            'remote_addr': request.remote_addr
        })
        
        return jsonify({
            'success': True,
            'message': f'Deleted all {deleted_count} error logs',
            'deleted_count': deleted_count
        })
    else:
        # Clear logs older than specified days
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        deleted_count = ErrorLog.query.filter(ErrorLog.timestamp < cutoff_date).delete()
        db.session.commit()
        
        # Log the administrative action for clearing old logs
        logger.info(f'Admin {current_user.username} (ID: {current_user.id}) cleared {deleted_count} error logs older than {days_to_keep} days', extra={
            'current_user_id': current_user.id,
            'current_username': current_user.username,
            'action': 'clear_old_error_logs',
            'days_to_keep': days_to_keep,
            'deleted_count': deleted_count,
            'cutoff_date': cutoff_date.isoformat(),
            'remote_addr': request.remote_addr
        })
        
        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} error logs older than {days_to_keep} days',
            'deleted_count': deleted_count
        })