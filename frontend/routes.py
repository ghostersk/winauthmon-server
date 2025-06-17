from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from auth.models import User, Company, UserCompany, ApiKey
from api.models import Log
from extensions import db
from datetime import datetime, timedelta
from sqlalchemy import or_
import pytz
import logging

# Initialize logger for this module
logger = logging.getLogger(__name__)

frontend = Blueprint('frontend', __name__)

frontend_bp = frontend

@frontend.route('/')
@frontend.route('/home')
def index():
    try:
        return render_template('frontend/home.html')
    except Exception as e:
        logger.exception("Home page error from IP %s: %s", request.remote_addr, str(e))
        flash('An error occurred while loading the home page.', 'error')
        return render_template('frontend/home.html')  # Fallback to basic template

@frontend.route('/about')
def about():
    try:
        return render_template('frontend/about.html')
    except Exception as e:
        logger.exception("About page error from IP %s: %s", request.remote_addr, str(e))
        flash('An error occurred while loading the about page.', 'error')
        return render_template('frontend/about.html')  # Fallback to basic template

@frontend.route('/profile')
@login_required
def profile():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        return render_template('frontend/profile.html', user=user)
    except Exception as e:
        logger.exception(
            "Profile page error for user %s (ID: %s) from IP %s: %s",
            current_user.username if current_user.is_authenticated else 'anonymous',
            current_user.id if current_user.is_authenticated else 'N/A',
            request.remote_addr,
            str(e)
        )
        flash('An error occurred while loading your profile. Please try again.', 'error')
        return redirect(url_for('frontend.index'))

@frontend.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get app timezone
        app_tz = pytz.timezone(current_app.config['TIMEZONE'])
        
        # Get date range from request or default to last 48 hours
        date_range = request.args.get('daterange')
        
        if date_range:
            start_str, end_str = date_range.split(' - ')
            start_date = datetime.strptime(start_str, '%Y-%m-%d %H:%M')
            end_date = datetime.strptime(end_str, '%Y-%m-%d %H:%M')
            
            # Make these timezone aware using the app's timezone
            start_date = app_tz.localize(start_date)
            end_date = app_tz.localize(end_date)
        else:
            end_date = datetime.now(app_tz) + timedelta(hours=1)  # Include 1 hour in the future
            start_date = end_date - timedelta(hours=49)  # Look back 48 hours from future end time

        # Get companies for the dropdown filter based on user role, ordered by name
        if current_user.is_global_admin():
            # GlobalAdmin can see all companies
            companies = Company.query.order_by(Company.name).all()
        else:
            # Get user's companies, ordered by name
            user_company_ids = [uc.company_id for uc in current_user.companies]
            companies = Company.query.filter(Company.id.in_(user_company_ids)).order_by(Company.name).all()

        # Get company filter if provided, otherwise use first available company
        company_id = request.args.get('company_id', type=int)
        if not company_id and companies:
            company_id = companies[0].id  # Default to first company

        # Convert timezone-aware dates to naive for comparison with database timestamps
        start_date_naive = start_date.replace(tzinfo=None)
        end_date_naive = end_date.replace(tzinfo=None)
        
        # Use joinedload to eagerly load the API key and company relationships
        query = Log.query.options(
            db.joinedload(Log.api_key),
            db.joinedload(Log.company)
        ).filter(Log.timestamp.between(start_date_naive, end_date_naive))
        
        # Apply company-specific filtering
        if current_user.is_global_admin():
            # GlobalAdmin with specific company selected
            if company_id:
                query = query.filter(Log.company_id == company_id)
        else:
            # Regular users always need company filtering
            user_company_ids = [uc.company_id for uc in current_user.companies]
            if company_id and company_id in user_company_ids:
                query = query.filter(Log.company_id == company_id)
            else:
                query = query.filter(Log.company_id.in_(user_company_ids))
        
        # Get the logs ordered by timestamp (newest first)
        logs = query.order_by(Log.timestamp.desc()).all()

        return render_template('frontend/dashboard.html', 
                              title='Dashboard', 
                              logs=logs,
                              start_date=start_date,
                              end_date=end_date,
                              companies=companies,
                              selected_company_id=company_id)
    
    except Exception as e:
        logger.exception(
            "Dashboard error for user %s (ID: %s, role: %s) from IP %s: %s",
            current_user.username if current_user.is_authenticated else 'anonymous',
            current_user.id if current_user.is_authenticated else 'N/A',
            current_user.role if current_user.is_authenticated else 'N/A',
            request.remote_addr,
            str(e)
        )
        flash('An error occurred while loading the dashboard. Please try again.', 'error')
        return redirect(url_for('frontend.index'))

@frontend.route('/time_spent_report')
@login_required
def time_spent_report():
    try:
        # Get app timezone
        app_tz = pytz.timezone(current_app.config['TIMEZONE'])
        
        # Get date range from request or default to last 7 days
        date_range = request.args.get('daterange')
        
        if date_range:
            start_str, end_str = date_range.split(' - ')
            start_date = datetime.strptime(start_str, '%Y-%m-%d %H:%M')
            end_date = datetime.strptime(end_str, '%Y-%m-%d %H:%M')
            
            # Make these timezone aware using the app's timezone
            start_date = app_tz.localize(start_date)
            end_date = app_tz.localize(end_date)
        else:
            end_date = datetime.now(app_tz) + timedelta(hours=1)  # Include 1 hour in the future
            start_date = end_date - timedelta(days=7, hours=1)  # Look back 7 days from future end time

        # Get filters
        company_id = request.args.get('company_id', type=int)
        api_key_id = request.args.get('api_key_id', type=int)
        group_by = request.args.get('group_by', 'user')  # Default to user grouping
        continue_iterate = request.args.get('continue_iterate') == 'on'  # Get checkbox value
        
        # Build base query with date range filter
        from auth.models import ApiKey, Company
        
        # Start with all the login/logout events within the date range
        # Convert timezone-aware dates to naive for comparison with database timestamps
        start_date_naive = start_date.replace(tzinfo=None)
        end_date_naive = end_date.replace(tzinfo=None)        
        logs_query = Log.query.filter(
            Log.timestamp.between(start_date_naive, end_date_naive)
        ).order_by(Log.timestamp.asc())
        
        # Apply company-specific filtering based on user role
        if current_user.is_global_admin():
            # GlobalAdmin should be allowed to see all records, no matter what company/site
            if company_id:
                logs_query = logs_query.filter(Log.company_id == company_id)
            # If no company_id specified, show all logs (no additional filtering)
        else:
            # CompanyAdmin and User should see only company log events for companies they are member of
            user_company_ids = [uc.company_id for uc in current_user.companies]
            
            if not user_company_ids:
                # If user has no company associations, show no logs
                logs_query = logs_query.filter(Log.id == -1)  # Impossible condition = no results
            else:
                if company_id and company_id in user_company_ids:
                    # Filter by the specific company if requested and user has access
                    logs_query = logs_query.filter(Log.company_id == company_id)
                else:
                    # Show logs from all companies the user has access to
                    logs_query = logs_query.filter(Log.company_id.in_(user_company_ids))
        
        # Apply API key filter if provided
        if api_key_id:
            # Ensure the API key belongs to a company the user has access to
            api_key = ApiKey.query.get(api_key_id)
            if api_key:
                if current_user.is_global_admin():
                    # GlobalAdmin can use any API key
                    logs_query = logs_query.filter(Log.api_key_id == api_key_id)
                else:
                    # Check if the API key belongs to a company the user has access to
                    user_company_ids = [uc.company_id for uc in current_user.companies]
                    if api_key.company_id in user_company_ids:
                        logs_query = logs_query.filter(Log.api_key_id == api_key_id)
                    # If API key doesn't belong to user's company, ignore the filter
        
        # Get all the relevant logs
        logs = logs_query.all()
        
        # Process logs to calculate time spent
        time_data = calculate_time_spent(logs, group_by, continue_iterate)
        
        # Get all companies for the dropdown filter
        if current_user.is_global_admin():
            companies = Company.query.all()
        else:
            companies = current_user.get_companies()
        
        # Get available API keys for filter
        if current_user.is_global_admin():
            api_keys = ApiKey.query.all()
        else:
            # Get API keys for companies user has access to
            user_company_ids = [uc.company_id for uc in current_user.companies]
            api_keys = ApiKey.query.filter(ApiKey.company_id.in_(user_company_ids)).all()

        return render_template('frontend/time_spent_report.html', 
                              title='Time Spent Report', 
                              time_data=time_data,
                              start_date=start_date,
                              end_date=end_date,
                              companies=companies,
                              api_keys=api_keys,
                              selected_company_id=company_id,
                              selected_api_key_id=api_key_id,
                              group_by=group_by,
                              continue_iterate=continue_iterate)
    
    except Exception as e:
        logger.exception(
            "Time spent report error for user %s (ID: %s, role: %s) from IP %s: %s",
            current_user.username if current_user.is_authenticated else 'anonymous',
            current_user.id if current_user.is_authenticated else 'N/A',
            current_user.role if current_user.is_authenticated else 'N/A',
            request.remote_addr,
            str(e)
        )
        flash('An error occurred while generating the time spent report. Please try again.', 'error')
        return redirect(url_for('frontend.dashboard'))

def calculate_time_spent(logs, group_by='user', continue_iterate=False):
    """
    Calculate time spent by users based on login/logout events.
    
    Args:
        logs: List of Log objects sorted by timestamp
        group_by: Whether to group by 'user' or 'user_computer'
        continue_iterate: Whether to continue iterating for additional login/logout pairs
        
    Returns:
        List of dictionaries with time spent information
    """
    from auth.models import Company, ApiKey
    
    # Dictionary to track user sessions
    # Key: user_name or user_name+computer_name depending on group_by
    # Value: dictionary with session tracking info
    active_sessions = {}
    
    # Dictionary to accumulate total time spent
    # Key: date + user_name + (computer_name) + company_id
    # Value: dictionary with accumulated time and session details
    time_totals = {}
    
    # Define login and logout event types - case-insensitive matching
    login_events = ['login', 'unlock', 'logon']  # Events that start a session
    logout_events = ['logout', 'lock', 'logoff']  # Events that end a session
    
    # Create a set to track which users have appeared in logs
    seen_users = set()
    
    # First pass: populate the time_totals dictionary with user entries
    # This ensures every user has an entry even if they don't have paired login/logout events
    for log in logs:
        # Determine the session key based on grouping option
        session_key = log.user_name
        if group_by == 'user_computer':
            session_key = f"{log.user_name}:{log.computer_name}"
        
        # Get date string in format YYYY-MM-DD
        log_date = log.timestamp.strftime('%Y-%m-%d')
        
        # Create a unique key for the time totals
        total_key = f"{log_date}:{session_key}:{log.company_id}"
        
        # Initialize the time total entry if it doesn't exist
        if total_key not in time_totals:
            # Get company info
            company = Company.query.get(log.company_id) if log.company_id else None
            company_name = company.name if company else "Unknown"
            
            # Get API key info
            api_key = ApiKey.query.get(log.api_key_id) if log.api_key_id else None
            api_key_description = api_key.description if api_key else "Unknown"
            
            # Initialize with zero time
            time_totals[total_key] = {
                'date': log_date,
                'user_name': log.user_name,
                'computer_name': log.computer_name if group_by == 'user_computer' else None,
                'company_id': log.company_id,
                'company_name': company_name,
                'api_key_id': log.api_key_id,
                'api_key_description': api_key_description,
                'total_seconds': 0,
                'first_login': None,
                'last_logout': None,
                'session_count': 0
            }
            
            # Track that we've seen this user
            seen_users.add(log.user_name)
            
        # Update login/logout timestamps even if we can't calculate duration
        event_type = log.event_type.lower() if log.event_type else ''
        
        # For all users, record their first login and last logout
        if event_type in login_events:
            if not time_totals[total_key]['first_login'] or log.timestamp < time_totals[total_key]['first_login']:
                time_totals[total_key]['first_login'] = log.timestamp
        
        if event_type in logout_events:
            if not time_totals[total_key]['last_logout'] or log.timestamp > time_totals[total_key]['last_logout']:
                time_totals[total_key]['last_logout'] = log.timestamp
    
    # Second pass: calculate session durations
    for log_index, log in enumerate(logs):
        # Determine the session key based on grouping option
        session_key = log.user_name
        if group_by == 'user_computer':
            session_key = f"{log.user_name}:{log.computer_name}"
        
        # Get date string in format YYYY-MM-DD
        log_date = log.timestamp.strftime('%Y-%m-%d')
        
        # Create a unique key for the time totals
        total_key = f"{log_date}:{session_key}:{log.company_id}"
        
        # Convert event_type to lowercase for case-insensitive comparison
        event_type = log.event_type.lower() if log.event_type else ''
        
        # Process any login-like event
        if event_type in login_events:
            # Record login time for this session
            active_sessions[session_key] = {
                'login_time': log.timestamp,
                'log_index': log_index,
                'company_id': log.company_id,
                'date': log_date
            }
        
        # Process any logout-like event
        elif event_type in logout_events and session_key in active_sessions:
            session = active_sessions[session_key]
            
            # Only process if session is from the same day and company
            if session['date'] == log_date and session['company_id'] == log.company_id:
                # Calculate duration of this session
                duration = (log.timestamp - session['login_time']).total_seconds()
                
                # Only count if duration is positive and reasonable (< 24 hours)
                if 0 < duration < 86400:  # 24 hours = 86400 seconds
                    # Add to the total time for this user/day combination
                    time_totals[total_key]['total_seconds'] += duration
                    time_totals[total_key]['session_count'] += 1
                
                # If we should continue iterating, leave the session active to match with future login events
                # Otherwise, remove the active session after processing
                if not continue_iterate:
                    del active_sessions[session_key]
            else:
                # If the session doesn't match day/company, remove it if we're not continuing to iterate
                if not continue_iterate:
                    del active_sessions[session_key]
    
    # Special case: If we only have one event of each type per user per day,
    # calculate duration between first login and last logout
    for total_key, entry in time_totals.items():
        if entry['session_count'] == 0 and entry['first_login'] and entry['last_logout']:
            # Calculate duration between first login and last logout
            duration = (entry['last_logout'] - entry['first_login']).total_seconds()
            
            # Only use if duration is positive and reasonable
            if 0 < duration < 86400:  # 24 hours = 86400 seconds
                entry['total_seconds'] += duration
                entry['session_count'] = 1
    
    # Convert the time_totals dictionary to a list of dictionaries
    result = []
    for entry in time_totals.values():
        # Format the total time as hours:minutes:seconds
        hours, remainder = divmod(entry['total_seconds'], 3600)
        minutes, seconds = divmod(remainder, 60)
        entry['formatted_time'] = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        
        result.append(entry)
    
    # Sort by date (newest first) and then by user_name
    result.sort(key=lambda x: (x['date'], x['user_name']), reverse=True)
    
    return result