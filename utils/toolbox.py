"""
Timezone utility functions for the Domain Logons application.

This module provides timezone-related utilities that can be used throughout
the application without causing circular import issues.
"""

from datetime import datetime, timezone
import pytz


def get_app_timezone():
    """Get the application timezone from config."""
    try:
        # Try to get app from Flask context first
        from flask import current_app
        app = current_app._get_current_object()
        if app and hasattr(app, 'config'):
            tz_name = app.config.get('TIMEZONE', 'Europe/London')
            return pytz.timezone(tz_name)
    except RuntimeError:
        # No application context, try to get config from os.environ or config file
        try:
            import configparser
            import os
            config = configparser.ConfigParser()
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
            if os.path.exists(config_path):
                config.read(config_path)
                tz_name = config.get('app', 'TIMEZONE', fallback='Europe/London')
                return pytz.timezone(tz_name)
        except Exception:
            pass
    except Exception:
        pass
    # Fallback to UTC
    return pytz.UTC


def get_current_timestamp():
    """Get current timestamp in the application's configured timezone."""
    app_tz = get_app_timezone()
    # Use timezone.utc instead of deprecated utcnow()
    utc_now = datetime.now(timezone.utc)
    # Convert to application timezone
    return utc_now.astimezone(app_tz).replace(tzinfo=None)  # Store as naive datetime in app timezone


def get_utc_timestamp():
    """Get current UTC timestamp as timezone-aware datetime."""
    return datetime.now(timezone.utc)


def convert_to_app_timezone(dt):
    """
    Convert a datetime to the application's configured timezone.
    
    Args:
        dt: datetime object (can be naive or timezone-aware)
        
    Returns:
        datetime: timezone-aware datetime in application timezone
    """
    app_tz = get_app_timezone()
    
    if dt.tzinfo is None:
        # If naive, assume it's already in the application timezone
        return app_tz.localize(dt)
    else:
        # If timezone-aware, convert to application timezone
        return dt.astimezone(app_tz)


def format_timestamp_for_display(dt):
    """
    Format a datetime for display with timezone information.
    
    Args:
        dt: datetime object
        
    Returns:
        str: formatted timestamp string
    """
    if dt is None:
        return ""
    
    # Convert to app timezone if needed
    if dt.tzinfo is None:
        # Assume naive datetime is already in app timezone
        app_tz = get_app_timezone()
        localized_dt = app_tz.localize(dt)
    else:
        # Convert timezone-aware datetime to app timezone
        localized_dt = convert_to_app_timezone(dt)
    
    return localized_dt.strftime('%Y-%m-%d %H:%M:%S %Z')


def get_filtered_loggers():
    """
    Get list of logger names that should be filtered out of database logging.
    This helps prevent feedback loops and reduces noise.
    """
    default_filters = []
    
    try:
        # Try to get app from Flask context first
        from flask import current_app
        app = current_app._get_current_object()
        if app and hasattr(app, 'config'):
            # Get filters from app config (which loads from config.ini)
            filter_string = app.config.get('DB_LOGGING_FILTERED_LOGGERS', '')
            if filter_string:
                return [logger.strip() for logger in filter_string.split(',') if logger.strip()]
    except RuntimeError:
        # No application context, try to read config directly
        try:
            import configparser
            import os
            config = configparser.ConfigParser()
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
            if os.path.exists(config_path):
                config.read(config_path)
                filter_string = config.get('logging', 'DB_LOGGING_FILTERED_LOGGERS', fallback='')
                if filter_string:
                    return [logger.strip() for logger in filter_string.split(',') if logger.strip()]
        except Exception:
            pass
    except Exception:
        pass
    
    # Fallback defaults if config not available
    return [
        'watchfiles.main',
        'watchfiles.watcher', 
        'watchdog',
        'uvicorn.access'
    ]


def get_filtered_message_patterns():
    """
    Get list of message patterns that should be filtered out of database logging.
    """
    default_patterns = []
    
    try:
        # Try to get app from Flask context first
        from flask import current_app
        app = current_app._get_current_object()
        if app and hasattr(app, 'config'):
            # Get patterns from app config (which loads from config.ini)
            pattern_string = app.config.get('DB_LOGGING_FILTERED_PATTERNS', '')
            if pattern_string:
                return [pattern.strip() for pattern in pattern_string.split(',') if pattern.strip()]
    except RuntimeError:
        # No application context, try to read config directly
        try:
            import configparser
            import os
            config = configparser.ConfigParser()
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
            if os.path.exists(config_path):
                config.read(config_path)
                pattern_string = config.get('logging', 'DB_LOGGING_FILTERED_PATTERNS', fallback='')
                if pattern_string:
                    return [pattern.strip() for pattern in pattern_string.split(',') if pattern.strip()]
        except Exception:
            pass
    except Exception:
        pass
    
    # Fallback defaults if config not available
    return [
        'database.db',
        'instance/',
        'file changed',
        'reloading'
    ]
