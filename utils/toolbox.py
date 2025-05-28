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


def generate_secret_key():
    """Generate a secure random secret key for Flask"""
    import secrets
    return secrets.token_hex(32)


def ensure_secure_secret_key(config):
    """
    Ensure config has a secure secret key, generate if needed.
    
    Args:
        config: ConfigParser object
        
    Returns:
        bool: True if key was generated/updated, False if existing key was secure
    """
    import logging
    
    logger = logging.getLogger(__name__)
    
    current_key = config.get('app', 'SECRET_KEY', fallback='')
    
    # List of insecure keys that should be replaced
    insecure_keys = [
        '',
        'your_secret_key',
        'your_secret_key_change_this_in_production',
        'dev',
        'development',
        'changeme',
        'insecure'
    ]
    
    if current_key in insecure_keys or len(current_key) < 32:
        new_key = generate_secret_key()
        if not config.has_section('app'):
            config.add_section('app')
        config.set('app', 'SECRET_KEY', new_key)
        logger.info("Generated new secure secret key")
        return True
    
    return False


def generate_ssl_certificates(cert_dir, cert_file='cert.pem', key_file='key.pem', 
                            country='XX', state='StateName', city='CityName', 
                            org='CompanyName', org_unit='CompanySectionName', 
                            common_name='localhost'):
    """
    Generate self-signed SSL certificates if they don't exist.
    
    Args:
        cert_dir: Directory to store certificates
        cert_file: Certificate filename (default: cert.pem)
        key_file: Private key filename (default: key.pem)
        country: Country code (default: XX)
        state: State name (default: StateName)
        city: City name (default: CityName)
        org: Organization name (default: CompanyName)
        org_unit: Organizational unit (default: CompanySectionName)
        common_name: Common name/hostname (default: localhost)
    
    Returns:
        tuple: (cert_path, key_path, was_generated)
    """
    import os
    import subprocess
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Ensure certificate directory exists
    os.makedirs(cert_dir, exist_ok=True)
    
    cert_path = os.path.join(cert_dir, cert_file)
    key_path = os.path.join(cert_dir, key_file)
    
    # Check if certificates already exist and are valid
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Check if files are not empty
        if os.path.getsize(cert_path) > 0 and os.path.getsize(key_path) > 0:
            logger.info(f"SSL certificates already exist at {cert_path} and {key_path}")
            return cert_path, key_path, False
    
    logger.info("Generating self-signed SSL certificates...")
    
    try:
        # Build the subject string
        subject = f"/C={country}/ST={state}/L={city}/O={org}/OU={org_unit}/CN={common_name}"
        
        # Generate certificate using openssl
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path,
            '-out', cert_path,
            '-sha256', '-days', '3650',
            '-nodes',
            '-subj', subject
        ]
        
        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Verify files were created successfully
        if os.path.exists(cert_path) and os.path.exists(key_path):
            # Set appropriate file permissions (readable by owner only for key)
            os.chmod(key_path, 0o600)  # Private key: owner read/write only
            os.chmod(cert_path, 0o644)  # Certificate: owner read/write, others read
            
            logger.info(f"✅ SSL certificates generated successfully:")
            logger.info(f"   Certificate: {cert_path}")
            logger.info(f"   Private key: {key_path}")
            logger.info(f"   Valid for: 3650 days (10 years)")
            logger.info(f"   Common Name: {common_name}")
            
            return cert_path, key_path, True
        else:
            logger.error("Certificate generation failed - files not created")
            return None, None, False
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate SSL certificates: {e}")
        logger.error(f"OpenSSL stderr: {e.stderr}")
        return None, None, False
    except FileNotFoundError:
        logger.error("OpenSSL not found. Please install OpenSSL to generate SSL certificates.")
        logger.info("On Ubuntu/Debian: sudo apt-get install openssl")
        logger.info("On CentOS/RHEL: sudo yum install openssl")
        logger.info("On macOS: brew install openssl")
        return None, None, False
    except Exception as e:
        logger.error(f"Unexpected error generating SSL certificates: {e}")
        return None, None, False


def ensure_ssl_certificates(config, app_dir):
    """
    Ensure SSL certificates exist, generate them if they don't.
    
    Args:
        config: ConfigParser object with SSL configuration
        app_dir: Application directory path
        
    Returns:
        tuple: (cert_path, key_path, ssl_enabled)
    """
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Ensure required sections exist
    if not config.has_section('server'):
        config.add_section('server')
    if not config.has_section('ssl'):
        config.add_section('ssl')
    
    # Get SSL configuration from config with proper fallbacks
    ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback=None)
    ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback=None)
    auto_generate_ssl = config.getboolean('server', 'AUTO_GENERATE_SSL', fallback=True)
    
    # If SSL is not configured, set default paths
    if not ssl_certfile or not ssl_keyfile:
        cert_dir = os.path.join(app_dir, 'instance', 'certs')
        ssl_certfile = os.path.join(cert_dir, 'cert.pem')
        ssl_keyfile = os.path.join(cert_dir, 'key.pem')
        
        # Set default paths in config
        config.set('server', 'SSL_CERTFILE', ssl_certfile)
        config.set('server', 'SSL_KEYFILE', ssl_keyfile)
        config.set('server', 'AUTO_GENERATE_SSL', 'true')
    else:
        # Use configured paths
        cert_dir = os.path.dirname(ssl_certfile)
    
    # Check if certificates exist
    if os.path.exists(ssl_certfile) and os.path.exists(ssl_keyfile):
        # Verify files are not empty
        if os.path.getsize(ssl_certfile) > 0 and os.path.getsize(ssl_keyfile) > 0:
            logger.info("SSL certificates found and valid")
            return ssl_certfile, ssl_keyfile, True
        else:
            logger.warning("SSL certificate files exist but are empty, regenerating...")
    
    # Generate certificates if auto-generation is enabled
    if auto_generate_ssl:
        logger.info("SSL certificates not found or invalid, generating self-signed certificates...")
        
        # Get certificate details from config or set defaults
        cert_country = config.get('ssl', 'CERT_COUNTRY', fallback='XX')
        cert_state = config.get('ssl', 'CERT_STATE', fallback='StateName')
        cert_city = config.get('ssl', 'CERT_CITY', fallback='CityName')
        cert_org = config.get('ssl', 'CERT_ORGANIZATION', fallback='WinAuthMon')
        cert_org_unit = config.get('ssl', 'CERT_ORG_UNIT', fallback='IT Department')
        cert_common_name = config.get('ssl', 'CERT_COMMON_NAME', fallback='localhost')
        
        # Set defaults in config if they don't exist
        config.set('ssl', 'CERT_COUNTRY', cert_country)
        config.set('ssl', 'CERT_STATE', cert_state)
        config.set('ssl', 'CERT_CITY', cert_city)
        config.set('ssl', 'CERT_ORGANIZATION', cert_org)
        config.set('ssl', 'CERT_ORG_UNIT', cert_org_unit)
        config.set('ssl', 'CERT_COMMON_NAME', cert_common_name)
        
        cert_path, key_path, generated = generate_ssl_certificates(
            cert_dir=cert_dir,
            country=cert_country,
            state=cert_state,
            city=cert_city,
            org=cert_org,
            org_unit=cert_org_unit,
            common_name=cert_common_name
        )
        
        if generated and cert_path and key_path:
            # Update config with generated certificate paths
            config.set('server', 'SSL_CERTFILE', cert_path)
            config.set('server', 'SSL_KEYFILE', key_path)
            
            return cert_path, key_path, True
        elif cert_path and key_path:
            # Certificates already existed
            return cert_path, key_path, True
        else:
            logger.warning("Failed to generate SSL certificates, SSL will be disabled")
            config.set('server', 'AUTO_GENERATE_SSL', 'false')
            return None, None, False
    else:
        logger.info("SSL certificate auto-generation is disabled")
        return None, None, False
