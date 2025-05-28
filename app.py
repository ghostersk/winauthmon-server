from flask import Flask, session, request, send_from_directory, render_template
from extensions import db, bcrypt, login_manager, get_env_var
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from auth import auth_bp
from api import api_bp
from frontend import frontend_bp
from datetime import datetime, timezone, timedelta
import pytz
import configparser
import os
import sys
import platform
import ssl
import logging
import argparse
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from flask_compress import Compress
# Import security utilities
from utils.security_headers import setup_security_headers
from utils.rate_limiter import apply_rate_limits
from utils.db_logging import setup_database_logging
from auth.models import User, Settings, ApiKey
# Removed SQLite encryption import

# Set up logging first
logging.basicConfig(
    level=logging.INFO,  # Default level, will be updated after config is loaded
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration setup with automatic config.ini management
from utils.config_manager import initialize_config

config_file = os.path.join(os.path.dirname(__file__), 'config.ini')

# Initialize configuration with automatic creation/updating
try:
    config = initialize_config(config_file, preserve_existing=True)
    logger.info("Configuration initialized successfully")
    
    # Auto-generate secure secret key if needed
    from utils.toolbox import ensure_secure_secret_key, ensure_ssl_certificates
    
    config_updated = False
    
    secret_key_updated = ensure_secure_secret_key(config)
    if secret_key_updated:
        config_updated = True
        logger.info("Generated new secure secret key")
    
    # Auto-generate SSL certificates if needed
    cert_path, key_path, ssl_enabled = ensure_ssl_certificates(config, os.path.dirname(__file__))
    if ssl_enabled and cert_path and key_path:
        config_updated = True
        logger.info("SSL certificates configured")
    
    # Save configuration if any updates were made
    if config_updated:
        try:
            with open(config_file, 'w') as f:
                config.write(f)
            logger.info("Configuration file updated with new settings")
        except Exception as e:
            logger.error(f"Failed to save configuration updates: {e}")
    
    # Update logging level based on config
    debug_mode = config.getboolean('app', 'APP_DEBUG', fallback=False)
    if debug_mode:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug mode enabled")
    
except Exception as e:
    logger.error(f"Failed to initialize configuration: {e}")
    # Fall back to basic ConfigParser if config manager fails
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        config.read(config_file)
    else:
        logger.error(f"Configuration file {config_file} not found and could not be created")
        exit(1)

app = Flask(__name__)

# Configure WSGI middleware for reverse proxy support (Traefik)
proxy_count = config.getint('proxy', 'PROXY_COUNT', fallback=1)
trust_x_forwarded_for = config.getboolean('proxy', 'TRUST_X_FORWARDED_FOR', fallback=True)
trust_x_forwarded_proto = config.getboolean('proxy', 'TRUST_X_FORWARDED_PROTO', fallback=True)
trust_x_forwarded_host = config.getboolean('proxy', 'TRUST_X_FORWARDED_HOST', fallback=True)
trust_x_forwarded_port = config.getboolean('proxy', 'TRUST_X_FORWARDED_PORT', fallback=True)
trust_x_forwarded_prefix = config.getboolean('proxy', 'TRUST_X_FORWARDED_PREFIX', fallback=False)

# Get trusted proxy IPs
trusted_proxies = config.get('proxy', 'TRUSTED_PROXIES', fallback='').strip()
if trusted_proxies:
    # Parse comma-separated IPs/CIDRs
    trusted_proxy_list = [ip.strip() for ip in trusted_proxies.split(',') if ip.strip()]
    logger.info(f"Configured trusted proxies: {trusted_proxy_list}")
else:
    trusted_proxy_list = None
    logger.info("No specific proxy IPs configured - trusting all proxies")

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=proxy_count if trust_x_forwarded_for else 0,
    x_proto=proxy_count if trust_x_forwarded_proto else 0,
    x_host=proxy_count if trust_x_forwarded_host else 0,
    x_port=proxy_count if trust_x_forwarded_port else 0,
    x_prefix=proxy_count if trust_x_forwarded_prefix else 0
)

# Configure Flask app from environment variables with fallback to config file
app.config['SECRET_KEY'] = get_env_var('SECRET_KEY', config.get('app', 'SECRET_KEY', fallback='your_secret_key'))
app.config['SQLALCHEMY_DATABASE_URI'] = get_env_var('DATABASE_URL', config.get('database', 'SQLALCHEMY_DATABASE_URI', fallback='sqlite:///database.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.getboolean('database', 'SQLALCHEMY_TRACK_MODIFICATIONS', fallback=False)

# Session security settings from environment or config
app.config['SESSION_COOKIE_SECURE'] = get_env_var('SESSION_COOKIE_SECURE', config.getboolean('session', 'SESSION_COOKIE_SECURE', fallback=True))
app.config['SESSION_COOKIE_HTTPONLY'] = get_env_var('SESSION_COOKIE_HTTPONLY', config.getboolean('session', 'SESSION_COOKIE_HTTPONLY', fallback=True))
app.config['SESSION_COOKIE_SAMESITE'] = get_env_var('SESSION_COOKIE_SAMESITE', config.get('session', 'SESSION_COOKIE_SAMESITE', fallback='Lax'))
app.config['REMEMBER_COOKIE_SECURE'] = get_env_var('REMEMBER_COOKIE_SECURE', config.getboolean('session', 'REMEMBER_COOKIE_SECURE', fallback=True))
app.config['REMEMBER_COOKIE_HTTPONLY'] = get_env_var('REMEMBER_COOKIE_HTTPONLY', config.getboolean('session', 'REMEMBER_COOKIE_HTTPONLY', fallback=True))
app.config['REMEMBER_COOKIE_DURATION'] = int(get_env_var('REMEMBER_COOKIE_DURATION', config.getint('session', 'REMEMBER_COOKIE_DURATION', fallback=7200)))
app.config['PERMANENT_SESSION_LIFETIME'] = int(get_env_var('PERMANENT_SESSION_LIFETIME', config.getint('session', 'PERMANENT_SESSION_LIFETIME', fallback=7200)))
app.config['APP_DEBUG'] = get_env_var('APP_DEBUG', config.getboolean('app', 'APP_DEBUG', fallback=False))
app.config['TIMEZONE'] = get_env_var('TIMEZONE', config.get('app', 'TIMEZONE', fallback='Europe/London'))

# Setup compression if enabled
if config.getboolean('cache', 'ENABLE_COMPRESSION', fallback=True):
    compress = Compress()
    compress.init_app(app)
    # Configure compression level and threshold
    app.config['COMPRESS_LEVEL'] = config.getint('cache', 'COMPRESSION_LEVEL', fallback=6)
    app.config['COMPRESS_MIN_SIZE'] = config.getint('cache', 'COMPRESSION_MIN_SIZE', fallback=500)
    app.config['COMPRESS_MIMETYPES'] = [
        'text/html', 'text/css', 'text/xml', 'application/json', 'application/javascript',
        'application/x-javascript', 'image/svg+xml'
    ]

# Enable CSRF protection
csrf = CSRFProtect(app)

# Configure static files with caching and proper MIME types
@app.route('/favicon.ico')
def favicon():
    response = send_from_directory(os.path.join(app.root_path, 'static', 'img'),
                               'favicon.ico', mimetype='image/x-icon')
    
    # Add cache headers manually instead of using cache_timeout
    max_age = config.getint('cache', 'IMAGE_MAX_AGE', fallback=604800)
    response.headers['Cache-Control'] = f'public, max-age={max_age}'
    response.headers['Expires'] = (datetime.now(timezone.utc) + timedelta(seconds=max_age)).strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    return response

# Add explicit static file serving with proper MIME types
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with proper MIME types"""
    from flask import send_from_directory
    import mimetypes
    
    # Ensure proper MIME type detection
    if filename.endswith('.css'):
        mimetype = 'text/css'
    elif filename.endswith('.js'):
        mimetype = 'application/javascript'
    elif filename.endswith('.png'):
        mimetype = 'image/png'
    elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
        mimetype = 'image/jpeg'
    elif filename.endswith('.gif'):
        mimetype = 'image/gif'
    elif filename.endswith('.ico'):
        mimetype = 'image/x-icon'
    elif filename.endswith('.woff'):
        mimetype = 'font/woff'
    elif filename.endswith('.woff2'):
        mimetype = 'font/woff2'
    elif filename.endswith('.ttf'):
        mimetype = 'font/ttf'
    else:
        # Use mimetypes module for other files
        mimetype, _ = mimetypes.guess_type(filename)
        if not mimetype:
            mimetype = 'application/octet-stream'
    
    try:
        response = send_from_directory(app.static_folder, filename, mimetype=mimetype)
        
        # Add cache headers based on file type
        if filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf')):
            max_age = config.getint('cache', 'IMAGE_MAX_AGE', fallback=604800)
        elif filename.endswith(('.js', '.css')):
            max_age = config.getint('cache', 'JS_CSS_MAX_AGE', fallback=43200)
        else:
            max_age = config.getint('cache', 'STATIC_MAX_AGE', fallback=86400)
            
        response.headers['Cache-Control'] = f'public, max-age={max_age}'
        response.headers['Expires'] = (datetime.now(timezone.utc) + timedelta(seconds=max_age)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # Add ETag for efficient caching
        response.add_etag()
        
        return response
        
    except FileNotFoundError:
        # Return 404 for missing static files instead of redirecting to HTML pages
        from flask import abort
        abort(404)

# Setup security headers
setup_security_headers(app, config)

# Configure HSTS settings for security headers
app.config['HSTS_ENABLED'] = config.getboolean('security', 'ENABLE_HSTS', fallback=True)
app.config['HSTS_MAX_AGE'] = config.getint('security', 'HSTS_MAX_AGE', fallback=31536000)

    # return send_from_directory(os.path.join(app.root_path, 'static', 'img'),
    #                            'favicon.png', mimetype='image/png',
    #                            cache_timeout=config.getint('cache', 'IMAGE_MAX_AGE', fallback=604800))

# Add cache headers to static files
@app.after_request
def add_cache_headers(response):
    # Only add cache headers for static files
    if request.path.startswith('/static/'):
        # Get cache settings from config
        default_max_age = config.getint('cache', 'STATIC_MAX_AGE', fallback=86400)
        image_max_age = config.getint('cache', 'IMAGE_MAX_AGE', fallback=604800)
        js_css_max_age = config.getint('cache', 'JS_CSS_MAX_AGE', fallback=43200)
        
        # Set default cache expiration
        max_age = default_max_age
        
        # Set longer cache for assets that rarely change like fonts, images
        if any(request.path.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff2', '.woff', '.ttf']):
            max_age = image_max_age
            
        # Set shorter cache for JS and CSS that might change with deployments
        if any(request.path.endswith(ext) for ext in ['.js', '.css']):
            max_age = js_css_max_age
            
        response.headers['Cache-Control'] = f'public, max-age={max_age}'
        response.headers['Expires'] = (datetime.now(timezone.utc) + timedelta(seconds=max_age)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # Add ETag support for efficient caching
        if 'ETag' not in response.headers:
            response.add_etag()
            
    return response

# Request logger middleware
@app.before_request
def log_request_info():
    if app.config['APP_DEBUG']:
        logger.debug('Request URL: %s', request.url)
        logger.debug('Request Method: %s', request.method)
        logger.debug('Request Headers: %s', dict(request.headers))
        # Only try to access request.json if the content type is application/json
        if request.is_json and request.get_data(as_text=True):
            try:
                logger.debug('Request Body: %s', request.json)
            except Exception as e:
                logger.debug('Error parsing JSON: %s', str(e))


# Ensure session is permanent and uses configured lifetime
@app.before_request
def make_session_permanent():
    session.permanent = True

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(frontend_bp)

# Setup rate limiting after blueprints are registered
apply_rate_limits(app, config)

def handle_http_exception(exc:HTTPException):
    """Use the code and description from an HTTPException to inform the user of an error"""    
    logger.debug('HTTP error %s - %s', exc.code, exc.description)
    
    # For static file 404s, return proper 404 response instead of HTML error page
    if request.path.startswith('/static/') and exc.code == 404:
        from flask import Response
        return Response(f"Static file not found: {request.path}", status=404, mimetype='text/plain')
    
    return render_template("error.html", status_code=exc.code, description=exc.description)

def handle_uncaught_exception(exc:Exception):
    """Log the exception, then return a generic server error page."""   
    logger.warning('HTTP error 500 - Internal server error')
    return render_template("error.html", status_code=500, description='Internal server error')

# This handler is run when an HTTPException, or any of its subclasses, is raised
app.register_error_handler(HTTPException, handle_http_exception)
# This handler is run for all other uncaught exceptions
app.register_error_handler(Exception, handle_uncaught_exception)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def init_app():
    with app.app_context():
        db.create_all()
        # Create settings if not exists
        if not Settings.query.first():
            settings = Settings(
                allow_registration=False, 
                restrict_email_domains=False,
                log_level='WARNING'  # Default logging level
            )
            db.session.add(settings)
        else:
            # Update existing settings to have log_level if it doesn't exist
            settings = Settings.query.first()
            if not hasattr(settings, 'log_level') or settings.log_level is None:
                settings.log_level = 'WARNING'
                db.session.add(settings)
        
        # Create default admin if not exists
        admin = User.query.filter_by(email='superadmin@example.com').first()
        if not admin:
            hashed_password = bcrypt.generate_password_hash('adminsuper').decode('utf-8')
            admin = User(
                username='superadmin',
                email='superadmin@example.com',
                password=hashed_password,
                role='GlobalAdmin',
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()

            # Create initial API key for admin
            api_key = ApiKey(
                key=ApiKey.generate_key(),
                description="Initial Admin API Key",
                user_id=admin.id
            )
            db.session.add(api_key)
        
        db.session.commit()

# Initialize the application
init_app()

# Setup database logging after app initialization
setup_database_logging(app)

@app.context_processor
def inject_settings():
    settings = Settings.query.first()
    return dict(allow_registration=settings.allow_registration if settings else False)

# Add template filter for proper timezone display
@app.template_filter('format_datetime')
def format_datetime(value):
    """Format a datetime with proper timezone"""
    if value is None:
        return ""
    
    # Use the timezone utility function
    from utils.toolbox import format_timestamp_for_display
    return format_timestamp_for_display(value)

# Exempt API endpoints from CSRF (since they use API keys)
with app.app_context():
    csrf.exempt(api_bp)

def get_best_server():
    """Determine the best server for the current OS"""
    system = platform.system().lower()
    
    if system == 'windows':
        return 'waitress'
    elif system in ['linux', 'darwin']:  # Linux or macOS
        return 'gunicorn'
    else:
        logger.warning(f"Unknown OS: {system}, defaulting to waitress")
        return 'waitress'

def run_with_waitress():
    """Run the application with Waitress (Windows-compatible production server)"""
    try:
        from waitress import serve
        
        # Read configuration
        host = config.get('server', 'HOST', fallback='0.0.0.0')
        port = config.getint('server', 'PORT', fallback=8000)
        threads = config.get('server', 'WORKERS', fallback='4')  # Waitress uses threads instead of processes
        ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback=None)
        ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback=None)
        
        logger.info(f"Starting Waitress server on {host}:{port} with {threads} threads")
        
        # Waitress configuration - optimized for performance  
        serve_kwargs = {
            'host': host,
            'port': port,
            'threads': int(threads),
            'connection_limit': 1000,
            'cleanup_interval': 30,
            'channel_timeout': 120,
            'log_socket_errors': True,
            # Valid Waitress performance optimizations
            'recv_bytes': 65536,  # Increase receive buffer
            'send_bytes': 65536,  # Increase send buffer
            'max_request_header_size': 262144,  # 256KB header limit
            'max_request_body_size': 1073741824,  # 1GB body limit
            'expose_tracebacks': False,  # Don't expose tracebacks in production
        }
        
        # Note: Waitress doesn't handle SSL directly - use reverse proxy for SSL
        if ssl_certfile and ssl_keyfile and os.path.exists(ssl_certfile) and os.path.exists(ssl_keyfile):
            logger.info("SSL certificates found - but Waitress doesn't handle SSL directly")
            logger.info("For SSL support, use a reverse proxy (nginx, traefik, etc.)")
            logger.info("Starting Waitress without SSL on HTTP")
        else:
            logger.info("No SSL certificates configured - starting with HTTP")
        
        # Start Waitress server (HTTP only - SSL handled by reverse proxy)
        serve(app, **serve_kwargs)
        
    except ImportError:
        logger.error("Waitress not installed. Install with: pip install waitress")
        return False
    except Exception as e:
        logger.error(f"Failed to start Waitress: {e}")
        return False
    
    return True

def run_with_gunicorn():
    """Run the application with Gunicorn (Linux/macOS production server)"""
    try:
        import subprocess
        import sys
        
        # Read configuration from existing config.ini
        host = config.get('server', 'HOST', fallback='0.0.0.0')
        port = config.getint('server', 'PORT', fallback=8000)
        workers = config.getint('server', 'WORKERS', fallback=4)
        timeout = config.getint('server', 'TIMEOUT', fallback=30)
        max_requests = config.getint('server', 'MAX_REQUESTS', fallback=1000)
        max_requests_jitter = config.getint('server', 'MAX_REQUESTS_JITTER', fallback=100)
        ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback=None)
        ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback=None)
        log_level = config.get('logging', 'LEVEL', fallback='info').lower()
        
        logger.info(f"Starting Gunicorn server on {host}:{port} with {workers} workers")
        logger.info(f"SSL: {'Enabled' if ssl_certfile and ssl_keyfile else 'Disabled'}")
        
        # Create logs directory
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Build Gunicorn command with all settings from config.ini
        cmd = [
            sys.executable, '-m', 'gunicorn',  # Use current Python interpreter
            '--bind', f'{host}:{port}',
            '--workers', str(workers),
            '--worker-class', 'sync',
            '--timeout', str(timeout),
            '--keep-alive', '5',
            '--max-requests', str(max_requests),
            '--max-requests-jitter', str(max_requests_jitter),
            '--preload',
            '--access-logfile', os.path.join(log_dir, 'gunicorn_access.log'),
            '--error-logfile', os.path.join(log_dir, 'gunicorn_error.log'),
            '--log-level', log_level,
            '--pid', os.path.join(os.path.dirname(__file__), 'gunicorn.pid'),
            'app:app'
        ]
        
        # Add SSL configuration if available
        if ssl_certfile and ssl_keyfile and os.path.exists(ssl_certfile) and os.path.exists(ssl_keyfile):
            cmd.extend(['--certfile', ssl_certfile, '--keyfile', ssl_keyfile])
            logger.info("SSL enabled with certificates")
        elif ssl_certfile and ssl_keyfile:
            logger.warning(f"SSL certificates not found: {ssl_certfile}, {ssl_keyfile}")
        
        logger.info(f"Starting gunicorn with command: {' '.join(cmd)}")
        
        # Run Gunicorn
        subprocess.run(cmd)
        
    except ImportError:
        logger.error("Gunicorn not available on this system")
        return False
    except FileNotFoundError:
        logger.error("Gunicorn command not found. Install with: pip install gunicorn")
        return False
    except Exception as e:
        logger.error(f"Failed to start Gunicorn: {e}")
        return False
    
    return True

def run_app():
    """Start the application with the best server for this OS"""
    best_server = get_best_server()
    
    logger.info(f"Detected OS: {platform.system()}")
    logger.info(f"Using server: {best_server}")
    
    if best_server == 'waitress':
        success = run_with_waitress()
    elif best_server == 'gunicorn':
        success = run_with_gunicorn()
    else:
        logger.error("No suitable server found")
        success = False
    
    if not success:
        logger.error("Failed to start preferred server, falling back to Flask dev server")
        # Fallback to Flask development server
        host = config.get('server', 'HOST', fallback='0.0.0.0')
        port = config.getint('server', 'PORT', fallback=8000)
        ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback='certs/cert.pem')
        ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback='certs/key.pem')
        
        ssl_context = None
        if ssl_certfile and ssl_keyfile and os.path.exists(ssl_certfile) and os.path.exists(ssl_keyfile):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)
            ssl_context.verify_mode = ssl.CERT_NONE
        
        app.run(debug=app.config['APP_DEBUG'], ssl_context=ssl_context, host=host, port=port)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Domain Logons Monitoring Application')
    parser.add_argument('--legacy', action='store_true', help='Use legacy Flask development server')
    parser.add_argument('--waitress', action='store_true', help='Force use of Waitress server (Windows)')
    parser.add_argument('--gunicorn', action='store_true', help='Force use of Gunicorn server (Linux/macOS)')
    args = parser.parse_args()
    
    if args.legacy:
        # Legacy Flask development server mode
        host = config.get('server', 'HOST', fallback='0.0.0.0')
        port = config.getint('server', 'PORT', fallback=8000)
        ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback='certs/cert.pem')
        ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback='certs/key.pem')
        
        ssl_context = None
        if ssl_certfile and ssl_keyfile and os.path.exists(ssl_certfile) and os.path.exists(ssl_keyfile):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)
            ssl_context.verify_mode = ssl.CERT_NONE
        
        logger.info("Starting Flask development server")
        app.run(debug=app.config['APP_DEBUG'], ssl_context=ssl_context, host=host, port=port)
    elif args.waitress:
        # Force Waitress server
        logger.info("Force using Waitress server")
        if not run_with_waitress():
            logger.error("Failed to start Waitress, no fallback available")
    elif args.gunicorn:
        # Force Gunicorn server
        logger.info("Force using Gunicorn server")
        if not run_with_gunicorn():
            logger.error("Failed to start Gunicorn, no fallback available")
    else:
        # Auto-detect best server for OS
        run_app()