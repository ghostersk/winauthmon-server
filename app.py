from flask import Flask, session, request, send_from_directory, render_template
from asgiref.wsgi import WsgiToAsgi
from extensions import db, bcrypt, login_manager, get_env_var
from auth.models import User, Settings, ApiKey
import ssl
import logging
from flask_wtf import CSRFProtect
from auth import auth_bp
from api import api_bp
from frontend import frontend_bp
from datetime import datetime, timezone, timedelta
import pytz
import configparser
import os
import uvicorn
import argparse
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from flask_compress import Compress
# Import security utilities
from utils.security_headers import setup_security_headers
from utils.rate_limiter import apply_rate_limits
from utils.db_logging import setup_database_logging
# Removed SQLite encryption import

# Load configuration from ini file
config = configparser.ConfigParser()
config_file = os.path.join(os.path.dirname(__file__), 'config.ini')
config.read(config_file)

# Set up logging
logging.basicConfig(
    level=logging.DEBUG if config.getboolean('app', 'APP_DEBUG', fallback=True) else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

# Configure static files with caching
@app.route('/favicon.ico')
def favicon():
    response = send_from_directory(os.path.join(app.root_path, 'static', 'img'),
                               'favicon.ico', mimetype='image/ico')
    
    # Add cache headers manually instead of using cache_timeout
    max_age = config.getint('cache', 'IMAGE_MAX_AGE', fallback=604800)
    response.headers['Cache-Control'] = f'public, max-age={max_age}'
    response.headers['Expires'] = (datetime.now(timezone.utc) + timedelta(seconds=max_age)).strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    return response

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

wsg = WsgiToAsgi(app)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(frontend_bp)

# Setup rate limiting after blueprints are registered
apply_rate_limits(app, config)

def handle_http_exception(exc:HTTPException):
    """Use the code and description from an HTTPException to inform the user of an error"""    
    logger.debug('HTTP error %s - %s', exc.code, exc.description)
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
    return User.query.get(int(user_id))

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

def run_app():
    """Start the application with Uvicorn using config settings"""
    host = config.get('server', 'HOST', fallback='0.0.0.0')
    port = config.getint('server', 'PORT', fallback=8000)
    ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback='certs/cert.pem')
    ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback='certs/key.pem')
    
    # Get new configuration settings
    development_mode = config.getboolean('server', 'DEVELOPMENT_MODE', fallback=False)
    watch_files = config.getboolean('server', 'WATCH_FILES', fallback=False)
    workers_setting = config.get('server', 'WORKERS', fallback='1')
    worker_lifetime = config.getint('server', 'WORKER_LIFETIME', fallback=86400)
    graceful_shutdown = config.getboolean('server', 'GRACEFUL_SHUTDOWN', fallback=True)
    shutdown_timeout = config.getint('server', 'SHUTDOWN_TIMEOUT', fallback=30)
    
    # Parse workers setting - could be "auto" or a number
    workers = None
    if workers_setting.lower() == 'auto':
        import multiprocessing
        workers = multiprocessing.cpu_count()
    else:
        try:
            workers = int(workers_setting)
        except ValueError:
            logger.warning(f"Invalid WORKERS setting '{workers_setting}', defaulting to 1")
            workers = 1
    
    # Only enable file watching in development mode
    reload_enabled = development_mode and watch_files
    
    # Use debug log level in development mode
    log_level = "debug" if development_mode else "info"
    
    logger.info(f"Starting application on {host}:{port} with SSL")
    logger.info(f"SSL certificate: {ssl_certfile}")
    logger.info(f"SSL key: {ssl_keyfile}")
    logger.info(f"Development mode: {development_mode}")
    logger.info(f"File watching: {reload_enabled}")
    logger.info(f"Workers: {workers}")
    
    # Get max requests per worker before graceful restart
    # Setting to None disables the worker auto-restart feature
    limit_max_requests = None
    if worker_lifetime > 0:
        # If worker_lifetime is set (> 0), we'll use a reasonable request limit
        # Default to around 10,000 requests per worker before restart
        limit_max_requests = 10000
    
    # Get trusted proxy configuration for Uvicorn
    trusted_proxies_config = config.get('proxy', 'TRUSTED_PROXIES', fallback='').strip()
    if trusted_proxies_config:
        forwarded_allow_ips = trusted_proxies_config.replace(',', ' ')
        logger.info(f"Uvicorn forwarded_allow_ips: {forwarded_allow_ips}")
    else:
        forwarded_allow_ips = '*'
        logger.info("Uvicorn allowing all IPs for forwarded headers")
    
    uvicorn.run(
        "app:wsg", 
        host=host, 
        port=port, 
        reload=reload_enabled,
        workers=workers,
        log_level=log_level,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
        timeout_keep_alive=65,  # Keep-alive timeout to detect hanging connections
        limit_max_requests=limit_max_requests,  # Fixed: Only restart workers after this many requests
        timeout_graceful_shutdown=shutdown_timeout
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Domain Logons Monitoring Application')
    parser.add_argument('--legacy', action='store_true', help='Use legacy Flask server instead of Uvicorn')
    args = parser.parse_args()
    
    if args.legacy:
        # Legacy Flask server mode
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_certfile = config.get('server', 'SSL_CERTFILE', fallback='certs/cert.pem')
        ssl_keyfile = config.get('server', 'SSL_KEYFILE', fallback='certs/key.pem')
        ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)
        ssl_context.verify_mode = ssl.CERT_NONE  # Accept self-signed certificates
        
        host = config.get('server', 'HOST', fallback='0.0.0.0')
        port = config.getint('server', 'PORT', fallback=8000)
        
        app.run(debug=app.config['APP_DEBUG'], ssl_context=ssl_context, host=host, port=port)
    else:
        # Default to Uvicorn server
        run_app()