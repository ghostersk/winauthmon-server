import time
import logging
from functools import wraps
from flask import request, jsonify, g
import redis
from werkzeug.exceptions import TooManyRequests
import os

logger = logging.getLogger(__name__)

# Configure Redis connection (if available)
def configure_redis(config=None):
    """Configure Redis connection from config"""
    global redis_client
    
    redis_url = None
    if config and config.has_option('rate_limiting', 'REDIS_URL'):
        redis_url = config.get('rate_limiting', 'REDIS_URL')
    
    if not redis_url:
        redis_url = os.environ.get('REDIS_URL', None)
    
    if redis_url:
        try:
            redis_client = redis.from_url(redis_url)
            redis_client.ping()  # Test connection
            logger.info("Redis connected for rate limiting")
        except Exception as e:
            logger.warning(f"Redis connection failed for rate limiting: {str(e)}")
            redis_client = None
    else:
        logger.info("No Redis URL configured, using in-memory rate limiting")

# Initialize Redis to None
redis_client = None

# In-memory rate limit storage (fallback if Redis is not available)
rate_limit_storage = {}

def rate_limit(limit=60, per=60, scope_func=None):
    """
    Rate limiting decorator for routes.
    
    Args:
        limit (int): Maximum number of requests allowed in the time period
        per (int): Time period in seconds
        scope_func (callable): Function to determine rate limit scope (default: by IP)
    
    Example usage:
        @app.route('/api/endpoint')
        @rate_limit(limit=10, per=60)  # 10 requests per minute
        def api_endpoint():
            return jsonify({"status": "success"})
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get scope key (default to IP address)
            if scope_func:
                scope = scope_func()
            else:
                # Default to client IP
                scope = get_remote_address()
            
            # Create a unique key for this route and scope
            key = f"rate_limit:{request.path}:{scope}"
            
            # Check rate limit
            current = get_rate_limit_value(key)
            
            # If this is a new key or expired, initialize it
            if current is None:
                set_rate_limit_value(key, 1, per)
                current = 1
            else:
                # Increment counter
                current = increment_rate_limit_value(key)
            
            # Add rate limit headers
            g.rate_limit_headers = {
                'X-RateLimit-Limit': str(limit),
                'X-RateLimit-Remaining': str(max(0, limit - current)),
                'X-RateLimit-Reset': str(int(time.time() + get_ttl(key)))
            }
            
            # If over limit, return 429 Too Many Requests
            if current > limit:
                logger.warning(f"Rate limit exceeded for {scope} on {request.path}")
                response = jsonify({
                    'error': 'Too many requests',
                    'message': f'Rate limit of {limit} requests per {per} seconds exceeded'
                })
                response.status_code = 429
                
                # Add rate limit headers to response
                for key, value in g.rate_limit_headers.items():
                    response.headers[key] = value
                
                return response
            
            # Execute the original route function
            response = f(*args, **kwargs)
            
            # Convert string response to Response object if needed
            from flask import make_response
            if isinstance(response, str):
                response = make_response(response)
            
            # Add rate limit headers to response
            if hasattr(response, 'headers'):
                for key, value in g.rate_limit_headers.items():
                    response.headers[key] = value
                
            return response
        return wrapped
    return decorator

def get_remote_address():
    """Get the client's IP address, respecting proxy headers"""
    # Check X-Forwarded-For header (used by Traefik and other proxies)
    if request.headers.get('X-Forwarded-For'):
        # Get the first IP in the chain (original client IP)
        forwarded_for = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        logger.debug(f"Using X-Forwarded-For IP: {forwarded_for} (from: {request.headers.get('X-Forwarded-For')})")
        return forwarded_for
    
    # Check X-Real-IP header (alternative proxy header)
    if request.headers.get('X-Real-IP'):
        real_ip = request.headers.get('X-Real-IP').strip()
        logger.debug(f"Using X-Real-IP: {real_ip}")
        return real_ip
    
    # Fallback to direct connection IP
    remote_addr = request.remote_addr
    logger.debug(f"Using direct remote_addr: {remote_addr}")
    return remote_addr

# Redis implementations
def get_rate_limit_value(key):
    """Get current rate limit counter value"""
    if redis_client:
        value = redis_client.get(key)
        return int(value) if value else None
    else:
        # Fallback to in-memory storage
        if key in rate_limit_storage:
            # Check if expired
            if time.time() > rate_limit_storage[key]['expires']:
                del rate_limit_storage[key]
                return None
            return rate_limit_storage[key]['value']
        return None

def set_rate_limit_value(key, value, ttl):
    """Set rate limit counter with TTL"""
    if redis_client:
        redis_client.setex(key, ttl, value)
    else:
        # Fallback to in-memory storage
        rate_limit_storage[key] = {
            'value': value,
            'expires': time.time() + ttl
        }

def increment_rate_limit_value(key):
    """Increment rate limit counter"""
    if redis_client:
        return redis_client.incr(key)
    else:
        # Fallback to in-memory storage
        if key in rate_limit_storage:
            rate_limit_storage[key]['value'] += 1
            return rate_limit_storage[key]['value']
        return 1

def get_ttl(key):
    """Get remaining TTL for a key"""
    if redis_client:
        ttl = redis_client.ttl(key)
        return max(0, ttl)
    else:
        # Fallback to in-memory storage
        if key in rate_limit_storage:
            return max(0, rate_limit_storage[key]['expires'] - time.time())
        return 0

# Utility to apply rate limits to entire blueprints
def apply_rate_limits(app, config=None):
    """Apply rate limits to sensitive routes"""
    if not config:
        return
        
    # Check if rate limiting is enabled
    if not config.getboolean('rate_limiting', 'ENABLE_RATE_LIMITING', fallback=True):
        return
    
    # Configure Redis connection
    configure_redis(config)
    
    # Get rate limiting configuration
    login_limit = config.getint('rate_limiting', 'LOGIN_LIMIT', fallback=10)
    login_period = config.getint('rate_limiting', 'LOGIN_PERIOD', fallback=60)
    register_limit = config.getint('rate_limiting', 'REGISTER_LIMIT', fallback=5)
    register_period = config.getint('rate_limiting', 'REGISTER_PERIOD', fallback=300)
    api_limit = config.getint('rate_limiting', 'API_LIMIT', fallback=60)
    api_period = config.getint('rate_limiting', 'API_PERIOD', fallback=60)
    
    # Login endpoint
    if 'auth.login' in app.view_functions:
        app.view_functions['auth.login'] = rate_limit(
            limit=login_limit, per=login_period
        )(app.view_functions['auth.login'])
    
    # Register endpoint
    if 'auth.register' in app.view_functions:
        app.view_functions['auth.register'] = rate_limit(
            limit=register_limit, per=register_period
        )(app.view_functions['auth.register'])
    
    # API endpoints
    api_routes = [route for route in app.url_map.iter_rules() 
                 if route.rule.startswith('/api/')]
    
    for route in api_routes:
        if route.endpoint in app.view_functions:
            app.view_functions[route.endpoint] = rate_limit(
                limit=api_limit, per=api_period
            )(app.view_functions[route.endpoint])