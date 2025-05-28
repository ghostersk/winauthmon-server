import os
import logging
from flask import request, current_app

logger = logging.getLogger(__name__)

def add_security_headers(response):
    """
    Add security headers to HTTP responses
    
    Headers added:
    - Content-Security-Policy: Prevents XSS attacks by specifying content sources
    - X-Content-Type-Options: Prevents MIME type sniffing
    - X-Frame-Options: Prevents clickjacking
    - X-XSS-Protection: Additional XSS protection for older browsers
    - Referrer-Policy: Controls referrer information
    - Strict-Transport-Security: Enforces HTTPS
    - Permissions-Policy: Controls browser features
    """
    # Content Security Policy - restricts sources of content
    csp = current_app.config.get('CONTENT_SECURITY_POLICY', 
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Additional XSS protection for older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Control referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS - force HTTPS (only in production)
    if not current_app.debug and not current_app.testing:
        hsts_enabled = current_app.config.get('HSTS_ENABLED', True)
        if hsts_enabled:
            hsts_max_age = current_app.config.get('HSTS_MAX_AGE', 31536000)
            response.headers['Strict-Transport-Security'] = f'max-age={hsts_max_age}; includeSubDomains'
    
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), payment=(), fullscreen=(self)'
    )
    
    return response

def setup_security_headers(app, config=None):
    """Register security headers middleware with Flask app"""
    if config and config.getboolean('security', 'ENABLE_SECURITY_HEADERS', fallback=True):
        # Set CSP from config if available
        if config.has_option('security', 'CONTENT_SECURITY_POLICY'):
            app.config['CONTENT_SECURITY_POLICY'] = config.get('security', 'CONTENT_SECURITY_POLICY')
        
        app.after_request(add_security_headers)