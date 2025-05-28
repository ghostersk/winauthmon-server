from flask import Blueprint, request, jsonify, current_app, g
from auth.models import User, ApiKey
from api.models import Log
from extensions import db
from functools import wraps
from datetime import datetime, timezone, timedelta
from api import api_bp
from sqlalchemy import and_, text
import pytz
import logging

# Use the existing blueprint from __init__.py instead of creating a new one
api = api_bp
logger = logging.getLogger(__name__)

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                logger.warning('API request without API key', extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'endpoint': request.endpoint,
                    'method': request.method
                })
                return jsonify({"message": "No API key provided"}), 401
            
            key = ApiKey.query.filter_by(key=api_key).first()
            if not key:
                logger.warning('Invalid API key used', extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'api_key_prefix': api_key[:8] + '...' if len(api_key) > 8 else api_key
                })
                return jsonify({"message": "Invalid API key"}), 401
                
            # Check if the API key is active
            if hasattr(key, 'is_active') and not key.is_active:
                logger.warning('Disabled API key used', extra={
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'api_key_id': key.id,
                    'company_id': key.company_id
                })
                return jsonify({"message": "API key has been disabled"}), 401
            
            # Update last used timestamp
            key.last_used = datetime.now(pytz.timezone(current_app.config['TIMEZONE']))
            
            # Save the API key and associated company in g object for use in route functions
            g.api_key = key
            g.company_id = key.company_id
            
            db.session.commit()
            return f(*args, **kwargs)
        except Exception as e:
            logger.exception('Error in API key authentication', extra={
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'endpoint': request.endpoint,
                'method': request.method,
                'has_api_key': bool(request.headers.get('X-API-Key')),
                'error': str(e)
            })
            return jsonify({"message": "Authentication error occurred"}), 500
    return decorated

@api.route('/log_event', methods=['POST'])
@require_api_key
def log_event():
    try:
        data = request.get_json()
        
        # Parse the timestamp from the request - handle different formats
        timestamp_str = data['Timestamp']
        timestamp_utc = None
        
        # Try different timestamp formats
        formats_to_try = [
            '%Y-%m-%dT%H:%M:%S%z',      # RFC3339/ISO8601 with timezone offset (from Go app)
            '%Y-%m-%dT%H:%M:%SZ',       # ISO format with Z (UTC)
            '%Y-%m-%d %H:%M:%S %Z',     # Format with timezone name
            '%Y-%m-%d %H:%M:%S',        # Simple format without timezone
            '%Y-%m-%d %H:%M:%S%z',      # Format with numeric timezone
        ]
        
        for fmt in formats_to_try:
            try:
                if fmt == '%Y-%m-%d %H:%M:%S %Z':
                    # Special handling for timezone names
                    dt_parts = timestamp_str.rsplit(' ', 1)
                    if len(dt_parts) == 2:
                        dt_str, tz_str = dt_parts
                        # Try to parse the datetime part
                        dt = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
                        
                        # Try to convert timezone abbreviation to a pytz timezone
                        tzinfos = {
                            'BST': 3600,   # British Summer Time (UTC+1)
                            'GMT': 0,      # Greenwich Mean Time
                            'UTC': 0,      # Coordinated Universal Time
                            # Add more timezone abbreviations as needed
                        }
                        
                        if tz_str in tzinfos:
                            # Create aware datetime with the specified timezone offset
                            offset = timedelta(seconds=tzinfos[tz_str])
                            timestamp_utc = dt.replace(tzinfo=timezone(offset))
                            break
                elif fmt == '%Y-%m-%dT%H:%M:%S%z':
                    # Handle RFC3339 format from Go application
                    timestamp_utc = datetime.strptime(timestamp_str, fmt)
                    break
                else:
                    timestamp_utc = datetime.strptime(timestamp_str, fmt)
                    if fmt == '%Y-%m-%d %H:%M:%S':  # No timezone info, assume UTC
                        timestamp_utc = pytz.utc.localize(timestamp_utc)
                    break
            except ValueError:
                continue
                
        if timestamp_utc is None:
            return jsonify({'message': f'Could not parse timestamp: {timestamp_str}', 'status': 'error'}), 400
        
        # Convert to the configured timezone
        from utils.toolbox import get_app_timezone
        app_timezone = get_app_timezone()
        if timestamp_utc.tzinfo is None:
            timestamp_utc = pytz.utc.localize(timestamp_utc)
        timestamp = timestamp_utc.astimezone(app_timezone)
        
        # Check if this is a retry attempt
        is_retry = data.get('retry', 0)
        
        # Check if a record with the same attributes already exists
        existing_log = Log.query.filter(
            and_(
                Log.event_type == data['EventType'],
                Log.user_name == data['UserName'],
                Log.computer_name == data['ComputerName'],
                Log.local_ip == data.get('LocalIP'),
                Log.timestamp == timestamp
            )
        ).first()
        
        if existing_log:
            # Record already exists, don't create duplicate
            return jsonify({'message': 'Event already recorded', 'status': 'success'}), 200
        
        # Create new log entry with company_id and api_key_id from the API key
        log = Log(
            event_type=data['EventType'],
            user_name=data['UserName'],
            computer_name=data['ComputerName'],
            local_ip=data.get('LocalIP'),
            public_ip=data.get('PublicIP'),
            timestamp=timestamp,
            retry=is_retry,
            company_id=g.company_id,  # Add the company ID from the API key
            api_key_id=g.api_key.id   # Add the API key ID
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'message': 'Event logged successfully', 'status': 'success'}), 201
    
    except Exception as e:
        db.session.rollback()
        logger.exception('Failed to log event in API', extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'api_key_id': getattr(g, 'api_key', {}).id if hasattr(g, 'api_key') and g.api_key else None,
            'company_id': getattr(g, 'company_id', None),
            'request_data': data if 'data' in locals() else None,
            'timestamp_str': data.get('Timestamp') if 'data' in locals() else None,
            'event_type': data.get('EventType') if 'data' in locals() else None,
            'user_name': data.get('UserName') if 'data' in locals() else None,
            'computer_name': data.get('ComputerName') if 'data' in locals() else None,
            'local_ip': data.get('LocalIP') if 'data' in locals() else None,
            'public_ip': data.get('PublicIP') if 'data' in locals() else None,
            'retry_attempt': data.get('retry', 0) if 'data' in locals() else None,
            'error': str(e)
        })
        return jsonify({'message': f'Failed to log event: {str(e)}', 'status': 'error'}), 500

@api.route('/health', methods=['POST'])
@require_api_key
def health_check():
    """
    Health check endpoint that verifies:
    - API key authentication (handled by @require_api_key decorator)
    - Database connectivity
    - Application status
    """
    try:
        # Test database connectivity by performing a simple query
        # This will raise an exception if the database is not accessible
        db.session.execute(text('SELECT 1')).fetchone()
        
        # Test that we can access the API key from the decorator
        api_key_id = g.api_key.id if hasattr(g, 'api_key') else None
        company_id = g.company_id if hasattr(g, 'company_id') else None
        
        # Get current timestamp in the configured timezone
        app_timezone = pytz.timezone(current_app.config['TIMEZONE'])
        current_time = datetime.now(app_timezone)
        
        return jsonify({
            'status': 'ok',
            'message': 'Health check passed',
            'timestamp': current_time.isoformat(),
            'database': 'connected',
            'api_key_verified': api_key_id is not None,
            'company_id': company_id
        }), 200
        
    except Exception as e:
        # Log the error for debugging purposes
        logger.exception('Health check failed', extra={
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'api_key_id': getattr(g, 'api_key', {}).id if hasattr(g, 'api_key') and g.api_key else None,
            'company_id': getattr(g, 'company_id', None),
            'error': str(e)
        })
        
        return jsonify({
            'status': 'error',
            'message': 'Health check failed',
            'error': str(e),
            'database': 'disconnected'
        }), 500