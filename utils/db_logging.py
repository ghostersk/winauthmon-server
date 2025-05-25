import logging
import traceback
import uuid
from datetime import datetime, timezone
from flask import request, g, has_request_context
from extensions import db
from api.models import ErrorLog
import threading
import pytz
from .toolbox import get_app_timezone, get_current_timestamp



class DatabaseLogHandler(logging.Handler):
    """
    Custom logging handler that stores log records in the database.
    Configurable logging level via database settings.
    """
    
    def __init__(self):
        super().__init__()
        self.setLevel(logging.WARNING)  # Default level, will be updated from config
        self._app = None  # Store app reference
        self._processed_records = set()  # Track processed records to avoid duplicates
        self._max_cache_size = 1000  # Limit cache size to prevent memory issues
        
    def emit(self, record):
        """
        Emit a log record to the database.
        This runs in a separate thread to avoid blocking the main application.
        """
        # Import filter functions
        from .toolbox import get_filtered_loggers, get_filtered_message_patterns
        
        # Get configured filters
        filtered_loggers = get_filtered_loggers()
        filtered_patterns = get_filtered_message_patterns()
        
        # Skip database logging for filtered loggers to prevent feedback loops
        if record.name in filtered_loggers:
            return
            
        # Also filter out messages containing specific patterns
        message = record.getMessage().lower()
        for pattern in filtered_patterns:
            if pattern.lower() in message:
                return
        
        # Create a unique identifier for this record to prevent duplicates
        record_id = (
            record.name,
            record.levelname, 
            record.getMessage(),
            record.created,
            getattr(record, 'pathname', ''),
            getattr(record, 'lineno', 0)
        )
        
        # Check if we've already processed this exact record
        if record_id in self._processed_records:
            return
        
        # Add to processed records cache
        self._processed_records.add(record_id)
        
        # Clean cache if it gets too large
        if len(self._processed_records) > self._max_cache_size:
            # Remove oldest half of entries (simple cleanup)
            self._processed_records = set(list(self._processed_records)[self._max_cache_size//2:])
        
        # Store the app reference if we have an application context
        if not self._app:
            try:
                from flask import current_app
                self._app = current_app._get_current_object()
            except RuntimeError:
                # No application context available, try to import app
                try:
                    from app import app
                    self._app = app
                except ImportError:
                    pass
        
        # Use a thread to avoid blocking the main application
        threading.Thread(target=self._emit_to_db, args=(record,), daemon=True).start()
    
    def _emit_to_db(self, record):
        """
        Actually write the log record to the database.
        This method runs in a separate thread.
        """
        try:
            # Use the stored app reference or try to get it
            app = self._app
            if not app:
                try:
                    from flask import current_app
                    app = current_app._get_current_object()
                except RuntimeError:
                    # No application context, try to import app
                    try:
                        from app import app
                    except ImportError:
                        print("Could not import app for database logging")
                        return
            
            with app.app_context():
                # Extract request information if available
                request_id = None
                user_id = None
                remote_addr = None
                
                if has_request_context():
                    try:
                        request_id = getattr(g, 'request_id', str(uuid.uuid4())[:8])
                        user_id = getattr(g, 'user_id', None)
                        remote_addr = request.remote_addr
                    except Exception:
                        # If we can't get request context, continue without it
                        pass
                
                # Format exception info if present
                exception_text = None
                if record.exc_info:
                    exception_text = ''.join(traceback.format_exception(*record.exc_info))
                
                # Create error log entry
                error_log = ErrorLog(
                    level=record.levelname,
                    logger_name=record.name,
                    message=self.format(record),
                    timestamp=get_current_timestamp(),
                    pathname=record.pathname if hasattr(record, 'pathname') else None,
                    lineno=record.lineno if hasattr(record, 'lineno') else None,
                    request_id=request_id,
                    user_id=user_id,
                    remote_addr=remote_addr,
                    exception=exception_text
                )
                
                db.session.add(error_log)
                db.session.commit()
                
        except Exception as e:
            # If database logging fails, fall back to console logging
            # Don't raise the exception to avoid breaking the application
            print(f"Failed to log to database: {e}")

def setup_database_logging(app):
    """
    Set up database logging for the Flask application.
    """
    # Create and configure the database handler
    db_handler = DatabaseLogHandler()
    db_handler._app = app  # Store app reference
    
    # Set initial logging level from settings (will be updated dynamically)
    update_logging_level(app, db_handler)
    
    # Set a formatter for the database logs
    formatter = logging.Formatter(
        '%(name)s - %(levelname)s - %(message)s'
    )
    db_handler.setFormatter(formatter)
    
    # Store handler reference in app for dynamic updates
    app.db_handler = db_handler
    
    # Only add to root logger to avoid duplicate logging
    # (app.logger propagates to root logger by default)
    root_logger = logging.getLogger()
    
    # Check if we already have this handler to avoid duplicates
    handler_exists = False
    for handler in root_logger.handlers:
        if isinstance(handler, DatabaseLogHandler):
            handler_exists = True
            break
    
    if not handler_exists:
        root_logger.addHandler(db_handler)
    
    # Add request ID to flask request context
    @app.before_request
    def add_request_id():
        g.request_id = str(uuid.uuid4())[:8]
        if hasattr(g, 'api_key') and g.api_key and g.api_key.user_id:
            g.user_id = g.api_key.user_id
        elif hasattr(g, 'current_user') and g.current_user and hasattr(g.current_user, 'id'):
            g.user_id = g.current_user.id
    
    app.logger.info("Database logging initialized")

def update_logging_level(app, db_handler=None):
    """
    Update the database logging level from settings.
    """
    try:
        with app.app_context():
            from auth.models import Settings
            settings = Settings.query.first()
            
            if settings and hasattr(settings, 'log_level'):
                # Convert string to logging level
                level_map = {
                    'DEBUG': logging.DEBUG,
                    'INFO': logging.INFO,
                    'WARNING': logging.WARNING,
                    'ERROR': logging.ERROR,
                    'CRITICAL': logging.CRITICAL
                }
                
                new_level = level_map.get(settings.log_level, logging.WARNING)
                
                # Update the handler if provided
                if db_handler:
                    db_handler.setLevel(new_level)
                # Or get it from app if stored
                elif hasattr(app, 'db_handler'):
                    app.db_handler.setLevel(new_level)
                    
                app.logger.info(f"Database logging level updated to: {settings.log_level}")
            else:
                # Default to WARNING if no setting found
                if db_handler:
                    db_handler.setLevel(logging.WARNING)
                elif hasattr(app, 'db_handler'):
                    app.db_handler.setLevel(logging.WARNING)
                    
    except Exception as e:
        print(f"Failed to update logging level: {e}")

def get_available_log_levels():
    """
    Get list of available logging levels for admin configuration.
    """
    return [
        ('DEBUG', 'Debug - All messages'),
        ('INFO', 'Info - General information and above'),
        ('WARNING', 'Warning - Warnings and above (default)'),
        ('ERROR', 'Error - Errors and above'),
        ('CRITICAL', 'Critical - Only critical errors')
    ]

def log_error(message, exception=None, level=logging.ERROR):
    """
    Convenience function to log errors to the database.
    
    Args:
        message: Error message
        exception: Exception object (optional)
        level: Logging level (default: ERROR)
    """
    logger = logging.getLogger(__name__)
    
    if exception:
        logger.log(level, message, exc_info=True)
    else:
        logger.log(level, message)

def log_warning(message):
    """Convenience function to log warnings."""
    log_error(message, level=logging.WARNING)

def log_critical(message, exception=None):
    """Convenience function to log critical errors."""
    log_error(message, exception, level=logging.CRITICAL)
