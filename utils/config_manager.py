#!/usr/bin/env python3
"""
Configuration Manager - Handles config.ini creation and updates
Preserves existing values while adding missing sections/options
"""

import os
import configparser
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages configuration file creation and updates"""
    
    def __init__(self, config_path: str = 'config.ini'):
        self.config_path = config_path
        self.config = configparser.ConfigParser(allow_no_value=True)
        
    def get_default_config(self) -> Dict[str, Dict[str, Any]]:
        """Define the default configuration structure and values"""
        return {
            'app': {
                'SECRET_KEY': 'your_secret_key_change_this_in_production',
                'APP_DEBUG': 'false',
                'TIMEZONE': 'Europe/London',
                '; Application configuration': None,
                '; SECRET_KEY: Change this to a random secret key in production': None,
                '; APP_DEBUG: Set to false in production': None,
                '; TIMEZONE: Your local timezone for log display': None,
            },
            
            'server': {
                'HOST': '0.0.0.0',
                'PORT': '8000',
                'SSL_CERTFILE': 'instance/certs/cert.pem',
                'SSL_KEYFILE': 'instance/certs/key.pem',
                'DEVELOPMENT_MODE': 'false',
                'WATCH_FILES': 'false',
                'WORKERS': '4',
                'WORKER_LIFETIME': '86400',
                'GRACEFUL_SHUTDOWN': 'true',
                'SHUTDOWN_TIMEOUT': '30',
                '; Server configuration': None,
                '; HOST: IP address to bind to (0.0.0.0 for all interfaces)': None,
                '; PORT: Port number to listen on': None,
                '; SSL_CERTFILE/SSL_KEYFILE: SSL certificate paths (for reverse proxy setups)': None,
                '; WORKERS: Number of threads (Waitress) or processes (Gunicorn)': None,
                '; DEVELOPMENT_MODE: Enable development features (false in production)': None,
            },
            
            'database': {
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///database.db',
                'SQLALCHEMY_TRACK_MODIFICATIONS': 'false',
                '; Database configuration': None,
                '; SQLALCHEMY_DATABASE_URI: Database connection string': None,
                '; For SQLite (default): sqlite:///database.db': None,
                '; For PostgreSQL: postgresql://user:pass@localhost:5432/dbname': None,
                '; For MySQL: mysql+pymysql://user:pass@localhost:3306/dbname': None,
                '; For MSSQL: mssql+pyodbc://user:pass@server/db?driver=ODBC+Driver+18+for+SQL+Server': None,
            },
            
            'session': {
                'SESSION_COOKIE_SECURE': 'true',
                'SESSION_COOKIE_HTTPONLY': 'true',
                'SESSION_COOKIE_SAMESITE': 'Lax',
                'REMEMBER_COOKIE_SECURE': 'true',
                'REMEMBER_COOKIE_HTTPONLY': 'true',
                'REMEMBER_COOKIE_DURATION': '7200',
                'PERMANENT_SESSION_LIFETIME': '7200',
                '; Session and cookie configuration': None,
                '; SESSION_COOKIE_SECURE: Only send cookies over HTTPS': None,
                '; REMEMBER_COOKIE_DURATION: Remember me duration in seconds': None,
            },
            
            'cache': {
                'STATIC_MAX_AGE': '86400',
                'IMAGE_MAX_AGE': '604800',
                'JS_CSS_MAX_AGE': '43200',
                'ENABLE_COMPRESSION': 'true',
                'COMPRESSION_LEVEL': '6',
                'COMPRESSION_MIN_SIZE': '500',
                '; Cache and compression settings': None,
                '; MAX_AGE values are in seconds': None,
                '; COMPRESSION_LEVEL: 1-9 (higher = better compression, more CPU)': None,
            },
            
            'security': {
                'CONTENT_SECURITY_POLICY': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.datatables.net https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.datatables.net; img-src 'self' data:; font-src 'self' https://cdn.datatables.net; connect-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'",
                'ENABLE_HSTS': 'true',
                'HSTS_MAX_AGE': '31536000',
                'ENABLE_SECURITY_HEADERS': 'true',
                '; Security headers configuration': None,
                '; CONTENT_SECURITY_POLICY: Controls allowed content sources': None,
                '; ENABLE_HSTS: HTTP Strict Transport Security (HTTPS only)': None,
                '; HSTS_MAX_AGE: HSTS duration in seconds': None,
            },
            
            'rate_limiting': {
                'ENABLE_RATE_LIMITING': 'true',
                'REDIS_URL': '',
                'LOGIN_LIMIT': '10',
                'LOGIN_PERIOD': '60',
                'REGISTER_LIMIT': '5',
                'REGISTER_PERIOD': '300',
                'API_LIMIT': '60',
                'API_PERIOD': '60',
                '; Rate limiting configuration': None,
                '; REDIS_URL: Redis connection for distributed rate limiting (leave empty for in-memory)': None,
                '; LOGIN_LIMIT: Max login attempts per LOGIN_PERIOD seconds': None,
                '; API_LIMIT: Max API requests per API_PERIOD seconds': None,
                '; Leave REDIS_URL empty to use in-memory rate limiting': None,
            },
            
            'proxy': {
                'PROXY_COUNT': '1',
                'TRUST_X_FORWARDED_FOR': 'true',
                'TRUST_X_FORWARDED_PROTO': 'true',
                'TRUST_X_FORWARDED_HOST': 'true',
                'TRUST_X_FORWARDED_PORT': 'true',
                'TRUST_X_FORWARDED_PREFIX': 'false',
                'TRUSTED_PROXIES': '',
                '; Reverse proxy configuration': None,
                '; PROXY_COUNT: Number of proxies between client and app': None,
                '; TRUSTED_PROXIES: Comma-separated proxy IPs (empty = trust all)': None,
                '; For Docker: 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16': None,
            },
            
            'logging': {
                'DB_LOGGING_ENABLED': 'true',
                'DB_LOGGING_FILTERED_LOGGERS': 'watchfiles.main,watchfiles.watcher,watchdog,uvicorn.access,__mp_main__,__main__,app',
                'DB_LOGGING_FILTERED_PATTERNS': 'database.db,instance/,file changed,reloading',
                'FILTER_FILE_WATCHER_LOGS': 'true',
                'DB_LOGGING_DEDUPE_INTERVAL': '1',
                '; Database logging configuration': None,
                '; DB_LOGGING_ENABLED: Enable/disable database logging': None,
                '; DB_LOGGING_FILTERED_LOGGERS: Comma-separated logger names to exclude': None,
                '; DB_LOGGING_FILTERED_PATTERNS: Comma-separated patterns to exclude': None,
            }
        }
    
    def load_existing_config(self) -> bool:
        """Load existing configuration file if it exists"""
        if os.path.exists(self.config_path):
            try:
                self.config.read(self.config_path)
                logger.info(f"Loaded existing configuration from {self.config_path}")
                return True
            except Exception as e:
                logger.error(f"Error reading existing config file: {e}")
                return False
        return False
    
    def merge_config(self, preserve_existing: bool = True) -> bool:
        """
        Merge default configuration with existing configuration
        
        Args:
            preserve_existing: If True, preserve existing values; if False, update to defaults
        """
        default_config = self.get_default_config()
        changes_made = False
        
        for section_name, section_data in default_config.items():
            # Add section if it doesn't exist
            if not self.config.has_section(section_name):
                self.config.add_section(section_name)
                changes_made = True
                logger.info(f"Added new section: [{section_name}]")
            
            # Add missing options to existing sections
            for option_key, option_value in section_data.items():
                if option_key.startswith(';'):
                    # This is a comment - always add/update
                    continue
                
                if not self.config.has_option(section_name, option_key):
                    # Missing option - add it
                    if option_value is not None:
                        self.config.set(section_name, option_key, str(option_value))
                        changes_made = True
                        logger.info(f"Added missing option: [{section_name}] {option_key}")
                elif not preserve_existing and option_value is not None:
                    # Update existing option to default (only if preserve_existing=False)
                    current_value = self.config.get(section_name, option_key)
                    if current_value != str(option_value):
                        logger.info(f"Would update [{section_name}] {option_key}: {current_value} -> {option_value}")
                        # Uncomment next line to actually update existing values
                        # self.config.set(section_name, option_key, str(option_value))
                        # changes_made = True
        
        return changes_made
    
    def remove_obsolete_options(self) -> bool:
        """Remove configuration options that are no longer needed"""
        # Define obsolete options that should be removed
        obsolete_options = {
            'server': ['UVICORN_WORKERS', 'ASYNC_MODE'],  # Old Uvicorn settings
            'security': ['FEATURE_POLICY'],  # Replaced by Permissions-Policy
            'rate_limiting': ['OLD_RATE_LIMIT_SETTING'],  # Example obsolete setting
        }
        
        changes_made = False
        
        for section_name, option_list in obsolete_options.items():
            if self.config.has_section(section_name):
                for option_key in option_list:
                    if self.config.has_option(section_name, option_key):
                        self.config.remove_option(section_name, option_key)
                        changes_made = True
                        logger.info(f"Removed obsolete option: [{section_name}] {option_key}")
        
        return changes_made
    
    def save_config(self) -> bool:
        """Save the configuration to file with proper formatting"""
        try:
            # Create backup of existing config
            if os.path.exists(self.config_path):
                backup_path = f"{self.config_path}.backup"
                import shutil
                shutil.copy2(self.config_path, backup_path)
                logger.info(f"Created backup: {backup_path}")
            
            # Write the configuration with proper formatting
            with open(self.config_path, 'w', encoding='utf-8') as f:
                # Write header comment
                f.write("; Configuration file for User Monitor Application\n")
                f.write("; This file is auto-managed - existing values are preserved\n")
                f.write("; Generated/Updated by ConfigManager\n\n")
                
                # Write sections with comments
                default_config = self.get_default_config()
                
                for section_name in default_config.keys():
                    if self.config.has_section(section_name):
                        f.write(f"[{section_name}]\n")
                        
                        # Write comments first
                        for key, value in default_config[section_name].items():
                            if key.startswith(';') and value is None:
                                f.write(f"{key}\n")
                        
                        # Write actual options
                        for option_key in self.config.options(section_name):
                            option_value = self.config.get(section_name, option_key)
                            f.write(f"{option_key} = {option_value}\n")
                        
                        f.write("\n")  # Empty line between sections
            
            logger.info(f"Configuration saved to {self.config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def ensure_config_exists(self, preserve_existing: bool = True) -> bool:
        """
        Main method to ensure configuration file exists and is up-to-date
        
        Args:
            preserve_existing: If True, preserve existing values; if False, reset to defaults
        
        Returns:
            bool: True if config was created/updated successfully
        """
        config_existed = self.load_existing_config()
        
        if not config_existed:
            logger.info("No configuration file found, creating new one with defaults")
        else:
            logger.info("Existing configuration found, checking for updates needed")
        
        # Merge configurations
        merge_changes = self.merge_config(preserve_existing)
        
        # Remove obsolete options
        removal_changes = self.remove_obsolete_options()
        
        # Save if changes were made or if config didn't exist
        if not config_existed or merge_changes or removal_changes:
            success = self.save_config()
            if success:
                if not config_existed:
                    logger.info("✅ New configuration file created successfully")
                else:
                    logger.info("✅ Configuration file updated successfully")
                return True
            else:
                logger.error("❌ Failed to save configuration file")
                return False
        else:
            logger.info("✅ Configuration file is up-to-date, no changes needed")
            return True

def initialize_config(config_path: str = 'config.ini', preserve_existing: bool = True) -> configparser.ConfigParser:
    """
    Initialize configuration file and return configured ConfigParser instance
    
    Args:
        config_path: Path to the configuration file
        preserve_existing: Whether to preserve existing configuration values
    
    Returns:
        ConfigParser instance with loaded configuration
    """
    manager = ConfigManager(config_path)
    
    if manager.ensure_config_exists(preserve_existing):
        # Reload the config after ensuring it exists
        config = configparser.ConfigParser()
        config.read(config_path)
        return config
    else:
        raise RuntimeError("Failed to initialize configuration file")

# Example usage and testing
if __name__ == "__main__":
    # Test the configuration manager
    import tempfile
    import os
    
    # Use a temporary file for testing
    test_config_path = os.path.join(tempfile.gettempdir(), 'test_config.ini')
    
    print("=== Testing Configuration Manager ===")
    
    try:
        # Test 1: Create new config
        print("\n1. Testing new configuration creation...")
        config = initialize_config(test_config_path, preserve_existing=True)
        print(f"✅ New config created with {len(config.sections())} sections")
        
        # Test 2: Load existing config and add missing options
        print("\n2. Testing existing configuration update...")
        config = initialize_config(test_config_path, preserve_existing=True)
        print("✅ Existing config loaded and updated")
        
        # Test 3: Show some values
        print("\n3. Sample configuration values:")
        print(f"   Database URI: {config.get('database', 'SQLALCHEMY_DATABASE_URI')}")
        print(f"   Server Port: {config.get('server', 'PORT')}")
        print(f"   Debug Mode: {config.get('app', 'APP_DEBUG')}")
        
        print(f"\n✅ Configuration file created at: {test_config_path}")
        print("You can examine this file to see the output format")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")