"""
Configuration Module
Handles configuration settings and validation.
"""

import os
import json
import configparser
from utils.logger import get_logger


class Config:
    """Configuration management class."""
    
    def __init__(self, args=None):
        """
        Initialize configuration with command line arguments.
        
        Args:
            args: Parsed command line arguments
        """
        self.args = args
        self.config_data = {}
        self.load_default_config()
        
        if args:
            self.update_from_args(args)
    
    def load_default_config(self):
        """Load default configuration values."""
        self.config_data = {
            # Target settings
            'target': {
                'host': None,
                'port': 445,
                'timeout': 30
            },
            
            # Authentication settings
            'auth': {
                'username': None,
                'password': None,
                'ntlm_hash': None,
                'null_session': False,
                'domain': None
            },
            
            # Scanning settings
            'scan': {
                'max_depth': 3,
                'size_limit_mb': 20,
                'threads': 5,
                'file_timeout': 10,
                'retry_attempts': 3
            },
            
            # Attack settings
            'attack': {
                'brute_force': False,
                'password_spray': False,
                'delay_between_attempts': 1,
                'delay_between_passwords': 300,
                'max_workers': 5,
                'throttle_attempts': 30
            },
            
            # Detection settings
            'detection': {
                'entropy_threshold': 4.5,
                'min_secret_length': 8,
                'max_secret_length': 100,
                'confidence_threshold': 'low',
                'custom_patterns': {}
            },
            
            # Output settings
            'output': {
                'format': 'json',
                'directory': 'output',
                'filename_prefix': 'cred-shadow',
                'include_context': True,
                'max_context_lines': 3
            },
            
            # Logging settings
            'logging': {
                'level': 'INFO',
                'file_logging': True,
                'console_logging': True,
                'log_attacks': True,
                'log_findings': True
            },
            
            # Performance settings
            'performance': {
                'connection_pool_size': 10,
                'max_file_size_mb': 50,
                'cache_enabled': True,
                'batch_size': 100
            }
        }
    
    def update_from_args(self, args):
        """
        Update configuration from command line arguments.
        
        Args:
            args: Parsed command line arguments
        """
        # Target settings
        if hasattr(args, 'target') and args.target:
            self.config_data['target']['host'] = args.target
        if hasattr(args, 'port') and args.port:
            self.config_data['target']['port'] = args.port
        if hasattr(args, 'timeout') and args.timeout:
            self.config_data['target']['timeout'] = args.timeout
        
        # Authentication settings
        if hasattr(args, 'username') and args.username:
            self.config_data['auth']['username'] = args.username
        if hasattr(args, 'password') and args.password:
            self.config_data['auth']['password'] = args.password
        if hasattr(args, 'hash') and args.hash:
            self.config_data['auth']['ntlm_hash'] = args.hash
        if hasattr(args, 'null_session') and args.null_session:
            self.config_data['auth']['null_session'] = args.null_session
        
        # Scanning settings
        if hasattr(args, 'depth') and args.depth:
            self.config_data['scan']['max_depth'] = args.depth
        if hasattr(args, 'size_limit') and args.size_limit:
            self.config_data['scan']['size_limit_mb'] = args.size_limit
        if hasattr(args, 'threads') and args.threads:
            self.config_data['scan']['threads'] = args.threads
        
        # Attack settings
        if hasattr(args, 'bruteforce') and args.bruteforce:
            self.config_data['attack']['brute_force'] = args.bruteforce
        if hasattr(args, 'spray') and args.spray:
            self.config_data['attack']['password_spray'] = args.spray
        
        # Logging settings
        if hasattr(args, 'verbose') and args.verbose:
            self.config_data['logging']['level'] = 'DEBUG'
        if hasattr(args, 'quiet') and args.quiet:
            self.config_data['logging']['level'] = 'ERROR'
    
    def load_from_file(self, config_file):
        """
        Load configuration from file.
        
        Args:
            config_file (str): Path to configuration file
        
        Returns:
            bool: True if loaded successfully
        """
        logger = get_logger()
        
        try:
            if config_file.endswith('.json'):
                return self._load_json_config(config_file)
            elif config_file.endswith('.ini') or config_file.endswith('.cfg'):
                return self._load_ini_config(config_file)
            else:
                logger.error(f"[-] Unsupported config file format: {config_file}")
                return False
        except Exception as e:
            logger.error(f"[-] Error loading config file: {str(e)}")
            return False
    
    def _load_json_config(self, config_file):
        """Load JSON configuration file."""
        logger = get_logger()
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            
            # Merge with existing config
            self._deep_merge(self.config_data, file_config)
            logger.info(f"[+] Loaded JSON config: {config_file}")
            return True
        except Exception as e:
            logger.error(f"[-] Error loading JSON config: {str(e)}")
            return False
    
    def _load_ini_config(self, config_file):
        """Load INI configuration file."""
        logger = get_logger()
        
        try:
            config = configparser.ConfigParser()
            config.read(config_file)
            
            # Convert INI to nested dict structure
            for section_name in config.sections():
                if section_name not in self.config_data:
                    self.config_data[section_name] = {}
                
                for key, value in config.items(section_name):
                    # Try to convert to appropriate type
                    try:
                        # Try boolean
                        if value.lower() in ['true', 'false']:
                            self.config_data[section_name][key] = value.lower() == 'true'
                        # Try integer
                        elif value.isdigit():
                            self.config_data[section_name][key] = int(value)
                        # Try float
                        elif '.' in value and value.replace('.', '').isdigit():
                            self.config_data[section_name][key] = float(value)
                        # Keep as string
                        else:
                            self.config_data[section_name][key] = value
                    except:
                        self.config_data[section_name][key] = value
            
            logger.info(f"[+] Loaded INI config: {config_file}")
            return True
        except Exception as e:
            logger.error(f"[-] Error loading INI config: {str(e)}")
            return False
    
    def _deep_merge(self, base_dict, update_dict):
        """Recursively merge dictionaries."""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def save_to_file(self, config_file):
        """
        Save configuration to file.
        
        Args:
            config_file (str): Path to save configuration
        
        Returns:
            bool: True if saved successfully
        """
        logger = get_logger()
        
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            
            if config_file.endswith('.json'):
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(self.config_data, f, indent=2)
            elif config_file.endswith('.ini') or config_file.endswith('.cfg'):
                config = configparser.ConfigParser()
                
                for section_name, section_data in self.config_data.items():
                    config.add_section(section_name)
                    for key, value in section_data.items():
                        config.set(section_name, key, str(value))
                
                with open(config_file, 'w', encoding='utf-8') as f:
                    config.write(f)
            else:
                logger.error(f"[-] Unsupported config file format: {config_file}")
                return False
            
            logger.info(f"[+] Configuration saved: {config_file}")
            return True
        except Exception as e:
            logger.error(f"[-] Error saving config: {str(e)}")
            return False
    
    def get(self, section, key=None, default=None):
        """
        Get configuration value.
        
        Args:
            section (str): Configuration section
            key (str): Configuration key (optional)
            default: Default value if not found
        
        Returns:
            Configuration value or default
        """
        if key is None:
            return self.config_data.get(section, default)
        
        section_data = self.config_data.get(section, {})
        return section_data.get(key, default)
    
    def set(self, section, key, value):
        """
        Set configuration value.
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            value: Value to set
        """
        if section not in self.config_data:
            self.config_data[section] = {}
        
        self.config_data[section][key] = value
    
    def validate(self):
        """
        Validate configuration settings.
        
        Returns:
            tuple: (is_valid, error_messages)
        """
        errors = []
        
        # Validate target settings
        if not self.get('target', 'host'):
            errors.append("Target host is required")
        
        port = self.get('target', 'port')
        if not isinstance(port, int) or port < 1 or port > 65535:
            errors.append("Invalid port number")
        
        # Validate scan settings
        depth = self.get('scan', 'max_depth')
        if not isinstance(depth, int) or depth < 1 or depth > 10:
            errors.append("Max depth must be between 1 and 10")
        
        size_limit = self.get('scan', 'size_limit_mb')
        if not isinstance(size_limit, int) or size_limit < 1:
            errors.append("Size limit must be a positive integer")
        
        threads = self.get('scan', 'threads')
        if not isinstance(threads, int) or threads < 1 or threads > 50:
            errors.append("Thread count must be between 1 and 50")
        
        # Validate attack settings
        if self.get('attack', 'brute_force') or self.get('attack', 'password_spray'):
            if not self.get('auth', 'username') and not hasattr(self.args, 'userlist'):
                errors.append("Username or userlist required for attacks")
        
        return len(errors) == 0, errors
    
    def get_wordlist_paths(self):
        """
        Get paths to wordlist files.
        
        Returns:
            dict: Dictionary with userlist and passlist paths
        """
        wordlists = {
            'userlist': None,
            'passlist': None
        }
        
        if hasattr(self.args, 'userlist') and self.args.userlist:
            wordlists['userlist'] = self.args.userlist
        else:
            # Check for default wordlists
            default_userlist = 'data/userlist.txt'
            if os.path.exists(default_userlist):
                wordlists['userlist'] = default_userlist
        
        if hasattr(self.args, 'passlist') and self.args.passlist:
            wordlists['passlist'] = self.args.passlist
        else:
            # Check for default wordlists
            default_passlist = 'data/passwordlist.txt'
            if os.path.exists(default_passlist):
                wordlists['passlist'] = default_passlist
        
        return wordlists
    
    def get_output_settings(self):
        """
        Get output format and file settings.
        
        Returns:
            dict: Output settings
        """
        output_settings = {
            'json_file': None,
            'csv_file': None,
            'directory': self.get('output', 'directory')
        }
        
        if hasattr(self.args, 'output') and self.args.output:
            output_settings['json_file'] = self.args.output
        
        if hasattr(self.args, 'csv') and self.args.csv:
            output_settings['csv_file'] = self.args.csv
        
        return output_settings
    
    def __str__(self):
        """String representation of configuration."""
        return json.dumps(self.config_data, indent=2)
