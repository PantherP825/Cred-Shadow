"""
Regex Patterns Module
Contains regex patterns for detecting secrets and sensitive information.
"""

import re

# Entropy threshold for high-entropy string detection
ENTROPY_THRESHOLD = 4.5

# Secret detection patterns
SECRET_PATTERNS = {
    # AWS Credentials
    'aws_access_key': {
        'pattern': r'AKIA[0-9A-Z]{16}',
        'description': 'AWS Access Key ID',
        'confidence': 'high'
    },
    'aws_secret_key': {
        'pattern': r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        'description': 'AWS Secret Access Key',
        'confidence': 'high'
    },
    'aws_session_token': {
        'pattern': r'aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
        'description': 'AWS Session Token',
        'confidence': 'medium'
    },
    
    # Azure Credentials
    'azure_client_secret': {
        'pattern': r'client_secret\s*[=:]\s*["\']?([A-Za-z0-9\-._~]{34,})["\']?',
        'description': 'Azure Client Secret',
        'confidence': 'medium'
    },
    'azure_subscription_key': {
        'pattern': r'subscription_key\s*[=:]\s*["\']?([A-Fa-f0-9]{32})["\']?',
        'description': 'Azure Subscription Key',
        'confidence': 'high'
    },
    
    # Google Cloud
    'gcp_service_account': {
        'pattern': r'"type":\s*"service_account"',
        'description': 'Google Cloud Service Account JSON',
        'confidence': 'high'
    },
    'gcp_api_key': {
        'pattern': r'AIza[0-9A-Za-z\-_]{35}',
        'description': 'Google API Key',
        'confidence': 'high'
    },
    
    # Database Credentials
    'db_connection_string': {
        'pattern': r'(mongodb|mysql|postgres|mssql)://[^\s;"\']*:[^\s;"\']*@[^\s;"\']*',
        'description': 'Database Connection String',
        'confidence': 'high'
    },
    'postgres_url': {
        'pattern': r'postgres://[^/\s]+:[^@\s]+@[^/\s]+/[^\s]+',
        'description': 'PostgreSQL Connection URL',
        'confidence': 'high'
    },
    'db_password': {
        'pattern': r'(db_password|database_password|db_pass)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
        'description': 'Database Password',
        'confidence': 'medium'
    },
    
    # API Keys and Tokens
    'generic_api_key': {
        'pattern': r'(api_key|apikey|api_token)\s*[=:]\s*["\']?([A-Za-z0-9\-._~]{20,})["\']?',
        'description': 'Generic API Key',
        'confidence': 'medium'
    },
    'bearer_token': {
        'pattern': r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
        'description': 'Bearer Token',
        'confidence': 'medium'
    },
    'jwt_token': {
        'pattern': r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
        'description': 'JWT Token',
        'confidence': 'medium'
    },
    
    # Social Media / OAuth
    'github_token': {
        'pattern': r'ghp_[A-Za-z0-9]{36}',
        'description': 'GitHub Personal Access Token',
        'confidence': 'high'
    },
    'github_oauth': {
        'pattern': r'gho_[A-Za-z0-9]{36}',
        'description': 'GitHub OAuth Token',
        'confidence': 'high'
    },
    'slack_token': {
        'pattern': r'xox[baprs]-[A-Za-z0-9\-]+',
        'description': 'Slack Token',
        'confidence': 'high'
    },
    'discord_token': {
        'pattern': r'[MN][A-Za-z\d]{23}\.[A-Za-z\d]{6}\.[A-Za-z\d\-_]{27}',
        'description': 'Discord Bot Token',
        'confidence': 'high'
    },
    
    # Private Keys
    'rsa_private_key': {
        'pattern': r'-----BEGIN (RSA )?PRIVATE KEY-----',
        'description': 'RSA Private Key',
        'confidence': 'high'
    },
    'ssh_private_key': {
        'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'description': 'SSH Private Key',
        'confidence': 'high'
    },
    'pgp_private_key': {
        'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'description': 'PGP Private Key',
        'confidence': 'high'
    },
    
    # Passwords and Secrets
    'password_assignment': {
        'pattern': r'(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{6,})["\']?',
        'description': 'Password Assignment',
        'confidence': 'low'
    },
    'secret_assignment': {
        'pattern': r'(secret|SECRET)\s*[=:]\s*["\']?([A-Za-z0-9\-._~+/=]{12,})["\']?',
        'description': 'Secret Assignment',
        'confidence': 'medium'
    },
    'token_assignment': {
        'pattern': r'(token|TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9\-._~+/=]{20,})["\']?',
        'description': 'Token Assignment',
        'confidence': 'medium'
    },
    
    # Email and Usernames
    'email_address': {
        'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'description': 'Email Address',
        'confidence': 'low'
    },
    
    # IP Addresses and URLs
    'private_ip': {
        'pattern': r'(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}',
        'description': 'Private IP Address',
        'confidence': 'low'
    },
    'internal_url': {
        'pattern': r'https?://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)[\w\-\./:]+',
        'description': 'Internal URL',
        'confidence': 'low'
    },
    
    # Windows Credentials
    'windows_sid': {
        'pattern': r'S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}',
        'description': 'Windows Security Identifier (SID)',
        'confidence': 'medium'
    },
    'ntlm_hash': {
        'pattern': r'[a-fA-F0-9]{32}:[a-fA-F0-9]{32}',
        'description': 'NTLM Hash',
        'confidence': 'high'
    },
    
    # Configuration Secrets
    'encryption_key': {
        'pattern': r'(encryption_key|encrypt_key)\s*[=:]\s*["\']?([A-Za-z0-9+/=]{32,})["\']?',
        'description': 'Encryption Key',
        'confidence': 'medium'
    },
    'salt_value': {
        'pattern': r'(salt|SALT)\s*[=:]\s*["\']?([A-Za-z0-9+/=]{16,})["\']?',
        'description': 'Salt Value',
        'confidence': 'low'
    },
}

# File extensions that commonly contain secrets
SECRET_FILE_EXTENSIONS = [
    '.env', '.environment',
    '.config', '.cfg', '.conf', '.ini',
    '.xml', '.json', '.yaml', '.yml',
    '.properties', '.settings',
    '.bak', '.backup', '.old', '.orig',
    '.key', '.pem', '.p12', '.pfx',
    '.sql', '.db', '.sqlite',
    '.log', '.txt'
]

# File names that commonly contain secrets
SECRET_FILE_NAMES = [
    'config', 'configuration', 'settings',
    'environment', 'env', 'secrets',
    'credentials', 'creds', 'auth',
    'password', 'passwd', 'pwd',
    'database', 'db', 'connection',
    'backup', 'dump', 'export',
    'id_rsa', 'id_dsa', 'id_ecdsa',
    'private', 'key', 'cert', 'certificate'
]

# Directories to exclude from scanning
EXCLUDED_DIRECTORIES = [
    'System Volume Information',
    '$RECYCLE.BIN',
    'Windows',
    'Program Files',
    'Program Files (x86)',
    'ProgramData',
    'Users/All Users',
    'Users/Default',
    'Users/Public',
    'temp',
    'tmp',
    '$Windows.~BT',
    '$Windows.~WS',
    'hiberfil.sys',
    'pagefile.sys',
    'swapfile.sys'
]

# Compile regex patterns for better performance
COMPILED_PATTERNS = {}

def get_compiled_patterns():
    """
    Get compiled regex patterns for better performance.
    
    Returns:
        dict: Dictionary of compiled regex patterns
    """
    global COMPILED_PATTERNS
    
    if not COMPILED_PATTERNS:
        for name, pattern_data in SECRET_PATTERNS.items():
            try:
                COMPILED_PATTERNS[name] = {
                    'regex': re.compile(pattern_data['pattern'], re.IGNORECASE | re.MULTILINE),
                    'description': pattern_data['description'],
                    'confidence': pattern_data['confidence']
                }
            except re.error as e:
                print(f"Error compiling pattern {name}: {e}")
    
    return COMPILED_PATTERNS


def is_secret_file(filename):
    """
    Check if a filename suggests it might contain secrets.
    
    Args:
        filename (str): Filename to check
    
    Returns:
        bool: True if filename suggests secrets
    """
    filename_lower = filename.lower()
    
    # Check file extensions
    for ext in SECRET_FILE_EXTENSIONS:
        if filename_lower.endswith(ext):
            return True
    
    # Check file names
    for name in SECRET_FILE_NAMES:
        if name in filename_lower:
            return True
    
    return False


def should_exclude_directory(directory_name):
    """
    Check if a directory should be excluded from scanning.
    
    Args:
        directory_name (str): Directory name to check
    
    Returns:
        bool: True if directory should be excluded
    """
    for excluded in EXCLUDED_DIRECTORIES:
        if excluded.lower() in directory_name.lower():
            return True
    
    return False


def get_high_confidence_patterns():
    """
    Get only high confidence patterns for priority scanning.
    
    Returns:
        dict: High confidence patterns
    """
    return {name: data for name, data in SECRET_PATTERNS.items() 
            if data['confidence'] == 'high'}


def get_custom_patterns():
    """
    Get custom patterns that can be defined by users.
    
    Returns:
        dict: Custom patterns dictionary
    """
    custom_patterns = {
        # Add custom patterns here
        'custom_secret': {
            'pattern': r'custom_pattern_here',
            'description': 'Custom Secret Pattern',
            'confidence': 'medium'
        }
    }
    
    return custom_patterns


def validate_pattern(pattern_string):
    """
    Validate a regex pattern string.
    
    Args:
        pattern_string (str): Regex pattern to validate
    
    Returns:
        bool: True if pattern is valid
    """
    try:
        re.compile(pattern_string)
        return True
    except re.error:
        return False


def add_custom_pattern(name, pattern, description, confidence='medium'):
    """
    Add a custom pattern to the detection patterns.
    
    Args:
        name (str): Pattern name
        pattern (str): Regex pattern
        description (str): Pattern description
        confidence (str): Confidence level (high, medium, low)
    
    Returns:
        bool: True if pattern was added successfully
    """
    global SECRET_PATTERNS
    
    if validate_pattern(pattern):
        SECRET_PATTERNS[name] = {
            'pattern': pattern,
            'description': description,
            'confidence': confidence
        }
        
        # Clear compiled patterns cache to force recompilation
        global COMPILED_PATTERNS
        COMPILED_PATTERNS = {}
        
        return True
    
    return False
