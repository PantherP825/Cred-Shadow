"""
Authentication utilities for CRED-SHADOW
Handles NTLM hash parsing and credential management.
"""

import binascii
import re
from utils.logger import get_logger


def parse_ntlm_hash(hash_string):
    """
    Parse NTLM hash string into LM and NT components.
    
    Args:
        hash_string (str): Hash in format "LM:NT" or just "NT"
    
    Returns:
        tuple: (lm_hash, nt_hash) or None if invalid
    """
    logger = get_logger()
    
    if not hash_string:
        return None
    
    # Remove any whitespace
    hash_string = hash_string.strip()
    
    # Check for LM:NT format
    if ':' in hash_string:
        parts = hash_string.split(':')
        if len(parts) != 2:
            logger.error("[-] Invalid hash format. Use LM:NT or just NT hash")
            return None
        
        lm_hash, nt_hash = parts
    else:
        # Just NT hash provided
        lm_hash = ''
        nt_hash = hash_string
    
    # Validate hash formats
    if lm_hash and not re.match(r'^[a-fA-F0-9]{32}$', lm_hash):
        logger.error("[-] Invalid LM hash format (must be 32 hex characters)")
        return None
    
    if nt_hash and not re.match(r'^[a-fA-F0-9]{32}$', nt_hash):
        logger.error("[-] Invalid NT hash format (must be 32 hex characters)")
        return None
    
    return (lm_hash, nt_hash)


def validate_ntlm_hash(lm_hash, nt_hash):
    """
    Validate NTLM hash components.
    
    Args:
        lm_hash (str): LM hash
        nt_hash (str): NT hash
    
    Returns:
        bool: True if valid
    """
    try:
        if lm_hash:
            binascii.unhexlify(lm_hash)
        if nt_hash:
            binascii.unhexlify(nt_hash)
        return True
    except (ValueError, TypeError):
        return False


def format_credentials_display(username, password, ntlm_hash):
    """
    Format credentials for safe display in logs.
    
    Args:
        username (str): Username
        password (str): Password
        ntlm_hash (tuple): NTLM hash tuple
    
    Returns:
        str: Formatted credential string
    """
    if ntlm_hash and ntlm_hash[1]:  # NT hash exists
        return f"{username}:<NTLM_HASH>"
    elif password:
        return f"{username}:<PASSWORD>"
    else:
        return f"{username}:<NULL>"


def create_credential_tuple(username, password, ntlm_hash):
    """
    Create a standardized credential tuple.
    
    Args:
        username (str): Username
        password (str): Password  
        ntlm_hash (tuple): NTLM hash tuple
    
    Returns:
        tuple: (username, password, ntlm_hash)
    """
    return (username, password, ntlm_hash)


def is_null_session(username, password, ntlm_hash):
    """
    Check if credentials represent a null session.
    
    Args:
        username (str): Username
        password (str): Password
        ntlm_hash (tuple): NTLM hash tuple
    
    Returns:
        bool: True if null session
    """
    return (not username or username == '') and (not password or password == '') and not ntlm_hash