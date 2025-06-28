"""
Hash Utilities Module
Handles NTLM hash parsing and validation for authentication.
"""

import binascii
from utils.logger import get_logger


def parse_ntlm_hash(hash_string):
    """
    Parse NTLM hash string into LM and NT hash components.
    
    Args:
        hash_string (str): Hash in format "LM:NT" or just "NT"
    
    Returns:
        tuple: (lm_hash, nt_hash) or None if invalid
    """
    logger = get_logger()
    
    if not hash_string:
        return None
    
    try:
        # Clean the hash string
        hash_string = hash_string.strip()
        
        # Handle different formats
        if ':' in hash_string:
            # Format: LM:NT
            parts = hash_string.split(':')
            if len(parts) != 2:
                logger.error(f"[-] Invalid hash format. Expected LM:NT, got: {hash_string}")
                return None
            
            lm_hash = parts[0].strip()
            nt_hash = parts[1].strip()
        else:
            # Format: NT only
            lm_hash = ""
            nt_hash = hash_string
        
        # Validate hash lengths and format
        if lm_hash and len(lm_hash) != 32:
            logger.error(f"[-] Invalid LM hash length. Expected 32 characters, got: {len(lm_hash)}")
            return None
        
        if len(nt_hash) != 32:
            logger.error(f"[-] Invalid NT hash length. Expected 32 characters, got: {len(nt_hash)}")
            return None
        
        # Validate hex format
        try:
            if lm_hash:
                binascii.unhexlify(lm_hash)
            binascii.unhexlify(nt_hash)
        except ValueError:
            logger.error(f"[-] Invalid hash format. Hashes must be hexadecimal")
            return None
        
        # Convert empty LM hash to None for impacket
        if not lm_hash or lm_hash.lower() == "aad3b435b51404eeaad3b435b51404ee":
            lm_hash = None
        
        logger.info(f"[+] Successfully parsed NTLM hash")
        return (lm_hash, nt_hash)
        
    except Exception as e:
        logger.error(f"[-] Error parsing NTLM hash: {e}")
        return None


def validate_hash_format(hash_string):
    """
    Validate NTLM hash format without parsing.
    
    Args:
        hash_string (str): Hash string to validate
    
    Returns:
        bool: True if format is valid
    """
    if not hash_string:
        return False
    
    hash_string = hash_string.strip()
    
    # Check for colon separator
    if ':' in hash_string:
        parts = hash_string.split(':')
        if len(parts) != 2:
            return False
        lm_hash, nt_hash = parts
        
        # Validate LM hash (32 hex chars or empty)
        if lm_hash and (len(lm_hash) != 32 or not all(c in '0123456789abcdefABCDEF' for c in lm_hash)):
            return False
        
        # Validate NT hash (32 hex chars)
        if len(nt_hash) != 32 or not all(c in '0123456789abcdefABCDEF' for c in nt_hash):
            return False
    else:
        # NT hash only
        if len(hash_string) != 32 or not all(c in '0123456789abcdefABCDEF' for c in hash_string):
            return False
    
    return True


def hash_to_string(lm_hash, nt_hash):
    """
    Convert hash tuple back to string format.
    
    Args:
        lm_hash (str): LM hash
        nt_hash (str): NT hash
    
    Returns:
        str: Hash in LM:NT format
    """
    if lm_hash:
        return f"{lm_hash}:{nt_hash}"
    else:
        return f":{nt_hash}"


def is_empty_lm_hash(lm_hash):
    """
    Check if LM hash is empty or default.
    
    Args:
        lm_hash (str): LM hash to check
    
    Returns:
        bool: True if empty LM hash
    """
    if not lm_hash:
        return True
    
    # Default empty LM hash
    empty_lm = "aad3b435b51404eeaad3b435b51404ee"
    return lm_hash.lower() == empty_lm.lower()


def get_hash_info(hash_string):
    """
    Get information about the hash format.
    
    Args:
        hash_string (str): Hash string
    
    Returns:
        dict: Hash information
    """
    parsed = parse_ntlm_hash(hash_string)
    if not parsed:
        return {"valid": False}
    
    lm_hash, nt_hash = parsed
    
    return {
        "valid": True,
        "has_lm": lm_hash is not None and not is_empty_lm_hash(lm_hash),
        "has_nt": nt_hash is not None,
        "lm_hash": lm_hash,
        "nt_hash": nt_hash,
        "format": "LM:NT" if lm_hash else "NT_ONLY"
    }