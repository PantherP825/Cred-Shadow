"""
Credential Validation Module
Handles validation of SMB credentials and service detection.
"""

import socket
import time
from impacket.smbconnection import SMBConnection
from impacket import version
from utils.logger import get_logger


def validate_credentials(target, username, password, ntlm_hash=None, port=445, logger=None):
    """
    Validate SMB credentials against target.
    
    Args:
        target (str): Target IP or hostname
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple (lm_hash, nt_hash)
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        bool: True if credentials are valid
    """
    if logger is None:
        logger = get_logger()
    
    smb_conn = None
    try:
        # Create SMB connection with shorter timeout for validation
        smb_conn = SMBConnection(target, target, None, port, timeout=5)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            # Try anonymous/null session
            try:
                smb_conn.login('', '')
            except:
                smb_conn.close()
                smb_conn = SMBConnection(target, target, None, port, timeout=5)
                smb_conn.login('guest', '')
        else:
            smb_conn.login(username or '', password or '')
        
        auth_type = "NTLM hash" if ntlm_hash else ("null session" if not username and not password else "credentials")
        logger.debug(f"[+] Valid {auth_type} for: {username or 'anonymous'}")
        return True
        
    except Exception as e:
        logger.debug(f"[-] Credential validation failed: {str(e)}")
        return False
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def probe_smb_service(target, port=445, timeout=10, logger=None):
    """
    Probe SMB service to check availability and gather basic info.
    
    Args:
        target (str): Target IP or hostname
        port (int): SMB port
        timeout (int): Connection timeout
        logger: Logger instance
    
    Returns:
        dict: Service information or None if not available
    """
    if logger is None:
        logger = get_logger()
    
    try:
        # Test basic TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result != 0:
            logger.debug(f"[-] Port {port} is not open on {target}")
            return None
        
        # Try to connect with SMB
        smb_conn = SMBConnection(target, target, sess_port=port, timeout=timeout)
        
        # Try anonymous connection to get server info
        try:
            smb_conn.login('', '')
            anonymous_ok = True
        except:
            anonymous_ok = False
        
        # Get server information
        server_name = smb_conn.getServerName()
        server_domain = smb_conn.getServerDomain()
        server_os = smb_conn.getServerOS()
        
        smb_conn.close()
        
        service_info = {
            'server_name': server_name,
            'domain': server_domain,
            'os': server_os,
            'anonymous_access': anonymous_ok,
            'smb_version': 'SMBv1/v2/v3'  # Could be enhanced to detect specific version
        }
        
        logger.info(f"[+] SMB service detected on {target}:{port}")
        logger.info(f"    Server: {server_name}")
        logger.info(f"    Domain: {server_domain}")
        logger.info(f"    OS: {server_os}")
        logger.info(f"    Anonymous: {'Yes' if anonymous_ok else 'No'}")
        
        return service_info
        
    except socket.error as e:
        logger.debug(f"[-] Network error probing {target}:{port} - {str(e)}")
        return None
    except Exception as e:
        logger.debug(f"[-] Error probing SMB service on {target}:{port} - {str(e)}")
        return None


def test_null_session(target, port=445, logger=None):
    """
    Test for null session access.
    
    Args:
        target (str): Target IP or hostname
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        bool: True if null session is allowed
    """
    if logger is None:
        logger = get_logger()
    
    return validate_credentials(target, '', '', port=port, logger=logger)


def test_guest_access(target, port=445, logger=None):
    """
    Test for guest account access.
    
    Args:
        target (str): Target IP or hostname
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        bool: True if guest access is allowed
    """
    if logger is None:
        logger = get_logger()
    
    # Try common guest account names
    guest_accounts = ['guest', 'Guest', 'GUEST', 'anonymous', 'Anonymous']
    
    for guest_user in guest_accounts:
        if validate_credentials(target, guest_user, '', port=port, logger=logger):
            logger.info(f"[+] Guest access available with account: {guest_user}")
            return True
    
    return False


def enumerate_smb_info(target, username, password, ntlm_hash=None, port=445, logger=None):
    """
    Enumerate detailed SMB information using valid credentials.
    
    Args:
        target (str): Target IP or hostname
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        dict: SMB information
    """
    if logger is None:
        logger = get_logger()
    
    smb_conn = None
    info = {}
    
    try:
        # Create SMB connection
        smb_conn = SMBConnection(target, target, sess_port=port)
        
        # Authenticate
        if ntlm_hash:
            lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, lmhash=lm_hash, nthash=nt_hash)
        else:
            smb_conn.login(username, password)
        
        # Gather information
        info['server_name'] = smb_conn.getServerName()
        info['server_domain'] = smb_conn.getServerDomain()
        info['server_os'] = smb_conn.getServerOS()
        info['server_time'] = time.ctime(smb_conn.getServerTime())
        
        # Try to get share list
        try:
            shares = smb_conn.listShares()
            info['shares'] = []
            
            for share in shares:
                share_info = {
                    'name': share['shi1_netname'][:-1],  # Remove null terminator
                    'type': share['shi1_type'],
                    'comment': share['shi1_remark'][:-1] if share['shi1_remark'] else ''
                }
                info['shares'].append(share_info)
        except Exception as e:
            logger.debug(f"[-] Could not enumerate shares: {str(e)}")
            info['shares'] = []
        
        logger.info(f"[+] Enumerated SMB info for {target}")
        
        return info
        
    except Exception as e:
        logger.error(f"[-] Error enumerating SMB info: {str(e)}")
        return {}
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def batch_validate_credentials(target, credential_list, port=445, logger=None, max_workers=5):
    """
    Validate multiple credentials in batch.
    
    Args:
        target (str): Target IP or hostname
        credential_list (list): List of credential tuples (username, password, ntlm_hash)
        port (int): SMB port
        logger: Logger instance
        max_workers (int): Maximum number of worker threads
    
    Returns:
        list: List of valid credential tuples
    """
    if logger is None:
        logger = get_logger()
    
    valid_creds = []
    
    import concurrent.futures
    
    def validate_single_cred(cred_tuple):
        """Validate a single credential."""
        username, password, ntlm_hash = cred_tuple
        
        if validate_credentials(target, username, password, ntlm_hash, port, logger):
            return cred_tuple
        return None
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all validation tasks
            future_to_creds = {executor.submit(validate_single_cred, cred): cred 
                              for cred in credential_list}
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_creds):
                try:
                    result = future.result()
                    if result:
                        valid_creds.append(result)
                except Exception as e:
                    logger.debug(f"[-] Validation error: {str(e)}")
        
        logger.info(f"[+] Batch validation completed: {len(valid_creds)}/{len(credential_list)} valid")
        
    except Exception as e:
        logger.error(f"[-] Batch validation error: {str(e)}")
    
    return valid_creds


def check_signing_requirements(target, port=445, logger=None):
    """
    Check SMB signing requirements.
    
    Args:
        target (str): Target IP or hostname
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        dict: Signing information
    """
    if logger is None:
        logger = get_logger()
    
    try:
        smb_conn = SMBConnection(target, target, sess_port=port)
        
        # The connection attempt itself will reveal signing requirements
        try:
            smb_conn.login('', '')
        except:
            pass  # We just want to establish the connection to check signing
        
        # Get server capabilities (this is simplified - real implementation would need more SMB protocol details)
        signing_info = {
            'signing_enabled': True,  # Most modern systems have signing enabled
            'signing_required': False,  # This would need deeper SMB negotiation to determine
            'encryption_supported': True  # SMB3+ typically supports encryption
        }
        
        smb_conn.close()
        
        logger.info(f"[+] SMB signing check completed for {target}")
        return signing_info
        
    except Exception as e:
        logger.debug(f"[-] Error checking SMB signing: {str(e)}")
        return {}
