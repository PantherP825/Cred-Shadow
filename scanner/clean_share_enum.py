"""
Clean SMB Share Enumeration Module
Eliminates cached data and fallback share names that cause old share names to persist.
"""

import socket
import time
import platform
import re
import os
from impacket.smbconnection import SMBConnection
from utils.logger import get_logger


def safe_decode_share_data(data, errors='ignore'):
    """Safely decode share data with multiple encoding fallbacks."""
    if isinstance(data, str):
        return data.rstrip('\x00')
    
    if not isinstance(data, bytes):
        return str(data).rstrip('\x00')
    
    # Try multiple encodings for cross-platform compatibility
    encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
    
    for encoding in encodings:
        try:
            return data.decode(encoding, errors=errors).rstrip('\x00')
        except (UnicodeDecodeError, AttributeError):
            continue
    
    # Last resort
    return data.decode('utf-8', errors='replace').rstrip('\x00')


def extract_real_share_name(share_object, logger=None):
    """
    Extract actual share name from impacket share object without fallbacks.
    Returns None if share name cannot be reliably extracted.
    """
    try:
        share_name = None
        
        # Method 1: Direct attribute access
        if hasattr(share_object, 'get_name'):
            share_name = safe_decode_share_data(share_object.get_name())
        elif hasattr(share_object, 'name'):
            share_name = safe_decode_share_data(share_object.name)
        elif hasattr(share_object, 'shi1_netname'):
            share_name = safe_decode_share_data(share_object.shi1_netname)
        elif hasattr(share_object, '__getitem__'):
            try:
                share_name = safe_decode_share_data(share_object['shi1_netname'])
            except (KeyError, TypeError):
                pass
        
        # Method 2: String representation parsing (strict)
        if not share_name:
            share_str = str(share_object)
            if logger:
                logger.debug(f"[*] Share string: {repr(share_str)}")
            
            # Look for valid share name patterns only
            match = re.search(r'^([a-zA-Z0-9$_\-\.]{1,15})\s*\(', share_str)
            if match:
                candidate = match.group(1)
                # Reject generic patterns
                if not re.match(r'^(Share_?\d+|share\d+|unknown|null|none|\d+)$', candidate, re.IGNORECASE):
                    share_name = candidate
        
        # Validate result
        if share_name and share_name.strip():
            share_name = share_name.strip()
            
            # Final validation - reject any generic or cached names
            if re.match(r'^(Share_?\d+|share\d+|unknown|null|none|albert|smbshare|Share_\d+)$', share_name, re.IGNORECASE):
                if logger:
                    logger.debug(f"[-] Rejecting generic/cached name: '{share_name}'")
                return None
            
            return share_name
        
        return None
        
    except Exception as e:
        if logger:
            logger.debug(f"[-] Share name extraction failed: {e}")
        return None


def get_share_type(share_object):
    """Extract share type from share object."""
    try:
        if hasattr(share_object, 'get_type'):
            return share_object.get_type()
        elif hasattr(share_object, 'type'):
            return share_object.type
        elif hasattr(share_object, 'shi1_type'):
            return share_object.shi1_type
        elif hasattr(share_object, '__getitem__'):
            try:
                return share_object['shi1_type']
            except (KeyError, TypeError):
                pass
        return 0
    except Exception:
        return 0


def get_share_comment(share_object):
    """Extract share comment from share object."""
    try:
        if hasattr(share_object, 'get_comment'):
            return safe_decode_share_data(share_object.get_comment())
        elif hasattr(share_object, 'comment'):
            return safe_decode_share_data(share_object.comment)
        elif hasattr(share_object, 'shi1_remark'):
            return safe_decode_share_data(share_object.shi1_remark)
        elif hasattr(share_object, '__getitem__'):
            try:
                return safe_decode_share_data(share_object['shi1_remark'])
            except (KeyError, TypeError):
                pass
        return ''
    except Exception:
        return ''


def test_share_access(target, share_name, username, password, ntlm_hash, port=445, logger=None):
    """Test comprehensive access to a specific share including read/write permissions."""
    try:
        # Get platform-appropriate timeout
        timeout = 30 if platform.system().lower() == 'windows' else 15
        
        smb_conn = SMBConnection(target, target, None, port, timeout=timeout)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            smb_conn.login('', '')
        else:
            smb_conn.login(username, password, '')
        
        # Test read access first
        can_read = False
        file_count = 0
        access_paths = ['', '.', '/', '*']
        
        for path in access_paths:
            try:
                files = smb_conn.listPath(share_name, path)
                file_count = len([f for f in files if f.get_longname() not in ['.', '..']])
                can_read = True
                break
            except Exception as read_error:
                if logger:
                    logger.debug(f"Read test failed for path '{path}': {read_error}")
                continue
        
        # Test write access by attempting to create a temporary file
        can_write = False
        if can_read:
            test_filename = f"cred_shadow_test_{int(time.time())}.tmp"
            try:
                # Try to create a small test file
                from io import BytesIO
                test_content = BytesIO(b"CRED-SHADOW access test")
                smb_conn.putFile(share_name, test_filename, test_content.read)
                # If successful, delete the test file
                try:
                    smb_conn.deleteFile(share_name, test_filename)
                except:
                    pass  # Ignore deletion errors
                can_write = True
            except Exception as write_error:
                if logger:
                    logger.debug(f"Write test failed: {write_error}")
                # Check for specific write permission errors
                error_str = str(write_error).lower()
                if 'access_denied' not in error_str and 'permission denied' not in error_str:
                    # Might be read-only due to share settings, not permissions
                    pass
        
        smb_conn.close()
        
        # Determine access level based on tests
        if can_read and can_write:
            return f"READ/WRITE ({file_count} items)"
        elif can_read:
            return f"READ ({file_count} items)"
        else:
            # Try to connect to share directly to see if it exists
            try:
                smb_conn2 = SMBConnection(target, target, None, port, timeout=timeout)
                if ntlm_hash:
                    if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                        lm_hash, nt_hash = ntlm_hash.split(':', 1)
                    else:
                        lm_hash, nt_hash = ntlm_hash
                    smb_conn2.login(username, password, '', lm_hash, nt_hash)
                else:
                    smb_conn2.login(username, password, '')
                
                # Try alternative access methods
                smb_conn2.connectTree(share_name)
                smb_conn2.close()
                return "LIMITED"
            except:
                return "NO ACCESS"
            
    except Exception as e:
        error_str = str(e).lower()
        if 'access_denied' in error_str or 'permission denied' in error_str:
            return "NO ACCESS"
        elif 'invalid share' in error_str or 'bad network name' in error_str:
            return "INVALID SHARE"
        else:
            if logger:
                logger.debug(f"Share access test error: {e}")
            return "UNKNOWN"


def list_directory(target, share_name, path, username, password, ntlm_hash, port=445):
    """
    List directory contents for manual mode navigation.
    
    Args:
        target (str): Target IP or hostname
        share_name (str): Share name
        path (str): Directory path
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
    
    Returns:
        list: List of file/directory info dictionaries
    """
    try:
        # Get platform-appropriate timeout
        timeout = 30 if platform.system().lower() == 'windows' else 15
        
        smb_conn = SMBConnection(target, target, None, port, timeout=timeout)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            smb_conn.login('', '')
        else:
            smb_conn.login(username, password, '')
        
        # Normalize path
        if not path or path == '/':
            path = ''
        elif path.startswith('/'):
            path = path[1:]
        
        # Try multiple path formats
        path_attempts = [path, path + '/*', path + '\\*', '*' if not path else path]
        
        files_info = []
        for attempt_path in path_attempts:
            try:
                files = smb_conn.listPath(share_name, attempt_path)
                
                for file_info in files:
                    filename = file_info.get_longname()
                    if filename in ['.', '..']:
                        continue
                    
                    file_dict = {
                        'name': filename,
                        'size': file_info.get_filesize() if hasattr(file_info, 'get_filesize') else 0,
                        'is_directory': file_info.is_directory(),
                        'modified_time': getattr(file_info, 'last_write_time', None),
                        'type': 'DIR' if file_info.is_directory() else 'FILE'
                    }
                    files_info.append(file_dict)
                
                break  # Success, exit the retry loop
                
            except Exception as e:
                error_str = str(e).lower()
                if 'access_denied' in error_str or 'permission denied' in error_str:
                    raise Exception(f"Access denied to {share_name}:{path}")
                elif 'invalid share' in error_str or 'bad network name' in error_str:
                    raise Exception(f"Invalid share: {share_name}")
                continue  # Try next path format
        
        smb_conn.close()
        return files_info
        
    except Exception as e:
        raise Exception(f"Directory listing failed: {str(e)}")





def get_file_info(target, share_name, file_path, username, password, ntlm_hash, port=445):
    """
    Get detailed file information for manual mode.
    
    Args:
        target (str): Target IP or hostname
        share_name (str): Share name
        file_path (str): File path
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
    
    Returns:
        dict: File information dictionary
    """
    try:
        # Get platform-appropriate timeout
        timeout = 30 if platform.system().lower() == 'windows' else 15
        
        smb_conn = SMBConnection(target, target, None, port, timeout=timeout)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            smb_conn.login('', '')
        else:
            smb_conn.login(username, password, '')
        
        # Get file info by listing the parent directory
        parent_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else ''
        filename = os.path.basename(file_path)
        
        try:
            files = smb_conn.listPath(share_name, parent_dir)
            file_attrs = None
            for f in files:
                if f.get_longname() == filename:
                    file_attrs = f
                    break
        except:
            # Fallback: try to list the file directly
            try:
                files = smb_conn.listPath(share_name, file_path)
                file_attrs = files[0] if files else None
            except:
                file_attrs = None
        
        if file_attrs:
            file_info = {
                'name': filename,
                'path': file_path,
                'size': file_attrs.get_filesize() if hasattr(file_attrs, 'get_filesize') else 0,
                'is_directory': file_attrs.is_directory(),
                'modified_time': getattr(file_attrs, 'last_write_time', None),
                'created_time': getattr(file_attrs, 'creation_time', None),
                'accessed_time': getattr(file_attrs, 'last_access_time', None)
            }
        else:
            file_info = {
                'name': filename,
                'path': file_path,
                'size': 0,
                'is_directory': False,
                'modified_time': None,
                'created_time': None,
                'accessed_time': None
            }
        
        smb_conn.close()
        return file_info
        
    except Exception as e:
        raise Exception(f"Failed to get file info: {str(e)}")


def enumerate_shares_clean(target, credentials_list, port=445, logger=None):
    """
    Clean share enumeration that only returns actual parsed share names.
    No fallback names, no cached data, no generic Share_X entries.
    """
    if logger is None:
        logger = get_logger()
    
    logger.info(f"[*] Starting clean share enumeration on {target}:{port}")
    
    # Check connectivity first with enhanced diagnostics
    timeout = 30 if platform.system().lower() == 'windows' else 15
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Quick timeout to avoid hanging on unreachable targets
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result != 0:
            error_msg = f"[-] Cannot connect to {target}:{port}"
            if result == 111:  # Connection refused
                error_msg += " (Connection refused - SMB service not running or blocked)"
            elif result == 110:  # Connection timed out
                error_msg += " (Connection timeout - target unreachable or firewalled)"
            elif result == 113:  # No route to host
                error_msg += " (No route to host - network connectivity issue)"
            elif result == 11:  # Resource temporarily unavailable
                error_msg += " (Resource unavailable - target may be down or unreachable)"
            elif result == 101:  # Network unreachable
                error_msg += " (Network unreachable - routing issue)"
            else:
                error_msg += f" (Error code: {result})"
            
            logger.error(error_msg)
            logger.info(f"[*] Connection troubleshooting suggestions:")
            logger.info(f"    - Target {target} may not be reachable from this environment")
            logger.info(f"    - SMB service may not be running on port {port}")
            logger.info(f"    - Firewall may be blocking connections to port {port}")
            logger.info(f"    - For lab environments (HTB/TryHackMe), ensure VPN is connected")
            logger.info(f"    - Try alternative SMB port: 139")
            logger.info(f"    - Verify target is powered on and accessible")
            
            # Try alternative port 139 for SMB
            if port == 445:
                logger.info(f"[*] Attempting connection to alternative SMB port 139...")
                try:
                    alt_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    alt_sock.settimeout(5)
                    alt_result = alt_sock.connect_ex((target, 139))
                    alt_sock.close()
                    
                    if alt_result == 0:
                        logger.info(f"[+] Port 139 is accessible - SMB service may be running on port 139")
                        logger.info(f"[*] Try running with: --port 139")
                    else:
                        logger.info(f"[-] Port 139 also unavailable (error {alt_result})")
                except:
                    pass
            
            return []
    except Exception as e:
        logger.error(f"[-] Connection test failed: {e}")
        logger.info(f"[*] Network error troubleshooting:")
        logger.info(f"    - Check DNS resolution for {target}")
        logger.info(f"    - Verify network interface is configured correctly")
        logger.info(f"    - Ensure no proxy settings are interfering")
        return []
    
    all_shares = []
    
    # Try each credential set
    for username, password, ntlm_hash in credentials_list:
        session_type = "Anonymous" if not username and not password else f"Authenticated ({username})"
        logger.info(f"[*] Trying {session_type}")
        
        try:
            smb_conn = SMBConnection(target, target, None, port, timeout=timeout)
            
            # Authenticate
            if ntlm_hash:
                if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                    lm_hash, nt_hash = ntlm_hash.split(':', 1)
                else:
                    lm_hash, nt_hash = ntlm_hash
                smb_conn.login(username, password, '', lm_hash, nt_hash)
            elif not username and not password:
                smb_conn.login('', '')
            else:
                smb_conn.login(username, password, '')
            
            logger.info(f"[+] Authentication successful: {session_type}")
            
            # Get shares
            raw_shares = smb_conn.listShares()
            logger.info(f"[*] Retrieved {len(raw_shares)} raw share objects")
            
            session_shares = []
            
            # Parse each share - ONLY add shares with valid names
            for i, share_obj in enumerate(raw_shares):
                share_name = extract_real_share_name(share_obj, logger)
                
                if share_name is None:
                    logger.debug(f"[-] Skipping unparseable share {i+1}")
                    continue
                
                share_type = get_share_type(share_obj)
                share_comment = get_share_comment(share_obj)
                
                logger.info(f"[*] Processing share: {share_name}")
                
                # Test access
                access_level = test_share_access(target, share_name, username, password, ntlm_hash, port, logger)
                
                share_info = {
                    'name': share_name,
                    'type': share_type,
                    'comment': share_comment or 'SMB share',
                    'access': access_level,
                    'session_type': session_type,
                    'credentials': {
                        'username': username or '',
                        'password': password or '',
                        'ntlm_hash': ntlm_hash
                    }
                }
                
                session_shares.append(share_info)
                logger.info(f"[+] Found share: {share_name} ({access_level})")
            
            # Add unique shares to master list
            for share in session_shares:
                existing = next((s for s in all_shares if s['name'] == share['name']), None)
                if not existing:
                    all_shares.append(share)
                elif share['access'] in ['READ/WRITE', 'READ'] and existing['access'] in ['NO ACCESS', 'UNKNOWN']:
                    existing.update(share)
            
            smb_conn.close()
            
            if session_shares:
                logger.info(f"[+] {session_type} found {len(session_shares)} shares")
            
        except Exception as e:
            logger.debug(f"[-] {session_type} failed: {e}")
            continue
    
    logger.info(f"[+] Clean enumeration complete: {len(all_shares)} valid shares found")
    return all_shares