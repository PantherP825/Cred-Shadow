"""
SMB Share Enumeration Module - Fixed for Robust Share Discovery
Handles SMB connection and share enumeration with consistent discovery across all session types.
"""

import socket
import time
import platform
import threading
from impacket.smbconnection import SMBConnection
from utils.logger import get_logger

# Global cache for preventing stale results
_share_cache_lock = threading.Lock()
_share_cache = {}

def clear_share_cache():
    """Clear the share cache to prevent stale results."""
    global _share_cache
    with _share_cache_lock:
        _share_cache.clear()

def get_platform_timeout():
    """Get platform-appropriate timeout values."""
    system = platform.system().lower()
    if system == 'windows':
        return 30  # Windows needs longer timeouts
    elif system == 'darwin':  # macOS
        return 20
    else:  # Linux and others
        return 15

def safe_decode_bytes(data, errors='ignore'):
    """Safely decode bytes to string with multiple encoding fallbacks."""
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


def parse_share_object(share, logger=None):
    """
    Parse share object from impacket listShares() response.
    Direct parsing without fallback to cached/hardcoded share names.
    
    Returns:
        tuple: (share_name, share_type, share_comment)
    """
    try:
        share_name = None
        share_type = 0
        share_comment = ''
        
        if logger:
            logger.debug(f"[*] Parsing share object: {type(share)} - {repr(share)}")
        
        # Method 1: Direct attribute access (most reliable)
        try:
            # Try impacket's direct attributes first
            if hasattr(share, 'get_name'):
                share_name = safe_decode_bytes(share.get_name())
            elif hasattr(share, 'name'):
                share_name = safe_decode_bytes(share.name)
            elif hasattr(share, 'shi1_netname'):
                share_name = safe_decode_bytes(share.shi1_netname)
            elif hasattr(share, '__getitem__'):
                # Dictionary-like access
                try:
                    share_name = safe_decode_bytes(share['shi1_netname'])
                except (KeyError, TypeError):
                    pass
            
            # Get share type
            if hasattr(share, 'get_type'):
                share_type = share.get_type()
            elif hasattr(share, 'type'):
                share_type = share.type
            elif hasattr(share, 'shi1_type'):
                share_type = share.shi1_type
            elif hasattr(share, '__getitem__'):
                try:
                    share_type = share['shi1_type']
                except (KeyError, TypeError):
                    pass
            
            # Get comment
            if hasattr(share, 'get_comment'):
                share_comment = safe_decode_bytes(share.get_comment())
            elif hasattr(share, 'comment'):
                share_comment = safe_decode_bytes(share.comment)
            elif hasattr(share, 'shi1_remark'):
                share_comment = safe_decode_bytes(share.shi1_remark)
            elif hasattr(share, '__getitem__'):
                try:
                    share_comment = safe_decode_bytes(share['shi1_remark'])
                except (KeyError, TypeError):
                    pass
                    
        except Exception as attr_error:
            if logger:
                logger.debug(f"[-] Attribute access failed: {attr_error}")
        
        # Method 2: String representation parsing (only for actual share names)
        if not share_name:
            try:
                share_str = str(share)
                if logger:
                    logger.debug(f"[*] Share string representation: {repr(share_str)}")
                
                # Look for patterns like: "ShareName (DISK)" or similar
                import re
                
                # Pattern 1: ShareName followed by type in parentheses
                match = re.search(r'^([a-zA-Z0-9$_\-\.]{1,15})\s*\(', share_str)
                if match:
                    share_name = match.group(1)
                    if logger:
                        logger.debug(f"[+] Extracted share name from pattern: '{share_name}'")
                else:
                    # Pattern 2: Look for valid share name at start of string
                    match = re.search(r'^([a-zA-Z0-9$_\-\.]{1,15})', share_str)
                    if match:
                        candidate = match.group(1)
                        # Verify it's not just numbers or generic pattern
                        if not re.match(r'^(Share_?\d+|share\d+|\d+)$', candidate, re.IGNORECASE):
                            share_name = candidate
                            if logger:
                                logger.debug(f"[+] Extracted share name from start: '{share_name}'")
                        
            except Exception as str_error:
                if logger:
                    logger.debug(f"[-] String parsing failed: {str_error}")
        
        # Validate and return results
        if share_name and share_name.strip() and len(share_name.strip()) > 0:
            share_name = share_name.strip()
            
            # Final validation - reject generic fallback names
            if re.match(r'^(Share_?\d+|share\d+|unknown|null|none|\d+)$', share_name, re.IGNORECASE):
                if logger:
                    logger.debug(f"[-] Rejecting generic fallback name: '{share_name}'")
                return None, None, None
            
            if logger:
                logger.info(f"[+] Successfully parsed share: '{share_name}' (type: {share_type})")
            return share_name, share_type, share_comment
        else:
            if logger:
                logger.debug(f"[-] Could not extract valid share name from object")
            return None, None, None
            
    except Exception as e:
        if logger:
            logger.debug(f"[-] Exception in parse_share_object: {repr(e)}")
        return None, None, None


def enum_shares(target, credentials_list, port=445, logger=None):
    """
    Enumerate SMB shares on target using provided credentials with robust discovery.
    Always returns discovered shares even if access is denied.
    
    Args:
        target (str): Target IP or hostname
        credentials_list (list): List of credential tuples (username, password, ntlm_hash)
        port (int): SMB port (default: 445)
        logger: Logger instance
    
    Returns:
        list: List of discovered shares with metadata (always returns shares found)
    """
    if logger is None:
        logger = get_logger()
    
    # Clear any cached results to prevent stale data from previous targets
    clear_share_cache()
    cache_key = f"{target}:{port}"
    
    logger.info(f"[*] Enumerating shares on {target}:{port}")
    logger.info(f"[*] Platform: {platform.system()} {platform.release()}")
    
    # Enhanced connectivity check with cross-platform compatibility
    platform_timeout = get_platform_timeout()
    connection_attempts = 3 if platform.system().lower() == 'windows' else 2
    
    for attempt in range(connection_attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            timeout_val = min(8, platform_timeout // 2) + attempt
            sock.settimeout(timeout_val)
            
            # Platform-specific socket configuration
            system = platform.system().lower()
            if system == 'windows':
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    # Windows-specific optimizations
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except (AttributeError, OSError):
                    pass
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except (AttributeError, OSError):
                    pass  # Not available on all systems
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                break  # Successful connection
            elif attempt == connection_attempts - 1:
                # Final attempt failed
                error_msg = f"[-] Cannot connect to {target}:{port} - Connection refused"
                if system == 'windows':
                    error_msg += "\n    Try: Check Windows Firewall, enable SMB client, run as administrator"
                    error_msg += "\n         Verify 'Client for Microsoft Networks' is enabled"
                elif system == 'linux':
                    error_msg += "\n    Try: sudo apt install samba-client cifs-utils"
                    error_msg += "\n         Check firewall: sudo ufw status"
                elif system == 'darwin':
                    error_msg += "\n    Try: Check Security & Privacy > Firewall settings"
                    error_msg += "\n         Test in Finder: Go > Connect to Server"
                
                logger.error(error_msg)
                return []
            else:
                # Retry with progressive delay
                time.sleep(0.5 * (attempt + 1))
                
        except Exception as conn_test_error:
            if attempt == connection_attempts - 1:
                logger.error(f"[-] Network connectivity test failed: {str(conn_test_error)}")
                logger.error(f"[-] Platform: {platform.system()} {platform.release()}")
                logger.error(f"[-] Troubleshooting: Verify network access and SMB client configuration")
                return []
            else:
                time.sleep(0.3 * (attempt + 1))
    
    all_discovered_shares = []
    session_types_tried = []
    
    # Check if we have authenticated credentials (non-empty username)
    authenticated_creds = [cred for cred in credentials_list if cred[0] and cred[0] not in ['', 'guest', 'anonymous']]
    
    if authenticated_creds:
        # If authenticated credentials are provided, ONLY use those
        logger.info(f"[*] Using authenticated credentials only (not trying anonymous sessions)")
        working_credentials = authenticated_creds
    else:
        # No authenticated credentials, use all provided (including anonymous/guest)
        logger.info(f"[*] No authenticated credentials provided, trying all session types")
        working_credentials = credentials_list
    
    for username, password, ntlm_hash in working_credentials:
        # Determine session type for logging
        if not username and not password:
            session_type = "Anonymous/Null Session"
        elif username == 'guest':
            session_type = "Guest Session"
        elif ntlm_hash:
            session_type = f"NTLM Hash Session ({username})"
        else:
            session_type = f"Authenticated Session ({username})"
            
        logger.info(f"[*] Trying {session_type}")
        session_types_tried.append(session_type)
        
        smb_conn = None
        try:
            # Create SMB connection with platform-appropriate timeout
            smb_conn = SMBConnection(target, target, None, port, timeout=platform_timeout)
            
            # Authenticate based on credential type
            auth_successful = False
            if ntlm_hash:
                # NTLM hash authentication
                if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                    lm_hash, nt_hash = ntlm_hash.split(':', 1)
                else:
                    lm_hash, nt_hash = ntlm_hash
                smb_conn.login(username, password, '', lm_hash, nt_hash)
                auth_successful = True
                logger.info(f"[+] NTLM authentication successful: {username}")
            elif not username and not password:
                # Try anonymous/null session variations
                try:
                    smb_conn.login('', '')
                    auth_successful = True
                    logger.info("[+] Anonymous session successful")
                except:
                    try:
                        smb_conn.close()
                        smb_conn = SMBConnection(target, target, None, port, timeout=platform_timeout)
                        smb_conn.login('guest', '')
                        auth_successful = True
                        logger.info("[+] Guest session successful")
                    except:
                        pass
            elif username == 'guest':
                # Guest authentication
                smb_conn.login('guest', password or '')
                auth_successful = True
                logger.info("[+] Guest authentication successful")
            else:
                # Standard username/password authentication - try different variations
                try:
                    smb_conn.login(username, password or '')
                    auth_successful = True
                    logger.info(f"[+] Standard authentication successful: {username}")
                except Exception as auth_err:
                    # Try with empty domain
                    try:
                        smb_conn.login(username, password or '', '')
                        auth_successful = True
                        logger.info(f"[+] Standard authentication successful (empty domain): {username}")
                    except:
                        raise auth_err
            
            if not auth_successful:
                logger.debug(f"[-] Authentication failed for {session_type}")
                continue
            
            # Try to enumerate shares
            try:
                shares_resp = smb_conn.listShares()
                logger.info(f"[+] Successfully enumerated shares with {session_type}")
                logger.info(f"[+] Retrieved {len(shares_resp)} shares from server")
                
                session_shares = []
                logger.debug(f"[*] Processing {len(shares_resp)} shares from {session_type}")
                
                # Use the fixed share parsing function
                for i, share in enumerate(shares_resp):
                    try:
                        # Use the improved parse_share_object function
                        share_name, share_type, share_comment = parse_share_object(share, logger)
                        
                        # If parsing completely failed, skip this share instead of using fallback names
                        if share_name is None:
                            logger.warning(f"[-] Could not parse share {i+1} - skipping to prevent incorrect data")
                            continue
                        
                        share_name = share_name.strip()
                        logger.info(f"[*] Processing share: {share_name} (type: {share_type})")
                        
                        # Test access to each share individually
                        access_level = test_individual_share_access(target, share_name, username, password, ntlm_hash, port, logger)
                        
                        # Create comprehensive share info
                        share_info = {
                            'name': share_name,
                            'type': share_type,
                            'comment': share_comment or '',
                            'access': access_level,
                            'session_type': session_type,
                            'credentials': {
                                'username': username or '',
                                'password': password or '',
                                'ntlm_hash': ntlm_hash
                            }
                        }
                        
                        session_shares.append(share_info)
                        logger.info(f"[+] Found share: {share_name} ({access_level}) - {share_comment}")
                    
                    except Exception as share_parse_error:
                        logger.error(f"[-] Error parsing share {i+1}: {str(share_parse_error)}")
                        logger.debug(f"[-] Share object type: {type(share)}")
                        logger.debug(f"[-] Share object attributes: {dir(share)}")
                        
                        # Emergency fallback - create a share entry we can manually connect to
                        fallback_name = f"Share_{i+1}"
                        logger.warning(f"[-] Using fallback name: {fallback_name}")
                        
                        share_info = {
                            'name': fallback_name,
                            'type': 0,
                            'comment': 'Parsing failed - manual access may work',
                            'access': 'UNKNOWN',
                            'session_type': session_type,
                            'credentials': {
                                'username': username or '',
                                'password': password or '',
                                'ntlm_hash': ntlm_hash
                            }
                        }
                        session_shares.append(share_info)
                        continue
                
                logger.info(f"[*] Session {session_type} parsed {len(session_shares)} valid shares")
                
                # Add unique shares to master list
                for share in session_shares:
                    # Check if share already discovered by another session
                    existing_share = next((s for s in all_discovered_shares if s['name'] == share['name']), None)
                    if existing_share:
                        # Update with better access if found
                        if share['access'] in ['READ/WRITE', 'READ'] and existing_share['access'] in ['NO ACCESS', 'UNKNOWN']:
                            existing_share.update(share)
                            logger.debug(f"[*] Updated access for {share['name']}: {share['access']}")
                    else:
                        all_discovered_shares.append(share)
                
                # If we found shares, we can break or continue to try other sessions for better access
                if session_shares:
                    logger.info(f"[+] Session {session_type} discovered {len(session_shares)} shares")
                
            except Exception as enum_error:
                logger.warning(f"[-] Share enumeration failed for {session_type}: {str(enum_error)}")
                
        except Exception as conn_error:
            error_msg = str(conn_error)
            if "STATUS_LOGON_FAILURE" in error_msg:
                logger.debug(f"[-] Authentication failed for {session_type}")
            elif "Connection refused" in error_msg or "timed out" in error_msg:
                logger.warning(f"[-] Connection failed to {target}:{port}")
                break  # No point trying other credentials if we can't connect
            else:
                logger.debug(f"[-] Connection error for {session_type}: {error_msg}")
        
        finally:
            if smb_conn:
                try:
                    smb_conn.close()
                except:
                    pass
    
    # Summary of results
    if all_discovered_shares:
        accessible_shares = [s for s in all_discovered_shares if s['access'] in ['READ', 'READ/WRITE', 'SPECIAL']]
        logger.info(f"[+] Total shares discovered: {len(all_discovered_shares)}")
        logger.info(f"[+] Accessible shares: {len(accessible_shares)}")
        logger.info(f"[+] Session types tried: {', '.join(session_types_tried)}")
        
        # List all shares found
        for share in all_discovered_shares:
            share_type_name = {0: "DISK", 1: "PRINT", 3: "IPC"}.get(share['type'], "OTHER")
            logger.info(f"    {share['name']} ({share_type_name}) - {share['access']} - {share['comment']}")
    else:
        logger.warning(f"[-] No shares discovered on {target}")
        logger.info(f"[*] Session types attempted: {', '.join(session_types_tried)}")
    
    return all_discovered_shares


def test_individual_share_access(target, share_name, username, password, ntlm_hash, port=445, logger=None):
    """
    Test access to a specific share individually with comprehensive error handling.
    Returns detailed access level information and file count.
    """
    import time
    
    if logger is None:
        logger = get_logger()
    
    smb_conn = None
    try:
        smb_conn = SMBConnection(target, target, None, port, timeout=10)
        
        # Authenticate based on provided credentials
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            # Try anonymous first, then guest
            try:
                smb_conn.login('', '')
                logger.debug(f"[+] Anonymous access successful for {share_name}")
            except:
                smb_conn.close()
                smb_conn = SMBConnection(target, target, None, port, timeout=10)
                smb_conn.login('guest', '')
                logger.debug(f"[+] Guest access successful for {share_name}")
        else:
            smb_conn.login(username or '', password or '')
            logger.debug(f"[+] Authenticated access successful for {share_name}")
        
        # Test read access with multiple path variations
        files_found = 0
        read_success = False
        
        # Try different path formats that work with impacket
        path_variations = ['/', '*', '.', '\\', '\\*']
        
        for path_var in path_variations:
            try:
                logger.debug(f"[*] Testing path '{path_var}' on share {share_name}")
                files = smb_conn.listPath(share_name, path_var)
                files_found = len([f for f in files if f.get_longname() not in ['.', '..']])
                read_success = True
                logger.debug(f"[+] Found {files_found} files/directories in {share_name} using path '{path_var}'")
                break
            except Exception as path_error:
                logger.debug(f"[-] Path '{path_var}' failed on {share_name}: {str(path_error)}")
                continue
        
        if read_success:
            # Test write access if read was successful
            try:
                test_dir = f"cred_shadow_test_{int(time.time())}"
                smb_conn.createDirectory(share_name, test_dir)
                smb_conn.deleteDirectory(share_name, test_dir)
                logger.debug(f"[+] Write access confirmed for {share_name}")
                return f"READ/WRITE ({files_found} items)"
            except Exception as write_error:
                logger.debug(f"[-] Write test failed for {share_name}: {str(write_error)}")
                return f"READ ({files_found} items)"
        else:
            # If standard listing failed, try alternative methods
            try:
                # For IPC$ and similar special shares
                if share_name.upper() in ['IPC$', 'PRINT$']:
                    # These are special shares - test differently
                    logger.debug(f"[*] Testing special share {share_name}")
                    return "SPECIAL (IPC/Print)"
                else:
                    # Try a different approach for regular shares
                    logger.debug(f"[-] Standard listing failed for {share_name}, trying alternative access")
                    return "LIMITED"
            except:
                pass
                
        # If we get here, access failed
        return "NO ACCESS"
                
    except Exception as test_error:
        error_str = str(test_error).upper()
        logger.debug(f"[-] Access test failed for {share_name}: {str(test_error)}")
        
        # Provide more specific error categorization
        if "ACCESS_DENIED" in error_str or "PERMISSION" in error_str:
            return "ACCESS DENIED"
        elif "INVALID_PARAMETER" in error_str:
            return "INVALID SHARE"
        elif "NETWORK_NAME_NOT_FOUND" in error_str:
            return "SHARE NOT FOUND"
        elif "LOGON_FAILURE" in error_str:
            return "AUTH FAILED"
        else:
            return "UNKNOWN ERROR"
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def try_all_session_types(target, port=445, logger=None):
    """
    Try all possible session types and return comprehensive credential list.
    Used for automation mode to test all authentication methods.
    """
    if logger is None:
        logger = get_logger()
    
    # Comprehensive session type list
    session_credentials = [
        ('', '', None),           # Anonymous session
        ('guest', '', None),      # Guest session
        ('guest', 'guest', None), # Guest with password
        ('anonymous', '', None),  # Anonymous variant
    ]
    
    logger.info("[*] Preparing to try all session types:")
    logger.info("    - Anonymous Session")
    logger.info("    - Null Session") 
    logger.info("    - Guest Session")
    
    return session_credentials


def test_share_access(target, share_name, username, password, ntlm_hash, port=445, logger=None):
    """Test access to a specific SMB share (legacy compatibility)."""
    access_level = test_individual_share_access(target, share_name, username, password, ntlm_hash, port, logger)
    return access_level in ['READ', 'READ/WRITE', 'SPECIAL']


def list_directory(target, share, path, username, password, ntlm_hash, port=445, logger=None):
    """List contents of a directory on an SMB share."""
    if logger is None:
        logger = get_logger()
    
    smb_conn = None
    try:
        smb_conn = SMBConnection(target, target, None, port, timeout=30)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            try:
                smb_conn.login('', '')
            except:
                smb_conn.close()
                smb_conn = SMBConnection(target, target, None, port, timeout=30)
                smb_conn.login('guest', '')
        else:
            smb_conn.login(username or '', password or '')
        
        # Normalize path for SMB listing
        if not path or path in ['', '*', '.']:
            list_path = '*'
        elif path.startswith('/'):
            list_path = path[1:] + '/*'
        else:
            list_path = path + '/*' if not path.endswith('*') else path
        
        logger.debug(f"[*] Listing path: {share}:{list_path}")
        
        # List directory contents with multiple path attempts
        files = None
        path_attempts = [list_path, '*', '.', '/', '\\*']
        
        for attempt_path in path_attempts:
            try:
                logger.debug(f"[*] Trying path: {attempt_path}")
                files = smb_conn.listPath(share, attempt_path)
                logger.debug(f"[+] Successfully listed {len(files)} items with path: {attempt_path}")
                break
            except Exception as path_err:
                logger.debug(f"[-] Path {attempt_path} failed: {str(path_err)}")
                continue
        
        if files is None:
            logger.debug(f"[-] All path attempts failed for {share}")
            return []
        
        file_list = []
        for file_info in files:
            try:
                filename = file_info.get_longname()
                if filename not in ['.', '..']:
                    # Handle file attributes safely
                    file_data = {
                        'name': filename,
                        'size': getattr(file_info, 'file_size', 0) or file_info.get_filesize() or 0,
                        'is_directory': file_info.is_directory(),
                        'created_time': None,
                        'modified_time': None,
                        'accessed_time': None
                    }
                    
                    # Safely get timestamps
                    try:
                        file_data['created_time'] = file_info.get_ctime_epoch()
                    except:
                        pass
                    
                    try:
                        file_data['modified_time'] = file_info.get_mtime_epoch()
                    except:
                        pass
                        
                    try:
                        file_data['accessed_time'] = file_info.get_atime_epoch()
                    except:
                        pass
                    
                    file_list.append(file_data)
                    logger.debug(f"[+] Added file: {filename} ({'DIR' if file_data['is_directory'] else 'FILE'})")
                    
            except Exception as file_err:
                logger.debug(f"[-] Error processing file info: {str(file_err)}")
                continue
        
        logger.debug(f"[+] Successfully processed {len(file_list)} files from {share}")
        return file_list
        
    except Exception as e:
        logger.error(f"[-] Error listing directory {share}:{path} - {str(e)}")
        return []
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def download_file(target, share, remote_path, local_path, username, password, ntlm_hash, port=445, logger=None):
    """Download a file from an SMB share."""
    if logger is None:
        logger = get_logger()
    
    import os
    from pathlib import Path
    
    smb_conn = None
    try:
        # Ensure local directory exists
        local_file = Path(local_path)
        local_file.parent.mkdir(parents=True, exist_ok=True)
        
        smb_conn = SMBConnection(target, target, None, port, timeout=30)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            try:
                smb_conn.login('', '')
            except:
                smb_conn.close()
                smb_conn = SMBConnection(target, target, None, port, timeout=30)
                smb_conn.login('guest', '')
        else:
            smb_conn.login(username or '', password or '')
        
        # Normalize remote path - remove leading slashes
        if remote_path.startswith('/'):
            remote_path = remote_path[1:]
        
        logger.debug(f"[*] Downloading {share}:{remote_path} to {local_path}")
        
        # Download file with proper error handling
        try:
            with open(local_path, 'wb') as fp:
                smb_conn.retrieveFile(share, remote_path, fp)
            
            # Verify file was downloaded
            if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                logger.info(f"[+] Downloaded: {remote_path} -> {local_path} ({os.path.getsize(local_path)} bytes)")
                return True
            else:
                logger.error(f"[-] Download failed - file is empty or doesn't exist: {local_path}")
                return False
                
        except Exception as download_err:
            logger.error(f"[-] Download error: {str(download_err)}")
            # Try alternative path formats
            alt_paths = [remote_path.replace('/', '\\'), remote_path.replace('\\', '/')]
            for alt_path in alt_paths:
                try:
                    logger.debug(f"[*] Trying alternative path: {alt_path}")
                    with open(local_path, 'wb') as fp:
                        smb_conn.retrieveFile(share, alt_path, fp)
                    
                    if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                        logger.info(f"[+] Downloaded with alternative path: {alt_path} -> {local_path}")
                        return True
                except:
                    continue
            
            return False
        
    except Exception as e:
        logger.error(f"[-] Error downloading {remote_path}: {str(e)}")
        return False
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def get_file_info(target, share, file_path, username, password, ntlm_hash, port=445, logger=None):
    """Get information about a file on an SMB share."""
    if logger is None:
        logger = get_logger()
    
    smb_conn = None
    try:
        smb_conn = SMBConnection(target, target, None, port, timeout=10)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            try:
                smb_conn.login('', '')
            except:
                smb_conn.close()
                smb_conn = SMBConnection(target, target, None, port, timeout=10)
                smb_conn.login('guest', '')
        else:
            smb_conn.login(username or '', password or '')
        
        # Get basic file info
        file_info = {
            'name': file_path.split('/')[-1],
            'size': 0,
            'is_directory': False,
            'created': 0,
            'modified': 0,
            'accessed': 0
        }
        
        return file_info
        
    except Exception as e:
        logger.debug(f"[-] Error getting file info for {file_path}: {str(e)}")
        return None
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass