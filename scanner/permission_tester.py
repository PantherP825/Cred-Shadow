"""
SMB Permission Testing Module
Provides detailed testing of SMB share permissions and access levels.
"""

import os
import tempfile
import time
from impacket.smbconnection import SMBConnection
from impacket import smbserver
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SHARING_VIOLATION


def test_share_access(target, share_name, username, password, ntlm_hash=None, test_type="read", port=445, timeout=10):
    """
    Test specific access permissions on an SMB share.
    
    Args:
        target (str): Target IP or hostname
        share_name (str): Share name to test
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple (lm_hash, nt_hash)
        test_type (str): Type of test ("read", "write", "admin")
        port (int): SMB port
        timeout (int): Connection timeout
    
    Returns:
        bool: True if access test succeeds
    """
    try:
        # Create SMB connection
        conn = SMBConnection(target, target, None, port, timeout=timeout)
        
        # Authenticate
        if ntlm_hash:
            lm_hash, nt_hash = ntlm_hash
            conn.login(username, password, '', lm_hash, nt_hash)
        else:
            conn.login(username, password, '')
        
        # Test based on type
        if test_type == "read":
            return _test_read_access(conn, share_name)
        elif test_type == "write":
            return _test_write_access(conn, share_name)
        elif test_type == "admin":
            return _test_admin_access(conn, share_name)
        else:
            return False
            
    except Exception:
        return False
    finally:
        try:
            if 'conn' in locals():
                conn.close()
        except:
            pass


def _test_read_access(conn, share_name):
    """Test read access to a share."""
    try:
        # Try to list directory contents
        files = conn.listPath(share_name, '*')
        return len(files) >= 0  # Even empty directories return . and ..
    except Exception:
        return False


def _test_write_access(conn, share_name):
    """Test write access to a share."""
    try:
        # Try to create a temporary file
        test_filename = f"cred_shadow_test_{int(time.time())}.tmp"
        test_content = b"CRED-SHADOW permission test file"
        
        # Create file
        fid = conn.createFile(share_name, test_filename)
        if fid:
            # Write test content
            conn.writeFile(share_name, test_filename, test_content)
            conn.closeFile(share_name, fid)
            
            # Clean up - delete the test file
            try:
                conn.deleteFile(share_name, test_filename)
            except:
                pass  # File deletion might fail but write succeeded
            
            return True
        return False
        
    except Exception:
        return False


def _test_admin_access(conn, share_name):
    """Test administrative access to a share."""
    try:
        # Try administrative operations
        
        # Test 1: Try to create a subdirectory
        test_dir = f"cred_shadow_admin_test_{int(time.time())}"
        try:
            conn.createDirectory(share_name, test_dir)
            # Clean up
            try:
                conn.deleteDirectory(share_name, test_dir)
            except:
                pass
            return True
        except:
            pass
        
        # Test 2: Try to access administrative files/directories
        admin_paths = [
            'System Volume Information',
            '$Recycle.Bin',
            'Windows',
            'Program Files'
        ]
        
        for admin_path in admin_paths:
            try:
                files = conn.listPath(share_name, admin_path + '\\*')
                if files:
                    return True
            except:
                continue
        
        return False
        
    except Exception:
        return False


def get_detailed_share_info(target, share_name, username, password, ntlm_hash=None, port=445, timeout=10):
    """
    Get detailed information about a share including permissions.
    
    Args:
        target (str): Target IP or hostname
        share_name (str): Share name to analyze
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        timeout (int): Connection timeout
    
    Returns:
        dict: Detailed share information
    """
    share_info = {
        'name': share_name,
        'path': f'//{target}/{share_name}',
        'accessible': False,
        'readable': False,
        'writable': False,
        'administrative': False,
        'file_count': 0,
        'directory_count': 0,
        'total_size': 0,
        'last_modified': None,
        'share_type': 'unknown',
        'permissions': {}
    }
    
    try:
        # Create SMB connection
        conn = SMBConnection(target, target, None, port, timeout=timeout)
        
        # Authenticate
        if ntlm_hash:
            lm_hash, nt_hash = ntlm_hash
            conn.login(username, password, '', lm_hash, nt_hash)
        else:
            conn.login(username, password, '')
        
        # Basic accessibility test
        try:
            files = conn.listPath(share_name, '*')
            share_info['accessible'] = True
            share_info['readable'] = True
            
            # Count files and directories
            for file_info in files:
                if file_info.filename in ['.', '..']:
                    continue
                
                if file_info.is_directory():
                    share_info['directory_count'] += 1
                else:
                    share_info['file_count'] += 1
                    share_info['total_size'] += file_info.get_filesize()
                
                # Track most recent modification
                file_time = file_info.get_mtime_epoch()
                if not share_info['last_modified'] or file_time > share_info['last_modified']:
                    share_info['last_modified'] = file_time
            
        except Exception:
            pass
        
        # Test write permissions
        share_info['writable'] = test_share_access(target, share_name, username, password, ntlm_hash, "write", port, timeout)
        
        # Test administrative permissions
        share_info['administrative'] = test_share_access(target, share_name, username, password, ntlm_hash, "admin", port, timeout)
        
        # Determine share type
        share_info['share_type'] = _determine_share_type(share_name, share_info)
        
        # Get detailed permissions
        share_info['permissions'] = _get_permission_details(share_info)
        
    except Exception:
        pass
    finally:
        try:
            if 'conn' in locals():
                conn.close()
        except:
            pass
    
    return share_info


def _determine_share_type(share_name, share_info):
    """Determine the type of share based on characteristics."""
    share_lower = share_name.lower()
    
    # Administrative shares
    if share_name.endswith('$'):
        return 'administrative'
    
    # System shares
    if share_lower in ['ipc$', 'admin$', 'c$', 'd$']:
        return 'system'
    
    # Common share types based on name patterns
    if any(pattern in share_lower for pattern in ['backup', 'archive']):
        return 'backup'
    
    if any(pattern in share_lower for pattern in ['temp', 'tmp', 'temporary']):
        return 'temporary'
    
    if any(pattern in share_lower for pattern in ['public', 'shared', 'common']):
        return 'public'
    
    if any(pattern in share_lower for pattern in ['home', 'user', 'profile']):
        return 'user'
    
    if any(pattern in share_lower for pattern in ['software', 'apps', 'programs']):
        return 'application'
    
    if any(pattern in share_lower for pattern in ['data', 'files', 'documents']):
        return 'data'
    
    # Based on content characteristics
    if share_info['file_count'] == 0 and share_info['directory_count'] > 0:
        return 'directory_only'
    
    if share_info['file_count'] > 0 and share_info['directory_count'] == 0:
        return 'file_only'
    
    return 'general'


def _get_permission_details(share_info):
    """Get detailed permission information."""
    permissions = {
        'read': share_info['readable'],
        'write': share_info['writable'],
        'administrative': share_info['administrative'],
        'access_level': 'none'
    }
    
    # Determine overall access level
    if share_info['administrative']:
        permissions['access_level'] = 'full_control'
    elif share_info['writable']:
        permissions['access_level'] = 'read_write'
    elif share_info['readable']:
        permissions['access_level'] = 'read_only'
    else:
        permissions['access_level'] = 'no_access'
    
    return permissions


def batch_test_permissions(target, shares, credentials_list, port=445, timeout=10):
    """
    Test permissions for multiple shares with multiple credential sets.
    
    Args:
        target (str): Target IP or hostname
        shares (list): List of share names
        credentials_list (list): List of credential tuples
        port (int): SMB port
        timeout (int): Connection timeout
    
    Returns:
        dict: Permission test results
    """
    results = {
        'target': target,
        'shares': {},
        'summary': {
            'total_shares': len(shares),
            'accessible_shares': 0,
            'writable_shares': 0,
            'administrative_shares': 0
        }
    }
    
    for share_name in shares:
        share_results = {
            'name': share_name,
            'credentials_tested': [],
            'best_access': 'none',
            'accessible_with': [],
            'writable_with': [],
            'administrative_with': []
        }
        
        for credentials in credentials_list:
            username, password, ntlm_hash = credentials
            user_context = username if username else 'anonymous'
            
            # Test this credential set
            share_info = get_detailed_share_info(target, share_name, username, password, ntlm_hash, port, timeout)
            
            cred_result = {
                'user': user_context,
                'accessible': share_info['accessible'],
                'readable': share_info['readable'],
                'writable': share_info['writable'],
                'administrative': share_info['administrative'],
                'access_level': share_info['permissions']['access_level']
            }
            
            share_results['credentials_tested'].append(cred_result)
            
            # Track access capabilities
            if share_info['accessible']:
                share_results['accessible_with'].append(user_context)
            
            if share_info['writable']:
                share_results['writable_with'].append(user_context)
            
            if share_info['administrative']:
                share_results['administrative_with'].append(user_context)
            
            # Update best access level
            access_levels = ['none', 'read_only', 'read_write', 'full_control']
            current_level = share_info['permissions']['access_level']
            if access_levels.index(current_level) > access_levels.index(share_results['best_access']):
                share_results['best_access'] = current_level
        
        results['shares'][share_name] = share_results
        
        # Update summary counts
        if share_results['accessible_with']:
            results['summary']['accessible_shares'] += 1
        
        if share_results['writable_with']:
            results['summary']['writable_shares'] += 1
        
        if share_results['administrative_with']:
            results['summary']['administrative_shares'] += 1
    
    return results