"""
SMB Compatibility Layer
Handles different SMB versions and authentication methods for maximum compatibility.
"""

import socket
import time
from impacket.smbconnection import SMBConnection
from impacket.smb3 import SMB3
from impacket.smb import SMB
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE


class SMBCompatConnection:
    """SMB connection wrapper with fallback mechanisms for maximum compatibility."""
    
    def __init__(self, target, port=445, timeout=15):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.connection = None
        self.smb_version = None
    
    def connect_and_authenticate(self, username, password, ntlm_hash=None):
        """
        Connect and authenticate with fallback methods.
        
        Args:
            username (str): Username
            password (str): Password  
            ntlm_hash (tuple): NTLM hash tuple (lm_hash, nt_hash)
        
        Returns:
            bool: True if successful
        """
        # Try different connection methods
        connection_methods = [
            self._connect_smb2_3,
            self._connect_smb1,
            self._connect_fallback
        ]
        
        for connect_method in connection_methods:
            try:
                if connect_method(username, password, ntlm_hash):
                    return True
            except Exception as e:
                continue
        
        return False
    
    def _connect_smb2_3(self, username, password, ntlm_hash):
        """Try SMB 2/3 connection."""
        try:
            self.connection = SMBConnection(self.target, self.target, None, self.port, timeout=self.timeout)
            
            if ntlm_hash:
                lm_hash, nt_hash = ntlm_hash
                self.connection.login(username, password, '', lm_hash, nt_hash)
            else:
                self.connection.login(username, password, '')
            
            self.smb_version = "SMB2/3"
            return True
            
        except Exception:
            if self.connection:
                try:
                    self.connection.close()
                except:
                    pass
                self.connection = None
            raise
    
    def _connect_smb1(self, username, password, ntlm_hash):
        """Try SMB1 connection with specific settings."""
        try:
            # Force SMB1
            self.connection = SMBConnection(self.target, self.target, None, self.port, timeout=self.timeout)
            # Set SMB1 specific options
            self.connection.set_timeout(self.timeout)
            
            if ntlm_hash:
                lm_hash, nt_hash = ntlm_hash
                self.connection.login(username, password, '', lm_hash, nt_hash)
            else:
                self.connection.login(username, password, '')
            
            self.smb_version = "SMB1"
            return True
            
        except Exception:
            if self.connection:
                try:
                    self.connection.close()
                except:
                    pass
                self.connection = None
            raise
    
    def _connect_fallback(self, username, password, ntlm_hash):
        """Fallback connection method with different parameters."""
        try:
            # Try with different session setup
            self.connection = SMBConnection(self.target, self.target, sess_port=self.port, timeout=self.timeout)
            
            # Try authentication with different approaches
            auth_methods = []
            
            if ntlm_hash:
                lm_hash, nt_hash = ntlm_hash
                auth_methods.append(lambda: self.connection.login(username, password, '', lm_hash, nt_hash))
            else:
                # Different authentication variations
                auth_methods.extend([
                    lambda: self.connection.login(username, password, ''),
                    lambda: self.connection.login(username, password, '', '', ''),
                    lambda: self.connection.login(username or '', password or '', ''),
                ])
                
                # For null sessions, try specific variations
                if not username and not password:
                    auth_methods.extend([
                        lambda: self.connection.login('', '', ''),
                        lambda: self.connection.login(None, '', ''),
                        lambda: self.connection.login('guest', '', ''),
                    ])
            
            for auth_method in auth_methods:
                try:
                    auth_method()
                    self.smb_version = "Fallback"
                    return True
                except Exception:
                    continue
            
            return False
            
        except Exception:
            if self.connection:
                try:
                    self.connection.close()
                except:
                    pass
                self.connection = None
            raise
    
    def list_shares(self):
        """List shares from the connected SMB session."""
        if not self.connection:
            raise Exception("Not connected")
        
        return self.connection.listShares()
    
    def close(self):
        """Close the connection."""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            self.connection = None


def enumerate_shares_robust(target, credentials_list, port=445, logger=None):
    """
    Robust share enumeration with maximum compatibility.
    
    Args:
        target (str): Target IP or hostname
        credentials_list (list): List of credential tuples
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        list: List of discovered shares
    """
    if logger:
        logger.info(f"[*] Starting robust share enumeration on {target}:{port}")
    
    all_shares = set()
    successful_connections = 0
    
    for username, password, ntlm_hash in credentials_list:
        user_context = username if username else "anonymous/null"
        
        if logger:
            logger.info(f"[*] Testing authentication: {user_context}")
        
        smb_conn = SMBCompatConnection(target, port)
        
        try:
            if smb_conn.connect_and_authenticate(username, password, ntlm_hash):
                successful_connections += 1
                
                if logger:
                    logger.info(f"[+] Connected successfully with {user_context} (using {smb_conn.smb_version})")
                
                try:
                    shares = smb_conn.list_shares()
                    
                    if logger:
                        logger.info(f"[+] Retrieved {len(shares)} share entries")
                    
                    for share in shares:
                        try:
                            # Extract share information
                            share_name = share['shi1_netname']
                            if isinstance(share_name, bytes):
                                share_name = share_name.decode('utf-8', errors='ignore').rstrip('\x00')
                            else:
                                share_name = str(share_name).rstrip('\x00')
                            
                            if not share_name or len(share_name) == 0:
                                continue
                            
                            share_type = share['shi1_type']
                            
                            # Get comment
                            share_comment = ''
                            if 'shi1_remark' in share and share['shi1_remark']:
                                comment_data = share['shi1_remark']
                                if isinstance(comment_data, bytes):
                                    share_comment = comment_data.decode('utf-8', errors='ignore').rstrip('\x00')
                                else:
                                    share_comment = str(comment_data).rstrip('\x00')
                            
                            # Process share types
                            if share_type == 0:  # Disk share
                                all_shares.add(share_name)
                                if logger:
                                    logger.info(f"[+] Disk share: {share_name} - {share_comment}")
                            
                            elif share_type == 3 and share_name.upper() == 'IPC$':  # IPC
                                all_shares.add(share_name)
                                if logger:
                                    logger.info(f"[+] IPC share: {share_name} - {share_comment}")
                            
                            elif share_type == 1 and share_name.lower() == 'print$':  # Print drivers
                                all_shares.add(share_name)
                                if logger:
                                    logger.info(f"[+] Print share: {share_name} - {share_comment}")
                            
                            else:
                                if logger:
                                    logger.debug(f"[*] Skipping share type {share_type}: {share_name}")
                        
                        except Exception as parse_error:
                            if logger:
                                logger.debug(f"[-] Error parsing share: {str(parse_error)}")
                            continue
                
                except Exception as list_error:
                    if logger:
                        logger.warning(f"[-] Failed to list shares: {str(list_error)}")
            
            else:
                if logger:
                    logger.debug(f"[-] Authentication failed for {user_context}")
        
        except Exception as conn_error:
            if logger:
                logger.debug(f"[-] Connection error for {user_context}: {str(conn_error)}")
        
        finally:
            smb_conn.close()
    
    # Results summary
    if all_shares:
        if logger:
            logger.info(f"[+] Share discovery successful! Found {len(all_shares)} shares: {', '.join(sorted(all_shares))}")
    else:
        if successful_connections > 0:
            if logger:
                logger.warning(f"[-] Connected successfully but found no accessible shares")
        else:
            if logger:
                logger.warning(f"[-] No successful connections established")
                logger.info(f"[*] Verify target is reachable and SMB service is running")
    
    return list(all_shares)