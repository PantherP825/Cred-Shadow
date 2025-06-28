"""
Cross-Platform Compatibility Module for CRED-SHADOW
Handles platform-specific networking, encoding, and SMB protocol differences.
"""

import os
import sys
import socket
import platform
import subprocess
from pathlib import Path


class PlatformCompat:
    """Handles cross-platform compatibility issues."""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.is_windows = self.platform == 'windows'
        self.is_linux = self.platform == 'linux'
        self.is_macos = self.platform == 'darwin'
        self.is_unix = self.is_linux or self.is_macos
        
        # Network configuration
        self.default_timeout = 30 if self.is_windows else 15
        self.connection_retries = 3 if self.is_windows else 2
        
        # Encoding preferences
        self.default_encoding = 'utf-8'
        self.fallback_encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
    
    def get_network_timeout(self):
        """Get platform-appropriate network timeout."""
        return self.default_timeout
    
    def get_connection_retries(self):
        """Get platform-appropriate connection retry count."""
        return self.connection_retries
    
    def safe_decode(self, data, errors='ignore'):
        """Safely decode bytes to string with platform-appropriate fallbacks."""
        if isinstance(data, str):
            return data
        
        if not isinstance(data, bytes):
            return str(data)
        
        # Try encodings in order of preference
        for encoding in self.fallback_encodings:
            try:
                return data.decode(encoding, errors=errors).rstrip('\x00')
            except (UnicodeDecodeError, AttributeError):
                continue
        
        # Last resort: force decode with replacement
        return data.decode('utf-8', errors='replace').rstrip('\x00')
    
    def normalize_smb_path(self, path):
        """Normalize SMB path for cross-platform compatibility."""
        if not path:
            return ''
        
        # Convert backslashes to forward slashes
        normalized = path.replace('\\', '/')
        
        # Remove leading/trailing slashes
        normalized = normalized.strip('/')
        
        return normalized
    
    def check_network_connectivity(self, target, port=445, timeout=None):
        """Check network connectivity with platform-specific optimizations."""
        if timeout is None:
            timeout = self.get_network_timeout()
        
        try:
            # Use platform-specific socket options
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if self.is_windows:
                # Windows-specific socket options
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:
                # Unix-specific socket options
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except AttributeError:
                    pass  # SO_REUSEPORT not available on all systems
            
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def get_smb_dialect_preference(self):
        """Get platform-appropriate SMB dialect preferences."""
        if self.is_windows:
            # Windows prefers newer dialects
            return ['SMB2_DIALECT_311', 'SMB2_DIALECT_302', 'SMB2_DIALECT_210', 'SMB_DIALECT']
        else:
            # Unix systems often work better with older dialects first
            return ['SMB_DIALECT', 'SMB2_DIALECT_210', 'SMB2_DIALECT_302', 'SMB2_DIALECT_311']
    
    def configure_impacket_connection(self, conn):
        """Configure impacket connection with platform-specific settings."""
        try:
            # Set platform-appropriate timeouts
            if hasattr(conn, '_SMBConnection__socket'):
                sock = conn._SMBConnection__socket
                if sock:
                    sock.settimeout(self.get_network_timeout())
            
            # Platform-specific SMB configuration
            if self.is_windows:
                # Windows-specific optimizations
                conn.set_timeout(self.get_network_timeout())
            elif self.is_linux:
                # Linux-specific optimizations
                conn.set_timeout(self.get_network_timeout())
            elif self.is_macos:
                # macOS-specific optimizations
                conn.set_timeout(self.get_network_timeout())
                
        except Exception:
            pass  # Best effort configuration
    
    def handle_smb_error(self, error):
        """Handle SMB errors with platform-specific context."""
        error_str = str(error).lower()
        
        if 'connection refused' in error_str:
            if self.is_windows:
                return "Connection refused. Check Windows Firewall and SMB service status."
            else:
                return "Connection refused. Check firewall rules and SMB client configuration."
        
        elif 'timeout' in error_str:
            if self.is_windows:
                return "Connection timeout. Try increasing timeout or check network connectivity."
            else:
                return "Connection timeout. Check network latency and firewall rules."
        
        elif 'permission denied' in error_str or 'access denied' in error_str:
            return "Access denied. Check credentials and share permissions."
        
        elif 'protocol' in error_str:
            if self.is_windows:
                return "Protocol error. Target may not support SMB or requires different authentication."
            else:
                return "Protocol error. Try installing samba-client or check SMB dialect compatibility."
        
        return f"SMB error: {error}"
    
    def get_debug_info(self):
        """Get platform debug information for troubleshooting."""
        info = {
            'platform': self.platform,
            'system': platform.system(),
            'release': platform.release(),
            'python_version': sys.version,
            'architecture': platform.architecture(),
            'network_timeout': self.get_network_timeout(),
            'encoding': self.default_encoding
        }
        
        # Add platform-specific debug info
        if self.is_linux:
            try:
                # Check for SMB client tools
                info['samba_client'] = subprocess.run(['which', 'smbclient'], 
                                                    capture_output=True, text=True).returncode == 0
                info['cifs_utils'] = subprocess.run(['which', 'mount.cifs'], 
                                                  capture_output=True, text=True).returncode == 0
            except Exception:
                pass
        
        return info


# Global compatibility instance
_platform_compat = PlatformCompat()


def get_platform_compat():
    """Get the global platform compatibility instance."""
    return _platform_compat


def safe_decode(data, errors='ignore'):
    """Safely decode bytes to string with platform fallbacks."""
    return _platform_compat.safe_decode(data, errors)


def check_connectivity(target, port=445, timeout=None):
    """Check network connectivity with platform optimizations."""
    return _platform_compat.check_network_connectivity(target, port, timeout)


def configure_smb_connection(conn):
    """Configure SMB connection for current platform."""
    return _platform_compat.configure_impacket_connection(conn)


def handle_smb_error(error):
    """Handle SMB error with platform context."""
    return _platform_compat.handle_smb_error(error)


def get_debug_info():
    """Get platform debug information."""
    return _platform_compat.get_debug_info()