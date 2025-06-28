"""
Cross-Platform Compatibility Fix for CRED-SHADOW
Resolves silent failures on different operating systems and machine configurations.
"""

import os
import sys
import platform
import socket
import time
import threading
from pathlib import Path


class CrossPlatformFix:
    """Handles cross-platform compatibility and silent failure prevention."""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == 'windows'
        self.is_linux = self.system == 'linux'
        self.is_macos = self.system == 'darwin'
        
        # Platform-specific configurations
        self._configure_platform_settings()
        
        # Session state management
        self._session_data = {}
        self._lock = threading.Lock()
    
    def _configure_platform_settings(self):
        """Configure platform-specific settings."""
        if self.is_windows:
            self.timeout = 45  # Windows needs longer timeouts
            self.connect_timeout = 10
            self.retry_count = 3
            self.encoding_preference = ['cp1252', 'utf-8', 'latin-1']
        elif self.is_macos:
            self.timeout = 25
            self.connect_timeout = 8
            self.retry_count = 2
            self.encoding_preference = ['utf-8', 'macroman', 'latin-1']
        else:  # Linux and others
            self.timeout = 20
            self.connect_timeout = 5
            self.retry_count = 2
            self.encoding_preference = ['utf-8', 'latin-1', 'cp1252']
    
    def clear_session_state(self, target=None):
        """Clear any cached session state to prevent stale data."""
        with self._lock:
            if target:
                # Clear specific target data
                keys_to_remove = [k for k in self._session_data.keys() if target in k]
                for key in keys_to_remove:
                    del self._session_data[key]
            else:
                # Clear all session data
                self._session_data.clear()
    
    def enhanced_connectivity_check(self, target, port=445):
        """Enhanced connectivity check with platform-specific optimizations."""
        try:
            # Multiple connection attempts with different approaches
            for attempt in range(self.retry_count):
                if self._try_connection(target, port, attempt):
                    return True
                
                if attempt < self.retry_count - 1:
                    time.sleep(0.5 * (attempt + 1))  # Progressive backoff
            
            return False
            
        except Exception as e:
            print(f"Enhanced connectivity check failed: {e}")
            return False
    
    def _try_connection(self, target, port, attempt):
        """Try connection with platform-specific socket configuration."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Platform-specific socket options
            if self.is_windows:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Windows-specific timeout handling
                sock.settimeout(self.connect_timeout + attempt * 2)
            elif self.is_linux:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass  # Not all Linux versions support this
                sock.settimeout(self.connect_timeout)
            elif self.is_macos:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # macOS-specific configuration
                sock.settimeout(self.connect_timeout + 1)
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def safe_decode_any(self, data, errors='ignore'):
        """Safely decode any data type with platform-appropriate encoding."""
        if isinstance(data, str):
            return data.rstrip('\x00')
        
        if not isinstance(data, bytes):
            return str(data).rstrip('\x00')
        
        # Try platform-preferred encodings first
        for encoding in self.encoding_preference:
            try:
                decoded = data.decode(encoding, errors=errors)
                return decoded.rstrip('\x00')
            except (UnicodeDecodeError, LookupError):
                continue
        
        # Fallback to replacement
        return data.decode('utf-8', errors='replace').rstrip('\x00')
    
    def get_platform_error_context(self, error):
        """Get platform-specific error context and troubleshooting advice."""
        error_str = str(error).lower()
        context = {
            'platform': self.system,
            'error': error_str,
            'advice': []
        }
        
        if 'connection refused' in error_str or 'connection failed' in error_str:
            if self.is_windows:
                context['advice'] = [
                    "Check Windows Defender Firewall settings",
                    "Verify SMB client is enabled (Windows Features)",
                    "Try running as Administrator",
                    "Check if target is reachable: ping {target}"
                ]
            elif self.is_linux:
                context['advice'] = [
                    "Install SMB client: sudo apt install samba-client cifs-utils",
                    "Check firewall: sudo ufw status",
                    "Verify network connectivity: ping {target}",
                    "Check SMB ports: nmap -p 445 {target}"
                ]
            elif self.is_macos:
                context['advice'] = [
                    "Check System Preferences > Security & Privacy > Firewall",
                    "Verify network permissions in Privacy settings",
                    "Test SMB in Finder: Go > Connect to Server",
                    "Check connectivity: ping {target}"
                ]
        
        elif 'timeout' in error_str:
            if self.is_windows:
                context['advice'] = [
                    "Increase timeout values",
                    "Check network latency with ping",
                    "Verify Windows SMB client configuration"
                ]
            else:
                context['advice'] = [
                    "Check network latency and stability",
                    "Verify firewall rules allow SMB traffic",
                    "Test with manual SMB connection"
                ]
        
        elif 'permission denied' in error_str or 'access denied' in error_str:
            context['advice'] = [
                "Verify credentials are correct",
                "Check share permissions on target",
                "Try different authentication methods"
            ]
        
        elif 'protocol' in error_str or 'dialect' in error_str:
            context['advice'] = [
                "Target may use different SMB version",
                "Try compatibility mode",
                "Check SMB protocol support on both ends"
            ]
        
        return context
    
    def configure_impacket_for_platform(self, connection):
        """Configure impacket connection with platform-specific optimizations."""
        try:
            # Set platform-appropriate timeout
            connection.set_timeout(self.timeout)
            
            # Platform-specific connection tuning
            if hasattr(connection, '_SMBConnection__socket'):
                sock = connection._SMBConnection__socket
                if sock:
                    sock.settimeout(self.timeout)
                    
                    # Platform-specific socket tuning
                    if self.is_windows:
                        # Windows-specific optimizations
                        try:
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        except Exception:
                            pass
                    elif self.is_linux:
                        # Linux-specific optimizations
                        try:
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        except Exception:
                            pass
        
        except Exception:
            pass  # Best effort configuration
    
    def get_diagnostic_info(self):
        """Get comprehensive diagnostic information for troubleshooting."""
        info = {
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'architecture': platform.architecture()
            },
            'python': {
                'version': sys.version,
                'executable': sys.executable,
                'path': sys.path[:3]  # First few entries
            },
            'network': {
                'hostname': socket.gethostname(),
                'fqdn': socket.getfqdn()
            },
            'configuration': {
                'timeout': self.timeout,
                'connect_timeout': self.connect_timeout,
                'retry_count': self.retry_count,
                'encoding_preference': self.encoding_preference
            }
        }
        
        # Platform-specific diagnostic info
        try:
            if self.is_linux:
                import subprocess
                # Check for SMB-related packages
                try:
                    result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=5)
                    if 'samba-client' in result.stdout:
                        info['samba_client_installed'] = True
                except Exception:
                    pass
            
            elif self.is_windows:
                # Check Windows SMB features
                try:
                    import subprocess
                    result = subprocess.run(['powershell', 'Get-WindowsOptionalFeature', '-Online', '-FeatureName', 'SMB1Protocol'], 
                                          capture_output=True, text=True, timeout=5)
                    info['smb_features_check'] = 'completed'
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return info


# Global instance
_cross_platform_fix = CrossPlatformFix()


def get_cross_platform_fix():
    """Get the global cross-platform fix instance."""
    return _cross_platform_fix


def clear_session_cache(target=None):
    """Clear session cache to prevent stale results."""
    _cross_platform_fix.clear_session_state(target)


def enhanced_connectivity_check(target, port=445):
    """Enhanced connectivity check."""
    return _cross_platform_fix.enhanced_connectivity_check(target, port)


def safe_decode(data, errors='ignore'):
    """Safe cross-platform decoding."""
    return _cross_platform_fix.safe_decode_any(data, errors)


def get_platform_error_context(error):
    """Get platform-specific error context."""
    return _cross_platform_fix.get_platform_error_context(error)


def configure_connection(connection):
    """Configure connection for current platform."""
    return _cross_platform_fix.configure_impacket_for_platform(connection)


def get_diagnostic_info():
    """Get diagnostic information."""
    return _cross_platform_fix.get_diagnostic_info()