#!/usr/bin/env python3
"""
Cross-Platform Compatibility Test for CRED-SHADOW
Tests and validates fixes for silent failures on different machines.
"""

import sys
import platform
import socket
import time
import subprocess
import os
from pathlib import Path

def test_basic_functionality():
    """Test basic Python and library functionality."""
    print("=== Basic Functionality Test ===")
    
    # Test Python version
    print(f"Python version: {sys.version}")
    
    # Test platform detection
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.architecture()}")
    
    # Test essential imports
    try:
        from impacket.smbconnection import SMBConnection
        print("✓ impacket imported successfully")
    except ImportError as e:
        print(f"✗ impacket import failed: {e}")
        return False
    
    try:
        from colorama import Fore, Style
        print("✓ colorama imported successfully")
    except ImportError as e:
        print(f"✗ colorama import failed: {e}")
        return False
    
    try:
        from rich.console import Console
        print("✓ rich imported successfully")
    except ImportError as e:
        print(f"✗ rich import failed: {e}")
        return False
    
    return True

def test_network_connectivity():
    """Test network connectivity with different approaches."""
    print("\n=== Network Connectivity Test ===")
    
    # Test basic socket functionality
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        # Test connection to a known good host
        result = sock.connect_ex(('8.8.8.8', 53))  # Google DNS
        sock.close()
        
        if result == 0:
            print("✓ Basic network connectivity works")
        else:
            print("✗ Basic network connectivity failed")
            return False
    except Exception as e:
        print(f"✗ Socket test failed: {e}")
        return False
    
    return True

def test_smb_target(target, port=445):
    """Test SMB connectivity to a specific target."""
    print(f"\n=== SMB Target Test: {target}:{port} ===")
    
    # Test raw socket connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Platform-specific timeout
        if platform.system().lower() == 'windows':
            timeout = 15
        else:
            timeout = 10
        
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            print(f"✓ Raw socket connection to {target}:{port} successful")
        else:
            print(f"✗ Raw socket connection to {target}:{port} failed (code: {result})")
            return False
    except Exception as e:
        print(f"✗ Socket connection test failed: {e}")
        return False
    
    # Test impacket SMB connection
    try:
        from impacket.smbconnection import SMBConnection
        
        print(f"Testing impacket SMB connection...")
        smb_conn = SMBConnection(target, target, None, port, timeout=timeout)
        
        # Try anonymous connection
        try:
            smb_conn.login('', '')
            print("✓ Anonymous SMB connection successful")
            
            # Try to list shares
            shares = smb_conn.listShares()
            print(f"✓ Share enumeration successful: {len(shares)} shares found")
            
            smb_conn.close()
            return True
            
        except Exception as login_error:
            print(f"Anonymous login failed: {login_error}")
            try:
                smb_conn.close()
            except:
                pass
            return False
            
    except Exception as e:
        print(f"✗ impacket SMB connection failed: {e}")
        return False

def test_cred_shadow_basic():
    """Test basic CRED-SHADOW functionality."""
    print("\n=== CRED-SHADOW Basic Test ===")
    
    try:
        # Test help command
        result = subprocess.run([sys.executable, 'main.py', '--help'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✓ CRED-SHADOW help command works")
            if "SMB Share Secret Scanner" in result.stdout:
                print("✓ Banner displays correctly")
            else:
                print("✗ Banner not found in output")
                return False
        else:
            print(f"✗ CRED-SHADOW help command failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ CRED-SHADOW help command timed out")
        return False
    except Exception as e:
        print(f"✗ CRED-SHADOW test failed: {e}")
        return False
    
    return True

def test_platform_specific():
    """Test platform-specific configurations."""
    print(f"\n=== Platform-Specific Test: {platform.system()} ===")
    
    system = platform.system().lower()
    
    if system == 'windows':
        print("Testing Windows-specific features...")
        
        # Test Windows SMB client
        try:
            result = subprocess.run(['powershell', 'Get-Service', 'LanmanWorkstation'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and 'Running' in result.stdout:
                print("✓ Windows SMB client service is running")
            else:
                print("⚠ Windows SMB client service may not be running")
        except Exception:
            print("⚠ Could not check Windows SMB client service")
    
    elif system == 'linux':
        print("Testing Linux-specific features...")
        
        # Test for samba-client
        try:
            result = subprocess.run(['which', 'smbclient'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✓ smbclient is installed")
            else:
                print("⚠ smbclient is not installed (install with: sudo apt install samba-client)")
        except Exception:
            print("⚠ Could not check for smbclient")
    
    elif system == 'darwin':
        print("Testing macOS-specific features...")
        
        # Test SMB support
        try:
            result = subprocess.run(['ls', '/System/Library/Filesystems/smbfs.fs'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✓ macOS SMB filesystem support is available")
            else:
                print("⚠ macOS SMB filesystem support may not be available")
        except Exception:
            print("⚠ Could not check macOS SMB support")
    
    return True

def run_diagnostic():
    """Run comprehensive diagnostic test."""
    print("CRED-SHADOW Cross-Platform Compatibility Diagnostic")
    print("=" * 60)
    
    all_passed = True
    
    # Run all tests
    if not test_basic_functionality():
        all_passed = False
    
    if not test_network_connectivity():
        all_passed = False
    
    if not test_cred_shadow_basic():
        all_passed = False
    
    if not test_platform_specific():
        all_passed = False
    
    # Test specific target if provided
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if not test_smb_target(target):
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED - CRED-SHADOW should work on this machine")
    else:
        print("✗ SOME TESTS FAILED - See above for specific issues")
        print("\nTroubleshooting suggestions:")
        
        system = platform.system().lower()
        if system == 'windows':
            print("• Run as Administrator")
            print("• Check Windows Firewall settings")
            print("• Enable 'Client for Microsoft Networks'")
        elif system == 'linux':
            print("• Install SMB client: sudo apt install samba-client cifs-utils")
            print("• Check firewall: sudo ufw status")
        elif system == 'darwin':
            print("• Check Security & Privacy settings")
            print("• Test SMB in Finder: Go > Connect to Server")
    
    return all_passed

if __name__ == "__main__":
    success = run_diagnostic()
    sys.exit(0 if success else 1)