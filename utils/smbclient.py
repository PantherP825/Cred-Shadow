"""
SMBClient Integration Module
Provides smbclient command-line integration for share discovery and enumeration.
"""

import subprocess
import re
import os
from typing import List, Dict, Optional, Tuple
import json
from colorama import Fore, Style


def check_smbclient_available():
    """
    Check if smbclient is available on the system.
    
    Returns:
        bool: True if smbclient is available
    """
    try:
        result = subprocess.run(['smbclient', '--version'], 
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def discover_smb_shares_smbclient(target, username=None, password=None, timeout=30):
    """
    Discover SMB shares using smbclient command.
    
    Args:
        target (str): Target IP or hostname
        username (str): Username for authentication
        password (str): Password for authentication
        timeout (int): Command timeout
    
    Returns:
        list: List of discovered shares
    """
    shares = []
    
    try:
        # Build smbclient command
        cmd = ['smbclient', '-L', target, '-N']  # -N for no password prompt
        
        if username:
            cmd.extend(['-U', username])
            if password:
                cmd.extend(['%' + password])
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            # Parse output for shares
            lines = result.stdout.split('\n')
            in_shares_section = False
            
            for line in lines:
                line = line.strip()
                
                if 'Sharename' in line and 'Type' in line:
                    in_shares_section = True
                    continue
                
                if in_shares_section and line:
                    if line.startswith('-') or line.startswith('='):
                        continue
                    
                    # Parse share information
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_type = parts[1] if len(parts) > 1 else "Unknown"
                        comment = ' '.join(parts[2:]) if len(parts) > 2 else ""
                        
                        # Filter out administrative shares if desired
                        if not share_name.endswith('$') or share_name.lower() in ['c$', 'd$', 'admin$']:
                            shares.append({
                                'name': share_name,
                                'type': share_type,
                                'comment': comment,
                                'accessible': None  # To be determined later
                            })
        
        return shares
        
    except subprocess.TimeoutExpired:
        print(f"[-] SMBClient timeout for target {target}")
        return []
    except Exception as e:
        print(f"[-] SMBClient error: {str(e)}")
        return []


def test_share_access_smbclient(target, share_name, username=None, password=None, timeout=10):
    """
    Test access to a specific share using smbclient.
    
    Args:
        target (str): Target IP or hostname
        share_name (str): Share name to test
        username (str): Username for authentication
        password (str): Password for authentication
        timeout (int): Command timeout
    
    Returns:
        dict: Access test results
    """
    try:
        # Build smbclient command for share access test
        share_path = f"//{target}/{share_name}"
        cmd = ['smbclient', share_path, '-c', 'ls', '-N']
        
        if username:
            cmd.extend(['-U', username])
            if password:
                cmd.append('%' + password)
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        accessible = result.returncode == 0
        error_msg = result.stderr.strip() if result.stderr else None
        
        return {
            'accessible': accessible,
            'error': error_msg,
            'output': result.stdout.strip() if result.stdout else None
        }
        
    except subprocess.TimeoutExpired:
        return {
            'accessible': False,
            'error': f"Timeout testing access to {share_name}",
            'output': None
        }
    except Exception as e:
        return {
            'accessible': False,
            'error': f"Error testing {share_name}: {str(e)}",
            'output': None
        }


def enumerate_share_contents_smbclient(target, share_name, username=None, password=None, 
                                     max_depth=3, timeout=30):
    """
    Enumerate share contents using smbclient.
    
    Args:
        target (str): Target IP or hostname
        share_name (str): Share name to enumerate
        username (str): Username for authentication
        password (str): Password for authentication
        max_depth (int): Maximum directory depth
        timeout (int): Command timeout
    
    Returns:
        list: List of files and directories
    """
    files = []
    
    try:
        share_path = f"//{target}/{share_name}"
        
        # Build recursive directory listing command
        cmd = ['smbclient', share_path, '-c', 'recurse on; ls', '-N']
        
        if username:
            cmd.extend(['-U', username])
            if password:
                cmd.append('%' + password)
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            # Parse directory listing
            lines = result.stdout.split('\n')
            current_dir = ""
            
            for line in lines:
                line = line.strip()
                
                if not line:
                    continue
                
                # Check for directory change
                if line.startswith('\\') and line.endswith('\\'):
                    current_dir = line[1:-1]  # Remove leading and trailing backslashes
                    continue
                
                # Parse file/directory entries
                if re.match(r'\s*[DA-Z]+\s+\d+', line):
                    parts = line.split()
                    if len(parts) >= 3:
                        attributes = parts[0]
                        size = parts[1] if parts[1].isdigit() else 0
                        name = ' '.join(parts[2:])
                        
                        # Skip . and .. entries
                        if name in ['.', '..']:
                            continue
                        
                        file_path = os.path.join(current_dir, name).replace('\\', '/')
                        
                        files.append({
                            'name': name,
                            'path': file_path,
                            'size': int(size) if str(size).isdigit() else 0,
                            'attributes': attributes,
                            'is_directory': 'D' in attributes,
                            'share': share_name
                        })
        
        return files[:1000]  # Limit results to prevent memory issues
        
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout enumerating share {share_name}")
        return []
    except Exception as e:
        print(f"[-] Error enumerating share {share_name}: {str(e)}")
        return []


def interactive_credential_prompt():
    """
    Interactive prompt for credential input.
    
    Returns:
        tuple: (username, password, use_hash, hash_value)
    """
    print(f"\n{Fore.CYAN}┌─ INTERACTIVE CREDENTIAL INPUT ─────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│ Enter credentials for SMB authentication               │{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Authentication options:{Style.RESET_ALL}")
    print("1. Username and password")
    print("2. NTLM hash")
    print("3. Anonymous/null session")
    print("4. Try all methods")
    
    choice = input(f"\n{Fore.GREEN}Select authentication method (1-4): {Style.RESET_ALL}").strip()
    
    if choice == "1":
        username = input(f"{Fore.GREEN}Username: {Style.RESET_ALL}").strip()
        password = input(f"{Fore.GREEN}Password: {Style.RESET_ALL}").strip()
        return username, password, False, None
    
    elif choice == "2":
        username = input(f"{Fore.GREEN}Username: {Style.RESET_ALL}").strip()
        hash_value = input(f"{Fore.GREEN}NTLM Hash (LM:NT): {Style.RESET_ALL}").strip()
        return username, "", True, hash_value
    
    elif choice == "3":
        return "", "", False, None
    
    elif choice == "4":
        return "try_all", "", False, None
    
    else:
        print(f"{Fore.RED}Invalid choice. Using anonymous access.{Style.RESET_ALL}")
        return "", "", False, None


def interactive_share_selection(shares):
    """
    Interactive share selection interface.
    
    Args:
        shares (list): List of discovered shares
    
    Returns:
        list: Selected shares for scanning
    """
    if not shares:
        print(f"{Fore.RED}No shares discovered.{Style.RESET_ALL}")
        return []
    
    print(f"\n{Fore.CYAN}┌─ DISCOVERED SMB SHARES ─────────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│ Select shares to scan                                   │{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    # Display shares
    for i, share in enumerate(shares, 1):
        status = "✓" if share.get('accessible') else "✗" if share.get('accessible') is False else "?"
        print(f"{i:2d}. {status} {share['name']:<15} {share['type']:<10} {share.get('comment', '')}")
    
    print(f"\n{Fore.YELLOW}Selection options:{Style.RESET_ALL}")
    print("• Enter share numbers separated by commas (e.g., 1,3,5)")
    print("• Enter 'all' to select all accessible shares")
    print("• Enter 'accessible' to select only accessible shares")
    print("• Press Enter to select all shares")
    
    selection = input(f"\n{Fore.GREEN}Select shares: {Style.RESET_ALL}").strip().lower()
    
    if not selection or selection == "all":
        return shares
    
    elif selection == "accessible":
        return [share for share in shares if share.get('accessible')]
    
    else:
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected_shares = []
            for i in indices:
                if 0 <= i < len(shares):
                    selected_shares.append(shares[i])
            return selected_shares
        except ValueError:
            print(f"{Fore.RED}Invalid selection. Using all shares.{Style.RESET_ALL}")
            return shares


def comprehensive_share_report(target, shares_data, scan_results=None):
    """
    Generate comprehensive report of discovered shares and scan results.
    
    Args:
        target (str): Target IP or hostname
        shares_data (list): Share discovery data
        scan_results (dict): Optional scan results
    
    Returns:
        dict: Comprehensive report
    """
    report = {
        'target': target,
        'timestamp': __import__('datetime').datetime.now().isoformat(),
        'tool': 'CRED-SHADOW',
        'discovery_method': 'smbclient',
        'shares': {
            'total_discovered': len(shares_data),
            'accessible': len([s for s in shares_data if s.get('accessible')]),
            'inaccessible': len([s for s in shares_data if s.get('accessible') is False]),
            'unknown': len([s for s in shares_data if s.get('accessible') is None]),
            'details': shares_data
        },
        'scan_results': scan_results or {}
    }
    
    return report


def smart_credential_discovery(target, logger=None):
    """
    Smart credential discovery that tries passwordless methods first.
    
    Args:
        target (str): Target IP or hostname
        logger: Logger instance
    
    Returns:
        list: Valid credential tuples
    """
    valid_creds = []
    
    # Try passwordless methods first
    passwordless_methods = [
        ("anonymous", "", "Anonymous login"),
        ("", "", "Null session"),
        ("guest", "", "Guest account (no password)"),
        ("guest", "guest", "Guest account (guest password)")
    ]
    
    for username, password, description in passwordless_methods:
        if logger:
            logger.info(f"[*] Trying {description}...")
        
        # Test credentials using smbclient
        shares = discover_smb_shares_smbclient(target, username, password)
        if shares:
            valid_creds.append((username, password, None))
            if logger:
                logger.info(f"[+] {description} successful - {len(shares)} shares discovered")
            break
        else:
            if logger:
                logger.info(f"[-] {description} failed")
    
    return valid_creds


def automated_share_discovery(target, credentials=None, logger=None):
    """
    Automated SMB share discovery and enumeration.
    
    Args:
        target (str): Target IP or hostname
        credentials (list): List of credential tuples
        logger: Logger instance
    
    Returns:
        dict: Discovery results
    """
    results = {
        'target': target,
        'shares_discovered': [],
        'accessible_shares': [],
        'scan_summary': {}
    }
    
    if not credentials:
        credentials = smart_credential_discovery(target, logger)
    
    for username, password, ntlm_hash in credentials:
        if logger:
            logger.info(f"[*] Discovering shares with credentials: {username or 'anonymous'}")
        
        shares = discover_smb_shares_smbclient(target, username, password)
        
        if shares:
            results['shares_discovered'].extend(shares)
            
            # Test access to each share
            for share in shares:
                access_test = test_share_access_smbclient(target, share['name'], username, password)
                share['accessible'] = access_test['accessible']
                share['access_error'] = access_test['error']
                
                if access_test['accessible']:
                    results['accessible_shares'].append(share)
                    if logger:
                        logger.info(f"[+] Share accessible: {share['name']}")
            
            break  # Use first working credentials
    
    results['scan_summary'] = {
        'total_shares': len(results['shares_discovered']),
        'accessible_shares': len(results['accessible_shares']),
        'credentials_used': len(credentials)
    }
    
    return results