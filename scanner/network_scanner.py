"""
Network Scanner Module
Handles CIDR scanning and subnet enumeration for SMB services.
"""

import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
from scanner.clean_share_enum import enumerate_shares_clean
import time


def is_port_open(host, port, timeout=3):
    """
    Check if a port is open on a host.
    
    Args:
        host (str): Target host IP
        port (int): Port to check
        timeout (int): Connection timeout
    
    Returns:
        bool: True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_smb_host(host, port=445, timeout=5):
    """
    Scan a single host for SMB service.
    
    Args:
        host (str): Target host IP
        port (int): SMB port
        timeout (int): Connection timeout
    
    Returns:
        dict: Host scan results
    """
    logger = get_logger()
    
    result = {
        'host': host,
        'smb_open': False,
        'smb_version': None,
        'hostname': None,
        'error': None
    }
    
    try:
        # Check if SMB port is open
        if not is_port_open(host, port, timeout):
            result['error'] = 'Port closed'
            return result
        
        result['smb_open'] = True
        
        # Try to get hostname via reverse DNS
        try:
            hostname = socket.gethostbyaddr(host)[0]
            result['hostname'] = hostname
        except Exception:
            pass
        
        # Try to detect SMB version (basic detection)
        try:
            from impacket.smbconnection import SMBConnection
            smb_conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            
            # Try to get server info
            server_name = smb_conn.getServerName()
            server_domain = smb_conn.getServerDomain()
            
            result['server_name'] = server_name
            result['server_domain'] = server_domain
            
            smb_conn.close()
            
        except Exception as e:
            result['error'] = str(e)
        
        logger.debug(f"[+] SMB service detected on {host}:{port}")
        
    except Exception as e:
        result['error'] = str(e)
        logger.debug(f"[-] Error scanning {host}: {e}")
    
    return result


def parse_cidr_targets(target_string):
    """
    Parse CIDR notation and expand to individual hosts.
    
    Args:
        target_string (str): Target in CIDR notation or single IP
    
    Returns:
        list: List of individual IP addresses
    """
    logger = get_logger()
    hosts = []
    
    try:
        # Handle comma-separated targets
        targets = [t.strip() for t in target_string.split(',')]
        
        for target in targets:
            try:
                # Try to parse as network
                network = ipaddress.ip_network(target, strict=False)
                
                # Limit to reasonable subnet sizes to prevent abuse
                if network.num_addresses > 65536:  # /16 or larger
                    logger.warning(f"[!] Large subnet detected ({network}). Limiting to first 1000 hosts.")
                    hosts.extend([str(ip) for ip in list(network.hosts())[:1000]])
                else:
                    hosts.extend([str(ip) for ip in network.hosts()])
                    
            except ValueError:
                # Not a valid network, try as single IP
                try:
                    ip = ipaddress.ip_address(target)
                    hosts.append(str(ip))
                except ValueError:
                    # Try as hostname
                    try:
                        resolved_ip = socket.gethostbyname(target)
                        hosts.append(resolved_ip)
                    except Exception:
                        logger.error(f"[-] Invalid target: {target}")
                        continue
        
        logger.info(f"[+] Parsed {len(hosts)} hosts from target specification")
        return hosts
        
    except Exception as e:
        logger.error(f"[-] Error parsing targets: {e}")
        return []


def scan_cidr_range(target_range, port=445, max_workers=20, timeout=5, logger=None):
    """
    Scan a CIDR range for SMB services.
    
    Args:
        target_range (str): CIDR notation or comma-separated IPs
        port (int): SMB port to scan
        max_workers (int): Maximum number of concurrent threads
        timeout (int): Connection timeout per host
        logger: Logger instance
    
    Returns:
        list: List of hosts with SMB services
    """
    if logger is None:
        logger = get_logger()
    
    logger.info(f"[+] Starting CIDR scan of {target_range}")
    
    # Parse targets
    hosts = parse_cidr_targets(target_range)
    if not hosts:
        logger.error("[-] No valid hosts to scan")
        return []
    
    logger.info(f"[+] Scanning {len(hosts)} hosts for SMB services...")
    
    smb_hosts = []
    completed = 0
    
    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scan jobs
        future_to_host = {
            executor.submit(scan_smb_host, host, port, timeout): host 
            for host in hosts
        }
        
        # Process results as they complete
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            completed += 1
            
            try:
                result = future.result()
                
                # Print progress every 10 hosts or at completion
                if completed % 10 == 0 or completed == len(hosts):
                    logger.info(f"[*] Progress: {completed}/{len(hosts)} hosts scanned")
                
                # Add hosts with SMB services
                if result['smb_open']:
                    smb_hosts.append(result)
                    logger.info(f"[+] SMB service found: {host}")
                    if result.get('hostname'):
                        logger.info(f"    Hostname: {result['hostname']}")
                    if result.get('server_name'):
                        logger.info(f"    Server Name: {result['server_name']}")
                    if result.get('server_domain'):
                        logger.info(f"    Domain: {result['server_domain']}")
                
            except Exception as e:
                logger.error(f"[-] Error processing result for {host}: {e}")
    
    logger.info(f"[+] CIDR scan complete. Found {len(smb_hosts)} hosts with SMB services")
    return smb_hosts


def scan_and_enumerate(target_range, credentials, port=445, max_workers=10, scan_timeout=5, logger=None):
    """
    Scan CIDR range and enumerate shares on discovered hosts.
    
    Args:
        target_range (str): CIDR notation or comma-separated IPs
        credentials (list): List of credential tuples
        port (int): SMB port
        max_workers (int): Maximum concurrent threads
        scan_timeout (int): Scan timeout per host
        logger: Logger instance
    
    Returns:
        dict: Results keyed by host IP
    """
    if logger is None:
        logger = get_logger()
    
    # First, discover SMB hosts
    smb_hosts = scan_cidr_range(target_range, port, max_workers, scan_timeout, logger)
    
    if not smb_hosts:
        logger.warning("[-] No SMB hosts discovered")
        return {}
    
    logger.info(f"[+] Starting share enumeration on {len(smb_hosts)} hosts...")
    
    results = {}
    
    # Enumerate shares on each discovered host
    for host_info in smb_hosts:
        host = host_info['host']
        logger.info(f"[*] Enumerating shares on {host}")
        
        host_results = {
            'host_info': host_info,
            'accessible_shares': [],
            'credentials_used': None
        }
        
        # Try each credential set
        for username, password, ntlm_hash in credentials:
            try:
                shares = enumerate_shares_clean(host, [(username, password, ntlm_hash)], port, logger)
                
                if shares:
                    host_results['accessible_shares'] = shares
                    host_results['credentials_used'] = (username, password, ntlm_hash)
                    logger.info(f"[+] Found {len(shares)} accessible shares on {host}")
                    break
                    
            except Exception as e:
                logger.debug(f"[-] Authentication failed for {username} on {host}: {e}")
                continue
        
        results[host] = host_results
    
    return results


def get_network_info(target_range):
    """
    Get information about the target network range.
    
    Args:
        target_range (str): CIDR notation
    
    Returns:
        dict: Network information
    """
    try:
        network = ipaddress.ip_network(target_range, strict=False)
        
        return {
            'network': str(network),
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'num_addresses': network.num_addresses,
            'prefix_length': network.prefixlen,
            'is_private': network.is_private,
            'is_multicast': network.is_multicast,
            'is_reserved': network.is_reserved
        }
    except Exception as e:
        return {'error': str(e)}


def validate_cidr_input(target_string):
    """
    Validate CIDR input before scanning.
    
    Args:
        target_string (str): Target specification
    
    Returns:
        tuple: (is_valid, error_message, estimated_hosts)
    """
    try:
        hosts = parse_cidr_targets(target_string)
        
        if not hosts:
            return False, "No valid hosts found in target specification", 0
        
        if len(hosts) > 10000:
            return False, f"Target range too large ({len(hosts)} hosts). Maximum allowed: 10000", len(hosts)
        
        return True, None, len(hosts)
        
    except Exception as e:
        return False, str(e), 0