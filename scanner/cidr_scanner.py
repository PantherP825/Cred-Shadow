"""
CIDR Scanner Module
Handles subnet enumeration and multi-target scanning.
"""

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.clean_share_enum import enumerate_shares_clean
from scanner.brute_force import test_smb_login
from utils.logger import get_logger


class CIDRScanner:
    """CIDR subnet scanner for SMB hosts."""
    
    def __init__(self, cidr, port=445, timeout=5, max_workers=20):
        """
        Initialize CIDR scanner.
        
        Args:
            cidr (str): CIDR notation (e.g., "192.168.1.0/24")
            port (int): SMB port to scan
            timeout (int): Connection timeout
            max_workers (int): Maximum concurrent threads
        """
        self.cidr = cidr
        self.port = port
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = get_logger()
        self.alive_hosts = []
        self.vulnerable_hosts = []
        
    def parse_cidr(self):
        """
        Parse CIDR notation into list of IP addresses.
        
        Returns:
            list: List of IP addresses
        """
        try:
            network = ipaddress.ip_network(self.cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            self.logger.error(f"[-] Invalid CIDR notation: {self.cidr} - {e}")
            return []
    
    def check_smb_port(self, target):
        """
        Check if SMB port is open on target.
        
        Args:
            target (str): Target IP address
        
        Returns:
            bool: True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, self.port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_host_port(self, target):
        """
        Scan single host for open SMB port.
        
        Args:
            target (str): Target IP address
        
        Returns:
            str: Target IP if port is open, None otherwise
        """
        if self.check_smb_port(target):
            self.logger.info(f"[+] SMB port open on {target}:{self.port}")
            return target
        return None
    
    def discover_smb_hosts(self):
        """
        Discover hosts with open SMB ports in the subnet.
        
        Returns:
            list: List of hosts with open SMB ports
        """
        self.logger.info(f"[*] Scanning CIDR range: {self.cidr}")
        targets = self.parse_cidr()
        
        if not targets:
            return []
        
        self.logger.info(f"[*] Scanning {len(targets)} hosts for SMB services")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {executor.submit(self.scan_host_port, target): target 
                              for target in targets}
            
            for future in as_completed(future_to_target):
                result = future.result()
                if result:
                    self.alive_hosts.append(result)
        
        self.logger.info(f"[+] Found {len(self.alive_hosts)} hosts with SMB services")
        return self.alive_hosts
    
    def test_null_sessions(self):
        """
        Test null sessions on discovered hosts.
        
        Returns:
            list: Hosts allowing null sessions
        """
        null_session_hosts = []
        
        self.logger.info("[*] Testing null sessions on discovered hosts")
        
        for host in self.alive_hosts:
            try:
                if test_smb_login(host, '', '', port=self.port, timeout=self.timeout):
                    self.logger.info(f"[+] Null session allowed on {host}")
                    null_session_hosts.append(host)
                else:
                    # Try guest account
                    if test_smb_login(host, 'guest', '', port=self.port, timeout=self.timeout):
                        self.logger.info(f"[+] Guest access allowed on {host}")
                        null_session_hosts.append(host)
            except Exception as e:
                self.logger.debug(f"[-] Error testing null session on {host}: {e}")
        
        return null_session_hosts
    
    def test_credentials_on_subnet(self, username, password, ntlm_hash=None):
        """
        Test credentials across all discovered hosts.
        
        Args:
            username (str): Username to test
            password (str): Password to test
            ntlm_hash (tuple): NTLM hash tuple
        
        Returns:
            list: Hosts where credentials are valid
        """
        valid_hosts = []
        
        self.logger.info(f"[*] Testing credentials {username} on {len(self.alive_hosts)} hosts")
        
        def test_host_creds(host):
            try:
                if test_smb_login(host, username, password, port=self.port, timeout=self.timeout):
                    self.logger.info(f"[+] Valid credentials on {host}: {username}")
                    return host
            except Exception as e:
                self.logger.debug(f"[-] Error testing credentials on {host}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(test_host_creds, host): host 
                            for host in self.alive_hosts}
            
            for future in as_completed(future_to_host):
                result = future.result()
                if result:
                    valid_hosts.append(result)
        
        return valid_hosts
    
    def enumerate_shares_subnet(self, username, password, ntlm_hash=None):
        """
        Enumerate shares on all accessible hosts.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            ntlm_hash (tuple): NTLM hash tuple
        
        Returns:
            dict: Host to shares mapping
        """
        host_shares = {}
        
        self.logger.info("[*] Enumerating shares on accessible hosts")
        
        def enum_host_shares(host):
            try:
                shares = enumerate_shares_clean(host, [(username, password, ntlm_hash)], 
                                   self.port, self.logger)
                if shares:
                    return (host, shares)
            except Exception as e:
                self.logger.debug(f"[-] Error enumerating shares on {host}: {e}")
            return (host, [])
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(enum_host_shares, host): host 
                            for host in self.alive_hosts}
            
            for future in as_completed(future_to_host):
                host, shares = future.result()
                if shares:
                    host_shares[host] = shares
                    self.logger.info(f"[+] {host}: {len(shares)} accessible shares")
        
        return host_shares


def scan_cidr_range(cidr, username=None, password=None, ntlm_hash=None, 
                   port=445, timeout=5, max_workers=20, logger=None):
    """
    Comprehensive CIDR range scanning.
    
    Args:
        cidr (str): CIDR notation
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        timeout (int): Connection timeout
        max_workers (int): Maximum concurrent threads
        logger: Logger instance
    
    Returns:
        dict: Scanning results
    """
    if logger is None:
        logger = get_logger()
    
    scanner = CIDRScanner(cidr, port, timeout, max_workers)
    
    # Discover SMB hosts
    smb_hosts = scanner.discover_smb_hosts()
    
    if not smb_hosts:
        logger.warning("[-] No SMB hosts discovered in range")
        return {
            'smb_hosts': [],
            'null_session_hosts': [],
            'credential_valid_hosts': [],
            'host_shares': {}
        }
    
    # Test null sessions
    null_hosts = scanner.test_null_sessions()
    
    # Test provided credentials if available
    cred_hosts = []
    if username:
        cred_hosts = scanner.test_credentials_on_subnet(username, password, ntlm_hash)
    
    # Enumerate shares on accessible hosts
    accessible_hosts = list(set(null_hosts + cred_hosts))
    host_shares = {}
    
    if accessible_hosts:
        # Use null session for null hosts, credentials for others
        for host in accessible_hosts:
            if host in null_hosts:
                shares = enumerate_shares_clean(host, [('', '', None)], port, logger)
            else:
                shares = enumerate_shares_clean(host, [(username, password, ntlm_hash)], 
                                   port, logger)
            if shares:
                host_shares[host] = shares
    
    results = {
        'smb_hosts': smb_hosts,
        'null_session_hosts': null_hosts,
        'credential_valid_hosts': cred_hosts,
        'host_shares': host_shares
    }
    
    return results