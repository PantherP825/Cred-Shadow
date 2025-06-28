"""
Secret Detection Module
Handles scanning files for credentials and sensitive information.
"""

import re
import os
import time
import concurrent.futures
from utils.regex_patterns import SECRET_PATTERNS, ENTROPY_THRESHOLD
from utils.logger import get_logger
from scanner.share_enum import list_directory, download_file, get_file_info


def calculate_entropy(string):
    """
    Calculate Shannon entropy of a string.

    Args:
        string (str): String to analyze

    Returns:
        float: Entropy value
    """
    import math

    if not string:
        return 0

    # Count character frequencies
    char_counts = {}
    for char in string:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0
    length = len(string)

    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy_string(string, min_length=20, max_length=100):
    """
    Check if a string has high entropy (potential secret).

    Args:
        string (str): String to analyze
        min_length (int): Minimum string length
        max_length (int): Maximum string length

    Returns:
        bool: True if high entropy string
    """
    if len(string) < min_length or len(string) > max_length:
        return False

    entropy = calculate_entropy(string)
    return entropy >= ENTROPY_THRESHOLD


def scan_file_content(content, file_path, patterns=None, logger=None, interactive=False):
    """
    Scan file content for secrets using regex patterns and entropy analysis.

    Args:
        content (bytes): File content
        file_path (str): File path for context
        patterns (dict): Custom regex patterns
        logger: Logger instance
        interactive (bool): Enable interactive mode for user decisions

    Returns:
        list: List of findings
    """
    if logger is None:
        logger = get_logger()

    findings = []

    try:
        # Try to decode content as text
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text_content = content.decode('latin-1')
            except:
                logger.debug(f"[-] Cannot decode file content: {file_path}")
                return findings

        # Use default patterns if none provided
        if patterns is None:
            patterns = SECRET_PATTERNS

        # Scan with regex patterns
        for pattern_name, pattern_data in patterns.items():
            regex = pattern_data['pattern']
            description = pattern_data['description']

            matches = re.finditer(regex, text_content, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                finding = {
                    'type': 'regex_match',
                    'pattern': pattern_name,
                    'description': description,
                    'file_path': file_path,
                    'line_number': text_content[:match.start()].count('\n') + 1,
                    'match': match.group(),
                    'context': get_line_context(text_content, match.start()),
                    'confidence': pattern_data.get('confidence', 'medium'),
                    'timestamp': time.time()
                }
                findings.append(finding)
                logger.info(f"[+] Found {pattern_name} in {file_path}")

                # Interactive mode will be handled at the main level
                # Just collect findings here
                pass

        # Entropy-based detection for potential secrets
        lines = text_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            # Look for assignments and key-value pairs
            for assignment_match in re.finditer(r'(\w+)\s*[=:]\s*["\']?([^"\'\s]+)["\']?', line):
                key, value = assignment_match.groups()

                # Skip common non-secret patterns
                if any(skip in key.lower() for skip in ['comment', 'description', 'name', 'title', 'url', 'path']):
                    continue

                if is_high_entropy_string(value):
                    finding = {
                        'type': 'high_entropy',
                        'pattern': 'entropy_detection',
                        'description': f'High entropy string in assignment: {key}',
                        'file_path': file_path,
                        'line_number': line_num,
                        'match': f"{key}={value}",
                        'context': line.strip(),
                        'confidence': 'low',
                        'entropy': calculate_entropy(value),
                        'timestamp': time.time()
                    }
                    findings.append(finding)
                    logger.info(f"[+] Found high entropy string in {file_path}:{line_num}")

    except Exception as e:
        logger.debug(f"[-] Error scanning file content: {str(e)}")

    return findings


# Interactive handling moved to main.py for better integration


def get_line_context(content, position, context_lines=2):
    """
    Get surrounding lines for context.

    Args:
        content (str): File content
        position (int): Character position
        context_lines (int): Number of context lines

    Returns:
        str: Context lines
    """
    lines = content.split('\n')
    line_num = content[:position].count('\n')

    start_line = max(0, line_num - context_lines)
    end_line = min(len(lines), line_num + context_lines + 1)

    context = []
    for i in range(start_line, end_line):
        prefix = ">>> " if i == line_num else "    "
        context.append(f"{prefix}{lines[i]}")

    return '\n'.join(context)


def should_scan_file(filename, file_size, size_limit_mb):
    """
    Determine if a file should be scanned based on filename and size.

    Args:
        filename (str): File name
        file_size (int): File size in bytes
        size_limit_mb (int): Size limit in MB

    Returns:
        bool: True if file should be scanned
    """
    # Size check
    if file_size > size_limit_mb * 1024 * 1024:
        return False

    # File extension whitelist
    scan_extensions = {
        '.txt', '.cfg', '.conf', '.config', '.ini', '.env', '.properties',
        '.xml', '.json', '.yaml', '.yml', '.sql', '.bak', '.backup',
        '.log', '.py', '.php', '.js', '.java', '.cs', '.cpp', '.c',
        '.sh', '.bat', '.cmd', '.ps1', '.rb', '.pl', '.go', '.rs'
    }

    # Check extension
    _, ext = os.path.splitext(filename.lower())
    if ext in scan_extensions:
        return True

    # Check for common secret file patterns
    secret_patterns = [
        'password', 'passwd', 'secret', 'key', 'token', 'credential',
        'auth', 'config', 'settings', 'environment'
    ]

    filename_lower = filename.lower()
    for pattern in secret_patterns:
        if pattern in filename_lower:
            return True

    return False


def scan_directory_recursive(target, share, path, username, password, ntlm_hash, 
                           depth, current_depth, size_limit_mb, port, logger, interactive=False):
    """
    Recursively scan directories for secrets.

    Args:
        target (str): Target IP or hostname
        share (str): Share name
        path (str): Current directory path
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        depth (int): Maximum depth
        current_depth (int): Current depth
        size_limit_mb (int): Size limit in MB
        port (int): SMB port
        logger: Logger instance
        interactive (bool): Enable interactive mode

    Returns:
        list: List of findings
    """
    findings = []

    if current_depth > depth:
        return findings

    try:
        # List directory contents
        files = list_directory(target, share, path, username, password, ntlm_hash, port, logger)

        for file_entry in files:
            filename = file_entry.get_longname()

            # Skip hidden files and system directories
            if filename.startswith('.') or filename in ['System Volume Information', '$RECYCLE.BIN']:
                continue

            file_path = f"{path}/{filename}" if path != '*' else filename

            try:
                # Check if it's a directory
                if file_entry.is_directory():
                    # Recursively scan subdirectory
                    sub_findings = scan_directory_recursive(
                        target, share, file_path, username, password, ntlm_hash,
                        depth, current_depth + 1, size_limit_mb, port, logger, interactive
                    )
                    findings.extend(sub_findings)
                else:
                    # Check if file should be scanned
                    file_size = file_entry.get_filesize()

                    if should_scan_file(filename, file_size, size_limit_mb):
                        logger.debug(f"[*] Scanning file: {share}/{file_path}")

                        # Download and scan file
                        content = download_file(target, share, file_path, username, password, ntlm_hash, port, logger)

                        if content:
                            file_findings = scan_file_content(content, f"{share}/{file_path}", logger=logger, interactive=interactive)
                            findings.extend(file_findings)
                    else:
                        logger.debug(f"[-] Skipping file (size/type): {filename}")

            except Exception as e:
                logger.debug(f"[-] Error processing {file_path}: {str(e)}")
                continue

    except Exception as e:
        logger.debug(f"[-] Error scanning directory {path}: {str(e)}")

    return findings


def find_secrets(target, share, username, password, ntlm_hash, depth=3, 
                size_limit=20, port=445, threads=5, logger=None, 
                yara_engine=None, plugin_manager=None, interactive=False):
    """
    Find secrets in an SMB share using multi-threaded scanning.

    Args:
        target (str): Target IP or hostname
        share (str): Share name
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        depth (int): Maximum depth
        size_limit_mb (int): Size limit in MB
        port (int): SMB port
        threads (int): Number of threads
        logger: Logger instance
        interactive (bool): Enable interactive mode

    Returns:
        list: List of findings
    """
    if logger is None:
        logger = get_logger()

    logger.info(f"[*] Starting secret scan on share: {share}")

    # Start recursive scan from root
    findings = scan_directory_recursive(
        target, share, '*', username, password, ntlm_hash,
        depth, 0, size_limit, port, logger, interactive
    )

    logger.info(f"[+] Completed scan of share {share}. Found {len(findings)} potential secrets")

    return findings


def find_secrets_in_shares(target, shares, credentials, args, logger):
    """
    Find secrets in multiple SMB shares - wrapper for main application.
    
    Args:
        target (str): Target IP or hostname
        shares (list): List of share names or share dictionaries
        credentials (list): List of credential tuples
        args: Command line arguments
        logger: Logger instance
    
    Returns:
        list: List of findings
    """
    all_findings = []
    
    for share_item in shares:
        # Handle both string share names and share dictionary objects
        if isinstance(share_item, dict):
            share_name = share_item.get('name', '')
            if not share_name:
                logger.warning(f"[-] Share dictionary missing 'name' field: {share_item}")
                continue
        elif isinstance(share_item, str):
            share_name = share_item
        else:
            logger.warning(f"[-] Unknown share item type: {type(share_item)} - {share_item}")
            continue
        
        # Ensure share_name is a string
        share_name = str(share_name).strip()
        if not share_name:
            logger.warning(f"[-] Empty share name, skipping")
            continue
            
        # Skip IPC$ share as it doesn't contain files
        if share_name.upper() == 'IPC$':
            logger.info(f"[*] Skipping IPC$ share (administrative share)")
            continue
            
        logger.info(f"[*] Scanning share: {share_name}")
        
        # Use first working credential set for this share
        working_creds = None
        for username, password, ntlm_hash in credentials:
            from scanner.validator import validate_credentials
            if validate_credentials(target, username, password, ntlm_hash, args.port, logger):
                working_creds = (username, password, ntlm_hash)
                break
        
        if not working_creds:
            logger.warning(f"[-] No valid credentials for share: {share_name}")
            continue
        
        username, password, ntlm_hash = working_creds
        
        # Scan share for secrets using the single-share function
        try:
            share_findings = find_secrets(
                target, share_name, username, password, ntlm_hash,
                depth=getattr(args, 'depth', 3), 
                size_limit=getattr(args, 'size_limit', 20), 
                port=getattr(args, 'port', 445),
                threads=getattr(args, 'threads', 5), 
                logger=logger, 
                interactive=getattr(args, 'interactive', False)
            )
            all_findings.extend(share_findings)
        except Exception as e:
            logger.error(f"[-] Error scanning share {share_name}: {str(e)}")
    
    return all_findings