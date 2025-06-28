"""
Logging Module
Handles all logging functionality including console and file output.
"""

import logging
import json
import csv
import os
import time
from datetime import datetime
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Global logger instance
_logger = None


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored console output."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def init_logger(log_file=None, verbose=False, quiet=False):
    """
    Initialize the logger with console and file handlers.
    
    Args:
        log_file (str): Log file path (optional)
        verbose (bool): Enable verbose logging
        quiet (bool): Enable quiet mode (errors only)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    global _logger
    
    # Create logger
    _logger = logging.getLogger('cred-shadow')
    _logger.setLevel(logging.DEBUG)
    
    # Clear any existing handlers
    _logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    
    if quiet:
        console_handler.setLevel(logging.ERROR)
    elif verbose:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    
    # Console formatter with colors
    console_formatter = ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    _logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        _logger.addHandler(file_handler)
    else:
        # Default log file
        log_dir = 'output'
        os.makedirs(log_dir, exist_ok=True)
        default_log_file = os.path.join(log_dir, f'cred-shadow_{int(time.time())}.log')
        
        file_handler = logging.FileHandler(default_log_file)
        file_handler.setLevel(logging.DEBUG)
        
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        _logger.addHandler(file_handler)
    
    return _logger


def get_logger():
    """
    Get the global logger instance.
    
    Returns:
        logging.Logger: Logger instance
    """
    global _logger
    
    if _logger is None:
        _logger = init_logger()
    
    return _logger


def log_finding(finding, logger=None):
    """
    Log a security finding with appropriate formatting.
    
    Args:
        finding (dict): Finding dictionary
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    finding_type = finding.get('type', 'unknown')
    pattern = finding.get('pattern', 'unknown')
    file_path = finding.get('file_path', 'unknown')
    confidence = finding.get('confidence', 'medium')
    
    # Color code by confidence
    if confidence == 'high':
        color = Fore.RED + Style.BRIGHT
    elif confidence == 'medium':
        color = Fore.YELLOW
    else:
        color = Fore.CYAN
    
    logger.info(f"{color}[FINDING] {pattern} in {file_path}{Style.RESET_ALL}")
    
    if finding.get('context'):
        logger.debug(f"Context:\n{finding['context']}")


def log_credential_found(username, password, target, logger=None):
    """
    Log when valid credentials are found.
    
    Args:
        username (str): Username
        password (str): Password
        target (str): Target system
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    # Mask password for logging
    masked_password = password[:2] + '*' * (len(password) - 2) if len(password) > 2 else '*' * len(password)
    
    logger.info(f"{Fore.GREEN + Style.BRIGHT}[CREDENTIALS] {target} - {username}:{masked_password}{Style.RESET_ALL}")


def log_attack_attempt(target, username, password, success, attack_type, logger=None):
    """
    Log attack attempts for audit purposes.
    
    Args:
        target (str): Target system
        username (str): Username attempted
        password (str): Password attempted
        success (bool): Whether attempt was successful
        attack_type (str): Type of attack (brute_force, spray, etc.)
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    status = "SUCCESS" if success else "FAILED"
    masked_password = password[:1] + '*' * (len(password) - 1) if password else "(empty)"
    
    logger.debug(f"[{attack_type.upper()}] {target} - {username}:{masked_password} - {status}")


def export_json(findings, output_file, logger=None):
    """
    Export findings to JSON format.
    
    Args:
        findings (list): List of finding dictionaries
        output_file (str): Output file path
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    try:
        # Prepare export data
        export_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(findings),
                'tool': 'CRED-SHADOW',
                'version': '1.0.0'
            },
            'findings': findings
        }
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Write JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"[+] Results exported to JSON: {output_file}")
        
    except Exception as e:
        logger.error(f"[-] Error exporting to JSON: {str(e)}")


def export_csv(findings, output_file, logger=None):
    """
    Export findings to CSV format.
    
    Args:
        findings (list): List of finding dictionaries
        output_file (str): Output file path
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Define CSV columns
        fieldnames = [
            'timestamp', 'type', 'pattern', 'description', 'file_path',
            'line_number', 'match', 'confidence', 'context'
        ]
        
        # Write CSV file
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in findings:
                # Convert timestamp to readable format
                if 'timestamp' in finding:
                    finding['timestamp'] = datetime.fromtimestamp(finding['timestamp']).isoformat()
                
                # Write only the fields we want in CSV
                csv_row = {field: finding.get(field, '') for field in fieldnames}
                writer.writerow(csv_row)
        
        logger.info(f"[+] Results exported to CSV: {output_file}")
        
    except Exception as e:
        logger.error(f"[-] Error exporting to CSV: {str(e)}")


def create_summary_report(findings, target, credentials_found, logger=None):
    """
    Create a summary report of the scan.
    
    Args:
        findings (list): List of finding dictionaries
        target (str): Target system
        credentials_found (int): Number of credentials found
        logger: Logger instance
    
    Returns:
        str: Summary report text
    """
    if logger is None:
        logger = get_logger()
    
    # Count findings by type
    finding_counts = {}
    confidence_counts = {'high': 0, 'medium': 0, 'low': 0}
    
    for finding in findings:
        pattern = finding.get('pattern', 'unknown')
        confidence = finding.get('confidence', 'medium')
        
        finding_counts[pattern] = finding_counts.get(pattern, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
    
    # Generate summary
    summary = f"""
CRED-SHADOW Scan Summary
========================
Target: {target}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Credentials Found: {credentials_found}
Total Findings: {len(findings)}

Findings by Confidence:
- High: {confidence_counts['high']}
- Medium: {confidence_counts['medium']}  
- Low: {confidence_counts['low']}

Findings by Pattern:
"""
    
    for pattern, count in sorted(finding_counts.items()):
        summary += f"- {pattern}: {count}\n"
    
    summary += f"\nDetailed results have been saved to the output directory.\n"
    
    return summary


def log_scan_start(target, credentials, logger=None):
    """
    Log the start of a scan with target and credential information.
    
    Args:
        target (str): Target system
        credentials (list): List of credential tuples
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    logger.info(f"{Fore.CYAN + Style.BRIGHT}[SCAN START] Target: {target}{Style.RESET_ALL}")
    logger.info(f"[SCAN START] Credentials to test: {len(credentials)}")


def log_scan_complete(target, findings, duration, logger=None):
    """
    Log scan completion with summary.
    
    Args:
        target (str): Target system
        findings (list): List of findings
        duration (float): Scan duration in seconds
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    logger.info(f"{Fore.CYAN + Style.BRIGHT}[SCAN COMPLETE] Target: {target}{Style.RESET_ALL}")
    logger.info(f"[SCAN COMPLETE] Duration: {duration:.2f} seconds")
    logger.info(f"[SCAN COMPLETE] Findings: {len(findings)}")
