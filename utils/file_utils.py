"""
File utilities for CRED-SHADOW
Provides file saving and export functionality.
"""

import json
import csv
import os
from datetime import datetime


def save_results_to_file(results, filename, logger=None):
    """
    Save results to JSON file.
    
    Args:
        results: Results data to save
        filename (str): Output filename
        logger: Logger instance
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        if logger:
            logger.info(f"[+] Results saved to {filename}")
        
    except Exception as e:
        if logger:
            logger.error(f"[-] Failed to save results to {filename}: {str(e)}")


def save_results_to_csv(results, filename, logger=None):
    """
    Save results to CSV file.
    
    Args:
        results: Results data to save
        filename (str): Output filename
        logger: Logger instance
    """
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if not results:
                return
            
            # Get fieldnames from first result
            if isinstance(results, list) and results:
                fieldnames = results[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            
        if logger:
            logger.info(f"[+] Results saved to {filename}")
            
    except Exception as e:
        if logger:
            logger.error(f"[-] Failed to save CSV to {filename}: {str(e)}")