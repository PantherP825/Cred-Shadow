#!/usr/bin/env python3
"""
Test script to debug share parsing issues.
This will help us understand what's happening with the impacket SHARE_INFO_1 objects.
"""

import sys
from impacket.smbconnection import SMBConnection
from utils.logger import get_logger

def test_share_parsing(target, username, password, port=445):
    """Test share parsing with detailed debugging."""
    logger = get_logger()
    
    try:
        # Create SMB connection
        conn = SMBConnection(target, target, timeout=30)
        conn.login(username, password)
        
        # Get shares
        shares_resp = conn.listShares()
        logger.info(f"[+] Retrieved {len(shares_resp)} shares from server")
        
        for i, share in enumerate(shares_resp):
            logger.info(f"\n[*] === DEBUGGING SHARE {i+1} ===")
            logger.info(f"[*] Share object type: {type(share)}")
            logger.info(f"[*] Share object dir: {[attr for attr in dir(share) if not attr.startswith('_')]}")
            
            # Try different access methods
            for attr in ['shi1_netname', 'netname', 'name']:
                if hasattr(share, attr):
                    try:
                        value = getattr(share, attr)
                        logger.info(f"[+] {attr}: {value} (type: {type(value)})")
                        
                        # Try to decode if it's bytes
                        if isinstance(value, bytes):
                            decoded = value.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                            logger.info(f"[+] {attr} decoded: '{decoded}'")
                        elif hasattr(value, 'decode'):
                            decoded = value.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                            logger.info(f"[+] {attr} decoded: '{decoded}'")
                        else:
                            logger.info(f"[+] {attr} as string: '{str(value)}'")
                            
                    except Exception as e:
                        logger.error(f"[-] Error accessing {attr}: {e}")
            
            # Try repr to see internal structure
            try:
                logger.info(f"[*] Share repr: {repr(share)}")
            except Exception as e:
                logger.error(f"[-] Error getting repr: {e}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"[-] Test failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python test_share_parsing.py <target> <username> <password>")
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    test_share_parsing(target, username, password)