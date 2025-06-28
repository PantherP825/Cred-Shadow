"""
Upload Functionality Tester
Tests file upload capabilities across different authentication methods and shares.
"""

import os
import tempfile
import time
from datetime import datetime
from colorama import Fore, Style
from impacket.smbconnection import SMBConnection
from utils.logger import get_logger


class UploadTester:
    """Test file upload capabilities on SMB shares."""
    
    def __init__(self, target, port=445, logger=None):
        """
        Initialize upload tester.
        
        Args:
            target (str): Target IP or hostname
            port (int): SMB port
            logger: Logger instance
        """
        self.target = target
        self.port = port
        self.logger = logger or get_logger()
        self.test_filename = f"cred_shadow_test_{int(time.time())}.txt"
        self.test_content = b"CRED-SHADOW Upload Test File\nCreated: " + str(datetime.now()).encode()
    
    def test_upload_permissions(self, credentials_list):
        """
        Test upload permissions across all provided credentials.
        
        Args:
            credentials_list (list): List of credential tuples
            
        Returns:
            dict: Upload test results
        """
        results = {
            'uploadable_shares': [],
            'failed_uploads': [],
            'total_tested': 0,
            'successful_uploads': 0
        }
        
        self.logger.info("[*] Testing upload permissions across accessible shares...")
        
        for creds in credentials_list:
            username, password, ntlm_hash = creds
            auth_type = self._get_auth_type(username, password, ntlm_hash)
            
            self.logger.info(f"[*] Testing upload with {auth_type}")
            
            # Get accessible shares for these credentials
            accessible_shares = self._get_accessible_shares(username, password, ntlm_hash)
            
            for share_name in accessible_shares:
                if share_name.upper() in ['IPC$', 'PRINT$']:
                    continue
                    
                results['total_tested'] += 1
                upload_result = self._test_share_upload(share_name, username, password, ntlm_hash)
                
                if upload_result['success']:
                    results['successful_uploads'] += 1
                    results['uploadable_shares'].append({
                        'share': share_name,
                        'auth_type': auth_type,
                        'credentials': (username, password, ntlm_hash),
                        'test_file': upload_result['test_file'],
                        'upload_path': upload_result['upload_path']
                    })
                    self.logger.info(f"[+] Upload successful: {share_name} ({auth_type})")
                else:
                    results['failed_uploads'].append({
                        'share': share_name,
                        'auth_type': auth_type,
                        'error': upload_result['error']
                    })
                    self.logger.debug(f"[-] Upload failed: {share_name} - {upload_result['error']}")
        
        self._display_upload_results(results)
        return results
    
    def _test_share_upload(self, share_name, username, password, ntlm_hash):
        """
        Test file upload to a specific share.
        
        Args:
            share_name (str): Share name to test
            username (str): Username for authentication
            password (str): Password for authentication
            ntlm_hash (tuple): NTLM hash tuple
            
        Returns:
            dict: Upload test result
        """
        smb_conn = None
        test_filename = f"{self.test_filename}_{share_name}"
        
        try:
            # Create SMB connection
            smb_conn = SMBConnection(self.target, self.target, timeout=30)
            
            # Authenticate
            if ntlm_hash and ntlm_hash != (None, None):
                lm_hash, nt_hash = ntlm_hash
                smb_conn.login(username, '', nthash=nt_hash, lmhash=lm_hash)
            else:
                smb_conn.login(username or '', password or '')
            
            # Try different upload paths
            upload_paths = [
                test_filename,
                f"\\{test_filename}",
                f"temp\\{test_filename}",
                f"uploads\\{test_filename}"
            ]
            
            for upload_path in upload_paths:
                try:
                    # Create temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(self.test_content)
                        temp_file_path = temp_file.name
                    
                    # Attempt upload
                    with open(temp_file_path, 'rb') as file_obj:
                        smb_conn.putFile(share_name, upload_path, file_obj.read)
                    
                    # Verify upload by trying to list or read the file
                    try:
                        # Try to get file info to verify it exists
                        file_info = smb_conn.listPath(share_name, upload_path)
                        if file_info:
                            # Cleanup - delete the test file
                            try:
                                smb_conn.deleteFile(share_name, upload_path)
                            except:
                                pass  # Cleanup attempt, don't fail if it doesn't work
                            
                            return {
                                'success': True,
                                'test_file': test_filename,
                                'upload_path': upload_path,
                                'error': None
                            }
                    except:
                        # File might have been uploaded but verification failed
                        try:
                            smb_conn.deleteFile(share_name, upload_path)
                        except:
                            pass
                        continue
                    
                    # Cleanup temp file
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
                        
                except Exception as upload_err:
                    self.logger.debug(f"Upload path {upload_path} failed: {str(upload_err)}")
                    continue
            
            return {
                'success': False,
                'test_file': test_filename,
                'upload_path': None,
                'error': 'All upload paths failed'
            }
            
        except Exception as e:
            return {
                'success': False,
                'test_file': test_filename,
                'upload_path': None,
                'error': str(e)
            }
        finally:
            if smb_conn:
                try:
                    smb_conn.close()
                except:
                    pass
    
    def _get_accessible_shares(self, username, password, ntlm_hash):
        """Get list of accessible shares for given credentials."""
        from scanner.clean_share_enum import enumerate_shares_clean
        
        shares = enumerate_shares_clean(self.target, [(username, password, ntlm_hash)], self.port, self.logger)
        
        share_names = []
        for share in shares:
            if isinstance(share, dict):
                share_names.append(share.get('name', ''))
            elif isinstance(share, str):
                share_names.append(share)
            else:
                share_names.append(str(share))
        
        return [name for name in share_names if name and name.strip()]
    
    def _get_auth_type(self, username, password, ntlm_hash):
        """Determine authentication type string."""
        if ntlm_hash:
            return f"NTLM Hash ({username})"
        elif not username and not password:
            return "Anonymous/Null Session"
        elif username == 'guest':
            return "Guest Account"
        else:
            return f"Credentials ({username})"
    
    def _display_upload_results(self, results):
        """Display upload test results."""
        print(f"\n{Fore.GREEN}═══════════════════════════════════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.GREEN}                                    UPLOAD PERMISSIONS TEST RESULTS                                   {Style.RESET_ALL}")
        print(f"{Fore.GREEN}═══════════════════════════════════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}📊 UPLOAD TEST SUMMARY{Style.RESET_ALL}")
        print(f"   • Total Shares Tested: {results['total_tested']}")
        print(f"   • Successful Uploads: {results['successful_uploads']}")
        print(f"   • Failed Uploads: {len(results['failed_uploads'])}")
        print(f"   • Uploadable Shares: {len(results['uploadable_shares'])}")
        
        if results['uploadable_shares']:
            print(f"\n{Fore.GREEN}✅ SHARES WITH UPLOAD PERMISSIONS:{Style.RESET_ALL}")
            print("-" * 90)
            print(f"{'SHARE NAME':<20} {'AUTH TYPE':<25} {'TEST STATUS':<15} {'NOTES':<30}")
            print("-" * 90)
            
            for share_info in results['uploadable_shares']:
                share_name = share_info['share'][:19]
                auth_type = share_info['auth_type'][:24]
                status = "UPLOAD OK"
                notes = f"Path: {share_info['upload_path']}"[:29]
                
                print(f"{share_name:<20} {auth_type:<25} {Fore.GREEN}{status:<15}{Style.RESET_ALL} {notes:<30}")
            
            print("-" * 90)
            
            print(f"\n{Fore.YELLOW}⚠️  SECURITY IMPLICATIONS:{Style.RESET_ALL}")
            print("   • These shares allow file uploads - potential security risk")
            print("   • Consider restricting write permissions if not required")
            print("   • Monitor these shares for unauthorized file uploads")
            print("   • Review access controls and user permissions")
        
        if results['failed_uploads']:
            print(f"\n{Fore.RED}❌ SHARES WITHOUT UPLOAD PERMISSIONS:{Style.RESET_ALL}")
            print("-" * 80)
            print(f"{'SHARE NAME':<20} {'AUTH TYPE':<25} {'ERROR':<35}")
            print("-" * 80)
            
            for failed_upload in results['failed_uploads'][:10]:  # Limit to 10
                share_name = failed_upload['share'][:19]
                auth_type = failed_upload['auth_type'][:24]
                error = failed_upload['error'][:34] if failed_upload['error'] else "Unknown error"
                
                print(f"{share_name:<20} {auth_type:<25} {error:<35}")
            
            if len(results['failed_uploads']) > 10:
                remaining = len(results['failed_uploads']) - 10
                print(f"{Fore.YELLOW}... and {remaining} more shares without upload permissions{Style.RESET_ALL}")
            
            print("-" * 80)


def test_upload_permissions(target, credentials, port=445, logger=None):
    """
    Main function to test upload permissions across shares.
    
    Args:
        target (str): Target IP or hostname
        credentials (list): List of credential tuples
        port (int): SMB port
        logger: Logger instance
        
    Returns:
        dict: Upload test results
    """
    if logger is None:
        logger = get_logger()
    
    upload_tester = UploadTester(target, port, logger)
    return upload_tester.test_upload_permissions(credentials)