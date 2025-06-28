"""
Automated File Discovery and Enumeration Module
Handles automated file discovery across all authentication types and integrates with manual exploration.
"""

import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TaskProgressColumn, BarColumn, TextColumn
from colorama import Fore, Style
from utils.logger import get_logger
from scanner.clean_share_enum import enumerate_shares_clean, list_directory
from manual_mode.navigator import manual_navigator


console = Console()


class FileDiscoveryEngine:
    """Automated file discovery and enumeration engine."""
    
    def __init__(self, target, port=445, logger=None):
        """
        Initialize file discovery engine.
        
        Args:
            target (str): Target IP or hostname
            port (int): SMB port
            logger: Logger instance
        """
        self.target = target
        self.port = port
        self.logger = logger or get_logger()
        self.discovered_files = {}
        self.total_files_found = 0
        self.total_directories_found = 0
        
    def discover_files_auto(self, credentials, max_depth=2, file_extensions=None):
        """
        Automatically discover and enumerate files across all shares.
        
        Args:
            credentials (list): List of credential tuples
            max_depth (int): Maximum directory traversal depth
            file_extensions (list): File extensions to focus on
            
        Returns:
            dict: Organized file discovery results
        """
        if file_extensions is None:
            file_extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.config', '.ini', '.xml', '.json']
        
        self.logger.info("[*] Starting automated file discovery...")
        
        results = {
            'shares': {},
            'total_files': 0,
            'total_directories': 0,
            'interesting_files': [],
            'credentials_used': []
        }
        
        # Try each credential set
        for username, password, ntlm_hash in credentials:
            auth_type = self._get_auth_type(username, password, ntlm_hash)
            self.logger.info(f"[*] Attempting discovery with {auth_type}")
            
            try:
                # Enumerate shares for this credential set
                shares = enumerate_shares_clean(self.target, [(username, password, ntlm_hash)], self.port, self.logger)
                
                if not shares:
                    self.logger.debug(f"[-] No shares accessible with {auth_type}")
                    continue
                
                self.logger.info(f"[+] Found {len(shares)} share(s) with {auth_type}")
                results['credentials_used'].append((username, password, ntlm_hash, auth_type))
                
                # Discover files in each share
                for share in shares:
                    share_name = share.get('name', '') if isinstance(share, dict) else str(share)
                    if not share_name or share_name in ['IPC$', 'print$']:
                        continue
                    
                    self.logger.info(f"[*] Discovering files in share: {share_name}")
                    
                    share_files = self._discover_share_files(
                        share_name, username, password, ntlm_hash, max_depth, file_extensions
                    )
                    
                    if share_files:
                        results['shares'][share_name] = {
                            'files': share_files,
                            'auth_type': auth_type,
                            'credentials': (username, password, ntlm_hash)
                        }
                        results['total_files'] += len([f for f in share_files if not f.get('is_directory', False)])
                        results['total_directories'] += len([f for f in share_files if f.get('is_directory', False)])
                        
                        # Identify interesting files
                        interesting = self._identify_interesting_files(share_files, share_name)
                        results['interesting_files'].extend(interesting)
                
            except Exception as e:
                self.logger.debug(f"[-] Discovery failed with {auth_type}: {str(e)}")
                continue
        
        self._display_discovery_results(results)
        return results
    
    def _discover_share_files(self, share_name, username, password, ntlm_hash, max_depth, file_extensions):
        """Discover files within a specific share."""
        discovered_files = []
        
        def discover_recursive(current_path, current_depth):
            if current_depth > max_depth:
                return
            
            try:
                files = list_directory(
                    self.target, share_name, current_path, 
                    username, password, ntlm_hash, self.port
                )
                
                for file_info in files:
                    if isinstance(file_info, dict):
                        file_name = file_info.get('name', '')
                        is_directory = file_info.get('is_directory', False)
                        file_size = file_info.get('size', 0)
                        
                        if file_name in ['.', '..']:
                            continue
                        
                        file_path = f"{current_path}/{file_name}" if current_path else file_name
                        
                        file_entry = {
                            'name': file_name,
                            'path': file_path,
                            'share': share_name,
                            'is_directory': is_directory,
                            'size': file_size,
                            'modified_time': file_info.get('modified_time'),
                            'extension': os.path.splitext(file_name)[1].lower() if not is_directory else None
                        }
                        
                        discovered_files.append(file_entry)
                        
                        # Recurse into directories
                        if is_directory and current_depth < max_depth:
                            discover_recursive(file_path, current_depth + 1)
                            
            except Exception as e:
                self.logger.debug(f"[-] Error discovering files in {current_path}: {str(e)}")
        
        # Start discovery from root
        discover_recursive('', 0)
        return discovered_files
    
    def _identify_interesting_files(self, files, share_name):
        """Identify potentially interesting files based on name patterns and extensions."""
        interesting_patterns = [
            'password', 'passwd', 'secret', 'key', 'token', 'credential', 'config',
            'backup', '.env', 'settings', 'database', 'db', 'sql', 'admin',
            'user', 'login', 'auth', 'private', 'confidential', 'sensitive'
        ]
        
        interesting_extensions = [
            '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.config', '.ini',
            '.xml', '.json', '.sql', '.db', '.bak', '.backup', '.env', '.key',
            '.pem', '.p12', '.pfx', '.crt', '.cer'
        ]
        
        interesting_files = []
        
        for file_info in files:
            if file_info.get('is_directory', False):
                continue
            
            file_name = file_info.get('name', '').lower()
            file_extension = file_info.get('extension', '').lower()
            
            # Check for interesting name patterns
            is_interesting = any(pattern in file_name for pattern in interesting_patterns)
            
            # Check for interesting extensions
            if not is_interesting:
                is_interesting = file_extension in interesting_extensions
            
            # Check for specific file names
            if not is_interesting:
                specific_files = ['web.config', 'app.config', 'database.yml', '.htaccess', '.htpasswd']
                is_interesting = file_name in specific_files
            
            if is_interesting:
                interesting_files.append({
                    'file': file_info,
                    'share': share_name,
                    'reason': 'Potentially contains sensitive information'
                })
        
        return interesting_files
    
    def _display_discovery_results(self, results):
        """Display comprehensive discovery results."""
        print("\n" + "="*80)
        print(f"{Fore.GREEN}AUTOMATED FILE DISCOVERY COMPLETE{Style.RESET_ALL}")
        print("="*80)
        print(f"Total Files Found: {results['total_files']}")
        print(f"Total Directories: {results['total_directories']}")
        print(f"Interesting Files: {len(results['interesting_files'])}")
        print(f"Accessible Shares: {len(results['shares'])}")
        print("="*80)
        
        # Display ALL files found in each share
        if results['shares']:
            print(f"\n{Fore.CYAN}ALL FILES DISCOVERED:{Style.RESET_ALL}")
            
            for share_name, share_info in results['shares'].items():
                files = share_info['files']
                file_count = len([f for f in files if not f.get('is_directory', False)])
                dir_count = len([f for f in files if f.get('is_directory', False)])
                total_size = sum(f.get('size', 0) for f in files if not f.get('is_directory', False))
                
                print(f"\n{Fore.YELLOW}Share: {share_name} ({share_info['auth_type']}){Style.RESET_ALL}")
                print(f"Files: {file_count}, Directories: {dir_count}, Total Size: {self._format_size(total_size)}")
                print("-" * 80)
                print(f"{'NAME':<35} {'TYPE':<6} {'SIZE':<10} {'MODIFIED':<25}")
                print("-" * 80)
                
                # Show ALL files (limit to 20 per share for readability)
                for i, file_info in enumerate(files):
                    if i >= 20:
                        remaining = len(files) - 20
                        print(f"{Fore.YELLOW}... and {remaining} more files in this share{Style.RESET_ALL}")
                        break
                        
                    name = file_info['name'][:34] if len(file_info['name']) > 34 else file_info['name']
                    file_type = "DIR" if file_info.get('is_directory', False) else "FILE"
                    size = self._format_size(file_info.get('size', 0)) if not file_info.get('is_directory', False) else "-"
                    modified = file_info.get('modified', 'Unknown')[:24] if file_info.get('modified') else "Unknown"
                    
                    print(f"{name:<35} {file_type:<6} {size:<10} {modified:<25}")
                
                print("-" * 80)
        
        # Display interesting files
        if results['interesting_files']:
            print(f"\n{Fore.YELLOW}INTERESTING FILES DISCOVERED:{Style.RESET_ALL}")
            print("-" * 100)
            print(f"{'Share':<15} {'File Path':<40} {'Size':<10} {'Ext':<8} {'Reason':<25}")
            print("-" * 100)
            
            for item in results['interesting_files'][:20]:  # Limit to top 20
                file_info = item['file']
                share = item['share'][:14]
                path = file_info['path'][:39] if len(file_info['path']) > 39 else file_info['path']
                size = self._format_size(file_info.get('size', 0))
                ext = file_info.get('extension', '') or 'N/A'
                reason = item['reason'][:24] if len(item['reason']) > 24 else item['reason']
                
                print(f"{share:<15} {path:<40} {size:<10} {ext:<8} {reason:<25}")
            
            print("-" * 100)
            
            if len(results['interesting_files']) > 20:
                print(f"{Fore.YELLOW}... and {len(results['interesting_files']) - 20} more interesting files{Style.RESET_ALL}")
    
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
    
    def _format_size(self, size):
        """Format file size in human readable format."""
        if size == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB']
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.1f} {units[unit_index]}"


def automated_file_discovery(target, credentials, port=445, max_depth=2, logger=None):
    """
    Main function for automated file discovery.
    
    Args:
        target (str): Target IP or hostname
        credentials (list): List of credential tuples
        port (int): SMB port
        max_depth (int): Maximum directory traversal depth
        logger: Logger instance
        
    Returns:
        dict: Discovery results
    """
    if logger is None:
        logger = get_logger()
    
    # Create discovery engine and perform file discovery
    discovery_engine = FileDiscoveryEngine(target, port, logger)
    
    # Use enum_shares directly to get comprehensive share information
    logger.info("[*] Discovering shares and files across all authentication methods...")
    
    results = {
        'shares': {},
        'total_files': 0,
        'total_directories': 0,
        'interesting_files': [],
        'credentials_used': []
    }
    
    # Get all accessible shares using enum_shares
    all_shares = enumerate_shares_clean(target, credentials, port, logger)
    
    if not all_shares:
        logger.warning("[-] No accessible shares found for file discovery")
        return results
    
    # Process each discovered share
    for share_info in all_shares:
        share_name = share_info.get('name', 'Unknown')
        share_creds = share_info.get('credentials', {})
        
        if share_name in ['IPC$', 'print$']:
            continue
            
        username = share_creds.get('username', '')
        password = share_creds.get('password', '')
        ntlm_hash = share_creds.get('ntlm_hash')
        
        auth_type = discovery_engine._get_auth_type(username, password, ntlm_hash)
        
        logger.info(f"[*] Discovering files in share: {share_name} using {auth_type}")
        
        # Discover files in this share
        share_files = discovery_engine._discover_share_files(
            share_name, username, password, ntlm_hash, max_depth, None
        )
        
        if share_files:
            results['shares'][share_name] = {
                'files': share_files,
                'auth_type': auth_type,
                'credentials': (username, password, ntlm_hash)
            }
            
            results['total_files'] += len([f for f in share_files if not f.get('is_directory', False)])
            results['total_directories'] += len([f for f in share_files if f.get('is_directory', False)])
            
            # Identify interesting files
            interesting = discovery_engine._identify_interesting_files(share_files, share_name)
            results['interesting_files'].extend(interesting)
            
            # Track credentials used
            cred_entry = (username, password, ntlm_hash, auth_type)
            if cred_entry not in results['credentials_used']:
                results['credentials_used'].append(cred_entry)
    
    # Display results
    discovery_engine._display_discovery_results(results)
    
    return results


def display_comprehensive_discovery_results(discovery_results, logger):
    """
    Display comprehensive file discovery results showing files found in each share
    with their authentication context.
    
    Args:
        discovery_results (dict): Results from automated discovery
        logger: Logger instance
    """
    if not discovery_results or not discovery_results.get('shares'):
        logger.warning("[-] No files discovered across any authentication methods")
        return
    
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]COMPREHENSIVE FILE DISCOVERY RESULTS[/bold cyan]\n"
        f"Files discovered across [green]{len(discovery_results['shares'])}[/green] accessible shares",
        border_style="cyan"
    ))
    
    total_files = discovery_results.get('total_files', 0)
    total_dirs = discovery_results.get('total_directories', 0)
    interesting_files = len(discovery_results.get('interesting_files', []))
    
    # Summary statistics
    console.print(f"\n[bold]Discovery Summary:[/bold]")
    console.print(f"  📁 Total Directories: [green]{total_dirs}[/green]")
    console.print(f"  📄 Total Files: [green]{total_files}[/green]")
    console.print(f"  🔍 Interesting Files: [yellow]{interesting_files}[/yellow]")
    console.print(f"  🔐 Authentication Methods Used: [cyan]{len(discovery_results.get('credentials_used', []))}[/cyan]")
    
    # Display files by share
    for share_name, share_data in discovery_results['shares'].items():
        auth_type = share_data.get('auth_type', 'Unknown')
        files = share_data.get('files', [])
        
        if not files:
            continue
            
        # Create share header
        console.print(f"\n[bold blue]═══ Share: {share_name} ═══[/bold blue]")
        console.print(f"[dim]Authentication: {auth_type}[/dim]")
        
        # Create table for this share's files
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("📂 Path", style="cyan", no_wrap=False, min_width=30)
        table.add_column("📋 Type", style="green", width=8)
        table.add_column("📏 Size", style="yellow", justify="right", width=10)
        table.add_column("📅 Modified", style="blue", width=20)
        table.add_column("🏷️ Category", style="red", width=12)
        
        # Sort files: directories first, then by name
        sorted_files = sorted(files, key=lambda x: (not x.get('is_directory', False), x.get('name', '').lower()))
        
        for file_info in sorted_files:
            name = file_info.get('name', 'Unknown')
            path = file_info.get('path', name)
            is_dir = file_info.get('is_directory', False)
            size = file_info.get('size', 0)
            modified = file_info.get('modified_time', 'Unknown')
            
            # Format file type
            file_type = "DIR" if is_dir else "FILE"
            
            # Format size
            if is_dir:
                size_str = "-"
            elif isinstance(size, (int, float)) and size > 0:
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f} KB"
                elif size < 1024 * 1024 * 1024:
                    size_str = f"{size/(1024*1024):.1f} MB"
                else:
                    size_str = f"{size/(1024*1024*1024):.1f} GB"
            else:
                size_str = "0 B"
            
            # Format modified time
            try:
                if isinstance(modified, (int, float)):
                    import time
                    modified_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(modified))
                else:
                    modified_str = str(modified)[:19] if modified and modified != 'Unknown' else 'Unknown'
            except:
                modified_str = 'Unknown'
            
            # Categorize file
            category = _categorize_file(name, is_dir)
            
            table.add_row(path, file_type, size_str, modified_str, category)
        
        console.print(table)
        console.print(f"[dim]Files in {share_name}: {len([f for f in files if not f.get('is_directory', False)])} files, {len([f for f in files if f.get('is_directory', False)])} directories[/dim]")
    
    # Display interesting files summary
    if discovery_results.get('interesting_files'):
        console.print(f"\n[bold yellow]🔍 INTERESTING FILES FOUND:[/bold yellow]")
        interesting_table = Table(show_header=True, header_style="bold yellow")
        interesting_table.add_column("Share", style="cyan", width=15)
        interesting_table.add_column("File", style="white", no_wrap=False)
        interesting_table.add_column("Category", style="red", width=15)
        interesting_table.add_column("Authentication", style="green", width=15)
        
        for item in discovery_results['interesting_files']:
            interesting_table.add_row(
                item.get('share', 'Unknown'),
                item.get('path', 'Unknown'),
                item.get('category', 'Unknown'),
                item.get('auth_type', 'Unknown')
            )
        
        console.print(interesting_table)
    
    # Authentication methods summary
    if discovery_results.get('credentials_used'):
        console.print(f"\n[bold green]🔐 AUTHENTICATION METHODS SUCCESSFUL:[/bold green]")
        for username, password, ntlm_hash, auth_type in discovery_results['credentials_used']:
            console.print(f"  • [cyan]{auth_type}[/cyan]")


def _categorize_file(filename, is_directory):
    """Categorize file based on name and extension."""
    if is_directory:
        return "Directory"
    
    name_lower = filename.lower()
    
    # Document files
    if any(ext in name_lower for ext in ['.doc', '.docx', '.pdf', '.txt', '.rtf']):
        return "Document"
    
    # Spreadsheets
    if any(ext in name_lower for ext in ['.xls', '.xlsx', '.csv']):
        return "Spreadsheet"
    
    # Configuration files
    if any(ext in name_lower for ext in ['.config', '.ini', '.conf', '.cfg', '.xml', '.json', '.yaml', '.yml']):
        return "Config"
    
    # Scripts and executables
    if any(ext in name_lower for ext in ['.bat', '.cmd', '.ps1', '.sh', '.exe', '.msi']):
        return "Executable"
    
    # Database files
    if any(ext in name_lower for ext in ['.db', '.sqlite', '.mdb', '.accdb']):
        return "Database"
    
    # Archive files
    if any(ext in name_lower for ext in ['.zip', '.rar', '.7z', '.tar', '.gz']):
        return "Archive"
    
    # Image files
    if any(ext in name_lower for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']):
        return "Image"
    
    # Backup files
    if any(pattern in name_lower for pattern in ['backup', '.bak', '.old', '.backup']):
        return "Backup"
    
    # Log files
    if any(ext in name_lower for ext in ['.log', '.logs']):
        return "Log"
    
    return "Other"


def prompt_manual_exploration(discovery_results, target, port, logger):
    """
    Prompt user for manual exploration options after automated discovery.
    
    Args:
        discovery_results (dict): Results from automated discovery
        target (str): Target IP or hostname
        port (int): SMB port
        logger: Logger instance
    """
    from colorama import Fore, Style
    
    if not discovery_results['shares']:
        logger.info("[*] No accessible shares found for manual exploration")
        return
    
    print(f"\n{Fore.CYAN}MANUAL EXPLORATION OPTIONS:{Style.RESET_ALL}")
    print("1. Full manual exploration mode (interactive shell)")
    print("2. Quick access to interesting files")
    print("3. Skip manual exploration")
    
    try:
        choice = input(f"\n{Fore.CYAN}Select option (1-3): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            # Start full manual exploration
            from manual_mode.navigator import manual_navigator
            
            # Prepare credentials from discovery results
            valid_creds = []
            for cred_info in discovery_results['credentials_used']:
                username, password, ntlm_hash, _ = cred_info
                valid_creds.append((username, password, ntlm_hash))
            
            # Convert discovery results to share format for manual mode
            shares = []
            for share_name, share_info in discovery_results['shares'].items():
                shares.append({
                    'name': share_name,
                    'credentials': share_info['credentials']
                })
            
            logger.info("[*] Starting manual exploration mode...")
            manual_navigator(target, valid_creds, port, shares)
            
        elif choice == '2':
            # Quick access to interesting files
            if discovery_results['interesting_files']:
                print(f"\n{Fore.YELLOW}QUICK ACCESS TO INTERESTING FILES:{Style.RESET_ALL}")
                for i, item in enumerate(discovery_results['interesting_files'][:10], 1):
                    file_info = item['file']
                    share = item['share']
                    print(f"{i}. {share}:{file_info['path']} ({item['reason']})")
                
                print(f"\n{Fore.GREEN}Use manual mode ('use <share>' then 'cat <file>') to access these files{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No interesting files found for quick access{Style.RESET_ALL}")
                
        elif choice == '3':
            logger.info("[*] Skipping manual exploration")
            
        else:
            logger.info("[*] Invalid choice, skipping manual exploration")
            
    except KeyboardInterrupt:
        logger.info("\n[*] Manual exploration cancelled by user")


def prompt_manual_exploration(results, target, port=445, logger=None):
    """
    Prompt user for manual exploration after automated discovery.
    
    Args:
        results (dict): Discovery results from automated scan
        target (str): Target IP or hostname
        port (int): SMB port
        logger: Logger instance
    """
    if logger is None:
        logger = get_logger()
    
    if not results['shares']:
        print("No accessible shares found for manual exploration.")
        return
    
    print("\nMANUAL EXPLORATION OPTIONS:")
    print("1. Enter manual mode for detailed exploration")
    print("2. Quick file access for interesting files")
    print("3. Skip manual exploration")
    
    try:
        choice = input(f"{Fore.CYAN}Select option (1-3): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            # Launch full manual mode
            print("Launching manual exploration mode...")
            
            # Prepare credentials for manual mode
            valid_creds = []
            for cred_info in results['credentials_used']:
                username, password, ntlm_hash, auth_type = cred_info
                valid_creds.append((username, password, ntlm_hash))
            
            # Extract shares list
            shares = list(results['shares'].keys())
            
            # Start manual navigation
            manual_navigator(target, valid_creds, port, shares)
            
        elif choice == '2':
            # Quick access to interesting files
            _quick_file_access(results, target, port, logger)
            
        elif choice == '3':
            print("Skipping manual exploration.")
            
        else:
            print("Invalid choice. Skipping manual exploration.")
            
    except KeyboardInterrupt:
        print("\nManual exploration cancelled.")
    except Exception as e:
        logger.error(f"Error in manual exploration prompt: {str(e)}")


def _quick_file_access(results, target, port, logger):
    """Quick access mode for interesting files."""
    if not results['interesting_files']:
        print("No interesting files found for quick access.")
        return
    
    print("\nQUICK FILE ACCESS MODE")
    print("Select files to download or view:")
    
    # Display numbered list of interesting files
    for i, item in enumerate(results['interesting_files'][:10], 1):
        file_info = item['file']
        print(f"{i}. {item['share']}:{file_info['path']} ({file_info.get('extension', 'N/A')})")
    
    try:
        selection = input(f"{Fore.CYAN}Enter file numbers (comma-separated) or 'all': {Style.RESET_ALL}").strip()
        
        if selection.lower() == 'all':
            selected_indices = list(range(len(results['interesting_files'][:10])))
        else:
            selected_indices = [int(x.strip()) - 1 for x in selection.split(',') if x.strip().isdigit()]
        
        for index in selected_indices:
            if 0 <= index < len(results['interesting_files']):
                item = results['interesting_files'][index]
                file_info = item['file']
                share_name = item['share']
                
                # Get credentials for this share
                share_info = results['shares'][share_name]
                username, password, ntlm_hash = share_info['credentials']
                
                print(f"\n{Fore.CYAN}Accessing: {share_name}:{file_info['path']}{Style.RESET_ALL}")
                
                # Attempt to view/download file
                _access_file_quick(target, share_name, file_info['path'], username, password, ntlm_hash, port, logger)
                
    except Exception as e:
        logger.error(f"Error in quick file access: {str(e)}")


def _access_file_quick(target, share, file_path, username, password, ntlm_hash, port, logger):
    """Quick file access for viewing or downloading."""
    from manual_mode.downloader import view_file_content, download_file_interactive
    
    try:
        # Try to view file content first
        content = view_file_content(target, share, file_path, username, password, ntlm_hash, port)
        
        if content:
            if len(content) > 1000:
                # Large file - offer download
                print(f"{Fore.YELLOW}File is large ({len(content)} bytes). Download? (y/n){Style.RESET_ALL}")
                if input().strip().lower() == 'y':
                    download_file_interactive(target, share, file_path, username, password, ntlm_hash, port)
            else:
                # Small file - display content
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    display_content = text_content[:500] + ("..." if len(text_content) > 500 else "")
                    
                    print(f"\n{Fore.BLUE}=== Contents of {os.path.basename(file_path)} ==={Style.RESET_ALL}")
                    print(display_content)
                    print(f"{Fore.BLUE}{'=' * (len(os.path.basename(file_path)) + 16)}{Style.RESET_ALL}\n")
                except UnicodeDecodeError:
                    print(f"{Fore.YELLOW}Binary file detected. Downloading...{Style.RESET_ALL}")
                    download_file_interactive(target, share, file_path, username, password, ntlm_hash, port)
        else:
            print(f"{Fore.RED}Could not access file: {file_path}{Style.RESET_ALL}")
            
    except Exception as e:
        logger.debug(f"Quick access error for {file_path}: {str(e)}")
        console.print(f"[red]Error accessing file: {str(e)}[/red]")