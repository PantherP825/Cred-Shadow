"""
Manual Navigation Module
Provides interactive command-line interface for manual SMB share exploration.
"""

import os
import sys
import cmd
import time
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from colorama import init, Fore, Style
from scanner.clean_share_enum import enumerate_shares_clean, list_directory, get_file_info
from scanner.secret_finder import scan_file_content
from manual_mode.downloader import download_file_interactive, view_file_content
from utils.logger import get_logger

# Initialize colorama and rich
init(autoreset=True)
console = Console()


class SMBNavigator(cmd.Cmd):
    """Interactive SMB navigation shell."""
    
    intro = f"""
{Fore.MAGENTA}┌─ MANUAL EXPLORATION MODE ──────────────────────────────────────────┐
│                                                                    │
│  Interactive SMB share navigation activated.                      │
│                                                                    │
│  Commands:                                                         │
│    ls [path]      - List directory contents                       │
│    cd <path>      - Change directory                              │
│    cat <file>     - Display file contents                         │
│    download <file> - Download file to local system               │
│    upload <file>   - Upload local file to current share          │
│    put <local_file> [remote_name] - Upload file to current share │
│    shares         - List available shares                         │
│    find <pattern> - Search for files matching pattern            │
│    scan <file>    - Scan file for secrets                        │
│    info <file>    - Show file information                        │
│    help           - Show this help message                       │
│    exit, quit     - Exit manual mode                             │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
    
    prompt = f"{Fore.CYAN}cred-shadow> {Style.RESET_ALL}"
    
    def __init__(self, target, credentials, port=445):
        """
        Initialize SMB navigator.
        
        Args:
            target (str): Target IP or hostname
            credentials (list): List of valid credential tuples
            port (int): SMB port
        """
        super().__init__()
        self.target = target
        self.credentials = credentials
        self.port = port
        self.current_creds = credentials[0] if credentials else (None, None, None)
        self.current_share = None
        self.current_path = ""
        self.shares = []
        self.logger = get_logger()
        
        # Initialize all share-related attributes to prevent AttributeError
        self.selected_shares = []
        self.discovered_shares = []
        
        # Load shares on startup
        self._load_shares()
    
    def _safe_smb_path_join(self, *parts):
        """Safely join SMB path components without creating invalid paths."""
        # Remove empty parts and normalize separators
        clean_parts = []
        for part in parts:
            if part and str(part).strip():
                # Convert to string and replace backslashes with forward slashes
                clean_part = str(part).strip().replace('\\', '/')
                # Remove leading/trailing slashes
                clean_part = clean_part.strip('/')
                if clean_part:
                    clean_parts.append(clean_part)
        
        # Join with forward slashes (SMB standard)
        if clean_parts:
            return '/'.join(clean_parts)
        return ""
    
    def _try_alternative_credentials(self):
        """Prompt user for alternative credentials when access is denied."""
        from rich.prompt import Prompt
        
        console.print("[yellow]Current credentials may not have sufficient access.[/yellow]")
        console.print("[cyan]Options:[/cyan]")
        console.print("  1. Enter new username/password")
        console.print("  2. Try blank/anonymous access")
        console.print("  3. Skip and continue with current credentials")
        
        choice = Prompt.ask("What would you like to do?", choices=["1", "2", "3"], default="3")
        
        if choice == "1":
            # Prompt for new credentials
            new_username = Prompt.ask("Enter username", default="")
            if new_username:
                new_password = Prompt.ask("Enter password", password=True, default="")
                self.current_creds = (new_username, new_password, None)
                console.print(f"[green]Updated credentials to: {new_username}[/green]")
                return True
            else:
                console.print("[yellow]No username provided. Using anonymous access.[/yellow]")
                self.current_creds = ("", "", None)
                return True
        elif choice == "2":
            # Try anonymous/blank access
            console.print("[cyan]Trying anonymous/blank access...[/cyan]")
            self.current_creds = ("", "", None)
            return True
        else:
            # Continue with current credentials
            return False
    
    def _load_shares(self):
        """Load available shares."""
        try:
            # Ensure attributes exist first
            if not hasattr(self, 'selected_shares'):
                self.selected_shares = []
            if not hasattr(self, 'discovered_shares'):
                self.discovered_shares = []
            
            # Use pre-selected shares if provided, otherwise enumerate all
            if self.selected_shares:
                self.shares = self.selected_shares
                console.print(f"[green]Using pre-selected {len(self.shares)} share(s): {', '.join(self.shares)}[/green]")
            elif hasattr(self, 'discovered_shares') and self.discovered_shares:
                # Use discovered shares passed from main
                self.shares = [share['name'] for share in self.discovered_shares]
                console.print(f"[green]Using discovered {len(self.shares)} share(s)[/green]")
            else:
                # Fresh enumeration - call the comprehensive enum_shares function
                console.print(f"[yellow]Enumerating shares on {self.target}...[/yellow]")
                
                # Use authenticated credentials if provided, otherwise try all session types
                if self.credentials:
                    # When credentials are provided, only use those (authenticated session)
                    all_session_creds = self.credentials
                    console.print(f"[green]Using authenticated session with provided credentials[/green]")
                else:
                    # No credentials provided, try all session types (anonymous, null, guest)
                    from scanner.share_enum import try_all_session_types
                    all_session_creds = try_all_session_types(self.target, self.port, self.logger)
                    console.print(f"[yellow]No credentials provided, trying all session types[/yellow]")
                
                # Use the robust enum_shares function
                discovered = enumerate_shares_clean(self.target, all_session_creds, self.port, self.logger)
                
                if discovered:
                    self.discovered_shares = discovered
                    self.shares = [share['name'] for share in discovered]
                    console.print(f"[green]Found {len(self.shares)} share(s)[/green]")
                    
                    # Display discovered shares in a table
                    if self.discovered_shares:
                        from rich.table import Table
                        table = Table(title="Discovered Shares")
                        table.add_column("Share Name", style="cyan")
                        table.add_column("Access Level", style="green")
                        table.add_column("Comment", style="dim")
                        
                        for share in self.discovered_shares:
                            access_color = {
                                'read': 'green',
                                'read/write': 'bright_green', 
                                'no access': 'red',
                                'special': 'yellow'
                            }.get(share.get('access', 'unknown').lower(), 'white')
                            
                            table.add_row(
                                share['name'],
                                f"[{access_color}]{share.get('access', 'UNKNOWN')}[/{access_color}]",
                                share.get('comment', '')
                            )
                        console.print(table)
                else:
                    console.print(f"[yellow]No shares enumerated on {self.target}[/yellow]")
                    console.print("[yellow]Manual mode will still allow manual connection attempts[/yellow]")
                    self.shares = []
            
            # Auto-select first non-IPC share
            if self.shares:
                for share in self.shares:
                    if share.upper() != 'IPC$':
                        self.current_share = share
                        break
                if not self.current_share and self.shares:
                    self.current_share = self.shares[0]
                    
                if self.current_share:
                    self.prompt = f"{Fore.CYAN}cred-shadow[{self.current_share}]> {Style.RESET_ALL}"
                    console.print(f"[cyan]Current share: {self.current_share}[/cyan]")
                
        except Exception as e:
            console.print(f"[red]Error loading shares: {str(e)}[/red]")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            # Ensure attributes exist even on error
            self.shares = []
    
    def do_shares(self, args):
        """List all discovered shares with access information."""
        if hasattr(self, 'discovered_shares') and self.discovered_shares:
            console.print(f"\n[bold]All discovered shares on {self.target}:[/bold]")
            
            # Create detailed table
            from rich.table import Table
            table = Table()
            table.add_column("ID", style="cyan", width=4)
            table.add_column("Share Name", style="white bold")
            table.add_column("Type", style="magenta")
            table.add_column("Access Level", style="green")
            table.add_column("Session Found", style="yellow")
            table.add_column("Comment", style="dim")
            
            for i, share in enumerate(self.discovered_shares, 1):
                share_type = {0: "DISK", 1: "PRINT", 3: "IPC"}.get(share.get('type', 0), "OTHER")
                access = share.get('access', 'UNKNOWN')
                access_color = {
                    'read': 'green',
                    'read/write': 'bright_green',
                    'no access': 'red', 
                    'special': 'yellow',
                    'unknown': 'dim'
                }.get(access.lower(), 'white')
                
                table.add_row(
                    str(i),
                    share['name'],
                    share_type,
                    f"[{access_color}]{access}[/{access_color}]",
                    share.get('session_type', 'Unknown'),
                    share.get('comment', '')
                )
            
            console.print(table)
            
            # Summary
            accessible = [s for s in self.discovered_shares if s.get('access', '').upper() in ['READ', 'READ/WRITE', 'SPECIAL']]
            console.print(f"\n[bold]Summary:[/bold] {len(accessible)} accessible, {len(self.discovered_shares) - len(accessible)} restricted")
            
        elif self.shares:
            console.print(f"\n[bold]Available shares on {self.target}:[/bold]")
            for i, share in enumerate(self.shares, 1):
                status = " (current)" if share == self.current_share else ""
                console.print(f"  [cyan]{i:2d}.[/cyan] {share}{status}")
        else:
            console.print("[yellow]No shares currently loaded[/yellow]")
            console.print("[yellow]Available commands:[/yellow]")
            console.print("  [cyan]enum[/cyan]           - Enumerate shares on target")
            console.print("  [cyan]use <sharename>[/cyan] - Attempt direct connection to share")
            console.print("  [cyan]help[/cyan]           - Show all available commands")
        
        console.print(f"\nUse [bold]'use <sharename>'[/bold] to connect to any share (even if restricted)")
    
    def do_use(self, args):
        """Switch to a different share."""
        if not args:
            console.print("[red]Usage: use <share_name>[/red]")
            return
        
        share_name = args.strip()
        
        # Always allow switching to any share name (direct connection attempt)
        self.current_share = share_name
        self.current_path = ""
        self.prompt = f"{Fore.CYAN}cred-shadow[{self.current_share}]> {Style.RESET_ALL}"
        
        if share_name in self.shares:
            console.print(f"[green]Switched to discovered share: {share_name}[/green]")
        else:
            console.print(f"[yellow]Attempting direct connection to share: {share_name}[/yellow]")
            console.print(f"[dim]Note: This share was not in the discovered list but you can still try to access it[/dim]")
            
        # Test connectivity to the share
        try:
            username, password, ntlm_hash = self.current_creds
            from scanner.share_enum import test_individual_share_access
            access_level = test_individual_share_access(
                self.target, share_name, username, password, ntlm_hash, self.port, self.logger
            )
            
            if "NO ACCESS" in access_level or "ACCESS DENIED" in access_level:
                console.print(f"[red]Warning: {access_level} for share '{share_name}'[/red]")
            else:
                console.print(f"[green]Access confirmed: {access_level}[/green]")
        except Exception as e:
            console.print(f"[dim]Could not test access: {str(e)}[/dim]")
    
    def do_ls(self, args):
        """List directory contents."""
        if not self.current_share:
            console.print("[red]No share selected. Use 'shares' to see available shares.[/red]")
            return
        
        # Handle IPC$ share differently - it's an administrative share
        if self.current_share.upper() == 'IPC$':
            console.print("[yellow]IPC$ is an administrative share used for inter-process communication.[/yellow]")
            console.print("[yellow]It doesn't contain files - use 'shares' to switch to a different share.[/yellow]")
            return
        
        path = args.strip() if args else self.current_path
        if not path:
            path = "*"
        
        try:
            username, password, ntlm_hash = self.current_creds
            files = list_directory(self.target, self.current_share, path, username, password, ntlm_hash, self.port)
            
            if not files:
                console.print("[yellow]Directory is empty or not accessible.[/yellow]")
                return
            
            table = Table(title=f"Contents of {self.current_share}/{path}")
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Type", style="magenta")
            table.add_column("Size", style="green", justify="right")
            table.add_column("Modified", style="blue")
            
            for file_info in files:
                # Safely extract file information with proper defaults
                filename = str(file_info.get('name', 'Unknown'))
                is_dir = file_info.get('is_directory', False)
                file_type = "DIR" if is_dir else "FILE"
                
                # Handle file size safely
                file_size = "-"
                if not is_dir:
                    size_val = file_info.get('size', 0)
                    if size_val and isinstance(size_val, (int, float)):
                        file_size = self._format_size(size_val)
                    else:
                        file_size = "0 B"
                
                # Handle modified time safely to prevent key errors
                modified_time = "Unknown"
                mod_time = file_info.get('modified_time')
                if mod_time:
                    try:
                        if isinstance(mod_time, (int, float)):
                            modified_time = time.ctime(mod_time)
                        else:
                            modified_time = str(mod_time)
                    except (ValueError, OSError):
                        modified_time = "Invalid Date"
                
                table.add_row(filename, file_type, file_size, modified_time)
            
            console.print(table)
            
        except Exception as e:
            error_msg = str(e)
            if "STATUS_ACCESS_DENIED" in error_msg or "Access Denied" in error_msg:
                console.print(f"[yellow]Access denied to {self.current_share}. Trying alternative credentials...[/yellow]")
                # Try alternative credential prompt
                if self._try_alternative_credentials():
                    # Retry with new credentials
                    try:
                        username, password, ntlm_hash = self.current_creds
                        files = list_directory(self.target, self.current_share, path, username, password, ntlm_hash, self.port)
                        if files:
                            console.print(f"[green]Access granted with alternative credentials![/green]")
                            # Display files with the same table logic as above
                            table = Table(title=f"Contents of {self.current_share}/{path}")
                            table.add_column("Name", style="cyan", no_wrap=True)
                            table.add_column("Type", style="magenta")
                            table.add_column("Size", style="green", justify="right")
                            table.add_column("Modified", style="blue")
                            
                            for file_info in files:
                                filename = str(file_info.get('name', 'Unknown'))
                                is_dir = file_info.get('is_directory', False)
                                file_type = "DIR" if is_dir else "FILE"
                                file_size = "-"
                                if not is_dir:
                                    size_val = file_info.get('size', 0)
                                    if size_val and isinstance(size_val, (int, float)):
                                        file_size = self._format_size(size_val)
                                    else:
                                        file_size = "0 B"
                                modified_time = "Unknown"
                                mod_time = file_info.get('modified_time')
                                if mod_time:
                                    try:
                                        if isinstance(mod_time, (int, float)):
                                            modified_time = time.ctime(mod_time)
                                        else:
                                            modified_time = str(mod_time)
                                    except (ValueError, OSError):
                                        modified_time = "Invalid Date"
                                table.add_row(filename, file_type, file_size, modified_time)
                            console.print(table)
                            return
                        else:
                            console.print("[yellow]Directory is empty or still not accessible.[/yellow]")
                    except Exception as retry_error:
                        console.print(f"[red]Still cannot access directory: {str(retry_error)}[/red]")
                else:
                    console.print("[red]No alternative credentials provided. Directory remains inaccessible.[/red]")
            else:
                console.print(f"[red]Error listing directory: {error_msg}[/red]")
    
    def do_cd(self, args):
        """Change directory."""
        if not args:
            console.print("[red]Usage: cd <directory>[/red]")
            return
        
        if not self.current_share:
            console.print("[red]No share selected.[/red]")
            return
        
        directory = args.strip()
        
        # Handle special cases
        if directory == "..":
            if self.current_path:
                path_parts = self.current_path.split('/')
                self.current_path = '/'.join(path_parts[:-1])
            else:
                console.print("[yellow]Already at root directory.[/yellow]")
                return
        elif directory == "/":
            self.current_path = ""
        else:
            # Build new path using safe path joining
            new_path = self._safe_smb_path_join(self.current_path, directory)
            
            # Verify directory exists
            try:
                username, password, ntlm_hash = self.current_creds
                files = list_directory(self.target, self.current_share, new_path, username, password, ntlm_hash, self.port)
                self.current_path = new_path
            except Exception as e:
                console.print(f"[red]Cannot access directory '{directory}': {str(e)}[/red]")
                return
        
        # Update prompt
        path_display = f"/{self.current_path}" if self.current_path else "/"
        self.prompt = f"{Fore.CYAN}cred-shadow[{self.current_share}{path_display}]> {Style.RESET_ALL}"
        console.print(f"[green]Changed to: {self.current_share}{path_display}[/green]")
    
    def do_cat(self, args):
        """Display file contents."""
        if not args:
            console.print("[red]Usage: cat <filename>[/red]")
            return
        
        filename = args.strip()
        
        # Build file path
        if self.current_path:
            file_path = self._safe_smb_path_join(self.current_path, filename)
        else:
            file_path = filename
        
        console.print(f"[cyan]Reading {filename} from {self.current_share}:{file_path}...[/cyan]")
        
        try:
            # Use direct SMB connection method
            content = self._read_file_direct(file_path)
            
            if content:
                # Display file content in a panel
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    if len(text_content) > 2000:
                        text_content = text_content[:2000] + "\n\n[... content truncated ...]"
                    
                    panel = Panel(
                        text_content,
                        title=f"Contents of {filename} ({len(content)} bytes)",
                        border_style="blue"
                    )
                    console.print(panel)
                except UnicodeDecodeError:
                    console.print(f"[yellow]Binary file detected ({len(content)} bytes). Use download command to save locally.[/yellow]")
            else:
                console.print("[red]Could not read file or file is empty.[/red]")
                
        except Exception as e:
            console.print(f"[red]Error reading file: {str(e)}[/red]")
    
    def do_download(self, args):
        """Download file to local system."""
        if not args:
            console.print("[red]Usage: download <filename> [local_path][/red]")
            return
        
        parts = args.strip().split()
        filename = parts[0]
        local_path = parts[1] if len(parts) > 1 else None
        
        # Build remote file path
        if self.current_path:
            remote_path = self._safe_smb_path_join(self.current_path, filename)
        else:
            remote_path = filename
            
        # Create local path if not provided
        if not local_path:
            import os
            downloads_dir = "downloads"
            os.makedirs(downloads_dir, exist_ok=True)
            local_path = os.path.join(downloads_dir, filename)
        
        console.print(f"[cyan]Downloading {filename} from {self.current_share}:{remote_path}...[/cyan]")
        
        try:
            username, password, ntlm_hash = self.current_creds
            success = self._download_file_direct(remote_path, local_path)
            
            if success:
                console.print(f"[green]File downloaded successfully: {filename} -> {local_path}[/green]")
            else:
                console.print(f"[red]Failed to download file: {filename}[/red]")
                
        except Exception as e:
            console.print(f"[red]Error downloading file: {str(e)}[/red]")
    
    def do_upload(self, args):
        """Upload local file to current share."""
        if not args:
            console.print("[red]Usage: upload <local_file_path> [remote_name][/red]")
            return
        
        parts = args.strip().split()
        local_file_path = parts[0]
        remote_name = parts[1] if len(parts) > 1 else os.path.basename(local_file_path)
        
        # Check if local file exists
        if not os.path.exists(local_file_path):
            console.print(f"[red]Local file not found: {local_file_path}[/red]")
            return
        
        # Build remote file path
        if self.current_path:
            remote_path = self._safe_smb_path_join(self.current_path, remote_name)
        else:
            remote_path = remote_name
        
        console.print(f"[cyan]Uploading {local_file_path} to {self.current_share}:{remote_path}...[/cyan]")
        
        try:
            success = self._upload_file_direct(local_file_path, remote_path)
            
            if success:
                console.print(f"[green]File uploaded successfully: {local_file_path} -> {self.current_share}:{remote_path}[/green]")
            else:
                console.print(f"[red]Failed to upload file: {local_file_path}[/red]")
                
        except Exception as e:
            console.print(f"[red]Error uploading file: {str(e)}[/red]")
    
    def do_put(self, args):
        """Upload file to current share (alias for upload with enhanced feedback)."""
        if not args:
            console.print("[red]Usage: put <local_file_path> [remote_name][/red]")
            console.print("[yellow]Examples:[/yellow]")
            console.print("  put /home/user/test.txt")
            console.print("  put ./document.pdf report.pdf")
            console.print("  put payload.exe malware.exe")
            return
        
        parts = args.strip().split()
        local_file_path = parts[0]
        remote_name = parts[1] if len(parts) > 1 else os.path.basename(local_file_path)
        
        # Check if local file exists
        if not os.path.exists(local_file_path):
            console.print(f"[red]Local file not found: {local_file_path}[/red]")
            return
        
        # Get file size for progress info
        file_size = os.path.getsize(local_file_path)
        file_size_str = self._format_size(file_size)
        
        # Display upload info
        console.print(f"[cyan]Upload Details:[/cyan]")
        console.print(f"  Local File: {local_file_path}")
        console.print(f"  File Size: {file_size_str}")
        console.print(f"  Target Share: {self.current_share}")
        console.print(f"  Remote Name: {remote_name}")
        console.print(f"  Authentication: {self._get_current_auth_type()}")
        
        # Build remote file path
        if self.current_path:
            remote_path = self._safe_smb_path_join(self.current_path, remote_name)
        else:
            remote_path = remote_name
        
        console.print(f"[cyan]Uploading {local_file_path} ({file_size_str}) to {self.current_share}:{remote_path}...[/cyan]")
        
        try:
            success = self._upload_file_direct(local_file_path, remote_path)
            
            if success:
                console.print(f"[green]✓ Upload successful: {local_file_path} -> {self.current_share}:{remote_path}[/green]")
                console.print(f"[green]✓ File is now accessible at: {remote_path}[/green]")
                
                # Suggest verification
                console.print(f"[yellow]Tip: Use 'ls' to verify the upload or 'cat {remote_name}' to view content[/yellow]")
            else:
                console.print(f"[red]✗ Upload failed: {local_file_path}[/red]")
                console.print(f"[yellow]Possible reasons:[/yellow]")
                console.print("  • Share does not have write permissions")
                console.print("  • File path contains invalid characters")
                console.print("  • Insufficient disk space on target")
                console.print("  • Authentication level insufficient for write access")
                
        except Exception as e:
            console.print(f"[red]Error during upload: {str(e)}[/red]")
    
    def _get_current_auth_type(self):
        """Get current authentication type for display."""
        username, password, ntlm_hash = self.current_creds
        
        if ntlm_hash:
            return f"NTLM Hash ({username})"
        elif not username and not password:
            return "Anonymous/Null Session"
        elif username == 'guest':
            return "Guest Account"
        else:
            return f"Credentials ({username})"
    
    def _download_file_direct(self, remote_path, local_path):
        """Direct file download with SMB connection."""
        from impacket.smbconnection import SMBConnection
        import os
        from pathlib import Path
        
        smb_conn = None
        try:
            # Ensure local directory exists
            local_file = Path(local_path)
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            smb_conn = SMBConnection(self.target, self.target, None, self.port, timeout=30)
            
            # Authenticate
            username, password, ntlm_hash = self.current_creds
            if ntlm_hash:
                if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                    lm_hash, nt_hash = ntlm_hash.split(':', 1)
                else:
                    lm_hash, nt_hash = ntlm_hash
                smb_conn.login(username, password, '', lm_hash, nt_hash)
            elif not username and not password:
                try:
                    smb_conn.login('', '')
                except:
                    smb_conn.close()
                    smb_conn = SMBConnection(self.target, self.target, None, self.port, timeout=30)
                    smb_conn.login('guest', '')
            else:
                smb_conn.login(username or '', password or '')
            
            # Normalize remote path
            if remote_path.startswith('/'):
                remote_path = remote_path[1:]
            
            # Download file with error handling
            try:
                with open(local_path, 'wb') as fp:
                    smb_conn.getFile(self.current_share, remote_path, fp.write)
                
                # Verify download
                if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                    self.logger.debug(f"Successfully downloaded {remote_path} ({os.path.getsize(local_path)} bytes)")
                    return True
                else:
                    self.logger.debug(f"Download failed - file is empty or missing: {local_path}")
                    return False
                    
            except Exception as download_err:
                self.logger.debug(f"Direct download failed: {str(download_err)}")
                # Try alternative path formats
                alt_paths = [
                    remote_path.replace('/', '\\'),
                    '\\' + remote_path.lstrip('\\').lstrip('/'),
                    remote_path.lstrip('\\').lstrip('/'),
                    f"{self.current_path}\\{remote_path}" if self.current_path else remote_path,
                    f"{self.current_path}/{remote_path}" if self.current_path else remote_path
                ]
                
                for alt_path in alt_paths:
                    try:
                        self.logger.debug(f"Trying alternative path: {alt_path}")
                        with open(local_path, 'wb') as fp:
                            smb_conn.getFile(self.current_share, alt_path, fp.write)
                        
                        if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                            self.logger.debug(f"Success with alternative path: {alt_path}")
                            return True
                    except Exception as alt_err:
                        self.logger.debug(f"Alternative path {alt_path} failed: {str(alt_err)}")
                        continue
                
                return False
                
        except Exception as e:
            self.logger.debug(f"Download error: {str(e)}")
            return False
        finally:
            if smb_conn:
                try:
                    smb_conn.close()
                except:
                    pass
    
    def _read_file_direct(self, remote_path):
        """Direct file reading with SMB connection."""
        from impacket.smbconnection import SMBConnection
        import tempfile
        
        smb_conn = None
        try:
            smb_conn = SMBConnection(self.target, self.target, None, self.port, timeout=30)
            
            # Authenticate
            username, password, ntlm_hash = self.current_creds
            if ntlm_hash:
                if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                    lm_hash, nt_hash = ntlm_hash.split(':', 1)
                else:
                    lm_hash, nt_hash = ntlm_hash
                smb_conn.login(username, password, '', lm_hash, nt_hash)
            elif not username and not password:
                try:
                    smb_conn.login('', '')
                except:
                    smb_conn.close()
                    smb_conn = SMBConnection(self.target, self.target, None, self.port, timeout=30)
                    smb_conn.login('guest', '')
            else:
                smb_conn.login(username or '', password or '')
            
            # Try multiple path formats
            path_attempts = [
                remote_path,
                remote_path.replace('/', '\\'),
                '\\' + remote_path.lstrip('\\').lstrip('/'),
                remote_path.lstrip('\\').lstrip('/'),
                f"{self.current_path}\\{remote_path}" if self.current_path else remote_path,
                f"{self.current_path}/{remote_path}" if self.current_path else remote_path
            ]
            
            for attempt_path in path_attempts:
                try:
                    self.logger.debug(f"Trying to read file: {self.current_share}:{attempt_path}")
                    with tempfile.NamedTemporaryFile() as temp_file:
                        smb_conn.getFile(self.current_share, attempt_path, temp_file.write)
                        temp_file.seek(0)
                        content = temp_file.read()
                        
                        if content:
                            self.logger.debug(f"Successfully read {len(content)} bytes from {attempt_path}")
                            return content
                            
                except Exception as path_err:
                    self.logger.debug(f"Path {attempt_path} failed: {str(path_err)}")
                    continue
            
            self.logger.debug(f"All path attempts failed for {remote_path}")
            return None
                
        except Exception as e:
            self.logger.debug(f"Read file error: {str(e)}")
            return None
        finally:
            if smb_conn:
                try:
                    smb_conn.close()
                except:
                    pass
    
    def _upload_file_direct(self, local_path, remote_path):
        """Direct file upload with SMB connection."""
        from impacket.smbconnection import SMBConnection
        import os
        
        smb_conn = None
        try:
            smb_conn = SMBConnection(self.target, self.target, None, self.port, timeout=30)
            
            # Authenticate
            username, password, ntlm_hash = self.current_creds
            if ntlm_hash:
                if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                    lm_hash, nt_hash = ntlm_hash.split(':', 1)
                else:
                    lm_hash, nt_hash = ntlm_hash
                smb_conn.login(username, password, '', lm_hash, nt_hash)
            elif not username and not password:
                try:
                    smb_conn.login('', '')
                except:
                    smb_conn.close()
                    smb_conn = SMBConnection(self.target, self.target, None, self.port, timeout=30)
                    smb_conn.login('guest', '')
            else:
                smb_conn.login(username or '', password or '')
            
            # Normalize remote path
            if remote_path.startswith('/'):
                remote_path = remote_path[1:]
            
            # Try upload with error handling
            try:
                with open(local_path, 'rb') as local_file:
                    smb_conn.putFile(self.current_share, remote_path, local_file.read)
                
                # Verify upload by checking if file exists
                try:
                    file_info = smb_conn.listPath(self.current_share, remote_path)
                    if file_info:
                        self.logger.debug(f"Upload verified: {remote_path}")
                        return True
                except:
                    # File might exist but verification failed
                    return True
                    
            except Exception as upload_err:
                self.logger.debug(f"Direct upload failed: {str(upload_err)}")
                # Try alternative path formats
                alt_paths = [
                    remote_path.replace('/', '\\'),
                    '\\' + remote_path.lstrip('\\').lstrip('/'),
                    remote_path.lstrip('\\').lstrip('/'),
                    f"{self.current_path}\\{os.path.basename(remote_path)}" if self.current_path else remote_path,
                    f"{self.current_path}/{os.path.basename(remote_path)}" if self.current_path else remote_path
                ]
                
                for alt_path in alt_paths:
                    try:
                        self.logger.debug(f"Trying alternative upload path: {alt_path}")
                        with open(local_path, 'rb') as local_file:
                            smb_conn.putFile(self.current_share, alt_path, local_file.read)
                        
                        # Verify alternative upload
                        try:
                            file_info = smb_conn.listPath(self.current_share, alt_path)
                            if file_info:
                                self.logger.debug(f"Alternative upload successful: {alt_path}")
                                return True
                        except:
                            continue
                            
                    except Exception as alt_err:
                        self.logger.debug(f"Alternative path {alt_path} failed: {str(alt_err)}")
                        continue
                
                return False
                
        except Exception as e:
            self.logger.debug(f"Upload error: {str(e)}")
            return False
        finally:
            if smb_conn:
                try:
                    smb_conn.close()
                except:
                    pass
    
    def do_scan(self, args):
        """Scan file for secrets."""
        if not args:
            console.print("[red]Usage: scan <filename>[/red]")
            return
        
        filename = args.strip()
        file_path = f"{self.current_path}/{filename}" if self.current_path else filename
        
        try:
            username, password, ntlm_hash = self.current_creds
            content = view_file_content(self.target, self.current_share, file_path, username, password, ntlm_hash, self.port)
            
            if content:
                findings = scan_file_content(content, f"{self.current_share}/{file_path}", logger=self.logger)
                
                if findings:
                    table = Table(title=f"Secrets found in {filename}")
                    table.add_column("Pattern", style="cyan")
                    table.add_column("Description", style="yellow")
                    table.add_column("Confidence", style="green")
                    table.add_column("Match", style="red")
                    
                    for finding in findings:
                        table.add_row(
                            finding.get('pattern', 'Unknown'),
                            finding.get('description', 'Unknown'),
                            finding.get('confidence', 'Unknown'),
                            finding.get('match', '')[:50] + "..." if len(finding.get('match', '')) > 50 else finding.get('match', '')
                        )
                    
                    console.print(table)
                else:
                    console.print("[green]No secrets found in file.[/green]")
            else:
                console.print("[red]Could not read file.[/red]")
                
        except Exception as e:
            console.print(f"[red]Error scanning file: {str(e)}[/red]")
    
    def do_info(self, args):
        """Show file information."""
        if not args:
            console.print("[red]Usage: info <filename>[/red]")
            return
        
        filename = args.strip()
        file_path = f"{self.current_path}/{filename}" if self.current_path else filename
        
        try:
            username, password, ntlm_hash = self.current_creds
            file_info = get_file_info(self.target, self.current_share, file_path, username, password, ntlm_hash, self.port)
            
            if file_info:
                table = Table(title=f"Information for {filename}")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="green")
                
                table.add_row("Size", self._format_size(file_info['size']))
                table.add_row("Modified", time.ctime(file_info['modified']))
                table.add_row("Created", time.ctime(file_info['created']))
                table.add_row("Type", "Directory" if file_info['is_directory'] else "File")
                
                console.print(table)
            else:
                console.print("[red]Could not get file information.[/red]")
                
        except Exception as e:
            console.print(f"[red]Error getting file info: {str(e)}[/red]")
    
    def do_find(self, args):
        """Search for files matching pattern."""
        if not args:
            console.print("[red]Usage: find <pattern>[/red]")
            return
        
        pattern = args.strip().lower()
        console.print(f"[blue]Searching for files matching '{pattern}'...[/blue]")
        
        try:
            matches = self._search_files(self.current_path, pattern)
            
            if matches:
                table = Table(title=f"Files matching '{pattern}'")
                table.add_column("Path", style="cyan")
                table.add_column("Name", style="yellow")
                table.add_column("Size", style="green")
                
                for match in matches[:50]:  # Limit results
                    table.add_row(match['path'], match['name'], match['size'])
                
                console.print(table)
                
                if len(matches) > 50:
                    console.print(f"[yellow]Showing first 50 of {len(matches)} matches.[/yellow]")
            else:
                console.print("[yellow]No files found matching the pattern.[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error searching files: {str(e)}[/red]")
    
    def _search_files(self, base_path, pattern, max_depth=3, current_depth=0):
        """Recursively search for files matching pattern."""
        matches = []
        
        if current_depth > max_depth:
            return matches
        
        try:
            username, password, ntlm_hash = self.current_creds
            files = list_directory(self.target, self.current_share, base_path or "*", username, password, ntlm_hash, self.port)
            
            for file_entry in files:
                filename = file_entry.get_longname()
                if filename in ['.', '..']:
                    continue
                
                file_path = f"{base_path}/{filename}" if base_path else filename
                
                # Check if filename matches pattern
                if pattern in filename.lower():
                    matches.append({
                        'path': file_path,
                        'name': filename,
                        'size': self._format_size(file_entry.get_filesize()) if not file_entry.is_directory() else "DIR"
                    })
                
                # Recursively search subdirectories
                if file_entry.is_directory() and current_depth < max_depth:
                    sub_matches = self._search_files(file_path, pattern, max_depth, current_depth + 1)
                    matches.extend(sub_matches)
        
        except Exception:
            pass  # Ignore errors during search
        
        return matches
    
    def _format_size(self, size):
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def do_pwd(self, args):
        """Print current working directory."""
        path_display = f"/{self.current_path}" if self.current_path else "/"
        console.print(f"[green]{self.current_share}{path_display}[/green]")
    
    def do_clear(self, args):
        """Clear the screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_creds(self, args):
        """Show current credentials."""
        username, password, ntlm_hash = self.current_creds
        console.print(f"[green]Current credentials:[/green]")
        console.print(f"  Username: {username or '(null)'}")
        console.print(f"  Password: {'*' * len(password) if password else '(empty)'}")
        console.print(f"  NTLM Hash: {'Yes' if ntlm_hash else 'No'}")
    
    def do_exit(self, args):
        """Exit manual mode."""
        console.print("[yellow]Exiting manual exploration mode...[/yellow]")
        return True
    
    def do_quit(self, args):
        """Exit manual mode."""
        return self.do_exit(args)
    
    def do_EOF(self, args):
        """Handle Ctrl+D."""
        print()  # Print newline
        return self.do_exit(args)
    
    def emptyline(self):
        """Handle empty line input."""
        pass
    
    def default(self, line):
        """Handle unknown commands."""
        console.print(f"[red]Unknown command: {line}. Type 'help' for available commands.[/red]")


def manual_navigator(target, credentials, port=445, shares=None):
    """
    Start manual navigation mode.
    
    Args:
        target (str): Target IP or hostname
        credentials (list): List of valid credential tuples
        port (int): SMB port
        shares (list): Pre-enumerated shares (optional)
    """
    try:
        if not credentials:
            console.print("[red]No valid credentials available for manual mode.[/red]")
            return
        
        navigator = SMBNavigator(target, credentials, port)
        
        # If shares were pre-enumerated, load them into navigator
        if shares:
            navigator.shares = shares
            navigator.discovered_shares = shares
            console.print(f"[green]Loaded {len(shares)} pre-enumerated shares[/green]")
        
        navigator.cmdloop()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Manual mode interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error in manual mode: {str(e)}[/red]")
