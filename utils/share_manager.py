"""
Share Manager for CRED-SHADOW
Handles share enumeration, access testing, and interactive share operations.
"""

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from utils.logger import get_logger

console = Console()

class ShareManager:
    """Manages share enumeration and access for automation mode."""
    
    def __init__(self, target, session_manager, port=445):
        self.target = target
        self.session_manager = session_manager
        self.port = port
        self.logger = get_logger()
        self.discovered_shares = []
        
    def enumerate_and_process_shares(self):
        """
        Enumerate all shares and process them with user interaction.
        """
        console.print("\n[bold blue]═══ Share Enumeration & Access ═══[/bold blue]")
        
        # Get current session credentials
        session = self.session_manager.get_session_info()
        if not session:
            console.print("[red][-] No active session for share enumeration[/red]")
            return False
        
        creds = session['credentials']
        credentials_list = [(creds['username'], creds['password'], creds['ntlm_hash'])]
        
        # Enumerate shares
        console.print(f"[cyan][*] Enumerating shares on {self.target}[/cyan]")
        
        try:
            from scanner.clean_share_enum import enumerate_shares_clean
            self.discovered_shares = enumerate_shares_clean(self.target, credentials_list, self.port, self.logger)
            
            if not self.discovered_shares:
                console.print("[yellow][-] No shares discovered[/yellow]")
                return False
            
            # Display discovered shares
            self._display_discovered_shares()
            
            # Process each share interactively
            return self._process_shares_interactively()
            
        except Exception as e:
            console.print(f"[red][-] Share enumeration error: {str(e)}[/red]")
            return False
    
    def _display_discovered_shares(self):
        """Display all discovered shares in a table."""
        table = Table(title=f"Discovered Shares on {self.target}")
        table.add_column("ID", style="cyan", width=4)
        table.add_column("Share Name", style="white bold")
        table.add_column("Type", style="magenta")
        table.add_column("Access Level", style="green")
        table.add_column("Comment", style="dim")
        
        for i, share in enumerate(self.discovered_shares, 1):
            share_type = {0: "DISK", 1: "PRINT", 3: "IPC"}.get(share.get('type', 0), "OTHER")
            access = share.get('access', 'UNKNOWN')
            
            # Color access level
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
                share.get('comment', '')
            )
        
        console.print(table)
        console.print(f"\n[bold]Total shares discovered:[/bold] {len(self.discovered_shares)}")
    
    def _process_shares_interactively(self):
        """Process each share with user interaction."""
        accessible_shares = 0
        
        for i, share in enumerate(self.discovered_shares, 1):
            share_name = share['name']
            access_level = share.get('access', 'UNKNOWN')
            
            console.print(f"\n[bold cyan]Processing Share {i}/{len(self.discovered_shares)}: {share_name}[/bold cyan]")
            
            # Ask user if they want to attempt access
            attempt_access = Confirm.ask(
                f"Attempt access to [bold]{share_name}[/bold]?",
                default=True
            )
            
            if not attempt_access:
                console.print(f"[yellow][*] Skipping {share_name}[/yellow]")
                continue
            
            # Attempt access based on current access level
            if access_level == 'NO ACCESS':
                console.print(f"[red][-] Access denied to {share_name}[/red]")
                
                # Ask for password if access denied
                password_prompt = Prompt.ask(
                    f"Password required for [bold]{share_name}[/bold]. Enter password (blank = try no password)",
                    password=True,
                    default=""
                )
                
                if password_prompt:
                    console.print(f"[cyan][*] Retrying access to {share_name} with provided password[/cyan]")
                    # Here you would retry with the new password
                    # For now, simulate success/failure
                    console.print(f"[yellow][*] Password authentication for {share_name} would be attempted here[/yellow]")
                else:
                    console.print(f"[yellow][*] Skipping to next share[/yellow]")
                    continue
            
            elif access_level in ['READ', 'READ/WRITE', 'SPECIAL']:
                console.print(f"[green][+] Access granted to {share_name} ({access_level})[/green]")
                accessible_shares += 1
                
                # Automatically list files/folders
                console.print(f"[cyan][*] Automatically listing contents of {share_name}[/cyan]")
                
                # Simulate file listing (would use actual SMB calls)
                self._simulate_share_contents(share_name)
                
                # Prompt for next action
                action = self._prompt_share_actions(share_name)
                if action == 'skip':
                    continue
                elif action == 'navigate':
                    self._handle_navigation(share_name)
                elif action == 'read':
                    self._handle_file_reading(share_name)
            
            else:
                console.print(f"[yellow][?] Unknown access level for {share_name}: {access_level}[/yellow]")
                continue
        
        console.print(f"\n[bold green]Share processing complete![/bold green]")
        console.print(f"[cyan]Accessible shares: {accessible_shares}/{len(self.discovered_shares)}[/cyan]")
        return True
    
    def _simulate_share_contents(self, share_name):
        """Simulate listing share contents."""
        # This would use actual SMB calls in production
        sample_contents = [
            {"name": "Documents", "type": "folder", "size": "-"},
            {"name": "config.txt", "type": "file", "size": "1.2 KB"},
            {"name": "Scripts", "type": "folder", "size": "-"},
            {"name": "readme.md", "type": "file", "size": "834 B"}
        ]
        
        table = Table(title=f"Contents of {share_name}")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Size", style="green")
        
        for item in sample_contents:
            icon = "📁" if item["type"] == "folder" else "📄"
            table.add_row(f"{icon} {item['name']}", item["type"], item["size"])
        
        console.print(table)
    
    def _prompt_share_actions(self, share_name):
        """Prompt user for what to do with accessible share."""
        console.print(f"\n[bold]What would you like to do with {share_name}?[/bold]")
        
        choices = [
            "navigate - Navigate into folder",
            "read - Read file content", 
            "skip - Skip to next share"
        ]
        
        for choice in choices:
            console.print(f"  [cyan]{choice}[/cyan]")
        
        action = Prompt.ask(
            "Choose action",
            choices=["navigate", "read", "skip"],
            default="skip"
        )
        
        return action
    
    def _handle_navigation(self, share_name):
        """Handle folder navigation."""
        folder = Prompt.ask(f"Enter folder name to navigate into (in {share_name})")
        console.print(f"[cyan][*] Navigating into {folder} in {share_name}[/cyan]")
        # Would implement actual navigation here
        console.print(f"[green][+] Navigation to {folder} would be implemented here[/green]")
    
    def _handle_file_reading(self, share_name):
        """Handle file reading."""
        filename = Prompt.ask(f"Enter filename to read (in {share_name})")
        console.print(f"[cyan][*] Reading {filename} from {share_name}[/cyan]")
        # Would implement actual file reading here
        console.print(f"[green][+] File reading for {filename} would be implemented here[/green]")
    
    def get_discovered_shares(self):
        """Get list of discovered shares."""
        return self.discovered_shares