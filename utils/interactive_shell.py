"""
Interactive Automation Shell for CRED-SHADOW
Provides dynamic command interface with session state management.
"""

import cmd
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from utils.logger import get_logger

console = Console()

class InteractiveShell(cmd.Cmd):
    """Interactive shell for dynamic SMB operations."""
    
    intro = """
┌─ INTERACTIVE AUTOMATION SHELL ──────────────────────────────────────┐
│                                                                      │
│  Dynamic SMB command interface with session state management.       │
│                                                                      │
│  Available commands:                                                 │
│    status          - Show current session status                    │
│    shares          - Browse available shares                        │
│    access <share>  - Access specific share                         │
│    ls [path]       - List files in current share                   │
│    cd <path>       - Change directory                              │
│    cat <file>      - Read file content                             │
│    download <file> - Download file                                 │
│    session         - Manage session (login/logout)                 │
│    help            - Show this help message                        │
│    exit            - Exit interactive shell                        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
"""
    
    prompt = "cred-shadow> "
    
    def __init__(self, target, session_manager, share_manager):
        super().__init__()
        self.target = target
        self.session_manager = session_manager
        self.share_manager = share_manager
        self.logger = get_logger()
        self.current_share = None
        self.current_path = "/"
        
        # Update prompt with session info
        self._update_prompt()
    
    def _update_prompt(self):
        """Update prompt based on current session and location."""
        session = self.session_manager.get_session_info()
        if session:
            username = session['credentials']['username']
            session_type = session['type'].lower()
            
            if self.current_share:
                self.prompt = f"cred-shadow[{session_type}@{self.target}:{self.current_share}]{self.current_path}> "
            else:
                self.prompt = f"cred-shadow[{session_type}@{self.target}]> "
        else:
            self.prompt = f"cred-shadow[no-session@{self.target}]> "
    
    def do_status(self, args):
        """Show current session status and connection info."""
        console.print("\n[bold blue]═══ Session Status ═══[/bold blue]")
        
        # Session information
        self.session_manager.display_session_status()
        
        # Current location
        if self.current_share:
            location_info = f"[bold cyan]Current Location:[/bold cyan] {self.current_share}{self.current_path}"
            console.print(Panel(location_info, border_style="cyan"))
        else:
            console.print(Panel("[bold yellow]No Share Selected[/bold yellow]", border_style="yellow"))
        
        # Share summary
        shares = self.share_manager.get_discovered_shares()
        if shares:
            accessible = len([s for s in shares if s.get('access') in ['READ', 'READ/WRITE', 'SPECIAL']])
            summary = f"[bold]Discovered Shares:[/bold] {len(shares)} total, {accessible} accessible"
            console.print(Panel(summary, border_style="green"))
    
    def do_shares(self, args):
        """Browse available shares."""
        console.print("\n[bold blue]═══ Available Shares ═══[/bold blue]")
        
        shares = self.share_manager.get_discovered_shares()
        if not shares:
            console.print("[yellow]No shares discovered. Use 'session' to establish connection first.[/yellow]")
            return
        
        table = Table()
        table.add_column("ID", style="cyan", width=4)
        table.add_column("Share Name", style="white bold")
        table.add_column("Access Level", style="green")
        table.add_column("Comment", style="dim")
        
        for i, share in enumerate(shares, 1):
            access = share.get('access', 'UNKNOWN')
            access_color = {
                'read': 'green',
                'read/write': 'bright_green',
                'no access': 'red',
                'special': 'yellow'
            }.get(access.lower(), 'white')
            
            table.add_row(
                str(i),
                share['name'],
                f"[{access_color}]{access}[/{access_color}]",
                share.get('comment', '')
            )
        
        console.print(table)
        console.print("\n[dim]Use 'access <share_name>' to connect to a specific share[/dim]")
    
    def do_access(self, args):
        """Access specific share."""
        if not args:
            console.print("[red]Usage: access <share_name>[/red]")
            return
        
        share_name = args.strip()
        shares = self.share_manager.get_discovered_shares()
        
        # Find the share
        target_share = None
        for share in shares:
            if share['name'].lower() == share_name.lower():
                target_share = share
                break
        
        if not target_share:
            console.print(f"[red]Share '{share_name}' not found[/red]")
            return
        
        access_level = target_share.get('access', 'UNKNOWN')
        
        if access_level == 'NO ACCESS':
            console.print(f"[red]Access denied to {share_name}[/red]")
            return
        
        self.current_share = share_name
        self.current_path = "/"
        self._update_prompt()
        
        console.print(f"[green]Successfully connected to share: {share_name}[/green]")
        
        # Auto-list contents
        self.do_ls("")
    
    def do_ls(self, args):
        """List files in current share."""
        if not self.current_share:
            console.print("[red]No share selected. Use 'access <share>' first.[/red]")
            return
        
        path = args.strip() if args else self.current_path
        console.print(f"[cyan]Listing contents of {self.current_share}:{path}[/cyan]")
        
        # Simulate directory listing
        sample_files = [
            {"name": ".", "type": "dir", "size": "-", "modified": "2024-12-27"},
            {"name": "..", "type": "dir", "size": "-", "modified": "2024-12-27"},
            {"name": "Documents", "type": "dir", "size": "-", "modified": "2024-12-20"},
            {"name": "config.txt", "type": "file", "size": "1.2K", "modified": "2024-12-25"},
            {"name": "Scripts", "type": "dir", "size": "-", "modified": "2024-12-15"},
            {"name": "readme.md", "type": "file", "size": "834B", "modified": "2024-12-22"}
        ]
        
        table = Table()
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Size", style="green")
        table.add_column("Modified", style="dim")
        
        for item in sample_files:
            icon = "📁" if item["type"] == "dir" else "📄"
            table.add_row(f"{icon} {item['name']}", item["type"], item["size"], item["modified"])
        
        console.print(table)
    
    def do_cd(self, args):
        """Change directory."""
        if not self.current_share:
            console.print("[red]No share selected. Use 'access <share>' first.[/red]")
            return
        
        if not args:
            console.print("[red]Usage: cd <directory>[/red]")
            return
        
        new_path = args.strip()
        
        if new_path == "..":
            # Go up one directory
            path_parts = self.current_path.rstrip('/').split('/')
            if len(path_parts) > 1:
                self.current_path = '/'.join(path_parts[:-1]) + '/'
            else:
                self.current_path = "/"
        else:
            # Navigate to new directory
            if new_path.startswith('/'):
                self.current_path = new_path
            else:
                self.current_path = self.current_path.rstrip('/') + '/' + new_path + '/'
        
        self._update_prompt()
        console.print(f"[green]Changed directory to: {self.current_path}[/green]")
    
    def do_cat(self, args):
        """Read file content."""
        if not self.current_share:
            console.print("[red]No share selected. Use 'access <share>' first.[/red]")
            return
        
        if not args:
            console.print("[red]Usage: cat <filename>[/red]")
            return
        
        filename = args.strip()
        file_path = f"{self.current_share}:{self.current_path}{filename}"
        
        console.print(f"[cyan]Reading file: {file_path}[/cyan]")
        
        # Simulate file content
        sample_content = f"""# Sample file content for {filename}
# This would be the actual file content in production

Configuration file for SMB share
Date: 2024-12-27
Author: System Administrator

[settings]
max_connections=100
timeout=30
debug=true

[credentials]
# Note: This is simulated content
admin_user=administrator
backup_path=/backups/daily
"""
        
        console.print(Panel(sample_content, title=f"Content of {filename}", border_style="green"))
    
    def do_download(self, args):
        """Download file."""
        if not self.current_share:
            console.print("[red]No share selected. Use 'access <share>' first.[/red]")
            return
        
        if not args:
            console.print("[red]Usage: download <filename>[/red]")
            return
        
        filename = args.strip()
        console.print(f"[cyan]Downloading {filename} from {self.current_share}[/cyan]")
        console.print(f"[green]File download would be implemented here: {filename}[/green]")
    
    def do_session(self, args):
        """Manage session (login/logout)."""
        if not args:
            console.print("[yellow]Usage: session [login|logout|info][/yellow]")
            console.print("[yellow]Current session:[/yellow]")
            self.do_status("")
            return
        
        action = args.strip().lower()
        
        if action == "info":
            self.do_status("")
        elif action == "logout":
            self.session_manager.current_session = None
            self.session_manager.session_type = None
            self.current_share = None
            self.current_path = "/"
            self._update_prompt()
            console.print("[yellow]Session logged out[/yellow]")
        elif action == "login":
            console.print("[cyan]Login functionality would prompt for new credentials here[/cyan]")
        else:
            console.print(f"[red]Unknown session action: {action}[/red]")
    
    def do_exit(self, args):
        """Exit interactive shell."""
        console.print("[yellow]Exiting interactive shell...[/yellow]")
        return True
    
    def do_quit(self, args):
        """Exit interactive shell."""
        return self.do_exit(args)
    
    def emptyline(self):
        """Handle empty input."""
        pass
    
    def default(self, line):
        """Handle unknown commands."""
        console.print(f"[red]Unknown command: {line}[/red]")
        console.print("[yellow]Type 'help' for available commands[/yellow]")