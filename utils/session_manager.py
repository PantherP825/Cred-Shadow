"""
Session Manager for CRED-SHADOW
Handles login sessions, authentication flow, and session state management.
"""

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from utils.logger import get_logger

console = Console()

class SessionManager:
    """Manages authentication sessions and login flows."""
    
    def __init__(self, target, port=445):
        self.target = target
        self.port = port
        self.logger = get_logger()
        self.current_session = None
        self.session_type = None
        self.credentials = None
        
    def attempt_automation_login_sequence(self, provided_credentials=None, userlist=None, passlist=None):
        """
        Attempt login sequence for automation mode:
        1. Anonymous Login
        2. Authenticated Login (if credentials provided)
        3. Bruteforce Login (if wordlists provided)
        """
        console.print("\n[bold blue]═══ Automation Login Sequence ═══[/bold blue]")
        
        # Step 1: Anonymous Login
        if self._attempt_anonymous_login():
            return True
            
        # Step 2: Authenticated Login (if credentials provided)
        if provided_credentials and self._attempt_authenticated_login(provided_credentials):
            return True
            
        # Step 3: Bruteforce Login (if wordlists provided)
        if userlist and passlist and self._attempt_bruteforce_login(userlist, passlist):
            return True
            
        console.print("[red][-] All login attempts failed[/red]")
        return False
    
    def _attempt_anonymous_login(self):
        """Attempt anonymous login (username=anonymous, password=anonymous)."""
        console.print("[cyan][*] Attempting Anonymous Login (username=anonymous, password=anonymous)[/cyan]")
        
        try:
            from scanner.clean_share_enum import enumerate_shares_clean
            test_creds = [('anonymous', 'anonymous', None)]
            result = enumerate_shares_clean(self.target, test_creds, self.port, self.logger)
            
            if result:
                self.current_session = {'username': 'anonymous', 'password': 'anonymous', 'ntlm_hash': None}
                self.session_type = "Anonymous"
                console.print("[green][+] Anonymous login successful![/green]")
                return True
            else:
                console.print("[yellow][-] Anonymous login failed or no shares accessible[/yellow]")
                return False
                
        except Exception as e:
            console.print(f"[red][-] Anonymous login error: {str(e)}[/red]")
            return False
    
    def _attempt_authenticated_login(self, credentials):
        """Attempt authenticated login with provided credentials."""
        username, password, ntlm_hash = credentials[0] if credentials else (None, None, None)
        
        if not username:
            return False
            
        console.print(f"[cyan][*] Attempting Authenticated Login (username={username})[/cyan]")
        
        try:
            from scanner.clean_share_enum import enumerate_shares_clean
            result = enumerate_shares_clean(self.target, credentials, self.port, self.logger)
            
            if result:
                self.current_session = {'username': username, 'password': password, 'ntlm_hash': ntlm_hash}
                self.session_type = "Authenticated"
                console.print(f"[green][+] Authenticated login successful for {username}![/green]")
                return True
            else:
                console.print(f"[yellow][-] Authenticated login failed for {username}[/yellow]")
                return False
                
        except Exception as e:
            console.print(f"[red][-] Authenticated login error: {str(e)}[/red]")
            return False
    
    def _attempt_bruteforce_login(self, userlist, passlist):
        """Attempt bruteforce login using wordlists."""
        console.print("[cyan][*] Attempting Bruteforce Login[/cyan]")
        
        try:
            # Load wordlists
            with open(userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            with open(passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            console.print(f"[cyan][*] Loaded {len(usernames)} usernames and {len(passwords)} passwords[/cyan]")
            
            # Try combinations (limit to first few for demo)
            max_attempts = min(10, len(usernames) * len(passwords))
            attempts = 0
            
            for username in usernames[:5]:  # Limit usernames for demo
                for password in passwords[:2]:  # Limit passwords for demo
                    attempts += 1
                    console.print(f"[dim][*] Trying {username}:{password} ({attempts}/{max_attempts})[/dim]")
                    
                    try:
                        from scanner.clean_share_enum import enumerate_shares_clean
                        test_creds = [(username, password, None)]
                        result = enumerate_shares_clean(self.target, test_creds, self.port, self.logger)
                        
                        if result:
                            console.print(f"[green][+] Valid credentials found: {username}:{password}[/green]")
                            
                            # Prompt user to create authenticated session
                            create_session = Confirm.ask(
                                f"Valid credentials found ({username}:{password}). Create authenticated session?",
                                default=True
                            )
                            
                            if create_session:
                                self.current_session = {'username': username, 'password': password, 'ntlm_hash': None}
                                self.session_type = "Bruteforce"
                                console.print("[green][+] Authenticated session created with bruteforced credentials![/green]")
                                return True
                            else:
                                console.print("[yellow][*] Session creation declined[/yellow]")
                                return False
                                
                    except Exception as e:
                        self.logger.debug(f"Bruteforce attempt failed: {str(e)}")
                        continue
            
            console.print("[yellow][-] Bruteforce login exhausted without success[/yellow]")
            return False
            
        except FileNotFoundError as e:
            console.print(f"[red][-] Wordlist file not found: {str(e)}[/red]")
            return False
        except Exception as e:
            console.print(f"[red][-] Bruteforce login error: {str(e)}[/red]")
            return False
    
    def get_session_info(self):
        """Get current session information."""
        if not self.current_session:
            return None
            
        return {
            'type': self.session_type,
            'credentials': self.current_session,
            'target': self.target,
            'port': self.port
        }
    
    def display_session_status(self):
        """Display current session status."""
        if self.current_session:
            username = self.current_session.get('username', 'Unknown')
            session_info = f"[bold green]Active Session:[/bold green] {self.session_type} ({username}@{self.target})"
            console.print(Panel(session_info, border_style="green"))
        else:
            console.print(Panel("[bold red]No Active Session[/bold red]", border_style="red"))