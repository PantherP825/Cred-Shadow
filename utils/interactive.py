"""
Interactive Mode Module
Provides interactive interfaces for credential input, share selection, and scanning control.
"""

import os
import sys
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text


# Initialize colorama
init(autoreset=True)
console = Console()


def display_welcome_interactive():
    """Display welcome message for interactive mode."""
    welcome_text = Text("CRED-SHADOW Interactive Mode", style="bold cyan")
    subtitle = Text("Smart SMB Share Discovery & Analysis", style="italic")
    
    panel = Panel.fit(
        f"{welcome_text}\n{subtitle}",
        border_style="cyan",
        padding=(1, 2)
    )
    
    console.print(panel)
    console.print()


def prompt_target_selection():
    """
    Interactive target selection.
    
    Returns:
        str: Target IP, hostname, or CIDR range
    """
    console.print("[bold yellow]Target Selection[/bold yellow]")
    console.print("Enter the target for SMB scanning:")
    console.print("• Single IP: 192.168.1.100")
    console.print("• Hostname: server.domain.com")
    console.print("• CIDR range: 192.168.1.0/24")
    console.print()
    
    target = Prompt.ask("[green]Target", default="192.168.1.100")
    return target


def prompt_authentication_method():
    """
    Interactive authentication method selection.
    
    Returns:
        dict: Authentication configuration
    """
    console.print("\n[bold yellow]Authentication Method[/bold yellow]")
    
    auth_table = Table(show_header=True, header_style="bold blue")
    auth_table.add_column("Option", style="dim", width=8)
    auth_table.add_column("Method", min_width=20)
    auth_table.add_column("Description")
    
    auth_table.add_row("1", "Anonymous", "No credentials required")
    auth_table.add_row("2", "Null Session", "Empty username/password")
    auth_table.add_row("3", "Guest Account", "Standard guest access")
    auth_table.add_row("4", "Username/Password", "Standard authentication")
    auth_table.add_row("5", "NTLM Hash", "Pass-the-hash authentication")
    auth_table.add_row("6", "Try All", "Attempt all methods automatically")
    auth_table.add_row("7", "Custom", "Specify multiple credentials")
    
    console.print(auth_table)
    console.print()
    
    choice = Prompt.ask("[green]Select authentication method", 
                       choices=["1", "2", "3", "4", "5", "6", "7"], 
                       default="6")
    
    auth_config = {}
    
    if choice == "1":
        auth_config = {"method": "anonymous", "username": "anonymous", "password": ""}
    elif choice == "2":
        auth_config = {"method": "null_session", "username": "", "password": ""}
    elif choice == "3":
        auth_config = {"method": "guest", "username": "guest", "password": ""}
    elif choice == "4":
        username = Prompt.ask("[green]Username")
        password = Prompt.ask("[green]Password", password=True)
        auth_config = {"method": "userpass", "username": username, "password": password}
    elif choice == "5":
        username = Prompt.ask("[green]Username")
        hash_value = Prompt.ask("[green]NTLM Hash (LM:NT format)")
        auth_config = {"method": "ntlm_hash", "username": username, "hash": hash_value}
    elif choice == "6":
        auth_config = {"method": "try_all"}
    elif choice == "7":
        auth_config = {"method": "custom"}
        auth_config["credentials"] = prompt_multiple_credentials()
    
    return auth_config


def prompt_multiple_credentials():
    """
    Prompt for multiple credential sets.
    
    Returns:
        list: List of credential dictionaries
    """
    credentials = []
    console.print("\n[bold yellow]Multiple Credentials Setup[/bold yellow]")
    console.print("Enter multiple credential sets (press Enter on empty username to finish)")
    
    while True:
        console.print(f"\n[bold cyan]Credential Set #{len(credentials) + 1}[/bold cyan]")
        username = Prompt.ask("[green]Username (or press Enter to finish)", default="")
        
        if not username:
            break
        
        auth_type = Prompt.ask("[green]Authentication type", 
                              choices=["password", "hash"], 
                              default="password")
        
        if auth_type == "password":
            password = Prompt.ask("[green]Password", password=True)
            credentials.append({"username": username, "password": password})
        else:
            hash_value = Prompt.ask("[green]NTLM Hash (LM:NT format)")
            credentials.append({"username": username, "hash": hash_value})
    
    return credentials


def prompt_scanning_options():
    """
    Interactive scanning options configuration.
    
    Returns:
        dict: Scanning configuration
    """
    console.print("\n[bold yellow]Scanning Options[/bold yellow]")
    
    config = {}
    
    # Discovery method
    discovery_method = Prompt.ask(
        "[green]Discovery method",
        choices=["auto", "smbclient", "impacket"],
        default="auto"
    )
    config["discovery_method"] = discovery_method
    
    # Scanning depth
    depth = Prompt.ask("[green]Directory scanning depth", default="3")
    try:
        config["depth"] = int(depth)
    except ValueError:
        config["depth"] = 3
    
    # File size limit
    size_limit = Prompt.ask("[green]Max file size to scan (MB)", default="20")
    try:
        config["size_limit"] = int(size_limit)
    except ValueError:
        config["size_limit"] = 20
    
    # Thread count
    threads = Prompt.ask("[green]Number of scanning threads", default="5")
    try:
        config["threads"] = int(threads)
    except ValueError:
        config["threads"] = 5
    
    # Advanced features
    config["enable_yara"] = Confirm.ask("[green]Enable YARA rules for pattern detection?", default=False)
    config["enable_plugins"] = Confirm.ask("[green]Enable custom detection plugins?", default=False)
    
    return config


def display_share_selection_table(shares):
    """
    Display shares in a formatted table for selection.
    
    Args:
        shares (list): List of discovered shares
    
    Returns:
        Table: Rich table object
    """
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Share Name", min_width=15)
    table.add_column("Type", width=10)
    table.add_column("Access", width=8)
    table.add_column("Comment", style="dim")
    
    for i, share in enumerate(shares, 1):
        access_status = "✓" if share.get('accessible') else "✗" if share.get('accessible') is False else "?"
        access_color = "green" if share.get('accessible') else "red" if share.get('accessible') is False else "yellow"
        
        table.add_row(
            str(i),
            share['name'],
            share.get('type', 'Unknown'),
            f"[{access_color}]{access_status}[/{access_color}]",
            share.get('comment', '')
        )
    
    return table


def prompt_share_selection(shares):
    """
    Interactive share selection interface.
    
    Args:
        shares (list): List of discovered shares
    
    Returns:
        list: Selected shares
    """
    if not shares:
        console.print("[red]No shares discovered.[/red]")
        return []
    
    console.print("\n[bold yellow]Share Selection[/bold yellow]")
    
    # Display shares table
    table = display_share_selection_table(shares)
    console.print(table)
    
    console.print("\n[bold cyan]Selection Options:[/bold cyan]")
    console.print("• Enter share numbers: 1,3,5")
    console.print("• Enter 'all' for all shares")
    console.print("• Enter 'accessible' for accessible shares only")
    console.print("• Press Enter for all shares")
    
    selection = Prompt.ask("[green]Select shares", default="all")
    
    if selection.lower() in ["all", ""]:
        return shares
    elif selection.lower() == "accessible":
        return [share for share in shares if share.get('accessible')]
    else:
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected_shares = []
            for i in indices:
                if 0 <= i < len(shares):
                    selected_shares.append(shares[i])
            return selected_shares
        except ValueError:
            console.print("[red]Invalid selection. Using all shares.[/red]")
            return shares


def display_scan_progress(current, total, share_name=""):
    """
    Display scanning progress.
    
    Args:
        current (int): Current progress
        total (int): Total items
        share_name (str): Current share being scanned
    """
    percentage = (current / total) * 100 if total > 0 else 0
    progress_bar = "█" * int(percentage // 5) + "░" * (20 - int(percentage // 5))
    
    status = f"[{progress_bar}] {percentage:.1f}% ({current}/{total})"
    if share_name:
        status += f" - {share_name}"
    
    # Use carriage return to overwrite previous line
    print(f"\r{Fore.CYAN}Scanning: {status}{Style.RESET_ALL}", end="", flush=True)


def display_scan_results_summary(results):
    """
    Display comprehensive scan results summary.
    
    Args:
        results (dict): Scan results
    """
    console.print("\n")
    console.print("[bold green]Scan Results Summary[/bold green]")
    
    # Create summary table
    summary_table = Table(show_header=True, header_style="bold blue")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")
    
    summary_table.add_row("Target", results.get('target', 'Unknown'))
    summary_table.add_row("Shares Discovered", str(results.get('total_shares', 0)))
    summary_table.add_row("Accessible Shares", str(results.get('accessible_shares', 0)))
    summary_table.add_row("Files Scanned", str(results.get('files_scanned', 0)))
    summary_table.add_row("Secrets Found", str(results.get('secrets_found', 0)))
    summary_table.add_row("High Risk Findings", str(results.get('high_risk_findings', 0)))
    
    console.print(summary_table)
    
    # Display findings if any
    if results.get('findings'):
        console.print("\n[bold yellow]Key Findings:[/bold yellow]")
        for i, finding in enumerate(results['findings'][:5], 1):  # Show top 5
            risk_color = "red" if finding.get('risk', '').lower() == 'high' else "yellow"
            console.print(f"{i}. [{risk_color}]{finding.get('type', 'Unknown')}[/{risk_color}] - {finding.get('file', 'Unknown file')}")


def prompt_export_options():
    """
    Interactive export options configuration.
    
    Returns:
        dict: Export configuration
    """
    console.print("\n[bold yellow]Export Options[/bold yellow]")
    
    config = {}
    
    # JSON export
    if Confirm.ask("[green]Export results to JSON file?", default=True):
        json_file = Prompt.ask("[green]JSON filename", default="cred_shadow_results.json")
        config["json_file"] = json_file
    
    # CSV export
    if Confirm.ask("[green]Export results to CSV file?", default=False):
        csv_file = Prompt.ask("[green]CSV filename", default="cred_shadow_results.csv")
        config["csv_file"] = csv_file
    
    # Webhook export
    if Confirm.ask("[green]Send results to webhook?", default=False):
        webhook_url = Prompt.ask("[green]Webhook URL")
        webhook_type = Prompt.ask("[green]Webhook type", 
                                 choices=["generic", "slack", "siem"], 
                                 default="generic")
        config["webhook"] = {
            "url": webhook_url,
            "type": webhook_type
        }
        
        if webhook_type != "generic":
            api_key = Prompt.ask("[green]API key (optional)", default="")
            if api_key:
                config["webhook"]["api_key"] = api_key
    
    return config


def run_interactive_mode():
    """
    Main interactive mode workflow.
    
    Returns:
        dict: Complete configuration for scanning
    """
    display_welcome_interactive()
    
    # Collect all configuration interactively
    config = {}
    
    config["target"] = prompt_target_selection()
    config["authentication"] = prompt_authentication_method()
    config["scanning"] = prompt_scanning_options()
    config["export"] = prompt_export_options()
    
    # Confirmation
    console.print("\n[bold yellow]Configuration Summary:[/bold yellow]")
    console.print(f"Target: {config['target']}")
    console.print(f"Authentication: {config['authentication']['method']}")
    console.print(f"Discovery: {config['scanning']['discovery_method']}")
    console.print(f"Depth: {config['scanning']['depth']}")
    console.print(f"YARA: {'Enabled' if config['scanning']['enable_yara'] else 'Disabled'}")
    console.print(f"Plugins: {'Enabled' if config['scanning']['enable_plugins'] else 'Disabled'}")
    
    if Confirm.ask("\n[green]Proceed with scan?", default=True):
        return config
    else:
        console.print("[yellow]Scan cancelled.[/yellow]")
        sys.exit(0)