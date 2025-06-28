"""
CRED-SHADOW: SMB Share Secret Scanner
A tool for ethical security testing, lab-based auditing, and internal system hardening.
Author: Ankit Pandey

WARNING: This tool is intended for authorized internal use, training labs, and educational purposes only.
Do not use on systems without explicit permission.
"""

import argparse
import sys
import os
import platform
from colorama import Fore, Style
from utils.banner import print_banner
from utils.logger import init_logger, get_logger
from utils.config import Config
from utils.hash_utils import parse_ntlm_hash, validate_hash_format
from utils.permission_analyzer import analyze_share_permissions
from utils.file_utils import save_results_to_file, save_results_to_csv
from scanner.clean_share_enum import enumerate_shares_clean
from scanner.secret_finder import find_secrets
from scanner.brute_force import smb_brute_force
from scanner.brute_force import password_spray
from scanner.validator import validate_credentials
from scanner.cidr_scanner import scan_cidr_range
from scanner.yara_engine import YARAEngine
from plugins import get_plugin_manager
from manual_mode.navigator import manual_navigator


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="CRED-SHADOW: SMB Share Secret Scanner for Ethical Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target options
    parser.add_argument("--target", help="Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)", required=True)
    parser.add_argument("--port", type=int, default=445, help="SMB port (default: 445, alternative: 139)")
    parser.add_argument("--cidr", action="store_true", help="Enable CIDR scanning mode for subnet enumeration")

    # Authentication options
    parser.add_argument("--username", "-u", help="Username for authentication")
    parser.add_argument("--password", "-p", help="Password for authentication")
    parser.add_argument("--hash", help="NTLM hash for authentication (format: LM:NT)")
    parser.add_argument("--null-session", action="store_true", help="Attempt null session (guest access)")
    parser.add_argument("--anonymous", action="store_true", help="Attempt anonymous login (no credentials)")
    parser.add_argument("--guest", action="store_true", help="Attempt guest account access")
    parser.add_argument("--try-all", action="store_true", help="Try all authentication methods (anonymous, null session, guest)")
    parser.add_argument("--prompt", action="store_true", help="Interactive mode for credential input and share selection")

    # Credential discovery options
    parser.add_argument("--userlist", help="Path to username wordlist file (required for brute-force)")
    parser.add_argument("--passlist", help="Path to password wordlist file (required for brute-force)")
    parser.add_argument("--bruteforce", action="store_true", help="Run SMB brute-force attack (requires --userlist and --passlist)")

    parser.add_argument("--delay", type=int, default=0, help="Delay in seconds between password attempts (default: 0 for no delay)")

    # Scanning options
    parser.add_argument("--depth", type=int, default=3, help="Directory traversal depth (default: 3)")
    parser.add_argument("--size-limit", type=int, default=20, help="Max file size in MB to scan (default: 20)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for scanning (default: 5)")
    parser.add_argument("--scan-timeout", type=int, default=5, help="Timeout for network scanning (default: 5)")
    parser.add_argument("--max-hosts", type=int, default=1000, help="Maximum hosts to scan in CIDR mode (default: 1000)")

    # YARA scanning options
    parser.add_argument("--yara-rules", nargs='+', help="YARA rule files for advanced pattern detection")
    parser.add_argument("--yara-dir", help="Directory containing YARA rule files")
    parser.add_argument("--enable-yara", action="store_true", help="Enable built-in YARA rules for secret detection")

    # Plugin system options
    parser.add_argument("--plugins", help="Directory containing custom detection plugins")
    parser.add_argument("--enable-plugins", action="store_true", help="Enable plugin system for custom detection rules")
    
    # Permission analysis options
    parser.add_argument("--analyze-permissions", action="store_true", help="Enable advanced share permission analysis and visualization")
    parser.add_argument("--permission-report", help="Export detailed permission analysis report to specified file")
    parser.add_argument("--test-upload", action="store_true", help="Test file upload permissions on accessible shares")
    parser.add_argument("--upload-report", help="Export upload test results to specified file")

    # Operation modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--manual', action='store_true', help='Manual exploration mode - interactive shell for SMB shares')
    mode_group.add_argument('--interactive', action='store_true', help='Interactive scanning mode - review each finding interactively')
    mode_group.add_argument("--auto", action="store_true", help="Automatic scanning mode - scan and report all findings (default)")

    # Output options
    parser.add_argument("--output", "-o", help="Output file path (JSON format)")
    parser.add_argument("--csv", help="Export results to CSV file")
    parser.add_argument("--webhook-url", help="Webhook URL for result export")
    parser.add_argument("--webhook-api-key", help="API key for webhook authentication")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (minimal output)")

    # Help examples
    parser.epilog = """
WARNING: This tool is intended for authorized internal use, training labs, and educational purposes only.
Do not use on systems without explicit permission.

Examples:
  %(prog)s --target 192.168.1.100 --username admin --password pass123
  %(prog)s --target 192.168.1.100 --anonymous
  %(prog)s --target 192.168.1.100 --null-session
  %(prog)s --target 192.168.1.100 --try-all
  %(prog)s --target 192.168.1.100 --prompt
  %(prog)s --target 192.168.1.100 --userlist usernames.txt --passlist passwords.txt --bruteforce

  %(prog)s --target 192.168.1.100 --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  %(prog)s --target 192.168.1.0/24 --cidr --username admin --password pass123
  %(prog)s --target 192.168.1.100 --username admin --password pass123 --manual
  %(prog)s --target 192.168.1.100 --username admin --password pass123 --analyze-permissions
  %(prog)s --target 192.168.1.100 --try-all --analyze-permissions --permission-report permissions.json
        """ % {'prog': parser.prog}
    
    return parser.parse_args()


def validate_args(args):
    """Validate command line arguments."""
    if args.bruteforce:
        if not args.userlist or not args.passlist:
            print("[-] Error: --userlist and --passlist are required for brute-force attacks")
            print("    Example: --userlist usernames.txt --passlist passwords.txt --bruteforce")
            return False
        
        if not os.path.exists(args.userlist):
            print(f"[-] Error: Username list file not found: {args.userlist}")
            print("    Create a file with one username per line")
            return False
        
        if not os.path.exists(args.passlist):
            print(f"[-] Error: Password list file not found: {args.passlist}")
            print("    Create a file with one password per line")
            return False
    


    return True


def collect_credentials(args, logger):
    """Collect credentials from various sources."""
    creds = []
    
    # Add explicit credentials
    if args.username and args.password:
        creds.append((args.username, args.password, None))
        logger.info(f"[+] Using provided credentials: {args.username}")
    
    # Add NTLM hash
    if args.hash:
        ntlm_hash = parse_ntlm_hash(args.hash)
        if ntlm_hash:
            username = args.username if args.username else ""
            creds.append((username, "", ntlm_hash))
            logger.info(f"[+] Using NTLM hash authentication for user: {username or 'anonymous'}")
        else:
            logger.error("[-] Failed to parse NTLM hash")
            return []

    # Handle null session with interactive prompting
    if args.null_session and not any([args.anonymous, args.guest, args.try_all, args.username]):
        from utils.credential_prompt import smart_credential_prompt
        interactive_creds = smart_credential_prompt(args, logger)
        creds.extend(interactive_creds)
        return creds
    
    # Add anonymous login
    if args.anonymous or args.try_all:
        creds.append(("anonymous", "", None))
        logger.info("[*] Attempting anonymous login...")
    
    # Add null session
    if args.null_session or args.try_all:
        creds.append(("", "", None))
        logger.info("[*] Attempting null session access...")
    
    # Add guest account
    if args.guest or args.try_all:
        creds.append(("guest", "", None))
        creds.append(("guest", "guest", None))
        logger.info("[*] Attempting guest account access...")

    # Perform brute-force attack
    if args.bruteforce:
        logger.info("[*] Starting SMB brute-force attack...")
        logger.info(f"[*] Using username wordlist: {args.userlist}")
        logger.info(f"[*] Using password wordlist: {args.passlist}")
        brute_creds = smb_brute_force(args.target, args.userlist, args.passlist, args.port, logger, delay=args.delay)
        creds.extend(brute_creds)
        
        # Offer automated file discovery after successful brute force
        if brute_creds and not args.manual:
            logger.info("[*] Valid credentials found! Starting automated file discovery...")
            
            try:
                from scanner.file_discovery import automated_file_discovery, prompt_manual_exploration
                discovery_results = automated_file_discovery(args.target, brute_creds, args.port, max_depth=2, logger=logger)
                
                if discovery_results['shares']:
                    logger.info(f"[+] Discovered files across {len(discovery_results['shares'])} accessible shares")
                    
                    # Ask user if they want manual exploration
                    try:
                        response = input(f"\n{Fore.CYAN}Start manual file exploration? (y/n): {Style.RESET_ALL}").strip().lower()
                        if response == 'y':
                            prompt_manual_exploration(discovery_results, args.target, args.port, logger)
                    except KeyboardInterrupt:
                        logger.info("\n[*] Continuing with normal operation...")
                        
            except Exception as e:
                logger.debug(f"Error in post-brute force discovery: {str(e)}")
    

    
    return creds


def main():
    """Main function."""
    logger = None
    args = None

    try:
        # Print banner
        print_banner()

        # Parse arguments
        args = parse_arguments()

        # Validate arguments
        if not validate_args(args):
            sys.exit(1)

        # Initialize logger
        logger = init_logger(verbose=args.verbose, quiet=args.quiet)

        # Initialize configuration
        config = Config(args)

        # Collect credentials
        logger.info(f"[*] Target: {args.target}:{args.port}")
        creds = collect_credentials(args, logger)

        if not creds:
            logger.error("[-] No valid credentials found or provided")
            sys.exit(1)

        logger.info(f"[+] Found {len(creds)} credential set(s)")

        # Handle different operation modes based on user choice
        if args.manual:
            # Manual exploration mode - user explicitly requested it
            logger.info("[*] Manual exploration mode requested")
            logger.info("[*] Using provided credentials for manual exploration...")
            
            # Use all provided credentials for manual mode (validation happens during actual operations)
            valid_creds = creds
            logger.info(f"[+] Loaded {len(valid_creds)} credential set(s) for manual exploration")
            
            try:
                logger.info("[*] Starting manual exploration mode...")
                logger.info(f"[*] Available credentials: {len(valid_creds)}")
                
                # Enumerate shares first before manual mode
                print("Enumerating shares on {}...".format(args.target))
                shares = enumerate_shares_clean(args.target, valid_creds, args.port, logger)
                
                if shares:
                    display_discovered_shares(shares, logger)
                    logger.info(f"[+] Found {len(shares)} shares for manual exploration")
                else:
                    logger.warning("No shares enumerated on {}".format(args.target))
                    print("Manual mode will still allow manual connection attempts")
                
                manual_navigator(args.target, valid_creds, args.port, shares if shares else [])
                return
            except Exception as e:
                logger.error(f"[-] Manual mode error: {str(e)}")
                sys.exit(1)
        
        else:
            # Automatic scanning mode
            logger.info("[*] Starting automatic scanning mode...")
            
            # Enumerate shares
            logger.info("[*] Enumerating SMB shares...")
            shares = enumerate_shares_clean(args.target, creds, args.port, logger)
            
            if not shares:
                logger.warning("[-] No accessible shares found")
                return
            
            logger.info(f"[+] Found {len(shares)} accessible share(s):")
            for share in shares:
                logger.info(f"    • {share}")
            
            # Handle interactive mode with automated file discovery
            if args.interactive:
                logger.info("[*] Starting interactive mode with automated file discovery...")
                
                # Perform automated file discovery
                from scanner.file_discovery import automated_file_discovery, prompt_manual_exploration
                discovery_results = automated_file_discovery(args.target, creds, args.port, max_depth=3, logger=logger)
                
                if discovery_results['shares']:
                    # Offer manual exploration options
                    try:
                        prompt_manual_exploration(discovery_results, args.target, args.port, logger)
                    except KeyboardInterrupt:
                        logger.info("[*] Interactive mode cancelled by user")
                else:
                    logger.info("[*] No accessible shares found for interactive exploration")
                return
            
            # Advanced permission analysis
            if args.analyze_permissions:
                logger.info("[*] Starting advanced permission analysis...")
                permission_analyzer = analyze_share_permissions(
                    args.target, shares, creds, logger
                )
                permission_analyzer.generate_detailed_report(args.target)
                
                # Export permission report if requested
                if args.permission_report:
                    permission_analyzer.export_to_json(args.permission_report)
                return
            
            # Upload permission testing
            if args.test_upload:
                logger.info("[*] Starting upload permission testing...")
                from scanner.upload_tester import test_upload_permissions
                upload_results = test_upload_permissions(args.target, creds, args.port, logger)
                if args.upload_report:
                    import json
                    with open(args.upload_report, 'w') as f:
                        json.dump(upload_results, f, indent=2, default=str)
                    logger.info(f"[+] Upload test results exported to: {args.upload_report}")
                return
            
            # Standard auto mode - discover ALL files and directories across ALL authentication methods
            logger.info("[*] Starting comprehensive file discovery across all authentication methods...")
            from scanner.file_discovery import automated_file_discovery, display_comprehensive_discovery_results
            
            # Perform comprehensive file discovery across all session types
            discovery_results = automated_file_discovery(args.target, creds, args.port, max_depth=3, logger=logger)
            
            # Display comprehensive results showing files found in each share with authentication context
            if discovery_results and discovery_results.get('shares'):
                display_comprehensive_discovery_results(discovery_results, logger)
            else:
                logger.warning("[-] No files discovered across any authentication methods")
            
            if discovery_results['shares']:
                logger.info(f"[+] Discovered files across {len(discovery_results['shares'])} accessible shares")
                logger.info(f"[+] Total files found: {discovery_results['total_files']}")
                logger.info(f"[+] Total directories found: {discovery_results['total_directories']}")
                
                # Export results if requested
                if hasattr(args, 'output') and args.output:
                    export_results_json(discovery_results, args.output, logger)
                if hasattr(args, 'csv') and args.csv:
                    # Convert discovery results to findings format for CSV export
                    findings = []
                    for share_name, share_info in discovery_results['shares'].items():
                        for file_info in share_info['files']:
                            findings.append({
                                'share': share_name,
                                'file_path': file_info['path'],
                                'file_name': file_info['name'],
                                'file_size': file_info.get('size', 0),
                                'is_directory': file_info.get('is_directory', False),
                                'modified': file_info.get('modified', 'Unknown'),
                                'auth_type': share_info['auth_type']
                            })
                    export_results_csv(findings, args.csv, logger)
            else:
                logger.info("[*] No accessible files found")
            
            # Offer interactive shell access after auto scan
            try:
                from rich.console import Console
                from rich.prompt import Confirm
                console = Console()
                console.print("\n[bold cyan]Automatic scan completed![/bold cyan]")
                shell_access = Confirm.ask("Would you like interactive shell access to explore the shares manually?", default=False)
                if shell_access:
                    selected_shares = interactive_share_selection(shares, logger, args, post_scan=True)
                    if selected_shares:
                        console.print(f"[green]Starting manual exploration for selected shares...[/green]")
                        manual_navigator(args.target, creds, args.port, selected_shares)
            except KeyboardInterrupt:
                logger.info("[*] Continuing without shell access...")

    except KeyboardInterrupt:
        if logger:
            logger.info("\n[*] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        if logger:
            logger.error(f"[-] Fatal error: {str(e)}")
        sys.exit(1)


def export_results_json(findings, filename, logger):
    """Save findings to JSON file."""
    try:
        import json
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        logger.info(f"[+] Results saved to {filename}")
    except Exception as e:
        logger.error(f"[-] Error saving results: {str(e)}")


def interactive_share_selection(shares, logger, args, post_scan=False):
    """Interactive share selection with enhanced options."""
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    if not shares:
        console.print("[red]No shares available for selection[/red]")
        return []
    
    # Display shares in a nice table
    title = "Post-Scan Share Selection" if post_scan else "Available SMB Shares"
    console.print(f"\n[bold cyan]{title}:[/bold cyan]")
    
    table = Table(title="SMB Shares")
    table.add_column("Index", style="cyan", no_wrap=True, width=8)
    table.add_column("Share Name", style="magenta", width=20)
    table.add_column("Type", style="green", width=15)
    table.add_column("Description", style="white", width=30)
    
    for i, share in enumerate(shares, 1):
        # Handle both string share names and share dictionary objects
        if isinstance(share, dict):
            share_name = str(share.get('name', f'Share_{i}'))
            share_access = str(share.get('access', 'UNKNOWN'))
            share_comment = str(share.get('comment', ''))
        else:
            share_name = str(share)
            share_access = 'UNKNOWN'
            share_comment = ''
        
        if share_name.upper() == 'IPC$':
            share_type, desc = "Administrative", "Inter-process communication"
        elif share_name.upper() in ['ADMIN$', 'C$']:
            share_type, desc = "Administrative", "Administrative access"
        else:
            share_type, desc = "File Share", "User accessible file share"
        
        # Add access level to description if available
        if share_access != 'UNKNOWN':
            desc = f"{desc} ({share_access})"
        
        table.add_row(str(i), share_name, share_type, desc)
    
    console.print(table)
    
    # Enhanced selection options
    try:
        if post_scan:
            choices = ["all", "custom", "shell", "quit"]
            help_text = "\n[cyan]Options:[/cyan] all=select all shares, custom=choose specific shares, shell=interactive shell mode, quit=exit"
        else:
            choices = ["all", "custom", "shell", "scan", "quit"]
            help_text = "\n[cyan]Options:[/cyan] all=select all shares, custom=choose specific, shell=manual exploration, scan=automatic scan, quit=exit"
        
        console.print(help_text)
        choice = Prompt.ask(
            "\nWhat would you like to do?",
            choices=choices,
            default="all" if args.auto else "shell"
        )
        
        if choice == "quit":
            return []
        elif choice == "shell":
            # Direct shell access
            console.print("[green]Starting interactive shell for share exploration...[/green]")
            manual_navigator(args.target, collect_credentials(args, logger), args.port, shares)
            return []
        elif choice == "scan":
            # Automatic scan mode
            return shares
        elif choice == "all":
            return shares
        else:  # custom
            return custom_share_selection(shares, console)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Selection cancelled[/yellow]")
        return []


def custom_share_selection(shares, console):
    """Handle custom share selection."""
    from rich.prompt import Prompt
    
    console.print("\n[bold yellow]Custom Share Selection:[/bold yellow]")
    console.print("Enter share numbers (comma-separated, e.g., 1,3) or 'all' for all shares:")
    console.print("You can also type 'list' to see the shares again, or 'quit' to exit")
    
    while True:
        try:
            selection = Prompt.ask("Your choice")
            
            if selection.lower() == "quit":
                return []
            elif selection.lower() == "all":
                return shares
            elif selection.lower() == "list":
                # Re-display the shares
                for i, share in enumerate(shares, 1):
                    # Handle both string and dict share objects
                    if isinstance(share, dict):
                        share_name = str(share.get('name', f'Share_{i}'))
                        share_access = str(share.get('access', ''))
                    else:
                        share_name = str(share)
                        share_access = ''
                    
                    share_type = "Administrative" if share_name.upper() in ['IPC$', 'ADMIN$', 'C$'] else "File Share"
                    access_info = f" - {share_access}" if share_access else ""
                    console.print(f"  {i}. [magenta]{share_name}[/magenta] ({share_type}{access_info})")
                continue
            
            # Parse numeric selection
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected = [shares[i] for i in indices if 0 <= i < len(shares)]
            
            if selected:
                # Create display names for selected shares
                selected_names = []
                for share in selected:
                    if isinstance(share, dict):
                        selected_names.append(str(share.get('name', 'Unknown')))
                    else:
                        selected_names.append(str(share))
                
                console.print(f"[green]Selected shares: {', '.join(selected_names)}[/green]")
                confirm = Prompt.ask("Proceed with these shares?", choices=["yes", "no"], default="yes")
                if confirm == "yes":
                    return selected
                # If no, continue the loop for new selection
            else:
                console.print("[red]Invalid selection. Please try again.[/red]")
                
        except (ValueError, IndexError):
            console.print("[red]Invalid input format. Use numbers separated by commas (e.g., 1,3,5)[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Selection cancelled[/yellow]")
            return []


def display_discovered_shares(shares, logger):
    """Display discovered shares with comprehensive information."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    if not shares:
        console.print("[red]No shares discovered[/red]")
        return
    
    # Create comprehensive table
    table = Table(title=f"Discovered {len(shares)} SMB Shares")
    table.add_column("Share Name", style="cyan bold")
    table.add_column("Type", style="magenta")
    table.add_column("Access Level", style="green")
    table.add_column("Session Found", style="yellow")
    table.add_column("Comment", style="dim")
    
    for share in shares:
        share_name = share.get('name', 'Unknown')
        share_type = {0: "DISK", 1: "PRINT", 3: "IPC"}.get(share.get('type', 0), "OTHER")
        access = share.get('access', 'UNKNOWN')
        session_type = share.get('session_type', 'Unknown')
        comment = share.get('comment', '')
        
        # Color access level
        access_color = {
            'read': 'green',
            'read/write': 'bright_green',
            'no access': 'red',
            'special': 'yellow',
            'unknown': 'dim'
        }.get(access.lower(), 'white')
        
        table.add_row(
            share_name,
            share_type,
            f"[{access_color}]{access}[/{access_color}]",
            session_type,
            comment
        )
    
    console.print(table)
    
    # Summary
    accessible = [s for s in shares if s.get('access', '').upper() in ['READ', 'READ/WRITE', 'SPECIAL']]
    console.print(f"\n[bold]Summary:[/bold] {len(accessible)} accessible, {len(shares) - len(accessible)} restricted shares")


def prompt_share_selection(shares, logger):
    """Legacy function for backward compatibility."""
    return interactive_share_selection(shares, logger, type('Args', (), {'auto': True}), post_scan=True)


def export_results_csv(findings, filename, logger):
    """Save findings to CSV file."""
    try:
        import csv
        with open(filename, 'w', newline='') as f:
            if findings:
                writer = csv.DictWriter(f, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)
        logger.info(f"[+] Results saved to {filename}")
    except Exception as e:
        logger.error(f"[-] Error saving CSV: {str(e)}")


if __name__ == "__main__":
    main()