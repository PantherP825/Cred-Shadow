"""
Banner Module
Displays the CRED-SHADOW banner and disclaimer.
"""

from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)


def print_banner():
    """Print the CRED-SHADOW banner with disclaimer."""

    banner = f"""
{Fore.RED + Style.BRIGHT}
  ▄████▄   ██▀███  ▓█████ ▓█████▄      ██████  ██░ ██  ▄▄▄      ▓█████▄  ▒█████   █     █░
 ▒██▀ ▀█  ▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌   ▒██    ▒ ▓██░ ██▒▒████▄    ▒██▀ ██▌▒██▒  ██▒▓█░ █ ░█░
 ▒▓█    ▄ ▓██ ░▄█ ▒▒███   ░██   █▌   ░ ▓██▄   ▒██▀▀██░▒██  ▀█▄  ░██   █▌▒██░  ██▒▒█░ █ ░█ 
 ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌     ▒   ██▒░▓█ ░██ ░██▄▄▄▄██ ░▓█▄   ▌▒██   ██░░█░ █ ░█ 
 ▒ ▓███▀ ░░██▓ ▒██▒░▒████▒░▒████▓    ▒██████▒▒░▓█▒░██▓ ▓█   ▓██▒░▒████▓ ░ ████▓▒░░░██▒██▓ 
 ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒  
   ░  ▒     ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒    ░ ░▒  ░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░ ░ ▒  ▒   ░ ▒ ▒░   ▒ ░ ░  
 ░          ░░   ░    ░    ░ ░  ░    ░  ░  ░   ░  ░░ ░  ░   ▒    ░ ░  ░ ░ ░ ░ ▒    ░   ░  
 ░ ░         ░        ░  ░   ░             ░   ░  ░  ░      ░  ░   ░        ░ ░      ░    
 ░                         ░                                   ░                          
{Style.RESET_ALL}
{Fore.CYAN + Style.BRIGHT}                         SMB Share Secret Scanner v1.0{Style.RESET_ALL}
{Fore.YELLOW}                    For Ethical Security Testing & Internal Audits{Style.RESET_ALL}

{Fore.RED + Style.BRIGHT}┌─ WARNING: ETHICAL USE ONLY ─────────────────────────────────────────┐
│                                                                      │
│  This tool is designed for AUTHORIZED internal security testing,     │
│  training laboratories, and educational purposes ONLY.               │
│                                                                      │
│  ⚠️  Do NOT use on systems without explicit written permission       │
│  ⚠️  Unauthorized access to computer systems is illegal              │
│  ⚠️  Users are responsible for compliance with local laws            │
│                                                                      │
│  By using this tool, you acknowledge that you have proper           │
│  authorization and will use it responsibly.                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}

{Fore.GREEN}Features:{Style.RESET_ALL}
  • SMB Share Enumeration & Secret Discovery
  • Null Session & Guest Access Testing  
  • Credential Brute Force & Password Spray
  • Intelligent Automation & Manual Exploration
  • Regex & Entropy-based Secret Detection
  • JSON/CSV Export & Comprehensive Logging

{Fore.CYAN}Author: Ankit Pandey | Version: 1.0.0 | Python SMB Security Scanner{Style.RESET_ALL}
"""

    print(banner)


def print_disclaimer():
    """Print additional legal disclaimer."""

    disclaimer = f"""
{Fore.YELLOW + Style.BRIGHT}LEGAL DISCLAIMER:{Style.RESET_ALL}

This software is provided for educational and authorized testing purposes only.
The authors and contributors are not responsible for any misuse or illegal
activities performed with this tool.

Users must ensure they have proper authorization before scanning any systems
that do not belong to them. Unauthorized access to computer systems may
violate local, state, or federal laws.

By continuing to use this tool, you acknowledge that you understand these
terms and will use the software responsibly and legally.

{Fore.GREEN}Press Enter to continue or Ctrl+C to exit...{Style.RESET_ALL}
"""

    print(disclaimer)
    try:
        input()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
        exit(0)


def print_help_banner():
    """Print help information banner."""

    help_text = f"""
{Fore.CYAN + Style.BRIGHT}CRED-SHADOW Usage Examples:{Style.RESET_ALL}

{Fore.GREEN}Basic Authentication:{Style.RESET_ALL}
  cred-shadow --target 192.168.1.100 --username admin --password password123
  cred-shadow --target 192.168.1.100 --null-session
  cred-shadow --target 192.168.1.100 --hash aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76

{Fore.GREEN}Credential Discovery:{Style.RESET_ALL}
  cred-shadow --target 192.168.1.100 --userlist data/userlist.txt --passlist data/passwordlist.txt --bruteforce
  cred-shadow --target 192.168.1.100 --userlist data/userlist.txt --passlist data/passwordlist.txt --spray

{Fore.GREEN}Advanced Options:{Style.RESET_ALL}
  cred-shadow --target 192.168.1.100 --username admin --password pass123 --depth 5 --size-limit 50
  cred-shadow --target 192.168.1.100 --username admin --password pass123 --manual
  cred-shadow --target 192.168.1.100 --username admin --password pass123 --output results.json --csv results.csv

{Fore.GREEN}Common Flags:{Style.RESET_ALL}
  --verbose, -v     Verbose output with debug information
  --quiet, -q       Quiet mode (errors only)
  --threads N       Number of scanning threads (default: 5)
  --timeout N       Connection timeout in seconds (default: 30)
"""

    print(help_text)


def print_success_banner(findings_count, target):
    """Print success banner after scan completion."""

    success_banner = f"""
{Fore.GREEN + Style.BRIGHT}
┌─ SCAN COMPLETED SUCCESSFULLY ──────────────────────────────────────┐
│                                                                    │
│  Target: {target:<50} │
│  Findings: {findings_count:<3} potential secrets discovered                      │
│                                                                    │
│  Results have been saved to the output directory.                 │
│  Check the log files for detailed information.                    │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}
"""

    print(success_banner)


def print_error_banner(error_message):
    """Print error banner."""

    error_banner = f"""
{Fore.RED + Style.BRIGHT}
┌─ ERROR ─────────────────────────────────────────────────────────────┐
│                                                                     │
│  {error_message:<65} │
│                                                                     │
│  Check the log files for more details or run with --verbose        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}
"""

    print(error_banner)


def print_manual_mode_banner():
    """Print banner for manual exploration mode."""

    manual_banner = f"""
{Fore.MAGENTA + Style.BRIGHT}
┌─ MANUAL EXPLORATION MODE ──────────────────────────────────────────┐
│                                                                    │
│  Interactive SMB share navigation activated.                      │
│                                                                    │
│  Commands:                                                         │
│    ls [path]      - List directory contents                       │
│    cd <path>      - Change directory                              │
│    cat <file>     - Display file contents                         │
│    download <file> - Download file to local system               │
│    shares         - List available shares                         │
│    find <pattern> - Search for files matching pattern            │
│    exit, quit     - Exit manual mode                             │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}
"""

    print(manual_banner)