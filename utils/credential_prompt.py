"""
Credential Prompting Module
Provides interactive credential prompting and smart authentication handling.
"""

import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def prompt_authentication_choice():
    """
    Prompt user to choose authentication method when null session is requested.
    
    Returns:
        str: Selected authentication method
    """
    print(f"\n{Fore.CYAN}┌─ AUTHENTICATION METHOD SELECTION ─────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│ Choose how to authenticate to the SMB service         │{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Available authentication methods:{Style.RESET_ALL}")
    print("1. Anonymous login (username: anonymous, no password)")
    print("2. Null session (empty username and password)")
    print("3. Guest account (username: guest, no password)")
    print("4. Guest account with password (username: guest, password: guest)")
    print("5. Try all methods automatically")
    print("6. Provide custom credentials")
    
    while True:
        try:
            choice = input(f"\n{Fore.GREEN}Select option (1-6): {Style.RESET_ALL}").strip()
            
            if choice in ['1', '2', '3', '4', '5', '6']:
                return choice
            else:
                print(f"{Fore.RED}Invalid choice. Please select 1-6.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
            sys.exit(0)
        except EOFError:
            print(f"\n{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
            sys.exit(0)


def prompt_custom_credentials():
    """
    Prompt for custom username and password.
    
    Returns:
        tuple: (username, password)
    """
    print(f"\n{Fore.CYAN}┌─ CUSTOM CREDENTIAL INPUT ─────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│ Enter your custom SMB credentials                     │{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    try:
        username = input(f"\n{Fore.GREEN}Username: {Style.RESET_ALL}").strip()
        password = input(f"{Fore.GREEN}Password: {Style.RESET_ALL}").strip()
        return username, password
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
    except EOFError:
        print(f"\n{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
        sys.exit(0)


def get_credentials_from_choice(choice):
    """
    Get credential tuples based on user choice.
    
    Args:
        choice (str): User's authentication choice
    
    Returns:
        list: List of credential tuples (username, password, ntlm_hash)
    """
    credentials = []
    
    if choice == "1":  # Anonymous login
        credentials.append(("anonymous", "", None))
        print(f"{Fore.BLUE}[*] Using anonymous login{Style.RESET_ALL}")
    
    elif choice == "2":  # Null session
        credentials.append(("", "", None))
        print(f"{Fore.BLUE}[*] Using null session{Style.RESET_ALL}")
    
    elif choice == "3":  # Guest account (no password)
        credentials.append(("guest", "", None))
        print(f"{Fore.BLUE}[*] Using guest account (no password){Style.RESET_ALL}")
    
    elif choice == "4":  # Guest account with password
        credentials.append(("guest", "guest", None))
        print(f"{Fore.BLUE}[*] Using guest account (password: guest){Style.RESET_ALL}")
    
    elif choice == "5":  # Try all methods
        credentials.extend([
            ("anonymous", "", None),
            ("", "", None),
            ("guest", "", None),
            ("guest", "guest", None)
        ])
        print(f"{Fore.BLUE}[*] Will try all authentication methods{Style.RESET_ALL}")
    
    elif choice == "6":  # Custom credentials
        username, password = prompt_custom_credentials()
        credentials.append((username, password, None))
        print(f"{Fore.BLUE}[*] Using custom credentials: {username}{Style.RESET_ALL}")
    
    return credentials


def smart_credential_prompt(args, logger):
    """
    Smart credential prompting that asks for authentication method when needed.
    
    Args:
        args: Command line arguments
        logger: Logger instance
    
    Returns:
        list: List of credential tuples
    """
    credentials = []
    
    # Check if explicit credentials are provided
    if args.username and args.password:
        credentials.append((args.username, args.password, None))
        logger.info(f"[+] Using provided credentials: {args.username}")
        return credentials
    
    # Check for NTLM hash
    if args.hash:
        from utils.auth import parse_ntlm_hash
        ntlm_hash = parse_ntlm_hash(args.hash)
        if ntlm_hash:
            username = args.username if args.username else ""
            credentials.append((username, "", ntlm_hash))
            logger.info(f"[+] Using NTLM hash authentication for user: {username or 'anonymous'}")
            return credentials
    
    # Handle null session with prompting
    if args.null_session:
        print(f"\n{Fore.YELLOW}Null session requested. Let's choose the best authentication method.{Style.RESET_ALL}")
        choice = prompt_authentication_choice()
        creds = get_credentials_from_choice(choice)
        credentials.extend(creds)
        return credentials
    
    # Handle specific authentication flags
    if args.anonymous:
        credentials.append(("anonymous", "", None))
        logger.info("[*] Using anonymous login")
    
    if args.guest:
        credentials.append(("guest", "", None))
        credentials.append(("guest", "guest", None))
        logger.info("[*] Using guest account access")
    
    if args.try_all:
        credentials.extend([
            ("anonymous", "", None),
            ("", "", None),
            ("guest", "", None),
            ("guest", "guest", None)
        ])
        logger.info("[*] Trying all authentication methods")
    
    # If no credentials are available, prompt the user
    if not credentials:
        print(f"\n{Fore.YELLOW}No authentication method specified. Please choose how to connect.{Style.RESET_ALL}")
        choice = prompt_authentication_choice()
        creds = get_credentials_from_choice(choice)
        credentials.extend(creds)
    
    return credentials


def confirm_credential_usage(credentials):
    """
    Display and confirm the credentials that will be used.
    
    Args:
        credentials (list): List of credential tuples
    
    Returns:
        bool: True if user confirms, False otherwise
    """
    print(f"\n{Fore.CYAN}┌─ CREDENTIAL CONFIRMATION ─────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│ The following credentials will be used for scanning   │{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    for i, (username, password, ntlm_hash) in enumerate(credentials, 1):
        if ntlm_hash:
            print(f"{i}. Username: {username or '(empty)'}, NTLM Hash: [REDACTED]")
        elif password:
            print(f"{i}. Username: {username or '(empty)'}, Password: {'*' * len(password)}")
        else:
            auth_type = "Anonymous" if username == "anonymous" else "Null session" if not username else "Guest" if username == "guest" else "No password"
            print(f"{i}. Username: {username or '(empty)'}, Type: {auth_type}")
    
    try:
        confirm = input(f"\n{Fore.GREEN}Proceed with these credentials? (y/n): {Style.RESET_ALL}").strip().lower()
        return confirm in ['y', 'yes', '']
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
    except EOFError:
        print(f"\n{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
        sys.exit(0)


def interactive_credential_selection():
    """
    Full interactive credential selection workflow.
    
    Returns:
        list: Selected credentials
    """
    print(f"\n{Fore.MAGENTA}┌─ INTERACTIVE CREDENTIAL SELECTION ────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}│ Configure authentication for SMB scanning             │{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}└────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    # Get authentication method choice
    choice = prompt_authentication_choice()
    credentials = get_credentials_from_choice(choice)
    
    # Confirm selection
    if confirm_credential_usage(credentials):
        return credentials
    else:
        print(f"{Fore.YELLOW}Credential selection cancelled. Please run the tool again.{Style.RESET_ALL}")
        sys.exit(0)