# CRED-SHADOW: SMB Share Secret Scanner

A comprehensive Python-based ethical security testing tool for SMB share credential and secret discovery, designed for authorized lab environments and security auditing.

## Features

- **Multi-Authentication Support**: Anonymous, null session, guest, and credential-based authentication
- **Comprehensive Share Enumeration**: Discovers and analyzes SMB shares across different protocol versions
- **Manual Exploration Mode**: Interactive shell for detailed share navigation
- **Brute Force Capabilities**: Username/password wordlist attacks with configurable delays
- **Advanced Secret Detection**: Regex and entropy-based analysis for credential discovery
- **Export Options**: JSON and CSV output formats for reporting
- **Permission Analysis**: Detailed share access level assessment

## Quick Start

### Installation

#### Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow

# Install dependencies
pip install -r local_requirements.txt

# Run the tool
python main.py --help
```

#### Universal Installation (All Platforms)
```bash
# Auto-detects platform and installs dependencies
python install_universal.py
```

#### Platform-Specific Installation

##### Red Hat/CentOS/Oracle Linux
```bash
sudo yum install -y python3-pip python3-venv gcc python3-devel libffi-devel openssl-devel
python3 install_universal.py
```

##### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv build-essential python3-dev libffi-dev libssl-dev
python3 install_universal.py
```

##### Fedora
```bash
sudo dnf install -y python3-pip python3-venv gcc python3-devel libffi-devel openssl-devel
python3 install_universal.py
```

##### macOS
```bash
# Install Homebrew dependencies (optional)
brew install python@3.11
python3 install_universal.py
```

##### Windows
```cmd
# Ensure Python 3.11+ is installed
python install_universal.py
```

### Basic Usage

```bash
# Authenticated scan
python main.py --target 192.168.1.3 --username albert --password bradley1

# Anonymous session
python main.py --target 192.168.1.3 --anonymous

# Try all authentication methods
python main.py --target 192.168.1.3 --try-all

# Manual exploration mode
python main.py --target 192.168.1.3 --username albert --password bradley1 --manual
```

## Authentication Methods

### Credential-Based
```bash
python main.py --target 192.168.1.3 --username admin --password password123
```

### Anonymous Access
```bash
python main.py --target 192.168.1.3 --anonymous
```

### Null Session
```bash
python main.py --target 192.168.1.3 --null-session
```

### Guest Account
```bash
python main.py --target 192.168.1.3 --guest
```

### NTLM Hash Authentication
```bash
python main.py --target 192.168.1.3 --username admin --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

## Advanced Features

### Brute Force Attacks
```bash
# Create wordlists
echo -e "admin\nuser\nroot" > usernames.txt
echo -e "password\n123456\nadmin" > passwords.txt

# Run brute force
python main.py --target 192.168.1.3 --userlist usernames.txt --passlist passwords.txt --bruteforce --delay 1
```

### Network Scanning (CIDR)
```bash
python main.py --target 192.168.1.0/24 --cidr --username admin --password password123
```

### Export Results
```bash
python main.py --target 192.168.1.3 --username admin --password password123 --output results.json --csv results.csv
```

### Permission Analysis
```bash
python main.py --target 192.168.1.3 --username admin --password password123 --analyze-permissions --permission-report permissions.json
```

## Manual Exploration

Enter interactive shell mode for detailed share exploration:

```bash
python main.py --target 192.168.1.3 --username albert --password bradley1 --manual
```

Available commands in manual mode:
- `ls [path]` - List directory contents
- `cd <path>` - Change directory
- `cat <file>` - Display file contents
- `download <file>` - Download file
- `shares` - Show available shares
- `help` - Show all commands

## Command Line Options

```
Authentication:
  --username, -u       Username for authentication
  --password, -p       Password for authentication
  --hash              NTLM hash (format: LM:NT)
  --anonymous         Anonymous login
  --null-session      Null session attempt
  --guest             Guest account access
  --try-all           Try all authentication methods

Scanning:
  --target            Target IP address or hostname
  --port              SMB port (default: 445)
  --cidr              Enable CIDR scanning
  --timeout           Connection timeout (default: 30)

Attack Options:
  --userlist          Username wordlist file
  --passlist          Password wordlist file
  --bruteforce        Enable brute force attack
  --delay             Delay between attempts (default: 0)

Modes:
  --auto              Automatic scanning (default)
  --interactive       Interactive mode
  --manual            Manual exploration mode

Analysis:
  --analyze-permissions    Advanced permission analysis
  --permission-report     Export permission report

Output:
  --output, -o        JSON output file
  --csv               CSV output file
  --verbose, -v       Verbose output
  --quiet, -q         Quiet mode
```

## Troubleshooting

### Connection Issues
```bash
# Test SMB connectivity
smbclient -L 192.168.1.3 -U username%password

# Check port access
nc -zv 192.168.1.3 445
```

### Share Enumeration Problems
- Verify credentials with external tools (smbclient, smbmap)
- Enable verbose mode (`--verbose`) for detailed debugging
- Try different authentication methods (`--try-all`)
- Check firewall and network connectivity

### Performance Tuning
```bash
# Faster scanning with reduced timeouts
python main.py --target 192.168.1.3 --username admin --password pass123 --timeout 10

# Multi-threaded scanning
python main.py --target 192.168.1.0/24 --cidr --threads 10
```

## Security Considerations

**IMPORTANT**: This tool is designed for authorized security testing only.

- Only use on systems you own or have explicit written permission to test
- Comply with all local laws and organizational policies
- Document all testing activities
- Use in isolated lab environments when possible
- Ensure test credentials are not production accounts

## Requirements

- Python 3.11+
- Network access to SMB targets (port 445)
- Supported platforms: Linux (RHEL/CentOS/Oracle/Ubuntu/Debian/Fedora), macOS, Windows
- Required packages (installed automatically):
  - impacket>=0.12.0
  - rich>=14.0.0
  - colorama>=0.4.6
  - smbprotocol>=1.15.0

## Platform Support

CRED-SHADOW is tested and supported on:
- **Enterprise Linux**: Red Hat Enterprise Linux, Oracle Linux, CentOS
- **Community Linux**: Ubuntu, Debian, Fedora, Arch, SUSE
- **Security Distributions**: Kali Linux, Parrot Security OS
- **Unix Systems**: macOS (Intel/Apple Silicon), FreeBSD, OpenBSD
- **Windows**: Windows 10/11, Windows Server 2019/2022

See `PLATFORM_COMPATIBILITY.md` for detailed platform-specific instructions.

## Support

For detailed documentation, see `LOCAL_DEPLOYMENT.md`.

For troubleshooting and advanced usage, enable verbose logging:
```bash
python main.py --target 192.168.1.3 --username admin --password pass123 --verbose
```

## License

This tool is for educational and authorized security testing purposes only.