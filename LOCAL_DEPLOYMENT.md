# CRED-SHADOW Local Deployment Guide

## Prerequisites

### System Requirements
- Python 3.11 or higher
- Network access to SMB targets (port 445)
- Linux/macOS/Windows compatible
- Administrative privileges (recommended for network scanning)

### Network Requirements
- Direct network connectivity to target SMB servers
- Port 445 access (SMB protocol)
- Firewall rules allowing outbound SMB connections

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd CRED-SHADOW
```

### 2. Install Dependencies
```bash
# Install required Python packages
pip install -r requirements.txt

# Or install individually:
pip install impacket>=0.12.0
pip install rich>=14.0.0
pip install colorama>=0.4.6
pip install smbprotocol>=1.15.0
```

### 3. Verify Installation
```bash
python main.py --help
```

## Usage Examples

### Basic Authentication Scanning
```bash
# Authenticated scan
python main.py --target 192.168.1.3 --username albert --password bradley1

# Anonymous session
python main.py --target 192.168.1.3 --anonymous

# Null session attempt
python main.py --target 192.168.1.3 --null-session

# Try all authentication methods
python main.py --target 192.168.1.3 --try-all
```

### Manual Exploration Mode
```bash
# Interactive shell for manual exploration
python main.py --target 192.168.1.3 --username albert --password bradley1 --manual
```

### Brute Force Attacks
```bash
# Create wordlists first
echo -e "admin\nuser\nalbert\nroot" > usernames.txt
echo -e "password\n123456\nbradley1\nadmin" > passwords.txt

# Run brute force
python main.py --target 192.168.1.3 --userlist usernames.txt --passlist passwords.txt --bruteforce
```

### Advanced Features
```bash
# Permission analysis
python main.py --target 192.168.1.3 --username albert --password bradley1 --analyze-permissions

# Export results
python main.py --target 192.168.1.3 --username albert --password bradley1 --output results.json --csv results.csv

# Verbose debugging
python main.py --target 192.168.1.3 --username albert --password bradley1 --verbose
```

## Troubleshooting

### Connection Issues
```bash
# Test SMB connectivity first
smbclient -L 192.168.1.3 -U albert%bradley1

# Check network connectivity
nc -zv 192.168.1.3 445
```

### Share Enumeration Problems
If shares are not being discovered:
1. Verify credentials work with smbclient
2. Check firewall settings
3. Enable verbose mode (`--verbose`) for detailed debugging
4. Try different authentication methods (`--try-all`)

### Performance Optimization
```bash
# Reduce timeouts for faster scanning
python main.py --target 192.168.1.3 --username albert --password bradley1 --timeout 10

# Increase threads for larger networks
python main.py --target 192.168.1.0/24 --cidr --threads 10
```

## Output Files

### JSON Export
```json
{
  "scan_results": [
    {
      "target": "192.168.1.3",
      "shares": [
        {
          "name": "smbshare",
          "type": 0,
          "access": "READ/WRITE",
          "files_found": 15,
          "secrets_found": 2
        }
      ]
    }
  ]
}
```

### CSV Export
Standard CSV format with columns: Target, Share, Access, Files, Secrets, Session Type

## Security Considerations

### Authorized Use Only
- Only use on systems you own or have explicit permission to test
- Comply with local laws and organizational policies
- Document all testing activities

### Lab Environment Setup
- Use isolated network segments for testing
- Implement proper logging and monitoring
- Ensure test credentials are not production accounts

## Support

### Debug Mode
Enable verbose logging to troubleshoot issues:
```bash
python main.py --target 192.168.1.3 --username albert --password bradley1 --verbose
```

### Log Files
Check application logs for detailed error information and debugging data.

### Known Working Configurations
- Tested with Windows Server 2019/2022 SMB shares
- Compatible with Samba 4.x implementations
- Works with various SMB protocol versions (1.0-3.1.1)