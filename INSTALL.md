# CRED-SHADOW Installation Guide

## Universal Installation (Recommended)

CRED-SHADOW works on any system with Python 3.11+. No special dependencies or platform-specific requirements.
##sudo apt install samba-client cifs-utils

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow

# 2. Install Python dependencies
pip install -r local_requirements.txt

# 3. Run the tool
python main.py --help
```

That's it! The tool is ready to use.

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)
```bash
# Install Python and pip if not available
sudo apt update
sudo apt install python3 python3-pip

# Clone and install
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow
pip3 install -r local_requirements.txt
python3 main.py --help
```

### Linux (Red Hat/CentOS/Fedora)
```bash
# Install Python and pip if not available
sudo yum install python3 python3-pip  # CentOS/RHEL
# OR
sudo dnf install python3 python3-pip  # Fedora

# Clone and install
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow
pip3 install -r local_requirements.txt
python3 main.py --help
```

### macOS
```bash
# Install Python via Homebrew (if needed)
brew install python3

# Clone and install
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow
pip3 install -r local_requirements.txt
python3 main.py --help
```

### Windows
```powershell
# Download Python from python.org if not installed

# Clone and install
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow
pip install -r local_requirements.txt
python main.py --help
```

## Virtual Environment (Optional but Recommended)

```bash
# Create virtual environment
python -m venv cred-shadow-env

# Activate it
source cred-shadow-env/bin/activate  # Linux/macOS
# OR
cred-shadow-env\Scripts\activate     # Windows

# Install dependencies
pip install -r local_requirements.txt

# Run tool
python main.py --help
```

## Dependencies

All dependencies are standard Python packages available via pip:

- `impacket>=0.12.0` - SMB protocol implementation
- `smbprotocol>=1.15.0` - Modern SMB client library  
- `rich>=14.0.0` - Terminal UI enhancements
- `colorama>=0.4.6` - Cross-platform colored output
- `yara-python>=4.3.0` - Pattern detection (optional)
- `termcolor>=2.3.0` - Colored terminal text
- `prettytable>=3.8.0` - Table formatting
- `python-dotenv>=1.0.0` - Environment variable loading
- `cryptography>=42.0.0` - Cryptographic operations
- `pyasn1>=0.4.8` - ASN.1 support

## Verification

Test the installation:

```bash
# Check help works
python main.py --help

# Test basic functionality (will show connection error - expected)
python main.py --target 127.0.0.1 --anonymous --auto
```

You should see the CRED-SHADOW banner and help text or connection diagnostics.

## Troubleshooting

### Python Version Issues
- Requires Python 3.11 or higher
- Check version: `python --version`
- Use `python3` instead of `python` on some systems

### Permission Errors
- Use `pip install --user` if system-wide install fails
- Consider using virtual environment (recommended)

### Network Issues
- Tool requires network access to SMB targets (ports 445/139)
- Corporate firewalls may block SMB traffic
- Test with local targets first

### Import Errors
- Ensure all dependencies installed: `pip install -r local_requirements.txt`
- Try reinstalling: `pip install --force-reinstall -r local_requirements.txt`

## Development Setup

For contributing or custom modifications:

```bash
# Clone with development setup
git clone https://github.com/your-repo/cred-shadow.git
cd cred-shadow

# Install with development dependencies
pip install -e .
pip install -r local_requirements.txt

# Run tests (if available)
python -m pytest tests/

# Run with development flags
python main.py --verbose --target 192.168.1.100 --try-all
```

## Security Considerations

- Tool is designed for authorized testing only
- Some antivirus software may flag security tools
- Add exceptions for development/testing directories
- Use in isolated lab environments when possible

## Support

- Check GitHub issues for common problems
- Review troubleshooting section above
- Ensure Python 3.11+ and all dependencies installed
- Test network connectivity to SMB targets
