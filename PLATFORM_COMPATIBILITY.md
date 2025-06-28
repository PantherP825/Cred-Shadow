# CRED-SHADOW Platform Compatibility Guide

## Supported Platforms

CRED-SHADOW is designed for universal cross-platform compatibility across all major operating systems and distributions.

### Officially Tested Platforms

#### Linux Distributions
- **Red Hat Enterprise Linux (RHEL)** 7, 8, 9
- **Oracle Linux** 7, 8, 9
- **CentOS** 7, 8, 9 (and CentOS Stream)
- **Ubuntu** 18.04, 20.04, 22.04, 24.04 LTS
- **Debian** 10, 11, 12
- **Fedora** 35, 36, 37, 38, 39
- **SUSE Linux Enterprise** 15
- **openSUSE** Leap/Tumbleweed
- **Arch Linux**
- **Kali Linux** (penetration testing focus)
- **Parrot Security OS**

#### Unix Systems
- **macOS** 11 (Big Sur), 12 (Monterey), 13 (Ventura), 14 (Sonoma)
- **FreeBSD** 13, 14
- **OpenBSD** 7.x
- **Solaris/illumos**

#### Windows
- **Windows 10** (all versions)
- **Windows 11** (all versions)
- **Windows Server 2019/2022**

## Installation Methods

### Universal Installer (Recommended)
Works on all platforms with automatic detection:
```bash
python3 install_universal.py
```

### Platform-Specific Installation

#### Red Hat/CentOS/Oracle Linux
```bash
# Install dependencies with YARA support
sudo yum install -y epel-release
sudo yum install -y python3-pip python3-venv gcc python3-devel libffi-devel openssl-devel yara-devel pkgconfig

# Run installer
python3 install_universal.py
```

#### Ubuntu/Debian/Kali Linux
```bash
# Install dependencies with YARA support
sudo apt update
sudo apt install -y python3-pip python3-venv build-essential python3-dev libffi-dev libssl-dev libyara-dev pkg-config

# Run installer
python3 install_universal.py
```

#### Fedora
```bash
# Install dependencies
sudo dnf install -y python3-pip python3-venv gcc python3-devel libffi-devel openssl-devel

# Run installer
python3 install_universal.py
```

#### macOS
```bash
# Install via Homebrew (optional)
brew install python@3.11

# Run installer
python3 install_universal.py
```

#### Windows
```cmd
# Ensure Python 3.11+ is installed and in PATH
python install_universal.py
```

## Platform-Specific Considerations

### Enterprise Linux (RHEL/CentOS/Oracle)

#### Package Management
- Uses `yum` (RHEL 7/CentOS 7) or `dnf` (RHEL 8+/CentOS 8+)
- May require EPEL repository for some dependencies
- SELinux considerations for network scanning

#### Firewall Configuration
```bash
# Allow SMB traffic (if needed)
sudo firewall-cmd --permanent --add-port=445/tcp
sudo firewall-cmd --reload
```

#### SELinux Considerations
```bash
# Check SELinux status
sestatus

# If needed, temporarily disable for testing
sudo setenforce 0
```

### Ubuntu/Debian Systems

#### Network Configuration
- Uses `ufw` firewall by default
- May need to configure network interfaces

#### Privilege Requirements
```bash
# For network scanning capabilities
sudo setcap cap_net_raw+ep $(which python3)
```

### macOS Specifics

#### Security Considerations
- Gatekeeper may block unsigned binaries
- Network scanning requires administrator privileges
- Python from Homebrew recommended over system Python

#### Installation via Homebrew
```bash
brew install python@3.11
brew install libffi openssl
```

### Windows Considerations

#### Python Installation
- Install from python.org or Microsoft Store
- Ensure Python is added to PATH
- May need Visual C++ Build Tools for some dependencies

#### Windows Defender
- May flag network scanning tools
- Add exclusion for CRED-SHADOW directory if needed

#### PowerShell Execution Policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Architecture Support

### CPU Architectures
- **x86_64 (AMD64)** - Primary support
- **ARM64/AArch64** - Full support (Apple Silicon, ARM servers)
- **x86 (32-bit)** - Legacy support where Python 3.11+ available
- **ARM** - Limited support (Raspberry Pi, embedded systems)

### Memory Requirements
- Minimum: 512MB RAM
- Recommended: 2GB+ RAM for large network scans
- Disk: 500MB for installation + logs/output

## Dependency Management

### Python Version Requirements
- **Minimum**: Python 3.11
- **Recommended**: Python 3.11 or 3.12
- **Maximum tested**: Python 3.12

### Core Dependencies
All platforms require these Python packages:
- impacket >= 0.12.0
- smbprotocol >= 1.15.0
- rich >= 14.0.0
- colorama >= 0.4.6
- cryptography >= 41.0.5

### System Dependencies

#### Compilation Requirements
Most platforms need build tools for cryptographic libraries:
- **Linux**: gcc, python3-dev, libffi-dev, openssl-dev
- **macOS**: Xcode Command Line Tools
- **Windows**: Visual C++ Build Tools

## Network Considerations

### Firewall Configuration
CRED-SHADOW requires outbound access to:
- **Port 445** (SMB/CIFS)
- **Port 135** (RPC endpoint mapper)
- **Dynamic RPC ports** (varies by target)

### Proxy Support
For environments with proxy requirements:
```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

## Troubleshooting by Platform

### Red Hat/Oracle Linux Issues
```bash
# Enable EPEL repository
sudo yum install epel-release

# Update system
sudo yum update

# Install additional development tools
sudo yum groupinstall "Development Tools"
```

### Ubuntu/Debian Issues
```bash
# Update package cache
sudo apt update && sudo apt upgrade

# Install build essentials
sudo apt install build-essential

# Fix broken packages
sudo apt --fix-broken install
```

### macOS Issues
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Update Homebrew
brew update && brew upgrade

# Fix Python path issues
echo 'export PATH="/usr/local/opt/python@3.11/bin:$PATH"' >> ~/.zshrc
```

### Windows Issues
- Ensure Python installer selected "Add to PATH"
- Install Microsoft C++ Build Tools if compilation fails
- Run Command Prompt as Administrator if permission issues

## Performance Optimization

### Linux/Unix Optimizations
```bash
# Increase file descriptor limits
ulimit -n 4096

# Optimize network stack
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
```

### Windows Optimizations
- Disable Windows Defender real-time scanning for tool directory
- Use SSD storage for better I/O performance
- Increase PowerShell execution timeout if needed

## Security Considerations

### Privilege Requirements
- Standard user privileges sufficient for most operations
- Administrator/root required for:
  - Raw socket access (some scanning modes)
  - System-wide dependency installation
  - Network configuration changes

### Network Security
- Tool generates network traffic to SMB servers
- Ensure compliance with organizational security policies
- Use in isolated lab environments when possible
- Monitor network traffic for security analysis

## Support Matrix

| Platform | Status | Notes |
|----------|--------|--------|
| RHEL 8/9 | ✅ Full | Primary enterprise target |
| Oracle Linux 8/9 | ✅ Full | Identical to RHEL |
| CentOS 8/9 | ✅ Full | Community enterprise |
| Ubuntu 20.04+ | ✅ Full | Primary development platform |
| Debian 11+ | ✅ Full | Stable base |
| Fedora 38+ | ✅ Full | Latest features |
| macOS 12+ | ✅ Full | Apple Silicon + Intel |
| Windows 10/11 | ✅ Full | PowerShell + CMD support |
| FreeBSD 13+ | ⚠️ Limited | Manual dependency install |
| OpenBSD 7+ | ⚠️ Limited | Manual dependency install |
| Legacy systems | ❌ Not supported | Python 3.11+ requirement |

## Contact and Support

For platform-specific issues or compatibility questions, enable verbose logging:
```bash
python main.py --target 192.168.1.3 --username admin --password pass123 --verbose
```

This provides detailed debugging information for troubleshooting platform-specific problems.