#!/usr/bin/env python3
"""
CRED-SHADOW Universal Installation Script
Cross-platform installer for Mac, Linux, Windows, Red Hat, Oracle Linux, and all platforms
"""

import os
import sys
import subprocess
import platform
import venv
from pathlib import Path

def detect_platform():
    """Detect the current platform and distribution."""
    system = platform.system().lower()
    dist = ""
    
    if system == "linux":
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                if "red hat" in content or "rhel" in content:
                    dist = "redhat"
                elif "oracle" in content:
                    dist = "oracle"
                elif "centos" in content:
                    dist = "centos"
                elif "ubuntu" in content:
                    dist = "ubuntu"
                elif "debian" in content:
                    dist = "debian"
                elif "fedora" in content:
                    dist = "fedora"
                else:
                    dist = "linux"
        except:
            dist = "linux"
    
    return system, dist

def check_python_version():
    """Check if Python 3.11+ is available."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        print(f"ERROR: Python 3.11+ required (found {version.major}.{version.minor})")
        print("Please install Python 3.11 or higher and try again.")
        return False
    
    print(f"✓ Python {version.major}.{version.minor}.{version.micro} detected")
    return True

def install_system_dependencies(system, dist):
    """Install system-level dependencies based on platform."""
    print("Checking system dependencies...")
    
    commands = []
    
    if system == "linux":
        if dist in ["redhat", "centos", "oracle", "fedora"]:
            # RHEL/CentOS/Oracle/Fedora
            commands = [
                ["sudo", "yum", "install", "-y", "epel-release"],  # Enable EPEL for YARA
                ["sudo", "yum", "install", "-y", "python3-pip", "python3-venv", "gcc", "python3-devel"],
                ["sudo", "yum", "install", "-y", "libffi-devel", "openssl-devel", "yara-devel", "pkgconfig"]
            ]
        elif dist in ["ubuntu", "debian", "kali"]:
            # Ubuntu/Debian/Kali Linux
            commands = [
                ["sudo", "apt", "update"],
                ["sudo", "apt", "install", "-y", "python3-pip", "python3-venv", "build-essential", "python3-dev"],
                ["sudo", "apt", "install", "-y", "libffi-dev", "libssl-dev", "libyara-dev", "pkg-config"]
            ]
        else:
            # Generic Linux - try both package managers with YARA support
            print("Generic Linux detected - attempting package installation...")
            try:
                # Try yum/dnf first (RHEL-based)
                subprocess.run(["sudo", "yum", "install", "-y", "epel-release"], check=False)
                subprocess.run(["sudo", "yum", "install", "-y", "python3-pip", "python3-venv", "gcc", "python3-devel"], check=False)
                subprocess.run(["sudo", "yum", "install", "-y", "libffi-devel", "openssl-devel", "yara-devel", "pkgconfig"], check=False)
            except:
                try:
                    # Try apt (Debian-based)
                    subprocess.run(["sudo", "apt", "update"], check=False)
                    subprocess.run(["sudo", "apt", "install", "-y", "python3-pip", "python3-venv", "build-essential", "python3-dev"], check=False)
                    subprocess.run(["sudo", "apt", "install", "-y", "libffi-dev", "libssl-dev", "libyara-dev", "pkg-config"], check=False)
                except:
                    print("Warning: Could not install system packages automatically")
                    print("YARA functionality may be limited")
    
    elif system == "darwin":
        # macOS
        print("macOS detected - checking for Homebrew...")
        try:
            subprocess.run(["brew", "--version"], check=True, capture_output=True)
            commands = [
                ["brew", "install", "python@3.11"],
                ["brew", "install", "yara", "pkg-config"]
            ]
        except:
            print("Homebrew not found - continuing with system Python")
            print("Warning: YARA may not be available without Homebrew")
    
    elif system == "windows":
        # Windows
        print("Windows detected - ensure Python is in PATH")
    
    # Execute installation commands
    for cmd in commands:
        try:
            print(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Command failed: {e}")
        except FileNotFoundError:
            print(f"Warning: Command not found: {cmd[0]}")

def create_virtual_environment():
    """Create and setup virtual environment."""
    venv_path = Path("cred_shadow_env")
    
    if venv_path.exists():
        print("Virtual environment already exists, removing...")
        import shutil
        shutil.rmtree(venv_path)
    
    print("Creating virtual environment...")
    venv.create(venv_path, with_pip=True)
    
    # Determine activation script path
    system = platform.system().lower()
    if system == "windows":
        activate_script = venv_path / "Scripts" / "activate"
        python_exe = venv_path / "Scripts" / "python.exe"
    else:
        activate_script = venv_path / "bin" / "activate"
        python_exe = venv_path / "bin" / "python"
    
    return python_exe, activate_script

def install_python_dependencies(python_exe):
    """Install Python dependencies."""
    print("Installing Python dependencies...")
    
    # Upgrade pip first
    subprocess.run([str(python_exe), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    
    # Core dependencies (required)
    core_deps = [
        "impacket>=0.12.0",
        "smbprotocol>=1.15.0", 
        "colorama>=0.4.6",
        "rich>=14.0.0",
        "pyasn1>=0.2.3",
        "pyasn1_modules",
        "pycryptodomex",
        "pyOpenSSL==24.0.0",
        "six",
        "ldap3>=2.5",
        "ldapdomaindump>=0.9.0",
        "flask>=1.0",
        "setuptools",
        "charset_normalizer",
        "cryptography>=41.0.5",
        "pyspnego",
        "markdown-it-py>=2.2.0"
    ]
    
    # Optional dependencies
    optional_deps = [
        "yara-python"
    ]
    
    # Install core dependencies
    for dep in core_deps:
        try:
            print(f"Installing {dep}...")
            subprocess.run([str(python_exe), "-m", "pip", "install", dep], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to install required dependency {dep}: {e}")
            raise
    
    # Install optional dependencies
    for dep in optional_deps:
        try:
            print(f"Installing optional {dep}...")
            subprocess.run([str(python_exe), "-m", "pip", "install", dep], check=True)
            print(f"✓ {dep} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to install optional {dep}: {e}")
            print(f"YARA functionality will be disabled - this is normal on some systems")

def verify_installation(python_exe):
    """Verify the installation works."""
    print("Verifying installation...")
    
    try:
        result = subprocess.run([str(python_exe), "main.py", "--help"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✓ CRED-SHADOW installation verified successfully")
            return True
        else:
            print(f"✗ Verification failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Verification error: {e}")
        return False

def create_platform_launchers():
    """Create platform-specific launcher scripts."""
    system = platform.system().lower()
    
    if system == "windows":
        # Windows batch file
        with open("cred-shadow.bat", "w") as f:
            f.write("""@echo off
call cred_shadow_env\\Scripts\\activate.bat
python main.py %*
""")
        print("Created Windows launcher: cred-shadow.bat")
        
    else:
        # Unix shell script
        with open("cred-shadow.sh", "w") as f:
            f.write("""#!/bin/bash
source cred_shadow_env/bin/activate
python main.py "$@"
""")
        os.chmod("cred-shadow.sh", 0o755)
        print("Created Unix launcher: cred-shadow.sh")

def print_usage_instructions():
    """Print platform-specific usage instructions."""
    system = platform.system().lower()
    
    print("\n" + "="*50)
    print("CRED-SHADOW Installation Complete!")
    print("="*50)
    
    if system == "windows":
        print("\nTo use CRED-SHADOW on Windows:")
        print("1. Use the launcher: cred-shadow.bat --target 192.168.1.3 --username admin --password pass123")
        print("2. Or manually activate: cred_shadow_env\\Scripts\\activate.bat")
        print("   Then run: python main.py --target 192.168.1.3 --username admin --password pass123")
    else:
        print("\nTo use CRED-SHADOW on Unix/Linux/macOS:")
        print("1. Use the launcher: ./cred-shadow.sh --target 192.168.1.3 --username admin --password pass123")
        print("2. Or manually activate: source cred_shadow_env/bin/activate")
        print("   Then run: python main.py --target 192.168.1.3 --username admin --password pass123")
    
    print("\nExample commands:")
    print("  Authenticated scan:   --target 192.168.1.3 --username albert --password bradley1")
    print("  Anonymous session:    --target 192.168.1.3 --anonymous")
    print("  Try all methods:      --target 192.168.1.3 --try-all")
    print("  Manual exploration:   --target 192.168.1.3 --username albert --password bradley1 --manual")
    print("  Verbose debugging:    --target 192.168.1.3 --username albert --password bradley1 --verbose")
    
    print(f"\nPlatform detected: {platform.system()} {platform.release()}")
    print("See LOCAL_DEPLOYMENT.md for detailed documentation.")

def main():
    """Main installation function."""
    print("CRED-SHADOW Universal Installer")
    print("="*40)
    
    # Detect platform
    system, dist = detect_platform()
    print(f"Platform: {system.title()}" + (f" ({dist.title()})" if dist else ""))
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install system dependencies
    install_system_dependencies(system, dist)
    
    # Create virtual environment
    python_exe, activate_script = create_virtual_environment()
    
    # Install Python dependencies
    install_python_dependencies(python_exe)
    
    # Verify installation
    if not verify_installation(python_exe):
        print("Installation verification failed!")
        sys.exit(1)
    
    # Create launchers
    create_platform_launchers()
    
    # Print usage instructions
    print_usage_instructions()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInstallation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nInstallation failed: {e}")
        sys.exit(1)