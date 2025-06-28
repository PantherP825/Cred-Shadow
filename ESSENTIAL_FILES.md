# CRED-SHADOW Essential Files

This document lists the essential files required to run CRED-SHADOW locally on any platform.

## Core Application Files

### Main Application
- `main.py` - Primary application entry point
- `local_requirements.txt` - Python dependencies for local installation
- `install_universal.py` - Universal cross-platform installer

### Scanner Engine (`scanner/`)
- `__init__.py` - Scanner package initialization
- `share_enum.py` - SMB share enumeration and discovery
- `secret_finder.py` - File content scanning for secrets
- `brute_force.py` - Credential brute force attacks
- `cidr_scanner.py` - Network subnet scanning
- `network_scanner.py` - Network connectivity testing
- `permission_tester.py` - Share permission analysis
- `validator.py` - Credential validation
- `yara_engine.py` - YARA rule engine (optional)

### Manual Exploration (`manual_mode/`)
- `__init__.py` - Manual mode package initialization
- `navigator.py` - Interactive shell for manual share exploration
- `downloader.py` - File download functionality

### Utilities (`utils/`)
- `__init__.py` - Utils package initialization
- `logger.py` - Logging system
- `banner.py` - Application banner and branding
- `config.py` - Configuration management
- `auth.py` - Authentication handling
- `interactive.py` - User interaction utilities
- `interactive_shell.py` - Interactive shell framework
- `credential_prompt.py` - Credential input prompts
- `file_utils.py` - File operations
- `hash_utils.py` - NTLM hash handling
- `regex_patterns.py` - Secret detection patterns
- `session_manager.py` - SMB session management
- `share_manager.py` - Share management utilities
- `smb_compat.py` - SMB protocol compatibility
- `smbclient.py` - SMB client wrapper
- `webhook.py` - Webhook integration
- `permission_analyzer.py` - Advanced permission analysis

### Plugin System (`plugins/`)
- `__init__.py` - Plugin system initialization

## Documentation
- `README.md` - Project overview and basic usage
- `man23.txt` - Comprehensive installation and usage manual
- `LOCAL_DEPLOYMENT.md` - Local deployment instructions
- `PLATFORM_COMPATIBILITY.md` - Platform-specific compatibility guide

## Total File Count
**Essential Files**: 29 core files across 4 directories plus 4 documentation files

## Removed Files
All development, testing, demo, and debugging files have been removed:
- Debug scripts (`debug_*.py`)
- Demo scripts (`demo_*.py`) 
- Test scripts (`test_*.py`)
- QA validation scripts
- Development assets and logs
- Cache directories (`__pycache__/`)
- Sample data files
- Backup files
- Replit-specific configurations

This minimal set provides complete functionality for local deployment across all platforms.