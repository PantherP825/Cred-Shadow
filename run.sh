#!/bin/bash
# CRED-SHADOW Standalone Launcher
# Universal script for running CRED-SHADOW on any Unix-like system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "  ▄████▄   ██▀███  ▓█████ ▓█████▄      ██████  ██░ ██  ▄▄▄      ▓█████▄  ▒█████   █     █░"
echo " ▒██▀ ▀█  ▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌   ▒██    ▒ ▓██░ ██▒▒████▄    ▒██▀ ██▌▒██▒  ██▒▓█░ █ ░█░"
echo " ▒▓█    ▄ ▓██ ░▄█ ▒▒███   ░██   █▌   ░ ▓██▄   ▒██▀▀██░▒██  ▀█▄  ░██   █▌▒██░  ██▒▒█░ █ ░█ "
echo " ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌     ▒   ██▒░▓█ ░██ ░██▄▄▄▄██ ░▓█▄   ▌▒██   ██░░█░ █ ░█ "
echo " ▒ ▓███▀ ░░██▓ ▒██▒░▒████▒░▒████▓    ▒██████▒▒░▓█▒░██▓ ▓█   ▓██▒░▒████▓ ░ ████▓▒░░░██▒██▓ "
echo " ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒  "
echo "   ░  ▒     ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒    ░ ░▒  ░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░ ░ ▒  ▒   ░ ▒ ▒░   ▒ ░ ░  "
echo " ░          ░░   ░    ░    ░ ░  ░    ░  ░  ░   ░  ░░ ░  ░   ▒    ░ ░  ░ ░ ░ ░ ▒    ░   ░  "
echo " ░ ░         ░        ░  ░   ░             ░   ░  ░  ░      ░  ░   ░        ░ ░      ░    "
echo " ░                         ░                                   ░                          "
echo -e "${NC}"
echo -e "${GREEN}                    CRED-SHADOW: SMB Share Secret Scanner${NC}"
echo -e "${YELLOW}                   For Ethical Security Testing & Internal Audits${NC}"
echo ""

# Check Python version
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}Error: Python not found. Please install Python 3.11 or higher.${NC}"
        exit 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    REQUIRED_VERSION="3.11"
    
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
        echo -e "${GREEN}✓ Python $PYTHON_VERSION detected${NC}"
    else
        echo -e "${RED}Error: Python 3.11+ required. Found: $PYTHON_VERSION${NC}"
        echo "Please upgrade Python or use a virtual environment with Python 3.11+"
        exit 1
    fi
}

# Check and install dependencies
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    if [ ! -f "local_requirements.txt" ]; then
        echo -e "${RED}Error: local_requirements.txt not found${NC}"
        echo "Please run this script from the CRED-SHADOW directory"
        exit 1
    fi
    
    # Check if dependencies are installed
    if $PYTHON_CMD -c "import impacket, smbprotocol, rich, colorama" 2>/dev/null; then
        echo -e "${GREEN}✓ All dependencies satisfied${NC}"
    else
        echo -e "${YELLOW}Installing dependencies...${NC}"
        $PYTHON_CMD -m pip install -r local_requirements.txt
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Dependencies installed successfully${NC}"
        else
            echo -e "${RED}Error: Failed to install dependencies${NC}"
            echo "Try: pip install --user -r local_requirements.txt"
            exit 1
        fi
    fi
}

# Main execution
main() {
    check_python
    check_dependencies
    
    echo -e "${GREEN}✓ CRED-SHADOW ready to run${NC}"
    echo ""
    
    # Run CRED-SHADOW with provided arguments
    if [ $# -eq 0 ]; then
        echo -e "${YELLOW}No arguments provided. Showing help...${NC}"
        $PYTHON_CMD main.py --help
    else
        echo -e "${BLUE}Running: $PYTHON_CMD main.py $@${NC}"
        $PYTHON_CMD main.py "$@"
    fi
}

# Run main function with all arguments
main "$@"