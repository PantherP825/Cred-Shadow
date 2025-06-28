@echo off
REM CRED-SHADOW Standalone Launcher for Windows
REM Universal script for running CRED-SHADOW on Windows systems

setlocal enabledelayedexpansion

echo.
echo   ████████  ██████  ███████ ██████       ███████ ██   ██  █████  ██████   ██████  ██     ██
echo  ██     ██ ██   ██ ██      ██   ██      ██      ██   ██ ██   ██ ██   ██ ██    ██ ██     ██
echo  ██        ██████  █████   ██   ██      ███████ ███████ ███████ ██   ██ ██    ██ ██  █  ██
echo  ██     ██ ██   ██ ██      ██   ██           ██ ██   ██ ██   ██ ██   ██ ██    ██ ██ ███ ██
echo   ████████ ██   ██ ███████ ██████       ███████ ██   ██ ██   ██ ██████   ██████   ███ ███
echo.
echo                    CRED-SHADOW: SMB Share Secret Scanner
echo                   For Ethical Security Testing ^& Internal Audits
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.11 or higher.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [INFO] Python detected
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Python version: %PYTHON_VERSION%

REM Check if we're in the right directory
if not exist "local_requirements.txt" (
    echo [ERROR] local_requirements.txt not found
    echo Please run this script from the CRED-SHADOW directory
    pause
    exit /b 1
)

REM Check dependencies
echo [INFO] Checking dependencies...
python -c "import impacket, smbprotocol, rich, colorama" 2>nul
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    python -m pip install -r local_requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        echo Try running: pip install --user -r local_requirements.txt
        pause
        exit /b 1
    )
    echo [SUCCESS] Dependencies installed
) else (
    echo [SUCCESS] All dependencies satisfied
)

echo [SUCCESS] CRED-SHADOW ready to run
echo.

REM Run CRED-SHADOW with provided arguments
if "%~1"=="" (
    echo [INFO] No arguments provided. Showing help...
    python main.py --help
) else (
    echo [INFO] Running: python main.py %*
    python main.py %*
)

echo.
echo Press any key to exit...
pause >nul