@echo off
setlocal EnableDelayedExpansion
title SentinelTrap Enterprise - Threat Intelligence Honeypot & Attack Surface Observer

echo ===============================================================================
echo   SENTINELTRAP ENTERPRISE v2.4 - INITIALIZATION SEQUENCE
echo   Threat Intelligence Honeypot ^& Global Attack Surface Observer
echo ===============================================================================
echo.

:: 1. Verify Python 3.9+ availability
echo [INFO] Verifying Python runtime environment...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python runtime was not found in your system PATH.
    echo         Please install Python 3.9 or newer from https://www.python.org/
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    for /f "delims=" %%V in ('python --version 2^>^&1') do set PY_VER=%%V
    echo [ERROR] Unsupported Python version detected: !PY_VER!
    echo         SentinelTrap requires Python 3.9 or higher.
    pause
    exit /b 1
)

for /f "delims=" %%V in ('python --version 2^>^&1') do set PY_VER=%%V
echo [OK]   Detected compatible runtime: !PY_VER!

:: 2. Provision Virtual Environment (.venv) if not present
if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating isolated Python virtual environment (.venv)...
    python -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to initialize virtual environment.
        pause
        exit /b 1
    )
    echo [OK]   Virtual environment created.
) else (
    echo [OK]   Existing virtual environment (.venv) verified.
)

:: 3. Install / Synchronize dependencies from requirements.txt
echo [INFO] Synchronizing package dependencies from requirements.txt...
".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
".venv\Scripts\python.exe" -m pip install -r requirements.txt --quiet
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Dependency installation encountered an error.
    pause
    exit /b 1
)
echo [OK]   All required packages verified.

:: 4. Launch Backend Server (app.py) and Adversarial Simulator (attack_simulator.py)
echo.
echo [INFO] Starting SentinelTrap Asynchronous Core (Web UI :8000 ^| SSH :2222 ^| HTTP :8080)...
start "SentinelTrap-Core" /B ".venv\Scripts\python.exe" app.py

timeout /t 2 /nobreak >nul

echo [INFO] Starting Local Adversarial Traffic Simulator (attack_simulator.py)...
start "SentinelTrap-Simulator" /B ".venv\Scripts\python.exe" attack_simulator.py

:: 5. Open default web browser to the Command Interface
echo [INFO] Opening Enterprise Command Interface at http://127.0.0.1:8000 ...
start "" "http://127.0.0.1:8000"

echo.
echo ===============================================================================
echo   SENTINELTRAP SENSOR STATUS : ONLINE
echo   Web Command Interface      : http://127.0.0.1:8000
echo   SSH Honeypot Listener      : 0.0.0.0:2222
echo   HTTP REST Admin Honeypot   : 0.0.0.0:8080
echo   Press [ENTER] or [CTRL+C] to stop all services and exit cleanly.
echo ===============================================================================
echo.

pause >nul

:CLEANUP
echo.
echo [INFO] Terminating SentinelTrap background services...
taskkill /FI "WINDOWTITLE eq SentinelTrap-Simulator*" /F >nul 2>nul
taskkill /FI "WINDOWTITLE eq SentinelTrap-Core*" /F >nul 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
)
echo [OK]   All processes terminated cleanly.
endlocal
exit /b 0
