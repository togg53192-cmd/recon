@echo off
echo.
echo  =============================================
echo   RECON - OSINT Aggregator Setup
echo  =============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [!] Python not found. Install from https://python.org
    pause
    exit /b 1
)

:: Install core dependency
echo  [*] Installing aiohttp...
pip install aiohttp --quiet

:: Install external tools
echo.
echo  [*] Installing Maigret...
pip install maigret --quiet

echo  [*] Installing Sherlock...
pip install sherlock-project --quiet

:: Clone Blackbird
if not exist "blackbird" (
    echo  [*] Cloning Blackbird...
    git clone https://github.com/p1ngul1n0/blackbird.git --quiet 2>nul
    if exist "blackbird\requirements.txt" (
        pip install -r blackbird\requirements.txt --quiet
    )
) else (
    echo  [*] Blackbird already exists, skipping
)

:: Clone SpiderFoot
if not exist "spiderfoot" (
    echo  [*] Cloning SpiderFoot...
    git clone https://github.com/smicallef/spiderfoot.git --quiet 2>nul
    if exist "spiderfoot\requirements.txt" (
        pip install -r spiderfoot\requirements.txt --quiet
    )
) else (
    echo  [*] SpiderFoot already exists, skipping
)

echo.
echo  =============================================
echo   Setup complete! Starting web UI...
echo  =============================================
echo.
echo  Open http://localhost:8420 in your browser
echo.

python server.py
pause
