# RECON - One-Click Installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/YOURNAME/recon/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$REPO_URL  = "https://github.com/togg53192-cmd/recon"
$RAW_URL   = "https://raw.githubusercontent.com/togg53192-cmd/recon/main"
$INSTALL_DIR = "$env:USERPROFILE\recon"
$FILES = @("recon.py", "recon_engine.py", "server.py", "README.md")

function Write-Header {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "    RECON - Multi-Source OSINT Aggregator" -ForegroundColor Cyan
    Write-Host "    Installer v1.0" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($msg) {
    Write-Host "  [*] $msg" -ForegroundColor Yellow
}

function Write-OK($msg) {
    Write-Host "  [+] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Red
}

function Write-Info($msg) {
    Write-Host "      $msg" -ForegroundColor Gray
}

# ── Check Python ─────────────────────────────────────────────────────────────

function Check-Python {
    Write-Step "Checking Python..."

    $py = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -ge 3 -and $minor -ge 8) {
                    $py = $cmd
                    Write-OK "Found $ver -> using '$cmd'"
                    break
                }
            }
        } catch {}
    }

    if (-not $py) {
        Write-Fail "Python 3.8+ not found."
        Write-Info "Download it from: https://www.python.org/downloads/"
        Write-Info "Make sure to check 'Add Python to PATH' during install."
        Write-Host ""
        Read-Host "  Press Enter to open the Python download page, then re-run this installer"
        Start-Process "https://www.python.org/downloads/"
        exit 1
    }

    return $py
}

# ── Check Git ────────────────────────────────────────────────────────────────

function Check-Git {
    try {
        $ver = & git --version 2>&1
        if ($ver -match "git version") {
            Write-OK "Git found: $ver"
            return $true
        }
    } catch {}
    Write-Info "Git not found - Blackbird integration will be skipped."
    return $false
}

# ── Download files ───────────────────────────────────────────────────────────

function Download-Files($py) {
    Write-Step "Setting up RECON in: $INSTALL_DIR"

    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null
    }

    $wc = New-Object System.Net.WebClient

    foreach ($file in $FILES) {
        $url  = "$RAW_URL/$file"
        $dest = "$INSTALL_DIR\$file"
        try {
            Write-Info "Downloading $file..."
            $wc.DownloadFile($url, $dest)
        } catch {
            Write-Fail "Failed to download $file from $url"
            Write-Info "Check that your repo is public and the URL is correct."
            exit 1
        }
    }

    Write-OK "All files downloaded."
}

# ── Install Python packages ──────────────────────────────────────────────────

function Install-Packages($py) {
    Write-Step "Installing required Python package (aiohttp)..."
    & $py -m pip install --quiet aiohttp
    Write-OK "aiohttp installed."

    Write-Host ""
    $ans = Read-Host "  Install optional tools (maigret + sherlock) for deeper scans? [Y/n]"
    if ($ans -eq "" -or $ans -match "^[Yy]") {
        Write-Step "Installing maigret and sherlock-project..."
        & $py -m pip install --quiet maigret sherlock-project
        Write-OK "Optional tools installed."
    } else {
        Write-Info "Skipped. You can install later: pip install maigret sherlock-project"
    }
}

# ── Optional: clone Blackbird ─────────────────────────────────────────────────

function Install-Blackbird($py, $hasGit) {
    if (-not $hasGit) { return }

    Write-Host ""
    $ans = Read-Host "  Install Blackbird (adds 600+ more sites)? Requires git. [Y/n]"
    if ($ans -eq "" -or $ans -match "^[Yy]") {
        $bbDir = "$INSTALL_DIR\blackbird"
        if (Test-Path $bbDir) {
            Write-Info "Blackbird already exists, pulling latest..."
            Set-Location $bbDir
            & git pull --quiet
        } else {
            Write-Step "Cloning Blackbird..."
            & git clone --quiet https://github.com/p1ngul1n0/blackbird.git $bbDir
        }
        & $py -m pip install --quiet -r "$bbDir\requirements.txt"
        Write-OK "Blackbird ready."
    } else {
        Write-Info "Skipped."
    }
}

# ── Create launcher ───────────────────────────────────────────────────────────

function Create-Launcher($py) {
    Write-Step "Creating launcher scripts..."

    # recon.bat - for CLI use
    $bat = "@echo off`r`n$py `"$INSTALL_DIR\recon.py`" %*"
    Set-Content -Path "$INSTALL_DIR\recon.bat" -Value $bat -Encoding ASCII

    # recon-web.bat - launches the web UI
    $webBat = "@echo off`r`necho Starting RECON web UI at http://localhost:8420`r`nstart http://localhost:8420`r`n$py `"$INSTALL_DIR\server.py`""
    Set-Content -Path "$INSTALL_DIR\recon-web.bat" -Value $webBat -Encoding ASCII

    Write-OK "Launchers created."
}

# ── Add to PATH ───────────────────────────────────────────────────────────────

function Add-ToPath {
    $current = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($current -notlike "*$INSTALL_DIR*") {
        Write-Step "Adding RECON to your PATH..."
        [Environment]::SetEnvironmentVariable("PATH", "$current;$INSTALL_DIR", "User")
        $env:PATH += ";$INSTALL_DIR"
        Write-OK "Added to PATH. You can now run 'recon <username>' from any terminal."
    } else {
        Write-OK "Already in PATH."
    }
}

# ── Final message ─────────────────────────────────────────────────────────────

function Write-Done {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "    RECON is ready!" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Scan a username:   " -NoNewline
    Write-Host "recon johndoe" -ForegroundColor White
    Write-Host "    Web UI:            " -NoNewline
    Write-Host "recon-web" -ForegroundColor White
    Write-Host "    CLI flags:         " -NoNewline
    Write-Host "recon johndoe --skip-wmn" -ForegroundColor White
    Write-Host ""
    Write-Host "    NOTE: Open a NEW terminal window for PATH changes to take effect." -ForegroundColor Yellow
    Write-Host ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Header
$py     = Check-Python
$hasGit = Check-Git
Download-Files $py
Install-Packages $py
Install-Blackbird $py $hasGit
Create-Launcher $py
Add-ToPath
Write-Done
