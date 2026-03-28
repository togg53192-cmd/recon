# RECON - One-Click Installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/togg53192-cmd/recon/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$RAW_URL     = "https://raw.githubusercontent.com/togg53192-cmd/recon/main"
$INSTALL_DIR = "$env:USERPROFILE\recon"
$FILES       = @("recon.py", "recon_engine.py", "server.py", "setup_and_run.bat", "README.md")

function Write-Header {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "    RECON - Multi-Source OSINT Aggregator" -ForegroundColor Cyan
    Write-Host "    Installer v2.1" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($msg) { Write-Host "  [*] $msg" -ForegroundColor Yellow }
function Write-OK($msg)   { Write-Host "  [+] $msg" -ForegroundColor Green  }
function Write-Fail($msg) { Write-Host "  [!] $msg" -ForegroundColor Red    }
function Write-Info($msg) { Write-Host "      $msg" -ForegroundColor Gray   }

# ── Check Python ──────────────────────────────────────────────────────────────

function Check-Python {
    Write-Step "Checking Python..."
    $py = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python (\d+)\.(\d+)") {
                if ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 8) {
                    $py = $cmd
                    Write-OK "Found $ver -> using '$cmd'"
                    break
                }
            }
        } catch {}
    }
    if (-not $py) {
        Write-Fail "Python 3.8+ not found."
        Write-Info "Download from: https://www.python.org/downloads/"
        Write-Info "Check 'Add Python to PATH' during install, then re-run this script."
        Read-Host "  Press Enter to open the download page"
        Start-Process "https://www.python.org/downloads/"
        exit 1
    }
    return $py
}

# ── Get Python version tuple ──────────────────────────────────────────────────

function Get-PythonVersion($py) {
    $ver = & $py --version 2>&1
    if ($ver -match "Python (\d+)\.(\d+)") {
        return @([int]$Matches[1], [int]$Matches[2])
    }
    return @(3, 10)
}

# ── Check Git ─────────────────────────────────────────────────────────────────

function Check-Git {
    try {
        $ver = & git --version 2>&1
        if ($ver -match "git version") { Write-OK "Git found: $ver"; return $true }
    } catch {}
    Write-Info "Git not found - Blackbird and SpiderFoot will be skipped."
    return $false
}

# ── Download core files ───────────────────────────────────────────────────────

function Download-Files {
    Write-Step "Downloading RECON files to: $INSTALL_DIR"
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null
    }
    $wc = New-Object System.Net.WebClient
    foreach ($file in $FILES) {
        try {
            Write-Info "Downloading $file..."
            $wc.DownloadFile("$RAW_URL/$file", "$INSTALL_DIR\$file")
        } catch {
            Write-Fail "Failed to download $file"
            Write-Info "Make sure your repo is public and all files are uploaded."
            exit 1
        }
    }
    Write-OK "All files downloaded."
}

# ── Install Python packages ───────────────────────────────────────────────────

function Install-Packages($py) {
    Write-Step "Installing core dependency (aiohttp)..."
    & $py -m pip install --quiet --upgrade aiohttp
    Write-OK "aiohttp installed."

    Write-Host ""
    $ans = Read-Host "  Install Maigret + Sherlock + Holehe for deeper scans? [Y/n]"
    if ($ans -eq "" -or $ans -match "^[Yy]") {
        Write-Step "Installing Maigret..."
        & $py -m pip install --quiet --upgrade maigret
        Write-Step "Installing Sherlock..."
        & $py -m pip install --quiet sherlock-project
        Write-Step "Installing Holehe..."
        & $py -m pip install --quiet holehe
        Write-OK "Maigret, Sherlock, and Holehe installed."
    } else {
        Write-Info "Skipped. Install later with: pip install maigret sherlock-project holehe"
    }
}

# ── Clone Blackbird ───────────────────────────────────────────────────────────

function Install-Blackbird($py, $hasGit) {
    if (-not $hasGit) { return }
    Write-Host ""
    $ans = Read-Host "  Install Blackbird (600+ extra sites)? [Y/n]"
    if ($ans -eq "" -or $ans -match "^[Yy]") {
        $dir = "$INSTALL_DIR\blackbird"
        if (Test-Path $dir) {
            Write-Info "Updating existing Blackbird..."
            Push-Location $dir; & git pull --quiet; Pop-Location
        } else {
            Write-Step "Cloning Blackbird..."
            & git clone --quiet https://github.com/p1ngul1n0/blackbird.git $dir
        }
        & $py -m pip install --quiet -r "$dir\requirements.txt"
        Write-OK "Blackbird ready."
    } else {
        Write-Info "Skipped."
    }
}

# ── Clone SpiderFoot ──────────────────────────────────────────────────────────

function Install-SpiderFoot($py, $hasGit) {
    if (-not $hasGit) { return }
    Write-Host ""
    $ans = Read-Host "  Install SpiderFoot (200+ OSINT modules)? [Y/n]"
    if (-not ($ans -eq "" -or $ans -match "^[Yy]")) {
        Write-Info "Skipped."
        return
    }

    # lxml on Windows requires pre-built wheels - try newest first, fall back
    Write-Step "Installing lxml (pre-built wheel for Windows)..."
    $lxmlOk = $false
    foreach ($ver in @("lxml==5.3.0", "lxml==5.2.2", "lxml==4.9.4", "lxml")) {
        Write-Info "Trying $ver..."
        $result = & $py -m pip install --quiet --only-binary=:all: $ver 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "lxml installed ($ver)."
            $lxmlOk = $true
            break
        }
    }

    if (-not $lxmlOk) {
        Write-Fail "Could not install lxml - SpiderFoot skipped."
        Write-Info "You can try manually: pip install lxml --only-binary=:all:"
        return
    }

    $dir = "$INSTALL_DIR\spiderfoot"
    if (Test-Path $dir) {
        Write-Info "Updating existing SpiderFoot..."
        Push-Location $dir; & git pull --quiet; Pop-Location
    } else {
        Write-Step "Cloning SpiderFoot..."
        & git clone --quiet https://github.com/smicallef/spiderfoot.git $dir
    }

    # Install SpiderFoot deps but skip lxml since we already have it
    Write-Step "Installing SpiderFoot dependencies..."
    $reqFile = "$dir\requirements.txt"
    $filteredReq = "$INSTALL_DIR\spiderfoot_requirements_filtered.txt"

    # Filter out lxml from requirements so pip doesn't try to recompile it
    Get-Content $reqFile | Where-Object { $_ -notmatch "^lxml" } | Set-Content $filteredReq

    & $py -m pip install --quiet -r $filteredReq
    Remove-Item $filteredReq -ErrorAction SilentlyContinue

    Write-OK "SpiderFoot ready."
}

# ── Create launchers ──────────────────────────────────────────────────────────

function Create-Launchers($py) {
    Write-Step "Creating launcher commands..."
    Set-Content "$INSTALL_DIR\recon.bat" "@echo off`r`n$py `"$INSTALL_DIR\recon.py`" %*" -Encoding ASCII
    Set-Content "$INSTALL_DIR\recon-web.bat" "@echo off`r`necho Starting RECON at http://localhost:8420`r`nstart http://localhost:8420`r`n$py `"$INSTALL_DIR\server.py`"" -Encoding ASCII
    Write-OK "Created: 'recon' and 'recon-web' commands."
}

# ── Add to PATH ───────────────────────────────────────────────────────────────

function Add-ToPath {
    $current = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($current -notlike "*$INSTALL_DIR*") {
        Write-Step "Adding RECON to PATH..."
        [Environment]::SetEnvironmentVariable("PATH", "$current;$INSTALL_DIR", "User")
        $env:PATH += ";$INSTALL_DIR"
        Write-OK "Added to PATH."
    } else {
        Write-OK "Already in PATH."
    }
}

# ── Done ──────────────────────────────────────────────────────────────────────

function Write-Done {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "    RECON is ready!" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Scan a username:    " -NoNewline; Write-Host "recon johndoe" -ForegroundColor White
    Write-Host "    Web UI:             " -NoNewline; Write-Host "recon-web" -ForegroundColor White
    Write-Host "    Skip WhatsMyName:   " -NoNewline; Write-Host "recon johndoe --skip-wmn" -ForegroundColor White
    Write-Host ""
    Write-Host "    Open a NEW terminal window before running." -ForegroundColor Yellow
    Write-Host ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Header
$py     = Check-Python
$hasGit = Check-Git
Download-Files
Install-Packages $py
Install-Blackbird $py $hasGit
Install-SpiderFoot $py $hasGit
Create-Launchers $py
Add-ToPath
Write-Done
