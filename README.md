# RECON - Multi-Source OSINT Aggregator

Aggregates results from 6 sources into one tool with a browser UI.

# Installation (Windows)

Open PowerShell and run:

```bash
powershellSet-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm https://raw.githubusercontent.com/togg53192-cmd/recon/main/install.ps1 | iex
```
# Usage

Web UI (recommended)

```bash
powershellrecon-web
```
Opens a browser at http://localhost:8420. Keep the terminal window open while using it. Search Can take around 5 min or more

# Command Line

```bash
recon johndoe
```
 Full scan

```bash
recon johndoe --skip-wmn      
```
Skip WhatsMyName (faster)

```bash
recon johndoe --skip-external  
```
Skip Blackbird/Maigret/Sherlock

## Uninstall

Delete the folder C:\Users\<you>\recon and remove it from your PATH in System Settings.
## Quick Start

```bash
pip install aiohttp
python server.py
# Open http://localhost:8420
```

## Full Setup (maximum coverage)

```bash
# 1. Core dependency
pip install aiohttp

# 2. Auto-install all external tools at once
python recon.py --install-tools

# OR install each manually:

# Blackbird (600+ sites)
git clone https://github.com/p1ngul1n0/blackbird.git
cd blackbird && pip install -r requirements.txt && cd ..

# SpiderFoot (200+ OSINT modules)
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot && pip install -r requirements.txt && cd ..

# Maigret (2000+ sites)
pip install maigret

# Sherlock (400+ sites)
pip install sherlock-project

# 3. Launch
python server.py           # Web UI at http://localhost:8420
python recon.py <username>  # CLI mode
```

## How Each Tool Is Integrated

| Tool | How it runs | What it parses |
|------|-------------|----------------|
| Built-in | Direct HTTP to 50+ APIs | JSON data (GitHub, Reddit, Bluesky, Chess.com, etc.) |
| WhatsMyName | Downloads DB, checks 500+ sites | Status codes + string matching |
| Blackbird | `python blackbird.py --username X --csv` | stdout + CSV/JSON files |
| SpiderFoot | `python sf.py -s "X" -o json -u passive` | JSON events (SOCIAL_MEDIA, ACCOUNT, etc.) |
| Maigret | `maigret X --json simple -o out.json` | JSON claimed profiles |
| Sherlock | `sherlock X --print-found` | stdout `[+] Site: URL` lines |

## CLI

```bash
python recon.py <username>              # Full scan
python recon.py <username> --skip-wmn   # Skip WhatsMyName
python recon.py <username> --skip-external  # Skip external tools
python recon.py --install-tools         # Auto-install everything
python recon.py --web                   # Launch web UI
```

## Environment Variables

- `BLACKBIRD_PATH` - Custom path to Blackbird directory
- `SPIDERFOOT_PATH` - Custom path to SpiderFoot directory
