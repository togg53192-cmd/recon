# RECON - Multi-Source OSINT Aggregator

A real OSINT tool that makes actual HTTP requests, integrates with Blackbird/Maigret/Sherlock,
downloads the WhatsMyName database (500+ sites), and serves results in a web UI.

# Installation (Windows)

Open PowerShell and run:

```bash
powershellSet-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm https://raw.githubusercontent.com/togg53192-cmd/recon/main/install.ps1 |
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

## Quick Setup

```bash
# 1. Install Python dependency
pip install aiohttp

# 2. (Optional) Install external OSINT tools for deeper coverage
pip install maigret sherlock-project

# 3. (Optional) Install Blackbird
git clone https://github.com/p1ngul1n0/blackbird.git
cd blackbird
pip install -r requirements.txt
cd ..

# 4. Run the Web UI
python server.py
# Open http://localhost:8420 in your browser

# OR run from command line
python recon.py <username>
```

## One-liner setup
```bash
pip install aiohttp maigret sherlock-project && python recon.py --install-tools
```

## Usage

### Web UI (recommended)
```bash
python server.py
# Opens at http://localhost:8420
```

### CLI
```bash
python recon.py johndoe                    # Full scan
python recon.py johndoe --skip-wmn         # Skip WhatsMyName (faster)
python recon.py johndoe --skip-external    # Skip Blackbird/Maigret/Sherlock
python recon.py --web                      # Launch web UI
```

## What It Actually Does

### Phase 1: Built-in API checks (50+ platforms)
Direct HTTP requests to platform APIs. Extracts real profile data:
- GitHub API: name, bio, repos, followers, creation date, email, blog, company, twitter
- Reddit API: karma, account age, verification status
- Bluesky API: display name, followers, posts, creation date
- Chess.com API: rating, title, country, join date
- Lichess API: game count, creation date
- HackerNews API: karma, creation date
- And 45+ more with status code / text matching detection

### Phase 2: WhatsMyName Database (500+ sites)
Downloads the actual WhatsMyName JSON database and runs every check using
their detection logic (status codes + string matching).

### Phase 3: External Tools
Runs installed tools as subprocesses and merges their results:
- **Blackbird**: Parses CLI output for found accounts
- **Maigret**: Parses JSON output for claimed profiles
- **Sherlock**: Parses stdout for found URLs

### Deduplication & Cross-referencing
When multiple sources find the same platform, confidence gets boosted.
The richest data version is kept.

## Cross-Reference Tools (clickable links in results)
- WhatsMyName, DigitalFootprint, Epieos
- breach.vip, search.0t.rocks
- OSINT Framework, ASINT Collection, SpiderFoot
- Google dorks, Yandex, Wayback Machine
- WhitePages, PeekYou, HaveIBeenPwned, IPLocation

## Files
- `recon_engine.py` - Core scanning engine
- `server.py` - Web UI server (http://localhost:8420)
- `recon.py` - CLI interface
- `README.md` - This file

## Export Formats
- JSON (full structured data)
- CSV (platform, category, URL, confidence, source)
- TXT (human-readable report)
