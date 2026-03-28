"""
RECON Engine - Core OSINT checking logic.
Used by both CLI (recon.py) and Web UI (server.py).
"""

import asyncio
import aiohttp
import json
import sys
import os
import time
import re
import shutil
import subprocess
import glob
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
from pathlib import Path

WHATSMYNAME_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CACHE_DIR = Path.home() / ".recon_cache"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


@dataclass
class Result:
    platform: str
    category: str
    profile_url: str
    exists: Optional[bool]
    confidence: float = 0.0
    source: str = "recon"
    status_code: Optional[int] = None
    response_ms: int = 0
    error: Optional[str] = None
    info: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "platform": self.platform, "category": self.category,
            "profile_url": self.profile_url, "exists": self.exists,
            "confidence": self.confidence, "source": self.source,
            "status_code": self.status_code, "response_ms": self.response_ms,
            "error": self.error, "info": self.info,
        }


# =================================================================
# BUILT-IN PLATFORMS (API-based, structured data extraction)
# =================================================================

PLATFORMS = [
    {"name":"GitHub","cat":"Developer","url":"https://api.github.com/users/{}","method":"status","ok":200,"fail":[404],"rel":0.98,"profile":"https://github.com/{}",
     "extract":{"login":"login","name":"name","bio":"bio","public_repos":"public_repos","followers":"followers","following":"following","created_at":"created_at","blog":"blog","location":"location","company":"company","twitter_username":"twitter_username","email":"email"}},
    {"name":"Reddit","cat":"Social","url":"https://www.reddit.com/user/{}/about.json","method":"status","ok":200,"fail":[404],"rel":0.95,"profile":"https://reddit.com/user/{}",
     "extract":{"name":"data.name","created_utc":"data.created_utc","total_karma":"data.total_karma","comment_karma":"data.comment_karma","verified":"data.verified"}},
    {"name":"Bluesky","cat":"Social","url":"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social","method":"status","ok":200,"fail":[400,404],"rel":0.92,"profile":"https://bsky.app/profile/{}.bsky.social",
     "extract":{"displayName":"displayName","description":"description","followersCount":"followersCount","followsCount":"followsCount","postsCount":"postsCount","createdAt":"createdAt"}},
    {"name":"GitLab","cat":"Developer","url":"https://gitlab.com/api/v4/users?username={}","method":"json_array_notempty","rel":0.95,"profile":"https://gitlab.com/{}",
     "extract_first":{"name":"name","username":"username","web_url":"web_url","created_at":"created_at","bio":"bio"}},
    {"name":"Bitbucket","cat":"Developer","url":"https://api.bitbucket.org/2.0/users/{}","method":"status","ok":200,"fail":[404],"rel":0.95,"profile":"https://bitbucket.org/{}",
     "extract":{"display_name":"display_name","created_on":"created_on"}},
    {"name":"Dev.to","cat":"Developer","url":"https://dev.to/api/users/by_username?url={}","method":"status","ok":200,"fail":[404],"rel":0.95,"profile":"https://dev.to/{}",
     "extract":{"name":"name","username":"username","joined_at":"joined_at","summary":"summary"}},
    {"name":"HackerNews","cat":"Forums","url":"https://hacker-news.firebaseio.com/v0/user/{}.json","method":"json_not_null","rel":0.98,"profile":"https://news.ycombinator.com/user?id={}",
     "extract":{"created":"created","karma":"karma","about":"about"}},
    {"name":"Chess.com","cat":"Gaming","url":"https://api.chess.com/pub/player/{}","method":"status","ok":200,"fail":[404],"rel":0.98,"profile":"https://chess.com/member/{}",
     "extract":{"username":"username","name":"name","title":"title","followers":"followers","country":"country","joined":"joined","last_online":"last_online","status":"status"}},
    {"name":"Lichess","cat":"Gaming","url":"https://lichess.org/api/user/{}","method":"status","ok":200,"fail":[404],"rel":0.98,"profile":"https://lichess.org/@/{}",
     "extract":{"username":"username","createdAt":"createdAt","seenAt":"seenAt","count.all":"count.all"}},
    {"name":"Imgur","cat":"Content","url":"https://api.imgur.com/account/v1/accounts/{}?client_id=546c25a59c58ad7","method":"status","ok":200,"fail":[404],"rel":0.92,"profile":"https://imgur.com/user/{}",
     "extract":{"bio":"bio","created_at":"created_at"}},
    {"name":"Kick","cat":"Content","url":"https://kick.com/api/v1/channels/{}","method":"status","ok":200,"fail":[404],"rel":0.92,"profile":"https://kick.com/{}",
     "extract":{"slug":"slug","verified":"verified","followers_count":"followers_count"}},
    {"name":"Keybase","cat":"Security","url":"https://keybase.io/_/api/1.0/user/lookup.json?usernames={}","method":"keybase","rel":0.95,"profile":"https://keybase.io/{}"},
    {"name":"Roblox","cat":"Gaming","url":"https://auth.roblox.com/v1/usernames/validate?birthday=2000-01-01&context=Signup&username={}","method":"roblox","rel":0.95,"profile":"https://www.roblox.com/search/users?keyword={}"},
    {"name":"Tumblr","cat":"Social","url":"https://api.tumblr.com/v2/blog/{}.tumblr.com/info?api_key=HqRvlMkmhfl0jPpXbEhpKjOOydMTMciJZpSbYPJSuL0PZhhDtJ","method":"status","ok":200,"fail":[404],"rel":0.90,"profile":"https://{}.tumblr.com",
     "extract":{"title":"response.blog.title","posts":"response.blog.posts","updated":"response.blog.updated"}},
    {"name":"Disqus","cat":"Forums","url":"https://disqus.com/api/3.0/users/details.json?user=username:{}&api_key=E8Uh5l5fHZ6gD8U3KycjAIAk46f68Zw7C6eW8WSjZvCLXebZ7p0r1yrYDrLilk2F","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://disqus.com/by/{}"},
    {"name":"Hugging Face","cat":"Developer","url":"https://huggingface.co/api/users/{}/overview","method":"status","ok":200,"fail":[404],"rel":0.95,"profile":"https://huggingface.co/{}"},
    {"name":"Twitter/X","cat":"Social","url":"https://x.com/{}","method":"status","ok":200,"fail":[404],"rel":0.65,"profile":"https://x.com/{}"},
    {"name":"Instagram","cat":"Social","url":"https://www.instagram.com/{}/","method":"status","ok":200,"fail":[404],"rel":0.55,"profile":"https://instagram.com/{}"},
    {"name":"TikTok","cat":"Social","url":"https://www.tiktok.com/@{}","method":"status","ok":200,"fail":[404],"rel":0.55,"profile":"https://tiktok.com/@{}"},
    {"name":"Pinterest","cat":"Social","url":"https://www.pinterest.com/{}/","method":"status","ok":200,"fail":[404],"rel":0.80,"profile":"https://pinterest.com/{}"},
    {"name":"YouTube","cat":"Content","url":"https://www.youtube.com/@{}","method":"status","ok":200,"fail":[404],"rel":0.70,"profile":"https://youtube.com/@{}"},
    {"name":"Medium","cat":"Content","url":"https://medium.com/@{}","method":"status","ok":200,"fail":[404,410],"rel":0.78,"profile":"https://medium.com/@{}"},
    {"name":"Substack","cat":"Content","url":"https://{}.substack.com/","method":"status","ok":200,"fail":[404],"rel":0.85,"profile":"https://{}.substack.com"},
    {"name":"SoundCloud","cat":"Content","url":"https://soundcloud.com/{}","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://soundcloud.com/{}"},
    {"name":"Last.fm","cat":"Content","url":"https://www.last.fm/user/{}","method":"status","ok":200,"fail":[404],"rel":0.92,"profile":"https://last.fm/user/{}"},
    {"name":"Bandcamp","cat":"Content","url":"https://{}.bandcamp.com/","method":"status","ok":200,"fail":[404],"rel":0.82,"profile":"https://{}.bandcamp.com"},
    {"name":"Replit","cat":"Developer","url":"https://replit.com/@{}","method":"status","ok":200,"fail":[404],"rel":0.85,"profile":"https://replit.com/@{}"},
    {"name":"CodePen","cat":"Developer","url":"https://codepen.io/{}","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://codepen.io/{}"},
    {"name":"npm","cat":"Developer","url":"https://www.npmjs.com/~{}","method":"status","ok":200,"fail":[404],"rel":0.90,"profile":"https://npmjs.com/~{}"},
    {"name":"PyPI","cat":"Developer","url":"https://pypi.org/user/{}/","method":"status","ok":200,"fail":[404],"rel":0.90,"profile":"https://pypi.org/user/{}"},
    {"name":"Kaggle","cat":"Developer","url":"https://www.kaggle.com/{}","method":"status","ok":200,"fail":[404],"rel":0.80,"profile":"https://kaggle.com/{}"},
    {"name":"Behance","cat":"Creative","url":"https://www.behance.net/{}","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://behance.net/{}"},
    {"name":"Dribbble","cat":"Creative","url":"https://dribbble.com/{}","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://dribbble.com/{}"},
    {"name":"DeviantArt","cat":"Creative","url":"https://www.deviantart.com/{}","method":"status","ok":200,"fail":[404],"rel":0.82,"profile":"https://deviantart.com/{}"},
    {"name":"ArtStation","cat":"Creative","url":"https://www.artstation.com/users/{}/quick.json","method":"status","ok":200,"fail":[404],"rel":0.95,"profile":"https://artstation.com/{}"},
    {"name":"Unsplash","cat":"Creative","url":"https://unsplash.com/@{}","method":"status","ok":200,"fail":[404],"rel":0.82,"profile":"https://unsplash.com/@{}"},
    {"name":"Flickr","cat":"Creative","url":"https://www.flickr.com/people/{}/","method":"status","ok":200,"fail":[404],"rel":0.82,"profile":"https://flickr.com/people/{}"},
    {"name":"Gravatar","cat":"Identity","url":"https://en.gravatar.com/{}.json","method":"status","ok":200,"fail":[404],"rel":0.92,"profile":"https://gravatar.com/{}"},
    {"name":"Letterboxd","cat":"Forums","url":"https://letterboxd.com/{}/","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://letterboxd.com/{}"},
    {"name":"ProductHunt","cat":"Forums","url":"https://www.producthunt.com/@{}","method":"status","ok":200,"fail":[404],"rel":0.82,"profile":"https://producthunt.com/@{}"},
    {"name":"Patreon","cat":"Commerce","url":"https://www.patreon.com/{}","method":"status","ok":200,"fail":[404],"rel":0.85,"profile":"https://patreon.com/{}"},
    {"name":"BuyMeACoffee","cat":"Commerce","url":"https://buymeacoffee.com/{}","method":"status","ok":200,"fail":[404],"rel":0.85,"profile":"https://buymeacoffee.com/{}"},
    {"name":"Etsy","cat":"Commerce","url":"https://www.etsy.com/shop/{}","method":"status","ok":200,"fail":[404],"rel":0.78,"profile":"https://etsy.com/shop/{}"},
    {"name":"Fiverr","cat":"Commerce","url":"https://www.fiverr.com/{}","method":"status","ok":200,"fail":[404],"rel":0.78,"profile":"https://fiverr.com/{}"},
    {"name":"Linktree","cat":"Identity","url":"https://linktr.ee/{}","method":"status","ok":200,"fail":[404],"rel":0.85,"profile":"https://linktr.ee/{}"},
    {"name":"About.me","cat":"Identity","url":"https://about.me/{}","method":"status","ok":200,"fail":[404],"rel":0.82,"profile":"https://about.me/{}"},
    {"name":"MyAnimeList","cat":"Gaming","url":"https://myanimelist.net/profile/{}","method":"status","ok":200,"fail":[404],"rel":0.88,"profile":"https://myanimelist.net/profile/{}"},
    {"name":"VK","cat":"Social","url":"https://vk.com/{}","method":"status","ok":200,"fail":[404],"rel":0.70,"profile":"https://vk.com/{}"},
    {"name":"Mastodon","cat":"Social","url":"https://mastodon.social/@{}","method":"status","ok":200,"fail":[404],"rel":0.80,"profile":"https://mastodon.social/@{}"},
    {"name":"WordPress","cat":"Identity","url":"https://{}.wordpress.com/","method":"status","ok":200,"fail":[404],"rel":0.70,"profile":"https://{}.wordpress.com"},
    {"name":"Steam","cat":"Gaming","url":"https://steamcommunity.com/id/{}","method":"text_absent","absent_text":"The specified profile could not be found","rel":0.88,"profile":"https://steamcommunity.com/id/{}"},
    {"name":"eBay","cat":"Commerce","url":"https://www.ebay.com/usr/{}","method":"text_absent","absent_text":"The User ID you entered was not found","rel":0.80,"profile":"https://ebay.com/usr/{}"},
    {"name":"Telegram","cat":"Messaging","url":"https://t.me/{}","method":"text_present","present_text":"tgme_page_title","rel":0.78,"profile":"https://t.me/{}"},
    {"name":"Snapchat","cat":"Social","url":"https://www.snapchat.com/add/{}","method":"text_present","present_text":"userDisplayName","rel":0.80,"profile":"https://snapchat.com/add/{}"},
]


# =================================================================
# HELPERS
# =================================================================

def extract_nested(data, path):
    for k in path.split("."):
        if isinstance(data, dict) and k in data:
            data = data[k]
        else:
            return None
    return data

def extract_info(data, mapping):
    info = {}
    for label, path in mapping.items():
        val = extract_nested(data, path)
        if val is not None and val != "" and val != []:
            if isinstance(val, str) and len(val) > 250:
                val = val[:250] + "..."
            info[label] = val
    return info

def ts_to_date(ts):
    if ts is None: return None
    try:
        if isinstance(ts, (int,float)):
            return datetime.fromtimestamp(ts/1000 if ts>1e12 else ts).strftime("%Y-%m-%d")
        if isinstance(ts, str) and "T" in ts: return ts[:10]
        return str(ts)
    except: return str(ts)


# =================================================================
# PHASE 1: BUILT-IN CHECKS
# =================================================================

async def check_builtin(session, p, username):
    url = p["url"].replace("{}", username)
    profile = p["profile"].replace("{}", username)
    r = Result(platform=p["name"], category=p["cat"], profile_url=profile, exists=None, source="recon")
    t0 = time.monotonic()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                               allow_redirects=True, headers=HEADERS, ssl=False) as resp:
            r.status_code = resp.status
            r.response_ms = int((time.monotonic()-t0)*1000)
            m = p["method"]; body = ""
            if m != "status" or "extract" in p or "extract_first" in p:
                body = await resp.text(errors="replace")
            if m == "status":
                if resp.status == p.get("ok",200): r.exists=True; r.confidence=p["rel"]*100
                elif resp.status in p.get("fail",[404]): r.exists=False; r.confidence=p["rel"]*100
                else: r.exists=None; r.confidence=25
            elif m == "text_present":
                if resp.status==200 and p["present_text"] in body: r.exists=True; r.confidence=p["rel"]*100
                else: r.exists=False; r.confidence=p["rel"]*90
            elif m == "text_absent":
                if resp.status==200 and p["absent_text"] not in body: r.exists=True; r.confidence=p["rel"]*100
                else: r.exists=False; r.confidence=p["rel"]*90
            elif m == "json_not_null":
                if resp.status==200 and body.strip() not in ("null","","{}"): r.exists=True; r.confidence=p["rel"]*100
                else: r.exists=False; r.confidence=95
            elif m == "json_array_notempty":
                try:
                    arr = json.loads(body)
                    if isinstance(arr,list) and len(arr)>0: r.exists=True; r.confidence=p["rel"]*100
                    else: r.exists=False; r.confidence=p["rel"]*100
                except: r.exists=None; r.confidence=15
            elif m == "keybase":
                try:
                    d = json.loads(body)
                    if d.get("them") and len(d["them"])>0 and d["them"][0]: r.exists=True; r.confidence=p["rel"]*100
                    else: r.exists=False; r.confidence=90
                except: r.exists=None; r.confidence=15
            elif m == "roblox":
                try:
                    d = json.loads(body)
                    if d.get("code")==2: r.exists=True; r.confidence=p["rel"]*100
                    else: r.exists=False; r.confidence=p["rel"]*100
                except: r.exists=None; r.confidence=15
            if r.exists and body:
                try:
                    jdata = json.loads(body)
                    if "extract" in p: r.info = extract_info(jdata, p["extract"])
                    elif "extract_first" in p:
                        if isinstance(jdata,list) and len(jdata)>0: r.info = extract_info(jdata[0], p["extract_first"])
                except: pass
            for key in list(r.info.keys()):
                if any(t in key.lower() for t in ["created","joined","ctime","updated","seen"]):
                    r.info[key] = ts_to_date(r.info[key])
    except asyncio.TimeoutError: r.error="Timeout"; r.response_ms=15000
    except aiohttp.ClientError as e: r.error=str(e)[:100]
    except Exception as e: r.error=str(e)[:100]
    return r

async def run_builtin_checks(username, callback=None):
    results = []
    connector = aiohttp.TCPConnector(limit=20, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_builtin(session, p, username) for p in PLATFORMS]
        done = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            done += 1
            if callback: callback("builtin", done, len(PLATFORMS), r)
    return results


# =================================================================
# PHASE 2: WHATSMYNAME DATABASE
# =================================================================

async def download_wmn_db(session):
    cache_file = CACHE_DIR / "wmn-data.json"
    CACHE_DIR.mkdir(exist_ok=True)
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
        with open(cache_file, "r", encoding="utf-8") as f: return json.load(f)
    try:
        async with session.get(WHATSMYNAME_URL, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                with open(cache_file, "w", encoding="utf-8") as f: json.dump(data, f)
                return data
    except: pass
    if cache_file.exists():
        with open(cache_file, "r", encoding="utf-8") as f: return json.load(f)
    return None

async def check_wmn_site(session, site, username):
    uri = site.get("uri_check","").replace("{account}", username)
    if not uri: return None
    r = Result(platform=site.get("name","Unknown"), category=site.get("cat","Other"),
               profile_url=uri, exists=None, source="whatsmyname")
    try:
        async with session.get(uri, timeout=aiohttp.ClientTimeout(total=10),
                               allow_redirects=True, headers=HEADERS, ssl=False) as resp:
            r.status_code = resp.status
            body = ""
            e_s = site.get("e_string",""); m_s = site.get("m_string","")
            if e_s or m_s: body = await resp.text(errors="replace")
            found = False
            if resp.status == site.get("e_code",200):
                found = (e_s in body) if e_s else True
            if m_s and m_s in body: found = False
            if resp.status == site.get("m_code",404) and not e_s: found = False
            r.exists = found; r.confidence = 75 if found else 70
    except: return None
    return r

async def run_wmn_checks(username, callback=None):
    results = []
    connector = aiohttp.TCPConnector(limit=30, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        wmn = await download_wmn_db(session)
        if not wmn: return results
        builtin_names = {p["name"].lower() for p in PLATFORMS}
        sites = [s for s in wmn.get("sites",[])
                 if s.get("name","").lower() not in builtin_names
                 and s.get("valid",True) is not False
                 and "{account}" in s.get("uri_check","")]
        total = len(sites)
        if callback: callback("wmn_start", 0, total, None)
        batch_size = 60
        for i in range(0, total, batch_size):
            batch = sites[i:i+batch_size]
            tasks = [check_wmn_site(session, s, username) for s in batch]
            batch_results = await asyncio.gather(*tasks)
            for r in batch_results:
                if r is not None: results.append(r)
            if callback: callback("wmn_progress", min(i+batch_size,total), total, None)
    return results


# =================================================================
# PHASE 3: EXTERNAL TOOLS
# =================================================================
# Each tool: find it, run it as subprocess, parse output.
# Supports: Blackbird, SpiderFoot, Maigret, Sherlock
# =================================================================

def find_tool(name):
    return shutil.which(name) is not None


def _find_script(name, filenames, extra_dirs=None):
    """Search common locations for a Python script."""
    dirs = [
        Path("."),
        Path(".."),
        Path.home(),
        Path.cwd(),
    ]
    if extra_dirs:
        dirs.extend(Path(d) for d in extra_dirs)

    for d in dirs:
        for fn in filenames:
            for sub in [name, ""]:
                p = d / sub / fn if sub else d / fn
                if p.exists():
                    return str(p.resolve())
    return None


# ── Blackbird ────────────────────────────────────────────────────

def find_blackbird():
    """Find blackbird.py — checks common locations and PATH."""
    found = _find_script("blackbird", ["blackbird.py"],
                         extra_dirs=[os.environ.get("BLACKBIRD_PATH","")])
    if found: return found
    if find_tool("blackbird"): return "blackbird"
    return None

def run_blackbird(username, search_type="username", callback=None):
    bb = find_blackbird()
    if not bb: return [], False
    CACHE_DIR.mkdir(exist_ok=True)

    if callback: callback("tool_start", 0, 0, "Blackbird")
    results = []

    try:
        cmd = ["blackbird"] if bb == "blackbird" else [sys.executable, bb]
        if search_type == "email":
            cmd.extend(["--email", username])
        else:
            cmd.extend(["--username", username])
        cmd.extend(["--csv", "--no-update"])

        cwd = str(Path(bb).parent) if bb != "blackbird" else None
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=cwd)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")

        # Parse Blackbird stdout — multiple known formats
        for line in output.splitlines():
            # Format: [+] - #ID SiteName account found - URL [status]
            m = re.search(
                r'\[\+\].*?#\d+\s+(.+?)\s+account found\s*-\s*(https?://\S+)', line)
            if not m:
                # Simpler: [+] SiteName - URL
                m = re.search(r'\[\+\]\s*(.+?)\s*-\s*(https?://\S+)', line)
            if m:
                results.append(Result(
                    platform=m.group(1).strip(), profile_url=m.group(2).strip().rstrip("]"),
                    category="Other", exists=True, confidence=82, source="blackbird"))

        # Parse CSV output files Blackbird may have created
        for pattern in [f"*{username}*.csv", "results/*.csv"]:
            for csv_path in glob.glob(pattern) + glob.glob(str(CACHE_DIR/pattern)):
                try:
                    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f.readlines()[1:]:
                            if "FOUND" not in line.upper(): continue
                            parts = [p.strip('" \t') for p in line.split(",")]
                            url = next((p for p in parts if p.startswith("http")), None)
                            if url and parts[0]:
                                results.append(Result(
                                    platform=parts[0], profile_url=url,
                                    category="Other", exists=True,
                                    confidence=82, source="blackbird"))
                except: pass

        # Parse JSON output files
        for pattern in [f"*{username}*.json"]:
            for jp in glob.glob(pattern) + glob.glob(str(CACHE_DIR/pattern)):
                try:
                    with open(jp, "r", encoding="utf-8") as f:
                        jdata = json.load(f)
                    if isinstance(jdata, list):
                        for item in jdata:
                            if isinstance(item, dict) and item.get("status") == "FOUND":
                                results.append(Result(
                                    platform=item.get("app","Unknown"),
                                    profile_url=item.get("url",""),
                                    category="Other", exists=True,
                                    confidence=82, source="blackbird",
                                    info=item.get("metadata",{}) or {}))
                except: pass

        if callback: callback("tool_done", len(results), 0, "Blackbird")
        return results, True
    except subprocess.TimeoutExpired:
        if callback: callback("tool_done", 0, 0, "Blackbird (timeout)")
        return [], True
    except Exception as e:
        if callback: callback("tool_error", 0, 0, f"Blackbird: {e}")
        return [], True


# ── SpiderFoot ───────────────────────────────────────────────────

def find_spiderfoot():
    """Find sf.py — SpiderFoot's main entry point."""
    found = _find_script("spiderfoot", ["sf.py"],
                         extra_dirs=[
                             os.environ.get("SPIDERFOOT_PATH",""),
                             "spiderfoot-4.0",
                         ])
    if found: return found
    # Check if spiderfoot is a pip-installed CLI
    if find_tool("spiderfoot"): return "spiderfoot"
    if find_tool("sf"): return "sf"
    return None

def run_spiderfoot(username, search_type="username", callback=None):
    """Run SpiderFoot CLI scan and parse JSON results.

    SpiderFoot CLI:
        python3 sf.py -s "username" -o json -u passive
    For emails:
        python3 sf.py -s "user@example.com" -o json -u passive
    """
    sf = find_spiderfoot()
    if not sf: return [], False
    CACHE_DIR.mkdir(exist_ok=True)

    if callback: callback("tool_start", 0, 0, "SpiderFoot")
    results = []

    try:
        if sf in ("spiderfoot", "sf"):
            cmd = [sf]
        else:
            cmd = [sys.executable, sf]

        # Quote the target for SpiderFoot (it auto-detects usernames)
        target = username
        cmd.extend(["-s", target, "-o", "json", "-u", "passive", "-q"])

        if callback: callback("tool_start", 0, 0, "SpiderFoot (passive scan, up to 5 min)")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                              cwd=str(Path(sf).parent) if sf not in ("spiderfoot","sf") else None)
        output = proc.stdout or ""

        # SpiderFoot JSON output is an array of event objects:
        # [{"type": "SOCIAL_MEDIA", "data": "...", "module": "sfp_accounts", "source": "..."}, ...]
        # Also can be tab-delimited: Source\tType\tSourceData\tData
        try:
            events = json.loads(output)
            if isinstance(events, list):
                for ev in events:
                    if not isinstance(ev, dict): continue
                    etype = ev.get("type","")
                    data = ev.get("data","")
                    module = ev.get("module","")
                    source_data = ev.get("source","")

                    # Social media / account / username events
                    if any(t in etype.upper() for t in [
                        "SOCIAL_MEDIA", "ACCOUNT", "USERNAME",
                        "AFFILIATE_", "EMAILADDR", "HUMAN_NAME",
                        "PHONE_NUMBER", "GEOINFO", "WEBSERVER_BANNER",
                        "LINKED_URL", "DOMAIN_NAME"
                    ]):
                        # Extract URL if present
                        url_match = re.search(r'https?://\S+', data)
                        url = url_match.group(0) if url_match else data

                        # Determine platform name from module or data
                        platform = module.replace("sfp_","").replace("_"," ").title()
                        if not platform or platform == "Accounts":
                            # Try to extract from URL
                            try:
                                from urllib.parse import urlparse
                                platform = urlparse(url).netloc.replace("www.","").split(".")[0].title()
                            except:
                                platform = etype

                        results.append(Result(
                            platform=f"SF:{platform}",
                            profile_url=url if url.startswith("http") else "",
                            category=etype.replace("_"," ").title(),
                            exists=True, confidence=78, source="spiderfoot",
                            info={"event_type": etype, "module": module, "raw": data[:200]}
                        ))
        except json.JSONDecodeError:
            # Fall back to tab-delimited parsing
            for line in output.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    src, etype, src_data, data = parts[0], parts[1], parts[2], parts[3]
                    if any(t in etype.upper() for t in ["SOCIAL","ACCOUNT","USERNAME","EMAIL"]):
                        url_match = re.search(r'https?://\S+', data)
                        results.append(Result(
                            platform=f"SF:{src.replace('sfp_','').title()}",
                            profile_url=url_match.group(0) if url_match else data,
                            category=etype.replace("_"," ").title(),
                            exists=True, confidence=78, source="spiderfoot",
                            info={"event_type": etype, "raw": data[:200]}
                        ))

        if callback: callback("tool_done", len(results), 0, "SpiderFoot")
        return results, True

    except subprocess.TimeoutExpired:
        if callback: callback("tool_done", 0, 0, "SpiderFoot (timed out after 5 min - no results)")
        return [], True
    except Exception as e:
        if callback: callback("tool_error", 0, 0, f"SpiderFoot: {e}")
        return [], True


# ── Maigret ──────────────────────────────────────────────────────

def run_maigret(username, callback=None):
    if not find_tool("maigret"): return [], False
    CACHE_DIR.mkdir(exist_ok=True)
    outfile = CACHE_DIR / f"maigret_{username}.json"

    if callback: callback("tool_start", 0, 0, "Maigret")
    results = []
    try:
        subprocess.run(
            ["maigret", username, "--json", "simple", "-o", str(outfile),
             "--timeout", "10", "--no-color"],
            capture_output=True, text=True, timeout=300)

        if outfile.exists():
            with open(outfile, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                items = data.get("results", data)
                if isinstance(items, dict):
                    for name, sd in items.items():
                        if not isinstance(sd, dict): continue
                        url = sd.get("url_user", sd.get("url",""))
                        status = str(sd.get("status",""))
                        if "Claimed" in status or sd.get("exists") is True:
                            tags = sd.get("tags",[])
                            cat = tags[0] if isinstance(tags,list) and tags else "Other"
                            info = {}
                            for k in ["fullname","bio","location","gender","links"]:
                                if sd.get(k): info[k] = sd[k]
                            results.append(Result(
                                platform=name, profile_url=url, category=cat,
                                exists=True, confidence=80, source="maigret",
                                info=info))

        if callback: callback("tool_done", len(results), 0, "Maigret")
        return results, True
    except subprocess.TimeoutExpired:
        if callback: callback("tool_done", 0, 0, "Maigret (timeout)")
        return [], True
    except Exception as e:
        if callback: callback("tool_error", 0, 0, f"Maigret: {e}")
        return [], True


# ── Sherlock ─────────────────────────────────────────────────────

def run_sherlock(username, callback=None):
    if not find_tool("sherlock"): return [], False

    if callback: callback("tool_start", 0, 0, "Sherlock")
    results = []
    try:
        proc = subprocess.run(
            ["sherlock", username, "--timeout", "10", "--print-found"],
            capture_output=True, text=True, timeout=300)

        for line in (proc.stdout or "").splitlines():
            m = re.match(r'\[\+\]\s*(.+?):\s*(https?://\S+)', line.strip())
            if m:
                results.append(Result(
                    platform=m.group(1).strip(), profile_url=m.group(2).strip(),
                    category="Other", exists=True, confidence=75, source="sherlock"))

        if callback: callback("tool_done", len(results), 0, "Sherlock")
        return results, True
    except subprocess.TimeoutExpired:
        if callback: callback("tool_done", 0, 0, "Sherlock (timeout)")
        return [], True
    except Exception as e:
        if callback: callback("tool_error", 0, 0, f"Sherlock: {e}")
        return [], True


# ── Auto-installer ───────────────────────────────────────────────

def install_tools(tools=None):
    """Install OSINT tools. tools: list of tool names or None for all."""
    available = {
        "maigret":   {"pip": "maigret"},
        "sherlock":  {"pip": "sherlock-project"},
        "holehe":    {"pip": "holehe"},
        "blackbird": {"git": "https://github.com/p1ngul1n0/blackbird.git",
                      "req": "requirements.txt"},
        "spiderfoot": {"git": "https://github.com/smicallef/spiderfoot.git",
                       "req": "requirements.txt"},
    }
    to_install = tools or list(available.keys())
    installed = []

    for name in to_install:
        spec = available.get(name)
        if not spec:
            print(f"  [!] Unknown tool: {name}")
            continue

        if "pip" in spec:
            print(f"  [*] pip install {spec['pip']}...")
            r = subprocess.run([sys.executable, "-m", "pip", "install", spec["pip"]],
                               capture_output=True, text=True)
            if r.returncode == 0:
                print(f"  [+] {name} installed via pip")
                installed.append(name)
            else:
                print(f"  [!] Failed: {r.stderr[:200]}")

        elif "git" in spec:
            target_dir = Path(name)
            if target_dir.exists():
                print(f"  [*] {name}/ already exists, skipping clone")
            else:
                print(f"  [*] git clone {spec['git']}...")
                r = subprocess.run(["git", "clone", spec["git"]],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    print(f"  [!] git clone failed: {r.stderr[:200]}")
                    continue

            if spec.get("req"):
                req_path = target_dir / spec["req"]
                if req_path.exists():
                    print(f"  [*] Installing {name} requirements...")
                    subprocess.run([sys.executable, "-m", "pip", "install",
                                    "-r", str(req_path)],
                                   capture_output=True, text=True)
            print(f"  [+] {name} installed via git clone")
            installed.append(name)

    return installed


# =================================================================
# INPUT TYPE DETECTION
# =================================================================

def detect_input_type(query):
    """Detect if input is email, phone, URL, IP, or username."""
    q = query.strip()
    if re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', q): return "email"
    if re.match(r'^\+?\d[\d\s\-()]{7,}$', q): return "phone"
    if re.match(r'^https?://', q): return "url"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', q): return "ip"
    return "username"


# =================================================================
# EMAIL-SPECIFIC OSINT CHECKS
# =================================================================

EMAIL_PLATFORMS = [
    # Services where we can check if an email is registered via password reset / signup
    {"name":"Gravatar (email)","cat":"Identity",
     "url":"https://en.gravatar.com/{}.json",
     "method":"status","ok":200,"fail":[404],"rel":0.95,
     "profile":"https://gravatar.com/{}",
     "hash_email": True,  # needs md5 hash of email
     "extract":{"displayName":"entry.0.displayName","aboutMe":"entry.0.aboutMe",
                "preferredUsername":"entry.0.preferredUsername",
                "currentLocation":"entry.0.currentLocation"}},
    {"name":"GitHub (email)","cat":"Developer",
     "url":"https://api.github.com/search/users?q={}+in:email",
     "method":"github_email","rel":0.90,
     "profile":"https://github.com/search?q={}&type=users"},
    {"name":"Spotify (signup check)","cat":"Content",
     "url":"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={}",
     "method":"spotify_email","rel":0.85,
     "profile":"https://open.spotify.com/"},
]

async def check_email_platform(session, p, email):
    """Check email-specific platforms."""
    target = email
    if p.get("hash_email"):
        import hashlib
        target = hashlib.md5(email.lower().strip().encode()).hexdigest()

    url = p["url"].replace("{}", target)
    profile = p["profile"].replace("{}", target)
    r = Result(platform=p["name"], category=p["cat"], profile_url=profile,
               exists=None, source="recon-email")

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=12),
                               allow_redirects=True, headers=HEADERS, ssl=False) as resp:
            r.status_code = resp.status
            body = await resp.text(errors="replace")
            method = p["method"]

            if method == "status":
                if resp.status == p.get("ok",200):
                    r.exists = True; r.confidence = p["rel"] * 100
                elif resp.status in p.get("fail",[404]):
                    r.exists = False; r.confidence = p["rel"] * 100
                else:
                    r.exists = None; r.confidence = 25

                if r.exists and "extract" in p:
                    try:
                        jdata = json.loads(body)
                        r.info = extract_info(jdata, p["extract"])
                    except: pass

            elif method == "github_email":
                try:
                    data = json.loads(body)
                    if data.get("total_count", 0) > 0:
                        r.exists = True; r.confidence = 90
                        items = data.get("items", [])
                        if items:
                            user = items[0]
                            r.profile_url = user.get("html_url", profile)
                            r.info = {"login": user.get("login"),
                                      "avatar": user.get("avatar_url")}
                    else:
                        r.exists = False; r.confidence = 85
                except:
                    r.exists = None; r.confidence = 15

            elif method == "spotify_email":
                try:
                    data = json.loads(body)
                    status_val = data.get("status", 0)
                    # status 20 = email already registered
                    if status_val == 20:
                        r.exists = True; r.confidence = 85
                    else:
                        r.exists = False; r.confidence = 80
                except:
                    r.exists = None; r.confidence = 15

    except: pass
    return r

async def run_email_checks(email, callback=None):
    """Run email-specific platform checks."""
    results = []
    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_email_platform(session, p, email) for p in EMAIL_PLATFORMS]
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            if callback and r.exists:
                callback("builtin", 0, 0, r)
    return results


# ── Holehe (email to account checker) ────────────────────────────

def run_holehe(email, callback=None):
    """Run holehe to check which services an email is registered on.
    holehe outputs: [+] service.com
    """
    if not find_tool("holehe"): return [], False

    if callback: callback("tool_start", 0, 0, "Holehe")
    results = []
    try:
        proc = subprocess.run(
            ["holehe", email, "--no-color"],
            capture_output=True, text=True, timeout=180)

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            # holehe format: [+] service.com exists
            m = re.match(r'\[\+\]\s*(\S+)', line)
            if m and "exists" in line.lower() or ("[+]" in line and "not" not in line.lower()):
                service = m.group(1) if m else line
                results.append(Result(
                    platform=service.strip(),
                    profile_url=f"https://{service.strip()}",
                    category="Email Registration",
                    exists=True, confidence=78, source="holehe"))

        if callback: callback("tool_done", len(results), 0, "Holehe")
        return results, True
    except subprocess.TimeoutExpired:
        if callback: callback("tool_done", 0, 0, "Holehe (timeout)")
        return [], True
    except Exception as e:
        if callback: callback("tool_error", 0, 0, f"Holehe: {e}")
        return [], True


# =================================================================
# VARIANT GENERATOR
# =================================================================

def generate_variants(username):
    base = username.lower().strip()
    variants = set()
    parts = re.split(r'[._\-]', base)
    if len(parts) > 1:
        for sep in ["","_",".","-"]:
            v = sep.join(parts)
            if v != base: variants.add(v)
    num = re.match(r'^(.+?)(\d{1,4})$', base)
    if num: variants.add(num.group(1))
    for pfx in ["real","the","official","its","iam","im","not"]:
        if base.startswith(pfx) and len(base)>len(pfx)+1: variants.add(base[len(pfx):])
        elif not base.startswith(pfx): variants.add(pfx+base)
    if base.startswith("_"): variants.add(base[1:])
    if not base.startswith("_"): variants.add("_"+base)
    for sfx in ["xo","xx","x","irl"]:
        if base.endswith(sfx) and len(base)>len(sfx)+2: variants.add(base[:-len(sfx)])
    variants.discard(base)
    return sorted(variants)[:12]


# =================================================================
# CROSS-REFERENCE LINKS
# =================================================================

def xref_links(username):
    return [
        {"tool":"WhatsMyName","url":f"https://whatsmyname.app/?q={username}","cat":"Username OSINT"},
        {"tool":"DigitalFootprint","url":"https://www.digitalfootprintcheck.com/free-checker.html","cat":"Username OSINT"},
        {"tool":"Epieos","url":f"https://epieos.com/?q={username}&t=username","cat":"Email/Username"},
        {"tool":"breach.vip","url":"https://breach.vip/","cat":"Breach DB"},
        {"tool":"search.0t.rocks","url":"https://search.0t.rocks/","cat":"Breach DB"},
        {"tool":"OSINT Framework","url":"https://osintframework.com/","cat":"Framework"},
        {"tool":"ASINT Collection","url":"https://start.me/p/b5Aow7/asint_collection","cat":"Framework"},
        {"tool":"SpiderFoot","url":"https://github.com/smicallef/spiderfoot","cat":"Framework"},
        {"tool":"Blackbird","url":"https://github.com/p1ngul1n0/blackbird","cat":"Username OSINT"},
        {"tool":"Maigret","url":"https://github.com/soxoj/maigret","cat":"Username OSINT"},
        {"tool":"Google (exact)","url":f'https://www.google.com/search?q="{username}"',"cat":"Search"},
        {"tool":"Google (social)","url":f'https://www.google.com/search?q="{username}"+site:twitter.com+OR+site:instagram.com+OR+site:reddit.com+OR+site:github.com',"cat":"Search"},
        {"tool":"Yandex","url":f'https://yandex.com/search/?text="{username}"',"cat":"Search"},
        {"tool":"Wayback Machine","url":f"https://web.archive.org/web/*/{username}*","cat":"Archives"},
        {"tool":"WhitePages","url":f"https://www.whitepages.com/name/{username}","cat":"People Search"},
        {"tool":"PeekYou","url":f"https://www.peekyou.com/{username}","cat":"People Search"},
        {"tool":"HaveIBeenPwned","url":"https://haveibeenpwned.com/","cat":"Security"},
        {"tool":"IPLocation","url":"https://iplocation.io/","cat":"IP OSINT"},
    ]


# =================================================================
# DEDUPLICATION
# =================================================================

def deduplicate(all_results):
    by_key = {}
    for r in all_results:
        key = r.platform.lower().replace(" ","").replace(".","")
        if key not in by_key:
            by_key[key] = r
        else:
            ex = by_key[key]
            if r.exists and ex.exists:
                ex.confidence = min(99, ex.confidence + 10)
                if r.source not in ex.source: ex.source += f"+{r.source}"
            if r.exists and len(r.info) > len(ex.info):
                r.confidence = ex.confidence; r.source = ex.source; by_key[key] = r
            elif r.exists and not ex.exists:
                by_key[key] = r
    return list(by_key.values())


# =================================================================
# FULL SCAN ORCHESTRATOR
# =================================================================

async def full_scan(username, skip_wmn=False, skip_external=False, callback=None):
    """Run all phases and return structured report."""
    sources = ["RECON built-in"]
    all_results = []
    input_type = detect_input_type(username)

    # Phase 1
    if callback: callback("phase", 1, 4, "Built-in platform checks")

    if input_type == "email":
        # Run email-specific checks
        if callback: callback("phase", 1, 4, "Email-specific checks")
        email_results = await run_email_checks(username, callback)
        all_results.extend(email_results)
        sources.append("Email checks")

        # Also extract username from email for username-based checks
        email_username = username.split("@")[0]
        builtin = await run_builtin_checks(email_username, callback)
        all_results.extend(builtin)
        if callback: callback("tool_done", 0, 0, f"Also checked username '{email_username}' from email")
    else:
        builtin = await run_builtin_checks(username, callback)
        all_results.extend(builtin)

    # Phase 2: WhatsMyName
    if not skip_wmn:
        if callback: callback("phase", 2, 4, "WhatsMyName database (500+ sites)")
        search_target = username.split("@")[0] if input_type == "email" else username
        wmn = await run_wmn_checks(search_target, callback)
        all_results.extend(wmn)
        sources.append("WhatsMyName")

    # Phase 3: External tools
    if not skip_external:
        if callback: callback("phase", 3, 4, "External tools (Blackbird, SpiderFoot, Maigret, Sherlock)")

        # Blackbird (supports both --username and --email)
        bb_search = "email" if input_type == "email" else "username"
        bb_results, bb_found = run_blackbird(username, search_type=bb_search, callback=callback)
        if bb_found: sources.append("Blackbird")
        all_results.extend(bb_results)
        if callback and bb_results:
            for r in bb_results: callback("ext_found", 0, 0, r)

        # SpiderFoot (auto-detects target type)
        sf_results, sf_found = run_spiderfoot(username, callback=callback)
        if sf_found: sources.append("SpiderFoot")
        all_results.extend(sf_results)
        if callback and sf_results:
            for r in sf_results: callback("ext_found", 0, 0, r)

        # Maigret (username only)
        search_target = username.split("@")[0] if input_type == "email" else username
        mg_results, mg_found = run_maigret(search_target, callback=callback)
        if mg_found: sources.append("Maigret")
        all_results.extend(mg_results)
        if callback and mg_results:
            for r in mg_results: callback("ext_found", 0, 0, r)

        # Sherlock (username only)
        sh_results, sh_found = run_sherlock(search_target, callback=callback)
        if sh_found: sources.append("Sherlock")
        all_results.extend(sh_results)
        if callback and sh_results:
            for r in sh_results: callback("ext_found", 0, 0, r)

        # Holehe (email only)
        if input_type == "email":
            ho_results, ho_found = run_holehe(username, callback=callback)
            if ho_found: sources.append("Holehe")
            all_results.extend(ho_results)
            if callback and ho_results:
                for r in ho_results: callback("ext_found", 0, 0, r)

        if not any([bb_found, sf_found, mg_found, sh_found]):
            if callback: callback("tool_error", 0, 0,
                "No external tools found. Run: python recon.py --install-tools")

    # Phase 4: Finalize
    if callback: callback("phase", 4, 4, "Deduplication & ranking")

    all_results = deduplicate(all_results)

    found = sorted([r for r in all_results if r.exists is True], key=lambda r: -r.confidence)
    not_found = [r for r in all_results if r.exists is False]
    errors = [r for r in all_results if r.exists is None]
    variants = generate_variants(username.split("@")[0] if input_type == "email" else username)
    xref = xref_links(username)

    report = {
        "target": username,
        "input_type": input_type,
        "timestamp": datetime.now().isoformat(),
        "sources": sources,
        "tools_status": {
            "blackbird": find_blackbird() is not None,
            "spiderfoot": find_spiderfoot() is not None,
            "maigret": find_tool("maigret"),
            "sherlock": find_tool("sherlock"),
            "holehe": find_tool("holehe"),
        },
        "summary": {
            "checked": len(all_results),
            "found": len(found),
            "not_found": len(not_found),
            "errors": len(errors),
        },
        "found": [r.to_dict() for r in found],
        "not_found": [r.platform for r in not_found],
        "errors": [{"platform":r.platform,"error":r.error} for r in errors],
        "variants": variants,
        "cross_reference": xref,
    }
    return report
