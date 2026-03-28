#!/usr/bin/env python3
"""
RECON CLI - Command-line OSINT scanner.
Usage: python recon.py <username>
"""
import asyncio, sys, os, json, argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recon_engine import full_scan, find_blackbird, find_tool, PLATFORMS, generate_variants

def cli_callback(event, current, total, detail):
    if event == "phase":
        print(f"\n  --- Phase {current}/{total}: {detail} ---\n", flush=True)
    elif event == "builtin":
        if detail and detail.exists:
            info_str = ""
            if detail.info:
                preview = [(k,v) for k,v in list(detail.info.items())[:3]
                           if not any(s in k.lower() for s in ["avatar","icon","image","img"])]
                if preview: info_str = " | " + " | ".join(f"{k}={v}" for k,v in preview)
            print(f"  [+] {detail.platform:<20} FOUND ({detail.confidence:.0f}%) -> {detail.profile_url}{info_str}")
        elif current % 15 == 0 or current == total:
            print(f"      [{current}/{total}] checked...", flush=True)
    elif event == "wmn_start":
        print(f"  [*] WhatsMyName: scanning {total} sites...", flush=True)
    elif event == "wmn_progress":
        if current % 100 == 0 or current == total:
            print(f"      [{current}/{total}] checked...", flush=True)

async def main():
    parser = argparse.ArgumentParser(description="RECON - Multi-Source OSINT Aggregator")
    parser.add_argument("username", nargs="?", help="Username to investigate")
    parser.add_argument("--skip-wmn", action="store_true")
    parser.add_argument("--skip-external", action="store_true")
    parser.add_argument("--web", action="store_true", help="Launch web UI instead")
    parser.add_argument("--install-tools", action="store_true")
    args = parser.parse_args()

    if args.install_tools:
        import subprocess
        for pkg in ["maigret", "sherlock-project", "aiohttp"]:
            print(f"  Installing {pkg}...")
            subprocess.run([sys.executable, "-m", "pip", "install", pkg], capture_output=True)
        print("  Done. You can also: git clone https://github.com/p1ngul1n0/blackbird.git")
        return

    if args.web:
        from server import main as serve
        serve()
        return

    if not args.username:
        parser.print_help()
        return

    username = args.username.strip()
    print(f"\n{'='*70}")
    print(f"  RECON - Multi-Source OSINT Aggregator")
    print(f"  Target:    {username}")
    print(f"  Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Built-in:  {len(PLATFORMS)} platforms")
    print(f"  Blackbird: {'YES' if find_blackbird() else 'no  (git clone https://github.com/p1ngul1n0/blackbird.git)'}")
    print(f"  Maigret:   {'YES' if find_tool('maigret') else 'no  (pip install maigret)'}")
    print(f"  Sherlock:  {'YES' if find_tool('sherlock') else 'no  (pip install sherlock-project)'}")
    print(f"{'='*70}")

    report = await full_scan(username, skip_wmn=args.skip_wmn,
                             skip_external=args.skip_external, callback=cli_callback)

    print(f"\n{'='*70}")
    print(f"  RESULTS: {report['summary']['found']} found | {report['summary']['not_found']} not found | {report['summary']['errors']} errors")
    print(f"  Sources: {', '.join(report['sources'])}")
    print(f"{'='*70}\n")

    for r in report["found"]:
        bar = "#" * int(r["confidence"]/10) + "-" * (10-int(r["confidence"]/10))
        print(f"  [{bar}] {r['confidence']:5.0f}%  {r['platform']:<22} [{r['source']}]")
        print(f"          -> {r['profile_url']}")
        for k,v in r.get("info",{}).items():
            if any(s in k.lower() for s in ["avatar","icon","image","img","banner"]): continue
            print(f"             {k}: {v}")
        print()

    print(f"  Variants: {', '.join('@'+v for v in report['variants'])}")
    print(f"\n  Cross-reference:")
    for t in report["cross_reference"]:
        print(f"    [{t['tool']}] {t['url']}")

    # Save
    with open(f"recon_{username}.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str, ensure_ascii=False)
    print(f"\n  Saved: recon_{username}.json\n")

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
