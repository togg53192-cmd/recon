#!/usr/bin/env python3
"""
RECON CLI - Command-line OSINT scanner.
Usage: python recon.py <username>
"""
import asyncio, sys, os, json, argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recon_engine import (full_scan, find_blackbird, find_spiderfoot, find_tool,
                         PLATFORMS, generate_variants, install_tools, detect_input_type)

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
    elif event == "tool_start":
        print(f"  [*] Running {detail}...", flush=True)
    elif event == "tool_done":
        print(f"  [+] {detail}: {current} accounts found")
    elif event == "tool_error":
        print(f"  [!] {detail}")
    elif event == "ext_found":
        if detail and hasattr(detail, 'platform'):
            print(f"      [+] {detail.platform:<20} -> {detail.profile_url}")

async def main():
    parser = argparse.ArgumentParser(description="RECON - Multi-Source OSINT Aggregator")
    parser.add_argument("username", nargs="?", help="Username to investigate")
    parser.add_argument("--skip-wmn", action="store_true")
    parser.add_argument("--skip-external", action="store_true")
    parser.add_argument("--web", action="store_true", help="Launch web UI instead")
    parser.add_argument("--install-tools", action="store_true")
    args = parser.parse_args()

    if args.install_tools:
        print("\n  Installing OSINT tools...\n")
        install_tools()
        print("\n  Done! Now run: python recon.py <username>")
        return

    if args.web:
        from server import main as serve
        serve()
        return

    if not args.username:
        parser.print_help()
        return

    username = args.username.strip()
    input_type = detect_input_type(username)

    from recon_engine import get_tool_debug_info, SCRIPT_DIR
    debug = get_tool_debug_info()

    print(f"\n{'='*70}")
    print(f"  RECON - Multi-Source OSINT Aggregator")
    print(f"  Target:      {username}")
    print(f"  Type:        {input_type}")
    print(f"  Time:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Script dir:  {SCRIPT_DIR}")
    print(f"  Built-in:    {len(PLATFORMS)} platforms")
    bb = find_blackbird()
    sf = find_spiderfoot()
    print(f"  Blackbird:   {bb or 'NOT FOUND'}")
    print(f"  SpiderFoot:  {sf or 'NOT FOUND'}")
    print(f"  Maigret:     {'YES' if find_tool('maigret') else 'NOT FOUND'}")
    print(f"  Sherlock:    {'YES' if find_tool('sherlock') else 'NOT FOUND'}")
    print(f"  Holehe:      {'YES' if find_tool('holehe') else 'NOT FOUND'}")
    if not bb or not sf:
        print(f"")
        print(f"  TIP: Clone tools into {SCRIPT_DIR}")
        if not bb: print(f"    git clone https://github.com/p1ngul1n0/blackbird.git")
        if not sf: print(f"    git clone https://github.com/smicallef/spiderfoot.git")
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
