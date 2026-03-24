#!/usr/bin/env python3
"""
File Type Identifier CLI
Usage:
    python cli.py <file_or_directory> [options]

Options:
    -r, --recursive     Scan directories recursively
    -v, --verbose       Show header hex dump and all matches
    -j, --json          Output results as JSON
    -s, --summary       Show summary only (no per-file output)
    --risk-only         Only show MISMATCH / HIGH_RISK files
"""

import sys
import json
import argparse
from pathlib import Path
from file_identifier import (
    analyze_file,
    analyze_directory,
    print_result,
    print_summary,
)

BANNER = r"""
 _____ _ _      _____                    _____    _            _   _  __ _           
|  ___(_) | ___|_   _|   _ _ __   ___   |_   _|__| | ___ _ __ | |_(_)/ _(_) ___ _ __
| |_  | | |/ _ \ | || | | | '_ \ / _ \    | |/ _` |/ _ \ '_ \| __| | |_| |/ _ \ '__|
|  _| | | |  __/ | || |_| | |_) |  __/    | | (_| |  __/ | | | |_| |  _| |  __/ |   
|_|   |_|_|\___| |_| \__, | .__/ \___|    |_|\__,_|\___|_| |_|\__|_|_| |_|\___|_|   
                      |___/|_|                                                         
  Magic Bytes Inspector  ·  Mismatch Detector  ·  Disguised File Hunter
"""


def main():
    parser = argparse.ArgumentParser(
        description="Identify file types via magic bytes and detect disguised files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="File or directory to analyze")
    parser.add_argument("-r", "--recursive", action="store_true", help="Scan directory recursively")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show hex dump and all matches")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-s", "--summary", action="store_true", help="Summary only")
    parser.add_argument("--risk-only", action="store_true", help="Show only MISMATCH / HIGH_RISK files")

    args = parser.parse_args()
    target = Path(args.target)

    if not args.json:
        print(BANNER)

    # Collect results
    if target.is_file():
        results = [analyze_file(str(target))]
    elif target.is_dir():
        results = analyze_directory(str(target), recursive=args.recursive)
    else:
        print(f"[ERROR] Target not found: {target}", file=sys.stderr)
        sys.exit(1)

    # JSON output mode
    if args.json:
        print(json.dumps(results, indent=2, default=str))
        return

    # Filter if --risk-only
    display_results = results
    if args.risk_only:
        display_results = [r for r in results if r.get("verdict") in ("MISMATCH", "HIGH_RISK")]

    # Per-file output
    if not args.summary:
        for r in display_results:
            print_result(r, verbose=args.verbose)

    # Always show summary for multi-file scans
    if len(results) > 1 or args.summary:
        print_summary(results)

    # Exit code: non-zero if any HIGH_RISK found
    high_risk = any(r.get("verdict") in ("HIGH_RISK", "MISMATCH") for r in results)
    sys.exit(1 if high_risk else 0)


if __name__ == "__main__":
    main()
