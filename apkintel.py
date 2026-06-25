#!/usr/bin/env python3
# apkintel.py
# ---------------------------------------------------------------------------
# APK Intelligence CLI  –  Main entry point
#
# Usage examples:
#   python apkintel.py sample.apk
#   python apkintel.py sample.apk --export-json results.json
#   python apkintel.py sample.apk --export-csv results.csv
#   python apkintel.py --update-db
#   python apkintel.py sample.apk --update-db --export-json out.json
# ---------------------------------------------------------------------------

import argparse
import os
import sys
import zipfile

from rich.console import Console

# ---- Project modules ------------------------------------------------------
from core.updater import update_database
from core.decompiler import verify_jadx, decompile_apk
from core.extractor import extract_data
from core.analyzer import match_threats
from core.scorer import calculate_score
from core.reporter import (
    report_results,
    export_json,
    export_csv,
    cleanup,
)

console = Console()

# ---- Constants ------------------------------------------------------------
DB_PATH = os.path.join(os.getcwd(), "threat_intel.db")


# ---- Helpers --------------------------------------------------------------

def _validate_apk(path: str) -> None:
    """Raise SystemExit if *path* is not a valid ZIP / APK archive."""
    if not os.path.isfile(path):
        console.print(f"[red]✗ File not found: {path}[/red]")
        sys.exit(1)
    if not zipfile.is_zipfile(path):
        console.print(f"[red]✗ Not a valid ZIP/APK archive: {path}[/red]")
        sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apkintel",
        description="APK Intelligence CLI – Static analysis & threat scoring for Android APKs.",
    )
    parser.add_argument(
        "apk",
        nargs="?",
        default=None,
        help="Path to the target .apk file.",
    )
    parser.add_argument(
        "--export-json",
        metavar="FILE",
        help="Export the full result dictionary to a JSON file.",
    )
    parser.add_argument(
        "--export-csv",
        metavar="FILE",
        help="Export the full result dictionary to a CSV file.",
    )
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Refresh the local threat-intelligence SQLite database from OSINT feeds.",
    )
    return parser


# ---- Main pipeline --------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # ---- Optional: update threat DB first ---------------------------------
    if args.update_db:
        console.print("\n[bold blue]━━━ Threat Database Update ━━━[/bold blue]")
        update_database()
        if args.apk is None:
            # User only wanted to update the DB – exit cleanly
            return

    # ---- Require an APK for analysis --------------------------------------
    if args.apk is None:
        parser.print_help()
        sys.exit(0)
    BANNER = r"""
       ___  ____  __ __  ____      __       __ 
      / _ |/ __ \/ //_/ /  _/__   / /____  / / 
     / __ / /_/ / ,<   _/ // _ \ / __/ -_)/ /  
    /_/ |_\____/_/|_| /___/_//_/ \__/\__//_/   
                                               
    Static Analysis & Threat Scoring Engine
    """
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print("[bold blue]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold blue]\n")
    console.print("\n[bold blue]━━━ APK Intelligence CLI ━━━[/bold blue]")

    # ---- Step 1: Input validation -----------------------------------------
    console.print("\n[bold]Step 1 – Validation[/bold]")
    _validate_apk(args.apk)
    apk_path = os.path.abspath(args.apk)
    console.print(f"  Target: [cyan]{apk_path}[/cyan]")

    jadx_path = verify_jadx()
    console.print(f"  jadx:   [cyan]{jadx_path}[/cyan]")

    if not os.path.isfile(DB_PATH):
        console.print(
            f"[yellow]⚠ {DB_PATH} not found. "
            "Threat matching will be skipped. Run with --update-db to create it.[/yellow]"
        )

    # ---- Step 2: Decompilation --------------------------------------------
    console.print("\n[bold]Step 2 – Decompilation[/bold]")
    temp_dir: str | None = None
    try:
        temp_dir = decompile_apk(apk_path, jadx_path)

        # ---- Step 3: Extraction -------------------------------------------
        console.print("\n[bold]Step 3 – Data Extraction[/bold]")
        extraction = extract_data(temp_dir)

        # ---- Step 4: Threat matching --------------------------------------
        console.print("\n[bold]Step 4 – Threat Matching[/bold]")
        malicious_matches = match_threats(extraction.ips, extraction.domains)

        # ---- Step 5: Scoring ----------------------------------------------
        console.print("\n[bold]Step 5 – Scoring[/bold]")
        verdict = calculate_score(
            permissions=extraction.permissions,
            capabilities=extraction.capabilities,
            trackers=extraction.trackers,
            malicious_matches=malicious_matches,
        )

        # ---- Assemble final result dictionary -----------------------------
        result: dict = {
            "metadata": {
                "package": extraction.package,
                "version": extraction.version,
            },
            "verdict": {
                "score": verdict["score"],
                "severity": verdict["severity"],
            },
            "permissions": sorted(extraction.permissions),
            "network": {
                "ips": sorted(extraction.ips),
                "domains": sorted(extraction.domains),
            },
            "trackers": sorted(extraction.trackers),
            "capabilities": sorted(extraction.capabilities),
            "malicious_matches": malicious_matches,
        }

        # ---- Step 6: Reporting & export -----------------------------------
        console.print()
        report_results(result)

        if args.export_json:
            export_json(result, args.export_json)
        if args.export_csv:
            export_csv(result, args.export_csv)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    except Exception as exc:
        console.print(f"\n[bold red]Fatal error: {exc}[/bold red]")
        raise
    finally:
        # ---- Cleanup ------------------------------------------------------
        if temp_dir:
            cleanup(temp_dir)


if __name__ == "__main__":
    main()