# core/reporter.py
# ---------------------------------------------------------------------------
# Reporting & Cleanup
#   • Renders colour-coded tables in the terminal via rich
#   • Exports the full result dictionary to JSON and/or CSV
#   • Removes the temporary jadx directory
# ---------------------------------------------------------------------------

import csv
import json
import os
import shutil
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


# ---- Terminal rendering ---------------------------------------------------

def _severity_style(severity: str) -> str:
    """Return a rich markup colour tag for a severity level."""
    return {
        "Low": "green",
        "Medium": "yellow",
        "High": "bold red",
    }.get(severity, "white")


def report_results(data: dict[str, Any]) -> None:
    """Print a series of rich tables summarising the full analysis."""

    console.rule("[bold blue]APK Intelligence Report[/bold blue]")

    # ---- Metadata ---------------------------------------------------------
    meta_table = Table(title="Metadata", show_header=False, expand=False)
    meta_table.add_column("Key", style="cyan")
    meta_table.add_column("Value")
    meta = data.get("metadata", {})
    meta_table.add_row("Package", meta.get("package", "N/A"))
    meta_table.add_row("Version", meta.get("version", "N/A"))
    console.print(meta_table)

    # ---- Verdict ----------------------------------------------------------
    verdict = data.get("verdict", {})
    sev = verdict.get("severity", "Low")
    style = _severity_style(sev)
    verd_table = Table(title="Verdict", show_header=False, expand=False)
    verd_table.add_column("Key", style="cyan")
    verd_table.add_column("Value")
    verd_table.add_row("Score", f"{verdict.get('score', 0)} / 100")
    verd_table.add_row("Severity", f"[{style}]{sev}[/{style}]")
    console.print(verd_table)

    # ---- Permissions ------------------------------------------------------
    perms = data.get("permissions", [])
    perm_table = Table(title=f"Permissions ({len(perms)})")
    perm_table.add_column("#", style="dim", width=4)
    perm_table.add_column("Permission")
    for idx, p in enumerate(perms, 1):
        perm_table.add_row(str(idx), p)
    console.print(perm_table)

    # ---- Network IOCs -----------------------------------------------------
    network = data.get("network", {})
    ips = network.get("ips", [])
    domains = network.get("domains", [])
    malicious = {m["indicator"] for m in data.get("malicious_matches", [])}

    net_table = Table(title=f"Network IOCs ({len(ips) + len(domains)})")
    net_table.add_column("Type", style="cyan")
    net_table.add_column("Indicator")
    net_table.add_column("Malicious", justify="center")
    for ip in sorted(ips):
        flag = "[bold red]YES[/bold red]" if ip in malicious else ""
        net_table.add_row("IP", ip, flag)
    for dom in sorted(domains):
        flag = "[bold red]YES[/bold red]" if dom in malicious else ""
        net_table.add_row("Domain", dom, flag)
    console.print(net_table)

    # ---- Trackers ---------------------------------------------------------
    trackers = data.get("trackers", [])
    trk_table = Table(title=f"Known Trackers ({len(trackers)})")
    trk_table.add_column("Tracker")
    for t in sorted(trackers):
        trk_table.add_row(t)
    console.print(trk_table)

    # ---- Suspicious Capabilities ------------------------------------------
    caps = data.get("capabilities", [])
    cap_table = Table(title=f"Suspicious Capabilities ({len(caps)})")
    cap_table.add_column("Capability")
    for c in sorted(caps):
        cap_table.add_row(c)
    console.print(cap_table)

    # ---- Malicious Matches Detail -----------------------------------------
    mal_matches = data.get("malicious_matches", [])
    if mal_matches:
        mal_table = Table(title="Malicious Database Matches")
        mal_table.add_column("Indicator", style="red")
        mal_table.add_column("Threat Type")
        mal_table.add_column("Found As")
        for m in mal_matches:
            mal_table.add_row(m["indicator"], m["type"], m["source"])
        console.print(mal_table)

    console.rule()


# ---- File export ----------------------------------------------------------

def export_json(data: dict[str, Any], filepath: str) -> None:
    """Write the result dictionary to a JSON file."""
    # Convert sets to sorted lists for JSON serialisation
    serialisable = _make_serialisable(data)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(serialisable, fh, indent=2, ensure_ascii=False)
    console.print(f"[green]✔ JSON exported → {filepath}[/green]")


def export_csv(data: dict[str, Any], filepath: str) -> None:
    """
    Write the result dictionary to a CSV file.
    Format: section, key, value  (one row per data point).
    """
    serialisable = _make_serialisable(data)
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["section", "key", "value"])

        # Metadata
        for k, v in serialisable.get("metadata", {}).items():
            writer.writerow(["metadata", k, v])

        # Verdict
        verdict = serialisable.get("verdict", {})
        writer.writerow(["verdict", "score", verdict.get("score", 0)])
        writer.writerow(["verdict", "severity", verdict.get("severity", "")])

        # Permissions
        for p in serialisable.get("permissions", []):
            writer.writerow(["permission", p, ""])

        # Network
        network = serialisable.get("network", {})
        for ip in network.get("ips", []):
            writer.writerow(["network_ip", ip, ""])
        for dom in network.get("domains", []):
            writer.writerow(["network_domain", dom, ""])

        # Trackers
        for t in serialisable.get("trackers", []):
            writer.writerow(["tracker", t, ""])

        # Capabilities
        for c in serialisable.get("capabilities", []):
            writer.writerow(["capability", c, ""])

        # Malicious matches
        for m in serialisable.get("malicious_matches", []):
            writer.writerow([
                "malicious_match",
                m.get("indicator", ""),
                f"type={m.get('type', '')};source={m.get('source', '')}",
            ])

    console.print(f"[green]✔ CSV exported → {filepath}[/green]")


def _make_serialisable(obj: Any) -> Any:
    """Recursively convert sets → sorted lists for JSON/CSV output."""
    if isinstance(obj, dict):
        return {k: _make_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, list):
        return [_make_serialisable(i) for i in obj]
    return obj


# ---- Cleanup --------------------------------------------------------------

def cleanup(temp_dir: str) -> None:
    """Forcefully remove the temporary jadx output directory."""
    if temp_dir and os.path.isdir(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
        console.print(f"[dim]Cleaned up {temp_dir}[/dim]")