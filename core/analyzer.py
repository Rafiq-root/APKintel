# core/analyzer.py
# ---------------------------------------------------------------------------
# Threat Matching – compares extracted IOCs (IPs & domains) against the
# local SQLite threat-intelligence database.
# ---------------------------------------------------------------------------

import os
import sqlite3
from rich.console import Console

console = Console()

DB_PATH = os.path.join(os.getcwd(), "threat_intel.db")

# ---- Allowlist ------------------------------------------------------------
# Domains that are universally trusted and should never trigger a threat match.
TRUSTED_DOMAINS: set[str] = {
    "github.com",
    "raw.githubusercontent.com",
    "developer.android.com",
    "schemas.android.com",
    "en.wikipedia.org",
    "f-droid.org",
    "example.com",
    "example.org",
    "ns.adobe.com",
    "xml.org",
    "goo.gle",
    "issuetracker.google.com",
    "play.google.com",
    "w3.org"
}

def match_threats(
    ips: set[str],
    domains: set[str],
    db_path: str = DB_PATH,
) -> list[dict]:
    """
    Query *malicious_network* for every extracted IP and domain.
    Batches lookups to prevent SQLite variable overflow limits.
    Filters out trusted domains prior to querying.
    """
    if not os.path.isfile(db_path):
        console.print(
            "[yellow]⚠ threat_intel.db not found – skipping threat matching. "
            "Run with --update-db first.[/yellow]"
        )
        return []

    # Apply Allowlist Filter
    filtered_domains = {d for d in domains if d not in TRUSTED_DOMAINS and not d.endswith(".local")}
    
    # Calculate the number of dropped domains for terminal visibility
    dropped_count = len(domains) - len(filtered_domains)
    if dropped_count > 0:
        console.print(f"[dim]Excluded {dropped_count} trusted domain(s) from threat lookup.[/dim]")

    matches: list[dict] = []
    all_indicators = list(ips | filtered_domains)

    if not all_indicators:
        return matches

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Batch indicators into sets of 500 to prevent 'too many SQL variables' error
    batch_size = 500
    hit_indicators: set[str] = set()

    for i in range(0, len(all_indicators), batch_size):
        batch = all_indicators[i : i + batch_size]
        placeholders = ",".join("?" for _ in batch)
        query = f"""
            SELECT indicator, type
              FROM malicious_network
             WHERE indicator IN ({placeholders})
        """
        cursor.execute(query, batch)

        for row in cursor.fetchall():
            ind = row["indicator"]
            if ind not in hit_indicators:
                hit_indicators.add(ind)
                source = "ip" if ind in ips else "domain"
                matches.append({
                    "indicator": ind,
                    "type": row["type"],
                    "source": source,
                })

    conn.close()

    if matches:
        console.print(
            f"[bold red]⚠ {len(matches)} malicious indicator(s) matched "
            f"in threat database![/bold red]"
        )
    else:
        console.print("[green]✔ No malicious indicators found in database.[/green]")

    return matches