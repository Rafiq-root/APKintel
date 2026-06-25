# core/updater.py
# ---------------------------------------------------------------------------
# Threat Feed Updater
# Stand-alone module that downloads OSINT indicators (IPs / domains) from
# public feeds and refreshes the local SQLite threat-intelligence database.
# ---------------------------------------------------------------------------

import os
import sqlite3
import urllib.request
import urllib.error
from rich.console import Console

console = Console()

# ---- Configuration --------------------------------------------------------

DB_PATH = os.path.join(os.getcwd(), "threat_intel.db")

# Public OSINT feeds.  Each entry is a dict with:
#   url    – raw-text feed URL (one indicator per line, or URLhaus CSV/text)
#   type   – classification tag written into the 'type' column
#   kind   – 'domain' | 'ip' | 'url'  (how to parse each line)
FEEDS = [
    {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "malware",
        "kind": "url",          # extract domain from each URL line
    },
    {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "malware",
        "kind": "ip",           # plain IP list (lines starting with '#' are comments)
    },
]

# ---- Database helpers -----------------------------------------------------

def _ensure_db(conn: sqlite3.Connection) -> None:
    """Create the malicious_network table if it does not yet exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS malicious_network (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT    NOT NULL,
            type      TEXT    NOT NULL,
            UNIQUE(indicator, type)
        )
        """
    )
    conn.commit()


def _flush_old_records(conn: sqlite3.Connection) -> None:
    """Delete every row so the table is rebuilt from fresh feeds."""
    conn.execute("DELETE FROM malicious_network")
    conn.commit()


# ---- Feed parsers ---------------------------------------------------------

def _extract_domain_from_url(raw_url: str) -> str | None:
    """Return the hostname portion of a URL, or None on failure."""
    try:
        # Handle lines that may have leading/trailing whitespace
        raw_url = raw_url.strip()
        if not raw_url or raw_url.startswith("#"):
            return None
        # Quick parse – works for http(s)://host/...
        after_scheme = raw_url.split("://", 1)[-1]
        domain = after_scheme.split("/", 1)[0].split(":", 1)[0]
        return domain.lower() if domain else None
    except Exception:
        return None


def _parse_feed_lines(lines: list[str], kind: str) -> set[str]:
    """Return a deduplicated set of indicators extracted from raw text lines."""
    indicators: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if kind == "url":
            domain = _extract_domain_from_url(line)
            if domain:
                indicators.add(domain)
        elif kind == "ip":
            # Very light validation – four dot-separated numbers
            parts = line.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                indicators.add(line)
        elif kind == "domain":
            indicators.add(line.lower())
    return indicators


# ---- Public API -----------------------------------------------------------

def update_database(db_path: str = DB_PATH) -> int:
    """
    Download every configured feed, parse indicators, and rebuild the
    malicious_network table.  Returns the total number of indicators stored.
    """
    console.print(f"[bold cyan]Target database:[/bold cyan] {db_path}")

    conn = sqlite3.connect(db_path)
    _ensure_db(conn)
    _flush_old_records(conn)

    total_inserted = 0

    for feed in FEEDS:
        console.print(f"  [yellow]→[/yellow] Fetching {feed['url']} ...")
        try:
            req = urllib.request.Request(
                feed["url"],
                headers={"User-Agent": "APKIntel-CLI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as exc:
            console.print(f"    [red]✗ Feed unavailable ({exc}). Skipping.[/red]")
            continue

        indicators = _parse_feed_lines(raw.splitlines(), feed["kind"])
        console.print(f"    Parsed [green]{len(indicators)}[/green] unique indicators.")

        # Batch insert (INSERT OR IGNORE to honour the UNIQUE constraint)
        rows = [(ind, feed["type"]) for ind in indicators]
        conn.executemany(
            "INSERT OR IGNORE INTO malicious_network (indicator, type) VALUES (?, ?)",
            rows,
        )
        conn.commit()
        total_inserted += len(indicators)

    conn.close()
    console.print(
        f"[bold green]✔ Database updated – {total_inserted} indicators stored.[/bold green]"
    )
    return total_inserted


# Allow running directly:  python -m core.updater
if __name__ == "__main__":
    update_database()