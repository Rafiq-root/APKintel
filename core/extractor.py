# core/extractor.py
# ---------------------------------------------------------------------------
# High-speed data extraction from decompiled APK output.
#   • Parses AndroidManifest.xml for metadata & permissions
#   • Concurrently scans every .java source file with regex
#   • Collects IPs, URLs, known trackers, and suspicious API calls
# ---------------------------------------------------------------------------

import os
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from rich.console import Console

console = Console()

# ---- Android XML namespace ------------------------------------------------
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# ---- Compiled regex patterns ----------------------------------------------

# IPv4 – four groups of 1-3 digits separated by dots, word-bounded
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# URLs – http or https up to the first whitespace / quote / angle-bracket
RE_URL = re.compile(r"https?://[^\s\"'<>]+")

# Tracker signatures  →  human-friendly label
TRACKER_MAP: dict[re.Pattern, str] = {
    re.compile(r"com\.google\.firebase"): "Firebase",
    re.compile(r"com\.google\.analytics"): "Google Analytics",
    re.compile(r"com\.facebook\.appevents"): "Facebook",
    re.compile(r"com\.appsflyer"): "AppsFlyer",
    re.compile(r"com\.adjust"): "Adjust",
    re.compile(r"com\.branch"): "Branch",
    re.compile(r"com\.mixpanel"): "Mixpanel",
    re.compile(r"com\.amplitude"): "Amplitude",
}

# Suspicious APIs  →  human-friendly label
SUSPICIOUS_API_MAP: dict[re.Pattern, str] = {
    re.compile(r"dalvik\.system\.DexClassLoader"): "Dynamic Loading",
    re.compile(r"dalvik\.system\.PathClassLoader"): "Dynamic Loading",
    re.compile(r"java\.lang\.reflect"): "Reflection",
    re.compile(r"java\.lang\.Runtime\.getRuntime\(\)\.exec"): "Command Execution",
    re.compile(r"android\.telephony\.SmsManager"): "SMS Sending",
}

# Max workers for the thread pool (bounded to avoid thrashing I/O)
MAX_WORKERS = 32


# ---- Data container -------------------------------------------------------

@dataclass
class ExtractionResult:
    """Aggregated findings from a single APK scan."""
    package: str = "unknown"
    version: str = "unknown"
    permissions: list[str] = field(default_factory=list)
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    trackers: set[str] = field(default_factory=set)
    capabilities: set[str] = field(default_factory=set)


# ---- Manifest parsing -----------------------------------------------------

def _parse_manifest(manifest_path: str) -> tuple[str, str, list[str]]:
    """
    Return (package_name, version_name, permissions_list) from the
    decompiled AndroidManifest.xml.
    """
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    package = root.get("package", "unknown")
    version = root.get(f"{ANDROID_NS}versionName", "unknown")

    permissions: list[str] = []
    for elem in root.iter(f"{ANDROID_NS}uses-permission"):
        name = elem.get(f"{ANDROID_NS}name")
        if name:
            permissions.append(name)
    # Fallback: some jadx versions drop the namespace prefix
    if not permissions:
        for elem in root.iter("uses-permission"):
            name = elem.get("name") or elem.get(f"{ANDROID_NS}name")
            if name:
                permissions.append(name)

    return package, version, permissions


# ---- Single-file scanner (runs inside a thread) ---------------------------

def _scan_java_file(filepath: str) -> dict:
    """
    Read one .java file and return a dict of sets for IPs, domains,
    trackers, and capabilities found within it.
    """
    result: dict = {
        "ips": set(),
        "domains": set(),
        "trackers": set(),
        "capabilities": set(),
    }
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return result

    # --- IPs ---------------------------------------------------------------
    for match in RE_IPV4.finditer(content):
        ip = match.group()
        # Filter out obvious non-routable / placeholder addresses
        if not ip.startswith(("0.", "127.", "255.")):
            result["ips"].add(ip)

    # --- URLs → extract domains -------------------------------------------
    for match in RE_URL.finditer(content):
        url = match.group().rstrip("/")
        try:
            after_scheme = url.split("://", 1)[-1]
            domain = after_scheme.split("/", 1)[0].split(":", 1)[0].lower()
            if domain and "." in domain:
                result["domains"].add(domain)
        except Exception:
            pass

    # --- Trackers ----------------------------------------------------------
    for pattern, label in TRACKER_MAP.items():
        if pattern.search(content):
            result["trackers"].add(label)

    # --- Suspicious APIs ---------------------------------------------------
    for pattern, label in SUSPICIOUS_API_MAP.items():
        if pattern.search(content):
            result["capabilities"].add(label)

    return result


# ---- Public API -----------------------------------------------------------

def extract_data(temp_dir: str) -> ExtractionResult:
    """
    Orchestrate manifest parsing + concurrent source-code scanning.

    Parameters
    ----------
    temp_dir : str
        Root of the jadx decompiled output.

    Returns
    -------
    ExtractionResult
    """
    result = ExtractionResult()

    # ---- 1. Manifest ------------------------------------------------------
    manifest_candidates = [
        os.path.join(temp_dir, "resources", "AndroidManifest.xml"),
        os.path.join(temp_dir, "AndroidManifest.xml"),
    ]
    manifest_path = next((p for p in manifest_candidates if os.path.isfile(p)), None)

    if manifest_path:
        pkg, ver, perms = _parse_manifest(manifest_path)
        result.package = pkg
        result.version = ver
        result.permissions = perms
        console.print(
            f"[cyan]Package:[/cyan] {pkg}  [cyan]Version:[/cyan] {ver}  "
            f"[cyan]Permissions:[/cyan] {len(perms)}"
        )
    else:
        console.print("[yellow]⚠ AndroidManifest.xml not found – metadata will be blank.[/yellow]")

    # ---- 2. Collect .java files -------------------------------------------
    sources_dir = os.path.join(temp_dir, "sources")
    if not os.path.isdir(sources_dir):
        # Some jadx versions put sources directly under temp_dir
        sources_dir = temp_dir

    java_files: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(sources_dir):
        for fname in filenames:
            if fname.endswith(".java"):
                java_files.append(os.path.join(dirpath, fname))

    console.print(f"[cyan]Scanning {len(java_files)} Java source files …[/cyan]")

    # ---- 3. Concurrent scan -----------------------------------------------
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_scan_java_file, fp): fp for fp in java_files}
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            if done_count % 500 == 0 or done_count == len(java_files):
                console.print(
                    f"  [dim]Progress: {done_count}/{len(java_files)} files[/dim]"
                )
            partial = future.result()
            result.ips.update(partial["ips"])
            result.domains.update(partial["domains"])
            result.trackers.update(partial["trackers"])
            result.capabilities.update(partial["capabilities"])

    console.print(
        f"[bold green]✔ Extraction done – "
        f"{len(result.ips)} IPs, {len(result.domains)} domains, "
        f"{len(result.trackers)} trackers, {len(result.capabilities)} capabilities[/bold green]"
    )
    return result