# core/scorer.py
# ---------------------------------------------------------------------------
# Deterministic Scoring Engine
# Produces a 0-100 risk score and a Low / Medium / High verdict.
# ---------------------------------------------------------------------------

from rich.console import Console

console = Console()

# ---- Scoring weights (from specification) ---------------------------------

CRITICAL_PERMISSIONS: set[str] = {
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
}

WEIGHT_CRITICAL_PERM = 15   # +15 per critical permission
WEIGHT_HIGH_RISK_API = 10   # +10 per suspicious capability
WEIGHT_TRACKER       = 5    # +5 per known tracker
WEIGHT_MALICIOUS_HIT = 30   # +30 if ANY malicious DB match exists

SCORE_MAX = 100


def calculate_score(
    permissions: list[str],
    capabilities: set[str],
    trackers: set[str],
    malicious_matches: list[dict],
) -> dict:
    """
    Compute the risk score and human-readable verdict.

    Returns
    -------
    dict
        ``{"score": int, "severity": str, "breakdown": dict}``
    """
    score = 0
    breakdown: dict[str, int] = {}

    # --- Critical permissions ----------------------------------------------
    crit_perms = [p for p in permissions if p in CRITICAL_PERMISSIONS]
    perm_points = len(crit_perms) * WEIGHT_CRITICAL_PERM
    breakdown["critical_permissions"] = perm_points
    score += perm_points

    # --- High-risk APIs / capabilities -------------------------------------
    api_points = len(capabilities) * WEIGHT_HIGH_RISK_API
    breakdown["high_risk_apis"] = api_points
    score += api_points

    # --- Known trackers ----------------------------------------------------
    tracker_points = len(trackers) * WEIGHT_TRACKER
    breakdown["trackers"] = tracker_points
    score += tracker_points

    # --- Malicious DB match ------------------------------------------------
    if malicious_matches:
        breakdown["malicious_db_match"] = WEIGHT_MALICIOUS_HIT
        score += WEIGHT_MALICIOUS_HIT
    else:
        breakdown["malicious_db_match"] = 0

    # --- Clamp & classify --------------------------------------------------
    score = min(score, SCORE_MAX)

    if score <= 30:
        severity = "Low"
    elif score <= 60:
        severity = "Medium"
    else:
        severity = "High"

    console.print(
        f"[bold]Risk Score:[/bold] {score}/100  "
        f"[bold]Severity:[/bold] {severity}"
    )

    return {
        "score": score,
        "severity": severity,
        "breakdown": breakdown,
    }