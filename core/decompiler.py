# core/decompiler.py
# ---------------------------------------------------------------------------
# Wraps the jadx CLI decompiler. Creates a temporary directory, runs jadx,
# and returns the path so downstream modules can scan the output.
# ---------------------------------------------------------------------------

import os
import shutil
import subprocess
import tempfile
from rich.console import Console

console = Console()

def verify_jadx() -> str:
    """
    Ensure the jadx binary is reachable via $PATH.
    Returns the absolute path to the binary or raises RuntimeError.
    """
    jadx_path = shutil.which("jadx")
    if not jadx_path:
        raise RuntimeError(
            "jadx binary not found in PATH. "
            "Install it from https://github.com/skylot/jadx and try again."
        )
    return jadx_path

def decompile_apk(apk_path: str, jadx_path: str | None = None) -> str:
    """
    Decompile *apk_path* into a fresh temporary directory.
    """
    if jadx_path is None:
        jadx_path = verify_jadx()

    # Create a uniquely-named temp dir under /tmp (Linux convention)
    temp_dir = tempfile.mkdtemp(prefix="apkintel_")
    console.print(f"[dim]Temp decompile dir: {temp_dir}[/dim]")

    cmd = [jadx_path, "-d", temp_dir, apk_path]
    console.print(f"[cyan]Running:[/cyan] {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    # Resilient Validation: Check if the Manifest was extracted instead of relying on exit codes.
    manifest_path = os.path.join(temp_dir, "resources", "AndroidManifest.xml")
    manifest_path_alt = os.path.join(temp_dir, "AndroidManifest.xml")

    if not (os.path.exists(manifest_path) or os.path.exists(manifest_path_alt)):
        # If no manifest exists, decompilation actually failed.
        shutil.rmtree(temp_dir, ignore_errors=True)
        error_msg = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"jadx failed catastrophically (exit {result.returncode}). No Manifest generated.\n{error_msg}"
        )

    if result.returncode != 0:
        console.print(f"[yellow]⚠ jadx returned code {result.returncode} (Partial Decompilation). Proceeding with extracted files.[/yellow]")

    console.print("[bold green]✔ Decompilation complete.[/bold green]")
    return temp_dir