"""
dwforsec tools [status|install|update]

External offensive tool manager.
"""
import asyncio
import sys
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from dwforsec.core.config import BASE_DIR

app = typer.Typer(
    help="External tool manager (install / update / status)",
    context_settings={"help_option_names": ["-h", "--help"]},
)

TOOLS_LIST = {
    "subfinder":   "https://github.com/projectdiscovery/subfinder",
    "assetfinder": "https://github.com/tomnomnom/assetfinder",
    "httpx":       "https://github.com/projectdiscovery/httpx",
    "naabu":       "https://github.com/projectdiscovery/naabu",
    "nuclei":      "https://github.com/projectdiscovery/nuclei",
    "katana":      "https://github.com/projectdiscovery/katana",
    "amass":       "https://github.com/owasp-amass/amass",
    "whatweb":     "https://github.com/urbanadventurer/WhatWeb",
    "wafw00f":     "https://github.com/EnableSecurity/wafw00f",
    "gau":         "https://github.com/lc/gau",
    "waybackurls": "https://github.com/tomnomnom/waybackurls",
    "hakrawler":   "https://github.com/hakluke/hakrawler",
    "sslscan":     "https://github.com/rbsec/sslscan",
    "testssl.sh":  "https://github.com/drwetter/testssl.sh",
}


def _is_installed(name: str) -> bool:
    if shutil.which(name):
        return True
    tools_dir = Path(BASE_DIR) / "dwforsec" / "tools"
    for ext in [".exe", ".bat", ".cmd", ""]:
        if (tools_dir / name / f"{name}{ext}").exists():
            return True
    return False


@app.command(
    "status",
    help="Show install status of all offensive security tools.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
def status():
    console = Console(highlight=False)

    installed = sum(1 for n in TOOLS_LIST if _is_installed(n))
    total = len(TOOLS_LIST)

    console.print(f"\n[bold cyan]Tools Status[/bold cyan]  —  "
                  f"[bold green]{installed}[/bold green] / {total} installed\n")

    t = Table(border_style="cyan", header_style="bold cyan", show_lines=False)
    t.add_column("Tool",       style="bold white",  min_width=14)
    t.add_column("Status",     min_width=12)
    t.add_column("Repository", style="dim white")

    for name, repo in TOOLS_LIST.items():
        if _is_installed(name):
            status_str = "[bold green]Installed[/bold green]"
        else:
            status_str = "[bold red]Missing[/bold red]  "
        t.add_row(name, status_str, repo)

    console.print(t)
    console.print(
        f"\n[dim]  Run [cyan]dwforsec tools install[/cyan] to clone and build all tools.[/dim]\n"
    )


@app.command(
    "install",
    help="Clone and build all offensive security tools.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
def install():
    console = Console(highlight=False)
    is_windows = sys.platform == "win32"

    if is_windows:
        script = Path(BASE_DIR) / "scripts" / "install-tools.ps1"
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    else:
        script = Path(BASE_DIR) / "scripts" / "install-tools.sh"
        try:
            script.chmod(0o755)
        except Exception:
            pass
        cmd = [str(script)]

    console.print(f"[bold cyan]›[/bold cyan]  Running installer: [dim]{script}[/dim]")

    from dwforsec.utils.subprocess_runner import run_subprocess
    code, stdout, stderr = asyncio.run(run_subprocess(cmd, timeout_sec=1800))
    console.print(stdout)
    if code != 0 and stderr:
        console.print(f"[yellow]{stderr}[/yellow]")
    console.print("[bold green]✔[/bold green]  Installer finished.")


@app.command(
    "update",
    help="Pull latest updates for all installed tools.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
def update():
    install()
