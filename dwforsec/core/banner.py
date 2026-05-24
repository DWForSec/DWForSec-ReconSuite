"""
Professional offensive-security banner.
ASCII-safe for Windows cp1252 and Linux terminals.
Shows version + loaded module count.
"""
import sys
import shutil
from rich.console import Console
from rich.panel import Panel
from dwforsec.core.constants import VERSION, SECURITY_WARNING

TOOLS = [
    "Subfinder", "Assetfinder", "Amass", "HTTPX", "Naabu",
    "Nmap", "Nuclei", "Katana", "GAU", "Waybackurls",
    "Hakrawler", "SSLScan", "testssl", "WhatWeb", "Wafw00f",
]

MODULES = [
    "Recon", "Crawl", "JSIntel", "SSLAudit",
    "NucleiScan", "Reporting", "Database",
]


def show_banner(console: Console | None = None):
    # Windows: try to upgrade stdout to UTF-8 so box-drawing chars render
    try:
        if sys.platform == "win32":
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if console is None:
        console = Console(highlight=False)

    tool_count  = len(TOOLS)
    module_count = len(MODULES)
    term_width  = min(shutil.get_terminal_size((80, 20)).columns, 80)

    # Core banner lines (all pure-ASCII so cp1252 is fine)
    lines = [
        f"[bold cyan]DWForSec-ReconSuite[/bold cyan]  [dim]v{VERSION}[/dim]",
        f"[dim]Offensive Reconnaissance & Attack Surface Mapping Platform[/dim]",
        "",
        "[dim cyan]" + "  ".join(MODULES) + "[/dim cyan]",
        "",
        f"[dim]Tools: {tool_count} supported  |  Modules: {module_count} loaded  |  DB: SQLite (async)[/dim]",
    ]

    try:
        panel = Panel(
            "\n".join(lines),
            border_style="cyan",
            padding=(0, 2),
        )
        console.print(panel)
    except Exception:
        # Hard fallback – plain print
        print(f"\n  DWForSec-ReconSuite v{VERSION}")
        print(f"  {' | '.join(MODULES)}\n")
