import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from dwforsec.core.constants import VERSION, SECURITY_WARNING

def show_banner():
    # Force UTF-8 output where possible; fall back to ASCII on legacy Windows terminals
    try:
        if sys.platform == "win32":
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    console = Console(highlight=False)

    banner_text = (
        "  DWForSec -- Offensive Reconnaissance Intelligence Framework\n"
        f"  Version: {VERSION}  |  CLI Mode: Terminal / Async Pipeline\n"
        "  ============================================================\n"
        "  [Subfinder][Assetfinder][Amass][HTTPX][Naabu][Nmap]\n"
        "  [Nuclei][Katana][GAU][Waybackurls][SSLScan][Wafw00f]\n"
    )

    try:
        panel = Panel.fit(
            banner_text.strip(),
            border_style="cyan",
            title="[bold green]DWForSec-ReconSuite[/bold green]",
            subtitle="[bold yellow]Offensive Security Intelligence[/bold yellow]"
        )
        console.print(panel)
        console.print(
            f"[bold red]WARNING:[/bold red] {SECURITY_WARNING}\n",
            justify="center"
        )
    except Exception:
        # Ultimate fallback – plain print
        print(f"\n  DWForSec-ReconSuite v{VERSION}")
        print(f"  WARNING: {SECURITY_WARNING}\n")
