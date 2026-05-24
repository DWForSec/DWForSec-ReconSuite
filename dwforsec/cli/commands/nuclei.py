"""
dwforsec nuclei <target>   |   dwforsec n <target>

Standalone Nuclei vulnerability scanner.
Falls back gracefully if nuclei binary is not installed.
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table

from dwforsec.services.recon.nuclei_service import run_nuclei

app = typer.Typer(
    help="Nuclei vulnerability scanner",
    context_settings={"help_option_names": ["-h", "--help"]},
)

SEV_STYLE = {
    "critical": "bold red",
    "high":     "bold dark_orange",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "dim white",
}


@app.command(
    name="nuclei",
    help=(
        "Run Nuclei vulnerability scanner against TARGET.\n\n"
        "[bold cyan]Examples:[/bold cyan]\n"
        "  dwforsec nuclei https://example.com\n"
        "  dwforsec nuclei https://example.com --json\n"
        "  dwforsec n https://example.com\n"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
def nuclei_cmd(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="URL or domain to scan"),
):
    obj = ctx.ensure_object(dict)
    json_out = obj.get("json_output", False)
    console = Console(highlight=False)

    console.print(f"[bold cyan]›[/bold cyan]  Nuclei scanning [bold white]{target}[/bold white]")
    findings = asyncio.run(run_nuclei(target))

    if not findings:
        console.print("[bold green]✔[/bold green]  No vulnerabilities detected.")
        return

    if json_out:
        import json
        print(json.dumps(findings, indent=2, default=str))
        return

    t = Table(border_style="cyan", header_style="bold cyan", show_lines=False)
    t.add_column("Severity",    style="bold", min_width=8)
    t.add_column("Template ID", min_width=28)
    t.add_column("Matched",     min_width=40)

    for f in sorted(findings, key=lambda x: ["critical","high","medium","low","info"].index(
            x.get("severity","info").lower()) if x.get("severity","info").lower() in
            ["critical","high","medium","low","info"] else 4):
        sev   = f.get("severity", "info").lower()
        style = SEV_STYLE.get(sev, "dim white")
        t.add_row(
            f"[{style}]{sev.upper()}[/{style}]",
            f.get("template_id") or "—",
            (f.get("matched_url") or f.get("host") or "—")[:60],
        )

    console.print(t)
    console.print(f"\n[dim]  {len(findings)} finding(s) — run [cyan]dwforsec report[/cyan] to export.[/dim]")
