"""
dwforsec ssl <target>   |   dwforsec s <target>

Standalone SSL/TLS auditor.
"""
import asyncio
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dwforsec.services.recon.sslscan_service import run_sslscan
from dwforsec.services.analyzer.ssl_analyzer import analyze_ssl_issues

app = typer.Typer(
    help="SSL/TLS security audit",
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.command(
    name="ssl",
    help=(
        "Audit SSL/TLS configuration of TARGET.\n\n"
        "Checks: protocol versions, cipher strength, HSTS, self-signed,\n"
        "        certificate expiry, issuer, Subject Alternative Names.\n\n"
        "[bold cyan]Examples:[/bold cyan]\n"
        "  dwforsec ssl example.com\n"
        "  dwforsec ssl 10.1.2.240\n"
        "  dwforsec s example.com\n"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
def ssl_cmd(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Domain or IP to audit"),
):
    obj = ctx.ensure_object(dict)
    json_out = obj.get("json_output", False)
    console = Console(highlight=False)

    console.print(f"[bold cyan]›[/bold cyan]  SSL/TLS audit: [bold white]{target}[/bold white]")
    data = asyncio.run(run_sslscan(target))

    if json_out:
        import json
        print(json.dumps(data, indent=2, default=str))
        return

    # Summary panel
    tls_vers = ", ".join(data.get("tls_versions", [])) or "N/A"
    issuer   = data.get("issuer") or "N/A"
    expiry   = data.get("expiry") or "N/A"
    sans     = ", ".join(data.get("sans", [])) or "N/A"

    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim cyan", min_width=16)
    t.add_column(style="bold white")
    t.add_row("Protocol(s)", tls_vers)
    t.add_row("Issuer",      issuer[:60])
    t.add_row("Expiry",      expiry)
    t.add_row("SANs",        sans[:60])

    console.print(Panel(t, title=f"[bold cyan]{target}[/bold cyan]",
                        border_style="cyan", padding=(0, 2)))

    # Weakness analysis
    tls_v0    = (data.get("tls_versions") or [""])[0]
    ciphers   = ", ".join(data.get("weak_ciphers", []))
    hsts      = data.get("hsts", False)
    issues    = analyze_ssl_issues(tls_v0, ciphers, hsts, False)

    if issues:
        console.print("\n[bold red]Weaknesses[/bold red]")
        for i in issues:
            sev_map = {"high": "bold red", "medium": "bold yellow", "low": "bold cyan"}
            style = sev_map.get(i["severity"], "dim white")
            console.print(f"  [{style}][{i['severity'].upper()}][/{style}]  {i['issue']}")
            console.print(f"  [dim]  → {i['recommendation']}[/dim]")
    else:
        console.print("\n[bold green]✔[/bold green]  No critical TLS weaknesses detected.")
