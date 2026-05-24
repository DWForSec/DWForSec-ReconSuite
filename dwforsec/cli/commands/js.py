"""
dwforsec js <file|url>   |   dwforsec j <file|url>

JavaScript / source code intelligence analyzer.
Detects: API keys, JWT, AWS keys, Firebase, Stripe, GraphQL,
         Swagger, WebSocket endpoints, internal IPs, debug flags.
"""
import typer
import httpx
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from dwforsec.services.analyzer.js_secret_analyzer import analyze_js_secrets
from dwforsec.services.analyzer.route_extractor import extract_routes

app = typer.Typer(
    help="JavaScript intelligence — secrets & endpoint extraction",
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _analyse_and_print(content: str, source: str, reveal: bool, json_out: bool, console: Console):
    findings = analyze_js_secrets(content, reveal=reveal)
    routes   = extract_routes(content)

    if json_out:
        import json
        print(json.dumps({"source": source, "secrets": findings, "routes": routes}, indent=2, default=str))
        return

    console.print(f"\n[bold cyan]Source:[/bold cyan]  {source}")

    if findings:
        t = Table(border_style="red", header_style="bold red", show_lines=False)
        t.add_column("Type",           style="bold yellow", min_width=22)
        t.add_column("Line",           style="cyan",        min_width=5)
        t.add_column("Match (masked)", style="bold white",  min_width=30)
        for f in findings:
            t.add_row(f["pattern_name"], str(f["line_number"]), f["masked_match"])
        console.print(t)
    else:
        console.print("  [bold green]✔[/bold green]  No secrets detected.")

    if routes:
        console.print(f"\n[bold cyan]Routes / Endpoints[/bold cyan]  ({len(routes)} found)")
        for r in routes[:40]:
            console.print(f"  [dim cyan]{r}[/dim cyan]")
    else:
        console.print("  [dim]No sensitive routes extracted.[/dim]")


@app.command(
    name="js",
    help=(
        "Analyze a local file or remote URL for secrets and endpoint leaks.\n\n"
        "[bold cyan]Examples:[/bold cyan]\n"
        "  dwforsec js app.js\n"
        "  dwforsec js https://example.com/assets/main.js\n"
        "  dwforsec js app.js --reveal\n"
        "  dwforsec j app.js\n"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
def js_cmd(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Local file path or remote URL"),
    reveal: bool = typer.Option(False, "--reveal", "-r", help="Show unmasked secret values"),
):
    obj = ctx.ensure_object(dict)
    json_out = obj.get("json_output", False)
    console  = Console(highlight=False)

    # Detect local vs remote
    if target.startswith("http://") or target.startswith("https://"):
        console.print(f"[bold cyan]›[/bold cyan]  Fetching [dim]{target}[/dim]")
        try:
            resp    = httpx.get(target, verify=False, timeout=10.0)
            content = resp.text
        except Exception as e:
            console.print(f"[bold red]✘[/bold red]  Failed to fetch: {e}")
            raise typer.Exit(1)
    else:
        path = Path(target)
        if not path.exists():
            console.print(f"[bold red]✘[/bold red]  File not found: {target}")
            raise typer.Exit(1)
        content = path.read_text(encoding="utf-8", errors="ignore")

    _analyse_and_print(content, target, reveal, json_out, console)
