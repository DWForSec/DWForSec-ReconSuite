"""
dwforsec crawl <url>   |   dwforsec c <url>

Web crawler — Katana binary or Python link-extractor fallback.
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table

from dwforsec.services.recon.katana_service import run_katana

app = typer.Typer(
    help="Web crawler — discover URLs, JS files, and endpoints",
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.command(
    name="crawl",
    help=(
        "Crawl TARGET and list all discovered URLs, JS files, and routes.\n\n"
        "[bold cyan]Examples:[/bold cyan]\n"
        "  dwforsec crawl https://example.com\n"
        "  dwforsec c https://example.com\n"
        "  dwforsec crawl https://example.com --depth 5\n"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
def crawl_cmd(
    ctx: typer.Context,
    url: str = typer.Argument(..., help="Target URL to crawl"),
    depth: int = typer.Option(3, "--depth", "-d", help="Crawl depth"),
):
    obj = ctx.ensure_object(dict)
    json_out = obj.get("json_output", False)
    console = Console(highlight=False)

    console.print(f"[bold cyan]›[/bold cyan]  Crawling [bold white]{url}[/bold white]")
    discovered = asyncio.run(run_katana(url))

    if not discovered:
        console.print("[yellow]  No URLs discovered.[/yellow]")
        return

    if json_out:
        import json
        print(json.dumps(discovered, indent=2))
        return

    # Categorise
    js_files    = [u for u in discovered if ".js" in u]
    admin_urls  = [u for u in discovered if any(k in u for k in ["/admin", "/dashboard", "/manage"])]
    api_urls    = [u for u in discovered if any(k in u for k in ["/api/", "/v1/", "/v2/", "/graphql"])]
    other_urls  = [u for u in discovered
                   if u not in js_files and u not in admin_urls and u not in api_urls]

    console.print(f"  [bold green]{len(discovered)}[/bold green] URLs  |  "
                  f"[bold yellow]{len(js_files)}[/bold yellow] JS  |  "
                  f"[bold red]{len(admin_urls)}[/bold red] Admin  |  "
                  f"[bold cyan]{len(api_urls)}[/bold cyan] API\n")

    def _section(label: str, items: list[str], style: str):
        if items:
            console.print(f"[{style}]{label}[/{style}]")
            for u in items[:30]:
                console.print(f"  [dim]{u}[/dim]")
            if len(items) > 30:
                console.print(f"  [dim]... and {len(items)-30} more[/dim]")
            console.print()

    _section("Admin / Dashboard", admin_urls, "bold red")
    _section("API Endpoints",     api_urls,   "bold cyan")
    _section("JavaScript Files",  js_files,   "bold yellow")
    _section("Other URLs",        other_urls, "dim white")
