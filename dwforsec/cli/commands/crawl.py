import typer
import asyncio
from rich.console import Console
from dwforsec.services.recon.katana_service import run_katana

app = typer.Typer(help="Crawl websites and discover pathways and assets")
console = Console()

@app.command("run")
def run_crawl(
    url: str = typer.Argument(..., help="Website URL to crawl")
):
    """
    Crawls website endpoints using Katana or native python crawler.
    """
    console.print(f"[bold green]Starting crawl on:[/bold green] {url}")
    discovered = asyncio.run(run_katana(url))
    
    if discovered:
        console.print(f"\n[bold cyan]Discovered {len(discovered)} assets/URLs:[/bold cyan]")
        for d in discovered:
            console.print(f"  {d}")
    else:
        console.print("[yellow]Crawl completed, but no assets were discovered.[/yellow]")
