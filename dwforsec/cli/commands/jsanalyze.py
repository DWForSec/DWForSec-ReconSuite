import typer
import asyncio
import httpx
from rich.console import Console
from rich.table import Table
from pathlib import Path
from dwforsec.services.analyzer.js_secret_analyzer import analyze_js_secrets
from dwforsec.services.analyzer.route_extractor import extract_routes

app = typer.Typer(help="Analyze JavaScript/source code files for secrets and endpoints")
console = Console()

@app.command("file")
def analyze_file(
    file_path: str = typer.Argument(..., help="Path to local JS/source file"),
    reveal: bool = typer.Option(False, "--reveal", help="Reveal unmasked secrets")
):
    """
    Analyzes a local JavaScript/source file.
    """
    path = Path(file_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File {file_path} not found.")
        raise typer.Exit(1)
        
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        console.print(f"[bold red]Failed to read file:[/bold red] {e}")
        raise typer.Exit(1)
        
    findings = analyze_js_secrets(content, reveal=reveal)
    routes = extract_routes(content)
    
    # Render table of secrets
    if findings:
        table = Table(title="Detected Secrets", border_style="red")
        table.add_column("Type", style="bold yellow")
        table.add_column("Line", style="cyan")
        table.add_column("Match (Masked)", style="bold white")
        
        for f in findings:
            table.add_row(f["pattern_name"], str(f["line_number"]), f["masked_match"])
        console.print(table)
    else:
        console.print("[green]No secrets detected.[/green]")
        
    # Render routes
    if routes:
        console.print("\n[bold cyan]Extracted Routing Endpoints:[/bold cyan]")
        for r in routes:
            console.print(f"  {r}")
    else:
        console.print("\n[dim]No endpoint routes extracted.[/dim]")

@app.command("url")
def analyze_url(
    url: str = typer.Argument(..., help="URL to JS/source file"),
    reveal: bool = typer.Option(False, "--reveal", help="Reveal unmasked secrets")
):
    """
    Fetches and analyzes a remote URL.
    """
    console.print(f"Fetching: {url}")
    try:
        resp = httpx.get(url, verify=False, timeout=10.0)
        content = resp.text
    except Exception as e:
        console.print(f"[bold red]Failed to fetch URL:[/bold red] {e}")
        raise typer.Exit(1)
        
    findings = analyze_js_secrets(content, reveal=reveal)
    routes = extract_routes(content)
    
    if findings:
        table = Table(title="Detected Secrets", border_style="red")
        table.add_column("Type", style="bold yellow")
        table.add_column("Line", style="cyan")
        table.add_column("Match (Masked)", style="bold white")
        
        for f in findings:
            table.add_row(f["pattern_name"], str(f["line_number"]), f["masked_match"])
        console.print(table)
    else:
        console.print("[green]No secrets detected.[/green]")
        
    if routes:
        console.print("\n[bold cyan]Extracted Routing Endpoints:[/bold cyan]")
        for r in routes:
            console.print(f"  {r}")
