import typer
import asyncio
from rich.console import Console
from dwforsec.services.db_loader import get_scan_data
from dwforsec.reports.html_report import HtmlReport
from dwforsec.reports.markdown_report import MarkdownReport
from dwforsec.reports.json_report import JsonReport
from dwforsec.reports.txt_report import TxtReport
from dwforsec.reports.pdf_report import PdfReport

app = typer.Typer(help="Export and manage target vulnerability reports")
console = Console()

@app.command("generate")
def generate(
    scan_id: int = typer.Argument(..., help="Scan ID to generate report from"),
    format: str = typer.Option("html", "--format", help="Output format: html, md, pdf, json, txt"),
    all_formats: bool = typer.Option(False, "--all-formats", help="Generate all report formats")
):
    """
    Generates vulnerability reports in multiple formats.
    """
    console.print(f"Loading scan results for Scan ID: {scan_id}...")
    scan_data = asyncio.run(get_scan_data(scan_id))
    
    if not scan_data:
        console.print(f"[bold red]Error:[/bold red] Scan ID {scan_id} does not exist in the database.")
        raise typer.Exit(1)
        
    formats = ["html", "md", "pdf", "json", "txt"] if all_formats else [format.lower()]
    
    for fmt in formats:
        if fmt == "html":
            rep = HtmlReport(scan_data)
        elif fmt in ["md", "markdown"]:
            rep = MarkdownReport(scan_data)
        elif fmt == "json":
            rep = JsonReport(scan_data)
        elif fmt == "txt":
            rep = TxtReport(scan_data)
        elif fmt == "pdf":
            rep = PdfReport(scan_data)
        else:
            console.print(f"[yellow]Unknown format '{fmt}'. Skipping.[/yellow]")
            continue
            
        path = asyncio.run(rep.generate())
        console.print(f"[bold green]Generated {fmt.upper()} report at:[/bold green] [cyan]{path}[/cyan]")
