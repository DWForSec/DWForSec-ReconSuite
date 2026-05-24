"""
dwforsec report <scan_id>

Generate scan reports in multiple formats.
"""
import asyncio
import typer
from rich.console import Console

from dwforsec.services.db_loader import get_scan_data
from dwforsec.reports.html_report     import HtmlReport
from dwforsec.reports.markdown_report import MarkdownReport
from dwforsec.reports.json_report     import JsonReport
from dwforsec.reports.txt_report      import TxtReport
from dwforsec.reports.pdf_report      import PdfReport

app = typer.Typer(
    help="Generate vulnerability reports from a completed scan",
    context_settings={"help_option_names": ["-h", "--help"]},
)

FORMAT_MAP = {
    "html":     HtmlReport,
    "md":       MarkdownReport,
    "markdown": MarkdownReport,
    "json":     JsonReport,
    "txt":      TxtReport,
    "pdf":      PdfReport,
}


@app.command(
    name="report",
    help=(
        "Export a completed scan as a report.\n\n"
        "Formats: html  md  json  txt  pdf\n\n"
        "[bold cyan]Examples:[/bold cyan]\n"
        "  dwforsec report 1\n"
        "  dwforsec report 1 --format pdf\n"
        "  dwforsec report 1 --all\n"
        "  dwforsec report 1 --format md --format json\n"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
def report_cmd(
    ctx: typer.Context,
    scan_id: int = typer.Argument(..., help="Scan ID returned after recon"),
    format: list[str] = typer.Option(
        ["html"], "--format", "-f",
        help="Output format (repeatable): html md json txt pdf",
    ),
    all_formats: bool = typer.Option(False, "--all", "-a",
                                     help="Generate all formats at once"),
):
    console = Console(highlight=False)
    console.print(f"[bold cyan]›[/bold cyan]  Loading scan [bold white]{scan_id}[/bold white]")

    scan_data = asyncio.run(get_scan_data(scan_id))
    if not scan_data:
        console.print(f"[bold red]✘[/bold red]  Scan ID {scan_id} not found.")
        raise typer.Exit(1)

    target = scan_data.get("target", "unknown")
    console.print(f"  Target: [bold white]{target}[/bold white]  |  "
                  f"Findings: [bold red]{scan_data.get('summary',{}).get('critical',0)+scan_data.get('summary',{}).get('high',0)}[/bold red] crit/high\n")

    formats = list(FORMAT_MAP.keys()) if all_formats else [f.lower() for f in format]

    for fmt in formats:
        cls = FORMAT_MAP.get(fmt)
        if cls is None:
            console.print(f"  [yellow]Unknown format '{fmt}' — skipping.[/yellow]")
            continue
        path = asyncio.run(cls(scan_data).generate())
        console.print(f"  [bold green]✔[/bold green]  {fmt.upper():8}  [cyan]{path}[/cyan]")
