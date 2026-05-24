import typer
import asyncio
from rich.console import Console
from rich.table import Table
from dwforsec.services.recon.nuclei_service import run_nuclei

app = typer.Typer(help="Trigger standalone Nuclei vulnerability scanner")
console = Console()

@app.command("run")
def run_vuln(
    target: str = typer.Argument(..., help="Target URL or domain to scan")
):
    """
    Executes Nuclei vulnerability scanner on the target.
    """
    console.print(f"[bold green]Starting Nuclei Vulnerability Scan on:[/bold green] {target}")
    findings = asyncio.run(run_nuclei(target))
    
    if findings:
        table = Table(title="Nuclei Detections", border_style="cyan")
        table.add_column("Template ID", style="bold white")
        table.add_column("Severity", style="bold")
        table.add_column("Matched URL", style="dim white")
        
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev == "critical":
                sev_styled = "[red]critical[/red]"
            elif sev == "high":
                sev_styled = "[orange3]high[/orange3]"
            elif sev == "medium":
                sev_styled = "[yellow]medium[/yellow]"
            elif sev == "low":
                sev_styled = "[blue]low[/blue]"
            else:
                sev_styled = "[grey50]info[/grey50]"
                
            table.add_row(f.get("template_id"), sev_styled, f.get("matched_url"))
            
        console.print(table)
    else:
        console.print("[green]Scan complete. No vulnerabilities detected.[/green]")
