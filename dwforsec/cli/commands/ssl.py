import typer
import asyncio
from rich.console import Console
from rich.panel import Panel
from dwforsec.services.recon.sslscan_service import run_sslscan
from dwforsec.services.analyzer.ssl_analyzer import analyze_ssl_issues

app = typer.Typer(help="Scan and analyze target SSL/TLS configuration")
console = Console()

@app.command("scan")
def scan_ssl(
    target: str = typer.Argument(..., help="Domain name or host IP to audit")
):
    """
    Performs SSL/TLS scan and logs security findings.
    """
    console.print(f"[bold green]Initiating SSL/TLS Audit for:[/bold green] {target}")
    
    # Run async SSL scan
    data = asyncio.run(run_sslscan(target))
    
    # Print results
    console.print(Panel.fit(
        f"Issuer: {data.get('issuer', 'N/A')}\n"
        f"Expiry: {data.get('expiry', 'N/A')}\n"
        f"Protocols: {', '.join(data.get('tls_versions', [])) or 'N/A'}\n"
        f"SANs: {', '.join(data.get('sans', [])) or 'N/A'}",
        title=f"SSL Details: {target}",
        border_style="cyan"
    ))
    
    # Check weaknesses
    tls_version = data.get("tls_versions")[0] if data.get("tls_versions") else ""
    weak_ciphers = ", ".join(data.get("weak_ciphers", []))
    hsts = data.get("hsts", False)
    
    findings = analyze_ssl_issues(tls_version, weak_ciphers, hsts, False)
    
    if findings:
        console.print("\n[bold red]SSL/TLS Weaknesses Identified:[/bold red]")
        for f in findings:
            console.print(f"[{f['severity'].upper()}] [yellow]{f['issue']}[/yellow]")
            console.print(f"  Remediation: {f['recommendation']}\n")
    else:
        console.print("\n[bold green]No critical SSL/TLS misconfigurations discovered.[/bold green]")
