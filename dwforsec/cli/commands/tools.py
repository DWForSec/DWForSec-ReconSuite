import typer
import sys
import shutil
from pathlib import Path
from rich.console import Console
from rich.table import Table
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.core.config import BASE_DIR

app = typer.Typer(help="Manage and verify offensive scanning tools")
console = Console()

TOOLS_LIST = {
    "subfinder": "https://github.com/projectdiscovery/subfinder",
    "assetfinder": "https://github.com/tomnomnom/assetfinder",
    "httpx": "https://github.com/projectdiscovery/httpx",
    "naabu": "https://github.com/projectdiscovery/naabu",
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "katana": "https://github.com/projectdiscovery/katana",
    "amass": "https://github.com/owasp-amass/amass",
    "whatweb": "https://github.com/urbanadventurer/WhatWeb",
    "wafw00f": "https://github.com/EnableSecurity/wafw00f",
    "gau": "https://github.com/lc/gau",
    "waybackurls": "https://github.com/tomnomnom/waybackurls",
    "hakrawler": "https://github.com/hakluke/hakrawler",
    "sslscan": "https://github.com/rbsec/sslscan",
    "testssl.sh": "https://github.com/drwetter/testssl.sh"
}

@app.command("status")
def status():
    """
    Checks install status of all 15 offensive security tools.
    """
    table = Table(title="Recon Suite Tools Status", border_style="cyan")
    table.add_column("Tool Name", style="bold white")
    table.add_column("Type / Repository", style="dim white")
    table.add_column("Status", style="bold")
    
    for tool, repo in TOOLS_LIST.items():
        # Check system PATH first
        path_exist = shutil.which(tool)
        # Check inside tools dir
        local_exist = (BASE_DIR / "dwforsec" / "tools" / tool).exists() or (BASE_DIR / "dwforsec" / "tools" / f"{tool}.exe").exists()
        
        if path_exist or local_exist:
            status_str = "[green]Installed[/green]"
        else:
            status_str = "[red]Not Found[/red]"
            
        table.add_row(tool, repo, status_str)
        
    console.print(table)

@app.command("install")
def install():
    """
    Installs missing tools using system script runners (install-tools.ps1 or .sh).
    """
    is_windows = sys.platform == "win32"
    console.print("[bold yellow]Starting tools installer environment check...[/bold yellow]")
    
    if is_windows:
        script_path = BASE_DIR / "scripts" / "install-tools.ps1"
        console.print(f"Running PowerShell installer script: {script_path}")
        # Run using powershell subprocess
        import asyncio
        from dwforsec.utils.subprocess_runner import run_subprocess
        # Running async inside sync typer command
        code, stdout, stderr = asyncio.run(run_subprocess(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]))
        console.print(stdout)
        if code != 0:
            console.print(f"[bold red]Installation script returned error code {code}:[/bold red]\n{stderr}")
    else:
        script_path = BASE_DIR / "scripts" / "install-tools.sh"
        console.print(f"Running Bash installer script: {script_path}")
        import asyncio
        from dwforsec.utils.subprocess_runner import run_subprocess
        # Set exec permission
        import os
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass
        code, stdout, stderr = asyncio.run(run_subprocess([str(script_path)]))
        console.print(stdout)
        if code != 0:
            console.print(f"[bold red]Installation script returned error code {code}:[/bold red]\n{stderr}")

@app.command("update")
def update():
    """
    Pulls updates for all cloned tool repositories.
    """
    console.print("[bold green]Checking for tools updates...[/bold green]")
    # Invoke installer script since it pulls updates automatically
    install()
