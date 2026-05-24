"""
DWForSec-ReconSuite — main CLI entrypoint.

Installed as:  dwforsec  (via pyproject.toml [project.scripts])

UX Design:
  dwforsec example.com             → auto-runs full recon
  dwforsec                         → interactive menu
  dwforsec recon example.com       → full pipeline
  dwforsec r    example.com        → alias for recon
  dwforsec nuclei https://t.com    → nuclei scan
  dwforsec n    https://t.com      → alias
  dwforsec ssl  target.com         → ssl audit
  dwforsec s    target.com         → alias
  dwforsec crawl https://t.com     → web crawler
  dwforsec c    https://t.com      → alias
  dwforsec js   app.js             → JS intelligence
  dwforsec j    app.js             → alias
  dwforsec report 1 --format html  → report
  dwforsec tools status            → tool manager
"""
import sys
import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text

from dwforsec.core.banner import show_banner
from dwforsec.core.constants import VERSION
from dwforsec.cli.context import AppContext

# ─── import sub-apps ───────────────────────────────────────────────────────────
from dwforsec.cli.commands.recon   import app as _recon_app,   recon_cmd
from dwforsec.cli.commands.nuclei  import app as _nuclei_app,  nuclei_cmd
from dwforsec.cli.commands.ssl     import app as _ssl_app,     ssl_cmd
from dwforsec.cli.commands.crawl   import app as _crawl_app,   crawl_cmd
from dwforsec.cli.commands.js      import app as _js_app,      js_cmd
from dwforsec.cli.commands.report  import app as _report_app,  report_cmd
from dwforsec.cli.commands.tools   import app as _tools_app


# ─── root app ──────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="dwforsec",
    help="Offensive Reconnaissance & Attack Surface Mapping Platform",
    context_settings={
        "help_option_names": ["-h", "--help"],
        "max_content_width": 100,
    },
    rich_markup_mode="rich",
    invoke_without_command=True,
    no_args_is_help=False,
    add_completion=True,
)


# ─── root callback (banner + global flags + default target) ───────────────────

@app.callback()
def root_callback(
    ctx:         typer.Context,
    verbose:     bool = typer.Option(False, "--verbose", "-v",
                                     help="Verbose output",              is_eager=False),
    json_output: bool = typer.Option(False, "--json",
                                     help="Machine-readable JSON output", is_eager=False),
    quiet:       bool = typer.Option(False, "--quiet", "-q",
                                     help="Suppress banner and decorations", is_eager=False),
    debug:       bool = typer.Option(False, "--debug",
                                     help="Show full stack traces",       is_eager=False),
    public_only: bool = typer.Option(False, "--public-only", "-P",
                                     help="Block private/local IP scanning", is_eager=False),
):
    """
    [bold cyan]DWForSec-ReconSuite[/bold cyan] — Offensive Reconnaissance & Attack Surface Mapping

    [bold]Quick start:[/bold]
      [cyan]dwforsec recon example.com[/cyan]        Full recon pipeline
      [cyan]dwforsec nuclei https://t.com[/cyan]     Nuclei vulnerability scan
      [cyan]dwforsec ssl target.com[/cyan]           SSL/TLS audit
      [cyan]dwforsec crawl https://t.com[/cyan]      Web crawler
      [cyan]dwforsec js app.js[/cyan]                JS secrets & route analysis
      [cyan]dwforsec report 1 --format pdf[/cyan]    Export report
      [cyan]dwforsec tools status[/cyan]             Check tool installs

    [bold]Aliases:[/bold]  r · n · s · c · j
    """
    # Store global flags in ctx.obj for all sub-commands
    ctx.ensure_object(dict)
    ctx.obj["verbose"]     = verbose
    ctx.obj["json_output"] = json_output
    ctx.obj["quiet"]       = quiet
    ctx.obj["debug"]       = debug
    ctx.obj["public_only"] = public_only

    console = Console(highlight=False)

    # Show banner unless --quiet or --json
    if not quiet and not json_output:
        show_banner(console)

    # Sub-command was explicitly given → let Typer handle it
    if ctx.invoked_subcommand is not None:
        return

    # ── No args at all → interactive menu ────────────────────────────────
    _interactive_menu(ctx, console)



# ─── default recon shortcut ────────────────────────────────────────────────────

def _run_default_recon(ctx: typer.Context, target: str,
                        public_only: bool, json_output: bool, console: Console):
    from dwforsec.cli.commands.recon import _run_pipeline
    from dwforsec.services.db_loader import get_scan_data
    from dwforsec.reports.html_report import HtmlReport

    console.print(f"[bold cyan]›[/bold cyan]  Auto-running full recon on "
                  f"[bold white]{target}[/bold white]\n")
    scan_id = asyncio.run(_run_pipeline(target, public_only, console))
    console.print(f"\n[bold green]✔[/bold green]  Scan ID [bold yellow]{scan_id}[/bold yellow]")

    scan_data = asyncio.run(get_scan_data(scan_id))
    path = asyncio.run(HtmlReport(scan_data).generate())
    console.print(f"[bold green]✔[/bold green]  Report   →  [cyan]{path}[/cyan]")


# ─── interactive menu ──────────────────────────────────────────────────────────

def _interactive_menu(ctx: typer.Context, console: Console):
    MENU = {
        "1": ("Full Recon Pipeline",       "recon"),
        "2": ("Nuclei Vulnerability Scan", "nuclei"),
        "3": ("SSL / TLS Audit",           "ssl"),
        "4": ("Web Crawler",               "crawl"),
        "5": ("JS Secret Analysis",        "js"),
        "6": ("Generate Report",           "report"),
        "7": ("Tool Status",               "tools"),
        "0": ("Exit",                      "exit"),
    }

    t = Table(border_style="cyan", header_style="bold cyan",
              show_header=False, show_lines=False, padding=(0, 2))
    t.add_column(style="bold cyan",  min_width=3)
    t.add_column(style="bold white")

    for key, (label, _) in MENU.items():
        t.add_row(f"[{key}]", label)

    console.print(Panel(t, title="[bold cyan]Select Operation[/bold cyan]",
                        border_style="cyan", padding=(0, 2)))

    choice = Prompt.ask("  [bold cyan]Choice[/bold cyan]",
                        choices=list(MENU.keys()), default="0")

    _, cmd = MENU[choice]
    if cmd == "exit":
        raise typer.Exit()

    # Dispatch to the chosen command
    if cmd == "recon":
        target = Prompt.ask("  Target (domain / IP)")
        ctx.invoke(recon_cmd, ctx=ctx, target=target)
    elif cmd == "nuclei":
        target = Prompt.ask("  Target URL")
        ctx.invoke(nuclei_cmd, ctx=ctx, target=target)
    elif cmd == "ssl":
        target = Prompt.ask("  Domain or IP")
        ctx.invoke(ssl_cmd, ctx=ctx, target=target)
    elif cmd == "crawl":
        url = Prompt.ask("  Target URL")
        ctx.invoke(crawl_cmd, ctx=ctx, url=url)
    elif cmd == "js":
        target = Prompt.ask("  File path or URL")
        ctx.invoke(js_cmd, ctx=ctx, target=target)
    elif cmd == "report":
        scan_id = int(Prompt.ask("  Scan ID"))
        fmt     = Prompt.ask("  Format", default="html",
                              choices=["html","md","json","txt","pdf"])
        ctx.invoke(report_cmd, ctx=ctx, scan_id=scan_id, format=[fmt], all_formats=False)
    elif cmd == "tools":
        from dwforsec.cli.commands.tools import status as tools_status
        tools_status()


# ─── register commands ─────────────────────────────────────────────────────────
# tools has multiple sub-commands → keep as sub-app
app.add_typer(_tools_app, name="tools", help="Tool manager")

# Single-command modules → register directly so `dwforsec recon <t>` works
app.command("recon",  help="Full recon pipeline"             )(recon_cmd)
app.command("nuclei", help="Nuclei vulnerability scan"       )(nuclei_cmd)
app.command("ssl",    help="SSL/TLS security audit"          )(ssl_cmd)
app.command("crawl",  help="Web crawler"                     )(crawl_cmd)
app.command("js",     help="JS intelligence analyzer"        )(js_cmd)
app.command("report", help="Report generator"                )(report_cmd)


# ─── shorthand aliases (r / n / s / c / j) ────────────────────────────────────

@app.command("r", hidden=True, context_settings={"help_option_names": ["-h","--help"]})
def alias_r(ctx: typer.Context,
             target: str = typer.Argument(...),
             public_only: bool = typer.Option(False, "--public-only", "-P")):
    """Alias for [cyan]recon[/cyan]"""
    ctx.ensure_object(dict)
    ctx.invoke(recon_cmd, ctx=ctx, target=target, public_only=public_only)

@app.command("n", hidden=True, context_settings={"help_option_names": ["-h","--help"]})
def alias_n(ctx: typer.Context,
             target: str = typer.Argument(...)):
    """Alias for [cyan]nuclei[/cyan]"""
    ctx.ensure_object(dict)
    ctx.invoke(nuclei_cmd, ctx=ctx, target=target)

@app.command("s", hidden=True, context_settings={"help_option_names": ["-h","--help"]})
def alias_s(ctx: typer.Context,
             target: str = typer.Argument(...)):
    """Alias for [cyan]ssl[/cyan]"""
    ctx.ensure_object(dict)
    ctx.invoke(ssl_cmd, ctx=ctx, target=target)

@app.command("c", hidden=True, context_settings={"help_option_names": ["-h","--help"]})
def alias_c(ctx: typer.Context,
             url: str = typer.Argument(...)):
    """Alias for [cyan]crawl[/cyan]"""
    ctx.ensure_object(dict)
    ctx.invoke(crawl_cmd, ctx=ctx, url=url)

@app.command("j", hidden=True, context_settings={"help_option_names": ["-h","--help"]})
def alias_j(ctx: typer.Context,
             target: str = typer.Argument(...),
             reveal: bool = typer.Option(False, "--reveal", "-r")):
    """Alias for [cyan]js[/cyan]"""
    ctx.ensure_object(dict)
    ctx.invoke(js_cmd, ctx=ctx, target=target, reveal=reveal)


# ─── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
