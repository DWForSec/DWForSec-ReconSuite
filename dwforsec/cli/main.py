import typer
from dwforsec.core.banner import show_banner
from dwforsec.cli.commands.recon import app as recon_app
from dwforsec.cli.commands.nuclei import app as nuclei_app
from dwforsec.cli.commands.ssl import app as ssl_app
from dwforsec.cli.commands.crawl import app as crawl_app
from dwforsec.cli.commands.jsanalyze import app as jsanalyze_app
from dwforsec.cli.commands.report import app as report_app
from dwforsec.cli.commands.tools import app as tools_app
from dwforsec.cli.commands.scan import app as scan_app

app = typer.Typer(
    help="DWForSec-ReconSuite: Offensive Reconnaissance & Intelligence Framework",
    invoke_without_command=True,
    no_args_is_help=True,
)

@app.callback()
def main_callback(ctx: typer.Context):
    """DWForSec-ReconSuite: Offensive Reconnaissance & Intelligence Framework"""
    show_banner()

# Add subcommands
app.add_typer(recon_app, name="recon")
app.add_typer(scan_app, name="scan")
app.add_typer(crawl_app, name="crawl")
app.add_typer(jsanalyze_app, name="jsanalyze")
app.add_typer(report_app, name="report")
app.add_typer(tools_app, name="tools")

if __name__ == "__main__":
    app()
