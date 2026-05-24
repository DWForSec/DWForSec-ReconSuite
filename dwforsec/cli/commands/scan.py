import typer
from dwforsec.cli.commands.nuclei import app as nuclei_app
from dwforsec.cli.commands.ssl import app as ssl_app

app = typer.Typer(help="Trigger target scans (nuclei, ssl)")

# Register subcommands
app.add_typer(nuclei_app, name="nuclei")
app.add_typer(ssl_app, name="ssl")
