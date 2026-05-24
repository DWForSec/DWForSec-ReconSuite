"""
Shared application context passed through Typer ctx.obj
to all subcommands for global flag propagation.
"""
from dataclasses import dataclass, field


@dataclass
class AppContext:
    verbose: bool = False
    json_output: bool = False
    quiet: bool = False
    debug: bool = False
    public_only: bool = False
