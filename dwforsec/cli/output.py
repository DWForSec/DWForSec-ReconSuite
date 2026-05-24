"""
Centralized output helpers.
Respects --quiet, --json, --debug global flags via AppContext.
"""
import json
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.theme import Theme

# Custom offensive-security colour theme
THEME = Theme({
    "critical": "bold red",
    "high":     "bold dark_orange",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "dim white",
    "success":  "bold green",
    "accent":   "bold cyan",
    "muted":    "dim white",
    "label":    "bold bright_white",
})

# Single shared console instance
console = Console(theme=THEME, highlight=False)
err_console = Console(theme=THEME, highlight=False, stderr=True)


def get_console() -> Console:
    return console


def severity_style(sev: str) -> str:
    return {
        "critical": "[critical]",
        "high":     "[high]",
        "medium":   "[medium]",
        "low":      "[low]",
        "info":     "[info]",
    }.get(sev.lower(), "[info]")


def print_finding(tool: str, sev: str, matched: str, desc: str = ""):
    tag = severity_style(sev)
    console.print(f"  {tag}[{sev.upper()}][/{sev.lower()}]  [label]{tool}[/label]  {matched}")
    if desc:
        console.print(f"       [muted]{desc[:100]}[/muted]")


def print_success(msg: str):
    console.print(f"[success]✔[/success]  {msg}")


def print_error(msg: str):
    err_console.print(f"[critical]✘[/critical]  {msg}")


def print_info(msg: str):
    console.print(f"[accent]›[/accent]  {msg}")


def print_section(title: str):
    console.print(f"\n[bold cyan]━━━ {title} ━━━[/bold cyan]")


def output_json(data: dict):
    print(json.dumps(data, indent=2, default=str))


def make_severity_table(title: str) -> Table:
    t = Table(title=title, border_style="cyan", header_style="bold cyan", show_lines=False)
    return t
