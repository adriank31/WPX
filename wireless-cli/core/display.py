"""
Shared terminal-display helpers built on `rich`.

Every module uses these so the CLI has a consistent look: a status header,
a live-updating panel, and standard success/fail/info message formatting.
"""

import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

console = Console()


def info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}")


def ok(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}")


def err(msg: str) -> None:
    console.print(f"[red][-][/red] {msg}")


def header(title: str) -> None:
    console.print(Panel.fit(f"[bold white]{title}[/bold white]", border_style="blue"))


def confirm(prompt: str) -> bool:
    try:
        resp = console.input(f"[yellow][?][/yellow] {prompt} (y/N): ").strip().lower()
        return resp in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


class StatusLine:
    """A single live-updating status line (used for short ongoing operations
    like 'Waiting for handshake... 00:32 elapsed')."""

    def __init__(self, label: str):
        self.label = label
        self._live = Live(self._render(""), console=console, refresh_per_second=4)

    def _render(self, text: str):
        return Text.from_markup(f"[cyan][*][/cyan] {self.label} {text}")

    def __enter__(self):
        self._live.__enter__()
        return self

    def update(self, text: str):
        self._live.update(self._render(text))

    def __exit__(self, *exc):
        self._live.__exit__(*exc)


def make_progress() -> Progress:
    return Progress(
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


def aps_table(aps: dict) -> Table:
    """Render the live recon AP dict as a rich Table."""
    table = Table(title="Discovered Access Points", show_lines=False)
    table.add_column("BSSID", style="white")
    table.add_column("SSID", style="bold white")
    table.add_column("Vendor", style="dim")
    table.add_column("Ch", justify="right")
    table.add_column("Auth", style="magenta")
    table.add_column("Power", justify="right")
    table.add_column("Vulnerabilities", style="red")

    for ap in sorted(aps.values(), key=lambda a: a.get("power", "-100") or "-100", reverse=True):
        vulns = ", ".join(ap.get("vulnerabilities", [])) or "—"
        table.add_row(
            ap["bssid"],
            ap.get("essid") or "[dim]<hidden>[/dim]",
            ap.get("vendor") or "—",
            str(ap.get("channel", "")),
            ap.get("privacy", ""),
            f'{ap.get("power","")} dBm',
            vulns,
        )
    return table


def clients_table(clients: dict) -> Table:
    table = Table(title="Associated Clients")
    table.add_column("MAC", style="white")
    table.add_column("Associated BSSID", style="dim")
    table.add_column("Probed SSIDs", style="cyan")
    for c in clients.values():
        table.add_row(c["mac"], c.get("associated_bssid", ""), c.get("probes", ""))
    return table


def interfaces_table(interfaces: list) -> Table:
    table = Table(title="Wireless Interfaces")
    table.add_column("Name", style="bold white")
    table.add_column("Mode")
    table.add_column("Driver", style="dim")
    table.add_column("Monitor capable?")
    table.add_column("Status")
    for i in interfaces:
        mon = i.get("supports_monitor")
        mon_str = "[green]yes[/green]" if mon is True else ("[red]no[/red]" if mon is False else "[dim]unknown[/dim]")
        status = "[red]busy[/red]" if i.get("claimed_by") else "[green]free[/green]"
        if i.get("claimed_by"):
            status += f" ({i['claimed_by']})"
        table.add_row(i["name"], i.get("mode", ""), i.get("driver", ""), mon_str, status)
    return table
