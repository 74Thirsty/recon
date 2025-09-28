"""Typer entrypoint for the FTP CLI application."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from config import ConfigManager, ServerProfile
from shell import FTPShell


app = typer.Typer(help="Modern FTP client with saved profiles and interactive shell.")
console = Console()
config = ConfigManager()


def _print_server_table(profiles) -> None:
    table = Table(title="Saved FTP Servers")
    table.add_column("Name", style="bold")
    table.add_column("Host")
    table.add_column("User")
    table.add_column("Port", justify="right")
    table.add_column("Secure", justify="center")

    for profile in profiles:
        table.add_row(
            profile.name,
            profile.host,
            profile.user,
            str(profile.port),
            "🔒" if profile.secure else "",
        )
    console.print(table)


@app.command()
def add_server(
    name: str = typer.Argument(..., help="Name for the server profile."),
    host: str = typer.Option(..., "--host", prompt=True, help="FTP host."),
    user: str = typer.Option(..., "--user", prompt=True, help="Username."),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True, help="Password."),
    port: int = typer.Option(21, "--port", help="FTP port."),
    secure: bool = typer.Option(False, "--secure", help="Use implicit TLS."),
) -> None:
    """Save a new FTP server profile."""

    config.add_server(name, host, user, password, port=port, secure=secure)
    console.print(f"[green]Server '{name}' saved.[/green]")


@app.command()
def list_servers() -> None:
    """List saved FTP server profiles."""

    profiles = list(config.list_servers())
    if not profiles:
        console.print("[yellow]No servers saved yet.[/yellow]")
        return
    _print_server_table(profiles)


@app.command()
def remove_server(name: str = typer.Argument(..., help="Name of the server profile.")) -> None:
    """Remove a saved FTP server profile."""

    if config.delete_server(name):
        console.print(f"[green]Removed server '{name}'.[/green]")
    else:
        console.print(f"[red]Server '{name}' not found.[/red]")


def _ensure_server(name: str) -> ServerProfile:
    profile = config.get_server(name)
    if not profile:
        console.print(f"[red]Server '{name}' not found.[/red]")
        raise typer.Exit(code=1)
    return profile


@app.command()
def connect(name: str = typer.Argument(..., help="Server profile to connect to.")) -> None:
    """Connect to a saved server and enter interactive shell."""

    profile = _ensure_server(name)
    shell = FTPShell(profile)
    shell.cmdloop()


if __name__ == "__main__":
    app()

