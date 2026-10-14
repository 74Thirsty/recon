"""Interactive FTP shell built on cmd2."""

from __future__ import annotations

from pathlib import Path
import cmd2
from rich.console import Console
from rich.prompt import Prompt

from config import ServerProfile
from ftp_client import FTPClient


console = Console()


class FTPShell(cmd2.Cmd):
    intro = "Welcome to FTP-CLI shell. Type 'help' to see available commands."
    prompt = "ftp> "

    def __init__(self, server: ServerProfile) -> None:
        super().__init__(allow_cli_args=False)
        self.server = server
        self.ftp = FTPClient(server)
        self.hidden_commands.append("py")  # hide python command for cleaner UX

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------
    def preloop(self) -> None:
        console.print(f"Connecting to [bold]{self.server.host}[/bold] as [green]{self.server.user}[/green]...")
        try:
            self.ftp.connect()
            console.print("[green]Connected successfully![/green]")
        except Exception as exc:  # pragma: no cover - surface failure
            console.print(f"[red]Connection failed:[/] {exc}")
            raise SystemExit(1)

    def postloop(self) -> None:
        if self.ftp.connected:
            self.ftp.close()
        console.print("[cyan]Disconnected. Goodbye![/cyan]")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _ensure_argument(self, argument: str, message: str) -> str:
        if argument:
            return argument
        return Prompt.ask(message)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    def do_pwd(self, _: cmd2.Statement) -> None:
        """Show current working directory."""

        console.print(f"[bold]{self.ftp.pwd()}[/bold]")

    def do_cd(self, statement: cmd2.Statement) -> None:
        """Change remote directory."""

        path = self._ensure_argument(statement.arg, "Remote path")
        try:
            new_path = self.ftp.cd(path)
            console.print(f"[green]Changed directory to[/green] [bold]{new_path}[/bold]")
        except Exception as exc:
            console.print(f"[red]Failed to change directory:[/] {exc}")

    def do_ls(self, statement: cmd2.Statement) -> None:
        """List files in the current or provided directory."""

        path = statement.arg.strip() or None
        try:
            self.ftp.show_directory_table(path)
        except Exception as exc:
            console.print(f"[red]Failed to list directory:[/] {exc}")

    def do_get(self, statement: cmd2.Statement) -> None:
        """Download a file from the server."""

        parts = statement.arg.split()
        if not parts:
            remote_path = Prompt.ask("Remote file path")
            local_path = Prompt.ask("Local destination", default=Path(remote_path).name)
        elif len(parts) == 1:
            remote_path = parts[0]
            local_path = Path(parts[0]).name
        else:
            remote_path, local_path = parts[0], parts[1]

        try:
            self.ftp.download(remote_path, local_path)
            console.print(f"[green]Downloaded[/green] {remote_path} → {local_path}")
        except Exception as exc:
            console.print(f"[red]Download failed:[/] {exc}")

    def do_put(self, statement: cmd2.Statement) -> None:
        """Upload a file to the server."""

        parts = statement.arg.split()
        if not parts:
            local_path = Prompt.ask("Local file path")
            remote_path = Prompt.ask("Remote destination", default=Path(local_path).name)
        elif len(parts) == 1:
            local_path = parts[0]
            remote_path = Path(parts[0]).name
        else:
            local_path, remote_path = parts[0], parts[1]

        try:
            self.ftp.upload(local_path, remote_path)
            console.print(f"[green]Uploaded[/green] {local_path} → {remote_path}")
        except Exception as exc:
            console.print(f"[red]Upload failed:[/] {exc}")

    def do_mkdir(self, statement: cmd2.Statement) -> None:
        """Create a directory on the server."""

        path = self._ensure_argument(statement.arg, "Directory name")
        try:
            self.ftp.mkdir(path)
            console.print(f"[green]Created directory[/green] {path}")
        except Exception as exc:
            console.print(f"[red]Failed to create directory:[/] {exc}")

    def do_rm(self, statement: cmd2.Statement) -> None:
        """Delete a file on the server."""

        path = self._ensure_argument(statement.arg, "File to remove")
        try:
            self.ftp.remove_file(path)
            console.print(f"[green]Removed[/green] {path}")
        except Exception as exc:
            console.print(f"[red]Failed to remove file:[/] {exc}")

    def do_disconnect(self, _: cmd2.Statement) -> bool:
        """Disconnect from the FTP server and exit the shell."""

        self.close()
        return True

    def do_exit(self, statement: cmd2.Statement) -> bool:  # pragma: no cover - alias
        return self.do_disconnect(statement)

    def do_quit(self, statement: cmd2.Statement) -> bool:  # pragma: no cover - alias
        return self.do_disconnect(statement)

    def close(self) -> None:
        if self.ftp.connected:
            try:
                self.ftp.close()
            except Exception as exc:  # pragma: no cover - best effort cleanup
                console.print(f"[yellow]Warning:[/] Failed to close connection cleanly: {exc}")


__all__ = ["FTPShell"]

