"""Configuration management for FTP CLI profiles."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, Optional

from rich.console import Console


console = Console()


DEFAULT_CONFIG_PATH = Path.home() / ".ftpcli" / "config.json"


@dataclass
class ServerProfile:
    """Represents a saved FTP server profile."""

    name: str
    host: str
    user: str
    password: str
    port: int = 21
    secure: bool = False

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, object]) -> "ServerProfile":
        return cls(
            name=name,
            host=str(data.get("host", "")),
            user=str(data.get("user", "")),
            password=str(data.get("password", "")),
            port=int(data.get("port", 21)),
            secure=bool(data.get("secure", False)),
        )

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data.pop("name", None)
        return data


class ConfigManager:
    """Handles loading and storing FTP server profiles."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_CONFIG_PATH
        self._ensure_config_file()
        self._profiles: Dict[str, ServerProfile] = {}
        self._load()

    def _ensure_config_file(self) -> None:
        if not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"servers": {}}), encoding="utf-8")

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            console.print(
                f"[yellow]Warning:[/] configuration file at {self.path} is corrupted. Resetting."
            )
            data = {"servers": {}}

        servers = data.get("servers", {})
        self._profiles = {
            name: ServerProfile.from_dict(name, value) for name, value in servers.items()
        }

    def _save(self) -> None:
        payload = {"servers": {name: profile.to_dict() for name, profile in self._profiles.items()}}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def add_server(
        self,
        name: str,
        host: str,
        user: str,
        password: str,
        *,
        port: int = 21,
        secure: bool = False,
    ) -> None:
        profile = ServerProfile(name=name, host=host, user=user, password=password, port=port, secure=secure)
        self._profiles[name] = profile
        self._save()

    def get_server(self, name: str) -> Optional[ServerProfile]:
        return self._profiles.get(name)

    def delete_server(self, name: str) -> bool:
        if name in self._profiles:
            del self._profiles[name]
            self._save()
            return True
        return False

    def list_servers(self) -> Iterable[ServerProfile]:
        return sorted(self._profiles.values(), key=lambda profile: profile.name.lower())


__all__ = ["ConfigManager", "ServerProfile", "DEFAULT_CONFIG_PATH"]

