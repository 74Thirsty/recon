"""Async FTP client wrapper built on top of aioftp."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import Any, Coroutine, Iterable, List, Optional, TypeVar

import aioftp
from rich.console import Console
from rich.table import Table

from config import ServerProfile
from utils.progress import run_progress_monitor


console = Console()


@dataclass
class DirectoryEntry:
    name: str
    is_dir: bool
    size: int | None = None
    modified: str | None = None


T = TypeVar("T")


class FTPClient:
    """High-level FTP client with progress reporting."""

    def __init__(self, profile: ServerProfile) -> None:
        self.profile = profile
        self._loop = asyncio.new_event_loop()
        self._thread = Thread(target=self._start_loop, daemon=True)
        self._thread.start()
        self._client: Optional[aioftp.Client] = None
        self._connected = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _start_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro: Coroutine[Any, Any, T]) -> asyncio.Future:
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    async def _ensure_client(self) -> aioftp.Client:
        if self._client is None:
            self._client = aioftp.Client()
        return self._client

    async def _connect(self) -> None:
        client = await self._ensure_client()
        await client.connect(self.profile.host, self.profile.port, ssl=self.profile.secure or None)
        await client.login(self.profile.user, self.profile.password)
        self._connected = True

    async def _disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.quit()
            finally:
                await self._client.close()
        self._client = None
        self._connected = False

    async def _pwd(self) -> str:
        if self._client is None:
            return "/"
        path = await self._client.get_current_directory()
        return str(path)

    async def _cwd(self, path: str) -> str:
        if self._client is None:
            raise RuntimeError("Client not connected")
        await self._client.change_directory(path)
        return await self._pwd()

    async def _list(self, path: Optional[str]) -> List[DirectoryEntry]:
        if self._client is None:
            raise RuntimeError("Client not connected")
        entries: List[DirectoryEntry] = []
        async for item_path, info in self._client.list(path or None):
            # info can be dict-like; fall back gracefully
            is_dir = str(info.get("type", "")).lower() == "dir"
            size_raw = info.get("size")
            try:
                size = int(size_raw) if size_raw is not None else None
            except (TypeError, ValueError):
                size = None
            modified = info.get("modify")
            entries.append(
                DirectoryEntry(name=item_path.name, is_dir=is_dir, size=size, modified=modified)
            )
        return entries

    async def _size(self, remote_path: str) -> int:
        if self._client is None:
            raise RuntimeError("Client not connected")
        stat = await self._client.stat(remote_path)
        size = getattr(stat, "size", None)
        if isinstance(size, (int, float)):
            return int(size)
        if size is None:
            return 0
        try:
            return int(size)
        except (TypeError, ValueError):
            return 0

    async def _download(self, remote_path: str, local_path: Path, queue: Queue) -> None:
        if self._client is None:
            raise RuntimeError("Client not connected")

        local_path.parent.mkdir(parents=True, exist_ok=True)

        async with self._client.download_stream(remote_path) as stream:
            with local_path.open("wb") as buffer:
                async for block in stream.iter_by_block(65536):
                    buffer.write(block)
                    queue.put(len(block))

        queue.put(None)

    async def _upload(self, local_path: Path, remote_path: str, queue: Queue) -> None:
        if self._client is None:
            raise RuntimeError("Client not connected")

        async with self._client.upload_stream(remote_path) as stream:
            with local_path.open("rb") as buffer:
                while True:
                    chunk = buffer.read(65536)
                    if not chunk:
                        break
                    await stream.write(chunk)
                    queue.put(len(chunk))

        queue.put(None)

    async def _mkdir(self, path: str) -> None:
        if self._client is None:
            raise RuntimeError("Client not connected")
        await self._client.make_directory(path)

    async def _remove(self, path: str) -> None:
        if self._client is None:
            raise RuntimeError("Client not connected")
        await self._client.remove_file(path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def connect(self) -> None:
        future = self._submit(self._connect())
        future.result()

    def disconnect(self) -> None:
        future = self._submit(self._disconnect())
        future.result()

    @property
    def connected(self) -> bool:
        return self._connected

    def pwd(self) -> str:
        future = self._submit(self._pwd())
        return future.result()

    def cd(self, path: str) -> str:
        future = self._submit(self._cwd(path))
        return future.result()

    def list_dir(self, path: Optional[str] = None) -> Iterable[DirectoryEntry]:
        future = self._submit(self._list(path))
        return future.result()

    def download(self, remote_path: str, local_path: str) -> None:
        target = Path(local_path)
        size_future = self._submit(self._size(remote_path))
        total = size_future.result()
        queue: Queue[int | None] = Queue()
        transfer_future = self._submit(self._download(remote_path, target, queue))
        run_progress_monitor(
            description=f"Downloading {remote_path}",
            total=total,
            queue=queue,
            future=transfer_future,
        )

    def upload(self, local_path: str, remote_path: str) -> None:
        source = Path(local_path)
        if not source.exists():
            raise FileNotFoundError(local_path)
        total = source.stat().st_size
        queue: Queue[int | None] = Queue()
        transfer_future = self._submit(self._upload(source, remote_path, queue))
        run_progress_monitor(
            description=f"Uploading {source.name}",
            total=total,
            queue=queue,
            future=transfer_future,
        )

    def show_directory_table(self, path: Optional[str] = None) -> None:
        entries = self.list_dir(path)
        table = Table(title=f"Directory listing for {path or self.pwd()}")
        table.add_column("Name", overflow="fold")
        table.add_column("Type")
        table.add_column("Size", justify="right")
        table.add_column("Modified", overflow="fold")
        for entry in entries:
            table.add_row(
                entry.name,
                "dir" if entry.is_dir else "file",
                f"{entry.size:,}" if entry.size else "-",
                entry.modified or "-",
            )
        console.print(table)

    def mkdir(self, path: str) -> None:
        future = self._submit(self._mkdir(path))
        future.result()

    def remove_file(self, path: str) -> None:
        future = self._submit(self._remove(path))
        future.result()

    def close(self) -> None:
        if self._connected:
            self.disconnect()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=1)


__all__ = ["FTPClient", "DirectoryEntry"]

