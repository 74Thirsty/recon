"""Progress bar utilities built with Rich."""

from __future__ import annotations

from queue import Empty, Queue
from typing import Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)


console = Console()


def _create_progress() -> Progress:
    return Progress(
        TextColumn("{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TransferSpeedColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )


def run_progress_monitor(
    *,
    description: str,
    total: Optional[int],
    queue: Queue,
    future,
) -> None:
    """Render a progress bar while monitoring a queue for updates."""

    if total in (0, None):
        total = None

    with _create_progress() as progress:
        task_id: TaskID = progress.add_task(description, total=total)
        while True:
            try:
                update = queue.get(timeout=0.1)
                if update is None:
                    progress.refresh()
                    break
                progress.advance(task_id, update)
            except Empty:
                pass

            if future.done():
                break

        # Wait for the transfer to finish and surface exceptions
        future.result()


__all__ = ["run_progress_monitor"]

