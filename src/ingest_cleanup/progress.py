from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import TextIO


class ProgressDisplay:
    """A single-line TTY display and a rate-limited log display."""

    def __init__(
        self,
        *,
        verbose: bool = False,
        expected_bytes: int | None = None,
        stream: TextIO | None = None,
        interval: float = 10.0,
    ) -> None:
        self.verbose = verbose
        self.expected_bytes = expected_bytes
        self.stream = stream or sys.stdout
        self.interval = interval
        self.tty = self.stream.isatty()
        self.phase = "Scanning"
        self.started = time.monotonic()
        self.last_emit = 0.0
        self.completed_by_path: dict[Path, int] = {}
        self.total_by_path: dict[Path, int] = {}
        self.current: Path | None = None
        self._line_open = False
        self._announced_phases: set[str] = set()

    @property
    def completed_bytes(self) -> int:
        return sum(self.completed_by_path.values())

    def set_phase(self, phase: str) -> None:
        if phase == self.phase:
            return
        if self.tty and self._line_open:
            print(file=self.stream, flush=True)
            self._line_open = False
        self.phase = phase
        if not self.tty and phase not in self._announced_phases:
            print(f"{phase}...", file=self.stream, flush=True)
            self._announced_phases.add(phase)

    def __call__(self, path: Path, complete: int, total: int) -> None:
        if total <= 0:
            return
        self.current = path
        self.completed_by_path[path] = complete
        self.total_by_path[path] = total
        now = time.monotonic()
        final_known = bool(self.expected_bytes and self.completed_bytes >= self.expected_bytes)
        if self.tty:
            self._emit(end="")
            self._line_open = True
        elif self.last_emit == 0.0 or now - self.last_emit >= self.interval or final_known:
            self._emit()
            self.last_emit = now

    def finish(self) -> None:
        if self.tty and self._line_open:
            print(file=self.stream, flush=True)
            self._line_open = False
        elif self.completed_by_path and time.monotonic() - self.last_emit > 0.05:
            self._emit()

    def _emit(self, *, end: str = "\n") -> None:
        elapsed = max(time.monotonic() - self.started, 0.001)
        completed = self.completed_bytes
        rate = completed / elapsed
        current_complete = self.completed_by_path.get(self.current, 0) if self.current else 0
        current_total = self.total_by_path.get(self.current, 0) if self.current else 0
        current_percent = current_complete * 100 // current_total if current_total else 0
        if self.expected_bytes:
            percent = min(100, completed * 100 // self.expected_bytes)
            progress = f"{percent}% | {completed / 2**20:.1f}/{self.expected_bytes / 2**20:.1f} MiB"
            remaining = max(0, self.expected_bytes - completed)
            eta = f" | ETA {remaining / rate:.0f}s" if rate > 0 and elapsed >= 1 else ""
        else:
            progress = f"file {current_percent}% | {completed / 2**20:.1f} MiB"
            eta = ""
        name = f" | {self.current.name}" if self.verbose and self.current else ""
        prefix = "\r\033[2K" if self.tty else ""
        print(
            f"{prefix}{self.phase} | {len(self.completed_by_path)} endpoint(s) | "
            f"{progress} | {rate / 2**20:.1f} MiB/s{eta}{name}",
            end=end,
            file=self.stream,
            flush=True,
        )

