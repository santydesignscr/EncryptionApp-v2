"""
app/gui/task_reporter.py — Thread-safe bridge between background workers and the UI.

Usage (in a worker thread):
    reporter.start("Encrypting…", cancel_flag)
    reporter.progress(0.5)   # throttled, safe from any thread
    reporter.finish("Done!", success=True)

The status bar and active page subscribe via bind_callbacks() /
bind_page_progress() and receive all updates on the main thread through
root.after(), so the UI never blocks.
"""

import time
from typing import Callable, List, Optional

_THROTTLE_S: float = 0.04  # max ~25 progress updates / second


class TaskReporter:
    """Mediates task progress between background threads and the UI layer."""

    def __init__(self, root) -> None:
        self._root = root

        # Callbacks registered by the global status bar
        self._on_start:    Optional[Callable[[str], None]]        = None
        self._on_progress: Optional[Callable[[float], None]]      = None
        self._on_finish:   Optional[Callable[[str, bool], None]]   = None

        self._cancel_flag: List[bool] = [False]
        self._last_t: float = 0.0
        self._active: bool = False

    # ── Registration ──────────────────────────────────────────────────────────

    def bind_status_bar(
        self,
        on_start:    Callable[[str], None],
        on_progress: Callable[[float], None],
        on_finish:   Callable[[str, bool], None],
    ) -> None:
        """Called once by TaskStatusBar to receive lifecycle callbacks."""
        self._on_start    = on_start
        self._on_progress = on_progress
        self._on_finish   = on_finish

    # ── Worker-thread API ──────────────────────────────────────────────────────

    def start(self, task_name: str, cancel_flag: List[bool]) -> None:
        """Signal the start of a task. Safe to call from a worker thread."""
        self._cancel_flag = cancel_flag
        self._active = True
        self._last_t = 0.0
        if self._on_start:
            cb = self._on_start
            self._root.after(0, lambda n=task_name: cb(n))

    def progress(self, fraction: float) -> None:
        """
        Report current progress as a value in [0.0, 1.0].
        Throttled — safe to call in tight loops from worker threads.
        """
        now = time.monotonic()
        if now - self._last_t < _THROTTLE_S:
            return
        self._last_t = now
        if self._on_progress:
            cb_prog = self._on_progress
            self._root.after(0, lambda f=fraction: cb_prog(f))

    def finish(self, message: str, success: bool = True) -> None:
        """Signal completion or failure. Safe to call from a worker thread."""
        self._active = False
        final = 1.0 if success else 0.0
        if self._on_progress:
            cb_prog = self._on_progress
            self._root.after(0, lambda f=final: cb_prog(f))
        if self._on_finish:
            cb_fin = self._on_finish
            self._root.after(0, lambda m=message, s=success: cb_fin(m, s))

    # ── UI-thread API ──────────────────────────────────────────────────────────

    def request_cancel(self) -> None:
        """Request cancellation of the running task (call from UI thread)."""
        self._cancel_flag[0] = True

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def cancel_flag(self) -> List[bool]:
        return self._cancel_flag
