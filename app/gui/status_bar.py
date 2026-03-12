"""
app/gui/status_bar.py — Persistent global task status bar.

Shown at the very bottom of the application window regardless of which
page is active, so users can monitor (and cancel) long-running operations
even after switching tabs.
"""

import customtkinter as ctk

from app.gui.task_reporter import TaskReporter


class TaskStatusBar(ctk.CTkFrame):
    """
    Thin always-visible bar at the bottom of the window.

    Layout:  [task label ─── progress bar ─────────────────── ✕ Cancel]
    """

    def __init__(self, parent, reporter: TaskReporter, **kwargs) -> None:
        super().__init__(parent, height=46, corner_radius=0, **kwargs)
        self.pack_propagate(False)
        self._reporter = reporter
        self._build()

        # Register our callbacks with the reporter
        reporter.bind_status_bar(
            on_start=self._on_start,
            on_progress=self._on_progress,
            on_finish=self._on_finish,
        )

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Thin top border
        ctk.CTkFrame(self, height=1, fg_color=("gray70", "gray30")).pack(fill="x")

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True)

        # Task name label (fixed width on the left)
        self._task_label = ctk.CTkLabel(
            content,
            text="Idle",
            width=180,
            anchor="w",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
        )
        self._task_label.pack(side="left", padx=(12, 8), pady=0)

        # Cancel button (right side, always present but disabled when idle)
        self._cancel_btn = ctk.CTkButton(
            content,
            text="✕ Cancel",
            width=90,
            height=28,
            fg_color="#7a1f1f",
            hover_color="#601616",
            state="disabled",
            command=self._reporter.request_cancel,
        )
        self._cancel_btn.pack(side="right", padx=12)

        # Progress bar fills remaining space
        self._bar = ctk.CTkProgressBar(content, height=10, corner_radius=5)
        self._bar.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=0)
        self._bar.set(0)

    # ── Reporter callbacks (always called on main thread via root.after) ───────

    def _on_start(self, task_name: str) -> None:
        self._task_label.configure(
            text=f"⏳  {task_name}",
            text_color=("gray20", "gray80"),
        )
        self._bar.set(0)
        self._cancel_btn.configure(state="normal")

    def _on_progress(self, fraction: float) -> None:
        self._bar.set(fraction)

    def _on_finish(self, message: str, success: bool) -> None:
        color  = "#4caf7d" if success else "#e05252"
        prefix = "✅" if success else "❌"
        self._task_label.configure(text=f"{prefix}  {message}", text_color=color)
        self._cancel_btn.configure(state="disabled")
