"""
app/gui/app_window.py — Root application window.

Responsibilities
----------------
* Build the sidebar navigation and host page frames.
* Own the global "current key" state; notify pages when it changes.
* Create the TaskReporter (shared progress mediator) and the persistent
  TaskStatusBar shown at the very bottom of the window.
"""

from typing import Optional, Tuple

import customtkinter as ctk

from app.config import APP_NAME, APP_VERSION
from app.gui.pages.file_page import FilePage
from app.gui.pages.key_page import KeyPage
from app.gui.pages.text_page import TextPage
from app.gui.pages.vault_page import VaultPage
from app.gui.status_bar import TaskStatusBar
from app.gui.task_reporter import TaskReporter

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_DIVIDER = ("gray65", "gray35")
_MUTED   = ("gray35", "gray65")


class AppWindow(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}  |  AES-256-GCM")
        self.geometry("980x740")
        self.minsize(820, 620)

        self._current_key: Optional[bytes] = None
        self._key_source: str = ""

        # Shared task reporter — created before pages so it can be passed in
        self._reporter = TaskReporter(self)

        self._build_sidebar()
        self._build_content_area()   # pages + status bar stacked vertically
        self._show_page("file")

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        self._sidebar = ctk.CTkFrame(self, width=225, corner_radius=0)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        # Logo
        logo = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        logo.pack(pady=(24, 8), padx=16, fill="x")
        ctk.CTkLabel(
            logo, text="🔒 EncryptApp",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="center")
        ctk.CTkLabel(
            logo, text=f"v{APP_VERSION}  ·  AES-256-GCM",
            font=ctk.CTkFont(size=11), text_color=_MUTED,
        ).pack(anchor="center")

        ctk.CTkFrame(self._sidebar, height=1, fg_color=_DIVIDER).pack(fill="x", pady=12, padx=16)

        # Global key status indicator
        self._key_status = ctk.CTkLabel(
            self._sidebar, text="⚠  No key loaded",
            font=ctk.CTkFont(size=12), text_color="#e05252",
        )
        self._key_status.pack(padx=16, pady=(0, 8))

        # Navigation buttons
        nav_items = [
            ("📁  File Encrypt/Decrypt", "file"),
            ("📝  Text Encrypt/Decrypt", "text"),
            ("🔑  Key Management",        "key"),
            ("🔐  Password Vault",         "vault"),
        ]
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        _NAV_TEXT        = ("gray10",  "gray90")
        _NAV_HOVER       = ("#b8d0f0", "#2d5a8e")
        _NAV_ACTIVE_FG   = ("#2d6ab5", "#1f538d")
        _NAV_ACTIVE_TEXT = ("white",   "white")

        for label, page_id in nav_items:
            btn = ctk.CTkButton(
                self._sidebar, text=label, anchor="w",
                fg_color="transparent", hover_color=_NAV_HOVER,
                text_color=_NAV_TEXT,
                font=ctk.CTkFont(size=13), height=40, corner_radius=8,
                command=lambda p=page_id: self._show_page(p),
            )
            btn.pack(padx=12, pady=3, fill="x")
            self._nav_buttons[page_id] = btn

        # Spacer + bottom controls
        ctk.CTkFrame(self._sidebar, fg_color="transparent").pack(fill="y", expand=True)
        ctk.CTkFrame(self._sidebar, height=1, fg_color=_DIVIDER).pack(fill="x", padx=16, pady=8)
        self._theme_switch = ctk.CTkSwitch(
            self._sidebar, text="Light mode", command=self._toggle_theme
        )
        self._theme_switch.pack(padx=16, pady=(0, 20))

    # ── Content area (pages + bottom status bar) ──────────────────────────────

    def _build_content_area(self) -> None:
        # Outer frame that holds pages (top) + status bar (bottom)
        right = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True)

        # Page container — scrollable so long pages never hide the fixed status bar
        self._main = ctk.CTkScrollableFrame(right, corner_radius=0, fg_color="transparent")
        self._main.pack(side="top", fill="both", expand=True)

        # Pages receive the reporter so they can drive the global progress bar
        self._file_page  = FilePage(self._main, reporter=self._reporter,
                                    loaded_key_provider=self._get_loaded_key)
        self._text_page  = TextPage(self._main, reporter=self._reporter,
                                    loaded_key_provider=self._get_loaded_key)
        self._key_page   = KeyPage(self._main, on_key_loaded=self._on_key_loaded)
        self._vault_page = VaultPage(self._main)

        self._pages = {
            "file":  self._file_page,
            "text":  self._text_page,
            "key":   self._key_page,
            "vault": self._vault_page,
        }

        # Persistent status bar — always visible at the very bottom
        self._status_bar = TaskStatusBar(right, reporter=self._reporter)
        self._status_bar.pack(side="bottom", fill="x")

    def _show_page(self, page_id: str) -> None:
        for frame in self._pages.values():
            frame.pack_forget()
        self._pages[page_id].pack(fill="both", expand=True, padx=20, pady=(20, 8))

        _NAV_TEXT  = ("gray10", "gray90")
        for pid, btn in self._nav_buttons.items():
            if pid == page_id:
                btn.configure(fg_color=("#2d6ab5", "#1f538d"), text_color=("white", "white"))
            else:
                btn.configure(fg_color="transparent", text_color=_NAV_TEXT)

    # ── Key propagation ────────────────────────────────────────────────────────

    def _on_key_loaded(self, key: bytes, source: str) -> None:
        """Called by KeyPage when a key is generated or loaded."""
        self._current_key = key
        self._key_source  = source
        self._key_status.configure(
            text=f"✅  Key ready", text_color="#4caf7d"
        )
        # Notify pages so they can update their "loaded key" UI
        self._file_page.notify_key_changed(key, source)
        self._text_page.notify_key_changed(key, source)

    def _get_loaded_key(self) -> Optional[Tuple[bytes, str]]:
        if self._current_key:
            return self._current_key, self._key_source
        return None

    # ── Theme ──────────────────────────────────────────────────────────────────

    def _toggle_theme(self) -> None:
        ctk.set_appearance_mode("light" if self._theme_switch.get() else "dark")
