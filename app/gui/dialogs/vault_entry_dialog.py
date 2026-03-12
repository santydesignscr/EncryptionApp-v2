"""
app/gui/dialogs/vault_entry_dialog.py — Modal dialog for adding a vault entry.
"""

from tkinter import messagebox
from typing import Optional, Tuple

import customtkinter as ctk


class VaultEntryDialog(ctk.CTkToplevel):
    """
    Modal dialog that collects name, username, password and an optional note
    for a new password-vault entry.

    Usage::

        dialog = VaultEntryDialog(parent)
        parent.wait_window(dialog)
        if dialog.result:
            name, username, password, note = dialog.result
    """

    # (name, username, password, note) or None if cancelled
    result: Optional[Tuple[str, str, str, str]] = None

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Add Vault Entry")
        self.geometry("440x300")
        self.resizable(False, False)
        self.grab_set()
        self._build()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        ctk.CTkLabel(
            self, text="Add Password Entry",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=(20, 12))

        self._vars: dict[str, ctk.StringVar] = {}
        fields = [
            ("Entry Name *", "name", ""),
            ("Username / Email *", "user", ""),
            ("Password *", "pw", "●"),
            ("Note (optional)", "note", ""),
        ]
        for label, key, show in fields:
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(row, text=label, width=150, anchor="w").pack(side="left")
            var = ctk.StringVar()
            self._vars[key] = var
            ctk.CTkEntry(row, textvariable=var, show=show).pack(
                side="left", fill="x", expand=True
            )

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(16, 8))
        ctk.CTkButton(
            btn_row, text="Save", width=100,
            fg_color="#1f7a3a", hover_color="#166030",
            command=self._save,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Cancel", width=100, command=self.destroy
        ).pack(side="left")

    # ── Actions ────────────────────────────────────────────────────────────────

    def _save(self) -> None:
        name = self._vars["name"].get().strip()
        user = self._vars["user"].get().strip()
        pw = self._vars["pw"].get()
        note = self._vars["note"].get().strip()

        if not name or not pw:
            messagebox.showwarning(
                "Missing Fields", "Entry name and password are required.", parent=self
            )
            return

        self.result = (name, user, pw, note)
        self.destroy()
