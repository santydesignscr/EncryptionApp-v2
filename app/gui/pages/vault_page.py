"""
app/gui/pages/vault_page.py — Password Vault page.

Responsibilities
----------------
* Create / unlock / lock the encrypted password vault.
* Add, view, copy and delete vault entries.
* Delegate all crypto and persistence to PasswordVault in the vault layer.
"""

from tkinter import messagebox

import customtkinter as ctk

from app.gui.dialogs.vault_entry_dialog import VaultEntryDialog
from app.gui.widgets import divider, section_title, subtitle
from app.vault.password_vault import PasswordVault


class VaultPage(ctk.CTkFrame):
    """Page for the AES-256-GCM encrypted local password vault."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, corner_radius=12, **kwargs)
        self._vault = PasswordVault()
        self._build()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Header row
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(20, 4))
        section_title(header, "Password Vault").pack(side="left")
        ctk.CTkButton(
            header, text="🔒 Lock Vault", width=120,
            fg_color="#7a3a1f", hover_color="#6a2a0f",
            command=self._lock,
        ).pack(side="right")

        subtitle(self, "Store and manage passwords — encrypted with AES-256-GCM").pack(
            padx=24, anchor="w"
        )
        divider(self).pack(fill="x", padx=24, pady=12)

        # ── Unlock / create card ──────────────────────────────────────────────
        unlock_card = ctk.CTkFrame(self, corner_radius=10)
        unlock_card.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(
            unlock_card, text="Vault Access",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(padx=16, pady=(12, 4), anchor="w")

        access_row = ctk.CTkFrame(unlock_card, fg_color="transparent")
        access_row.pack(fill="x", padx=16, pady=(4, 12))
        self._master_var = ctk.StringVar()
        ctk.CTkEntry(
            access_row, textvariable=self._master_var,
            show="●", placeholder_text="Master password…",
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(
            access_row, text="Unlock", width=90, command=self._unlock
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            access_row, text="Create New", width=110, command=self._create
        ).pack(side="left")

        # ── Entry list card ───────────────────────────────────────────────────
        list_card = ctk.CTkFrame(self, corner_radius=10)
        list_card.pack(fill="both", expand=True, padx=24, pady=4)

        list_header = ctk.CTkFrame(list_card, fg_color="transparent")
        list_header.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            list_header, text="Stored Entries",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(side="left")
        ctk.CTkButton(
            list_header, text="➕ Add Entry", width=110, command=self._add_entry
        ).pack(side="right")

        self._list_frame = ctk.CTkScrollableFrame(list_card, height=220)
        self._list_frame.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self._status = ctk.CTkLabel(
            self, text="Vault is locked.",
            font=ctk.CTkFont(size=12), text_color="gray",
        )
        self._status.pack(padx=24, anchor="w", pady=(0, 12))

        self._refresh_list()

    # ── Vault lifecycle ────────────────────────────────────────────────────────

    def _unlock(self) -> None:
        pw = self._master_var.get()
        if not pw:
            messagebox.showwarning("No Password", "Enter the master password.")
            return
        if not self._vault.vault_exists():
            messagebox.showinfo("No Vault", "No vault found. Create a new one first.")
            return
        if self._vault.unlock(pw):
            self._set_status("✅ Vault unlocked.", "#6BCB77")
            self._refresh_list()
        else:
            messagebox.showerror("Unlock Failed", "Wrong master password or vault is corrupted.")

    def _create(self) -> None:
        pw = self._master_var.get()
        if not pw:
            messagebox.showwarning("No Password", "Enter a master password.")
            return
        if len(pw) < 8:
            messagebox.showwarning("Weak Password", "Master password must be at least 8 characters.")
            return
        if self._vault.vault_exists():
            if not messagebox.askyesno(
                "Overwrite Vault",
                "A vault already exists. Creating a new one will OVERWRITE it.\nContinue?",
            ):
                return
        self._vault.create(pw)
        self._set_status("✅ New vault created and unlocked.", "#6BCB77")
        self._refresh_list()

    def _lock(self) -> None:
        self._vault.lock()
        self._set_status("Vault is locked.", "gray")
        self._refresh_list()

    # ── Entry management ───────────────────────────────────────────────────────

    def _add_entry(self) -> None:
        if not self._vault.is_unlocked:
            messagebox.showwarning("Vault Locked", "Please unlock the vault first.")
            return
        dialog = VaultEntryDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            name, username, password, note = dialog.result
            self._vault.add_entry(name, username, password, note)
            self._refresh_list()

    def _refresh_list(self) -> None:
        for widget in self._list_frame.winfo_children():
            widget.destroy()

        if not self._vault.is_unlocked:
            ctk.CTkLabel(
                self._list_frame, text="🔒 Vault is locked.", text_color="gray"
            ).pack(pady=8)
            return

        entries = self._vault.get_entries()
        if not entries:
            ctk.CTkLabel(
                self._list_frame, text="No entries yet. Add one above.", text_color="gray"
            ).pack(pady=8)
            return

        for name, data in entries.items():
            self._build_entry_row(name, data)

    def _build_entry_row(self, name: str, data: dict) -> None:
        row = ctk.CTkFrame(
            self._list_frame, corner_radius=8, border_width=1, border_color="#2d2d2d"
        )
        row.pack(fill="x", pady=3)

        # Info section
        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=12, pady=8)
        ctk.CTkLabel(
            info, text=name, font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w")
        ctk.CTkLabel(
            info, text=f"👤 {data.get('username', '')}",
            font=ctk.CTkFont(size=11), text_color="gray",
        ).pack(anchor="w")
        if data.get("note"):
            ctk.CTkLabel(
                info, text=f"📝 {data['note']}",
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(anchor="w")

        # Action buttons
        btns = ctk.CTkFrame(row, fg_color="transparent")
        btns.pack(side="right", padx=8, pady=4)

        def copy_pw(n=name) -> None:
            pw = self._vault.get_entries()[n]["password"]
            self.clipboard_clear()
            self.clipboard_append(pw)
            self._set_status(f"📋 Password for '{n}' copied.", "gray")

        def show_pw(n=name) -> None:
            pw = self._vault.get_entries()[n]["password"]
            messagebox.showinfo(f"Password: {n}", f"Password: {pw}")

        def delete(n=name) -> None:
            if messagebox.askyesno("Delete Entry", f"Delete entry '{n}'?"):
                self._vault.delete_entry(n)
                self._refresh_list()

        ctk.CTkButton(btns, text="📋 Copy", width=70, height=28, command=copy_pw).pack(pady=2)
        ctk.CTkButton(btns, text="👁 Show", width=70, height=28, command=show_pw).pack(pady=2)
        ctk.CTkButton(
            btns, text="🗑 Delete", width=70, height=28,
            fg_color="#7a1f1f", hover_color="#601616",
            command=delete,
        ).pack(pady=2)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _set_status(self, text: str, color: str) -> None:
        self._status.configure(text=text, text_color=color)
