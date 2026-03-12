"""
app/gui/pages/key_page.py — Key Management page.

Responsibilities
----------------
* Generate a new secure 256-bit key file.
* Load an existing key file and expose it to the rest of the app via a callback.
* Display the key fingerprint (SHA-256 display hash) for verification.
"""

from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable, Optional

import customtkinter as ctk

from app.crypto.core import generate_key_file, key_fingerprint, load_key_file
from app.gui.widgets import divider, section_title, subtitle


class KeyPage(ctk.CTkFrame):
    """Page for generating and loading AES-256 key files."""

    def __init__(self, parent, on_key_loaded: Callable[[bytes, str], None], **kwargs):
        """
        Args:
            on_key_loaded: Callback invoked with (key_bytes, source_description)
                           when a key is successfully generated or loaded.
        """
        super().__init__(parent, corner_radius=12, **kwargs)
        self._on_key_loaded = on_key_loaded
        self._current_key: Optional[bytes] = None
        self._build()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        section_title(self, "Key Management").pack(pady=(20, 4), padx=24, anchor="w")
        subtitle(self, "Generate & manage AES-256 key files").pack(padx=24, anchor="w")
        divider(self).pack(fill="x", padx=24, pady=12)

        # ── Generate section ──────────────────────────────────────────────────
        gen_card = ctk.CTkFrame(self, corner_radius=10)
        gen_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            gen_card, text="Generate New Key File",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(padx=16, pady=(12, 4), anchor="w")
        ctk.CTkLabel(
            gen_card,
            text=(
                "Creates a cryptographically secure 256-bit random key file.\n"
                "Store it safely — losing this file means losing access to encrypted data."
            ),
            font=ctk.CTkFont(size=12), text_color="gray", justify="left",
        ).pack(padx=16, anchor="w")

        gen_row = ctk.CTkFrame(gen_card, fg_color="transparent")
        gen_row.pack(fill="x", padx=16, pady=(8, 12))
        self._gen_path_var = ctk.StringVar()
        ctk.CTkEntry(
            gen_row, textvariable=self._gen_path_var, placeholder_text="Output key file path…"
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(
            gen_row, text="Choose Path", width=110, command=self._browse_gen_path
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            gen_row, text="🔑  Generate", width=110,
            fg_color="#1f7a3a", hover_color="#166030",
            command=self._generate,
        ).pack(side="left")

        # ── Load section ──────────────────────────────────────────────────────
        load_card = ctk.CTkFrame(self, corner_radius=10)
        load_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            load_card, text="Load Key File",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(padx=16, pady=(12, 4), anchor="w")
        ctk.CTkLabel(
            load_card,
            text="Load a previously generated key file to use for encrypt/decrypt operations.",
            font=ctk.CTkFont(size=12), text_color="gray",
        ).pack(padx=16, anchor="w")

        load_row = ctk.CTkFrame(load_card, fg_color="transparent")
        load_row.pack(fill="x", padx=16, pady=(8, 12))
        self._load_path_var = ctk.StringVar()
        ctk.CTkEntry(
            load_row, textvariable=self._load_path_var, placeholder_text="Key file path…"
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(
            load_row, text="Browse", width=80, command=self._browse_load_path
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            load_row, text="🔓  Load Key", width=110, command=self._load
        ).pack(side="left")

        # ── Status card ───────────────────────────────────────────────────────
        self._status_card = ctk.CTkFrame(self, corner_radius=10, border_width=1,
                                          border_color="#1f538d")
        self._status_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            self._status_card, text="Current Key Status",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(padx=16, pady=(12, 4), anchor="w")
        self._status_label = ctk.CTkLabel(
            self._status_card, text="No key loaded.",
            font=ctk.CTkFont(size=12),
        )
        self._status_label.pack(padx=16, pady=(0, 12), anchor="w")

        # ── Fingerprint ───────────────────────────────────────────────────────
        fp_card = ctk.CTkFrame(self, corner_radius=10)
        fp_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            fp_card, text="Key Fingerprint  (SHA-256)",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(padx=16, pady=(12, 4), anchor="w")
        self._fp_label = ctk.CTkLabel(
            fp_card, text="—",
            font=ctk.CTkFont(family="Courier", size=11), text_color="#4EC9B0",
        )
        self._fp_label.pack(padx=16, pady=(0, 12), anchor="w")

    # ── Actions ────────────────────────────────────────────────────────────────

    def _browse_gen_path(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save key file as",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if path:
            self._gen_path_var.set(path)

    def _browse_load_path(self) -> None:
        path = filedialog.askopenfilename(
            title="Load key file",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if path:
            self._load_path_var.set(path)

    def _generate(self) -> None:
        path = self._gen_path_var.get().strip()
        if not path:
            messagebox.showwarning("No Path", "Please specify a path for the key file.")
            return
        try:
            key = generate_key_file(path)
            self._apply_key(key, f"Key File: {Path(path).name}")
            messagebox.showinfo(
                "Key Generated",
                f"Key file saved to:\n{path}\n\n"
                "⚠ Keep this file safe. Anyone with it can decrypt your data.",
            )
        except Exception as exc:
            messagebox.showerror("Generation Error", str(exc))

    def _load(self) -> None:
        path = self._load_path_var.get().strip()
        if not path:
            messagebox.showwarning("No Path", "Please specify a key file to load.")
            return
        try:
            key = load_key_file(path)
            self._apply_key(key, f"Key File: {Path(path).name}")
            messagebox.showinfo("Key Loaded", f"Key loaded successfully:\n{path}")
        except Exception as exc:
            messagebox.showerror("Load Error", str(exc))

    def _apply_key(self, key: bytes, source: str) -> None:
        self._current_key = key
        self._status_label.configure(text=f"Source: {source}\nKey size: 256 bits")
        self._fp_label.configure(text=key_fingerprint(key))
        self._on_key_loaded(key, source)

    # ── Public ─────────────────────────────────────────────────────────────────

    def update_status(self, key: Optional[bytes], source: str) -> None:
        """Update the UI to reflect a key change triggered elsewhere."""
        if key:
            self._fp_label.configure(text=key_fingerprint(key))
            self._status_label.configure(text=f"Source: {source}\nKey size: 256 bits")
        else:
            self._fp_label.configure(text="—")
            self._status_label.configure(text="No key loaded.")
