"""
app/gui/pages/file_page.py — File Encryption / Decryption page.

Responsibilities
----------------
* Collect source file, destination path, and key material (password OR key
  file) via a tabbed UI.
* If a key was already loaded via Key Management, offer it for direct use
  and disable manual entry unless the user explicitly selects "Custom key".
* Delegate encryption/decryption to the crypto layer via background threads
  so the UI stays fully responsive.
* Report progress both to the local progress bar and to the shared
  TaskReporter (global status bar visible on every page).
"""

import threading
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable, List, Optional, Tuple, Union

import customtkinter as ctk

from app.crypto.core import InvalidTag, load_key_file
from app.crypto.file_crypto import (
    decrypt_file,
    decrypt_file_with_password,
    encrypt_file,
    encrypt_file_with_password,
)
from app.gui.task_reporter import TaskReporter
from app.gui.widgets import divider, section_title, status_label, subtitle

_MUTED = ("gray30", "gray65")


class FilePage(ctk.CTkFrame):
    """Page for encrypting and decrypting files of any size."""

    def __init__(
        self,
        parent,
        reporter: TaskReporter,
        loaded_key_provider: Callable[[], Optional[Tuple[bytes, str]]],
        **kwargs,
    ) -> None:
        super().__init__(parent, corner_radius=12, **kwargs)
        self._reporter            = reporter
        self._loaded_key_provider = loaded_key_provider
        self._loaded_key: Optional[bytes] = None
        self._loaded_key_source:  str     = ""
        self._dst_user_edited: bool = False
        self._build()

    # ── Public API (called by AppWindow) ──────────────────────────────────────

    def notify_key_changed(self, key: Optional[bytes], source: str) -> None:
        """Called when the global key changes (Key Management page)."""
        self._loaded_key        = key
        self._loaded_key_source = source
        self._refresh_loaded_key_card()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        section_title(self, "File Encryption / Decryption").pack(
            pady=(20, 4), padx=24, anchor="w"
        )
        subtitle(self, "Encrypt or decrypt files of any size using AES-256-GCM").pack(
            padx=24, anchor="w"
        )
        divider(self).pack(fill="x", padx=24, pady=12)

        # ── File paths ────────────────────────────────────────────────────────
        self._src_var = ctk.StringVar()
        self._dst_var = ctk.StringVar()
        self._src_var.trace_add("write", self._on_src_changed)
        self._dst_var.trace_add("write", self._on_dst_edited)
        self._add_browse_row("Input File:",  self._src_var, self._browse_src)
        self._add_browse_row("Output Path:", self._dst_var, self._browse_dst)

        divider(self).pack(fill="x", padx=24, pady=(8, 0))

        # ── Key source tabs ───────────────────────────────────────────────────
        self._tabs = ctk.CTkTabview(self, height=130)
        self._tabs.pack(fill="x", padx=24, pady=(0, 4))
        self._tabs.add("🔒  Password")
        self._tabs.add("🔑  Key File")
        self._build_password_tab(self._tabs.tab("🔒  Password"))
        self._build_keyfile_tab(self._tabs.tab("🔑  Key File"))

        # ── Action row ────────────────────────────────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=8)
        self._encrypt_btn = ctk.CTkButton(
            btn_row, text="🔒  Encrypt File", width=160, height=40,
            fg_color="#1f7a3a", hover_color="#166030",
            command=lambda: self._start("encrypt"),
        )
        self._encrypt_btn.pack(side="left", padx=(0, 12))
        self._decrypt_btn = ctk.CTkButton(
            btn_row, text="🔓  Decrypt File", width=160, height=40,
            fg_color="#1f3a7a", hover_color="#163060",
            command=lambda: self._start("decrypt"),
        )
        self._decrypt_btn.pack(side="left")

        self._status = status_label(self)
        self._status.pack(padx=24, anchor="w", pady=(0, 8))

    # ── Tab: Password ──────────────────────────────────────────────────────────

    def _build_password_tab(self, tab: ctk.CTkFrame) -> None:
        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=4, pady=(8, 4))
        ctk.CTkLabel(row, text="Password:", width=90, anchor="w").pack(side="left")
        self._pw_var   = ctk.StringVar()
        self._pw_entry = ctk.CTkEntry(
            row, textvariable=self._pw_var, show="●", placeholder_text="Enter password…"
        )
        self._pw_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._show_pw_cb = ctk.CTkCheckBox(
            row, text="Show", width=60,
            command=lambda: _toggle_show(self._pw_entry, self._show_pw_cb),
        )
        self._show_pw_cb.pack(side="left")

    # ── Tab: Key File ──────────────────────────────────────────────────────────

    def _build_keyfile_tab(self, tab: ctk.CTkFrame) -> None:
        # "Use loaded key from Key Management" card
        self._loaded_card = ctk.CTkFrame(tab, fg_color="transparent")
        self._loaded_card.pack(fill="x", padx=4, pady=(6, 0))

        self._use_loaded_var = ctk.StringVar(value="custom")
        self._loaded_radio = ctk.CTkRadioButton(
            self._loaded_card,
            text="Use loaded key from Key Management",
            variable=self._use_loaded_var, value="loaded",
            command=self._on_key_source_change,
        )
        self._loaded_radio.pack(side="left")
        self._loaded_fp_label = ctk.CTkLabel(
            self._loaded_card, text="", font=ctk.CTkFont(size=10), text_color=_MUTED
        )
        self._loaded_fp_label.pack(side="left", padx=(8, 0))

        # "Use custom key file"
        custom_row = ctk.CTkFrame(tab, fg_color="transparent")
        custom_row.pack(fill="x", padx=4, pady=(4, 0))
        ctk.CTkRadioButton(
            custom_row,
            text="Use custom key file:",
            variable=self._use_loaded_var, value="custom",
            command=self._on_key_source_change,
        ).pack(side="left", padx=(0, 8))
        self._kf_var   = ctk.StringVar()
        self._kf_entry = ctk.CTkEntry(
            custom_row, textvariable=self._kf_var,
            placeholder_text="Browse or paste path…"
        )
        self._kf_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._kf_browse_btn = ctk.CTkButton(
            custom_row, text="Browse", width=80, command=self._browse_kf
        )
        self._kf_browse_btn.pack(side="left")

        self._refresh_loaded_key_card()

    def _refresh_loaded_key_card(self) -> None:
        """Show/hide the 'loaded key' radio based on whether a key exists."""
        if self._loaded_key:
            from app.crypto.core import key_fingerprint
            fp = key_fingerprint(self._loaded_key)[:19] + "…"
            self._loaded_fp_label.configure(
                text=f"({self._loaded_key_source}  ·  {fp})"
            )
            self._loaded_radio.configure(state="normal")
        else:
            self._loaded_fp_label.configure(text="(no key loaded)")
            self._loaded_radio.configure(state="disabled")
            self._use_loaded_var.set("custom")
            self._on_key_source_change()

    def _on_key_source_change(self) -> None:
        using_loaded = (self._use_loaded_var.get() == "loaded")
        state = "disabled" if using_loaded else "normal"
        self._kf_entry.configure(state=state)
        self._kf_browse_btn.configure(state=state)

    # ── File dialogs ───────────────────────────────────────────────────────────

    def _browse_src(self) -> None:
        path = filedialog.askopenfilename(title="Select input file")
        if path:
            self._dst_user_edited = False   # new source resets the override flag
            self._src_var.set(path)         # triggers _on_src_changed

    def _browse_dst(self) -> None:
        src = self._src_var.get().strip()
        encrypting = not src.lower().endswith(".enc")
        if encrypting:
            ext   = ".enc"
            types = [("Encrypted files", "*.enc"), ("All files", "*.*")]
        else:
            # Decrypting: suggest the original extension derived from the source stem
            stem     = Path(src).stem if src else ""
            orig_ext = Path(stem).suffix or ""
            ext      = orig_ext
            types    = [("All files", "*.*")]
            if orig_ext:
                types.insert(0, (f"{orig_ext.lstrip('.')} files", f"*{orig_ext}"))
        current_dst = self._dst_var.get().strip()
        init_dir  = str(Path(current_dst).parent) if current_dst else ""
        init_file = Path(current_dst).name         if current_dst else ""
        path = filedialog.asksaveasfilename(
            title="Select output file",
            defaultextension=ext,
            filetypes=types,
            initialdir=init_dir,
            initialfile=init_file,
        )
        if path:
            self._dst_user_edited = True
            self._dst_var.set(path)

    # ── Output path auto-compute ───────────────────────────────────────────────

    def _on_src_changed(self, *_) -> None:
        """Recompute the suggested output path whenever the source changes."""
        if self._dst_user_edited:
            return
        self._update_dst_suggestion()

    def _on_dst_edited(self, *_) -> None:
        """Mark dst as user-edited only when the change came from direct typing.
        Browse already sets the flag explicitly, so we guard against our own
        programmatic writes with _dst_user_edited."""
        # Only count as user-edited when the src has a value
        # (avoids marking on the initial empty-string write at startup).
        if self._src_var.get() and not hasattr(self, "_dst_suppress"):
            self._dst_user_edited = True

    def _update_dst_suggestion(self) -> None:
        """Set _dst_var to the auto-suggested path without triggering user-edit flag."""
        src = self._src_var.get().strip()
        if not src:
            return
        p = Path(src)
        # Guess mode by extension: .enc → decrypting, anything else → encrypting
        if p.suffix.lower() == ".enc":
            suggested = str(p.parent / p.stem)   # strip .enc  →  original name
        else:
            suggested = str(p) + ".enc"          # append .enc
        self._dst_suppress = True
        try:
            self._dst_var.set(suggested)
        finally:
            del self._dst_suppress

    def _browse_kf(self) -> None:
        path = filedialog.askopenfilename(
            title="Select key file",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if path:
            self._kf_var.set(path)

    # ── Key resolution ─────────────────────────────────────────────────────────

    def _resolve_key(self) -> Optional[Tuple[str, Union[bytes, str]]]:
        """
        Determine which key/password to use.

        Returns:
            ("keyfile", key_bytes) | ("password", password_str) | None
        """
        tab = self._tabs.get()
        if "Password" in tab:
            pw = self._pw_var.get()
            if not pw:
                messagebox.showwarning("No Password", "Enter a password.")
                return None
            return ("password", pw)

        # Key File tab
        if self._use_loaded_var.get() == "loaded":
            if not self._loaded_key:
                messagebox.showwarning("No Key", "No key is currently loaded.")
                return None
            return ("keyfile", self._loaded_key)

        kf = self._kf_var.get().strip()
        if not kf:
            messagebox.showwarning("No Key File", "Please browse to a key file.")
            return None
        try:
            key = load_key_file(kf)
            return ("keyfile", key)
        except Exception as exc:
            messagebox.showerror("Key File Error", str(exc))
            return None

    # ── Operation ─────────────────────────────────────────────────────────────

    def _start(self, mode: str) -> None:
        src = self._src_var.get().strip()
        dst = self._dst_var.get().strip()
        if not src:
            messagebox.showwarning("Missing Input", "Please select an input file.")
            return
        if not dst:
            messagebox.showwarning("Missing Output", "Please specify an output path.")
            return
        key_info = self._resolve_key()
        if key_info is None:
            return

        cancel_flag: List[bool] = [False]
        self._encrypt_btn.configure(state="disabled")
        self._decrypt_btn.configure(state="disabled")
        verb = "Encrypting" if mode == "encrypt" else "Decrypting"
        self._set_status(f"{verb}…", ("gray40", "gray60"))

        fname = Path(src).name
        self._reporter.start(f"{verb} {fname}", cancel_flag)

        threading.Thread(
            target=self._worker,
            args=(mode, src, dst, key_info, cancel_flag),
            daemon=True,
        ).start()

    def _worker(
        self,
        mode: str,
        src: str,
        dst: str,
        key_info: Tuple[str, Union[bytes, str]],
        cancel_flag: List[bool],
    ) -> None:
        key_type, key_data = key_info
        try:
            if key_type == "keyfile":
                assert isinstance(key_data, bytes)
                key: bytes = key_data
                if mode == "encrypt":
                    encrypt_file(src, dst, key, self._reporter.progress, cancel_flag)
                    result_path = dst
                else:
                    result_path = decrypt_file(
                        src, str(Path(dst).parent), key,
                        self._reporter.progress, cancel_flag,
                        dst_name=Path(dst).name,
                    )
            else:
                assert isinstance(key_data, str)
                pw: str = key_data
                if mode == "encrypt":
                    encrypt_file_with_password(
                        src, dst, pw, self._reporter.progress, cancel_flag
                    )
                    result_path = dst
                else:
                    result_path = decrypt_file_with_password(
                        src, str(Path(dst).parent), pw,
                        self._reporter.progress, cancel_flag,
                        dst_name=Path(dst).name,
                    )

            verb = "Encrypted" if mode == "encrypt" else "Decrypted"
            msg  = f"{verb} → {Path(result_path).name}"
            self._reporter.finish(msg, success=True)
            self.after(0, lambda m=msg: self._done(True, m))

        except InterruptedError:
            self._reporter.finish("Cancelled", success=False)
            self.after(0, lambda: self._done(False, "Operation cancelled."))
        except InvalidTag:
            err = "Decryption failed: wrong key or tampered file."
            self._reporter.finish(err, success=False)
            self.after(0, lambda e=err: self._done(False, e, show_error=True))
        except Exception as exc:
            err = str(exc)
            self._reporter.finish(err, success=False)
            self.after(0, lambda e=err: self._done(False, e, show_error=True))

    def _done(self, success: bool, message: str, show_error: bool = False) -> None:
        self._encrypt_btn.configure(state="normal")
        self._decrypt_btn.configure(state="normal")
        # Reset so the next source selection re-triggers the auto-suggestion.
        self._dst_user_edited = False
        if success:
            self._set_status(f"✅  {message}", "#4caf7d")
        else:
            color = "#e05252" if show_error else "#FFA500"
            self._set_status(message, color)
            if show_error:
                messagebox.showerror("Operation Failed", message)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _set_status(self, text: str, color) -> None:
        self._status.configure(text=text, text_color=color)

    def _add_browse_row(self, label: str, var: ctk.StringVar, cmd) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(row, text=label, width=100, anchor="w").pack(side="left")
        ctk.CTkEntry(row, textvariable=var).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ctk.CTkButton(row, text="Browse", width=80, command=cmd).pack(side="left")


def _toggle_show(entry: ctk.CTkEntry, cb: ctk.CTkCheckBox) -> None:
    entry.configure(show="" if cb.get() else "●")
