"""
app/gui/pages/text_page.py — Text Encryption / Decryption page.

Responsibilities
----------------
* Encrypt / decrypt arbitrary plaintext in memory using AES-256-GCM.
* Export ciphertext as a `.etxt` JSON file.
* Import and decrypt a `.etxt` file back to plaintext.
* Provide copy-to-clipboard and swap-input/output helpers.
* Mirror progress to the global TaskReporter / TaskStatusBar.
"""

import base64
import json
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable, Optional, Tuple, Union

import customtkinter as ctk

from app.crypto.core import InvalidTag, decrypt_bytes, encrypt_bytes, load_key_file
from app.crypto.kdf import derive_key_scrypt, generate_salt
from app.gui.task_reporter import TaskReporter
from app.gui.widgets import divider, section_title, status_label, subtitle

_MUTED = ("gray30", "gray65")


def _toggle_show(entry: ctk.CTkEntry, cb: ctk.CTkCheckBox) -> None:
    entry.configure(show="" if cb.get() else "●")


class TextPage(ctk.CTkFrame):
    """Page for encrypting/decrypting text and exporting/importing .etxt files."""

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
        self._build()

    # ── Public API (called by AppWindow) ──────────────────────────────────────

    def notify_key_changed(self, key: Optional[bytes], source: str) -> None:
        """Called when the global key changes (Key Management page)."""
        self._loaded_key        = key
        self._loaded_key_source = source
        self._refresh_loaded_key_card()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        section_title(self, "Text Encryption / Decryption").pack(
            pady=(20, 4), padx=24, anchor="w"
        )
        subtitle(self, "Encrypt plaintext and export as an encrypted .etxt file").pack(
            padx=24, anchor="w"
        )
        divider(self).pack(fill="x", padx=24, pady=12)

        # ── Import / Export buttons (above input to avoid confusion) ──────────
        io_row = ctk.CTkFrame(self, fg_color="transparent")
        io_row.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkButton(
            io_row, text="💾  Export .etxt", width=150, height=36,
            command=self._export,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            io_row, text="📂  Import .etxt", width=150, height=36,
            command=self._import,
        ).pack(side="left")

        # ── Input text area ───────────────────────────────────────────────────
        ctk.CTkLabel(self, text="Input Text:", font=ctk.CTkFont(size=13, weight="bold"),
                     anchor="w").pack(padx=24, anchor="w")
        self._input_box = ctk.CTkTextbox(self, height=130, corner_radius=8)
        self._input_box.pack(fill="x", padx=24, pady=(4, 8))

        divider(self).pack(fill="x", padx=24)

        # ── Key source tabs ───────────────────────────────────────────────────
        self._tabs = ctk.CTkTabview(self, height=120)
        self._tabs.pack(fill="x", padx=24, pady=(0, 4))
        self._tabs.add("🔒  Password")
        self._tabs.add("🔑  Key File")
        self._build_password_tab(self._tabs.tab("🔒  Password"))
        self._build_keyfile_tab(self._tabs.tab("🔑  Key File"))

        # ── Encrypt / Decrypt buttons ─────────────────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=8)
        ctk.CTkButton(
            btn_row, text="🔒  Encrypt", width=140, height=40,
            fg_color="#1f7a3a", hover_color="#166030",
            command=self._encrypt,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="🔓  Decrypt", width=140, height=40,
            fg_color="#1f3a7a", hover_color="#163060",
            command=self._decrypt,
        ).pack(side="left")

        divider(self).pack(fill="x", padx=24, pady=8)

        # ── Output text area (read-only) ──────────────────────────────────────
        ctk.CTkLabel(self, text="Output:", font=ctk.CTkFont(size=13, weight="bold"),
                     anchor="w").pack(padx=24, anchor="w")
        self._output_box = ctk.CTkTextbox(self, height=150, corner_radius=8, state="disabled")
        self._output_box.pack(fill="x", padx=24, pady=(4, 8))

        out_btn_row = ctk.CTkFrame(self, fg_color="transparent")
        out_btn_row.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkButton(
            out_btn_row, text="📋  Copy Output", width=140,
            command=self._copy_output,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            out_btn_row, text="🔄  Move Output → Input", width=180,
            command=self._swap,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            out_btn_row, text="🗑  Clear", width=90,
            fg_color=("gray75", "gray25"), hover_color=("gray65", "gray35"),
            command=self._clear_output,
        ).pack(side="left")

        self._status = status_label(self)
        self._status.pack(padx=24, anchor="w", pady=(0, 8))

    # ── Tab builders ──────────────────────────────────────────────────────────

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

    def _build_keyfile_tab(self, tab: ctk.CTkFrame) -> None:
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

    # ── Key resolution ─────────────────────────────────────────────────────────

    def _resolve_key(self) -> Optional[Tuple[Union[bytes, str], bool]]:
        """Return (key_data, is_keyfile) based on the active tab's selection."""
        tab = self._tabs.get()
        if "Password" in tab:
            pw = self._pw_var.get()
            if not pw:
                messagebox.showwarning("No Password", "Enter a password.")
                return None
            return (pw, False)

        # Key File tab
        if self._use_loaded_var.get() == "loaded":
            if not self._loaded_key:
                messagebox.showwarning("No Key", "No key is currently loaded.")
                return None
            return (self._loaded_key, True)

        kf = self._kf_var.get().strip()
        if not kf:
            messagebox.showwarning("No Key File", "Please browse to a key file.")
            return None
        try:
            key = load_key_file(kf)
            return (key, True)
        except Exception as exc:
            messagebox.showerror("Key File Error", str(exc))
            return None

    # ── Encrypt / Decrypt ──────────────────────────────────────────────────────

    def _encrypt(self) -> None:
        content = self._input_box.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("Empty Input", "Please enter text to encrypt.")
            return
        result = self._resolve_key()
        if result is None:
            return
        key_data, is_keyfile = result
        try:
            payload = self._build_payload(content.encode("utf-8"), key_data, is_keyfile)
            encoded = base64.b64encode(json.dumps(payload).encode()).decode()
            self._set_output(encoded)
            self._set_status("✅ Text encrypted successfully.", "#6BCB77")
        except Exception as exc:
            messagebox.showerror("Encryption Error", str(exc))

    def _decrypt(self) -> None:
        content = self._input_box.get("1.0", "end-1c").strip()
        if not content:
            messagebox.showwarning("Empty Input", "Please enter encrypted text to decrypt.")
            return
        result = self._resolve_key()
        if result is None:
            return
        key_data, is_keyfile = result
        try:
            plaintext = self._decrypt_payload(
                json.loads(base64.b64decode(content).decode()),
                key_data, is_keyfile,
            )
            self._set_output(plaintext.decode("utf-8"))
            self._set_status("✅ Text decrypted successfully.", "#6BCB77")
        except InvalidTag:
            messagebox.showerror("Decryption Failed", "Wrong key or corrupted / tampered ciphertext.")
        except Exception as exc:
            messagebox.showerror("Decryption Error", f"Failed to decrypt: {exc}")

    # ── Export / Import ────────────────────────────────────────────────────────

    def _export(self) -> None:
        content = self._input_box.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("Empty Input", "Please enter text to encrypt and export.")
            return
        result = self._resolve_key()
        if result is None:
            return
        path = filedialog.asksaveasfilename(
            title="Export encrypted text file",
            defaultextension=".etxt",
            filetypes=[("Encrypted Text", "*.etxt"), ("All Files", "*.*")],
        )
        if not path:
            return
        key_data, is_keyfile = result
        try:
            payload = self._build_payload(content.encode("utf-8"), key_data, is_keyfile)
            Path(path).write_text(json.dumps(payload), encoding="utf-8")
            self._set_status(f"✅ Exported to {Path(path).name}", "#6BCB77")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def _import(self) -> None:
        path = filedialog.askopenfilename(
            title="Import encrypted text file",
            filetypes=[("Encrypted Text", "*.etxt"), ("All Files", "*.*")],
        )
        if not path:
            return
        result = self._resolve_key()
        if result is None:
            return
        key_data, is_keyfile = result
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            plaintext = self._decrypt_payload(payload, key_data, is_keyfile)
            self._input_box.delete("1.0", "end")
            self._input_box.insert("1.0", plaintext.decode("utf-8"))
            self._output_box.configure(state="normal")
            self._output_box.delete("1.0", "end")
            self._output_box.configure(state="disabled")
            self._set_status(f"✅ Imported & decrypted from {Path(path).name}", "#6BCB77")
        except InvalidTag:
            messagebox.showerror("Decryption Failed", "Wrong key or file is corrupted / tampered.")
        except Exception as exc:
            messagebox.showerror("Import Error", str(exc))

    # ── Payload helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(plaintext: bytes, key_data, is_keyfile: bool) -> dict:
        if is_keyfile:
            nonce, ct = encrypt_bytes(plaintext, key_data)
            return {
                "mode": "keyfile",
                "nonce": base64.b64encode(nonce).decode(),
                "data": base64.b64encode(ct).decode(),
            }
        else:
            salt = generate_salt()
            key = derive_key_scrypt(key_data, salt)
            nonce, ct = encrypt_bytes(plaintext, key)
            return {
                "mode": "password",
                "salt": base64.b64encode(salt).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "data": base64.b64encode(ct).decode(),
            }

    @staticmethod
    def _decrypt_payload(payload: dict, key_data, is_keyfile: bool) -> bytes:
        mode = payload.get("mode", "password")
        nonce = base64.b64decode(payload["nonce"])
        ct = base64.b64decode(payload["data"])

        if mode == "keyfile":
            if not is_keyfile:
                raise ValueError(
                    "This text was encrypted with a key file. "
                    "Please load the correct key file."
                )
            return decrypt_bytes(nonce, ct, key_data)
        else:
            if is_keyfile:
                raise ValueError(
                    "This text was encrypted with a password. "
                    "Please enter the password instead of a key file."
                )
            salt = base64.b64decode(payload["salt"])
            key = derive_key_scrypt(key_data, salt)
            return decrypt_bytes(nonce, ct, key)

    # ── UI helpers ─────────────────────────────────────────────────────────────

    def _browse_kf(self) -> None:
        path = filedialog.askopenfilename(
            title="Select key file",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if path:
            self._kf_var.set(path)

    def _set_output(self, text: str) -> None:
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.insert("1.0", text)
        self._output_box.configure(state="disabled")

    def _copy_output(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._output_box.get("1.0", "end-1c"))
        self._set_status("📋 Output copied to clipboard.", "gray")

    def _swap(self) -> None:
        out = self._output_box.get("1.0", "end-1c")
        self._input_box.delete("1.0", "end")
        self._input_box.insert("1.0", out)
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")

    def _clear_output(self) -> None:
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")
        self._set_status("", "gray")

    def _set_status(self, text: str, color: str) -> None:
        self._status.configure(text=text, text_color=color)


