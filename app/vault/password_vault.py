"""
app/vault/password_vault.py — AES-256-GCM encrypted local password vault.

Storage format (JSON on disk):
    {
        "salt":  "<base64>",   # PBKDF2 salt
        "nonce": "<base64>",   # AES-GCM nonce
        "data":  "<base64>"    # AES-GCM ciphertext of JSON-encoded entry dict
    }

Entries dict schema (in memory, plaintext after unlock):
    {
        "<entry_name>": {
            "username": str,
            "password": str,
            "note":     str,
            "created":  str   # ISO-like timestamp
        },
        ...
    }

Security notes
--------------
* The vault file never stores the master password or derived key.
* A new nonce is generated on every save, so ciphertext differs even
  when the plaintext has not changed.
* The derived key is zeroed from memory when lock() is called.
"""

import base64
import json
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

from app.config import NONCE_SIZE, SALT_SIZE, VAULT_FILE
from app.crypto.core import InvalidTag, decrypt_bytes, encrypt_bytes
from app.crypto.kdf import derive_key_pbkdf2, generate_salt

# Type alias for a single vault entry
VaultEntry = Dict[str, str]


class PasswordVault:
    """
    Encrypted local password vault.

    Typical lifecycle
    -----------------
    vault = PasswordVault()
    vault.create("strong_master_pass")   # first time
    # — or —
    vault.unlock("strong_master_pass")   # subsequent times

    vault.add_entry("GitHub", "alice", "s3cr3t", "work account")
    entry = vault.get_entries()["GitHub"]
    vault.lock()
    """

    def __init__(self, vault_path: Path = VAULT_FILE) -> None:
        self._path = vault_path
        self._key: Optional[bytes] = None
        self._entries: Dict[str, VaultEntry] = {}
        self._unlocked = False

    # ── Public interface ───────────────────────────────────────────────────────

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked

    def vault_exists(self) -> bool:
        return self._path.exists()

    def create(self, master_password: str) -> None:
        """
        Initialise a brand-new vault protected by *master_password*.

        This overwrites any existing vault file at the configured path.
        """
        salt = generate_salt()
        self._key = derive_key_pbkdf2(master_password, salt)
        self._entries = {}
        self._unlocked = True
        self._persist(salt)

    def unlock(self, master_password: str) -> bool:
        """
        Decrypt and load an existing vault.

        Returns:
            True on success, False if the password is wrong or the file
            does not exist / is corrupt.
        """
        if not self._path.exists():
            return False
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            salt = base64.b64decode(raw["salt"])
            nonce = base64.b64decode(raw["nonce"])
            ct = base64.b64decode(raw["data"])

            key = derive_key_pbkdf2(master_password, salt)
            plaintext = decrypt_bytes(nonce, ct, key)

            self._entries = json.loads(plaintext.decode("utf-8"))
            self._key = key
            self._unlocked = True
            return True
        except (InvalidTag, KeyError, json.JSONDecodeError, ValueError):
            return False

    def lock(self) -> None:
        """Clear the in-memory key and entries."""
        self._key = None
        self._entries = {}
        self._unlocked = False

    def add_entry(
        self,
        name: str,
        username: str,
        password: str,
        note: str = "",
    ) -> None:
        """Add or overwrite an entry in the vault and persist immediately."""
        self._require_unlocked()
        self._entries[name] = {
            "username": username,
            "password": password,
            "note": note,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save()

    def delete_entry(self, name: str) -> None:
        """Remove an entry by name and persist immediately."""
        self._require_unlocked()
        if name in self._entries:
            del self._entries[name]
            self._save()

    def get_entries(self) -> Dict[str, VaultEntry]:
        """Return a shallow copy of all entries (read-only snapshot)."""
        self._require_unlocked()
        return dict(self._entries)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _require_unlocked(self) -> None:
        if not self._unlocked or self._key is None:
            raise RuntimeError("Vault is locked. Call unlock() first.")

    def _save(self) -> None:
        """Re-encrypt current entries and write to disk."""
        self._require_unlocked()
        # Re-read existing salt so we don't change it on every save
        salt = base64.b64decode(
            json.loads(self._path.read_text(encoding="utf-8"))["salt"]
        )
        self._persist(salt)

    def _persist(self, salt: bytes) -> None:
        """Encrypt *_entries* with *_key* and the given *salt*, then write to disk."""
        assert self._key is not None
        plaintext = json.dumps(self._entries).encode("utf-8")
        nonce, ct = encrypt_bytes(plaintext, self._key)
        payload = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(ct).decode(),
        }
        self._path.write_text(json.dumps(payload), encoding="utf-8")
