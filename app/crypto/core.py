"""
app/crypto/core.py — Low-level AES-256-GCM primitives.

All direct calls to the cryptography library's AESGCM API are
centralised here.  Higher layers use only these functions and
never import AESGCM themselves.

Functions
---------
generate_key()          → random 256-bit key
generate_nonce()        → random 96-bit nonce
encrypt_bytes()         → (nonce, ciphertext+tag)
decrypt_bytes()         → plaintext  (raises InvalidTag on failure)
generate_key_file()     → write key file to disk, return key bytes
load_key_file()         → read key file from disk, return key bytes
key_fingerprint()       → hex SHA-256 of key bytes (for display)
"""

import hashlib
import secrets
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidTag  # re-exported for callers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import AES_KEY_SIZE, KEY_FILE_MAGIC, NONCE_SIZE, SALT_SIZE

# Make InvalidTag importable from this module so callers have one import source.
__all__ = [
    "generate_key",
    "generate_nonce",
    "encrypt_bytes",
    "decrypt_bytes",
    "generate_key_file",
    "load_key_file",
    "key_fingerprint",
    "InvalidTag",
]


def generate_key() -> bytes:
    """Return a cryptographically secure random 256-bit AES key."""
    return secrets.token_bytes(AES_KEY_SIZE)


def generate_nonce() -> bytes:
    """Return a cryptographically secure random 96-bit GCM nonce."""
    return secrets.token_bytes(NONCE_SIZE)


def encrypt_bytes(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM using *key*.

    A fresh random nonce is generated for every call.

    Returns:
        (nonce, ciphertext)  — both must be stored; nonce is not secret.
    """
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-256-GCM.

    Raises:
        cryptography.exceptions.InvalidTag: if the key is wrong or the
            ciphertext has been tampered with.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Key-file helpers ───────────────────────────────────────────────────────────

def generate_key_file(path: str) -> bytes:
    """
    Generate a new random 256-bit key and persist it to *path*.

    File layout (binary):
        KEY_FILE_MAGIC (8 bytes)
        salt           (SALT_SIZE bytes) — reserved for future use
        nonce          (NONCE_SIZE bytes) — reserved for future use
        key            (AES_KEY_SIZE bytes)

    Returns:
        The raw key bytes that were written.
    """
    key = secrets.token_bytes(AES_KEY_SIZE)
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    with open(path, "wb") as fh:
        fh.write(KEY_FILE_MAGIC)
        fh.write(salt)
        fh.write(nonce)
        fh.write(key)

    return key


def load_key_file(path: str) -> bytes:
    """
    Load a key from a file previously created by :func:`generate_key_file`.

    Raises:
        ValueError: if the file has the wrong magic or is truncated.
    """
    with open(path, "rb") as fh:
        magic = fh.read(len(KEY_FILE_MAGIC))
        if magic != KEY_FILE_MAGIC:
            raise ValueError("Not a valid EncryptionApp key file.")
        fh.read(SALT_SIZE)   # skip reserved salt
        fh.read(NONCE_SIZE)  # skip reserved nonce
        key = fh.read(AES_KEY_SIZE)

    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key file is corrupt or truncated.")

    return key


def key_fingerprint(key: bytes) -> str:
    """
    Return a human-readable SHA-256 fingerprint of *key*.

    Formatted as groups of 4 hex characters separated by spaces,
    suitable for display in the UI — it lets users verify they're
    using the correct key without exposing the key itself.
    """
    digest = hashlib.sha256(key).hexdigest()
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))
