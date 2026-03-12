"""
app/crypto/file_crypto.py — Chunked file encryption / decryption.

Design goals
------------
* Support arbitrarily large files without loading them into RAM.
* Authenticate every chunk independently (each has its own nonce+tag),
  so a truncated or reordered file is detected before any plaintext
  is written.
* Embed the original filename inside the ciphertext so the correct
  output name is restored on decryption.
* Allow callers to track progress via a callback and to cancel mid-way.

Binary format (password-encrypted files add a 6-byte prefix before this):
─────────────────────────────────────────────────────────────────────────
  FILE_MAGIC      (7 bytes)  b"ENCAPP2"
  FORMAT_VERSION  (1 byte)   b"\\x01"
  salt            (32 bytes) random — present but unused for key-file mode
  num_chunks      (8 bytes)  little-endian uint64
  For each chunk:
    nonce         (12 bytes)
    ct_len        (4 bytes)  little-endian uint32  (length of ciphertext+tag)
    ciphertext    (ct_len bytes)
  filename_nonce  (12 bytes)
  filename_ct_len (4 bytes)
  filename_ct     (filename_ct_len bytes)
─────────────────────────────────────────────────────────────────────────

Password-encrypted wrapper (prepended by encrypt_file_with_password):
  PASSWORD_FILE_MARKER (6 bytes) b"PWENC1"
  salt                 (32 bytes) — used for Scrypt KDF
  <rest of the format above>
"""

import os
import struct
from pathlib import Path
from typing import Callable, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import (
    CHUNK_SIZE,
    FILE_MAGIC,
    FORMAT_VERSION,
    NONCE_SIZE,
    PASSWORD_FILE_MARKER,
    SALT_SIZE,
)
from app.crypto.core import InvalidTag, generate_nonce
from app.crypto.kdf import derive_key_scrypt, generate_salt

ProgressCallback = Callable[[float], None]


# ── Public API ─────────────────────────────────────────────────────────────────

def encrypt_file(
    src: str,
    dst: str,
    key: bytes,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_flag: Optional[List[bool]] = None,
) -> None:
    """
    Encrypt *src* into *dst* using AES-256-GCM in chunked mode.

    Args:
        src:         Path to the plaintext input file.
        dst:         Path to write the encrypted output file.
        key:         32-byte AES-256 key (from key file or KDF).
        progress_cb: Called with a float in [0.0, 1.0] as chunks are processed.
        cancel_flag: A mutable list[bool]; set cancel_flag[0] = True to abort.

    Raises:
        InterruptedError: if cancel_flag[0] is set to True during processing.
    """
    src_path = Path(src)
    file_size = src_path.stat().st_size
    filename_bytes = src_path.name.encode("utf-8")
    aesgcm = AESGCM(key)

    num_chunks = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    salt = generate_salt()  # stored in header (used when wrapping with password)

    try:
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            _write_header(fout, salt, num_chunks)

            bytes_done = 0
            while True:
                _check_cancel(cancel_flag)
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = generate_nonce()
                ct = aesgcm.encrypt(nonce, chunk, None)
                fout.write(nonce)
                fout.write(struct.pack("<I", len(ct)))
                fout.write(ct)

                bytes_done += len(chunk)
                if progress_cb and file_size > 0:
                    progress_cb(bytes_done / file_size)

            # Append encrypted original filename
            fn_nonce = generate_nonce()
            fn_ct = aesgcm.encrypt(fn_nonce, filename_bytes, None)
            fout.write(fn_nonce)
            fout.write(struct.pack("<I", len(fn_ct)))
            fout.write(fn_ct)
    except BaseException:
        if os.path.exists(dst):
            os.remove(dst)
        raise


def decrypt_file(
    src: str,
    dst_dir: str,
    key: bytes,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_flag: Optional[List[bool]] = None,
) -> str:
    """
    Decrypt a chunked AES-256-GCM file produced by :func:`encrypt_file`.

    Args:
        src:         Path to the encrypted input file.
        dst_dir:     Directory where the decrypted file will be written.
        key:         32-byte AES-256 key.
        progress_cb: Called with a float in [0.0, 1.0] as chunks are decrypted.
        cancel_flag: A mutable list[bool]; set cancel_flag[0] = True to abort.

    Returns:
        Absolute path to the decrypted output file.

    Raises:
        ValueError:       if the file header is invalid.
        InvalidTag:       if the key is wrong or the file has been tampered with.
        InterruptedError: if cancel_flag[0] is set to True during processing.
    """
    aesgcm = AESGCM(key)

    with open(src, "rb") as fin:
        _read_and_validate_header(fin)
        num_chunks = struct.unpack("<Q", fin.read(8))[0]

        chunks = []
        for _ in range(num_chunks):
            _check_cancel(cancel_flag)
            nonce = fin.read(NONCE_SIZE)
            ct_len = struct.unpack("<I", fin.read(4))[0]
            ct = fin.read(ct_len)
            chunks.append((nonce, ct))

        fn_nonce = fin.read(NONCE_SIZE)
        fn_ct_len = struct.unpack("<I", fin.read(4))[0]
        fn_ct = fin.read(fn_ct_len)

    # Recover original filename (best-effort; fall back gracefully)
    try:
        original_name = aesgcm.decrypt(fn_nonce, fn_ct, None).decode("utf-8")
    except Exception:
        original_name = "decrypted_file"

    output_path = os.path.join(dst_dir, original_name)
    total = len(chunks)

    try:
        with open(output_path, "wb") as fout:
            for i, (nonce, ct) in enumerate(chunks):
                _check_cancel(cancel_flag)
                fout.write(aesgcm.decrypt(nonce, ct, None))
                if progress_cb:
                    progress_cb((i + 1) / total)
    except BaseException:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise

    return output_path


def encrypt_file_with_password(
    src: str,
    dst: str,
    password: str,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_flag: Optional[List[bool]] = None,
) -> None:
    """
    Derive a key from *password* via Scrypt and encrypt *src* → *dst*.

    The salt is prepended to the file (inside a PASSWORD_FILE_MARKER wrapper)
    so that decryption only requires the password — no separate salt storage.
    """
    salt = generate_salt()
    key = derive_key_scrypt(password, salt)

    tmp_path = dst + ".tmp_enc"
    try:
        encrypt_file(src, tmp_path, key, progress_cb, cancel_flag)
        # Wrap: PASSWORD_FILE_MARKER + salt + encrypted-file content
        with open(tmp_path, "rb") as fin, open(dst, "wb") as fout:
            fout.write(PASSWORD_FILE_MARKER)
            fout.write(salt)
            fout.write(fin.read())
    except BaseException:
        if os.path.exists(dst):
            os.remove(dst)
        raise
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def decrypt_file_with_password(
    src: str,
    dst_dir: str,
    password: str,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_flag: Optional[List[bool]] = None,
) -> str:
    """
    Decrypt a file previously encrypted with :func:`encrypt_file_with_password`.

    Returns:
        Absolute path to the decrypted output file.

    Raises:
        ValueError:  if the file does not start with PASSWORD_FILE_MARKER.
        InvalidTag:  wrong password or tampered file.
    """
    with open(src, "rb") as fin:
        marker = fin.read(len(PASSWORD_FILE_MARKER))
        if marker != PASSWORD_FILE_MARKER:
            raise ValueError(
                "This file was not encrypted with a password "
                "(missing PWENC1 marker). Use key-file decryption instead."
            )
        salt = fin.read(SALT_SIZE)
        inner_data = fin.read()

    key = derive_key_scrypt(password, salt)

    tmp_path = src + ".tmp_dec"
    try:
        with open(tmp_path, "wb") as fout:
            fout.write(inner_data)
        return decrypt_file(tmp_path, dst_dir, key, progress_cb, cancel_flag)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _write_header(fout, salt: bytes, num_chunks: int) -> None:
    fout.write(FILE_MAGIC)
    fout.write(FORMAT_VERSION)
    fout.write(salt)
    fout.write(struct.pack("<Q", num_chunks))


def _read_and_validate_header(fin) -> None:
    magic = fin.read(len(FILE_MAGIC))
    if magic != FILE_MAGIC:
        raise ValueError("Not a valid EncryptionApp v2 encrypted file.")
    version = fin.read(1)
    if version != FORMAT_VERSION:
        raise ValueError(f"Unsupported file format version: {version!r}")
    fin.read(SALT_SIZE)  # skip stored salt (used only for password wrapper)


def _check_cancel(cancel_flag: Optional[List[bool]]) -> None:
    if cancel_flag and cancel_flag[0]:
        raise InterruptedError("Operation was cancelled by the user.")
