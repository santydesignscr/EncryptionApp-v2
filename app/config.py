"""
app/config.py — Application-wide constants and configuration.
All magic numbers live here; nothing else should hard-code them.
"""

from pathlib import Path

# ── Application metadata ───────────────────────────────────────────────────────
APP_NAME = "EncryptionApp"
APP_VERSION = "2.0"

# ── AES-256-GCM parameters ────────────────────────────────────────────────────
AES_KEY_SIZE: int = 32          # bytes → 256-bit key
NONCE_SIZE: int = 12            # bytes → 96-bit GCM nonce (NIST recommended)
SALT_SIZE: int = 32             # bytes → 256-bit random salt

# ── Scrypt KDF parameters (password → file/text key) ─────────────────────────
# N=2^17 is the OWASP-recommended minimum for interactive logins (2024).
SCRYPT_N: int = 2 ** 17         # CPU/memory cost factor  (131 072)
SCRYPT_R: int = 8               # block size parameter
SCRYPT_P: int = 1               # parallelisation factor

# ── PBKDF2 parameters (password → vault master key) ───────────────────────────
PBKDF2_ITERATIONS: int = 600_000   # NIST SP 800-132 recommendation for SHA-256

# ── File processing ────────────────────────────────────────────────────────────
CHUNK_SIZE: int = 64 * 1024     # 64 KB per chunk — good balance for large files

# ── Encrypted-file binary format ──────────────────────────────────────────────
FILE_MAGIC: bytes = b"ENCAPP2"  # 7-byte magic header (identifies our format)
FORMAT_VERSION: bytes = b"\x01"
PASSWORD_FILE_MARKER: bytes = b"PWENC1"  # 6-byte prefix for password-encrypted files
KEY_FILE_MAGIC: bytes = b"KEYFILE2"      # 8-byte magic for key files

# ── Persistent storage locations ──────────────────────────────────────────────
VAULT_FILE: Path = Path.home() / ".encryptionapp_vault.json"
