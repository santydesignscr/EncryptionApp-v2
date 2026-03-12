"""
app/crypto/kdf.py — Key Derivation Functions.

Two KDFs are provided:
  - derive_key_scrypt   : password → file/text encryption key  (Scrypt, memory-hard)
  - derive_key_pbkdf2   : password → vault master key          (PBKDF2-SHA256, high iterations)
"""

import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.config import (
    AES_KEY_SIZE,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
)


def generate_salt() -> bytes:
    """Return a cryptographically secure random salt of SALT_SIZE bytes."""
    return secrets.token_bytes(SALT_SIZE)


def derive_key_scrypt(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from *password* using Scrypt.

    Use this for file and text encryption where the cost parameters
    make brute-force attacks expensive even on GPUs / ASICs.

    Args:
        password: The user-supplied plaintext password.
        salt:     A random SALT_SIZE-byte value (must be stored alongside
                  the ciphertext so the same key can be re-derived).

    Returns:
        32-byte (256-bit) derived key.
    """
    kdf = Scrypt(
        salt=salt,
        length=AES_KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from *password* using PBKDF2-HMAC-SHA256.

    Used exclusively for the password vault master key.

    Args:
        password: The vault master password.
        salt:     A random SALT_SIZE-byte value stored in the vault file.

    Returns:
        32-byte (256-bit) derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))
