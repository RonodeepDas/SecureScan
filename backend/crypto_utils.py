"""
crypto_utils.py — AES-256-GCM field-level encryption for SecureScan.

Key material is loaded exclusively from the ENCRYPTION_KEY environment variable
(32 bytes, hex-encoded). Nothing is hard-coded.

Wire format (base64url-encoded):
  [ 12-byte nonce | ciphertext | 16-byte GCM tag ]
"""

import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

_NONCE_SIZE = 12  # 96-bit nonce recommended for GCM
_KEY_SIZE = 32    # 256-bit key


def _load_key() -> bytes:
    raw = os.environ.get("ENCRYPTION_KEY", "")
    if not raw:
        raise EnvironmentError(
            "ENCRYPTION_KEY is not set. "
            "Generate one with:\n"
            "  python -c \"import os, binascii; "
            "print(binascii.hexlify(os.urandom(32)).decode())\""
        )
    try:
        key = binascii.unhexlify(raw.strip())
    except Exception:
        raise ValueError("ENCRYPTION_KEY must be a 64-character hex string (32 bytes).")
    if len(key) != _KEY_SIZE:
        raise ValueError(
            f"ENCRYPTION_KEY must decode to exactly {_KEY_SIZE} bytes, got {len(key)}."
        )
    return key


# Load once at module import; fail fast on bad config.
_KEY: bytes = _load_key()
_AESGCM = AESGCM(_KEY)


def encrypt(plaintext: str) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns a URL-safe base64 string:  nonce || ciphertext+tag
    The GCM tag is appended to the ciphertext by the library.
    """
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext_with_tag = _AESGCM.encrypt(nonce, plaintext.encode(), None)
    blob = nonce + ciphertext_with_tag
    return base64.urlsafe_b64encode(blob).decode()


def decrypt(token: str) -> str:
    """
    Decrypt a token produced by *encrypt()*.
    Raises ValueError on any authentication or format failure.
    """
    try:
        blob = base64.urlsafe_b64decode(token.encode())
    except Exception as exc:
        raise ValueError(f"Invalid base64 token: {exc}") from exc

    if len(blob) < _NONCE_SIZE + 16:  # nonce + minimum tag
        raise ValueError("Token too short to be valid ciphertext.")

    nonce = blob[:_NONCE_SIZE]
    ciphertext_with_tag = blob[_NONCE_SIZE:]
    try:
        plaintext = _AESGCM.decrypt(nonce, ciphertext_with_tag, None)
    except Exception as exc:
        raise ValueError(f"Decryption failed (tampered data or wrong key): {exc}") from exc

    return plaintext.decode()
