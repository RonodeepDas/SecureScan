"""
tests/test_crypto.py — AES-256-GCM roundtrip and tamper-detection tests.
"""

import binascii
import os
import pytest

# Set ENCRYPTION_KEY before importing crypto_utils
os.environ["ENCRYPTION_KEY"] = binascii.hexlify(os.urandom(32)).decode()

from crypto_utils import decrypt, encrypt  # noqa: E402


def test_roundtrip_simple():
    original = "hello, SecureScan!"
    assert decrypt(encrypt(original)) == original


def test_roundtrip_unicode():
    original = "パスワード 🔐 café"
    assert decrypt(encrypt(original)) == original


def test_roundtrip_empty_string():
    assert decrypt(encrypt("")) == ""


def test_roundtrip_long_string():
    original = "x" * 10_000
    assert decrypt(encrypt(original)) == original


def test_different_ciphertexts_for_same_plaintext():
    """Each call must use a fresh nonce → different ciphertext."""
    pt = "same plaintext"
    c1 = encrypt(pt)
    c2 = encrypt(pt)
    assert c1 != c2  # nonces differ


def test_tamper_detection():
    """Flipping a byte in the ciphertext must raise ValueError."""
    token = encrypt("important data")
    # Flip one byte in the base64-decoded blob
    import base64
    blob = bytearray(base64.urlsafe_b64decode(token))
    blob[-1] ^= 0xFF
    tampered = base64.urlsafe_b64encode(bytes(blob)).decode()
    with pytest.raises(ValueError):
        decrypt(tampered)


def test_decrypt_garbage():
    with pytest.raises(ValueError):
        decrypt("not-valid-base64!!!")


def test_decrypt_too_short():
    import base64
    short = base64.urlsafe_b64encode(b"\x00" * 5).decode()
    with pytest.raises(ValueError):
        decrypt(short)
