"""AES helpers for user-provided Pak keys."""

from __future__ import annotations

from Crypto.Cipher import AES


def key_from_hex(key_hex: str) -> bytes:
    """Parse an AES key from a hex string."""
    normalized = key_hex.strip().removeprefix("0x").replace(" ", "")
    key = bytes.fromhex(normalized)
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes / 64 hex characters")
    return key


def decrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    """Decrypt complete AES-256 ECB blocks.

    Pak metadata records the logical plaintext length separately, but encrypted
    regions in the archive are stored as complete AES blocks. Callers must read
    that padded region before decrypting and trim the plaintext themselves.
    """
    if len(data) % 16:
        raise ValueError("AES-ECB ciphertext length must be a multiple of 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)
