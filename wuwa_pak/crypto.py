"""AES helpers for user-provided Pak keys."""

from __future__ import annotations

from Crypto.Cipher import AES


def key_from_hex(key_hex: str) -> bytes:
    normalized = key_hex.strip().removeprefix("0x").replace(" ", "")
    key = bytes.fromhex(normalized)
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes / 64 hex characters")
    return key


def decrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    pad = (16 - len(data) % 16) % 16
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data + b"\x00" * pad)[: len(data)]
