"""Synthetic fixture helpers for wuwa-pak tests.

These helpers generate tiny, deterministic byte sequences for unit tests. They do
not use real game files, real Pak files, real database bytes, or real keys.
"""

from __future__ import annotations

import struct

TEST_AES_KEY = bytes(32)
FAKE_SQLITE_PAYLOAD = b"SQLite format 3\x00" + b"synthetic-only"


def fstring_utf8(value: str) -> bytes:
    raw = value.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def fstring_utf16(value: str) -> bytes:
    raw = value.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<i", -(len(raw) // 2)) + raw


def empty_fstring() -> bytes:
    return struct.pack("<i", 0)


def pak_footer(
    *,
    version: int = 12,
    index_offset: int = 128,
    index_size: int = 64,
    encrypted: bool = False,
    guid: bytes = bytes(16),
    compression_methods: tuple[str, ...] = ("Zlib",),
) -> bytes:
    footer = bytearray(221)
    footer[0:16] = guid
    footer[16] = 1 if encrypted else 0
    struct.pack_into("<I", footer, 17, 0x5A6F12E1)
    struct.pack_into("<I", footer, 21, version)
    struct.pack_into("<Q", footer, 25, index_offset)
    struct.pack_into("<Q", footer, 33, index_size)
    for index, name in enumerate(compression_methods[:5]):
        encoded = name.encode("ascii")[:31]
        base = 61 + index * 32
        footer[base : base + len(encoded)] = encoded
    return bytes(footer)
