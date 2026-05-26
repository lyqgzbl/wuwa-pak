"""Binary readers used by Pak parsing."""

from __future__ import annotations

import struct


def align16(value: int) -> int:
    return (value + 15) & ~15


def read_fstring(data: bytes, pos: int) -> tuple[str, int]:
    length = struct.unpack_from("<i", data, pos)[0]
    pos += 4
    if length == 0:
        return "", pos
    if length < 0:
        char_count = -length
        raw = data[pos : pos + char_count * 2]
        value = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return value, pos + char_count * 2
    value = data[pos : pos + length - 1].decode("utf-8", errors="replace")
    return value, pos + length
