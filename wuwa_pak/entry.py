# Copyright 2026 lyqgzbl
#
# Licensed under the Apache License, Version 2.0. See the package LICENSE file.
#
# The Wuthering Waves Pak entry decoding behavior in this file was implemented
# with reference to CUE4Parse's Apache-2.0 licensed Pak entry implementation.
# See the package NOTICE file for attribution details.

"""Wuthering Waves Pak entry decoding."""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class PakEntry:
    name: str
    offset: int
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    compression_block_size: int
    encrypted: bool
    blocks: list[tuple[int, int]]
    struct_size: int
    custom_data: int


def decode_entry(
    data: bytes,
    offset: int,
    version: int,
    name: str = "",
) -> tuple[PakEntry, int]:
    """Decode a single Pak entry from the encoded index.

    Args:
        data: The raw binary data of the encoded index.
        offset: Offset within the data to start decoding.
        version: Pak format version.
        name: Filename of the entry (optional).

    Returns:
        A tuple containing the decoded PakEntry and the new offset.
    """
    pos = offset
    bitfield = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    custom_data = 0

    if version >= 12:
        bitfield = (
            ((bitfield >> 16) & 0x3F)
            | ((bitfield & 0xFFFF) << 6)
            | (((bitfield >> 28) & 1) << 22)
            | ((bitfield & 0x0FC00000) << 1)
            | ((bitfield & 0xC0000000) >> 1)
            | (((bitfield >> 29) & 1) << 31)
        )
        custom_data = data[pos]
        pos += 1

    block_size_encoded = bitfield & 0x3F
    if block_size_encoded == 0x3F:
        compression_block_size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    else:
        compression_block_size = block_size_encoded << 11

    compression_method = (bitfield >> 23) & 0x3F
    encrypted = bool(bitfield & (1 << 22))
    block_count = (bitfield >> 6) & 0xFFFF

    if bitfield & (1 << 31):
        file_offset = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    else:
        file_offset = struct.unpack_from("<q", data, pos)[0]
        pos += 8

    if bitfield & (1 << 30):
        uncompressed_size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    else:
        uncompressed_size = struct.unpack_from("<q", data, pos)[0]
        pos += 8

    if version >= 12:
        file_offset, uncompressed_size = uncompressed_size, file_offset

    if compression_method != 0:
        if bitfield & (1 << 29):
            compressed_size = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        else:
            compressed_size = struct.unpack_from("<q", data, pos)[0]
            pos += 8
    else:
        compressed_size = uncompressed_size

    if block_count == 1 and compression_block_size == 0:
        compression_block_size = uncompressed_size
    elif block_count == 0:
        compression_block_size = 0

    struct_size = 53
    if compression_method != 0:
        struct_size += 4 + block_count * 16

    alignment = 16 if encrypted else 1
    blocks: list[tuple[int, int]] = []
    block_offset = file_offset + struct_size

    if block_count == 1 and not encrypted:
        blocks.append((block_offset, block_offset + compressed_size))
    elif block_count > 0:
        for _ in range(block_count):
            block_length = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            blocks.append((block_offset, block_offset + block_length))
            block_offset += (block_length + alignment - 1) & ~(alignment - 1)

    return PakEntry(
        name=name,
        offset=file_offset,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        compression_method=compression_method,
        compression_block_size=compression_block_size,
        encrypted=encrypted,
        blocks=blocks,
        struct_size=struct_size,
        custom_data=custom_data,
    ), pos


def wuwa_encryption_limit(custom_data: int) -> float:
    """Determine the encryption limit based on Wuthering Waves custom data flags.

    Args:
        custom_data: The custom data flag from the Pak entry.

    Returns:
        The maximum number of bytes to decrypt (or infinity if fully encrypted).
    """
    if custom_data == 0:
        return float("inf")
    if custom_data == 1:
        return 0x200000
    if custom_data == 2:
        return 0x800
    if custom_data == 4:
        return 0
    return float("inf")
