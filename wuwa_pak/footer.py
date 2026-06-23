"""Pak footer parsing."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

PAK_FOOTER_SIZE = 221
PAK_MAGIC = 0x5A6F12E1


@dataclass(frozen=True)
class PakFooter:
    version: int
    index_offset: int
    index_size: int
    encrypted: bool
    compression_methods: list[str]
    guid: bytes


def read_footer(file: BinaryIO) -> PakFooter | None:
    """Read and parse the Pak footer from the end of the file."""
    file.seek(-PAK_FOOTER_SIZE, 2)
    footer = file.read(PAK_FOOTER_SIZE)
    magic = struct.unpack_from("<I", footer, 17)[0]
    if magic != PAK_MAGIC:
        return None

    compression_methods = ["None"]
    for i in range(5):
        base = 61 + i * 32
        name = (
            footer[base : base + 32]
            .split(b"\x00", 1)[0]
            .decode(
                "ascii",
                errors="replace",
            )
        )
        if name:
            compression_methods.append(name)

    return PakFooter(
        version=struct.unpack_from("<I", footer, 21)[0],
        index_offset=struct.unpack_from("<Q", footer, 25)[0],
        index_size=struct.unpack_from("<Q", footer, 33)[0],
        encrypted=footer[16] != 0,
        compression_methods=compression_methods,
        guid=footer[0:16],
    )
