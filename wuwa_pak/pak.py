# Copyright 2026 lyqgzbl
#
# Licensed under the Apache License, Version 2.0. See the package LICENSE file.
#
# The Wuthering Waves Pak parsing and partial encryption behavior in this file
# was implemented with reference to CUE4Parse's Apache-2.0 licensed Pak reader
# implementation. See the package NOTICE file for attribution details.

"""Pak archive parsing and extraction."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from math import isinf
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from wuwa_pak.binary import align16, read_fstring
from wuwa_pak.crypto import decrypt_aes_ecb, key_from_hex
from wuwa_pak.entry import PakEntry, decode_entry, wuwa_encryption_limit
from wuwa_pak.footer import PakFooter, read_footer


@dataclass
class PakArchive:
    path: Path
    footer: PakFooter
    entries: list[PakEntry]
    key: bytes

    @classmethod
    def open(cls, pak_path: str | Path, key_hex: str) -> PakArchive:
        """Open a Pak archive and parse its index.

        Args:
            pak_path: Path to the Pak file.
            key_hex: AES key as a hex string.

        Returns:
            The parsed PakArchive instance.
        """
        path = Path(pak_path)
        key = key_from_hex(key_hex)
        with path.open("rb") as file:
            footer = read_footer(file)
            if footer is None:
                raise ValueError(f"Not a supported Pak file: {path}")
            entries = _read_entries(file, footer, key)
        return cls(path=path, footer=footer, entries=entries, key=key)

    def extract_entry(self, entry: PakEntry) -> bytes:
        """Extract the uncompressed data for a specific entry.

        Args:
            entry: The PakEntry to extract.

        Returns:
            Uncompressed file data.
        """
        with self.path.open("rb") as file:
            return _extract_entry(
                file,
                entry,
                self.footer.compression_methods,
                self.key,
            )


def _decrypt(data: bytes, key: bytes) -> bytes:
    return decrypt_aes_ecb(data, key)


def _read_entries(file: BinaryIO, footer: PakFooter, key: bytes) -> list[PakEntry]:
    index_read_size = (
        align16(footer.index_size) if footer.encrypted else footer.index_size
    )
    file.seek(0, 2)
    file_size = file.tell()
    if (
        footer.index_offset < 0
        or footer.index_size < 0
        or footer.index_offset + index_read_size > file_size
    ):
        raise ValueError("Pak index points outside the archive")
    file.seek(footer.index_offset)
    index_raw = file.read(index_read_size)
    if len(index_raw) != index_read_size:
        raise ValueError("Pak index is truncated")
    if footer.encrypted:
        index_raw = _decrypt(index_raw, key)[: footer.index_size]

    try:
        pos = 0
        mount, pos = read_fstring(index_raw, pos)
        file_count = struct.unpack_from("<i", index_raw, pos)[0]
        pos += 4
        if file_count <= 0 or file_count > 1_000_000:
            return []
        pos += 8

        has_path_hash_index = struct.unpack_from("<i", index_raw, pos)[0]
        pos += 4
        if has_path_hash_index:
            pos += 8 + 8 + 20

        has_full_directory_index = struct.unpack_from("<i", index_raw, pos)[0]
        pos += 4
        full_directory_offset = full_directory_size = 0
        if has_full_directory_index:
            full_directory_offset = struct.unpack_from("<q", index_raw, pos)[0]
            pos += 8
            full_directory_size = struct.unpack_from("<q", index_raw, pos)[0]
            pos += 8 + 20

        encoded_size = struct.unpack_from("<i", index_raw, pos)[0]
        pos += 4
        if encoded_size < 0 or pos + encoded_size > len(index_raw):
            raise ValueError("invalid encoded Pak entry size")
        encoded_entries = index_raw[pos : pos + encoded_size]
    except (IndexError, struct.error, ValueError) as exc:
        raise ValueError("invalid Pak index") from exc

    filenames: dict[int, str] = {}
    if has_full_directory_index and full_directory_size > 0:
        filenames = _read_full_directory_index(
            file,
            mount,
            full_directory_offset,
            full_directory_size,
            footer.encrypted,
            key,
        )

    entries: list[PakEntry] = []
    for entry_index in sorted(filenames):
        try:
            entry, _ = decode_entry(
                encoded_entries,
                entry_index,
                footer.version,
                name=filenames[entry_index],
            )
        except (struct.error, IndexError, ValueError):
            continue
        entries.append(entry)
    return entries


def _read_full_directory_index(
    file: BinaryIO,
    mount: str,
    offset: int,
    size: int,
    encrypted: bool,
    key: bytes,
) -> dict[int, str]:
    if offset < 0 or size < 0:
        raise ValueError("invalid full directory index range")
    read_size = align16(size) if encrypted else size
    file.seek(0, 2)
    if offset + read_size > file.tell():
        raise ValueError("full directory index points outside the archive")
    file.seek(offset)
    raw = file.read(read_size)
    if len(raw) != read_size:
        raise ValueError("full directory index is truncated")
    if encrypted:
        raw = _decrypt(raw, key)[:size]

    filenames: dict[int, str] = {}
    try:
        pos = 0
        directory_count = struct.unpack_from("<i", raw, pos)[0]
        pos += 4
        if directory_count < 0 or directory_count > 1_000_000:
            raise ValueError("invalid full directory count")
        for _ in range(directory_count):
            dirname, pos = read_fstring(raw, pos)
            file_count = struct.unpack_from("<i", raw, pos)[0]
            pos += 4
            if file_count < 0 or file_count > 1_000_000:
                raise ValueError("invalid full directory file count")
            for _ in range(file_count):
                filename, pos = read_fstring(raw, pos)
                entry_index = struct.unpack_from("<I", raw, pos)[0]
                pos += 4
                filenames[entry_index] = mount + dirname + filename
    except (IndexError, struct.error, ValueError) as exc:
        raise ValueError("invalid full directory index") from exc
    return filenames


def _extract_entry(
    file: BinaryIO,
    entry: PakEntry,
    compression_methods: list[str],
    key: bytes,
) -> bytes:
    limit = wuwa_encryption_limit(entry.custom_data)

    if entry.compression_method == 0:
        data_offset = entry.offset + entry.struct_size
        size = entry.uncompressed_size
        read_size = size
        encrypted_length = 0
        if entry.encrypted and limit > 0:
            limited_size = size if isinf(limit) else min(int(limit), size)
            encrypted_length = align16(limited_size)
            read_size = max(size, encrypted_length)
        file.seek(data_offset)
        raw = file.read(read_size)
        if encrypted_length > 0:
            decrypted = _decrypt(raw[:encrypted_length], key)
            raw = decrypted[: min(encrypted_length, size)] + raw[encrypted_length:]
        return raw[:size]

    if entry.compression_method >= len(compression_methods):
        raise ValueError(f"unsupported compression method {entry.compression_method}")
    method_name = compression_methods[entry.compression_method]
    if method_name != "Zlib":
        raise ValueError(f"unsupported compression method {method_name!r}")
    result = bytearray()
    remaining_limit = None if isinf(limit) else int(limit)

    for block_start, block_end in entry.blocks:
        block_size = block_end - block_start
        block_uncompressed = min(
            entry.compression_block_size,
            entry.uncompressed_size - len(result),
        )

        if remaining_limit is None and entry.encrypted:
            read_size = align16(block_size)
            file.seek(block_start)
            raw = _decrypt(file.read(read_size), key)[:block_size]
        elif (
            remaining_limit is not None
            and remaining_limit >= block_size
            and entry.encrypted
        ):
            read_size = align16(block_size)
            file.seek(block_start)
            raw = _decrypt(file.read(read_size), key)[:block_size]
            remaining_limit -= read_size
        elif remaining_limit is not None and remaining_limit > 0 and entry.encrypted:
            encrypted_part_size = int(remaining_limit)
            encrypted_read_size = align16(encrypted_part_size)
            file.seek(block_start)
            decrypted = _decrypt(file.read(encrypted_read_size), key)[
                :encrypted_part_size
            ]
            file.seek(block_start + encrypted_read_size)
            plain = file.read(block_size - encrypted_read_size)
            raw = decrypted + plain
            remaining_limit = 0
        else:
            file.seek(block_start)
            raw = file.read(block_size)

        try:
            decompressed = zlib.decompress(raw, -15, block_uncompressed)
        except zlib.error as exc:
            raise ValueError("invalid Zlib-compressed Pak block") from exc
        result.extend(decompressed)

    return bytes(result[: entry.uncompressed_size])


def public_entry_name(name: str) -> str:
    """Strip Unreal Engine mount points to return a clean relative path.

    Args:
        name: Raw entry name from the Pak index.

    Returns:
        Cleaned relative file path.
    """
    rel = name.replace("\\", "/")
    if rel.startswith("/"):
        raise ValueError(f"unsafe Pak entry path: {name!r}")
    for prefix in (
        "../../../Client/Content/Aki/",
        "../../../Client/Content/",
        "../../../",
        "Client/Content/Aki/",
        "Content/Aki/",
    ):
        if rel.startswith(prefix):
            rel = rel[len(prefix) :]
            break
    path = PurePosixPath(rel)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"unsafe Pak entry path: {name!r}")
    return path.as_posix()
