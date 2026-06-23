from __future__ import annotations

import struct

from wuwa_pak.entry import decode_entry, wuwa_encryption_limit


def test_wuwa_encryption_limit_mapping() -> None:
    assert wuwa_encryption_limit(0) == float("inf")
    assert wuwa_encryption_limit(1) == 0x200000
    assert wuwa_encryption_limit(2) == 0x800
    assert wuwa_encryption_limit(4) == 0
    assert wuwa_encryption_limit(99) == float("inf")


def test_decode_entry_v11_uncompressed() -> None:
    # Construct a simple V11 bitfield (no encryption, no compression, no custom data)
    # block_size_encoded = 0, block_count = 1
    # 00000000 00000000 00000000 01 000000 -> 0x00000040
    bitfield = 0x00000040

    # 4 bytes bitfield, 8 bytes offset, 8 bytes uncompressed size
    data = (
        struct.pack("<I", bitfield) + struct.pack("<q", 1024) + struct.pack("<q", 500)
    )

    entry, pos = decode_entry(data, 0, version=11, name="test.txt")

    assert pos == 20
    assert entry.name == "test.txt"
    assert entry.offset == 1024
    assert entry.uncompressed_size == 500
    assert entry.compressed_size == 500
    assert entry.compression_method == 0
    assert entry.encrypted is False
    assert entry.custom_data == 0


def test_decode_entry_v12_compressed_encrypted() -> None:
    # V12 bitfield is scrambled.
    # block_size_encoded = 0x3F (63), explicit compression_block_size=0x1000
    # compression_method = 1
    # encrypted = 1 (bit 22)
    # block_count = 2 (bit 6)
    # Unscrambled bitfield logic:
    # bitfield = block_size | count<<6 | enc<<22 | method<<23
    # bitfield = 0x3F | (2<<6) | (1<<22) | (1<<23) = 12583007

    # The decoder does this descramble for v12:
    # descramble logic is long

    # Let's craft the bitfield that results in the unscrambled value
    # Unscrambled we want:
    # bit 0-5 = 0x3F (from scrambled >> 16) => scrambled bit 16-21 = 0x3F
    # bit 6-21 = 2 (from scrambled & 0xFFFF) => scrambled bit 0-15 = 2
    # bit 22 = 1 (from scrambled >> 28) => scrambled bit 28 = 1
    # bit 23-28 = 1 mapping

    # Reverse mapping for scrambled -> unscrambled:
    # target bitfield mappings

    # 0x3F -> goes to scrambled bits 16-21
    scrambled = 0x3F << 16
    # 2 -> goes to scrambled bits 0-15
    scrambled |= 2
    # 1 (encrypted) -> goes to scrambled bit 28
    scrambled |= 1 << 28
    # compression_method mapping
    # shift mapping
    # So scrambled bit 22 = 1
    scrambled |= 1 << 22

    # Pack the data: V12 format
    # bitfield (4 bytes)
    # custom_data (1 byte)
    # compression_block_size (4 bytes, because block_size_encoded == 0x3F)
    # uncompressed_size (8 bytes) swapped with file_offset in V12
    # bit 31=0, bit 30=0 in scrambled (8 bytes each swapped)
    # compressed_size (8 bytes)
    # 2 block lengths (4 bytes each)

    data = struct.pack("<I", scrambled)
    data += b"\x01"  # custom_data = 1
    data += struct.pack("<I", 0x1000)  # compression_block_size
    data += struct.pack(
        "<q", 1000
    )  # file_offset (in V12 this position is uncompressed_size, swapped later)
    data += struct.pack(
        "<q", 5000
    )  # uncompressed_size (in V12 this position is file_offset, swapped later)
    data += struct.pack("<q", 800)  # compressed_size
    data += struct.pack("<I", 400)  # block 1 length
    data += struct.pack("<I", 400)  # block 2 length

    entry, _pos = decode_entry(data, 0, version=12, name="encrypted.pak")

    assert entry.encrypted is True
    assert entry.compression_method == 1
    assert entry.compression_block_size == 0x1000
    assert entry.custom_data == 1
    assert entry.uncompressed_size == 1000
    assert entry.offset == 5000
    assert entry.compressed_size == 800
    assert len(entry.blocks) == 2


def test_decode_entry_32bit_fields() -> None:
    # bit 31 (file_offset 32-bit), bit 30 (uncomp 32-bit)
    # bit 29 (compressed_size 32-bit if method != 0).
    # Also block_count = 0 (so compression_block_size logic falls back)
    # compression_method = 1 (to trigger bit 29 check)

    # Unscrambled bitfield logic:
    # 0x3F (block_size_encoded)
    # (1 << 31) -> bit 31 set
    # (1 << 30) -> bit 30 set
    # (1 << 29) -> bit 29 set
    # (1 << 23) -> compression method = 1
    # block_count = 0 (bits 6-21)

    bitfield = 0x3F | (1 << 31) | (1 << 30) | (1 << 29) | (1 << 23)

    data = struct.pack("<I", bitfield)
    data += struct.pack("<I", 0x1000)  # compression_block_size
    data += struct.pack("<I", 1234)  # file_offset (32-bit)
    data += struct.pack("<I", 5678)  # uncompressed_size (32-bit)
    data += struct.pack("<I", 9012)  # compressed_size (32-bit)

    entry, _pos = decode_entry(data, 0, version=11, name="32bit.pak")

    assert entry.offset == 1234
    assert entry.uncompressed_size == 5678
    assert entry.compressed_size == 9012
    assert entry.compression_block_size == 0
    assert len(entry.blocks) == 0
