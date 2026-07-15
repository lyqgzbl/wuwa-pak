from __future__ import annotations

import zlib
from io import BytesIO

import pytest
from Crypto.Cipher import AES
from fixtures.generate_fixtures import TEST_AES_KEY, fstring_utf8, pak_footer
from wuwa_pak.entry import PakEntry
from wuwa_pak.pak import (
    PakArchive,
    _extract_entry,
    _read_full_directory_index,
    public_entry_name,
)


def test_extract_encrypted_uncompressed_reads_aligned_ciphertext() -> None:
    plaintext = b'{"clientMd5":"0123456789abcdef0123456789abcdef"}'
    encrypted = AES.new(TEST_AES_KEY, AES.MODE_ECB).encrypt(
        plaintext + b"\x00" * (16 - len(plaintext) % 16)
    )
    file = BytesIO(b"\x00" * 53 + encrypted)
    entry = PakEntry(
        name="Content/Fake/Data/example.json",
        offset=0,
        compressed_size=len(plaintext),
        uncompressed_size=len(plaintext),
        compression_method=0,
        compression_block_size=0,
        encrypted=True,
        blocks=[],
        struct_size=53,
        custom_data=0,
    )

    assert _extract_entry(file, entry, ["None"], TEST_AES_KEY) == plaintext


def test_extract_compressed_blocks() -> None:
    plaintext1 = b"A" * 1000
    plaintext2 = b"B" * 500

    compobj1 = zlib.compressobj(wbits=-15)
    comp1 = compobj1.compress(plaintext1) + compobj1.flush()

    compobj2 = zlib.compressobj(wbits=-15)
    comp2 = compobj2.compress(plaintext2) + compobj2.flush()

    file_data = b"\x00" * 100 + comp1 + comp2
    file = BytesIO(file_data)

    entry = PakEntry(
        name="compressed.txt",
        offset=100 - 53,  # fake offset so struct_size (53) + offset doesn't matter much
        compressed_size=len(comp1) + len(comp2),
        uncompressed_size=1500,
        compression_method=1,
        compression_block_size=1000,
        encrypted=False,
        blocks=[
            (100, 100 + len(comp1)),
            (100 + len(comp1), 100 + len(comp1) + len(comp2)),
        ],
        struct_size=53,
        custom_data=0,
    )

    assert (
        _extract_entry(file, entry, ["None", "Zlib"], TEST_AES_KEY)
        == plaintext1 + plaintext2
    )


def test_public_entry_name() -> None:
    assert public_entry_name("../../../Client/Content/Aki/Map/1.json") == "Map/1.json"
    assert public_entry_name("Client/Content/Aki/UI/Icon.png") == "UI/Icon.png"
    assert public_entry_name("Content/Aki/Config/config.json") == "Config/config.json"
    assert (
        public_entry_name("../../../Engine/Content/Core.uasset")
        == "Engine/Content/Core.uasset"
    )


@pytest.mark.parametrize(
    "name", ["../../outside.txt", "/tmp/outside.txt", "Content/../x"]
)
def test_public_entry_name_rejects_unsafe_paths(name: str) -> None:
    with pytest.raises(ValueError, match="unsafe Pak entry path"):
        public_entry_name(name)


def test_read_full_directory_index() -> None:
    import struct
    # Build a fake directory index buffer
    # directory_count: 1
    # dir 1: "Content/"
    # file_count: 1
    # file 1: "data.json", entry_index: 42

    buf = struct.pack("<i", 1)  # directory_count
    buf += fstring_utf8("Content/")
    buf += struct.pack("<i", 1)  # file_count
    buf += fstring_utf8("data.json")
    buf += struct.pack("<I", 42)  # entry_index

    file = BytesIO(buf)

    result = _read_full_directory_index(
        file=file,
        mount="../../../",
        offset=0,
        size=len(buf),
        encrypted=False,
        key=TEST_AES_KEY,
    )

    assert result == {42: "../../../Content/data.json"}


def test_pak_archive_open_invalid(tmp_path) -> None:
    invalid_pak = tmp_path / "invalid.pak"
    # Make sure the file is at least 221 bytes so file.seek(-PAK_FOOTER_SIZE, 2) works
    invalid_pak.write_bytes(b"0" * 250)

    with pytest.raises(ValueError, match="Not a supported Pak file"):
        PakArchive.open(invalid_pak, "00" * 32)


def test_pak_archive_open_valid(tmp_path) -> None:
    valid_pak = tmp_path / "valid.pak"

    # We need a valid footer and a valid index that parses correctly.
    # Since _read_entries parses fstring mount, we should provide an index big enough
    # or just let it fail early and return [].
    # If we pass 0 for index_size, read_fstring will throw struct.error.
    # We need an empty index but with enough valid structure so it bails correctly.
    import struct

    buf = struct.pack("<i", 0)  # empty fstring length
    buf += struct.pack("<i", 0)  # file_count = 0 (causes it to return [])

    footer_data = pak_footer(
        version=12,
        index_offset=0,
        index_size=len(buf),
        encrypted=False,
    )
    valid_pak.write_bytes(buf + b"pad" * 100 + footer_data)

    # _read_entries will return empty list since file_count is 0
    archive = PakArchive.open(valid_pak, "00" * 32)
    assert archive.footer.version == 12
    assert archive.entries == []


def test_read_entries() -> None:
    import struct
    # We will build a small valid index with one entry.
    # index_raw format:
    # fstring mount point (e.g. "../../../")
    # int file_count
    # path hash index stuff (offset 8)
    # int has_path_hash_index
    # int has_full_directory_index
    # int encoded_size
    # encoded_entries

    buf = fstring_utf8("../../../")
    buf += struct.pack("<i", 1)  # file_count
    buf += b"\x00" * 8  # the path hash index offset stuff that gets skipped "pos += 8"
    buf += struct.pack("<i", 0)  # has_path_hash_index
    buf += struct.pack("<i", 0)  # has_full_directory_index
    buf += struct.pack("<i", 4)  # encoded_size
    buf += b"\x00\x00\x00\x00"  # encoded_entries

    file = BytesIO(b"pad_data" + buf)

    class FakeFooter:
        index_offset = 8
        index_size = len(buf)
        encrypted = False
        version = 12

    # Test _read_entries
    from typing import cast

    from wuwa_pak.pak import PakFooter, _read_entries

    entries = _read_entries(file, cast("PakFooter", FakeFooter()), TEST_AES_KEY)

    # decode_entry won't find anything matching since we have no full directory index,
    # so it continues/errors and entries remain []
    assert entries == []


def test_read_entries_with_full_dir() -> None:
    import struct

    from fixtures.generate_fixtures import fstring_utf8

    # Let's craft a directory index buffer first
    dir_buf = struct.pack("<i", 1)  # directory_count
    dir_buf += fstring_utf8("Content/")
    dir_buf += struct.pack("<i", 1)  # file_count
    dir_buf += fstring_utf8("data.json")
    dir_buf += struct.pack("<I", 0)  # entry_index = 0

    # Now craft the entries buffer. We need 1 entry, encoded.
    # It must be index 0
    entry_bitfield = 0x00000040  # basic v11 uncompressed entry
    entry_buf = (
        struct.pack("<I", entry_bitfield)
        + struct.pack("<q", 100)
        + struct.pack("<q", 200)
    )

    # Now craft the main index raw
    idx_buf = fstring_utf8("../../../")
    idx_buf += struct.pack("<i", 1)  # file_count
    idx_buf += struct.pack("<q", 0)  # pos += 8 skip
    idx_buf += struct.pack("<i", 0)  # has_path_hash_index
    idx_buf += struct.pack("<i", 1)  # has_full_directory_index
    idx_buf += struct.pack("<q", 1000)  # full_directory_offset (we will seek to this)
    idx_buf += struct.pack("<q", len(dir_buf))  # full_directory_size
    idx_buf += b"\x00" * 20  # full directory 20 bytes skip
    idx_buf += struct.pack("<i", len(entry_buf))  # encoded_size
    idx_buf += entry_buf  # encoded_entries

    # We need a file that returns idx_buf at footer.index_offset,
    # and dir_buf at full_directory_offset
    file_data = bytearray(2000)
    file_data[100 : 100 + len(idx_buf)] = idx_buf
    file_data[1000 : 1000 + len(dir_buf)] = dir_buf

    file = BytesIO(file_data)

    class FakeFooter:
        index_offset = 100
        index_size = len(idx_buf)
        encrypted = False
        version = 11

    from typing import cast

    from wuwa_pak.pak import PakFooter, _read_entries

    entries = _read_entries(file, cast("PakFooter", FakeFooter()), TEST_AES_KEY)

    assert len(entries) == 1
    assert entries[0].name == "../../../Content/data.json"
    assert entries[0].offset == 100
    assert entries[0].uncompressed_size == 200


def test_extract_entry_method(tmp_path) -> None:
    # Test PakArchive.extract_entry opening the file itself
    pak_file = tmp_path / "test.pak"
    pak_file.write_bytes(b"A" * 100)

    class FakeFooter:
        compression_methods = ("None",)

    from typing import cast

    from wuwa_pak.pak import PakFooter

    archive = PakArchive(
        path=pak_file,
        footer=cast("PakFooter", FakeFooter()),
        entries=[],
        key=TEST_AES_KEY,
    )

    entry = PakEntry(
        name="test",
        offset=0,
        compressed_size=10,
        uncompressed_size=10,
        compression_method=0,
        compression_block_size=0,
        encrypted=False,
        blocks=[],
        struct_size=0,
        custom_data=0,
    )

    # Should read 10 bytes from 0
    assert archive.extract_entry(entry) == b"A" * 10


def test_extract_compressed_encrypted_blocks() -> None:
    plaintext1 = b"A" * 1000
    compobj1 = zlib.compressobj(wbits=-15)
    comp1 = compobj1.compress(plaintext1) + compobj1.flush()

    # Needs 16 bytes alignment encrypt
    from wuwa_pak.binary import align16

    padded_comp = comp1 + b"\x00" * (align16(len(comp1)) - len(comp1))
    encrypted_comp = AES.new(TEST_AES_KEY, AES.MODE_ECB).encrypt(padded_comp)

    file_data = b"\x00" * 100 + encrypted_comp
    file = BytesIO(file_data)

    entry = PakEntry(
        name="compressed_enc.txt",
        offset=0,  # not used for blocks
        compressed_size=len(comp1),
        uncompressed_size=1000,
        compression_method=1,
        compression_block_size=1000,
        encrypted=True,
        blocks=[
            (100, 100 + len(comp1)),
        ],
        struct_size=53,
        custom_data=0,  # inf encryption limit -> full encrypt
    )

    assert _extract_entry(file, entry, ["None", "Zlib"], TEST_AES_KEY) == plaintext1


def test_extract_compressed_encrypted_blocks_partial_mocked(monkeypatch) -> None:
    plaintext1 = bytes((index * 73 + 19) % 256 for index in range(1000))
    compobj1 = zlib.compressobj(wbits=-15)
    comp1 = compobj1.compress(plaintext1) + compobj1.flush()

    plaintext2 = bytes((index * 41 + 7) % 256 for index in range(500))
    compobj2 = zlib.compressobj(wbits=-15)
    comp2 = compobj2.compress(plaintext2) + compobj2.flush()

    limit = 16
    monkeypatch.setattr("wuwa_pak.pak.wuwa_encryption_limit", lambda x: limit)

    # Block 1: First 16 bytes encrypted.
    block1_enc_part = AES.new(TEST_AES_KEY, AES.MODE_ECB).encrypt(comp1[:16])
    block1_data = block1_enc_part + comp1[16:]

    # Block 2: Plain
    block2_data = comp2

    file_data = b"\x00" * 100 + block1_data + block2_data
    file = BytesIO(file_data)

    entry = PakEntry(
        name="partial_enc.txt",
        offset=0,
        compressed_size=len(comp1) + len(comp2),
        uncompressed_size=1500,
        compression_method=1,
        compression_block_size=1000,
        encrypted=True,
        blocks=[
            (100, 100 + len(comp1)),
            (100 + len(comp1), 100 + len(comp1) + len(comp2)),
        ],
        struct_size=53,
        custom_data=2,
    )

    assert (
        _extract_entry(file, entry, ["None", "Zlib"], TEST_AES_KEY)
        == plaintext1 + plaintext2
    )


def test_extract_compressed_encrypted_blocks_limit_exact(monkeypatch) -> None:
    # Limit exactly covers block 1
    plaintext1 = bytes((index * 73 + 19) % 256 for index in range(1000))
    compobj1 = zlib.compressobj(wbits=-15)
    comp1 = compobj1.compress(plaintext1) + compobj1.flush()

    # Pad block 1 since it's fully encrypted
    from wuwa_pak.binary import align16

    padded_comp1 = comp1 + b"\x00" * (align16(len(comp1)) - len(comp1))
    block1_data = AES.new(TEST_AES_KEY, AES.MODE_ECB).encrypt(padded_comp1)

    plaintext2 = bytes((index * 41 + 7) % 256 for index in range(500))
    compobj2 = zlib.compressobj(wbits=-15)
    comp2 = compobj2.compress(plaintext2) + compobj2.flush()

    block2_data = comp2  # Not encrypted since limit is exhausted

    monkeypatch.setattr(
        "wuwa_pak.pak.wuwa_encryption_limit", lambda x: align16(len(comp1))
    )

    file_data = b"\x00" * 100 + block1_data + block2_data
    file = BytesIO(file_data)

    entry = PakEntry(
        name="exact_enc.txt",
        offset=0,
        compressed_size=len(comp1) + len(comp2),
        uncompressed_size=1500,
        compression_method=1,
        compression_block_size=1000,
        encrypted=True,
        blocks=[
            (100, 100 + len(comp1)),
            (100 + len(block1_data), 100 + len(block1_data) + len(comp2)),
        ],
        struct_size=53,
        custom_data=2,
    )

    assert (
        _extract_entry(file, entry, ["None", "Zlib"], TEST_AES_KEY)
        == plaintext1 + plaintext2
    )
