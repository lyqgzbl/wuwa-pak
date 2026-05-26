from __future__ import annotations

from io import BytesIO

from Crypto.Cipher import AES
from fixtures.generate_fixtures import TEST_AES_KEY
from wuwa_pak.entry import PakEntry
from wuwa_pak.pak import _extract_entry


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
