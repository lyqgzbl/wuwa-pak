from io import BytesIO

from fixtures.generate_fixtures import pak_footer
from wuwa_pak.footer import read_footer


def test_read_footer_from_synthetic_bytes() -> None:
    footer = read_footer(BytesIO(pak_footer(index_offset=256, index_size=128)))

    assert footer is not None
    assert footer.version == 12
    assert footer.index_offset == 256
    assert footer.index_size == 128
    assert footer.encrypted is False
    assert footer.compression_methods[:2] == ["None", "Zlib"]


def test_read_footer_returns_none_for_bad_magic() -> None:
    data = bytearray(pak_footer())
    data[17:21] = b"BAD!"
    assert read_footer(BytesIO(bytes(data))) is None
