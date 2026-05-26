from fixtures.generate_fixtures import empty_fstring, fstring_utf8, fstring_utf16
from wuwa_pak.binary import align16, read_fstring


def test_align16() -> None:
    assert align16(0) == 0
    assert align16(1) == 16
    assert align16(16) == 16
    assert align16(17) == 32


def test_read_empty_fstring() -> None:
    value, pos = read_fstring(empty_fstring(), 0)
    assert value == ""
    assert pos == 4


def test_read_utf8_fstring() -> None:
    value, pos = read_fstring(fstring_utf8("Content/Fake/Data/example.txt"), 0)
    assert value == "Content/Fake/Data/example.txt"
    assert pos > 4


def test_read_utf16_fstring() -> None:
    value, pos = read_fstring(fstring_utf16("FakeName"), 0)
    assert value == "FakeName"
    assert pos > 4
