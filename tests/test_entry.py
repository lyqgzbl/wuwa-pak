from wuwa_pak.entry import wuwa_encryption_limit


def test_wuwa_encryption_limit_mapping() -> None:
    assert wuwa_encryption_limit(0) == float("inf")
    assert wuwa_encryption_limit(1) == 0x200000
    assert wuwa_encryption_limit(2) == 0x800
    assert wuwa_encryption_limit(4) == 0
    assert wuwa_encryption_limit(99) == float("inf")
