import pytest
from Crypto.Cipher import AES
from fixtures.generate_fixtures import TEST_AES_KEY
from wuwa_pak.crypto import decrypt_aes_ecb, key_from_hex


def test_key_from_hex_accepts_32_byte_key() -> None:
    assert key_from_hex("00" * 32) == TEST_AES_KEY


def test_key_from_hex_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="AES key"):
        key_from_hex("00" * 31)


def test_decrypt_aes_ecb_synthetic_roundtrip() -> None:
    plaintext = b"synthetic-block!"  # 16 bytes
    encrypted = AES.new(TEST_AES_KEY, AES.MODE_ECB).encrypt(plaintext)
    assert decrypt_aes_ecb(encrypted, TEST_AES_KEY) == plaintext
