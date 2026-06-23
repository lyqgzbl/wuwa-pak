from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from wuwa_pak.cli import main
from wuwa_pak.pak import PakArchive


def test_cli_requires_pak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["wuwa-pak", "info", "--key", "00" * 32])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2


def test_cli_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["wuwa-pak", "info", "--pak", "fake.pak"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2


def test_extract_requires_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["wuwa-pak", "extract", "--pak", "fake.pak", "--key", "00" * 32],
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2


@pytest.fixture
def mock_archive(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    archive = MagicMock(spec=PakArchive)
    archive.path = Path("fake.pak")

    footer = MagicMock()
    footer.version = 12
    footer.encrypted = False
    footer.compression_methods = ["None", "Zlib"]
    archive.footer = footer

    entry1 = MagicMock()
    entry1.name = "Content/Fake/Data/file1.txt"
    entry1.uncompressed_size = 100
    entry1.compressed_size = 50
    entry1.compression_method = 1
    entry1.encrypted = False

    entry2 = MagicMock()
    entry2.name = "Content/Fake/Data/db.db"
    entry2.uncompressed_size = 200
    entry2.compressed_size = 200
    entry2.compression_method = 0
    entry2.encrypted = False

    archive.entries = [entry1, entry2]

    # Mock staticmethod/classmethod on the class
    open_mock = MagicMock(return_value=archive)
    monkeypatch.setattr("wuwa_pak.cli.PakArchive.open", open_mock)

    return archive


def test_cli_info(
    mock_archive: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["wuwa-pak", "info", "--pak", "fake.pak", "--key", "00" * 32]
    )
    assert main() == 0
    out, _ = capsys.readouterr()
    assert "Version: 12" in out
    assert "Entries: 2" in out


def test_cli_list_with_filter(
    mock_archive: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["wuwa-pak", "list", "--pak", "fake.pak", "--key", "00" * 32, "--filter", "db"],
    )
    assert main() == 0
    out, _ = capsys.readouterr()
    assert "db.db" in out
    assert "file1.txt" not in out


def test_cli_extract(
    mock_archive: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_archive.extract_entry.return_value = b"test_data"

    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "wuwa-pak",
            "extract",
            "--pak",
            "fake.pak",
            "--key",
            "00" * 32,
            "--out",
            str(out_dir),
        ],
    )

    assert main() == 0
    out, _ = capsys.readouterr()

    # Check that file was created with correct relative path
    # (public_entry_name strips prefixes)
    expected_path = out_dir / "Content/Fake/Data/file1.txt"
    assert expected_path.exists()
    assert expected_path.read_bytes() == b"test_data"
    assert str(expected_path) in out


def test_cli_scan_sqlite(
    mock_archive: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_extract(entry):
        if entry.name.endswith(".db"):
            return b"SQLite format 3\x00_data"
        return b"normal_data"

    mock_archive.extract_entry.side_effect = fake_extract
    monkeypatch.setattr(
        sys,
        "argv",
        ["wuwa-pak", "scan-sqlite", "--pak", "fake.pak", "--key", "00" * 32],
    )

    assert main() == 0
    out, _ = capsys.readouterr()
    assert "Content/Fake/Data/db.db" in out
    assert "file1.txt" not in out


def test_cli_exception_handling(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def raise_err(*args, **kwargs):
        raise ValueError("Test encryption error")

    monkeypatch.setattr("wuwa_pak.cli.PakArchive.open", raise_err)
    monkeypatch.setattr(
        sys, "argv", ["wuwa-pak", "info", "--pak", "fake.pak", "--key", "00" * 32]
    )

    assert main() == 1
    _, err = capsys.readouterr()
    assert "wuwa-pak: Test encryption error" in err
