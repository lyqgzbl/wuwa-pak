from __future__ import annotations

import sys

import pytest
from wuwa_pak.cli import main


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
