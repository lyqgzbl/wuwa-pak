"""Command line entry point for the public-bound Pak tool."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from wuwa_pak.pak import PakArchive, public_entry_name


def _matching_entries(archive: PakArchive, name_filter: str | None):
    entries = archive.entries
    if name_filter:
        needle = name_filter.lower()
        entries = [entry for entry in entries if needle in entry.name.lower()]
    return entries


def _print_info(archive: PakArchive) -> None:
    footer = archive.footer
    print(f"Pak: {archive.path}")
    print(f"Version: {footer.version}")
    print(f"Encrypted index: {footer.encrypted}")
    print(f"Entries: {len(archive.entries)}")
    print(f"Compression methods: {', '.join(footer.compression_methods)}")


def _list_entries(archive: PakArchive, name_filter: str | None) -> None:
    for entry in _matching_entries(archive, name_filter):
        method = (
            archive.footer.compression_methods[entry.compression_method]
            if entry.compression_method < len(archive.footer.compression_methods)
            else "?"
        )
        print(
            f"{entry.name}\t{entry.uncompressed_size}\t"
            f"compressed={entry.compressed_size}\tmethod={method}\t"
            f"encrypted={entry.encrypted}"
        )


def _extract_entries(archive: PakArchive, name_filter: str | None, out: str) -> None:
    out_dir = Path(out)
    for entry in _matching_entries(archive, name_filter):
        rel = public_entry_name(entry.name)
        out_path = out_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(archive.extract_entry(entry))
        print(out_path)


def _scan_sqlite(archive: PakArchive, name_filter: str | None) -> None:
    signature = b"SQLite format 3\x00"
    for entry in _matching_entries(archive, name_filter):
        if entry.uncompressed_size <= 0:
            continue
        data = archive.extract_entry(entry)
        if signature in data:
            print(entry.name)


def main() -> int:
    parser = argparse.ArgumentParser(prog="wuwa-pak")
    parser.add_argument(
        "command",
        choices=["info", "list", "extract", "scan-sqlite"],
        help="Pak operation to run",
    )
    parser.add_argument("--pak", required=True, help="Path to a user-provided Pak file")
    parser.add_argument("--key", required=True, help="AES key as hex")
    parser.add_argument("--out", help="Output directory for extraction")
    parser.add_argument("--filter", help="Optional filename filter")
    args = parser.parse_args()

    if args.command == "extract" and not args.out:
        parser.error("extract requires --out")

    try:
        archive = PakArchive.open(args.pak, args.key)
        if args.command == "info":
            _print_info(archive)
        elif args.command == "list":
            _list_entries(archive, args.filter)
        elif args.command == "extract":
            _extract_entries(archive, args.filter, args.out)
        elif args.command == "scan-sqlite":
            _scan_sqlite(archive, args.filter)
    except Exception as exc:
        print(f"wuwa-pak: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
