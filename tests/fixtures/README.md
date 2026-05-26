# Synthetic Fixtures

Tests for `wuwa-pak` must use synthetic fixtures by default.

Do not copy real game Pak files, extracted game files, real SQLite databases,
real encrypted payloads, captured metadata, or real AES keys into this directory.

Fixture rules:

- Generate tiny binary blobs specifically for parser tests.
- Use fake paths such as `Content/Fake/Data/example.txt`.
- Use deterministic test-only AES keys such as all-zero bytes.
- Keep payloads small and human-reviewable.
- Prefer checked-in generator code over opaque binary blobs.
- Never copy bytes from real game files into fixtures.

`generate_fixtures.py` contains helpers for building minimal byte sequences used
by unit tests. It intentionally does not generate real Pak archives.
