# wuwa-pak

`wuwa-pak` is a Python Pak parser and extractor for Wuthering Waves research
workflows where users explicitly provide their own Pak files and AES keys.

## Safety Boundary

This project does not include key acquisition, process injection, Frida hooks,
CDP/V8 Inspector integration, or game runtime automation. Users are expected to
provide their own Pak files and AES keys.

The CLI does not discover local game paths, discover game processes, attach to a
running process, dump keys, or update key files.

## Usage

```bash
wuwa-pak info --pak path/to/file.pak --key HEX_KEY
wuwa-pak list --pak path/to/file.pak --key HEX_KEY
wuwa-pak extract --pak path/to/file.pak --key HEX_KEY --out out/
wuwa-pak extract --pak path/to/file.pak --key HEX_KEY --filter .db --out out/
wuwa-pak scan-sqlite --pak path/to/file.pak --key HEX_KEY
```

All commands require explicit `--pak` and `--key` inputs. `extract` also requires
an explicit `--out` directory.

## Testing

Tests use synthetic fixtures only. Do not add real game Pak files, extracted game
files, real SQLite databases, real encrypted payloads, captured metadata, or real
keys to this repository.

Fixture documentation and generation helpers live under `tests/fixtures/`.

## Attribution

Parts of the Wuthering Waves Pak entry decoding and partial encryption behavior
were implemented with reference to CUE4Parse, an Apache-2.0 licensed Unreal
Engine archive parsing library: https://github.com/FabianFG/CUE4Parse

This project is an independent Python implementation focused on scripting and
offline research workflows.

## License

`wuwa-pak` is licensed under the Apache License, Version 2.0. See `LICENSE` and
`NOTICE`.
