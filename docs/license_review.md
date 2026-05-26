# License Review

This document records the public-release license review for `wuwa-pak`.

## Reference Project

- Project: CUE4Parse
- URL: https://github.com/FabianFG/CUE4Parse
- License: Apache License 2.0
- NOTICE file: present in the upstream repository

## Relevant Upstream Areas

The Wuthering Waves Pak behavior in `wuwa-pak` was reviewed against these
CUE4Parse areas:

- `CUE4Parse/UE4/Pak/Objects/FPakEntry.cs`
- `CUE4Parse/UE4/Pak/Objects/FPakInfo.cs`
- `CUE4Parse/UE4/Pak/PakFileReader.cs`
- `CUE4Parse/GameTypes/Misc/UE4/Paks/PartialEncryptionPakFileReader.cs`

## Relationship Assessment

`wuwa-pak` does not copy CUE4Parse C# source files verbatim. It is a Python
implementation with different module boundaries, data classes, I/O structure,
and command-line behavior.

The project does intentionally reproduce Wuthering Waves Pak behavior described
by CUE4Parse, including:

- Pak entry bitfield reordering for Wuthering Waves v12-style entries.
- Reading the Wuthering Waves custom entry byte.
- Swapping entry offset and uncompressed size for Wuthering Waves entries.
- Partial encryption length behavior for custom data values `0`, `1`, `2`, and
  `4`.

Because these behaviors were implemented with reference to CUE4Parse, this
project uses Apache-2.0 for compatibility and clarity.

## Attribution Decision

Public documentation should attribute CUE4Parse directly, not FModel as the
primary source. FModel is related to the broader ecosystem, but the implementation
reference reviewed here is CUE4Parse.

Required public files:

- `LICENSE` with Apache License 2.0 text.
- `NOTICE` with CUE4Parse attribution and a clear relationship statement.
- README attribution section referencing CUE4Parse and its Apache-2.0 license.
- File-level comments in `wuwa_pak/entry.py` and `wuwa_pak/pak.py`, because
  these files contain the strongest behavior-level relationship to CUE4Parse.
- `pyproject.toml` package metadata declaring Apache-2.0 and including license
  files in distributions.

## Publishing Notes

Before publishing a standalone public repository, verify that the release staging
directory includes the Apache-2.0 `LICENSE`, `NOTICE`, README attribution, and no
private runtime/key acquisition content.
