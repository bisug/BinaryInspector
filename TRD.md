# Technical Requirements

## Baseline

- Stable Rust 1.98.1 (edition 2021) is the minimum supported Rust version.
- The CLI runs on Linux, macOS, and Windows hosts on architectures supported by Rust; it inspects ELF files only.
- Inspected files are untrusted. The tool reads a bounded owned buffer and never executes, maps, loads, or sends a binary over the network.

## Design constraints

- Parser-derived offsets, sizes, and counts use checked arithmetic and explicit caps.
- Only regular files are accepted. Symlinks, directories, devices, and FIFOs fail before reading.
- Malformed, truncated, and unsupported input returns a parse error, never a panic.
- Binary-provided strings are rendered as printable ASCII with every other byte escaped as `\xNN`; this is deterministic and terminal-safe. JSON is emitted through `serde_json`.
- Results use owned, strongly typed domain models deriving `serde::Serialize`; deterministic vectors preserve file order.

## Dependencies

The foundation uses `clap` 4.6.7 for argument parsing and `serde` 1.0.229 for typed domain models. Both were verified against crates.io and docs.rs on 2026-09-19; their declared MSRVs are below this project's Rust 1.98.1 baseline. `serde_json` will be verified and added only with Phase 6.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Usage error |
| 2 | File-system error |
| 3 | Malformed, truncated, or unsupported binary |

## JSON compatibility

Phase 6 will introduce schema version `1`. JSON key ordering follows model declaration order; changing a field name or type is a breaking schema change.
