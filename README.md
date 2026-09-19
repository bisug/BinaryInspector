# BinaryInspector

<p>
  <a href="https://github.com/bisug/BinaryInspector/actions/workflows/ci.yml"><img src="https://github.com/bisug/BinaryInspector/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://github.com/bisug/BinaryInspector/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-0b6e4f.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Rust-1.98.1%2B-b7410e.svg" alt="Rust 1.98.1 or newer">
  <a href="https://github.com/bisug/BinaryInspector/security"><img src="https://img.shields.io/badge/security-policy-5b5bd6.svg" alt="Security policy"></a>
</p>

BinaryInspector is a safe, local Rust CLI for inspecting ELF binaries. It never executes, loads, or dynamically links its target and performs no runtime network I/O.

## Current capabilities

- ELF32/ELF64 identity, ABI, machine, endianness, type, entry point, and file size
- Sections and program segments
- Dynamic interpreter, `DT_NEEDED`, `RPATH`, and `RUNPATH`
- Bounded reads, checked parser arithmetic, and terminal-safe binary strings (`\xNN` escaping)

Symbols, hardening analysis, and JSON output are planned. See the [roadmap](ROADMAP.md).

## Install from source

```sh
git clone https://github.com/bisug/BinaryInspector.git
cd BinaryInspector
cargo build --release
```

The executable is `target/release/binary-inspector`.

## Usage

```text
binary-inspector <FILE>
binary-inspector <FILE> -S              # sections
binary-inspector <FILE> -l              # segments
binary-inspector <FILE> -d              # dependencies
binary-inspector <FILE> -Sld            # combine categories
binary-inspector <FILE> --all           # explicit all categories
binary-inspector --help
binary-inspector --version
```

No category flag prints all currently implemented categories; flags can be combined.

```sh
binary-inspector /bin/ls -d
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Inspection succeeded |
| 1 | Command-line usage error |
| 2 | File-system error, including a non-regular target |
| 3 | Malformed, truncated, or unsupported ELF input |

## Safety

Every binary is untrusted input. BinaryInspector accepts regular, non-symlink files only, rejects oversized input, uses no `unsafe` code, and sanitizes untrusted terminal text. Read the [security policy](SECURITY.md) for the complete model and private vulnerability reporting process.

## Development

Requires Rust 1.98.1 or newer, edition 2021. The CLI runs on Linux, macOS, and Windows hosts; v1 inspects ELF only.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```

See [CONTRIBUTING.md](CONTRIBUTING.md). GitHub Actions tests Linux, macOS, and Windows; CodeQL scans Rust on pushes, pull requests, and weekly.

## Documentation

[Product requirements](PRD.md) · [Technical requirements](TRD.md) · [Architecture](ARCHITECTURE.md) · [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE)
