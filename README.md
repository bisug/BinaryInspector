# BinaryInspector

<p>
  <a href="https://github.com/bisug/BinaryInspector/actions/workflows/ci.yml"><img src="https://github.com/bisug/BinaryInspector/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://github.com/bisug/BinaryInspector/actions/workflows/gui-build.yml"><img src="https://github.com/bisug/BinaryInspector/actions/workflows/gui-build.yml/badge.svg?branch=main" alt="GUI build status"></a>
  <a href="https://scorecard.dev/viewer/?site=github.com/bisug/BinaryInspector"><img src="https://api.scorecard.dev/projects/github.com/bisug/BinaryInspector/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/bisug/BinaryInspector/releases"><img src="https://img.shields.io/github/v/release/bisug/BinaryInspector.svg" alt="Latest release"></a>
  <a href="https://github.com/bisug/BinaryInspector/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-0b6e4f.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Rust-1.98.1%2B-b7410e.svg" alt="Rust 1.98.1 or newer">
  <a href="https://github.com/bisug/BinaryInspector/security"><img src="https://img.shields.io/badge/security-policy-5b5bd6.svg" alt="Security policy"></a>
</p>

BinaryInspector is a safe, local Rust CLI and native desktop application for inspecting ELF binaries. It never executes, loads, or dynamically links its target and performs no runtime network I/O.

## Current capabilities

- ELF32/ELF64 identity, ABI, machine, endianness, type, entry point, and file size
- Section and program segment tables
- Dynamic interpreter, `DT_NEEDED`, `RPATH`, and `RUNPATH`
- Cross-platform native desktop GUI (`binary-inspector-gui`) with file dialog, drag-and-drop, and background inspection
- Bounded reads, checked parser arithmetic, symlink/FIFO traversal protection, and terminal-safe binary strings (`\xNN` escaping)

Symbols, hardening analysis, and JSON output are planned. See the [roadmap](ROADMAP.md).

## Installation

### Automated installer (Linux & macOS)

Install the latest verified binaries to `~/.local/bin` and register the Linux desktop application:

```sh
curl -fsSL https://raw.githubusercontent.com/bisug/BinaryInspector/main/install.sh | bash
```

Or from a local clone:

```sh
./install.sh                # Installs both CLI and GUI to ~/.local/bin
./install.sh --cli-only     # Installs only the CLI
./install.sh --gui-only     # Installs only the GUI
./install.sh --from-source  # Builds from source using cargo
```

### Pre-built binaries

Download the latest pre-built binaries for Linux, macOS, and Windows from [GitHub Releases](https://github.com/bisug/BinaryInspector/releases).

### Build from source

```sh
git clone https://github.com/bisug/BinaryInspector.git
cd BinaryInspector
cargo build --release
```

The CLI executable is `target/release/binary-inspector`.

To build the native desktop GUI application:

```sh
cargo build --release --bin binary-inspector-gui
```

The GUI executable is `target/release/binary-inspector-gui` (`.exe` on Windows). It supports file picker dialogs, drag-and-drop, and presents Overview, Sections, Segments, and Dependencies views. It uses the same safe inspection core as the CLI.

## Usage

### Command-line interface

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

### Native desktop GUI

Launch the GUI:

```sh
binary-inspector-gui
```

- Click **Open binary** to select an ELF binary using the native platform file chooser.
- Or simply **drag and drop** an ELF binary into the application window.
- The binary is parsed asynchronously on a background thread while the UI remains fully responsive.
- Navigate between **Overview**, **Sections**, **Segments**, and **Dependencies** tabs.

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
