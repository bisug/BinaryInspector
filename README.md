# BinaryInspector

<p>
  <a href="https://github.com/bisug/BinaryInspector/actions/workflows/ci.yml"><img src="https://github.com/bisug/BinaryInspector/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://github.com/bisug/BinaryInspector/actions/workflows/gui-build.yml"><img src="https://github.com/bisug/BinaryInspector/actions/workflows/gui-build.yml/badge.svg?branch=main" alt="GUI build status"></a>
  <a href="https://scorecard.dev/viewer/?site=github.com/bisug/BinaryInspector"><img src="https://api.scorecard.dev/projects/github.com/bisug/BinaryInspector/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/bisug/BinaryInspector/releases"><img src="https://img.shields.io/github/v/release/bisug/BinaryInspector.svg" alt="Latest release"></a>
  <a href="https://github.com/bisug/BinaryInspector/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-0b6e4f.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Rust-1.99.0%2B-b7410e.svg" alt="Rust 1.99.0 or newer">
  <a href="https://github.com/bisug/BinaryInspector/security"><img src="https://img.shields.io/badge/security-policy-5b5bd6.svg" alt="Security policy"></a>
  <a href="https://github.com/bisug/BinaryInspector/wiki"><img src="https://img.shields.io/badge/docs-wiki-8a63d2.svg" alt="Documentation wiki"></a>
</p>

BinaryInspector is a safe, local Rust CLI and optional native desktop application for inspecting ELF, Windows PE/COFF, and Apple Mach-O binaries. It never executes, loads, or dynamically links its target and performs no runtime network I/O.

**Documentation lives in the [wiki](https://github.com/bisug/BinaryInspector/wiki)** — installation, CLI reference, GUI guide, security checks, JSON schema, safety model, and more.

## Supported Binary Formats

BinaryInspector provides full, safe static inspection across all major desktop and server executable formats without executing untrusted code:

| Format | Operating Systems | Architecture Coverage | Common File Types / Extensions | Key Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **ELF** | Linux, FreeBSD, NetBSD, OpenBSD, Android | x86 (32/64), ARM, AArch64, RISC-V, MIPS, PowerPC, s390x | Executables, `.so`, `.o`, core dumps | ELF32/64 headers, section & program segments, dynamic linking (`DT_NEEDED`, `RPATH`), relocations, symbols, GNU build notes, checksec mitigations (RELRO, Canary, NX, PIE, Fortify). |
| **PE / COFF** | Windows, Windows Server, UEFI | x86 (i386), x86-64 (AMD64), ARM, ARM64 | `.exe`, `.dll`, `.sys`, `.efi`, `.obj` | DOS header, PE32 & PE32+ optional headers, data directories, section tables, virtual addresses, checksec mitigations (ASLR, High Entropy VA, DEP/NX, Stack Canary). |
| **Mach-O** | macOS, iOS, iPadOS, watchOS, tvOS, visionOS | x86_64, ARM, ARM64, ARM64e | Executables, `.dylib`, `.bundle` | 32-bit & 64-bit Mach-O headers, load commands (`LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_MAIN`), UUID, min OS/SDK, checksec mitigations (PIE, Canary, NX/W^X, Fortify). |
| **Universal / Fat** | Apple Darwin / macOS multi-arch | Multi-slice containers (e.g. x86_64 + ARM64) | Universal binaries, `.dylib`, `.framework` | Fat header (`FAT_MAGIC` / `FAT_MAGIC_64`), slice extraction, architecture enumeration, and deep inspection of target slice payloads. |

## Current Capabilities

- **Format Auto-Detection**: Instant identification and dispatch of ELF, PE/COFF, Mach-O, and Universal Fat binaries.
- **Security Mitigations (checksec)**: RELRO, Stack Canary, NX/DEP, PIE/ASLR, High Entropy VA, Fortify Source, W^X violations, and insecure RPATHs.
- **Section & Segment Analysis**: Permissions, virtual mapping, file offsets, and per-section Shannon entropy (0.0 to 8.0 bits/byte) to identify packed or encrypted code.
- **Strings, Secrets & Embedded Artifacts**: Multi-encoding scanner (ASCII/UTF-8 and UTF-16LE) with automated semantic categorization for URLs, IP addresses, filesystem paths, cryptographic secrets/UUIDs, and email addresses.
- **Dynamic Linking & Dependencies**: Shared libraries (`DT_NEEDED`, DLLs, Dylibs), interpreter paths, and runtime search paths (`RPATH`, `RUNPATH`).
- **Symbols & Relocations**: Static and dynamic symbol tables, imports, exports, bindings, visibility, and base relocation entries.
- **Cross-Platform Native Desktop GUI**: Interactive interface (`binary-inspector-gui`) featuring virtualized tables, sorting, category chips, clipboard actions, drag-and-drop, and background inspection.
- **Deterministic & Machine-Readable Output**: Unambiguous terminal reports and schema-versioned JSON (`--json`) for automation and CI/CD pipelines.
- **Memory Safety Guarantee**: Strictly built with `#![forbid(unsafe_code)]` across all modules. Bounded reads, checked parser arithmetic, symlink/FIFO traversal protection, and terminal-safe binary escaping.

## Installation

> Alternative install methods, desktop-entry registration details, and troubleshooting: [Installation](https://github.com/bisug/BinaryInspector/wiki/Installation).

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

The default build produces the CLI without compiling the GUI dependency stack. The CLI executable is `target/release/binary-inspector`.

To build the native desktop GUI application:

```sh
cargo build --release --features gui --bin binary-inspector-gui
```

The GUI executable is `target/release/binary-inspector-gui` (`.exe` on Windows). It supports file picker dialogs, drag-and-drop, and presents Overview, Mitigations, Symbols, Sections, Segments, Dependencies, Notes, and Relocations views. It uses the same safe inspection core as the CLI.

Release builds use whole-program LTO and stripped symbols for smaller binaries. Use the `gui` feature only when building the desktop application.

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

No category flag prints all currently implemented categories; flags can be combined. Full flag reference: [Command-Line-Reference](https://github.com/bisug/BinaryInspector/wiki/Command-Line-Reference).

```sh
binary-inspector /bin/ls -d
```

### Native desktop GUI

Launch the GUI:

```sh
binary-inspector-gui
```

- Click **Choose Binary** to select any ELF, PE, or Mach-O binary using the native platform file chooser.
- Or simply **drag and drop** a binary into the application window.
- The binary is parsed asynchronously on a background thread while the UI remains fully responsive.
- Navigate between **Overview**, **Mitigations**, **Symbols**, **Sections**, **Segments**, **Dependencies**, **Notes**, **Relocations**, and **Strings & Secrets** tabs.

Full walkthrough — tabs, sorting, symbol detail pane, and keyboard shortcuts: [GUI Guide](https://github.com/bisug/BinaryInspector/wiki/GUI-Guide).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Inspection succeeded |
| 1 | Command-line usage error |
| 2 | File-system error, including a non-regular target |
| 3 | Malformed, truncated, or unsupported binary input |

Error categories and remediation hints for each failure: [Exit Codes and Errors](https://github.com/bisug/BinaryInspector/wiki/Exit-Codes-and-Errors).

## Safety

Every binary is untrusted input. BinaryInspector accepts regular, non-symlink files only, rejects oversized input, uses no `unsafe` code, and sanitizes untrusted terminal text. The technical safety model is documented in the [wiki](https://github.com/bisug/BinaryInspector/wiki/Safety-Model); report vulnerabilities privately per the [security policy](SECURITY.md).

## Development

Requires Rust 1.99.0 or newer, edition 2024. The CLI runs on Linux, macOS, and Windows hosts; inspects ELF, PE/COFF, and Mach-O.

```sh
cargo fmt --check
cargo clippy --all-targets --features gui -- -D warnings
cargo test
cargo doc --no-deps
```

See [CONTRIBUTING.md](CONTRIBUTING.md). GitHub Actions tests Linux, macOS, and Windows; CodeQL scans Rust on pushes, pull requests, and weekly. Build matrix, toolchain notes, and fuzzing setup: [Building from Source](https://github.com/bisug/BinaryInspector/wiki/Building-from-Source) · [Fuzzing and Testing](https://github.com/bisug/BinaryInspector/wiki/Fuzzing-and-Testing).

## License

[MIT](LICENSE)
