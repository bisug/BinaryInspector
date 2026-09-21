# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- `--json` flag (Phase 8): pretty-printed, schema-versioned JSON report (`schema_version: 1`) covering every category, plus CLI integration test.

### Fixed

- Dynamic table, symbols, notes, and relocations are now also decoded from program headers when section headers are absent (stripped binaries), so interpreter, `DT_NEEDED`, RPATH/RUNPATH, and binding-mode reporting remain correct.
- PIE detection falls back to `DT_FLAGS_1` `DF_1_PIE` for static PIE binaries.
- Section-header tables located beyond the end of the file are rejected instead of amplifying parse work.
- Entropy computation is bounded by a shared 64 MiB scan budget across all sections.
- Fuzzing workflow now fails the CI job on a crash instead of swallowing errors.

### Removed

- Untracked `samples/` fixture binaries; fixtures must be regenerated from committed sources (per `CONTRIBUTING.md`).

## [0.2.0] - 2026-09-20

### Added

- Structured `ParseError` and `AppError` types with specific variants for ELF parsing, identification, limits, and file constraints.
- Actionable UI guidance cards in GUI failed state showing failure categorization and user remediation tips.
- CLI integration tests in `tests/cli.rs` covering exit codes 0, 1, 2, and 3.
- Security hardening analysis (`checksec`): RELRO (Full/Partial), Stack Canary, NX Stack, PIE, Fortified Functions, RWX Segments, and Insecure RPATH.
- Symbol table inspection (`-s` / `--symbols`): static (`.symtab`) and dynamic (`.dynsym`) symbols with type, binding, visibility, and import/export identification.
- ELF notes inspection (`-n` / `--notes`): GNU Build ID, ABI requirements, and hardware properties (x86 IBT/SHSTK, ARM BTI/PAC).
- Relocations inspection (`-r` / `--relocations`): SHT_REL / SHT_RELA entries with $O(1)$ symbol resolution.
- Desktop GUI virtual scrolling with `show_rows` and pinned sticky headers across large symbol and relocation tables.
- GUI interactive search filtering, sortable columns, adjustable column widths, and copy-to-clipboard buttons.
- GUI resizable split layout with drag-and-drop file target overlay.

### Fixed

- Eliminated panic paths (`.expect`) in numeric parsing helpers (`read_u16`, `read_u32`, `read_i32`, `read_u64`, `read_i64`).
- Mapped Unix `libc::ELOOP` from `O_NOFOLLOW` and non-regular files directly to `AppError::InvalidFileType`.
- Checksec RELRO detection now correctly recognizes `DT_BIND_NOW` (dynamic tag 24) for Full RELRO.
- Checksec stack canary detection now recognizes `__stack_chk_fail_local` on PIC and 32-bit x86 binaries.
- Checksec PIE detection correctly distinguishes static PIE binaries from shared libraries via `DT_DEBUG`.
- GUI background inspection spinner freezing when mouse is stationary.
- $O(R \times S)$ relocation resolution performance bottleneck, reducing lookup complexity to $O(1)$.
- Unbounded note allocation loop capped at `MAX_NOTE_ENTRIES = 8_192`.

### Performance

- Fast static ASCII lookup tables for SHA-256 and byte escaping.
- Zero-allocation comparisons for symbol type and binding table sorting.

## [0.1.0] - 2026-09-19

### Added

- Native GUI executable with open-file, drag-and-drop, background inspection, and Phase 1–3 views.
- Phase 1 ELF identification and bounded regular-file input handling.
- CLI foundation with documented exit codes and deterministic human-readable output.
- Phase 2 section and program-segment inspection with bounds validation and terminal-safe section names.
- Phase 3 dynamic dependencies, interpreter, RPATH, and RUNPATH inspection.

### Changed

- Added short category flags and copy-paste CLI examples.
- Replaced the GUI's default GPU stack with the lighter native OpenGL renderer and optimized release build settings.

### Security

- Capped decoded ELF strings, dynamic-table work, and total emitted text.
- Validated all on-disk section ranges and dynamic string-table links.
- Hardened Unix target opening against symlink traversal and FIFO replacement races.

## [0.0.0] - 2026-09-19

### Added

- Initial product, technical, architecture, security, and contribution documentation.
