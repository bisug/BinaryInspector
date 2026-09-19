# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Changed

- Added short category flags and copy-paste CLI examples.

### Added

- Native GUI executable with open-file, drag-and-drop, background inspection, and Phase 1–3 views.

### Security

- Capped decoded ELF strings, dynamic-table work, and total emitted text.
- Validated all on-disk section ranges and dynamic string-table links.
- Hardened Unix target opening against symlink traversal and FIFO replacement races.

### Added

- Phase 1 ELF identification and bounded regular-file input handling.
- CLI foundation with documented exit codes and deterministic human-readable output.
- Phase 2 section and program-segment inspection with bounds validation and terminal-safe section names.
- Phase 3 dynamic dependencies, interpreter, RPATH, and RUNPATH inspection.

## [0.0.0] - 2026-09-19

### Added

- Initial product, technical, architecture, security, and contribution documentation.
