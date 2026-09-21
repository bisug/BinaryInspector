# Roadmap

- [x] 1. Foundation: documentation, package, CLI shell, input validation, and typed error handling.
- [x] 2. Identification: ELF header and file metadata.
- [x] 3. Structure: section and program-header tables.
- [x] 4. Dependencies: dynamic table, interpreter, RPATH, and RUNPATH.
- [x] 5. Symbols: `.symtab` and `.dynsym`; stripped binaries remain successful inspections.
- [x] 6. Security: PIE, NX, RELRO, and stack-canary indicators.
- [x] 7. Native GUI: Linux, macOS, and Windows executable builds; file picker, drag-and-drop, and Phase 1–3 inspection views.
- [x] 8. JSON: versioned schema and filter combinations.
- [ ] 9. Hardening: cross-architecture fixtures, malformed and fuzz-derived regressions, then `cargo-fuzz`.

Deferred: C++ and Rust symbol demangling, PE/Mach-O decoding, disassembly, and all network-based enrichment.
