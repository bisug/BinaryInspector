# Roadmap

1. Foundation: documentation, package, CLI shell, input validation, and typed error handling.
2. Identification: ELF header and file metadata.
3. Structure: section and program-header tables.
4. Dependencies: dynamic table, interpreter, RPATH, and RUNPATH.
5. Symbols: `.symtab` and `.dynsym`; stripped binaries remain successful inspections.
6. Security: PIE, NX, RELRO, and stack-canary indicators.
7. JSON: versioned schema and filter combinations.
8. Hardening: cross-architecture fixtures, malformed and fuzz-derived regressions, then `cargo-fuzz`.

Deferred: C++ and Rust symbol demangling, PE/Mach-O decoding, disassembly, and all network-based enrichment.
