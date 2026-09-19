# Product Requirements

BinaryInspector is a local command-line tool that reports facts about ELF executables without running them.

## v1 scope

1. Identify ELF class, machine, endianness, type, OS ABI, entry point, and basic file metadata.
2. Report sections and program segments.
3. Report dynamic dependencies, interpreter, RPATH, and RUNPATH.
4. Report static and dynamic symbols, including stripped-file status.
5. Report reliably detectable hardening properties: PIE, NX, RELRO, and stack-canary references.
6. Emit a stable versioned JSON representation and support category filters.
7. Provide a native desktop GUI for Linux, macOS, and Windows that reuses the same inspection core.

No flag prints all categories. `--sections`, `--segments`, `--symbols`, `--dependencies`, and `--security` combine. `--json` writes JSON only to stdout. Human output honors `NO_COLOR` and `--no-color`. The GUI offers file selection and drag-and-drop; it must preserve the CLI's no-execution guarantee.

## Out of scope

Disassembly, execution or loading, malware scoring, runtime network lookups, and PE/Mach-O parsing are excluded.
