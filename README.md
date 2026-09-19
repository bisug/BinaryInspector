# BinaryInspector

BinaryInspector is a local Rust CLI for safely inspecting ELF binaries. It does not execute or load the files it reads and performs no runtime network I/O.

## Status

Phases 1–3 are implemented: ELF identity, structure, interpreter, dynamic dependencies, RPATH, and RUNPATH. Later phases add symbols, security properties, and JSON. The planned full CLI is:

```text
binary-inspector <FILE> [--sections] [--segments] [--symbols] [--dependencies] [--security] [--json]
```

No category flags will print all categories. JSON will be introduced in Phase 6 and will use a documented schema version. Exit codes are 0 (success), 1 (usage), 2 (I/O), and 3 (parse).

## Requirements

- Rust 1.98.1 or newer, edition 2021
- Linux, macOS, or Windows host; ELF is the only inspected format in v1

See [TRD.md](TRD.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [ROADMAP.md](ROADMAP.md) for the design and delivery plan.

## License

MIT. See [LICENSE](LICENSE).
