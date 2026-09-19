# Architecture

```
CLI -> input validation -> elf parser -> analysis -> Binary model -> reporter
```

- `cli`: command-line parsing, selection flags, and exit-code mapping.
- `input`: regular-file validation and bounded byte reads.
- `elf`: ELF-specific decoding and validation; it produces domain values, not terminal text.
- `analysis`: derives dependencies and hardening properties from decoded ELF data.
- `model`: serializable, format-neutral result types and report selections.
- `report`: sanitized human text and JSON serialization.

There is deliberately no format trait or plugin system: the `elf` module and a single inspection entry point are the extension seam. A second format may add another decoder behind that entry point without changing CLI or reporting.

Data flows one way. Untrusted bytes stay in parsing/analysis; reporting receives validated owned values. Vectors retain file order and no user-visible output depends on hash-map iteration.
