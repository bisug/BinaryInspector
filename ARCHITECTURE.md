# Architecture

```
CLI or native GUI -> input validation -> elf parser -> analysis -> Binary model -> reporter
```

- `cli`: command-line parsing, selection flags, and exit-code mapping.
- `gui`: native `eframe` executable. It opens or receives dropped files and performs inspection off the UI thread.
- `input`: regular-file validation and bounded byte reads.
- `elf`: ELF-specific decoding and validation; it produces domain values, not terminal text.
- `analysis`: derives dependencies and hardening properties from decoded ELF data.
- `model`: serializable, format-neutral result types and report selections.
- `report`: sanitized human text and JSON serialization.

There is deliberately no format trait or plugin system: the `elf` module and a single inspection entry point are the extension seam. Both executables call that entry point, so a second format may add another decoder without changing their interaction layers.

Data flows one way. Untrusted bytes stay in parsing/analysis; reporting receives validated owned values. Vectors retain file order and no user-visible output depends on hash-map iteration.
