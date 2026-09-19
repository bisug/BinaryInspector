# Contributing

Use Rust 1.98.1 and keep changes small and reviewable. Before committing, run:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```

Treat all fixture binaries as generated artifacts: commit the smallest source and a regeneration command beside each fixture, record its target architecture, and do not replace it with an unexplained blob. Add a malformed-input regression for every parser bug.

Do not add dependencies without documenting why the standard library and installed dependencies are insufficient. Do not commit credentials, personal configuration, agent artifacts, or generated build directories.
