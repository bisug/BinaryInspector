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

Use GitHub issues for public bugs and feature requests; use pull requests for changes. Do not report security issues publicly—follow [SECURITY.md](SECURITY.md).

The GUI is a separate executable, `binary-inspector-gui`, and must call the shared `inspect` function rather than reimplementing parsing. Validate it with `cargo build --release --bin binary-inspector-gui`; visual smoke-testing is required on each supported desktop platform before a GUI release.
