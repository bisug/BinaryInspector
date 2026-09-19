# Security Policy

BinaryInspector treats every target as hostile input. It accepts regular files only, opens Unix targets without following symlinks or blocking on FIFO replacement, does no runtime networking, and never executes, loads, or dynamically links the target. Parser bounds checks, allocation caps, sanitized terminal strings, and structured JSON output are security boundaries.

Report a suspected vulnerability privately to the project maintainer rather than opening a public issue. Include the affected revision, reproduction steps or a minimal sample where safe to share, impact, and any proposed mitigation. The maintainer will acknowledge reports, assess a fix, and coordinate disclosure before publishing details.

No `unsafe` code is planned. Any future `unsafe` use must document its justification, invariants, and review coverage.
