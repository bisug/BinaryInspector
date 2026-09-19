# Security Policy

BinaryInspector treats every target as hostile input. It accepts regular files only, opens Unix targets without following symlinks or blocking on FIFO replacement, does no runtime networking, and never executes, loads, or dynamically links the target. Parser bounds checks, allocation caps, sanitized terminal strings, and structured JSON output are security boundaries.

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability privately, use one of the following methods:

1. **GitHub Security Advisories (Preferred)**: Submit a confidential report via [GitHub Private Vulnerability Reporting](https://github.com/bisug/BinaryInspector/security/advisories/new).
2. **Email**: Send details directly to the project maintainer at [bisu.ghlan@gmail.com](mailto:bisu.ghlan@gmail.com).

### Information to Include

To help us triage and resolve issues quickly, please provide:
- The affected version or commit SHA.
- A description of the vulnerability and its potential impact.
- Step-by-step reproduction steps or a minimal sample binary where safe to share.
- Any proposed remediation or mitigation.

### Response and Disclosure

- **Acknowledgment**: You will receive an initial response acknowledging your report within 48 hours.
- **Assessment**: The maintainer will investigate the issue and coordinate with you on fix validation.
- **Coordinated Disclosure**: Fixes will be released promptly, and security advisories published once patched versions are available.

## Code Safety

No `unsafe` code is permitted in this repository (`#![forbid(unsafe_code)]`). Any future proposed use must document its mathematical justification, invariant proofs, and comprehensive security review coverage.
