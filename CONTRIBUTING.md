# Contributing to Cawide

Thank you for your interest in contributing to Cawide!

## Prerequisites

- **Rust**: Stable toolchain installed via [rustup](https://rustup.rs).
- **Cargo tools**: Install gate check utilities:
  ```sh
  cargo install cargo-nextest cargo-deny --locked
  ```
- **Node.js**: Version ≥ 18 for npm wrapper packaging and scripts.

## Local Gate Commands

Before opening a pull request, ensure all local gate checks pass:

1. Code formatting:
   ```sh
   cargo fmt --all --check
   ```
2. Linter / Clippy:
   ```sh
   cargo clippy --workspace --all-targets --locked -- -D warnings
   ```
3. Test suite:
   ```sh
   cargo nextest run --workspace --locked
   ```
4. Dependency and license checks:
   ```sh
   cargo deny check
   ```

## Contribution Guidelines

### Developer Certificate of Origin (DCO)

All commits must include a Signed-off-by line certifying compliance with the Developer Certificate of Origin (DCO):
```sh
git commit -s -m "feat(daemon): add support for custom socket path"
```
This requirement is enforced automatically by CI.

### Pull Requests & Commits

- **Conventional Commits**: Use conventional commit titles (`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, etc.).
- **Atomic Changes**: Keep one logical change per pull request.
- **Tests**: Include automated unit or integration tests for all functional changes or bug fixes.

### Scope & Feedback

- The official iOS app is proprietary and not hosted in this repository.
- Feedback, bug reports, and suggestions regarding the mobile app should be submitted via GitHub Discussions.

### Licensing

All inbound contributions are licensed under the Apache License, Version 2.0 (inbound = outbound).
