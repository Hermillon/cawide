# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.0] - 2026-11-23

### Added
- Account-bound machines with co-signed device trust (`cawide-account` crate, account login/trust sync, and RPC/IPC support).

### Fixed
- Reserve full zstd compress bound in `PtyChunkEncoder` to prevent `'Destination buffer is too small'` errors on high-entropy PTY chunks.
- Preserve user `ZDOTDIR` during zsh startup integration so plugin managers (`antidote`, `zimfw`, `prezto`) and `HISTFILE` work properly.

### Changed
- Updated dependencies (`iroh`, `portable-pty`, `rusqlite`, `zstd`, `opener`) and removed unused `noq-proto` and voice compile handler.

## [0.13.0] - 2026-11-13

### Added
- First public source release under Apache-2.0.

### Changed
- Cawide Cloud endpoint is `https://api.cawide.dev`, verified with the operating system trust store.

### Removed
- `CAWIDE_CLOUD_CERT_SHA256` (certificate pinning).
