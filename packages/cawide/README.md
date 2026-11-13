<p align="center">
  <img src="https://raw.githubusercontent.com/Hermillon/cawide/main/assets/cawide-icon.png" alt="Cawide Icon" width="96" />
</p>

<h1 align="center">cawide</h1>

<p align="center">
  <strong>Your coding agent is waiting. Approve it from your iPhone.</strong>
</p>

<p align="center">
  <a href="https://cawide.dev">Website</a> ·
  <a href="https://github.com/Hermillon/cawide">GitHub Repository</a> ·
  <a href="https://github.com/Hermillon/cawide/blob/main/docs/architecture.md">Architecture</a>
</p>

---

## Installation

```bash
npm install -g cawide
```

This package installs the precompiled native `cawide` host daemon for your operating system and CPU architecture (macOS, Linux, and Windows on x64/arm64).

## Quick Start

Start Cawide in your project workspace:

```bash
cawide serve --workdir ~/project
```

Then scan the QR code displayed in your terminal using the **Cawide for iPhone** app.

## Common Commands

- `cawide serve --workdir <path>`: Start the host daemon in background mode
- `cawide status`: Check daemon connectivity, active sessions, and pairing state
- `cawide logs -f`: Stream daemon logs
- `cawide stop`: Stop the running daemon
- `cawide pair`: Generate a fresh pairing QR code for a running daemon
- `cawide open <port>`: Open a localhost port or URL in the Cawide browser on your phone
- `cawide setup <agent>`: Install integration hooks for `claude`, `codex`, `omp`, or `opencode`

For full documentation, command flags, architecture, and source code, visit the [Hermillon/cawide GitHub Repository](https://github.com/Hermillon/cawide).

## License

Apache-2.0. Copyright 2026 Đỗ Đăng Long and contributors.
