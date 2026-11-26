# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.16.0] - 2026-11-26

### Added
- First-class Claude Code integration: loop-proof POSIX `claude` launcher shim (`CAWIDE_CLAUDE_SHIM_PID` / `CAWIDE_CLAUDE_OWNER`) injecting per-launch `--settings <config_dir>/agents/claude-settings.json` with all 15 hook events, plus `ClaudeEvent` and long-lived `ClaudePermission` IPC (`run_claude_hook`, `ClaudeSessionState`).
- Interactive remote responses for Claude Code `PermissionRequest` (`Bash`/tool approvals, `AskUserQuestion`, and `ExitPlanMode` plan review/feedback), backed by a `transcript_path` watcher and PTY-input anchor accelerator.
- `remove_legacy_claude_hooks` cleanup for legacy `" hook claude --event "` entries in `~/.claude/settings.json` without creating `.cawide-bak` backups.
- `cawide agent <codex|opencode>` launcher and native Codex/OpenCode observers with phone replies.

### Removed
- codex/opencode hooks, OpenCode plugin, codex/opencode shims, `cawide setup codex|opencode`.

### Fixed
- daemons with a non-default config dir (tests) no longer modify `$HOME`; legacy codex/opencode entries are cleaned on daemon start.

### Notes
- On Windows, `pwsh`/`cmd` PTYs resolve `claude.cmd` via `PATHEXT` rather than the POSIX `sh` shim, so Claude Code state comes from process probing only.

## [0.15.3] - 2026-11-25

### Added
- Managed account pairing (`PairManagedRequest`/`AccountAdopt`), 120 s authorization lease for account-managed hosts, and signed push producers carrying `host_epoch`.

### Changed
- Managed host removal revokes immediately and prunes push channels; legacy QR pairing (`PairRequest`) and `AccountClaim` are refused on managed hosts.

### Fixed
- Unmanaged pending-claim admission no longer gates locally paired keys on a snapshot lease.

## [0.15.2] - 2026-11-25

### Fixed
- Removed `extract_text_question` heuristic guessing on OMP `agent_end` so completed turns always transition cleanly to `Completed` without false `WaitingForInput` prompts.
- Guarded OMP `cawide.js` (`isMain`) against non-interactive runs (`ctx?.hasUI === false`) and added `tool_execution_end` cleanup so blocked/denied tool calls do not leave stale attention prompts.
- Cleared stale non-`Plan` attention items on `TurnOutcome::Started` and mapped `OSC 7501` `kind=permission` to `AttentionKind::Approval`.

## [0.15.1] - 2026-11-25

### Changed
- Unified `tab_title` fallback (`entry.title` -> `cwd` basename -> `session_id`) across alerts and Live Activity payloads.

### Fixed
- Emit `dismiss_immediately` on Live Activity `End` payloads for `kill_session`, `remove`, `remove_if_same`, `kill_all`, clean EOF exits, shell return after completion, and `Idle` transitions.

## [0.15.0] - 2026-11-24

### Added
- Long-lived OMP v3 streaming extension (`// cawide-telemetry v3`) and `cawide hook omp --stream` (`IpcRequest::AgentStream`) with `epoch`/`seq` ordering, `plan_review_requested`/`resolved`, `tool_approval_requested`/`resolved`, `ask` options, `awaitingAsyncWork`/`willContinue`, and `finalTextHead`/`finalTextTail` question detection.
- `RpcRequest::SetPushChannelV2` (`PushChannelV2` with `PUSH_CAP_*` capability flags) and `RpcRequest::AgentRespond` (`AgentChoice`) for remote approval, ask, plan review (`ResolvePlanReview`), and text replies.
- End-to-end push payload encryption (`ChaCha20-Poly1305` with bound AAD and fresh 12-byte nonce) for alert notifications and Live Activity content states.
- Serial per-`(channel_id, session_id)` Live Activity dispatch with monotonic Unix-second timestamps, 20 s tool-step coalescing, and `PUSH_CAP_PUSH_TO_START` `start_attributes`.
- OSC 7501 (`working|blocked|done|error|idle`) fallback in `TermSignals` and `AgentTracker` when hook updates are absent or stall during `Thinking`.

### Changed
- Enforced strict PTY gating in `cawide hook` and generated JS extensions: both `CAWIDE_SESSION_ID` and `CAWIDE_SOCKET` are required (removed workdir and default-socket fallbacks).
- Removed host-side `last_input_unix` push suppression so clients handle session-level foreground suppression directly.

### Fixed
- Isolated `auto_setup_all` in `CawideServer::bind` to run only when `config.config_dir` matches the default `config_dir()`, preventing test/dev daemons from overwriting user agent configs.

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
