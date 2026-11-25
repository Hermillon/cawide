# Cawide System Invariants & Architecture Directives

Governing architectural invariants, wire protocol contracts, and subsystem rules.

## 1. Non-Negotiable System Invariants

| Invariant | Directives & Enforcement |
|:---|:---|
| **Direct Keystroke Path** | Keystrokes MUST route directly to the QUIC PTY stream without dispatching through main-thread runloop queues or UI layout passes. Client terminal engines MUST render immediately on local echo or raw PTY read. |
| **Zero Head-of-Line Blocking** | Multiplexing MUST isolate failure domains over independent RFC 9000 QUIC streams: PTY (`0x04`), Control (`0x02`), RPC (`0x03`), and Tunnel (`0x05`). A stall or backpressure on RPC or Tunnel streams MUST NOT impede PTY input/output. |
| **Session Indestructibility** | Host child processes, shells, and agent CLI sessions MUST survive client disconnections, IP roaming, cellular handoffs, and background suspension. Sessions persist across transport resets via the ring buffer and headless PTY master. |
| **Host Ring-Buffer & Backpressure Limits** | PTY ring buffer MUST enforce `DEFAULT_RING_BUFFER_CAPACITY = 4 MiB`, 2 MiB replay ceiling, and 10,000-line scrollback; output coalesces at 16 ms (`PTY_COALESCE_INTERVAL` in `crates/cawide-host/src/net/dispatcher.rs`), chunks cap at `MAX_PTY_CHUNK_RAW = 64 KiB` (`crates/cawide-protocol/src/codec.rs`). |
| **Zero-Trust TOFU Security** | Ephemeral pairing MUST operate over ALPN `cawide/pair/1` with a 5-minute TTL. Active sessions MUST operate over ALPN `cawide/5` with mTLS 1.3 using raw Ed25519 keys. Unrecognized node IDs MUST be rejected at `EndpointHooks::after_handshake` with close code `0x01` (`CLOSE_UNAUTHORIZED`) prior to stream acceptance. Account-synced keys are admitted only through a verified mutual-signature `DeviceLink` path from a locally paired key; Cawide Cloud can revoke but never grant. Account-managed hosts require a live 120 s snapshot lease (`LEASE_SECS`) and reject legacy `PairRequest`/`AccountClaim`. |

---

## 2. Wire Protocol Contract Registry

### 2.1 ALPN Identifiers
- `cawide/5`: Production interactive sessions (PTY, RPC, Control, Tunnel).
- `cawide/pair/1`: Ephemeral out-of-band TOFU device pairing.

### 2.2 Stream Multiplexing & Framing
Each QUIC bi-directional stream initiated by the client MUST begin with a 1-byte purpose identifier:

| Purpose ID | Identifier | Framing & Payload Limits |
|:---|:---|:---|
| `0x02` | `STREAM_PURPOSE_CONTROL` | 4-byte BE length prefix + Postcard DTO (incl. `PairManagedRequest`/`PairManagedResponse`). Max: 64 KB. |
| `0x03` | `STREAM_PURPOSE_RPC` | 4-byte BE request ID + 4-byte BE length prefix (bit 31 `RPC_FLAG_COMPRESSED`) + Postcard payload (incl. `AccountAdopt`; trailing `RPC_CAP_ZSTD` byte inside len when caps != 0). Max: 16 MB. |
| `0x04` | `STREAM_PURPOSE_PTY` | 2-byte BE length-prefixed `PtyAttachHeader`, 4-byte BE length-prefixed `PtyAttachAck` (max 8 MB), followed by the raw byte stream or, with `accept_chunked_output`, u32-BE prefixed frames (bit 31 `PTY_CHUNK_FLAG_COMPRESSED`; bit 30 `PTY_CHUNK_FLAG_INPUT_MODE`: 1-byte ECHO/ICANON flags, only with `accept_input_mode_frames`). |
| `0x05` | `STREAM_PURPOSE_TUNNEL` | 2-byte BE length-prefixed `TunnelOpen` / `TunnelAck`, followed by raw bidirectional TCP/SOCKS5 byte stream. |

### 2.3 Connection Close Codes
- `0x00`: `CLOSE_PAIRING_DONE` - Pairing handshake finished successfully.
- `0x01`: `CLOSE_UNAUTHORIZED` - Peer public key unrecognized or untrusted.
- `0x02`: `CLOSE_PAIRING_DISABLED` - Daemon pairing mode is inactive or expired.
- `0x03`: `CLOSE_UNSUPPORTED_ALPN` - Client requested an unsupported ALPN.

### 2.4 Stream Reset Codes
- `0x10`: `STREAM_ERR_UNKNOWN_PURPOSE` - Stream purpose byte not supported.
- `0x11`: `STREAM_ERR_INVALID_SESSION` - Requested session ID does not exist.
- `0x12`: `STREAM_ERR_SPAWN_FAILED` - Failed to spawn PTY child process.
- `0x13`: `STREAM_ERR_PROTOCOL` - Framing error, deserialization failure, or size violation.
- `0x14`: `STREAM_ERR_SESSION_OCCUPIED` - Session currently attached by another client.
- `0x15`: `STREAM_ERR_SESSION_TAKEN` - Session taken over by higher-priority attachment.
- `0x16`: `STREAM_ERR_SESSION_GONE` - Child process exited and session is destroyed.
- `0x17`: `STREAM_ERR_RESYNC` - Live-attached client fell behind the ring buffer while streaming; client MUST re-attach to receive a screen snapshot.

---

## 3. Crate Responsibilities & Invariants

### 3.1 Architectural Scope
This domain covers `crates/cawide-protocol`, `crates/cawide-account`, and `crates/cawide-host`.

### 3.2 Invariants & Runtime Guidelines

| Area | Directive & Enforcement |
|:---|:---|
| **Async Runtime** | Tokio multi-threaded runtime MUST drive network I/O, QUIC streams, and timers. Async tasks MUST NOT execute blocking operations directly. |
| **Blocking Work Isolation** | Blocking filesystem operations, PTY read loops, and process spawns MUST use `tokio::task::spawn_blocking` to avoid stalling reactor threads. |
| **PTY Ring Buffer** | Enforce `DEFAULT_RING_BUFFER_CAPACITY = 4 MiB`, 2 MiB replay ceiling, 10,000-line scrollback. |
| **Ring Underrun Resync** | On attach, an offset outside the retained ring, or more than `MAX_REPLAY_BYTES` behind head, MUST receive `PtyAttachAck::Snapshot` (or `SnapshotGzip`) with no stream reset. A live-attached client that falls behind the ring while streaming MUST be reset with `0x17` (`STREAM_ERR_RESYNC`); it re-attaches with its current received offset and receives a snapshot. |
| **Serialization** | All wire DTOs on Control and RPC streams MUST serialize using `postcard`. Length prefixes MUST precede payloads: 4-byte big-endian for Control (max 64 KB) and RPC (max 16 MB; negotiated zstd compression via bit 31 flag and trailing caps byte). |
| **Zero-Copy Stream I/O** | PTY byte streaming between PTY master and QUIC stream MUST minimize memory allocations using bounded buffers. |

### 3.3 Host Subsystem Router

| Path | Responsibility | Governing Invariants |
|:---|:---|:---|
| `crates/cawide-host/src/rpc/` | RPC dispatch, workspace jail, filesystem RPCs, hardened process runner (`setsid` + process-group kill) | INV-FS-001/002/003 |
| `crates/cawide-host/src/rpc/git/` | Git engine behind the `Git { root, op: GitOp }` envelope: hardened `git` CLI, staging, LFS detection, history graph, branches, remotes, stash, sequencer, SSH host-key policy | INV-GIT-001/002/003, INV-LFS-001, INV-SSH-001 |
| `crates/cawide-host/src/forge/` | Forge engine behind `ForgeAccounts`/`Forge` RPCs: REST adapters (GitHub, GitLab, Gitea, Bitbucket, Azure DevOps), capability table, flock-guarded account store, `cawide git-credential` helper, SSH key/host-key trust | INV-FORGE-001/002, INV-SSH-001 |
| `crates/cawide-account/` | Account trust statements (`DeviceLink`, `MachineClaim`, `ManagedClaimBody`, `DeviceSessionRegistration`, `cawide/managed-claim/1`, `cawide/managed-claim-accept/1`, `cawide/device-session-register/1`, SAS) | Trust model in docs/architecture.md |
| `crates/cawide-host/src/agent/` | PTY-gated telemetry (`AgentStream`), `AgentRespond`, E2E push (`push.rs`) | `docs/architecture.md` §4 |

Specifications: [docs/architecture.md §2.5](docs/architecture.md#25-rpc-engine-security-cratescawide-hostsrcrpc) and [docs/architecture.md §2.7](docs/architecture.md#27-forge-engine-cratescawide-hostsrcforge).

### 3.4 Verification Commands
Run from the `cawide` root (`oss/cawide` in cawide-production):
```bash
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 4. npm Package Rules

### 4.1 Scope
This domain covers `packages/cawide/` and scripts associated with publishing the `cawide` host CLI via npm.

### 4.2 Invariants & Distribution Rules

| Domain | Directive & Enforcement |
|:---|:---|
| **Multi-Platform Binary Resolution** | The root npm package `cawide` acts as an orchestrator. It resolves pre-compiled host binaries via platform-specific packages declared in `optionalDependencies` (`cawide-darwin-arm64`, `cawide-darwin-x64`, `cawide-linux-x64`, `cawide-linux-arm64`, `cawide-win32-x64`). |
| **No Runtime Build Step** | The npm installer MUST NOT attempt to invoke `cargo build` on end-user machines. If the matching platform binary package is absent, the installer MUST emit an actionable diagnostic pointing to manual installation instructions. |
| **Packaging Automation** | Packaging and tarball generation MUST be performed via `scripts/package-npm.js`. Direct modifications to generated platform packages outside of the packaging script are prohibited. |

### 4.3 Packaging Commands
Run from repository root:
```bash
# Package local host binary for testing
node scripts/package-npm.js --local

# Dry-run validation of publishable npm tarballs
node scripts/package-npm.js --pack --dry-run
```
