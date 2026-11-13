//! RPC stream messages and structures

use crate::types::control::SessionSummary;
use serde::{Deserialize, Serialize};

use super::forge::{ForgeAccountOp, ForgeAccountReply, ForgeError, ForgeRepoOp, ForgeRepoReply};
use super::git::{GitError, GitOp, GitReply};
/// Maximum number of active sessions permitted on a host.
pub const MAX_SESSIONS: usize = 32;

/// Framing container pairing a Request ID with its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcFrame<T> {
    pub request_id: u32,
    pub payload: T,
}

/// Maximum file size served by `FsRead` (500 KB, INV-FS-002).
pub const MAX_FILE_SIZE: u64 = 500 * 1024;
/// Maximum file size served by `FsReadChunk` (64 MB). `FsRead` keeps its 500 KB cap.
pub const MAX_CHUNKED_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// Maximum bytes returned by one `FsReadChunk`; larger `length` values are clamped (4 MB).
pub const FS_READ_CHUNK_MAX_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum combined diff size returned by `GitDiff` (200 KB, INV-GIT-001).
pub const MAX_DIFF_BYTES: usize = 200 * 1024;
/// Maximum `FsUpload` payload (8 MB, INV-FS-003).
pub const FS_UPLOAD_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Directory entries visited by one `FsSearch` before it stops walking.
pub const FS_SEARCH_MAX_VISITED_ENTRIES: usize = 20_000;
/// Maximum results returned by one `FsSearch`.
pub const FS_SEARCH_MAX_RESULTS: usize = 100;

/// Remote procedure call requests sent on stream 0x03.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RpcRequest {
    FsList {
        root: String,
        path: String,
        recursive: bool,
    },
    FsRead {
        root: String,
        path: String,
        offset: u64,
        length: u32,
    },
    FsSearch {
        root: String,
        query: String,
    },
    FsUpload {
        filename: String,
        data: Vec<u8>,
    },
    RemoteOpen {
        root: String,
        target: String,
    },
    Git {
        root: String,
        op: GitOp,
    },
    ForgeAccounts {
        op: ForgeAccountOp,
    },
    Forge {
        root: String,
        account: Option<String>,
        op: ForgeRepoOp,
    },
    SessionList,
    SessionCreate {
        session_id: String,
        command: Option<String>,
        workdir: Option<String>,
    },
    SessionKill {
        session_id: String,
    },
    HostInfo,
    FsReadChunk {
        root: String,
        path: String,
        offset: u64,
        length: u32,
    },
    PortList,
    VoiceCompilePrompt {
        session_id: String,
        transcript: String,
        active_file: Option<String>,
        language_mode: String,
    },
    SetPushChannel {
        channel: Option<PushChannel>,
    },
}

/// Remote procedure call responses returned on stream 0x03.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RpcResponse {
    FsList(Result<Vec<FsEntry>, String>),
    FsRead(Result<FsReadResult, String>),
    FsSearch(Result<Vec<FsSearchResult>, String>),
    /// Absolute host path of the stored upload.
    FsUpload(Result<String, String>),
    RemoteOpen(Result<(), String>),
    Git {
        result: Result<GitReply, GitError>,
    },
    ForgeAccounts {
        result: Result<ForgeAccountReply, ForgeError>,
    },
    Forge {
        result: Result<ForgeRepoReply, ForgeError>,
    },
    SessionList(Result<Vec<SessionSummary>, String>),
    SessionCreate(Result<SessionSummary, String>),
    SessionKill(Result<(), String>),
    HostInfo(Result<HostInfo, String>),
    FsReadChunk(Result<FsChunk, String>),
    PortList(Result<Vec<ListeningPort>, String>),
    VoiceCompilePrompt(Result<VoiceCompileResult, String>),
    SetPushChannel(Result<(), String>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PushChannel {
    pub channel_id: String,
    pub secret: String,
}

/// Result of voice prompt compilation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VoiceCompileResult {
    pub clean_prompt: String,
    pub detected_language: String,
}

/// File system directory entry.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ts: u64,
}

/// Bounded file read. `too_large` files return no data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FsReadResult {
    pub data: Vec<u8>,
    pub too_large: bool,
    pub total_size: u64,
}

/// One slice of a file up to `MAX_CHUNKED_FILE_SIZE`. `length == 0` returns metadata only.
/// `too_large` files return no data. Clients compare (`total_size`, `modified_unix_ns`)
/// across chunks to detect a file changing mid-download.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FsChunk {
    pub data: Vec<u8>,
    pub too_large: bool,
    pub total_size: u64,
    pub modified_unix_ns: u64,
}

/// Fuzzy search hit; `match_indices` are char indices into `path`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FsSearchResult {
    pub path: String,
    pub score: u32,
    pub match_indices: Vec<u32>,
}

/// Host platform and workspace facts returned by `RpcRequest::HostInfo`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    /// Display name (same source as `PairResponse.host_name`).
    pub host_name: String,
    /// `std::env::consts::OS` on the host, e.g. "macos", "linux".
    pub os: String,
    /// `std::env::consts::ARCH` on the host, e.g. "aarch64", "x86_64".
    pub arch: String,
    /// cawide-host crate version, e.g. "0.5.0".
    pub version: String,
    /// Canonical workspace root (absolute host path).
    pub workdir: String,
}

/// Single diff hunk representing changes in a file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DiffHunk {
    pub file_path: String,
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub header: String,
    pub lines: Vec<DiffLine>,
    pub content_hash: String,
}

/// Single line in a diff hunk.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffLineKind,
    pub content: String,
}

/// Kind of diff line.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiffLineKind {
    Context,
    Addition,
    Deletion,
}

/// Host listening port discovered by port scanning.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ListeningPort {
    pub port: u16,
    pub addresses: Vec<String>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub session_id: Option<String>,
}
