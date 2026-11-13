//! Domain protocol types

pub mod control;
pub mod forge;
pub mod git;
pub mod pty;
pub mod rpc;
pub mod tunnel;

pub use forge::*;
pub use git::*;

pub use control::{AgentState, AgentStatus, ControlMessage, HostEvent, SessionSummary};
pub use pty::{PtyAttachAck, PtyAttachHeader};
pub use rpc::{
    DiffHunk, DiffLine, DiffLineKind, FsChunk, FsEntry, FsReadResult, FsSearchResult, HostInfo,
    ListeningPort, PushChannel, RpcFrame, RpcRequest, RpcResponse, VoiceCompileResult,
    FS_READ_CHUNK_MAX_BYTES, FS_SEARCH_MAX_RESULTS, FS_SEARCH_MAX_VISITED_ENTRIES,
    FS_UPLOAD_MAX_BYTES, MAX_CHUNKED_FILE_SIZE, MAX_DIFF_BYTES, MAX_FILE_SIZE, MAX_SESSIONS,
};
pub use tunnel::{TunnelAck, TunnelFailure, TunnelOpen, MAX_TUNNEL_HEADER_SIZE};
