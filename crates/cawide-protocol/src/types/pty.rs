//! PTY stream attach headers

use serde::{Deserialize, Serialize};

/// Connection header sent on the PTY stream (0x04) immediately after the purpose byte.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PtyAttachHeader {
    pub session_id: String,
    pub last_ack_offset: u64,
    pub resume: bool,
    pub accept_compressed_snapshot: bool,
    pub accept_chunked_output: bool,
    pub accept_input_mode_frames: bool,
}

impl PtyAttachHeader {
    pub fn new(session_id: impl Into<String>, last_ack_offset: u64, resume: bool) -> Self {
        Self {
            session_id: session_id.into(),
            last_ack_offset,
            resume,
            accept_compressed_snapshot: false,
            accept_chunked_output: false,
            accept_input_mode_frames: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyPtyAttachHeaderV5 {
    pub session_id: String,
    pub last_ack_offset: u64,
    pub resume: bool,
    pub accept_compressed_snapshot: bool,
    pub accept_chunked_output: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyPtyAttachHeaderV4 {
    pub session_id: String,
    pub last_ack_offset: u64,
    pub resume: bool,
    pub accept_compressed_snapshot: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyPtyAttachHeader {
    pub session_id: String,
    pub last_ack_offset: u64,
    pub resume: bool,
}

/// Host reply to a PTY attach, sent once (length-prefixed postcard) before the raw output bytes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PtyAttachAck {
    /// Output continues exactly at the requested `offset`; ring bytes from there follow.
    Replay { offset: u64 },
    /// The requested offset is no longer retained (older than the ring tail, or past the head
    /// because the session restarted). `screen` redraws the current terminal state; `history`
    /// holds older lines for an empty terminal. Live bytes that follow start at `offset`.
    Snapshot {
        offset: u64,
        history: Vec<u8>,
        screen: Vec<u8>,
    },
    SnapshotGzip {
        offset: u64,
        uncompressed_history_len: u32,
        history: Vec<u8>,
        uncompressed_screen_len: u32,
        screen: Vec<u8>,
    },
}
