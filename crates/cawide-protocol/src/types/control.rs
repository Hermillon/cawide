//! Control stream messages

use serde::{Deserialize, Serialize};

use super::rpc::ListeningPort;

/// High-level control messages exchanged on stream 0x02.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    PairRequest {
        pairing_secret: [u8; 32],
        client_node_id: [u8; 32],
        device_name: String,
    },
    PairResponse {
        success: bool,
        error: Option<String>,
        host_name: Option<String>,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Ping {
        client_ts: u64,
    },
    Pong {
        client_ts: u64,
        host_ts: u64,
    },
    /// Host-initiated notification pushed to every open Control stream.
    HostEvent(HostEvent),
}

/// Host state changes that clients should react to (e.g. refresh Git views).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    GitChanged {
        root: String,
    },
    /// Workspace-relative paths; empty = refresh everything.
    FsChanged {
        root: String,
        paths: Vec<String>,
    },
    SessionsChanged,
    SessionUpdated {
        summary: SessionSummary,
    },
    /// Events were dropped (slow client): refetch all state.
    Resync,
    PortsChanged {
        ports: Vec<ListeningPort>,
    },
    WebUrlDetected {
        session_id: String,
        url: String,
    },
    OpenUrl {
        url: String,
        session_id: Option<String>,
    },
}

/// Agent lifecycle states for adaptive UI rendering.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Thinking {
        task_desc: String,
    },
    WaitingForInput {
        prompt: String,
        options: Vec<String>,
    },
    Completed {
        summary: String,
    },
}

/// Full snapshot of an agent's current state within a session.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentState {
    pub agent: String,
    pub status: AgentStatus,
    pub updated_ts: u64,
}

/// Summary of an active session on the host daemon.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: String,
    /// Live working directory of the session's foreground shell/agent (canonical absolute path).
    pub workdir: String,
    pub active_cmd: Option<String>,
    pub last_active_ts: u64,
    pub alive: bool,
    pub exit_code: Option<i32>,
    pub attached: bool,
    pub agent: Option<AgentState>,
    /// Work-tree root enclosing `workdir`.
    pub git_root: Option<String>,
    /// Terminal title set via OSC 0/2, sanitized.
    pub title: Option<String>,
    /// Host-wide monotonic revision of this session's published cwd/git_root/title/agent; clients keep the summary with the higher revision.
    pub revision: u64,
}
