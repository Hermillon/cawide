use serde::{Deserialize, Serialize};

/// Header sent by the phone to request opening a web tunnel to a target host and port.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TunnelOpen {
    pub host: String,
    pub port: u16,
}

/// Category of tunnel connection failure returned by the host.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelFailure {
    Refused,
    Unreachable,
    DnsFailed,
    TimedOut,
    InvalidTarget,
    Other,
}

/// Acknowledgement from host responding to a `TunnelOpen` request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TunnelAck {
    Connected,
    Failed {
        reason: TunnelFailure,
        message: String,
    },
}

/// Maximum allowed length for tunnel open/ack headers (1024 bytes).
pub const MAX_TUNNEL_HEADER_SIZE: usize = 1024;
