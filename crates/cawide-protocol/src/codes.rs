//! Standard protocol constants, ALPN strings, close codes, and stream reset codes.

pub const ALPN_CAWIDE: &[u8] = b"cawide/5";
pub const ALPN_CAWIDE_LEGACY: [&[u8]; 2] = [b"cawide/4", b"cawide/3"];
pub const ALPN_CAWIDE_PAIR: &[u8] = b"cawide/pair/1";

// QUIC CONNECTION_CLOSE application codes (hooks)
/// Reason: `unauthorized node id`.
pub const CLOSE_UNAUTHORIZED: u32 = 0x01;
/// Reason: `pairing disabled`.
pub const CLOSE_PAIRING_DISABLED: u32 = 0x02;
/// Reason: `unsupported alpn`.
pub const CLOSE_UNSUPPORTED_ALPN: u32 = 0x03;
/// Reason: `pairing complete` (sent by the client).
pub const CLOSE_PAIRING_DONE: u32 = 0x00;

// Stream RESET/STOP codes (dispatcher)
pub const STREAM_ERR_UNKNOWN_PURPOSE: u32 = 0x10;
pub const STREAM_ERR_INVALID_SESSION: u32 = 0x11;
pub const STREAM_ERR_SPAWN_FAILED: u32 = 0x12;
pub const STREAM_ERR_PROTOCOL: u32 = 0x13;
pub const STREAM_ERR_SESSION_OCCUPIED: u32 = 0x14;
pub const STREAM_ERR_SESSION_TAKEN: u32 = 0x15;
pub const STREAM_ERR_SESSION_GONE: u32 = 0x16;
/// Client fell behind the host ring buffer; re-attach to receive a screen snapshot.
pub const STREAM_ERR_RESYNC: u32 = 0x17;
