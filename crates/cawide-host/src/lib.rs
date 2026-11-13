//! Cawide Host
//!
//! Foundational daemon host engine for Cawide remote vibe coding.

pub mod agent;
pub mod auth;
pub mod cloud;
pub mod daemon;
pub mod devices;
pub mod forge;
pub mod net;
pub mod ports;
pub mod power;
pub mod profile;
pub mod pty;
pub mod push;
pub mod rpc;
pub mod ui;
pub mod update;
pub mod watch;
pub mod web;
pub use auth::{AuthError, AuthorizedEntry, AuthorizedKeysStore, PairingManager, PairingTicket};
pub use pty::{
    AttachStart, PtyError, PtySession, PtySpawnOptions, SessionOutput, SliceResult, Utf8RingBuffer,
    BROADCAST_CHANNEL_CAPACITY, DEFAULT_RING_BUFFER_CAPACITY, MAX_REPLAY_BYTES,
    SNAPSHOT_MODE_BASELINE, SNAPSHOT_SCROLLBACK_LINES,
};
