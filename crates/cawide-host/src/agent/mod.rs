//! Agent telemetry, event mapping, hooks, and shell setup (Brick 7).

pub mod claude;
pub mod detect;
pub mod hook;
pub mod map;
pub mod respond;
pub mod setup;
pub mod tracker;

use cawide_protocol::types::HostEvent;

use crate::agent::map::AgentSignal;
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::ipc::IpcResponse;
use crate::net::registry::{HookOutcome, SessionRegistry};

pub fn ingest(
    registry: &SessionRegistry,
    broadcaster: &HostEventBroadcaster,
    session_id: &str,
    agent: &str,
    signal: AgentSignal,
) -> IpcResponse {
    if session_id.is_empty() {
        return IpcResponse::Error("unknown session".into());
    }

    match registry.apply_hook_signal(session_id, agent, signal) {
        HookOutcome::Updated(summary) => {
            broadcaster.broadcast(HostEvent::SessionUpdated { summary: *summary });
            IpcResponse::Ok
        }
        HookOutcome::Ignored => IpcResponse::Ok,
        HookOutcome::UnknownSession => IpcResponse::Error("unknown session".into()),
    }
}
