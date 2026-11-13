//! Agent telemetry, event mapping, hooks, and shell setup (Brick 7).

pub mod detect;
pub mod hook;
pub mod map;
pub mod setup;
pub mod tracker;

use cawide_protocol::types::{AgentStatus, HostEvent};

use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::ipc::IpcResponse;
use crate::net::registry::{HookOutcome, SessionRegistry};

pub fn ingest(
    registry: &SessionRegistry,
    broadcaster: &HostEventBroadcaster,
    session_id: Option<&str>,
    workdir: Option<&str>,
    agent: &str,
    status: AgentStatus,
) -> IpcResponse {
    let resolved_session_id = match session_id.filter(|s| !s.is_empty()) {
        Some(id) => Some(id.to_string()),
        None => workdir.and_then(|w| registry.find_by_workdir(std::path::Path::new(w))),
    };

    let Some(target_session_id) = resolved_session_id else {
        return IpcResponse::Error("unknown session".into());
    };

    match registry.apply_hook(&target_session_id, agent, status) {
        HookOutcome::Updated(summary) => {
            broadcaster.broadcast(HostEvent::SessionUpdated { summary: *summary });
            IpcResponse::Ok
        }
        HookOutcome::Ignored => IpcResponse::Ok,
        HookOutcome::UnknownSession => IpcResponse::Error("unknown session".into()),
    }
}
