//! Session lifecycle RPC handlers (Brick 9).

use cawide_protocol::types::SessionSummary;

use crate::net::registry::SessionRegistry;

pub async fn create(
    registry: &SessionRegistry,
    session_id: &str,
    command: Option<String>,
    workdir: Option<&str>,
    cols: u16,
    rows: u16,
) -> Result<SessionSummary, String> {
    registry.create_session(session_id, command, workdir, cols, rows)
}

pub async fn kill(registry: &SessionRegistry, session_id: &str) -> Result<(), String> {
    registry.kill_session(session_id)
}
