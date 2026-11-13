//! Agent hook execution (Brick 7).

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use crate::agent::map::map_event;
use crate::net::ipc::IpcRequest;
use crate::net::send_ipc_request;

struct SyncStdoutGuard {
    need_flush: bool,
}

impl SyncStdoutGuard {
    fn new(agent: &str) -> Self {
        Self {
            need_flush: agent == "codex" || agent == "claude",
        }
    }

    fn flush_now(&mut self) {
        if self.need_flush {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(b"{}");
            let _ = out.flush();
            self.need_flush = false;
        }
    }
}

impl Drop for SyncStdoutGuard {
    fn drop(&mut self) {
        self.flush_now();
    }
}

pub async fn run_hook(agent: &str, event: Option<&str>, payload_arg: Option<&str>) {
    let mut stdout_guard = SyncStdoutGuard::new(agent);

    if agent == "codex" && event == Some("Stop") {
        stdout_guard.flush_now();
    }

    let payload: serde_json::Value = if let Some(arg) = payload_arg {
        serde_json::from_str(arg).unwrap_or(serde_json::Value::Null)
    } else if !std::io::stdin().is_terminal() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().take(256 * 1024);
            let mut buf = Vec::new();
            let _ = stdin.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            Err(_) => serde_json::Value::Null,
        }
    } else {
        serde_json::Value::Null
    };

    if agent == "codex" && payload.get("hook_event_name").and_then(|v| v.as_str()) == Some("Stop") {
        stdout_guard.flush_now();
    }

    let session_id = std::env::var("CAWIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let workdir = if session_id.is_none() {
        let from_payload = payload
            .get("cwd")
            .or_else(|| payload.get("workdir"))
            .or_else(|| payload.get("directory"))
            .or_else(|| payload.get("workspace"))
            .or_else(|| payload.get("location").and_then(|l| l.get("directory")))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        from_payload
            .or_else(|| std::env::current_dir().ok())
            .map(|p| p.display().to_string())
    } else {
        None
    };

    if session_id.is_none() && workdir.is_none() {
        return;
    }

    let socket_path = match std::env::var("CAWIDE_SOCKET") {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        _ => match crate::net::config_dir() {
            Ok(dir) => crate::net::default_ipc_path(&dir),
            Err(_) => return,
        },
    };

    let status = match map_event(agent, event, &payload) {
        Some(s) => s,
        None => return,
    };

    let req = IpcRequest::AgentEvent {
        session_id,
        workdir,
        agent: agent.to_string(),
        status,
    };
    let _ =
        tokio::time::timeout(Duration::from_secs(1), send_ipc_request(&socket_path, &req)).await;
}
