#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cawide_host::agent::observe::{ObserverHub, ObserverPaths};
use cawide_host::net::broadcaster::HostEventBroadcaster;
use cawide_host::net::probe::SessionProbe;
use cawide_host::net::registry::SessionRegistry;
use cawide_protocol::types::{AgentStatus, HostEvent};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rusqlite::Connection;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{broadcast, mpsc, Notify};
use tokio_websockets::{Message, ServerBuilder};

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    fn set(vars: &[(&'static str, &Path)]) -> Self {
        let mut saved = Vec::with_capacity(vars.len());
        for &(k, v) in vars {
            saved.push((k, std::env::var_os(k)));
            std::env::set_var(k, v);
        }
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, prev) in self.saved.drain(..) {
            match prev {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn short_tempdir() -> tempfile::TempDir {
    let probe = std::env::temp_dir().join("cwXXXXXX/c/app-server-control/app-server-control.sock");
    if probe.as_os_str().len() < 95 {
        tempfile::Builder::new().prefix("cw").tempdir().unwrap()
    } else {
        tempfile::Builder::new()
            .prefix("cw")
            .tempdir_in("/tmp")
            .unwrap()
    }
}

fn write_fake_agent(bin_dir: &Path, name: &str) {
    std::fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join(name);
    std::fs::write(&path, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn wait_session_event<F>(
    rx: &mut broadcast::Receiver<HostEvent>,
    session_id: &str,
    pred: F,
    timeout: Duration,
) -> HostEvent
where
    F: Fn(&cawide_protocol::types::SessionSummary) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        assert!(
            !rem.is_zero(),
            "timed out waiting for SessionUpdated on {session_id}"
        );
        match tokio::time::timeout(rem, rx.recv()).await {
            Ok(Ok(ev @ HostEvent::SessionUpdated { .. })) => {
                if let HostEvent::SessionUpdated { ref summary } = ev {
                    if summary.session_id == session_id && pred(summary) {
                        return ev;
                    }
                }
            }
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => panic!("broadcaster closed"),
            Err(_) => panic!("timed out waiting for SessionUpdated on {session_id}"),
        }
    }
}

struct FakeCodexDaemon {
    socket_path: PathBuf,
    received: Arc<Mutex<Vec<Value>>>,
    outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<String>>>>,
    notify: Arc<Notify>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeCodexDaemon {
    fn start(socket_path: PathBuf, loaded_threads: Vec<String>) -> Self {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<String>>>> =
            Arc::new(Mutex::new(None));
        let notify = Arc::new(Notify::new());

        let rec_srv = Arc::clone(&received);
        let out_srv = Arc::clone(&outbound_tx);
        let notify_srv = Arc::clone(&notify);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let rec = Arc::clone(&rec_srv);
                let out_slot = Arc::clone(&out_srv);
                let n = Arc::clone(&notify_srv);
                let loaded = loaded_threads.clone();
                tokio::spawn(async move {
                    let Ok((_, ws_stream)) = ServerBuilder::new().accept(stream).await else {
                        return;
                    };
                    let (mut write_half, mut read_half) = ws_stream.split();
                    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                    *out_slot.lock() = Some(tx);
                    n.notify_waiters();

                    loop {
                        tokio::select! {
                            inbound = read_half.next() => {
                                match inbound {
                                    Some(Ok(msg)) => {
                                        if let Some(text) = msg.as_text() {
                                            if let Ok(val) = serde_json::from_str::<Value>(text) {
                                                rec.lock().push(val.clone());
                                                n.notify_waiters();
                                                if let (Some(id), Some(method)) = (val.get("id"), val.get("method").and_then(|v| v.as_str())) {
                                                    let result = match method {
                                                        "initialize" | "thread/unsubscribe" => Some(json!({})),
                                                        "thread/loaded/list" => Some(json!({ "data": loaded })),
                                                        "thread/resume" => {
                                                            let tid = val["params"]["threadId"].as_str().unwrap_or("");
                                                            Some(json!({ "thread": { "id": tid, "sessionId": tid } }))
                                                        }
                                                        "thread/read" => {
                                                            let tid = val["params"]["threadId"].as_str().unwrap_or("");
                                                            Some(json!({ "thread": { "id": tid, "sessionId": tid, "status": { "type": "idle" } } }))
                                                        }
                                                        _ => None,
                                                    };
                                                    if let Some(res) = result {
                                                        let resp = json!({ "id": id, "result": res });
                                                        if write_half.send(Message::text(resp.to_string())).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => break,
                                }
                            }
                            out = rx.recv() => {
                                match out {
                                    Some(s) => {
                                        if write_half.send(Message::text(s)).await.is_err() {
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                });
            }
        });

        Self {
            socket_path,
            received,
            outbound_tx,
            notify,
            accept_task,
        }
    }

    fn send_to_client(&self, msg: &Value) {
        if let Some(tx) = self.outbound_tx.lock().as_ref() {
            let _ = tx.send(msg.to_string());
        }
    }

    fn received_snapshot(&self) -> Vec<Value> {
        self.received.lock().clone()
    }

    async fn wait_for_method(&self, method: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            if self
                .received
                .lock()
                .iter()
                .any(|v| v.get("method").and_then(|m| m.as_str()) == Some(method))
            {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(!rem.is_zero(), "timed out waiting for {method}");
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }
}

impl Drop for FakeCodexDaemon {
    fn drop(&mut self) {
        self.accept_task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

struct FakeOcService {
    requested_paths: Arc<Mutex<Vec<String>>>,
    sse_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Value>>>>,
    notify: Arc<Notify>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeOcService {
    async fn start(opencode_state_dir: &Path) -> Self {
        std::fs::create_dir_all(opencode_state_dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pid = u64::from(std::process::id());
        std::fs::write(
            opencode_state_dir.join("service.json"),
            serde_json::to_vec(&json!({
                "id": "srv-fallback",
                "version": "1.0.0",
                "url": format!("http://127.0.0.1:{port}"),
                "pid": pid,
                "password": "pw",
            }))
            .unwrap(),
        )
        .unwrap();

        let requested_paths = Arc::new(Mutex::new(Vec::new()));
        let sse_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Value>>>> = Arc::new(Mutex::new(None));
        let notify = Arc::new(Notify::new());

        let req_srv = Arc::clone(&requested_paths);
        let sse_srv = Arc::clone(&sse_tx);
        let notify_srv = Arc::clone(&notify);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let reqs = Arc::clone(&req_srv);
                let sse_slot = Arc::clone(&sse_srv);
                let n = Arc::clone(&notify_srv);
                tokio::spawn(async move {
                    let _ = handle_oc_http(stream, pid, reqs, sse_slot, n).await;
                });
            }
        });

        Self {
            requested_paths,
            sse_tx,
            notify,
            accept_task,
        }
    }

    fn send_sse(&self, ev: &Value) {
        if let Some(tx) = self.sse_tx.lock().as_ref() {
            let _ = tx.send(ev.clone());
        }
    }

    fn requested_snapshot(&self) -> Vec<String> {
        self.requested_paths.lock().clone()
    }

    async fn wait_for_path(&self, path: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            if self.requested_paths.lock().iter().any(|p| p == path) {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(!rem.is_zero(), "timed out waiting for {path}");
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }
}

impl Drop for FakeOcService {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn handle_oc_http(
    mut stream: TcpStream,
    pid: u64,
    requested_paths: Arc<Mutex<Vec<String>>>,
    sse_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Value>>>>,
    notify: Arc<Notify>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let req_line = header_str.lines().next().unwrap_or("");
    let raw_target = req_line.split_whitespace().nth(1).unwrap_or("/");
    let path = raw_target
        .split_once('?')
        .map_or(raw_target, |(p, _)| p)
        .to_string();

    requested_paths.lock().push(path.clone());
    notify.notify_waiters();

    if path == "/api/event" {
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        stream.write_all(headers.as_bytes()).await?;
        stream.flush().await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
        *sse_tx.lock() = Some(tx);
        while let Some(val) = rx.recv().await {
            let payload = format!("data: {val}\n\n");
            let frame = format!("{:x}\r\n{}\r\n", payload.len(), payload);
            if stream.write_all(frame.as_bytes()).await.is_err() {
                break;
            }
            if stream.flush().await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    let body = if path == "/api/info" {
        serde_json::to_vec(&json!({ "pid": pid, "version": "1.0.0" })).unwrap()
    } else if path == "/api/session/active" {
        serde_json::to_vec(&json!({ "data": {} })).unwrap()
    } else {
        serde_json::to_vec(&json!({ "data": [] })).unwrap()
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_codex_no_daemon_uses_rollout_over_running_daemon() {
    let _guard = TEST_LOCK.lock().await;
    let tmp = short_tempdir();
    let workdir = tmp.path().join("w");
    let bin = tmp.path().join("bin");
    let codex_home = tmp.path().join("c");
    let xdg_state = tmp.path().join("st");
    let xdg_data = tmp.path().join("da");
    let home = tmp.path().join("h");
    let cfg_dir = tmp.path().join("cfg");
    for d in [
        &workdir,
        &codex_home,
        &xdg_state,
        &xdg_data,
        &home,
        &cfg_dir,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_fake_agent(&bin, "codex");

    let _env = EnvGuard::set(&[
        ("CODEX_HOME", &codex_home),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_DATA_HOME", &xdg_data),
        ("HOME", &home),
        ("CAWIDE_CONFIG_DIR", &cfg_dir),
    ]);

    let u_id = "01a211ba-6ad0-7230-8009-0401d46a4790";
    let day_dir = codex_home.join("sessions/2026/11/26");
    std::fs::create_dir_all(&day_dir).unwrap();
    let rollout_path = day_dir.join(format!("rollout-2026-11-26T00-00-00-{u_id}.jsonl"));
    std::fs::write(&rollout_path, "").unwrap();

    let socket_path = codex_home
        .join("app-server-control")
        .join("app-server-control.sock");
    let daemon = FakeCodexDaemon::start(socket_path, vec![u_id.to_string()]);

    let paths = ObserverPaths::from_env().unwrap();
    let broadcaster = Arc::new(HostEventBroadcaster::new(64));
    let mut event_rx = broadcaster.subscribe();
    let (obs_tx, obs_rx) = mpsc::channel(16);
    let registry = Arc::new(
        SessionRegistry::new(workdir, None, vec![], Arc::clone(&broadcaster))
            .with_observer_sender(obs_tx),
    );
    let _probe = SessionProbe::spawn(Arc::clone(&registry), Arc::clone(&broadcaster), None);
    let _hub = ObserverHub::spawn(
        Arc::clone(&registry),
        Arc::clone(&broadcaster),
        paths,
        obs_rx,
    );

    registry
        .create_session(
            "sess-codex-fallback",
            Some(format!("{}/codex --no-daemon resume {u_id}", bin.display())),
            None,
            80,
            24,
        )
        .unwrap();

    // Wait until adapter has connected and polled thread/loaded/list (so rollout baseline seek ran).
    daemon
        .wait_for_method("thread/loaded/list", Duration::from_secs(8))
        .await;
    assert!(
        !daemon
            .received_snapshot()
            .iter()
            .any(|v| v["method"] == "thread/resume" && v["params"]["threadId"] == u_id),
        "rollout-only root must not subscribe via daemon"
    );

    // Append task_started -> Thinking
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&rollout_path)
            .unwrap();
        writeln!(
            f,
            "{}",
            json!({ "type": "event_msg", "payload": { "type": "task_started" } })
        )
        .unwrap();
        f.flush().unwrap();
    }
    wait_session_event(
        &mut event_rx,
        "sess-codex-fallback",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Thinking { .. }))
        },
        Duration::from_secs(5),
    )
    .await;

    // Daemon notification for u_id must be ignored because rollout source wins.
    daemon.send_to_client(&json!({
        "method": "turn/completed",
        "params": { "threadId": u_id, "turn": { "status": "completed" } }
    }));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mid_summary = registry
        .list()
        .into_iter()
        .find(|s| s.session_id == "sess-codex-fallback")
        .unwrap();
    assert!(matches!(
        mid_summary.agent.as_ref().map(|a| &a.status),
        Some(AgentStatus::Thinking { .. })
    ));
    // Append task_complete -> Completed
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&rollout_path)
            .unwrap();
        writeln!(
            f,
            "{}",
            json!({
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "last_agent_message": "rollout done"
                }
            })
        )
        .unwrap();
        f.flush().unwrap();
    }
    let ev_done = wait_session_event(
        &mut event_rx,
        "sess-codex-fallback",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Completed { .. }))
        },
        Duration::from_secs(5),
    )
    .await;
    if let HostEvent::SessionUpdated { summary } = ev_done {
        assert_eq!(
            summary.agent.unwrap().status,
            AgentStatus::Completed {
                summary: "rollout done".into()
            }
        );
    }

    registry.kill_session("sess-codex-fallback").unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_opencode_standalone_uses_db_over_running_service() {
    let _guard = TEST_LOCK.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let workdir = tmp.path().join("work");
    let bin = tmp.path().join("bin");
    let codex_home = tmp.path().join("codex");
    let xdg_state = tmp.path().join("state");
    let xdg_data = tmp.path().join("data");
    let home = tmp.path().join("home");
    let cfg_dir = tmp.path().join("cfg");
    let opencode_state = xdg_state.join("opencode");
    let opencode_data = xdg_data.join("opencode");
    for d in [
        &workdir,
        &codex_home,
        &xdg_state,
        &xdg_data,
        &home,
        &cfg_dir,
        &opencode_state,
        &opencode_data,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_fake_agent(&bin, "opencode");

    let _env = EnvGuard::set(&[
        ("CODEX_HOME", &codex_home),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_DATA_HOME", &xdg_data),
        ("HOME", &home),
        ("CAWIDE_CONFIG_DIR", &cfg_dir),
    ]);

    let db_path = opencode_data.join("opencode.db");
    let db = Connection::open(&db_path).unwrap();
    db.execute_batch(
        "CREATE TABLE session_v2 (
            id TEXT PRIMARY KEY,
            time_busy INTEGER,
            time_idle INTEGER,
            idle_outcome TEXT
        );
        CREATE TABLE session_message (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            type TEXT NOT NULL,
            seq INTEGER NOT NULL,
            data TEXT NOT NULL
        );",
    )
    .unwrap();
    db.execute(
        "INSERT INTO session_v2 (id, time_busy, time_idle, idle_outcome) VALUES ('ses_db', NULL, 100, NULL)",
        [],
    )
    .unwrap();

    let service = FakeOcService::start(&opencode_state).await;

    let paths = ObserverPaths::from_env().unwrap();
    let broadcaster = Arc::new(HostEventBroadcaster::new(64));
    let mut event_rx = broadcaster.subscribe();
    let (obs_tx, obs_rx) = mpsc::channel(16);
    let registry = Arc::new(
        SessionRegistry::new(workdir, None, vec![], Arc::clone(&broadcaster))
            .with_observer_sender(obs_tx),
    );
    let _probe = SessionProbe::spawn(Arc::clone(&registry), Arc::clone(&broadcaster), None);
    let _hub = ObserverHub::spawn(
        Arc::clone(&registry),
        Arc::clone(&broadcaster),
        paths,
        obs_rx,
    );

    registry
        .create_session(
            "sess-opencode-fallback",
            Some(format!("{}/opencode --standalone -s ses_db", bin.display())),
            None,
            80,
            24,
        )
        .unwrap();

    service
        .wait_for_path("/api/event", Duration::from_secs(8))
        .await;
    // Allow tick 0 + tick 1 so OpenCodeDbPoller records the idle baseline for ses_db.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert!(
        !service
            .requested_snapshot()
            .iter()
            .any(|p| p == "/api/session/ses_db"),
        "db-only root must not sync via HTTP service"
    );

    // SSE event for ses_db must be ignored because db source wins.
    service.send_sse(&json!({
        "type": "session.execution.started",
        "data": { "sessionID": "ses_db" }
    }));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let pre_summary = registry
        .list()
        .into_iter()
        .find(|s| s.session_id == "sess-opencode-fallback")
        .unwrap();
    assert!(
        pre_summary
            .agent
            .as_ref()
            .is_none_or(|a| matches!(a.status, AgentStatus::Idle)),
        "SSE must not drive db-only root, got {:?}",
        pre_summary.agent
    );

    // Flip DB to busy -> Thinking
    db.execute(
        "UPDATE session_v2 SET time_busy = 200 WHERE id = 'ses_db'",
        [],
    )
    .unwrap();
    wait_session_event(
        &mut event_rx,
        "sess-opencode-fallback",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Thinking { .. }))
        },
        Duration::from_secs(5),
    )
    .await;

    // Insert assistant message and flip DB to idle succeeded -> Completed
    db.execute(
        "INSERT INTO session_message (id, session_id, type, seq, data) VALUES ('m1', 'ses_db', 'assistant', 1, ?1)",
        [json!({ "content": [{ "type": "text", "text": "db done" }] }).to_string()],
    )
    .unwrap();
    db.execute(
        "UPDATE session_v2 SET time_idle = 300, idle_outcome = 'succeeded' WHERE id = 'ses_db'",
        [],
    )
    .unwrap();
    let ev_done = wait_session_event(
        &mut event_rx,
        "sess-opencode-fallback",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Completed { .. }))
        },
        Duration::from_secs(5),
    )
    .await;
    if let HostEvent::SessionUpdated { summary } = ev_done {
        assert_eq!(
            summary.agent.unwrap().status,
            AgentStatus::Completed {
                summary: "db done".into()
            }
        );
    }

    registry.kill_session("sess-opencode-fallback").unwrap();
}
