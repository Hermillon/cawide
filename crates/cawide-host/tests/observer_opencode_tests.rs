#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cawide_host::agent::observe::{ObserverHub, ObserverPaths};
use cawide_host::agent::respond::respond_to_session;
use cawide_host::net::broadcaster::HostEventBroadcaster;
use cawide_host::net::probe::SessionProbe;
use cawide_host::net::registry::SessionRegistry;
use cawide_host::push::{AgentAlert, AgentAlertKind};
use cawide_protocol::types::{AgentChoice, AgentStatus, HostEvent};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Notify};

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

fn write_fake_opencode(bin_dir: &Path) {
    std::fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join("opencode");
    std::fs::write(&path, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

enum SseAction {
    Event(Value),
    Drop,
}

struct FakeOcState {
    pid: u64,
    active_sessions: serde_json::Map<String, Value>,
    session_outcomes: HashMap<String, String>,
    permissions: HashMap<String, Vec<Value>>,
    forms: HashMap<String, Vec<Value>>,
    prepared_counter: u64,
    captured_permission_replies: Vec<(String, String, Value)>,
    requested_paths: Vec<(String, String)>,
    sse_tx: Option<mpsc::UnboundedSender<SseAction>>,
}

struct FakeOpenCodeServer {
    state: Arc<Mutex<FakeOcState>>,
    notify: Arc<Notify>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeOpenCodeServer {
    async fn start(opencode_state_dir: &Path) -> Self {
        std::fs::create_dir_all(opencode_state_dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pid = u64::from(std::process::id());
        let password = "test-opencode-password".to_string();

        let service_json = json!({
            "id": "srv-test",
            "version": "1.0.0",
            "url": format!("http://127.0.0.1:{port}"),
            "pid": pid,
            "password": password,
        });
        std::fs::write(
            opencode_state_dir.join("service.json"),
            serde_json::to_vec(&service_json).unwrap(),
        )
        .unwrap();

        let state = Arc::new(Mutex::new(FakeOcState {
            pid,
            active_sessions: serde_json::Map::new(),
            session_outcomes: HashMap::new(),
            permissions: HashMap::new(),
            forms: HashMap::new(),
            prepared_counter: 0,
            captured_permission_replies: Vec::new(),
            requested_paths: Vec::new(),
            sse_tx: None,
        }));
        let notify = Arc::new(Notify::new());

        let state_srv = Arc::clone(&state);
        let notify_srv = Arc::clone(&notify);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let st = Arc::clone(&state_srv);
                let n = Arc::clone(&notify_srv);
                tokio::spawn(async move {
                    let _ = handle_http_conn(stream, st, n).await;
                });
            }
        });

        Self {
            state,
            notify,
            accept_task,
        }
    }

    fn send_sse(&self, ev: &Value) {
        let tx = self
            .state
            .lock()
            .sse_tx
            .as_ref()
            .expect("no active SSE connection")
            .clone();
        tx.send(SseAction::Event(ev.clone())).unwrap();
    }

    fn drop_sse(&self) {
        let mut st = self.state.lock();
        if let Some(tx) = st.sse_tx.take() {
            let _ = tx.send(SseAction::Drop);
        }
    }

    fn set_active(&self, sid: &str, active: bool) {
        let mut st = self.state.lock();
        if active {
            st.active_sessions.insert(sid.to_string(), json!({}));
        } else {
            st.active_sessions.remove(sid);
        }
    }

    fn set_outcome(&self, sid: &str, outcome: &str) {
        self.state
            .lock()
            .session_outcomes
            .insert(sid.to_string(), outcome.to_string());
    }

    fn captured_replies(&self) -> Vec<(String, String, Value)> {
        self.state.lock().captured_permission_replies.clone()
    }

    async fn wait_for_request(&self, method: &str, path: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            if self
                .state
                .lock()
                .requested_paths
                .iter()
                .any(|(m, p)| m == method && p == path)
            {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(!rem.is_zero(), "timed out waiting for HTTP {method} {path}");
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }

    async fn wait_for_reply_count(&self, count: usize, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            if self.state.lock().captured_permission_replies.len() >= count {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(!rem.is_zero(), "timed out waiting for permission reply");
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }
}

impl Drop for FakeOpenCodeServer {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.drop_sse();
    }
}

async fn handle_http_conn(
    mut stream: TcpStream,
    state: Arc<Mutex<FakeOcState>>,
    notify: Arc<Notify>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
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
    let mut lines = header_str.lines();
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target
        .split_once('?')
        .map_or(raw_target, |(p, _)| p)
        .to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = val.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    if method == "GET" && path == "/api/event" {
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        stream.write_all(headers.as_bytes()).await?;
        stream.flush().await?;

        let (tx, mut rx) = mpsc::unbounded_channel::<SseAction>();
        {
            let mut st = state.lock();
            st.requested_paths.push((method, path));
            if let Some(prev) = st.sse_tx.take() {
                let _ = prev.send(SseAction::Drop);
            }
            st.sse_tx = Some(tx.clone());
        }
        notify.notify_waiters();

        while let Some(action) = rx.recv().await {
            match action {
                SseAction::Event(val) => {
                    let payload = format!("data: {val}\n\n");
                    let frame = format!("{:x}\r\n{}\r\n", payload.len(), payload);
                    if stream.write_all(frame.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream.flush().await.is_err() {
                        break;
                    }
                }
                SseAction::Drop => break,
            }
        }

        let mut st = state.lock();
        if st.sse_tx.as_ref().is_some_and(|cur| cur.same_channel(&tx)) {
            st.sse_tx = None;
        }
        return Ok(());
    }

    let (status_line, resp_body): (&str, Option<Vec<u8>>) = {
        let mut st = state.lock();
        st.requested_paths.push((method.clone(), path.clone()));

        if method == "GET" && path == "/api/info" {
            (
                "200 OK",
                Some(serde_json::to_vec(&json!({ "pid": st.pid, "version": "1.0.0" })).unwrap()),
            )
        } else if method == "GET" && path == "/api/session/active" {
            (
                "200 OK",
                Some(serde_json::to_vec(&json!({ "data": st.active_sessions })).unwrap()),
            )
        } else if method == "POST" && path == "/api/session" {
            st.prepared_counter += 1;
            let id = format!("ses_prep_{}", st.prepared_counter);
            (
                "200 OK",
                Some(serde_json::to_vec(&json!({ "data": { "id": id } })).unwrap()),
            )
        } else if let Some(rest) = path.strip_prefix("/api/session/") {
            let segs: Vec<&str> = rest.split('/').collect();
            match (method.as_str(), segs.as_slice()) {
                ("GET", [sid]) => {
                    let mut data = json!({ "id": sid });
                    if let Some(outcome) = st.session_outcomes.get(*sid) {
                        data["outcome"] = json!(outcome);
                    }
                    (
                        "200 OK",
                        Some(serde_json::to_vec(&json!({ "data": data })).unwrap()),
                    )
                }
                ("GET", [sid, "permission"]) => {
                    let list = st.permissions.get(*sid).cloned().unwrap_or_default();
                    (
                        "200 OK",
                        Some(serde_json::to_vec(&json!({ "data": list })).unwrap()),
                    )
                }
                ("GET", [sid, "form"]) => {
                    let list = st.forms.get(*sid).cloned().unwrap_or_default();
                    (
                        "200 OK",
                        Some(serde_json::to_vec(&json!({ "data": list })).unwrap()),
                    )
                }
                ("POST", [sid, "permission", rid, "reply"]) => {
                    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    st.captured_permission_replies.push((
                        (*sid).to_string(),
                        (*rid).to_string(),
                        parsed,
                    ));
                    ("204 No Content", None)
                }
                ("POST", [_sid, "form", _fid, "reply"]) => ("204 No Content", None),
                _ => ("404 Not Found", Some(b"{\"error\":\"not found\"}".to_vec())),
            }
        } else {
            ("404 Not Found", Some(b"{\"error\":\"not found\"}".to_vec()))
        }
    };
    notify.notify_waiters();

    match resp_body {
        Some(bytes) => {
            let head = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(&bytes).await?;
        }
        None => {
            let head = format!("HTTP/1.1 {status_line}\r\nConnection: close\r\n\r\n");
            stream.write_all(head.as_bytes()).await?;
        }
    }
    stream.flush().await
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

async fn wait_alert<F>(
    rx: &mut mpsc::Receiver<AgentAlert>,
    pred: F,
    timeout: Duration,
) -> AgentAlert
where
    F: Fn(&AgentAlert) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        assert!(!rem.is_zero(), "timed out waiting for AgentAlert");
        match tokio::time::timeout(rem, rx.recv()).await {
            Ok(Some(alert)) => {
                if pred(&alert) {
                    return alert;
                }
            }
            Ok(None) => panic!("alert channel closed"),
            Err(_) => panic!("timed out waiting for AgentAlert"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_opencode_observer_lifecycle_and_sse_drop_recovery() {
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
    for d in [
        &workdir,
        &codex_home,
        &xdg_state,
        &xdg_data,
        &home,
        &cfg_dir,
        &opencode_state,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_fake_opencode(&bin);

    let _env = EnvGuard::set(&[
        ("CODEX_HOME", &codex_home),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_DATA_HOME", &xdg_data),
        ("HOME", &home),
        ("CAWIDE_CONFIG_DIR", &cfg_dir),
    ]);

    let server = FakeOpenCodeServer::start(&opencode_state).await;

    let paths = ObserverPaths::from_env().unwrap();
    let broadcaster = Arc::new(HostEventBroadcaster::new(64));
    let mut event_rx = broadcaster.subscribe();
    let (alert_tx, mut alert_rx) = mpsc::channel(64);
    let (activity_tx, _activity_rx) = mpsc::channel(128);
    let (obs_tx, obs_rx) = mpsc::channel(16);

    let registry = Arc::new(
        SessionRegistry::new(workdir.clone(), None, vec![], Arc::clone(&broadcaster))
            .with_alert_sender(alert_tx)
            .with_activity_sender(activity_tx)
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
            "sess-opencode",
            Some(format!("{}/opencode -s ses_test", bin.display())),
            None,
            80,
            24,
        )
        .unwrap();

    server
        .wait_for_request("GET", "/api/session/ses_test/form", Duration::from_secs(8))
        .await;

    // 1. start -> Thinking
    server.set_active("ses_test", true);
    server.send_sse(&json!({
        "type": "session.execution.started",
        "data": { "sessionID": "ses_test" }
    }));
    wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Thinking { .. }))
        },
        Duration::from_secs(5),
    )
    .await;

    // 2. permission.asked -> NeedsApproval
    server.send_sse(&json!({
        "type": "permission.asked",
        "data": {
            "id": "per_1",
            "sessionID": "ses_test",
            "action": "bash",
            "resources": ["rm -rf /tmp/x"]
        }
    }));
    wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::WaitingForInput { .. }))
        },
        Duration::from_secs(5),
    )
    .await;
    wait_alert(
        &mut alert_rx,
        |a| a.session_id == "sess-opencode" && a.kind == AgentAlertKind::NeedsApproval,
        Duration::from_secs(5),
    )
    .await;

    // 3. respond Option 1 -> {"decision":"reject"} captured
    respond_to_session(
        &registry,
        "sess-opencode",
        0,
        "bash: rm -rf /tmp/x",
        AgentChoice::Option { index: 1 },
    )
    .await
    .unwrap();
    server.wait_for_reply_count(1, Duration::from_secs(5)).await;
    let replies = server.captured_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].0, "ses_test");
    assert_eq!(replies[0].1, "per_1");
    assert_eq!(replies[0].2, json!({ "decision": "reject" }));

    // 4. text.ended "ok" + session.execution.succeeded -> Completed{"ok"}
    server.set_active("ses_test", false);
    server.send_sse(&json!({
        "type": "session.text.ended",
        "data": { "sessionID": "ses_test", "text": "ok" }
    }));
    server.send_sse(&json!({
        "type": "session.execution.succeeded",
        "data": { "sessionID": "ses_test" }
    }));
    let ev_ok = wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Completed { .. }))
        },
        Duration::from_secs(5),
    )
    .await;
    if let HostEvent::SessionUpdated { summary } = ev_ok {
        assert_eq!(
            summary.agent.unwrap().status,
            AgentStatus::Completed {
                summary: "ok".into()
            }
        );
    }
    wait_alert(
        &mut alert_rx,
        |a| a.session_id == "sess-opencode" && a.kind == AgentAlertKind::Finished,
        Duration::from_secs(5),
    )
    .await;

    // 5. next start + failed {error:{message:"rate limit"}} -> Completed{"Error: rate limit"} + Failed alert
    server.set_active("ses_test", true);
    server.send_sse(&json!({
        "type": "session.execution.started",
        "data": { "sessionID": "ses_test" }
    }));
    wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Thinking { .. }))
        },
        Duration::from_secs(5),
    )
    .await;

    server.set_active("ses_test", false);
    server.send_sse(&json!({
        "type": "session.execution.failed",
        "data": {
            "sessionID": "ses_test",
            "error": { "message": "rate limit" }
        }
    }));
    let ev_fail = wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Completed { .. }))
        },
        Duration::from_secs(5),
    )
    .await;
    if let HostEvent::SessionUpdated { summary } = ev_fail {
        assert_eq!(
            summary.agent.unwrap().status,
            AgentStatus::Completed {
                summary: "Error: rate limit".into()
            }
        );
    }
    wait_alert(
        &mut alert_rx,
        |a| a.session_id == "sess-opencode" && a.kind == AgentAlertKind::Failed,
        Duration::from_secs(5),
    )
    .await;

    // 6. SSE drop mid-turn then /api/session/{sid} with outcome: "succeeded" -> Completed
    server.set_active("ses_test", true);
    server.send_sse(&json!({
        "type": "session.execution.started",
        "data": { "sessionID": "ses_test" }
    }));
    wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Thinking { .. }))
        },
        Duration::from_secs(5),
    )
    .await;

    server.set_active("ses_test", false);
    server.set_outcome("ses_test", "succeeded");
    server.drop_sse();

    wait_session_event(
        &mut event_rx,
        "sess-opencode",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Completed { .. }))
        },
        Duration::from_secs(8),
    )
    .await;

    // Verify POST /api/session handler via observer_prepare
    let prepared = registry
        .observer_prepare("opencode", workdir)
        .await
        .unwrap();
    assert_eq!(prepared, "ses_prep_1");

    registry.kill_session("sess-opencode").unwrap();
}
