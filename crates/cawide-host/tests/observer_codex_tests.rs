#![cfg(unix)]

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cawide_host::agent::observe::{ObserverHub, ObserverPaths};
use cawide_host::agent::respond::respond_to_session;
use cawide_host::net::broadcaster::HostEventBroadcaster;
use cawide_host::net::probe::SessionProbe;
use cawide_host::net::registry::SessionRegistry;
use cawide_host::push::{
    ActivityEventKind, ActivityPhase, ActivityUpdateEvent, AgentAlert, AgentAlertKind,
};
use cawide_protocol::types::{AgentChoice, AgentStatus, HostEvent};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::net::UnixListener;
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

fn write_fake_codex(bin_dir: &Path) {
    std::fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join("codex");
    std::fs::write(&path, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

enum DaemonOut {
    Text(String),
    Close,
}

struct FakeDaemonState {
    loaded_threads: Vec<String>,
    thread_status: String,
    prepared_ids: VecDeque<String>,
    received: Vec<Value>,
    outbound_tx: Option<mpsc::UnboundedSender<DaemonOut>>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

struct FakeCodexDaemon {
    socket_path: PathBuf,
    state: Arc<Mutex<FakeDaemonState>>,
    notify: Arc<Notify>,
}

impl FakeCodexDaemon {
    fn new(socket_path: PathBuf, loaded_threads: Vec<String>, prepared_ids: Vec<String>) -> Self {
        Self {
            socket_path,
            state: Arc::new(Mutex::new(FakeDaemonState {
                loaded_threads,
                thread_status: "idle".to_string(),
                prepared_ids: prepared_ids.into(),
                received: Vec::new(),
                outbound_tx: None,
                accept_task: None,
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    fn start_accepting(&self) {
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path).unwrap();
        let state = Arc::clone(&self.state);
        let notify = Arc::clone(&self.notify);

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state_conn = Arc::clone(&state);
                let notify_conn = Arc::clone(&notify);
                tokio::spawn(async move {
                    let Ok((_, ws_stream)) = ServerBuilder::new().accept(stream).await else {
                        return;
                    };
                    let (mut write_half, mut read_half) = ws_stream.split();
                    let (tx, mut rx) = mpsc::unbounded_channel::<DaemonOut>();
                    {
                        let mut st = state_conn.lock();
                        if let Some(prev) = st.outbound_tx.take() {
                            let _ = prev.send(DaemonOut::Close);
                        }
                        st.outbound_tx = Some(tx.clone());
                    }
                    notify_conn.notify_waiters();

                    loop {
                        tokio::select! {
                            inbound = read_half.next() => {
                                match inbound {
                                    Some(Ok(msg)) => {
                                        if let Some(text) = msg.as_text() {
                                            if let Ok(val) = serde_json::from_str::<Value>(text) {
                                                let reply = {
                                                    let mut st = state_conn.lock();
                                                    st.received.push(val.clone());
                                                    build_auto_reply(&val, &mut st)
                                                };
                                                notify_conn.notify_waiters();
                                                if let Some(resp) = reply {
                                                    if write_half.send(Message::text(resp.to_string())).await.is_err() {
                                                        break;
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
                                    Some(DaemonOut::Text(s)) => {
                                        if write_half.send(Message::text(s)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(DaemonOut::Close) | None => break,
                                }
                            }
                        }
                    }

                    let mut st = state_conn.lock();
                    if st
                        .outbound_tx
                        .as_ref()
                        .is_some_and(|cur| cur.same_channel(&tx))
                    {
                        st.outbound_tx = None;
                    }
                });
            }
        });

        let mut st = self.state.lock();
        if let Some(prev) = st.accept_task.replace(task) {
            prev.abort();
        }
    }

    fn drop_active_connection(&self) {
        let mut st = self.state.lock();
        if let Some(tx) = st.outbound_tx.take() {
            let _ = tx.send(DaemonOut::Close);
        }
    }

    fn stop_accepting(&self) {
        let mut st = self.state.lock();
        if let Some(task) = st.accept_task.take() {
            task.abort();
        }
        if let Some(tx) = st.outbound_tx.take() {
            let _ = tx.send(DaemonOut::Close);
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }

    fn send_to_client(&self, msg: &Value) {
        let tx = self
            .state
            .lock()
            .outbound_tx
            .as_ref()
            .expect("no active daemon connection")
            .clone();
        tx.send(DaemonOut::Text(msg.to_string())).unwrap();
    }

    fn msg_count(&self) -> usize {
        self.state.lock().received.len()
    }

    async fn wait_for_msg<F>(&self, from_idx: usize, pred: F, timeout: Duration) -> Value
    where
        F: Fn(&Value) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            if let Some(found) = self.state.lock().received[from_idx..]
                .iter()
                .find(|v| pred(v))
                .cloned()
            {
                return found;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(!rem.is_zero(), "timed out waiting for daemon message");
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }
}

impl Drop for FakeCodexDaemon {
    fn drop(&mut self) {
        self.stop_accepting();
    }
}

fn build_auto_reply(val: &Value, st: &mut FakeDaemonState) -> Option<Value> {
    let id = val.get("id")?.clone();
    let method = val.get("method").and_then(|v| v.as_str())?;
    let params = val.get("params").unwrap_or(&Value::Null);
    let result = match method {
        "initialize" | "thread/name/set" | "thread/unsubscribe" => json!({}),
        "thread/loaded/list" => json!({ "data": st.loaded_threads }),
        "thread/resume" => {
            let tid = params
                .get("threadId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            json!({ "thread": { "id": tid, "sessionId": tid } })
        }
        "thread/read" => {
            let tid = params
                .get("threadId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            json!({
                "thread": {
                    "id": tid,
                    "sessionId": tid,
                    "status": { "type": st.thread_status }
                }
            })
        }
        "thread/turns/list" => json!({ "data": [] }),
        "thread/start" => {
            let tid = st
                .prepared_ids
                .pop_front()
                .unwrap_or_else(|| "01a211ba-6ad0-7230-8009-0401d46a9999".to_string());
            if !st.loaded_threads.contains(&tid) {
                st.loaded_threads.push(tid.clone());
            }
            json!({ "thread": { "id": tid } })
        }
        _ => return None,
    };
    Some(json!({ "id": id, "result": result }))
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

async fn wait_activity<F>(
    rx: &mut mpsc::Receiver<ActivityUpdateEvent>,
    pred: F,
    timeout: Duration,
) -> ActivityUpdateEvent
where
    F: Fn(&ActivityUpdateEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        assert!(!rem.is_zero(), "timed out waiting for ActivityUpdateEvent");
        match tokio::time::timeout(rem, rx.recv()).await {
            Ok(Some(act)) => {
                if pred(&act) {
                    return act;
                }
            }
            Ok(None) => panic!("activity channel closed"),
            Err(_) => panic!("timed out waiting for ActivityUpdateEvent"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_codex_observer_lifecycle_reconnect_and_unsubscribe() {
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
    write_fake_codex(&bin);

    let _env = EnvGuard::set(&[
        ("CODEX_HOME", &codex_home),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_DATA_HOME", &xdg_data),
        ("HOME", &home),
        ("CAWIDE_CONFIG_DIR", &cfg_dir),
    ]);

    let u_id = "01a211ba-6ad0-7230-8009-0401d46a4787";
    let socket_path = codex_home
        .join("app-server-control")
        .join("app-server-control.sock");
    let daemon = FakeCodexDaemon::new(socket_path, vec![u_id.to_string()], vec![]);
    daemon.start_accepting();

    let paths = ObserverPaths::from_env().unwrap();
    let broadcaster = Arc::new(HostEventBroadcaster::new(64));
    let mut event_rx = broadcaster.subscribe();
    let (alert_tx, mut alert_rx) = mpsc::channel(64);
    let (activity_tx, mut activity_rx) = mpsc::channel(128);
    let (obs_tx, obs_rx) = mpsc::channel(16);

    let registry = Arc::new(
        SessionRegistry::new(workdir, None, vec![], Arc::clone(&broadcaster))
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
            "sess-codex",
            Some(format!("{}/codex resume {u_id}", bin.display())),
            None,
            80,
            24,
        )
        .unwrap();

    daemon
        .wait_for_msg(
            0,
            |v| v["method"] == "thread/read" && v["params"]["threadId"] == u_id,
            Duration::from_secs(8),
        )
        .await;

    // 1. turn/started -> Thinking
    daemon.send_to_client(&json!({
        "method": "turn/started",
        "params": { "threadId": u_id }
    }));
    wait_session_event(
        &mut event_rx,
        "sess-codex",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::Thinking { .. }))
        },
        Duration::from_secs(5),
    )
    .await;

    // 2. approval id 7 `rm -rf build` -> WaitingForInput + 1 NeedsApproval alert + Waiting phase
    daemon.send_to_client(&json!({
        "id": 7,
        "method": "item/commandExecution/requestApproval",
        "params": {
            "threadId": u_id,
            "command": "rm -rf build",
            "kind": "command"
        }
    }));
    let ev_wait = wait_session_event(
        &mut event_rx,
        "sess-codex",
        |s| {
            s.agent
                .as_ref()
                .is_some_and(|a| matches!(a.status, AgentStatus::WaitingForInput { .. }))
        },
        Duration::from_secs(5),
    )
    .await;
    if let HostEvent::SessionUpdated { summary } = ev_wait {
        match summary.agent.unwrap().status {
            AgentStatus::WaitingForInput { prompt, options } => {
                assert_eq!(prompt, "Run: rm -rf build");
                assert_eq!(options.len(), 3);
            }
            other => panic!("expected WaitingForInput, got {other:?}"),
        }
    }
    let alert1 = wait_alert(
        &mut alert_rx,
        |a| a.session_id == "sess-codex" && a.kind == AgentAlertKind::NeedsApproval,
        Duration::from_secs(5),
    )
    .await;
    assert!(alert1.detail.actionable);
    let mut needs_approval_alerts = 1usize;
    while let Ok(extra) = alert_rx.try_recv() {
        if extra.kind == AgentAlertKind::NeedsApproval {
            needs_approval_alerts += 1;
        }
    }
    assert_eq!(needs_approval_alerts, 1);

    wait_activity(
        &mut activity_rx,
        |a| {
            a.session_id == "sess-codex"
                && a.phase == ActivityPhase::Waiting
                && a.event == ActivityEventKind::Update
        },
        Duration::from_secs(5),
    )
    .await;

    // 3. socket closed and reopened within 3 s -> no state change, still 1 alert
    let mark = daemon.msg_count();
    let closed_at = Instant::now();
    daemon.drop_active_connection();
    daemon
        .wait_for_msg(
            mark,
            |v| v["method"] == "thread/read" && v["params"]["threadId"] == u_id,
            Duration::from_secs(5),
        )
        .await;
    assert!(
        closed_at.elapsed() < Duration::from_secs(3),
        "reconnect took {:?}",
        closed_at.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let snap_reopen = registry.respond_snapshot("sess-codex").unwrap();
    assert!(matches!(
        snap_reopen.agent_state.as_ref().map(|a| &a.status),
        Some(AgentStatus::WaitingForInput { prompt, options })
            if prompt == "Run: rm -rf build" && options.len() == 3
    ));
    assert!(snap_reopen
        .head_attention
        .as_ref()
        .is_some_and(|h| h.actionable));
    while let Ok(extra) = alert_rx.try_recv() {
        if extra.kind == AgentAlertKind::NeedsApproval {
            needs_approval_alerts += 1;
        }
    }
    assert_eq!(needs_approval_alerts, 1);

    // 4. socket closed for 11 s -> same key re-emitted with actionable: false and no new alert
    let expected_key = format!("obs:codex:{u_id}:7");
    let down_at = Instant::now();
    daemon.stop_accepting();
    wait_session_event(
        &mut event_rx,
        "sess-codex",
        |_| {
            registry
                .respond_snapshot("sess-codex")
                .and_then(|s| s.head_attention)
                .is_some_and(|h| h.key.as_deref() == Some(expected_key.as_str()) && !h.actionable)
        },
        Duration::from_secs(14),
    )
    .await;
    if let Some(rem) = Duration::from_secs(11).checked_sub(down_at.elapsed()) {
        tokio::time::sleep(rem).await;
    }
    let snap_down = registry.respond_snapshot("sess-codex").unwrap();
    let head_down = snap_down.head_attention.unwrap();
    assert_eq!(head_down.key.as_deref(), Some(expected_key.as_str()));
    assert!(!head_down.actionable);
    while let Ok(extra) = alert_rx.try_recv() {
        if extra.kind == AgentAlertKind::NeedsApproval {
            needs_approval_alerts += 1;
        }
    }
    assert_eq!(needs_approval_alerts, 1);

    // 5. reopen + replay -> actionable again, total NeedsApproval alerts == 2
    let mark = daemon.msg_count();
    daemon.start_accepting();
    daemon
        .wait_for_msg(
            mark,
            |v| v["method"] == "thread/resume" && v["params"]["threadId"] == u_id,
            Duration::from_secs(6),
        )
        .await;
    daemon.send_to_client(&json!({
        "id": 7,
        "method": "item/commandExecution/requestApproval",
        "params": {
            "threadId": u_id,
            "command": "rm -rf build",
            "kind": "command"
        }
    }));
    let alert2 = wait_alert(
        &mut alert_rx,
        |a| a.session_id == "sess-codex" && a.kind == AgentAlertKind::NeedsApproval,
        Duration::from_secs(5),
    )
    .await;
    assert!(alert2.detail.actionable);
    needs_approval_alerts += 1;
    assert_eq!(needs_approval_alerts, 2);
    assert!(
        registry
            .respond_snapshot("sess-codex")
            .unwrap()
            .head_attention
            .unwrap()
            .actionable
    );

    // 6. respond_to_session with Option 0 -> fake daemon receives {"id":7,"result":{"decision":"accept"}}
    let mark = daemon.msg_count();
    respond_to_session(
        &registry,
        "sess-codex",
        0,
        "Run: rm -rf build",
        AgentChoice::Option { index: 0 },
    )
    .await
    .unwrap();
    let reply_msg = daemon
        .wait_for_msg(
            mark,
            |v| v.get("id") == Some(&json!(7)) && v.get("result").is_some(),
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(reply_msg["result"], json!({ "decision": "accept" }));

    // 7. agentMessage "done" + turn/completed -> Completed{"done"} + Finished alert + Done phase
    daemon.send_to_client(&json!({
        "method": "item/completed",
        "params": {
            "threadId": u_id,
            "item": { "type": "agentMessage", "text": "done" }
        }
    }));
    daemon.send_to_client(&json!({
        "method": "turn/completed",
        "params": {
            "threadId": u_id,
            "turn": { "status": "completed" }
        }
    }));
    let ev_done = wait_session_event(
        &mut event_rx,
        "sess-codex",
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
                summary: "done".into()
            }
        );
    }
    wait_alert(
        &mut alert_rx,
        |a| a.session_id == "sess-codex" && a.kind == AgentAlertKind::Finished,
        Duration::from_secs(5),
    )
    .await;
    wait_activity(
        &mut activity_rx,
        |a| {
            a.session_id == "sess-codex"
                && a.phase == ActivityPhase::Done
                && a.event == ActivityEventKind::End
        },
        Duration::from_secs(5),
    )
    .await;

    // 8. unverified fake codex (<dir>/codex without resume <uuid>) -> no observer status
    registry
        .create_session(
            "sess-unverified",
            Some(format!("{}/codex", bin.display())),
            None,
            80,
            24,
        )
        .unwrap();
    let cand_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if registry
            .observer_candidates("codex")
            .iter()
            .any(|c| c.session_id == "sess-unverified")
        {
            break;
        }
        assert!(
            Instant::now() < cand_deadline,
            "probe did not detect sess-unverified"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let unverified_summary = registry
        .list()
        .into_iter()
        .find(|s| s.session_id == "sess-unverified")
        .unwrap();
    assert!(
        unverified_summary
            .agent
            .as_ref()
            .is_none_or(|a| matches!(a.status, AgentStatus::Idle)),
        "unverified codex must have no observer status, got {:?}",
        unverified_summary.agent
    );

    // 9. kill verified session -> thread/unsubscribe received for u_id
    let mark = daemon.msg_count();
    registry.kill_session("sess-codex").unwrap();
    let unsub = daemon
        .wait_for_msg(
            mark,
            |v| v["method"] == "thread/unsubscribe" && v["params"]["threadId"] == u_id,
            Duration::from_secs(6),
        )
        .await;
    assert_eq!(unsub["params"]["threadId"], u_id);

    registry.kill_session("sess-unverified").unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_codex_observer_prepare_queued_and_connected() {
    let _guard = TEST_LOCK.lock().await;
    let tmp = short_tempdir();
    let workdir = tmp.path().join("w");
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

    let _env = EnvGuard::set(&[
        ("CODEX_HOME", &codex_home),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_DATA_HOME", &xdg_data),
        ("HOME", &home),
        ("CAWIDE_CONFIG_DIR", &cfg_dir),
    ]);

    let uuid2 = "01a211ba-6ad0-7230-8009-0401d46a4788";
    let uuid3 = "01a211ba-6ad0-7230-8009-0401d46a4789";
    let socket_path = codex_home
        .join("app-server-control")
        .join("app-server-control.sock");
    let daemon = FakeCodexDaemon::new(
        socket_path,
        vec![],
        vec![uuid2.to_string(), uuid3.to_string()],
    );

    let paths = ObserverPaths::from_env().unwrap();
    let broadcaster = Arc::new(HostEventBroadcaster::new(64));
    let (obs_tx, obs_rx) = mpsc::channel(16);
    let registry = Arc::new(
        SessionRegistry::new(workdir.clone(), None, vec![], Arc::clone(&broadcaster))
            .with_observer_sender(obs_tx),
    );
    let _hub = ObserverHub::spawn(
        Arc::clone(&registry),
        Arc::clone(&broadcaster),
        paths,
        obs_rx,
    );

    // Queue prepare BEFORE socket accepts.
    let prep_handle = tokio::spawn({
        let reg = Arc::clone(&registry);
        let cwd = workdir.clone();
        async move { reg.observer_prepare("codex", cwd).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    daemon.start_accepting();
    let prepared1 = tokio::time::timeout(Duration::from_secs(8), prep_handle)
        .await
        .expect("queued observer_prepare timed out")
        .unwrap()
        .unwrap();
    assert_eq!(prepared1, uuid2);

    let name_set1 = daemon
        .wait_for_msg(
            0,
            |v| v["method"] == "thread/name/set" && v["params"]["threadId"] == uuid2,
            Duration::from_secs(3),
        )
        .await;
    assert_eq!(name_set1["params"]["name"], "cawide");

    // Prepare while already connected.
    let mark = daemon.msg_count();
    let prepared2 = registry.observer_prepare("codex", workdir).await.unwrap();
    assert_eq!(prepared2, uuid3);
    let name_set2 = daemon
        .wait_for_msg(
            mark,
            |v| v["method"] == "thread/name/set" && v["params"]["threadId"] == uuid3,
            Duration::from_secs(3),
        )
        .await;
    assert_eq!(name_set2["params"]["name"], "cawide");
}
