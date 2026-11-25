#![cfg(unix)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cawide_host::net::ipc::serve_ipc;
use cawide_host::net::{
    bind_ipc_listener, CawideServer, CawideServerConfig, HostEventBroadcaster, IpcContext,
    NetworkMode, SessionRegistry,
};
use cawide_host::push::{ActivityEventKind, ActivityPhase, AgentAlertKind, PushService};
use cawide_protocol::types::{
    AgentChoice, AgentState, AgentStatus, HostEvent, RpcRequest, RpcResponse,
};
use cawide_protocol::{
    read_control_message, read_pty_attach_ack, read_rpc_response, write_control_message,
    write_pty_attach_header, write_rpc_request, ControlMessage, PtyAttachAck, PtyAttachHeader,
    StreamPurpose,
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::Endpoint;

use super::common::{authorized_client, open, within};
use super::next_event_matching;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/claude");

fn read_fixture_json(rel: &str) -> serde_json::Value {
    let path = format!("{FIXTURES_DIR}/{rel}");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"))
}

fn read_transcript_lines(rel: &str) -> Vec<String> {
    let path = format!("{FIXTURES_DIR}/{rel}");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read transcript {path}: {e}"))
        .lines()
        .map(str::to_string)
        .collect()
}

struct ClaudeHarness {
    _tmp: tempfile::TempDir,
    server: CawideServer,
    _ep: Endpoint,
    _conn: Connection,
    _csend: SendStream,
    crecv: RecvStream,
    psend: SendStream,
    _precv: RecvStream,
    rsend: SendStream,
    rrecv: RecvStream,
    req_id: u32,
    session_id: String,
    claude_session_id: String,
    transcript_path: PathBuf,
}

impl ClaudeHarness {
    async fn new(session_id: &str, launch_cmd: &str, wait_ready: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("conf");
        let workdir = tmp.path().join("workdir");
        let upload_dir = tmp.path().join("uploads");
        std::fs::create_dir_all(&workdir).unwrap();
        let transcript_path = tmp.path().join("transcript.jsonl");
        std::fs::write(&transcript_path, "").unwrap();

        let config = CawideServerConfig {
            config_dir,
            network_mode: NetworkMode::LocalOnly,
            workdir,
            launch_cmd: Some(launch_cmd.to_string()),
            upload_dir: Some(upload_dir),
            opener: None,
            watch_workspace: false,
            port: None,
            external_addr: None,
            relay_url: None,
            forge: cawide_host::forge::ForgeHostConfig::default(),
            git_env: Vec::new(),
        };

        let server = within(CawideServer::bind(config)).await.unwrap();
        let (ep, conn) = authorized_client(&server).await;

        let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
        within(write_control_message(
            &mut csend,
            &ControlMessage::Ping { client_ts: 1 },
        ))
        .await
        .unwrap();
        match within(read_control_message(&mut crecv)).await.unwrap() {
            Some(ControlMessage::Pong { client_ts: 1, .. }) => {}
            other => panic!("expected Pong, got {other:?}"),
        }

        let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
        within(write_pty_attach_header(
            &mut psend,
            &PtyAttachHeader::new(session_id, 0, false),
        ))
        .await
        .unwrap();
        let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
        assert!(matches!(ack, PtyAttachAck::Replay { .. }));

        if wait_ready {
            let pty = server.registry().get(session_id).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut offset = 0u64;
            loop {
                let slice = pty.read_slice(offset);
                offset = slice.end_offset;
                if slice.data.windows(5).any(|w| w == b"READY") {
                    break;
                }
                assert!(Instant::now() < deadline, "PTY did not print READY");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let (rsend, rrecv) = open(&conn, StreamPurpose::Rpc).await;

        Self {
            _tmp: tmp,
            server,
            _ep: ep,
            _conn: conn,
            _csend: csend,
            crecv,
            psend,
            _precv: precv,
            rsend,
            rrecv,
            req_id: 1,
            session_id: session_id.to_string(),
            claude_session_id: format!("claude-{session_id}"),
            transcript_path,
        }
    }

    fn fixture(&self, rel: &str) -> serde_json::Value {
        let mut v = read_fixture_json(rel);
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "session_id".into(),
                serde_json::Value::String(self.claude_session_id.clone()),
            );
            obj.insert(
                "transcript_path".into(),
                serde_json::Value::String(self.transcript_path.to_string_lossy().into_owned()),
            );
        }
        v
    }

    fn run_hook(&self, payload: &serde_json::Value) -> Output {
        let child = self.spawn_hook(payload);
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "hook exited with {:?}, stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn spawn_hook(&self, payload: &serde_json::Value) -> Child {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
            .arg("hook")
            .arg("claude")
            .env("CAWIDE_SESSION_ID", &self.session_id)
            .env("CAWIDE_SOCKET", self.server.socket_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            let bytes = serde_json::to_vec(payload).unwrap();
            stdin.write_all(&bytes).unwrap();
        }
        child
    }

    async fn wait_status<F>(&mut self, pred: F) -> AgentState
    where
        F: Fn(&AgentStatus) -> bool,
    {
        let sid = self.session_id.clone();
        let ev = next_event_matching(
            &mut self.crecv,
            |e| matches!(e, HostEvent::SessionUpdated { summary } if summary.session_id == sid && summary.agent.as_ref().is_some_and(|a| pred(&a.status))),
            Duration::from_secs(5),
        )
        .await
        .expect("timed out waiting for matching SessionUpdated");
        match ev {
            HostEvent::SessionUpdated { summary } => summary.agent.unwrap(),
            _ => unreachable!(),
        }
    }

    async fn start_turn(&mut self) {
        let start = self.fixture("hooks/session_start_startup.json");
        let out = self.run_hook(&start);
        assert!(out.stdout.is_empty());
        self.wait_status(|s| matches!(s, AgentStatus::Idle)).await;

        let prompt = self.fixture("hooks/user_prompt_submit.json");
        let out = self.run_hook(&prompt);
        assert!(out.stdout.is_empty());
        self.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
            .await;
    }

    async fn respond(
        &mut self,
        prompt_id: u64,
        prompt: &str,
        choice: AgentChoice,
    ) -> Result<(), String> {
        let id = self.req_id;
        self.req_id += 1;
        let req = RpcRequest::AgentRespond {
            session_id: self.session_id.clone(),
            prompt_id,
            prompt: prompt.to_string(),
            choice,
        };
        within(write_rpc_request(&mut self.rsend, id, &req))
            .await
            .unwrap();
        let frame = within(read_rpc_response(&mut self.rrecv))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.request_id, id);
        match frame.payload {
            RpcResponse::AgentRespond(res) => res,
            other => panic!("expected AgentRespond, got {other:?}"),
        }
    }

    fn append_transcript_lines(&self, lines: &[&str]) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.transcript_path)
            .unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        f.flush().unwrap();
    }

    async fn wait_child_output(child: Child) -> Output {
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || child.wait_with_output().unwrap()),
        )
        .await
        .expect("hook child did not exit within 5s")
        .unwrap()
    }

    async fn shutdown(self) {
        self.server.shutdown().await.unwrap();
    }
}

const CAT_CMD: &str = "sh -c 'stty raw -echo; printf READY; exec cat'";

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_a_bash_permission_allow_and_g_second_respond_rejected() {
    let mut h = ClaudeHarness::new("claude-w3-a", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let child = h.spawn_hook(&perm);

    let waiting = h
        .wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;
    let prompt = match &waiting.status {
        AgentStatus::WaitingForInput { prompt, options } => {
            assert_eq!(options, &vec!["Allow".to_string(), "Deny".to_string()]);
            prompt.clone()
        }
        _ => unreachable!(),
    };

    // (a) Option 0 -> allow
    assert_eq!(
        h.respond(0, &prompt, AgentChoice::Option { index: 0 })
            .await,
        Ok(())
    );

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout_str.trim())
        .unwrap_or_else(|e| panic!("expected JSON stdout, got {stdout_str:?}: {e}"));
    assert_eq!(
        parsed,
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "allow"
                }
            }
        })
    );

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());
    assert!(snap.head_attention.is_none());

    // (g) Second respond_to_session on already-answered permission -> Err("prompt no longer open")
    assert_eq!(
        h.respond(0, &prompt, AgentChoice::Option { index: 0 })
            .await,
        Err("prompt no longer open".into())
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_b_bash_permission_deny_with_message() {
    let mut h = ClaudeHarness::new("claude-w3-b", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let child = h.spawn_hook(&perm);

    let waiting = h
        .wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;
    let prompt = match &waiting.status {
        AgentStatus::WaitingForInput { prompt, .. } => prompt.clone(),
        _ => unreachable!(),
    };

    assert_eq!(
        h.respond(
            0,
            &prompt,
            AgentChoice::Text {
                text: "Use ls instead".into()
            }
        )
        .await,
        Ok(())
    );

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
    assert_eq!(parsed["hookSpecificOutput"]["decision"]["behavior"], "deny");
    assert_eq!(
        parsed["hookSpecificOutput"]["decision"]["message"],
        "Use ls instead"
    );

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_c_post_tool_use_dismisses_blocked_permission_hook() {
    let mut h = ClaudeHarness::new("claude-w3-c", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    let tuid = pre["tool_use_id"].as_str().unwrap().to_string();
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    let mut post = h.fixture("hooks/post_tool_use_bash.json");
    post.as_object_mut().unwrap().remove("agent_id");
    post.as_object_mut().unwrap().remove("agent_type");
    post["tool_use_id"] = serde_json::Value::String(tuid);
    post["tool_input"] = pre["tool_input"].clone();
    h.run_hook(&post);

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    assert!(
        out.stdout.is_empty(),
        "dismissed hook must emit empty stdout, got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());
    assert!(snap.head_attention.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_d_killed_permission_hook_clears_attention_and_restores_status() {
    let mut h = ClaudeHarness::new("claude-w3-d", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let mut child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    child.kill().unwrap();
    let _ = child.wait().unwrap();

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());
    assert!(snap.head_attention.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_e_ask_user_question_option_and_oob_rejected() {
    let mut h = ClaudeHarness::new("claude-w3-e", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_ask_user_question.json");
    h.run_hook(&pre);

    let perm = h.fixture("hooks/permission_request_ask_user_question.json");
    let mut child = h.spawn_hook(&perm);

    let waiting = h
        .wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;
    let prompt = match &waiting.status {
        AgentStatus::WaitingForInput { prompt, options } => {
            assert_eq!(
                options,
                &vec!["Red".to_string(), "Green".to_string(), "Blue".to_string()]
            );
            prompt.clone()
        }
        _ => unreachable!(),
    };

    // Out-of-bounds option returns "unsupported choice" without dismissing hook
    assert_eq!(
        h.respond(0, &prompt, AgentChoice::Option { index: 99 })
            .await,
        Err("unsupported choice".into())
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "hook must remain blocked after out-of-bounds choice"
    );

    // Option 1 -> "Green"
    assert_eq!(
        h.respond(0, &prompt, AgentChoice::Option { index: 1 })
            .await,
        Ok(())
    );

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["decision"]["behavior"],
        "allow"
    );
    assert_eq!(
        parsed["hookSpecificOutput"]["decision"]["updatedInput"]["answers"]["Pick a color?"],
        "Green"
    );

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_f_exit_plan_mode_approve_accept_edits() {
    let mut h = ClaudeHarness::new("claude-w3-f", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_exit_plan_mode.json");
    h.run_hook(&pre);

    let perm = h.fixture("hooks/permission_request_exit_plan_mode.json");
    let child = h.spawn_hook(&perm);

    let waiting = h
        .wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;
    let prompt = match &waiting.status {
        AgentStatus::WaitingForInput { prompt, options } => {
            assert_eq!(
                options,
                &vec!["Approve".to_string(), "Approve & accept edits".to_string()]
            );
            prompt.clone()
        }
        _ => unreachable!(),
    };

    assert_eq!(
        h.respond(0, &prompt, AgentChoice::Option { index: 1 })
            .await,
        Ok(())
    );

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["decision"]["behavior"],
        "allow"
    );
    let perms = parsed["hookSpecificOutput"]["decision"]["updatedPermissions"]
        .as_array()
        .unwrap();
    assert_eq!(
        perms[0],
        serde_json::json!({
            "type": "setMode",
            "mode": "acceptEdits",
            "destination": "session"
        })
    );

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_h_parent_process_dies_hook_exits_under_2s() {
    let mut h = ClaudeHarness::new("claude-w3-h", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let cmd = format!("{} hook claude; true", env!("CARGO_BIN_EXE_cawide"));
    let mut parent = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .env("CAWIDE_SESSION_ID", &h.session_id)
        .env("CAWIDE_SOCKET", h.server.socket_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = parent.stdin.take().unwrap();
        stdin
            .write_all(&serde_json::to_vec(&perm).unwrap())
            .unwrap();
    }
    let mut child_stdout = parent.stdout.take().unwrap();

    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    let kill_at = Instant::now();
    parent.kill().unwrap();
    let _ = parent.wait().unwrap();

    let stdout_bytes = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || {
            use std::io::Read as _;
            let mut buf = Vec::new();
            child_stdout.read_to_end(&mut buf).unwrap();
            buf
        }),
    )
    .await
    .expect("orphaned hook did not close stdout within 3s")
    .unwrap();

    let elapsed = kill_at.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "hook took {elapsed:?} to exit after parent SIGKILL (expected < 2s)"
    );
    assert!(stdout_bytes.is_empty());

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_i_transcript_approved_tool_result_answered_elsewhere() {
    let mut h = ClaudeHarness::new("claude-w3-i", CAT_CMD, true).await;
    h.start_turn().await;

    let lines = read_transcript_lines("transcripts/approved_tool.jsonl");
    let write_input = serde_json::json!({
        "file_path": "/tmp/cc-fx/plan.txt",
        "content": "hi\n"
    });

    let mut pre = h.fixture("hooks/pre_tool_use_write.json");
    pre["tool_use_id"] = serde_json::Value::String("call_13076200003776771996".into());
    pre["tool_input"] = write_input.clone();
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Write:")),
    )
    .await;

    let mut perm = h.fixture("hooks/permission_request_write.json");
    perm["tool_input"] = write_input;
    let child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    // Append line 3 (index 2) from approved_tool.jsonl matching call_13076200003776771996
    h.append_transcript_lines(&[&lines[2]]);

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());
    assert!(snap.head_attention.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_i2_transcript_terminal_no_interrupted_no_finished_alert_dismiss_immediately() {
    let lines = read_transcript_lines("transcripts/terminal_no.jsonl");
    assert_eq!(lines.len(), 4);

    // Part 1: Full CawideServer E2E with real binary + lines 2, 3, 4 of terminal_no.jsonl
    let mut h = ClaudeHarness::new("claude-w3-i2", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    h.append_transcript_lines(&[&lines[1], &lines[2], &lines[3]]);

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    h.wait_status(|s| matches!(s, AgentStatus::Idle)).await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());
    assert!(snap.head_attention.is_none());

    // Part 2: Verify exact AgentAlert and ActivityUpdateEvent channels via serve_ipc + real binary
    // (also testing fallback when PreToolUse was absent so line 3 prompt_snapshot is skipped and line 4 triggers Interrupted)
    let obs_tmp = tempfile::tempdir().unwrap();
    let obs_conf = obs_tmp.path().join("conf");
    let obs_work = obs_tmp.path().join("work");
    std::fs::create_dir_all(&obs_conf).unwrap();
    std::fs::create_dir_all(&obs_work).unwrap();
    let obs_transcript = obs_tmp.path().join("transcript.jsonl");
    std::fs::write(&obs_transcript, "").unwrap();

    let broadcaster = Arc::new(HostEventBroadcaster::new(32));
    let (alert_tx, mut alert_rx) = tokio::sync::mpsc::channel(64);
    let (act_tx, mut act_rx) = tokio::sync::mpsc::channel(64);
    let reg = Arc::new(
        SessionRegistry::new(
            obs_work.canonicalize().unwrap(),
            Some(CAT_CMD.into()),
            Vec::new(),
            Arc::clone(&broadcaster),
        )
        .with_config_dir(obs_conf.clone())
        .with_alert_sender(alert_tx)
        .with_activity_sender(act_tx),
    );
    reg.create_session("obs-i2", None, None, 80, 24).unwrap();

    let obs_sock = obs_conf.join("obs.sock");
    let listener = bind_ipc_listener(&obs_sock).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let push = PushService::open_with_cloud(
        &obs_conf,
        Arc::clone(h.server.auth_store()),
        h.server.node_id(),
        [0u8; 32],
        None,
    );
    let ctx = Arc::new(IpcContext {
        node_id: h.server.node_id(),
        endpoint: h.server.endpoint().clone(),
        pairing_manager: Arc::clone(h.server.pairing_manager()),
        auth_store: Arc::clone(h.server.auth_store()),
        registry: Arc::clone(&reg),
        broadcaster: Arc::clone(&broadcaster),
        connections: Arc::clone(h.server.connections()),
        trust: None,
        push,
        shutdown_tx: stop_tx.clone(),
    });
    let ipc_task = tokio::spawn(serve_ipc(listener, ctx, stop_rx));

    let run_obs_hook = |payload: &serde_json::Value| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cawide"))
            .arg("hook")
            .arg("claude")
            .env("CAWIDE_SESSION_ID", "obs-i2")
            .env("CAWIDE_SOCKET", &obs_sock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(payload).unwrap())
            .unwrap();
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success());
    };

    let mut start = read_fixture_json("hooks/session_start_startup.json");
    start["session_id"] = "obs-sid".into();
    start["transcript_path"] = obs_transcript.to_string_lossy().into_owned().into();
    run_obs_hook(&start);

    let mut prompt = read_fixture_json("hooks/user_prompt_submit.json");
    prompt["session_id"] = "obs-sid".into();
    prompt["transcript_path"] = obs_transcript.to_string_lossy().into_owned().into();
    run_obs_hook(&prompt);

    let mut perm_obs = read_fixture_json("hooks/permission_request_bash.json");
    perm_obs["session_id"] = "obs-sid".into();
    perm_obs["transcript_path"] = obs_transcript.to_string_lossy().into_owned().into();
    let mut perm_child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("claude")
        .env("CAWIDE_SESSION_ID", "obs-i2")
        .env("CAWIDE_SOCKET", &obs_sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    perm_child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&perm_obs).unwrap())
        .unwrap();

    let wait_deadline = Instant::now() + Duration::from_secs(5);
    while !matches!(
        reg.respond_snapshot("obs-i2")
            .and_then(|s| s.agent_state)
            .map(|a| a.status),
        Some(AgentStatus::WaitingForInput { .. })
    ) {
        assert!(Instant::now() < wait_deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&obs_transcript)
            .unwrap();
        for line in [&lines[1], &lines[2], &lines[3]] {
            writeln!(f, "{line}").unwrap();
        }
        f.flush().unwrap();
    }

    let obs_out = ClaudeHarness::wait_child_output(perm_child).await;
    assert!(obs_out.status.success());
    assert!(obs_out.stdout.is_empty());

    let idle_deadline = Instant::now() + Duration::from_secs(5);
    while !matches!(
        reg.respond_snapshot("obs-i2")
            .and_then(|s| s.agent_state)
            .map(|a| a.status),
        Some(AgentStatus::Idle)
    ) {
        assert!(Instant::now() < idle_deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut alerts = Vec::new();
    while let Ok(a) = alert_rx.try_recv() {
        alerts.push(a);
    }
    assert!(
        !alerts.iter().any(|a| a.kind == AgentAlertKind::Finished),
        "terminal No must NOT emit Finished alert, got {alerts:?}"
    );

    let mut activities = Vec::new();
    while let Ok(act) = act_rx.try_recv() {
        activities.push(act);
    }
    let last_act = activities.last().expect("expected Live Activity events");
    assert_eq!(last_act.phase, ActivityPhase::Done);
    assert_eq!(last_act.event, ActivityEventKind::End);
    assert!(
        last_act.dismiss_immediately,
        "expected dismiss_immediately=true on terminal No End activity, got {last_act:?}"
    );

    stop_tx.send_replace(true);
    let _ = ipc_task.await;
    reg.kill_all();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_i3_transcript_plan_feedback_dismisses_and_second_plan_answerable() {
    let lines = read_transcript_lines("transcripts/plan_feedback.jsonl");
    let mut h = ClaudeHarness::new("claude-w3-i3", CAT_CMD, true).await;
    h.start_turn().await;

    // First ExitPlanMode
    let pre1 = h.fixture("hooks/pre_tool_use_exit_plan_mode.json");
    h.run_hook(&pre1);
    let perm1 = h.fixture("hooks/permission_request_exit_plan_mode.json");
    let child1 = h.spawn_hook(&perm1);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    // Append line 2 (index 1) from plan_feedback.jsonl (userFeedback)
    h.append_transcript_lines(&[&lines[1]]);

    let out1 = ClaudeHarness::wait_child_output(child1).await;
    assert!(out1.status.success());
    assert!(out1.stdout.is_empty());

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    assert!(h
        .server
        .registry()
        .respond_snapshot(&h.session_id)
        .unwrap()
        .claude_pending
        .is_none());

    // Second PreToolUse(ExitPlanMode) + PermissionRequest(ExitPlanMode)
    let mut pre2 = h.fixture("hooks/pre_tool_use_exit_plan_mode.json");
    pre2["tool_use_id"] = serde_json::Value::String("call_second_plan_999".into());
    h.run_hook(&pre2);
    let perm2 = h.fixture("hooks/permission_request_exit_plan_mode.json");
    let child2 = h.spawn_hook(&perm2);

    let waiting2 = h
        .wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;
    let prompt2 = match &waiting2.status {
        AgentStatus::WaitingForInput { prompt, .. } => prompt.clone(),
        _ => unreachable!(),
    };

    assert_eq!(
        h.respond(0, &prompt2, AgentChoice::Option { index: 0 })
            .await,
        Ok(())
    );
    let out2 = ClaudeHarness::wait_child_output(child2).await;
    assert!(out2.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out2.stdout).trim()).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["decision"]["behavior"],
        "allow"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_i4_transcript_feedback_tool_result_answered_elsewhere() {
    let mut h = ClaudeHarness::new("claude-w3-i4", CAT_CMD, true).await;
    h.start_turn().await;

    let mut pre = h.fixture("hooks/pre_tool_use_bash.json");
    pre["tool_use_id"] = serde_json::Value::String("call_feedback_bash_1".into());
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    let feedback_line = serde_json::json!({
        "type": "user",
        "userFeedback": "run pwd instead",
        "toolDenialKind": "user-rejected",
        "message": {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "call_feedback_bash_1",
                "is_error": true,
                "content": "rejected with feedback"
            }]
        }
    })
    .to_string();
    h.append_transcript_lines(&[&feedback_line]);

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_j_legacy_event_flag_exits_empty_no_attention() {
    let mut h = ClaudeHarness::new("claude-w3-j", CAT_CMD, true).await;
    h.start_turn().await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("claude")
        .arg("--event")
        .arg("PermissionRequest")
        .env("CAWIDE_SESSION_ID", &h.session_id)
        .env("CAWIDE_SOCKET", h.server.socket_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&perm).unwrap())
        .unwrap();

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(matches!(
        snap.agent_state.as_ref().map(|a| &a.status),
        Some(AgentStatus::Thinking { .. })
    ));
    assert!(snap.head_attention.is_none());
    assert!(snap.claude_pending.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_k_and_l_stop_clears_plan_and_completed_reply_pastes_to_pty() {
    let mut h = ClaudeHarness::new("claude-w3-kl", CAT_CMD, true).await;
    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_exit_plan_mode.json");
    h.run_hook(&pre);
    let perm = h.fixture("hooks/permission_request_exit_plan_mode.json");
    let child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    // (k) Stop clears Plan attention and dismisses blocked ExitPlanMode hook
    let stop = h.fixture("hooks/stop.json");
    h.run_hook(&stop);

    let out = ClaudeHarness::wait_child_output(child).await;
    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    let completed = h
        .wait_status(|s| matches!(s, AgentStatus::Completed { .. }))
        .await;
    let summary = match &completed.status {
        AgentStatus::Completed { summary } => summary.clone(),
        _ => unreachable!(),
    };
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());
    assert!(snap
        .head_attention
        .as_ref()
        .is_some_and(|a| matches!(a.kind, cawide_host::agent::map::AttentionKind::TextQuestion)));

    // (l) Completed-turn reply bracketed-pastes to PTY
    let pty = h.server.registry().get(&h.session_id).unwrap();
    let mut offset = pty.read_slice(0).end_offset;

    assert_eq!(
        h.respond(
            0,
            &summary,
            AgentChoice::Text {
                text: "follow up".into()
            }
        )
        .await,
        Ok(())
    );

    let mut captured = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let expected = b"\x1b[200~follow up\x1b[201~\r";
    while !captured.windows(expected.len()).any(|w| w == expected) {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        captured.extend_from_slice(&slice.data);
        assert!(
            Instant::now() < deadline,
            "expected bracketed paste in PTY output, got {:?}",
            String::from_utf8_lossy(&captured)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_m_probe_reset_drops_pending_and_dismisses_hook() {
    let mut h = ClaudeHarness::new("claude-w3-m", "sh -s", false).await;
    let pty = h.server.registry().get(&h.session_id).unwrap();
    pty.send_input_async(bytes::Bytes::from_static(b"printf READY\n"))
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut offset = 0u64;
    loop {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        if slice.data.windows(5).any(|w| w == b"READY") {
            break;
        }
        assert!(Instant::now() < deadline, "sh -s did not print READY");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    h.start_turn().await;

    let pre = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;

    let perm = h.fixture("hooks/permission_request_bash.json");
    let child = h.spawn_hook(&perm);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    // SessionProbe runs every 1s and sees Foreground::Shell (`sh -s`); after >= 3s it resets tracker
    // and sweep_pending drops pending_permissions -> hook receives ClaudeDismissed and exits.
    let out = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::task::spawn_blocking(move || child.wait_with_output().unwrap()),
    )
    .await
    .expect("hook was not dismissed by probe reset within 8s")
    .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.agent_state.is_none());
    assert!(snap.claude_pending.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_w3_n_pty_input_accelerator_anchor_checks() {
    let mut h = ClaudeHarness::new("claude-w3-n", CAT_CMD, true).await;
    h.start_turn().await;

    // Test 1: Anchor-less tool (CustomTool) pending -> write \r to PTY -> after 500ms NOT dismissed
    let mut custom_perm = h.fixture("hooks/permission_request_bash.json");
    custom_perm["tool_name"] = serde_json::Value::String("CustomTool".into());
    let mut child1 = h.spawn_hook(&custom_perm);
    let waiting1 = h
        .wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;
    let prompt1 = match &waiting1.status {
        AgentStatus::WaitingForInput { prompt, .. } => prompt.clone(),
        _ => unreachable!(),
    };

    h.psend.write_all(b"\r").await.unwrap();
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(
        child1.try_wait().unwrap().is_none(),
        "anchor-less tool must NOT be dismissed by PTY \\r"
    );
    assert!(h
        .server
        .registry()
        .respond_snapshot(&h.session_id)
        .unwrap()
        .claude_pending
        .is_some());

    // Clean up Test 1 via respond
    assert_eq!(
        h.respond(0, &prompt1, AgentChoice::Option { index: 0 })
            .await,
        Ok(())
    );
    let _ = ClaudeHarness::wait_child_output(child1).await;
    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;

    // Write Bash anchor onto PTY screen before PermissionRequest
    let pty = h.server.registry().get(&h.session_id).unwrap();
    h.psend
        .write_all(b"Do you want to proceed?\r\n")
        .await
        .unwrap();
    let anchor_deadline = Instant::now() + Duration::from_secs(3);
    while !pty.screen_contents().contains("Do you want to proceed?") {
        assert!(Instant::now() < anchor_deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Test 3: Anchored tool (Bash) with anchor still visible -> send 1\r while anchor stays -> NOT dismissed
    let pre3 = h.fixture("hooks/pre_tool_use_bash.json");
    h.run_hook(&pre3);
    h.wait_status(
        |s| matches!(s, AgentStatus::Thinking { task_desc } if task_desc.starts_with("Bash:")),
    )
    .await;
    let perm3 = h.fixture("hooks/permission_request_bash.json");
    let mut child3 = h.spawn_hook(&perm3);
    h.wait_status(|s| matches!(s, AgentStatus::WaitingForInput { .. }))
        .await;

    h.psend.write_all(b"1\r").await.unwrap();
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(
        child3.try_wait().unwrap().is_none(),
        "anchored tool must NOT be dismissed while anchor stays on screen"
    );
    assert!(h
        .server
        .registry()
        .respond_snapshot(&h.session_id)
        .unwrap()
        .claude_pending
        .is_some());

    // Test 2: Clear screen (\x1b[2J\x1b[H) and send \r -> dismissed within ~500ms!
    let clear_at = Instant::now();
    h.psend.write_all(b"\x1b[2J\x1b[H\r").await.unwrap();

    let out3 = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || child3.wait_with_output().unwrap()),
    )
    .await
    .expect("anchored tool was not dismissed after screen clear + \\r")
    .unwrap();
    let dismiss_elapsed = clear_at.elapsed();
    assert!(out3.status.success());
    assert!(out3.stdout.is_empty());
    assert!(
        dismiss_elapsed < Duration::from_millis(1200),
        "expected fast anchor dismissal (~400-500ms), took {dismiss_elapsed:?}"
    );

    h.wait_status(|s| matches!(s, AgentStatus::Thinking { .. }))
        .await;
    let snap = h.server.registry().respond_snapshot(&h.session_id).unwrap();
    assert!(snap.claude_pending.is_none());

    h.shutdown().await;
}
#[test]
#[ignore]
fn test_real_claude_e2e() {
    if std::env::var("CAWIDE_E2E_REAL_CLAUDE").is_err() {
        return;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        use cawide_host::agent::map::AttentionKind;
        use cawide_host::agent::respond::respond_to_session;
        use cawide_host::net::registry::ClaudePendingKind;

        let workdir = std::env::temp_dir().join("cawide-e2e-claude");
        std::fs::create_dir_all(&workdir).unwrap();
        if !workdir.join(".git").exists() {
            let run_git = |args: &[&str]| {
                let st = Command::new("git")
                    .args(args)
                    .current_dir(&workdir)
                    .status()
                    .unwrap();
                assert!(st.success(), "git {args:?} failed");
            };
            run_git(&["init"]);
            run_git(&["config", "user.name", "Cawide E2E"]);
            run_git(&["config", "user.email", "e2e@cawide.local"]);
            std::fs::write(workdir.join("README.md"), "cawide e2e\n").unwrap();
            run_git(&["add", "README.md"]);
            run_git(&["commit", "-m", "init"]);
        }

        let reset_workdir = || {
            let st1 = Command::new("git")
                .args(["reset", "--hard", "HEAD"])
                .current_dir(&workdir)
                .status()
                .unwrap();
            assert!(st1.success());
            let st2 = Command::new("git")
                .args(["clean", "-fdx"])
                .current_dir(&workdir)
                .status()
                .unwrap();
            assert!(st2.success());
        };
        reset_workdir();

        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("conf");
        let upload_dir = tmp.path().join("uploads");

        let config = CawideServerConfig {
            config_dir: config_dir.clone(),
            network_mode: NetworkMode::LocalOnly,
            workdir: workdir.clone(),
            launch_cmd: None,
            upload_dir: Some(upload_dir),
            opener: None,
            watch_workspace: false,
            port: None,
            external_addr: None,
            relay_url: None,
            forge: cawide_host::forge::ForgeHostConfig::default(),
            git_env: Vec::new(),
        };

        let server = within(CawideServer::bind(config)).await.unwrap();

        // Ensure <config_dir>/bin/cawide points to the real cawide CLI binary (not the test runner).
        let bin_cawide = config_dir.join("bin/cawide");
        let _ = std::fs::remove_file(&bin_cawide);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_cawide"), &bin_cawide).unwrap();

        let (_ep, conn) = authorized_client(&server).await;
        let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
        within(write_control_message(
            &mut csend,
            &ControlMessage::Ping { client_ts: 1 },
        ))
        .await
        .unwrap();
        match within(read_control_message(&mut crecv)).await.unwrap() {
            Some(ControlMessage::Pong { client_ts: 1, .. }) => {}
            other => panic!("expected Pong, got {other:?}"),
        }

        async fn start_claude_session(
            server: &CawideServer,
            conn: &Connection,
            sid: &str,
            mode: &str,
        ) -> (SendStream, RecvStream) {
            let cmd = format!(
                "exec env -u CLAUDECODE -u CLAUDE_CODE_CHILD_SESSION -u CAWIDE_CLAUDE_OWNER claude --permission-mode {mode}"
            );
            server
                .registry()
                .create_session(sid, Some(cmd), None, 120, 40)
                .unwrap();

            let (mut psend, mut precv) = open(conn, StreamPurpose::Pty).await;
            within(write_pty_attach_header(
                &mut psend,
                &PtyAttachHeader::new(sid, 0, false),
            ))
            .await
            .unwrap();
            let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
            assert!(matches!(ack, PtyAttachAck::Replay { .. }));

            let pty = server.registry().get(sid).unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut sent_trust = false;
            loop {
                let screen = pty.screen_contents();
                assert!(
                    Instant::now() < deadline,
                    "[{sid}] timed out waiting for Claude input box; screen:\n{screen}"
                );
                assert!(
                    pty.is_alive(),
                    "[{sid}] claude PTY exited unexpectedly; screen:\n{screen}"
                );
                if screen.contains("Yes, I trust this folder")
                    || screen.contains("Quick safety check")
                {
                    if !sent_trust {
                        eprintln!("[{sid}] accepting folder trust prompt");
                        if screen.contains("❯ No, exit") {
                            psend.write_all(b"\x1b[B").await.unwrap();
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        }
                        psend.write_all(b"\r").await.unwrap();
                        sent_trust = true;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    continue;
                }
                if (screen.contains("❯ ") || screen.contains("❯\u{a0}"))
                    && !screen.contains("Yes, I trust this folder")
                    && !screen.contains("Quick safety check")
                {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }

            (psend, precv)
        }

        async fn send_prompt(psend: &mut SendStream, prompt: &str) {
            let paste = format!("\x1b[200~{prompt}\x1b[201~");
            psend.write_all(paste.as_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            psend.write_all(b"\r").await.unwrap();
        }

        async fn wait_session_status<F>(
            crecv: &mut RecvStream,
            server: &CawideServer,
            sid: &str,
            timeout: Duration,
            pred: F,
        ) -> AgentState
        where
            F: Fn(&AgentStatus) -> bool,
        {
            let ev = next_event_matching(
                crecv,
                |e| matches!(e, HostEvent::SessionUpdated { summary } if summary.session_id == sid && summary.agent.as_ref().is_some_and(|a| pred(&a.status))),
                timeout,
            )
            .await
            .unwrap_or_else(|| {
                let snap = server.registry().respond_snapshot(sid);
                let screen = server
                    .registry()
                    .get(sid)
                    .map(|p| p.screen_contents())
                    .unwrap_or_default();
                panic!(
                    "[{sid}] timed out waiting for SessionUpdated; snap={:?}\nscreen:\n{screen}",
                    snap.as_ref().map(|s| (&s.agent_state, &s.claude_pending))
                );
            });
            match ev {
                HostEvent::SessionUpdated { summary } => summary.agent.unwrap(),
                _ => unreachable!(),
            }
        }

        async fn wait_waiting_with_pending(
            crecv: &mut RecvStream,
            server: &CawideServer,
            sid: &str,
            timeout: Duration,
        ) -> (String, Vec<String>, ClaudePendingKind, AttentionKind) {
            let state = wait_session_status(
                crecv,
                server,
                sid,
                timeout,
                |s| matches!(s, AgentStatus::WaitingForInput { .. }),
            )
            .await;
            let (prompt, options) = match state.status {
                AgentStatus::WaitingForInput { prompt, options } => (prompt, options),
                _ => unreachable!(),
            };
            let snap = server.registry().respond_snapshot(sid).unwrap();
            let (_, pending_kind) = snap
                .claude_pending
                .expect("expected active claude_pending in registry");
            let head_kind = snap.head_attention.expect("expected head_attention").kind;
            (prompt, options, pending_kind, head_kind)
        }

        // Case 1: Bash allow
        {
            let sid = "e2e-case-1";
            eprintln!("=== Case 1: Bash allow ===");
            let (mut psend, _precv) = start_claude_session(&server, &conn, sid, "default").await;
            send_prompt(
                &mut psend,
                "Use the Bash tool to run exactly: touch test_allow.txt",
            )
            .await;

            let (prompt, _opts, pending_kind, _) =
                wait_waiting_with_pending(&mut crecv, &server, sid, Duration::from_secs(180)).await;
            assert_eq!(pending_kind, ClaudePendingKind::Approval);
            eprintln!("[{sid}] answering Option 0 (Allow) for: {prompt}");
            respond_to_session(
                server.registry(),
                sid,
                0,
                &prompt,
                AgentChoice::Option { index: 0 },
            )
            .await
            .unwrap();

            let done = wait_session_status(
                &mut crecv,
                &server,
                sid,
                Duration::from_secs(180),
                |s| matches!(s, AgentStatus::Completed { .. }),
            )
            .await;
            eprintln!("[{sid}] completed: {:?}", done.status);
            assert!(workdir.join("test_allow.txt").exists());
            server.registry().kill_session(sid).unwrap();
            reset_workdir();
        }

        // Case 2: Deny-with-feedback
        {
            let sid = "e2e-case-2";
            eprintln!("=== Case 2: Deny-with-feedback ===");
            let (mut psend, _precv) = start_claude_session(&server, &conn, sid, "default").await;
            send_prompt(
                &mut psend,
                "Use the Bash tool to run exactly: touch test_deny.txt",
            )
            .await;

            let (prompt, _opts, pending_kind, _) =
                wait_waiting_with_pending(&mut crecv, &server, sid, Duration::from_secs(180)).await;
            assert_eq!(pending_kind, ClaudePendingKind::Approval);
            eprintln!("[{sid}] denying with feedback for: {prompt}");
            respond_to_session(
                server.registry(),
                sid,
                0,
                &prompt,
                AgentChoice::Text {
                    text: "Do not create test_deny, create test_deny_alt.txt instead".into(),
                },
            )
            .await
            .unwrap();

            // Approve follow-up tool call(s) until Completed
            let deadline = Instant::now() + Duration::from_secs(180);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "[{sid}] timed out waiting for completion");
                let st = wait_session_status(
                    &mut crecv,
                    &server,
                    sid,
                    remaining,
                    |s| matches!(s, AgentStatus::WaitingForInput { .. } | AgentStatus::Completed { .. }),
                )
                .await;
                match st.status {
                    AgentStatus::WaitingForInput { prompt, .. } => {
                        eprintln!("[{sid}] approving follow-up tool: {prompt}");
                        respond_to_session(
                            server.registry(),
                            sid,
                            0,
                            &prompt,
                            AgentChoice::Option { index: 0 },
                        )
                        .await
                        .unwrap();
                    }
                    AgentStatus::Completed { summary } => {
                        eprintln!("[{sid}] completed: {summary}");
                        break;
                    }
                    _ => unreachable!(),
                }
            }
            assert!(workdir.join("test_deny_alt.txt").exists());
            assert!(!workdir.join("test_deny.txt").exists());
            server.registry().kill_session(sid).unwrap();
            reset_workdir();
        }

        // Case 3: AskUserQuestion option
        {
            let sid = "e2e-case-3";
            eprintln!("=== Case 3: AskUserQuestion option ===");
            let (mut psend, _precv) = start_claude_session(&server, &conn, sid, "default").await;
            send_prompt(
                &mut psend,
                "Use the AskUserQuestion tool to ask me one single-select question \"Coffee or tea?\" with options \"Coffee\" first and \"Tea\" second. Then reply with the exact choice I picked.",
            )
            .await;

            let (prompt, opts, pending_kind, head_kind) =
                wait_waiting_with_pending(&mut crecv, &server, sid, Duration::from_secs(180)).await;
            assert_eq!(pending_kind, ClaudePendingKind::Ask);
            assert!(matches!(head_kind, AttentionKind::Ask { multi: false, .. }));
            eprintln!("[{sid}] AskUserQuestion prompt={prompt:?} opts={opts:?}");
            assert!(
                opts.first()
                    .is_some_and(|o| o.to_ascii_lowercase().contains("coffee")),
                "expected option 0 to be coffee, got {opts:?}"
            );
            respond_to_session(
                server.registry(),
                sid,
                0,
                &prompt,
                AgentChoice::Option { index: 0 },
            )
            .await
            .unwrap();

            let done = wait_session_status(
                &mut crecv,
                &server,
                sid,
                Duration::from_secs(180),
                |s| matches!(s, AgentStatus::Completed { .. }),
            )
            .await;
            match &done.status {
                AgentStatus::Completed { summary } => {
                    eprintln!("[{sid}] completed: {summary}");
                    assert!(
                        summary.to_ascii_lowercase().contains("coffee"),
                        "expected reply mentioning coffee, got {summary:?}"
                    );
                }
                _ => unreachable!(),
            }
            server.registry().kill_session(sid).unwrap();
            reset_workdir();
        }

        // Case 4: ExitPlanMode approve
        {
            let sid = "e2e-case-4";
            eprintln!("=== Case 4: ExitPlanMode approve ===");
            let (mut psend, _precv) = start_claude_session(&server, &conn, sid, "plan").await;
            send_prompt(
                &mut psend,
                "Make a 1-step plan to create plan_file.txt containing ok using the Write tool. Do not explore; immediately call ExitPlanMode with the plan.",
            )
            .await;

            let (prompt, _opts, pending_kind, head_kind) =
                wait_waiting_with_pending(&mut crecv, &server, sid, Duration::from_secs(180)).await;
            assert_eq!(pending_kind, ClaudePendingKind::Plan);
            assert!(matches!(head_kind, AttentionKind::Plan { .. }));
            eprintln!("[{sid}] approving plan (Option 0): {prompt}");
            respond_to_session(
                server.registry(),
                sid,
                0,
                &prompt,
                AgentChoice::Option { index: 0 },
            )
            .await
            .unwrap();

            let deadline = Instant::now() + Duration::from_secs(180);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "[{sid}] timed out waiting for plan execution");
                let st = wait_session_status(
                    &mut crecv,
                    &server,
                    sid,
                    remaining,
                    |s| matches!(s, AgentStatus::WaitingForInput { .. } | AgentStatus::Completed { .. }),
                )
                .await;
                match st.status {
                    AgentStatus::WaitingForInput { prompt, .. } => {
                        eprintln!("[{sid}] approving plan execution tool: {prompt}");
                        respond_to_session(
                            server.registry(),
                            sid,
                            0,
                            &prompt,
                            AgentChoice::Option { index: 0 },
                        )
                        .await
                        .unwrap();
                    }
                    AgentStatus::Completed { summary } => {
                        eprintln!("[{sid}] completed: {summary}");
                        break;
                    }
                    _ => unreachable!(),
                }
            }
            assert!(workdir.join("plan_file.txt").exists());
            server.registry().kill_session(sid).unwrap();
            reset_workdir();
        }

        // Case 5: Terminal-first "No"
        {
            let sid = "e2e-case-5";
            eprintln!("=== Case 5: Terminal-first No ===");
            let (mut psend, _precv) = start_claude_session(&server, &conn, sid, "default").await;
            send_prompt(
                &mut psend,
                "Use the Bash tool to run exactly: touch test_term_no.txt",
            )
            .await;

            let (_prompt, _opts, pending_kind, _) =
                wait_waiting_with_pending(&mut crecv, &server, sid, Duration::from_secs(180)).await;
            assert_eq!(pending_kind, ClaudePendingKind::Approval);

            let pty = server.registry().get(sid).unwrap();
            let anchor_deadline = Instant::now() + Duration::from_secs(10);
            while !pty.screen_contents().contains("Do you want to proceed?") {
                assert!(Instant::now() < anchor_deadline, "Bash dialog anchor did not appear");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            eprintln!("[{sid}] sending 4\\r directly to PTY");
            psend.write_all(b"4\r").await.unwrap();

            let idle = wait_session_status(
                &mut crecv,
                &server,
                sid,
                Duration::from_secs(15),
                |s| matches!(s, AgentStatus::Idle),
            )
            .await;
            eprintln!("[{sid}] transitioned to {:?}", idle.status);
            let snap = server.registry().respond_snapshot(sid).unwrap();
            assert!(snap.claude_pending.is_none());
            assert!(snap.head_attention.is_none());
            assert!(!workdir.join("test_term_no.txt").exists());
            server.registry().kill_session(sid).unwrap();
            reset_workdir();
        }

        // Case 6: Terminal-first "Yes" on long-running tool (PTY accelerator)
        {
            let sid = "e2e-case-6";
            eprintln!("=== Case 6: Terminal-first Yes (PTY accelerator) ===");
            let (mut psend, _precv) = start_claude_session(&server, &conn, sid, "default").await;
            send_prompt(
                &mut psend,
                "Use the Bash tool to run exactly: sleep 5 && touch test_accel.txt",
            )
            .await;

            let (_prompt, _opts, pending_kind, _) =
                wait_waiting_with_pending(&mut crecv, &server, sid, Duration::from_secs(180)).await;
            assert_eq!(pending_kind, ClaudePendingKind::Approval);

            let pty = server.registry().get(sid).unwrap();
            let anchor_deadline = Instant::now() + Duration::from_secs(10);
            while !pty.screen_contents().contains("Do you want to proceed?") {
                assert!(Instant::now() < anchor_deadline, "Bash dialog anchor did not appear");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            let sent_at = Instant::now();
            eprintln!("[{sid}] sending 1\\r directly to PTY");
            psend.write_all(b"1\r").await.unwrap();

            let thinking = wait_session_status(
                &mut crecv,
                &server,
                sid,
                Duration::from_secs(5),
                |s| matches!(s, AgentStatus::Thinking { .. }),
            )
            .await;
            let dismiss_elapsed = sent_at.elapsed();
            eprintln!(
                "[{sid}] accelerator dismissed pending in {dismiss_elapsed:?}: {:?}",
                thinking.status
            );
            assert!(
                dismiss_elapsed < Duration::from_secs(2),
                "expected PTY accelerator dismissal < 2s, took {dismiss_elapsed:?}"
            );
            let snap = server.registry().respond_snapshot(sid).unwrap();
            assert!(snap.claude_pending.is_none());

            let done = wait_session_status(
                &mut crecv,
                &server,
                sid,
                Duration::from_secs(180),
                |s| matches!(s, AgentStatus::Completed { .. }),
            )
            .await;
            eprintln!("[{sid}] completed: {:?}", done.status);
            assert!(workdir.join("test_accel.txt").exists());
            server.registry().kill_session(sid).unwrap();
            reset_workdir();
        }

        server.shutdown().await.unwrap();
    });
}
