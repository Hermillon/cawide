//! Integration tests for agent telemetry, hooks, and shell setup (Brick 7).

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cawide_host::agent::setup::run_setup;
use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_protocol::types::{
    AgentChoice, AgentStatus, HostEvent, PushChannelV2, RpcFrame, RpcRequest, RpcResponse,
    PUSH_CAP_E2E_CONTENT,
};
use cawide_protocol::{
    read_control_message, read_pty_attach_ack, read_rpc_response, write_control_message,
    write_pty_attach_header, write_rpc_request, ControlMessage, PtyAttachAck, PtyAttachHeader,
    StreamPurpose,
};
use common::{authorized_client, open, within};
use iroh::endpoint::RecvStream;

async fn next_event_matching<F>(
    recv: &mut RecvStream,
    pred: F,
    timeout: Duration,
) -> Option<HostEvent>
where
    F: Fn(&HostEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, read_control_message(recv)).await {
            Ok(Ok(Some(ControlMessage::HostEvent(event)))) => {
                if pred(&event) {
                    return Some(event);
                }
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
        }
    }
    None
}

#[test]
fn test_setup_claude_idempotent_and_preserves_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_file = claude_dir.join("settings.json");

    let initial = serde_json::json!({
        "unrelated_key": "preserved_value",
        "hooks": {
            "SessionStart": [
                {
                    "hooks": [
                        { "type": "command", "command": "echo custom_start" }
                    ]
                }
            ]
        }
    });
    std::fs::write(
        &settings_file,
        serde_json::to_string_pretty(&initial).unwrap(),
    )
    .unwrap();

    let exe = PathBuf::from("/usr/local/bin/cawide");
    let summary1 = run_setup(home, &exe, "claude", false).unwrap();
    assert!(!summary1.is_empty());

    let bytes1 = std::fs::read(&settings_file).unwrap();
    let bak_file = claude_dir.join("settings.json.cawide-bak");
    assert!(
        bak_file.exists(),
        ".cawide-bak must be created on first edit"
    );
    let bak_content: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bak_file).unwrap()).unwrap();
    assert_eq!(bak_content["unrelated_key"], "preserved_value");

    let _summary2 = run_setup(home, &exe, "claude", false).unwrap();
    let bytes2 = std::fs::read(&settings_file).unwrap();
    assert_eq!(bytes1, bytes2, "setup must be byte-for-byte idempotent");

    let parsed: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(parsed["unrelated_key"], "preserved_value");
    let start_groups = parsed["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(start_groups.len(), 2, "custom hook + cawide hook");

    // Test remove
    let _summary3 = run_setup(home, &exe, "claude", true).unwrap();
    let removed_bytes = std::fs::read(&settings_file).unwrap();
    let removed_parsed: serde_json::Value = serde_json::from_slice(&removed_bytes).unwrap();
    assert_eq!(removed_parsed["unrelated_key"], "preserved_value");
    let rem_start_groups = removed_parsed["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(rem_start_groups.len(), 1, "only custom hook remains");
}

#[test]
fn test_setup_codex_foreign_notify_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let codex_dir = home.join(".codex");
    std::fs::create_dir_all(&codex_dir).unwrap();
    let config_file = codex_dir.join("config.toml");
    std::fs::write(&config_file, "notify = [\"custom\", \"script\"]\n").unwrap();

    let exe = PathBuf::from("/usr/local/bin/cawide");
    let summary = run_setup(home, &exe, "codex", false).unwrap();
    assert!(
        summary.ends_with("Codex ignores new or changed hooks until you approve them: run /hooks inside Codex once."),
        "summary must end with approval instruction: {summary}"
    );

    let config_content = std::fs::read_to_string(&config_file).unwrap();
    assert!(
        config_content.contains("custom"),
        "foreign notify must be kept"
    );
    assert!(
        config_content.contains("features.hooks = true") || config_content.contains("hooks = true"),
        "features.hooks must be enabled"
    );

    let hooks_file = codex_dir.join("hooks.json");
    assert!(hooks_file.exists());
}

#[test]
fn test_setup_omp_refuses_non_marker_and_opencode() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let omp_ext_dir = home.join(".omp/agent/extensions");
    std::fs::create_dir_all(&omp_ext_dir).unwrap();
    let omp_file = omp_ext_dir.join("cawide.js");
    std::fs::write(&omp_file, "// foreign extension without marker\n").unwrap();

    let exe = PathBuf::from("/usr/local/bin/cawide");
    let err = run_setup(home, &exe, "omp", false).unwrap_err();
    assert!(
        err.to_string().contains("refusing") || err.to_string().contains("marker"),
        "must refuse non-marker file: {err}"
    );

    // Overwriting with marker allowed
    std::fs::write(&omp_file, "// cawide-telemetry v1\n").unwrap();
    let summary = run_setup(home, &exe, "omp", false).unwrap();
    assert!(!summary.is_empty());
    let omp_content = std::fs::read_to_string(&omp_file).unwrap();
    assert!(omp_content.starts_with("// cawide-telemetry v3"));
    assert!(omp_content.contains("CAWIDE_SESSION_ID"));
    assert!(omp_content.contains("CAWIDE_SOCKET"));
    assert!(omp_content.contains("\"--stream\""));
    assert!(omp_content.contains("plan_review_requested"));
    assert!(omp_content.contains("resolvePlanReview"));
    // OpenCode setup
    let opencode_summary = run_setup(home, &exe, "opencode", false).unwrap();
    assert!(!opencode_summary.is_empty());
    let opencode_file = home.join(".config/opencode/plugins/cawide.js");
    assert!(opencode_file.exists());
    let opencode_content = std::fs::read_to_string(&opencode_file).unwrap();
    assert!(opencode_content.starts_with("// cawide-telemetry v3"));
    assert!(opencode_content.contains("CAWIDE_SESSION_ID"));
    assert!(opencode_content.contains("CAWIDE_SOCKET"));
}

#[test]
fn test_cli_hook_no_env() {
    let output = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("claude")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "{}");
}

#[test]
fn test_cli_hook_codex_stop_prints_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("codex")
        .arg("--event")
        .arg("Stop")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "{}");
}

#[test]
fn test_cli_hook_hanging_stdin_timeout() {
    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("claude")
        .env("CAWIDE_SESSION_ID", "test-sess")
        .env("CAWIDE_SOCKET", "/tmp/nonexistent-cawide.sock")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _stdin = child.stdin.take();
    let status = child.wait().unwrap();
    assert!(status.success());
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "must wait for stdin recv_timeout of 2s, took {:?}",
        start.elapsed()
    );
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "hanging stdin must timeout and exit 0 within 4s, took {:?}",
        start.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_hook_agent_status_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let launch = format!(
        "sh -c 'sleep 1; echo \"{{\\\"hook_event_name\\\":\\\"Stop\\\",\\\"last_assistant_message\\\":\\\"done\\\"}}\" | {} hook claude; sleep 5'",
        env!("CARGO_BIN_EXE_cawide")
    );
    let config = CawideServerConfig {
        config_dir: tmp.path().join("conf"),
        network_mode: NetworkMode::LocalOnly,
        workdir: tmp.path().join("workdir"),
        launch_cmd: Some(launch),
        upload_dir: Some(tmp.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };
    std::fs::create_dir_all(&config.workdir).unwrap();

    let server = within(CawideServer::bind(config)).await.unwrap();
    let (_ep, conn) = authorized_client(&server).await;

    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;

    // Ping/Pong sync
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 42 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 42, .. }) => {}
        other => panic!("expected Pong, got {other:?}"),
    }

    // Attach PTY session
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("agent-sess", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    // Wait up to 10s for SessionUpdated
    let event = next_event_matching(
        &mut crecv,
        |ev| matches!(ev, HostEvent::SessionUpdated { .. }),
        Duration::from_secs(10),
    )
    .await;

    match event {
        Some(HostEvent::SessionUpdated { summary }) => {
            assert_eq!(summary.session_id, "agent-sess");
            let state = summary.agent.expect("agent state present");
            assert_eq!(state.agent, "claude");
            assert_eq!(
                state.status,
                AgentStatus::Completed {
                    summary: "done".into()
                }
            );
        }
        other => panic!("expected SessionUpdated, got {other:?}"),
    }

    // Check SessionList shows agent set
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(&mut rsend, 1, &RpcRequest::SessionList))
        .await
        .unwrap();
    match within(read_rpc_response(&mut rrecv)).await.unwrap() {
        Some(RpcFrame {
            request_id: 1,
            payload: RpcResponse::SessionList(Ok(sessions)),
        }) => {
            let s = sessions
                .iter()
                .find(|s| s.session_id == "agent-sess")
                .expect("session must be listed");
            assert!(s.agent.is_some(), "agent must be set");
            let agent_state = s.agent.as_ref().unwrap();
            assert_eq!(agent_state.agent, "claude");
            assert_eq!(
                agent_state.status,
                AgentStatus::Completed {
                    summary: "done".into()
                }
            );
        }
        other => panic!("expected SessionList response, got {other:?}"),
    }

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cli_hook_strict_pty_gating() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("conf");
    let workdir = tmp.path().join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();

    let config = CawideServerConfig {
        config_dir: config_dir.clone(),
        network_mode: NetworkMode::LocalOnly,
        workdir: workdir.clone(),
        launch_cmd: Some("sh -c 'sleep 10'".into()),
        upload_dir: Some(tmp.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };

    let server = within(CawideServer::bind(config)).await.unwrap();
    let (_ep, conn) = authorized_client(&server).await;

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("gated-sess", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    // 1. Missing CAWIDE_SESSION_ID (even with CAWIDE_SOCKET and matching workdir) must be ignored.
    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("claude")
        .current_dir(&workdir)
        .env_remove("CAWIDE_SESSION_ID")
        .env("CAWIDE_SOCKET", server.socket_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(br#"{"hook_event_name":"Stop","last_assistant_message":"ignored"}"#)
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "{}");

    // 2. Missing CAWIDE_SOCKET (even with CAWIDE_SESSION_ID and CAWIDE_CONFIG_DIR) must be ignored.
    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("omp")
        .arg("--event")
        .arg("agent_end")
        .current_dir(&workdir)
        .env("CAWIDE_SESSION_ID", "gated-sess")
        .env("CAWIDE_CONFIG_DIR", &config_dir)
        .env_remove("CAWIDE_SOCKET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(br#"{"summary":"ignored"}"#).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    // Verify session still has no agent state.
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(&mut rsend, 1, &RpcRequest::SessionList))
        .await
        .unwrap();
    match within(read_rpc_response(&mut rrecv)).await.unwrap() {
        Some(RpcFrame {
            request_id: 1,
            payload: RpcResponse::SessionList(Ok(sessions)),
        }) => {
            let s = sessions
                .iter()
                .find(|s| s.session_id == "gated-sess")
                .expect("session must be listed");
            assert!(
                s.agent.is_none(),
                "hook without both CAWIDE_SESSION_ID and CAWIDE_SOCKET must not update session, got {:?}",
                s.agent
            );
        }
        other => panic!("expected SessionList response, got {other:?}"),
    }

    // 3. With both CAWIDE_SESSION_ID and CAWIDE_SOCKET set, hook updates the session.
    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("claude")
        .env("CAWIDE_SESSION_ID", "gated-sess")
        .env("CAWIDE_SOCKET", server.socket_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(br#"{"hook_event_name":"Stop","last_assistant_message":"accepted"}"#)
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    within(write_rpc_request(&mut rsend, 2, &RpcRequest::SessionList))
        .await
        .unwrap();
    match within(read_rpc_response(&mut rrecv)).await.unwrap() {
        Some(RpcFrame {
            request_id: 2,
            payload: RpcResponse::SessionList(Ok(sessions)),
        }) => {
            let s = sessions
                .iter()
                .find(|s| s.session_id == "gated-sess")
                .expect("session must be listed");
            let agent_state = s.agent.as_ref().expect("agent must be set");
            assert_eq!(agent_state.agent, "claude");
            assert_eq!(
                agent_state.status,
                AgentStatus::Completed {
                    summary: "accepted".into()
                }
            );
        }
        other => panic!("expected SessionList response, got {other:?}"),
    }

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_bind_non_default_config_dir_skips_auto_setup() {
    struct EnvRestore {
        home: Option<std::ffi::OsString>,
        config_dir: Option<std::ffi::OsString>,
    }
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match &self.config_dir {
                Some(v) => std::env::set_var("CAWIDE_CONFIG_DIR", v),
                None => std::env::remove_var("CAWIDE_CONFIG_DIR"),
            }
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let temp_home = tmp.path().join("home");
    let omp_agent_dir = temp_home.join(".omp/agent");
    std::fs::create_dir_all(&omp_agent_dir).unwrap();

    let _restore = EnvRestore {
        home: std::env::var_os("HOME"),
        config_dir: std::env::var_os("CAWIDE_CONFIG_DIR"),
    };
    std::env::set_var("HOME", &temp_home);
    std::env::remove_var("CAWIDE_CONFIG_DIR");

    let workdir = tmp.path().join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();
    let config = CawideServerConfig {
        config_dir: tmp.path().join("custom-conf"),
        network_mode: NetworkMode::LocalOnly,
        workdir,
        launch_cmd: None,
        upload_dir: Some(tmp.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };

    let server = within(CawideServer::bind(config)).await.unwrap();
    assert!(
        !omp_agent_dir.join("extensions/cawide.js").exists(),
        "binding CawideServer with non-default config_dir must not run auto_setup_all into HOME"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cli_hook_omp_stream_e2e() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("conf");
    let workdir = tmp.path().join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();

    let config = CawideServerConfig {
        config_dir,
        network_mode: NetworkMode::LocalOnly,
        workdir,
        launch_cmd: Some("sh -c 'sleep 10'".into()),
        upload_dir: Some(tmp.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };

    let server = within(CawideServer::bind(config)).await.unwrap();
    let (_ep, conn) = authorized_client(&server).await;

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("stream-sess", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 1 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("omp")
        .arg("--stream")
        .env("CAWIDE_SESSION_ID", "stream-sess")
        .env("CAWIDE_SOCKET", server.socket_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            r#"{{"event":"before_agent_start","epoch":1,"seq":1,"ts":100,"payload":{{"prompt":"hello"}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"event":"agent_end","epoch":1,"seq":2,"ts":101,"payload":{{"finalTextHead":"All done.","finalTextTail":"All done."}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"event":"session_shutdown","epoch":1,"seq":3,"ts":102,"payload":{{}}}}"#
        )
        .unwrap();
    }

    let start = Instant::now();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(
        start.elapsed() < Duration::from_millis(1500),
        "stream hook must exit within 1.5s on session_shutdown, took {:?}",
        start.elapsed()
    );

    let ev = next_event_matching(
        &mut crecv,
        |ev| matches!(ev, HostEvent::SessionUpdated { summary } if summary.session_id == "stream-sess" && summary.agent.is_some()),
        Duration::from_secs(5),
    )
    .await;
    assert!(ev.is_some(), "expected SessionUpdated from --stream hook");

    server.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn test_rpc_set_push_channel_v2_and_agent_respond_e2e() {
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("conf");
    let workdir = tmp.path().join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();

    let config = CawideServerConfig {
        config_dir,
        network_mode: NetworkMode::LocalOnly,
        workdir,
        launch_cmd: Some("sh -c 'stty raw -echo; printf READY; exec cat'".into()),
        upload_dir: Some(tmp.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };

    let server = within(CawideServer::bind(config)).await.unwrap();
    let (_ep, conn) = authorized_client(&server).await;

    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 1 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("resp-sess", 0, false),
    ))
    .await
    .unwrap();
    let _ = within(read_pty_attach_ack(&mut precv)).await.unwrap();

    let pty = server.registry().get("resp-sess").unwrap();
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    let mut offset = 0u64;
    loop {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        if slice.data.windows(5).any(|w| w == b"READY") {
            break;
        }
        assert!(Instant::now() < ready_deadline, "PTY did not print READY");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;
    let mut req_id = 1u32;
    async fn call_rpc(
        rsend: &mut iroh::endpoint::SendStream,
        rrecv: &mut RecvStream,
        req_id: &mut u32,
        req: RpcRequest,
    ) -> RpcResponse {
        let id = *req_id;
        *req_id += 1;
        within(write_rpc_request(rsend, id, &req)).await.unwrap();
        within(read_rpc_response(rrecv))
            .await
            .unwrap()
            .unwrap()
            .payload
    }

    // 1. SetPushChannelV2 validation over QUIC RPC
    let secret = "0123456789abcdef".repeat(4);
    let ok_v2 = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::SetPushChannelV2 {
            channel: Some(PushChannelV2 {
                channel_id: "chan-v2".into(),
                secret: secret.clone(),
                content_key: vec![0x55; 32],
                caps: PUSH_CAP_E2E_CONTENT,
            }),
        },
    )
    .await;
    assert_eq!(ok_v2, RpcResponse::SetPushChannelV2(Ok(())));

    let bad_v2 = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::SetPushChannelV2 {
            channel: Some(PushChannelV2 {
                channel_id: "chan-v2".into(),
                secret,
                content_key: vec![0x55; 16],
                caps: PUSH_CAP_E2E_CONTENT,
            }),
        },
    )
    .await;
    assert!(matches!(bad_v2, RpcResponse::SetPushChannelV2(Err(_))));
    // 2. Start long-lived omp --stream hook
    let mut child = Command::new(env!("CARGO_BIN_EXE_cawide"))
        .arg("hook")
        .arg("omp")
        .arg("--stream")
        .env("CAWIDE_SESSION_ID", "resp-sess")
        .env("CAWIDE_SOCKET", server.socket_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut hook_stdin = child.stdin.take().unwrap();

    // Thinking rejects Option
    writeln!(
        hook_stdin,
        r#"{{"event":"before_agent_start","epoch":1,"seq":1,"ts":100,"payload":{{"prompt":"hi"}}}}"#
    )
    .unwrap();
    hook_stdin.flush().unwrap();
    assert!(next_event_matching(
        &mut crecv,
        |e| matches!(e, HostEvent::SessionUpdated { summary } if matches!(&summary.agent, Some(a) if matches!(a.status, AgentStatus::Thinking { .. }))),
        Duration::from_secs(5),
    )
    .await
    .is_some());

    let resp = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "hi".into(),
            choice: AgentChoice::Option { index: 0 },
        },
    )
    .await;
    assert_eq!(
        resp,
        RpcResponse::AgentRespond(Err("prompt no longer open".into()))
    );

    // 3. OMP Approval: mismatch rejected, Option 0 sends \x11 after 700ms, Option 1 sends \x1b
    let app_start = Instant::now();
    writeln!(
        hook_stdin,
        r#"{{"event":"tool_approval_requested","epoch":1,"seq":2,"ts":101,"payload":{{"toolName":"bash","toolCallId":"tc-1","command":"ls"}}}}"#
    )
    .unwrap();
    hook_stdin.flush().unwrap();
    assert!(next_event_matching(
        &mut crecv,
        |e| matches!(e, HostEvent::SessionUpdated { summary } if matches!(&summary.agent, Some(a) if matches!(a.status, AgentStatus::WaitingForInput { .. }))),
        Duration::from_secs(5),
    )
    .await
    .is_some());

    let mismatch = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 999_999_999,
            prompt: "Run `ls`?".into(),
            choice: AgentChoice::Option { index: 0 },
        },
    )
    .await;
    assert_eq!(
        mismatch,
        RpcResponse::AgentRespond(Err("prompt no longer open".into()))
    );

    let allow = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "Run `ls`?".into(),
            choice: AgentChoice::Option { index: 0 },
        },
    )
    .await;
    assert_eq!(allow, RpcResponse::AgentRespond(Ok(())));
    assert!(
        app_start.elapsed() >= Duration::from_millis(650),
        "OMP approval allow must wait ~700ms settle window, took {:?}",
        app_start.elapsed()
    );

    let mut captured = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !captured.contains(&0x11) {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        captured.extend_from_slice(&slice.data);
        assert!(Instant::now() < deadline, "expected 0x11 in PTY output");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let deny = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "Run `ls`?".into(),
            choice: AgentChoice::Option { index: 1 },
        },
    )
    .await;
    assert_eq!(deny, RpcResponse::AgentRespond(Ok(())));
    captured.clear();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !captured.contains(&0x1b) {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        captured.extend_from_slice(&slice.data);
        assert!(Instant::now() < deadline, "expected 0x1b in PTY output");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 4. Multi-select Ask rejects Option; single-select Ask sends exact arrows + Other paste
    writeln!(
        hook_stdin,
        r#"{{"event":"tool_approval_resolved","epoch":1,"seq":3,"ts":102,"payload":{{"toolCallId":"tc-1","approved":true}}}}"#
    )
    .unwrap();
    writeln!(
        hook_stdin,
        r#"{{"event":"tool_call","epoch":1,"seq":4,"ts":103,"payload":{{"toolName":"ask","toolCallId":"tc-ask-m","questionsLength":1,"question":"Multi?","options":["A","B"],"multi":true}}}}"#
    )
    .unwrap();
    hook_stdin.flush().unwrap();
    assert!(next_event_matching(
        &mut crecv,
        |e| matches!(e, HostEvent::SessionUpdated { summary } if matches!(&summary.agent, Some(a) if matches!(&a.status, AgentStatus::WaitingForInput { prompt, .. } if prompt == "Multi?"))),
        Duration::from_secs(5),
    )
    .await
    .is_some());

    let multi_err = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "Multi?".into(),
            choice: AgentChoice::Option { index: 0 },
        },
    )
    .await;
    assert_eq!(
        multi_err,
        RpcResponse::AgentRespond(Err("unsupported choice".into()))
    );

    writeln!(
        hook_stdin,
        r#"{{"event":"tool_result","epoch":1,"seq":5,"ts":104,"payload":{{"toolName":"ask","toolCallId":"tc-ask-m","isError":false}}}}"#
    )
    .unwrap();
    writeln!(
        hook_stdin,
        r#"{{"event":"tool_call","epoch":1,"seq":6,"ts":105,"payload":{{"toolName":"ask","toolCallId":"tc-ask-1","questionsLength":1,"question":"Pick","options":["A","B"],"multi":false}}}}"#
    )
    .unwrap();
    hook_stdin.flush().unwrap();
    assert!(next_event_matching(
        &mut crecv,
        |e| matches!(e, HostEvent::SessionUpdated { summary } if matches!(&summary.agent, Some(a) if matches!(&a.status, AgentStatus::WaitingForInput { prompt, .. } if prompt == "Pick"))),
        Duration::from_secs(5),
    )
    .await
    .is_some());

    let ask_opt = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "Pick".into(),
            choice: AgentChoice::Option { index: 1 },
        },
    )
    .await;
    assert_eq!(ask_opt, RpcResponse::AgentRespond(Ok(())));
    let expected_ask_opt = b"\x1b[A\x1b[A\x1b[A\x1b[A\x1b[B\r";
    captured.clear();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !captured
        .windows(expected_ask_opt.len())
        .any(|w| w == expected_ask_opt)
    {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        captured.extend_from_slice(&slice.data);
        assert!(
            Instant::now() < deadline,
            "expected Ask option arrows in PTY output, got {captured:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let ask_text = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "Pick".into(),
            choice: AgentChoice::Text {
                text: "Custom".into(),
            },
        },
    )
    .await;
    assert_eq!(ask_text, RpcResponse::AgentRespond(Ok(())));
    let expected_ask_text = b"\x1b[A\x1b[A\x1b[A\x1b[A\x1b[B\x1b[B\r\x1b[200~Custom\x1b[201~\r";
    captured.clear();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !captured
        .windows(expected_ask_text.len())
        .any(|w| w == expected_ask_text)
    {
        let slice = pty.read_slice(offset);
        offset = slice.end_offset;
        captured.extend_from_slice(&slice.data);
        assert!(
            Instant::now() < deadline,
            "expected Ask Other paste in PTY output, got {captured:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 5. OMP Plan dispatches over AgentStream to hook stdout
    writeln!(
        hook_stdin,
        r#"{{"event":"tool_result","epoch":1,"seq":7,"ts":106,"payload":{{"toolName":"ask","toolCallId":"tc-ask-1","isError":false}}}}"#
    )
    .unwrap();
    writeln!(
        hook_stdin,
        r#"{{"event":"plan_review_requested","epoch":1,"seq":8,"ts":107,"payload":{{"reviewId":"rev-42","title":"Plan","options":[{{"id":"execute","label":"Execute"}},{{"id":"keep","label":"Keep"}}]}}}}"#
    )
    .unwrap();
    hook_stdin.flush().unwrap();
    assert!(next_event_matching(
        &mut crecv,
        |e| matches!(e, HostEvent::SessionUpdated { summary } if matches!(&summary.agent, Some(a) if matches!(&a.status, AgentStatus::WaitingForInput { prompt, .. } if prompt == "Plan"))),
        Duration::from_secs(5),
    )
    .await
    .is_some());

    let plan_resp = call_rpc(
        &mut rsend,
        &mut rrecv,
        &mut req_id,
        RpcRequest::AgentRespond {
            session_id: "resp-sess".into(),
            prompt_id: 0,
            prompt: "Plan".into(),
            choice: AgentChoice::Option { index: 0 },
        },
    )
    .await;
    assert_eq!(plan_resp, RpcResponse::AgentRespond(Ok(())));

    // Give stream a moment to flush stdout before shutdown
    tokio::time::sleep(Duration::from_millis(100)).await;
    writeln!(
        hook_stdin,
        r#"{{"event":"session_shutdown","epoch":1,"seq":9,"ts":108,"payload":{{}}}}"#
    )
    .unwrap();
    drop(hook_stdin);

    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout_str.trim())
        .unwrap_or_else(|e| panic!("expected JSON line on hook stdout, got {stdout_str:?}: {e}"));
    assert_eq!(parsed["type"], "resolve_plan_review");
    assert_eq!(parsed["reviewId"], "rev-42");
    assert_eq!(parsed["choice"], "execute");

    server.shutdown().await.unwrap();
}
