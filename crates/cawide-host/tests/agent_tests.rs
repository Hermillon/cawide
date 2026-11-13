//! Integration tests for agent telemetry, hooks, and shell setup (Brick 7).

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cawide_host::agent::setup::run_setup;
use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_protocol::types::{AgentStatus, HostEvent, RpcFrame, RpcRequest, RpcResponse};
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
    assert!(omp_content.starts_with("// cawide-telemetry"));
    // OpenCode setup
    let opencode_summary = run_setup(home, &exe, "opencode", false).unwrap();
    assert!(!opencode_summary.is_empty());
    let opencode_file = home.join(".config/opencode/plugins/cawide.js");
    assert!(opencode_file.exists());
    let opencode_content = std::fs::read_to_string(&opencode_file).unwrap();
    assert!(opencode_content.starts_with("// cawide-telemetry"));
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
