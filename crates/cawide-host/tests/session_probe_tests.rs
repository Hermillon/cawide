//! End-to-end integration tests for background session probing (Step 2i).
//!
//! Scenarios tested:
//! 1. `cd sub` updates session `cwd` and `git_root`
//! 2. Terminal title escape sequence updates session `title`
//! 3. Filesystem watcher dynamically follows session `cwd`
//! 4. Fake `omp` agent: Thinking held >=16s -> Completed -> None
//! 5. `git init` in existing workdir without `cd` updates `git_root`

mod common;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
#[cfg(unix)]
use cawide_protocol::types::AgentStatus;
use cawide_protocol::types::{HostEvent, PtyAttachAck, PtyAttachHeader};
use cawide_protocol::{
    read_control_message, read_pty_attach_ack, write_control_message, write_pty_attach_header,
    ControlMessage, StreamPurpose,
};
use common::{authorized_client, open, within};
use iroh::endpoint::RecvStream;
use tokio::io::AsyncWriteExt;

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

struct TestServer {
    server: CawideServer,
    workdir: PathBuf,
    _tmp: tempfile::TempDir,
}

impl TestServer {
    async fn start(watch_workspace: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("workdir");
        std::fs::create_dir_all(&workdir).unwrap();
        let config_dir = tmp.path().join("conf");
        let upload_dir = tmp.path().join("uploads");

        let config = CawideServerConfig {
            config_dir,
            network_mode: NetworkMode::LocalOnly,
            workdir: workdir.clone(),
            launch_cmd: None,
            upload_dir: Some(upload_dir),
            opener: None,
            watch_workspace,
            port: None,
            external_addr: None,
            relay_url: None,
            forge: cawide_host::forge::ForgeHostConfig::default(),
            git_env: Vec::new(),
        };

        let server = within(CawideServer::bind(config)).await.unwrap();
        Self {
            server,
            workdir,
            _tmp: tmp,
        }
    }

    fn workdir(&self) -> PathBuf {
        self.workdir.canonicalize().unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_probe_cd_sub_updates_cwd_and_git_root() {
    let fixture = TestServer::start(true).await;
    let workdir = fixture.workdir();

    // Initialize git repository at workdir root
    Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&workdir)
        .status()
        .unwrap();

    let sub = workdir.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let sub_canon = sub.canonicalize().unwrap();

    let (_ep, conn) = authorized_client(&fixture.server).await;
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;

    // Ping sync
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 1 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    // Attach PTY
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("sess-cd", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    // Send `cd sub` command to shell
    psend.write_all(b"cd sub\n").await.unwrap();
    psend.flush().await.unwrap();

    // Wait for SessionUpdated event with updated cwd and git_root
    let ev = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-cd"
                    && summary.workdir == sub_canon.display().to_string()
            }
            _ => false,
        },
        Duration::from_secs(6),
    )
    .await
    .expect("SessionUpdated with new sub cwd");

    match ev {
        HostEvent::SessionUpdated { summary } => {
            assert_eq!(summary.workdir, sub_canon.display().to_string());
            assert_eq!(summary.git_root, Some(workdir.display().to_string()));
        }
        _ => panic!("unexpected event"),
    }

    fixture.server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_probe_title_updates() {
    let fixture = TestServer::start(false).await;
    let (_ep, conn) = authorized_client(&fixture.server).await;
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;

    // Ping sync
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 2 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    // Attach PTY
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("sess-title", 0, false),
    ))
    .await
    .unwrap();
    let _ = within(read_pty_attach_ack(&mut precv)).await.unwrap();

    // Send OSC title escape code
    psend
        .write_all(b"printf '\\033]0;cawide-probe-title\\007'; sleep 5\n")
        .await
        .unwrap();
    psend.flush().await.unwrap();

    // Wait for SessionUpdated with title set
    let ev = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-title"
                    && summary.title.as_deref() == Some("cawide-probe-title")
            }
            _ => false,
        },
        Duration::from_secs(15),
    )
    .await
    .expect("SessionUpdated with updated title");

    if let HostEvent::SessionUpdated { summary } = ev {
        assert_eq!(summary.title.as_deref(), Some("cawide-probe-title"));
    }

    fixture.server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_probe_watcher_follows_cwd() {
    let fixture = TestServer::start(true).await;
    let outside = fixture._tmp.path().join("outside_dir");
    std::fs::create_dir_all(&outside).unwrap();
    let outside_canon = outside.canonicalize().unwrap();

    let (_ep, conn) = authorized_client(&fixture.server).await;
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;

    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 3 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("sess-watch", 0, false),
    ))
    .await
    .unwrap();
    let _ = within(read_pty_attach_ack(&mut precv)).await.unwrap();

    // CD outside of the workspace into outside_canon
    let cd_cmd = format!("cd {}\n", outside_canon.display());
    psend.write_all(cd_cmd.as_bytes()).await.unwrap();
    psend.flush().await.unwrap();

    // Wait until probe picks up the outside cwd
    let _ = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-watch"
                    && summary.workdir == outside_canon.display().to_string()
            }
            _ => false,
        },
        Duration::from_secs(6),
    )
    .await
    .expect("SessionUpdated to outside_dir");

    // Wait a brief moment for watcher sync to attach to outside_dir
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create a file in outside_canon
    let test_file = outside_canon.join("followed.txt");
    std::fs::write(&test_file, b"content").unwrap();

    // Expect FsChanged for outside_dir root naming followed.txt
    let ev = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::FsChanged { root, paths } => {
                root == &outside_canon.display().to_string()
                    && (paths.is_empty() || paths.iter().any(|p| p == "followed.txt"))
            }
            _ => false,
        },
        Duration::from_secs(6),
    )
    .await
    .expect("FsChanged event from followed cwd");

    assert!(matches!(ev, HostEvent::FsChanged { .. }));
    fixture.server.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn test_probe_fake_omp_thinking_held_completed_none() {
    let fixture = TestServer::start(false).await;
    let workdir = fixture.workdir();

    // Create a fake `omp` executable in workdir/bin
    let bin_dir = workdir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let omp_path = bin_dir.join("omp");

    let omp_script =
        "#!/bin/sh\nprintf '\\033]9;4;3\\007'\nsleep 20\nprintf '\\033]9;4;0;\\007'\nsleep 60\n";
    std::fs::write(&omp_path, omp_script).unwrap();
    std::fs::set_permissions(&omp_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let (_ep, conn) = authorized_client(&fixture.server).await;
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;

    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 4 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("sess-omp", 0, false),
    ))
    .await
    .unwrap();
    let _ = within(read_pty_attach_ack(&mut precv)).await.unwrap();

    // Execute the fake omp script under the shell
    let run_cmd = format!("{}\n", omp_path.display());
    psend.write_all(run_cmd.as_bytes()).await.unwrap();
    psend.flush().await.unwrap();
    // 1. Expect Thinking
    let ev1 = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-omp"
                    && matches!(
                        &summary.agent,
                        Some(s) if s.agent == "omp" && matches!(s.status, AgentStatus::Thinking { .. })
                    )
            }
            _ => false,
        },
        Duration::from_secs(6),
    )
    .await
    .expect("AgentStatus::Thinking for omp");
    assert!(matches!(ev1, HostEvent::SessionUpdated { .. }));

    let thinking_start = Instant::now();

    // 2. Expect Completed when sleep 16 finishes and \033]9;4;0\007 is emitted
    let ev2 = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-omp"
                    && matches!(
                        &summary.agent,
                        Some(s) if s.agent == "omp" && matches!(s.status, AgentStatus::Completed { .. })
                    )
            }
            _ => false,
        },
        Duration::from_secs(35),
    )
    .await
    .expect("AgentStatus::Completed after held >= 16s");

    let held_duration = thinking_start.elapsed();
    assert!(
        held_duration >= Duration::from_secs(16),
        "Thinking must be held for >=16s, took {held_duration:?}"
    );
    assert!(matches!(ev2, HostEvent::SessionUpdated { .. }));

    // 3. Send Ctrl-C (\x03) to interrupt sleep 60 and return to shell, clearing agent
    psend.write_all(b"\x03").await.unwrap();
    psend.flush().await.unwrap();

    let ev3 = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-omp" && summary.agent.is_none()
            }
            _ => false,
        },
        Duration::from_secs(10),
    )
    .await
    .expect("Agent becomes None after omp is interrupted");
    assert!(matches!(ev3, HostEvent::SessionUpdated { .. }));

    fixture.server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_probe_git_init_without_cd_updates_git_root() {
    let fixture = TestServer::start(false).await;
    let workdir = fixture.workdir();

    let (_ep, conn) = authorized_client(&fixture.server).await;
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;

    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 5 },
    ))
    .await
    .unwrap();
    let _ = within(read_control_message(&mut crecv)).await.unwrap();

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("sess-git-init", 0, false),
    ))
    .await
    .unwrap();
    let _ = within(read_pty_attach_ack(&mut precv)).await.unwrap();

    // Now run git init in workdir from the outside
    Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&workdir)
        .status()
        .unwrap();

    // Wait for SessionUpdated with git_root detected on next probe
    let ev = next_event_matching(
        &mut crecv,
        |e| match e {
            HostEvent::SessionUpdated { summary } => {
                summary.session_id == "sess-git-init"
                    && summary.git_root == Some(workdir.display().to_string())
            }
            _ => false,
        },
        Duration::from_secs(6),
    )
    .await
    .expect("SessionUpdated with newly initialized git_root");

    match ev {
        HostEvent::SessionUpdated { summary } => {
            assert_eq!(summary.git_root, Some(workdir.display().to_string()));
        }
        _ => panic!("unexpected event"),
    }

    fixture.server.shutdown().await.unwrap();
}
