//! Integration tests for workspace filesystem watcher (Brick 8).

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_protocol::{
    read_control_message, write_control_message, ControlMessage, HostEvent, StreamPurpose,
};
use common::{authorized_client, open, within};
use iroh::endpoint::{Connection, RecvStream, SendStream};

static PING_SEQ: AtomicU64 = AtomicU64::new(100);

struct TestFixture {
    server: CawideServer,
    _ep: iroh::Endpoint,
    conn: Connection,
    _config_dir: tempfile::TempDir,
    workdir: tempfile::TempDir,
}

impl TestFixture {
    async fn new() -> Self {
        let config_dir = tempfile::tempdir().expect("config tempdir");
        let workdir = tempfile::tempdir().expect("workdir tempdir");

        // Initialize git repo in workdir
        let status = Command::new("git")
            .arg("init")
            .current_dir(workdir.path())
            .status()
            .expect("git init");
        assert!(status.success(), "git init must succeed");

        // Write .gitignore with debug.log
        fs::write(workdir.path().join(".gitignore"), "debug.log\n").expect("write .gitignore");

        let config = CawideServerConfig {
            config_dir: config_dir.path().join("conf"),
            network_mode: NetworkMode::LocalOnly,
            workdir: workdir.path().to_path_buf(),
            launch_cmd: None,
            upload_dir: Some(config_dir.path().join("uploads")),
            opener: None,
            watch_workspace: true,
            port: None,
            external_addr: None,
            relay_url: None,
            forge: cawide_host::forge::ForgeHostConfig::default(),
            git_env: Vec::new(),
        };

        let server = within(CawideServer::bind(config))
            .await
            .expect("server bind");
        let (ep, conn) = authorized_client(&server).await;

        Self {
            server,
            _ep: ep,
            conn,
            _config_dir: config_dir,
            workdir,
        }
    }

    fn workdir_path(&self) -> &Path {
        self.workdir.path()
    }

    async fn shutdown(self) {
        let _ = self.server.shutdown().await;
    }
}

struct EventStream {
    send: SendStream,
    recv: RecvStream,
    buffered: Vec<HostEvent>,
}

impl EventStream {
    async fn open(conn: &Connection) -> Self {
        let (send, recv) = open(conn, StreamPurpose::Control).await;
        Self {
            send,
            recv,
            buffered: Vec::new(),
        }
    }

    async fn drain_stale_events(&mut self) {
        let ping_ts = PING_SEQ.fetch_add(1, Ordering::Relaxed);
        within(write_control_message(
            &mut self.send,
            &ControlMessage::Ping { client_ts: ping_ts },
        ))
        .await
        .expect("write ping");

        // Wait for pong
        loop {
            match within(read_control_message(&mut self.recv))
                .await
                .expect("read pong")
            {
                Some(ControlMessage::Pong { client_ts, .. }) if client_ts == ping_ts => break,
                Some(ControlMessage::HostEvent(_)) => {} // stale event
                Some(other) => panic!("unexpected message before pong: {other:?}"),
                None => panic!("stream closed during ping/pong sync"),
            }
        }

        // Drain until 1s passes with no events, max 5s total
        let start = tokio::time::Instant::now();
        let max_drain = Duration::from_secs(5);
        while start.elapsed() < max_drain {
            match tokio::time::timeout(
                Duration::from_millis(1000),
                read_control_message(&mut self.recv),
            )
            .await
            {
                Ok(Ok(Some(ControlMessage::HostEvent(_)))) => {
                    // Stale event arrived; continue draining
                }
                Ok(Ok(Some(other))) => panic!("unexpected message during drain: {other:?}"),
                Ok(Ok(None)) => panic!("stream closed during drain"),
                Ok(Err(e)) => panic!("stream error during drain: {e}"),
                Err(_) => {
                    // 1 second of silence reached
                    break;
                }
            }
        }
        self.buffered.clear();
    }

    async fn next_event_matching<F>(
        &mut self,
        pred: F,
        timeout: Duration,
    ) -> Result<HostEvent, String>
    where
        F: Fn(&HostEvent) -> bool,
    {
        // Check buffer first
        if let Some(pos) = self.buffered.iter().position(&pred) {
            return Ok(self.buffered.remove(pos));
        }

        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, read_control_message(&mut self.recv)).await {
                Ok(Ok(Some(ControlMessage::HostEvent(event)))) => {
                    if pred(&event) {
                        return Ok(event);
                    } else {
                        self.buffered.push(event);
                    }
                }
                Ok(Ok(Some(_other))) => {}
                Ok(Ok(None)) => return Err("control stream closed early".into()),
                Ok(Err(e)) => return Err(format!("control stream read error: {e}")),
                Err(_) => return Err("timed out waiting for matching event".into()),
            }
        }
        Err("timed out waiting for matching event".into())
    }

    async fn collect_events(&mut self, duration: Duration) -> Vec<HostEvent> {
        let mut events = std::mem::take(&mut self.buffered);
        let deadline = tokio::time::Instant::now() + duration;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, read_control_message(&mut self.recv)).await {
                Ok(Ok(Some(ControlMessage::HostEvent(event)))) => {
                    events.push(event);
                }
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) => break,
                Ok(Err(_)) => break,
                Err(_) => break, // timeout reached
            }
        }
        events
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_file_emits_fs_changed_and_git_changed() {
    let fixture = TestFixture::new().await;
    let mut stream = EventStream::open(&fixture.conn).await;
    stream.drain_stale_events().await;

    // Write a.txt
    let file_path = fixture.workdir_path().join("a.txt");
    fs::write(&file_path, "hello world").expect("write a.txt");

    // Must emit FsChanged naming a.txt within 3s
    let fs_ev = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::FsChanged { paths, .. } if paths.iter().any(|p| p == "a.txt")),
            Duration::from_secs(3),
        )
        .await
        .expect("FsChanged containing a.txt within 3s");

    if let HostEvent::FsChanged { paths, .. } = fs_ev {
        assert!(paths.contains(&"a.txt".to_string()));
    }

    // Must emit GitChanged within 3s
    let _git_ev = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::GitChanged { .. }),
            Duration::from_secs(3),
        )
        .await
        .expect("GitChanged within 3s");

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_ignored_dirs_and_files_emits_nothing() {
    let fixture = TestFixture::new().await;
    let mut stream = EventStream::open(&fixture.conn).await;
    stream.drain_stale_events().await;

    // Write node_modules/x.js, target/y, and debug.log
    let nm = fixture.workdir_path().join("node_modules");
    fs::create_dir_all(&nm).expect("create node_modules");
    fs::write(nm.join("x.js"), "console.log('x');").expect("write x.js");

    let target = fixture.workdir_path().join("target");
    fs::create_dir_all(&target).expect("create target");
    fs::write(target.join("y"), "target binary").expect("write target/y");

    fs::write(fixture.workdir_path().join("debug.log"), "debug output").expect("write debug.log");

    // Within 1.5s, no FsChanged naming node_modules/, target/, debug.log, and no empty-paths FsChanged
    let events = stream.collect_events(Duration::from_millis(1500)).await;

    for ev in &events {
        if let HostEvent::FsChanged { paths, .. } = ev {
            assert!(
                !paths.is_empty(),
                "must not emit empty-paths FsChanged for ignored changes"
            );
            for p in paths {
                assert!(
                    !p.starts_with("node_modules"),
                    "unexpected node_modules path: {p}"
                );
                assert!(!p.starts_with("target"), "unexpected target path: {p}");
                assert_ne!(p, "debug.log", "unexpected debug.log path");
            }
        }
    }

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_500_burst_cap() {
    let fixture = TestFixture::new().await;
    let mut stream = EventStream::open(&fixture.conn).await;
    stream.drain_stale_events().await;

    // Write 500 files in one burst
    for i in 0..500 {
        let name = format!("burst_{i}.txt");
        fs::write(fixture.workdir_path().join(name), "burst").expect("write burst file");
    }

    // Collect events for 3s
    let events = stream.collect_events(Duration::from_secs(3)).await;

    let fs_events: Vec<_> = events
        .into_iter()
        .filter(|e| matches!(e, HostEvent::FsChanged { .. }))
        .collect();

    // All events must have <= 200 paths or be empty (refresh-all)
    assert!(
        !fs_events.is_empty() && fs_events.len() <= 20,
        "expected between 1 and 20 FsChanged events, got {}",
        fs_events.len()
    );
    for ev in &fs_events {
        if let HostEvent::FsChanged { paths, .. } = ev {
            assert!(
                paths.len() <= 200 || paths.is_empty(),
                "each FsChanged must have <= 200 paths or be empty (refresh-all), got {}",
                paths.len()
            );
        }
    }

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_churn_immunity() {
    let fixture = TestFixture::new().await;
    let mut stream = EventStream::open(&fixture.conn).await;
    stream.drain_stale_events().await;

    let target_dir = fixture.workdir_path().join("target");
    fs::create_dir_all(&target_dir).expect("create target dir");

    let spam_file = target_dir.join("spam");
    let a_file = fixture.workdir_path().join("a.txt");

    // Background task touching target/spam every 50ms for 3s
    let spam_handle = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(3000);
        let mut i = 0u64;
        while tokio::time::Instant::now() < deadline {
            let _ = fs::write(&spam_file, format!("spam {i}"));
            i += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    // Write a.txt at 0.5s
    tokio::time::sleep(Duration::from_millis(500)).await;
    fs::write(&a_file, "a content").expect("write a.txt");

    // An FsChanged naming a.txt arrives within 2s of the write
    let ev = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::FsChanged { paths, .. } if paths.iter().any(|p| p == "a.txt")),
            Duration::from_secs(2),
        )
        .await
        .expect("FsChanged naming a.txt within 2s of write");

    if let HostEvent::FsChanged { paths, .. } = ev {
        assert!(paths.contains(&"a.txt".to_string()));
    }

    let _ = spam_handle.await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_git_add_emits_git_changed_no_dotgit_fs_changed() {
    let fixture = TestFixture::new().await;
    let mut stream = EventStream::open(&fixture.conn).await;
    stream.drain_stale_events().await;

    // Create a.txt and wait for its FsChanged/GitChanged to be consumed
    let a_path = fixture.workdir_path().join("a.txt");
    fs::write(&a_path, "initial").expect("write a.txt");

    let _ = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::FsChanged { paths, .. } if paths.iter().any(|p| p == "a.txt")),
            Duration::from_secs(3),
        )
        .await;
    let _ = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::GitChanged { .. }),
            Duration::from_secs(3),
        )
        .await;

    // Drain any remaining events
    let _ = stream.collect_events(Duration::from_millis(300)).await;

    // Run git add a.txt
    let status = Command::new("git")
        .args(["add", "a.txt"])
        .current_dir(fixture.workdir_path())
        .status()
        .expect("git add");
    assert!(status.success());

    // Expect GitChanged within 3s
    let git_ev = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::GitChanged { .. }),
            Duration::from_secs(3),
        )
        .await
        .expect("GitChanged on git add");
    assert!(matches!(git_ev, HostEvent::GitChanged { .. }));

    // Check all events collected: none should have .git paths in FsChanged
    let events = stream.collect_events(Duration::from_millis(500)).await;
    for ev in events {
        if let HostEvent::FsChanged { paths, .. } = ev {
            for p in paths {
                assert!(
                    !p.starts_with(".git/") && p != ".git",
                    "unexpected .git path in FsChanged: {p}"
                );
            }
        }
    }

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gitignore_update_reloads_and_ignores_subsequent_writes() {
    let fixture = TestFixture::new().await;
    let mut stream = EventStream::open(&fixture.conn).await;
    stream.drain_stale_events().await;

    // Append b.txt to .gitignore
    let gitignore_path = fixture.workdir_path().join(".gitignore");
    let mut content = fs::read_to_string(&gitignore_path).unwrap_or_default();
    content.push_str("b.txt\n");
    fs::write(&gitignore_path, &content).expect("update .gitignore");

    // Wait for watcher to observe and reload .gitignore
    let _ = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::FsChanged { paths, .. } if paths.iter().any(|p| p == ".gitignore")),
            Duration::from_secs(3),
        )
        .await
        .expect("FsChanged containing .gitignore");

    // Write b.txt
    fs::write(fixture.workdir_path().join("b.txt"), "ignored b").expect("write b.txt");

    // Write c.txt (not ignored) to verify watcher detects non-ignored changes
    fs::write(fixture.workdir_path().join("c.txt"), "c content").expect("write c.txt");

    // An FsChanged naming c.txt should arrive within 3s
    let c_ev = stream
        .next_event_matching(
            |e| matches!(e, HostEvent::FsChanged { paths, .. } if paths.iter().any(|p| p == "c.txt")),
            Duration::from_secs(3),
        )
        .await
        .expect("FsChanged containing c.txt within 3s");

    if let HostEvent::FsChanged { paths, .. } = &c_ev {
        assert!(
            !paths.contains(&"b.txt".to_string()),
            "b.txt should be ignored after .gitignore update"
        );
    }
    // None of the collected events must contain b.txt
    let events = stream.collect_events(Duration::from_millis(500)).await;
    for ev in events {
        if let HostEvent::FsChanged { paths, .. } = ev {
            assert!(
                !paths.contains(&"b.txt".to_string()),
                "b.txt should be ignored after .gitignore update"
            );
        }
    }

    fixture.shutdown().await;
}
