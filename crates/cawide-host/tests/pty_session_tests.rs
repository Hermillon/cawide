use cawide_host::pty::error::PtyError;
use cawide_host::pty::session::{PtySession, PtySpawnOptions};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_invalid_dimensions() {
    let opts = PtySpawnOptions::default();
    let res0 = PtySession::spawn(0, 24, opts.clone());
    assert!(matches!(res0, Err(PtyError::InvalidDimensions(0, 24))));

    let res1 = PtySession::spawn(80, 0, opts);
    assert!(matches!(res1, Err(PtyError::InvalidDimensions(80, 0))));
}

#[tokio::test]
async fn test_spawn_command_and_streaming() {
    let opts = PtySpawnOptions {
        launch_cmd: None,
        ..Default::default()
    };
    let session = PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");
    let mut rx = session.subscribe();

    assert!(session.is_alive());

    // Send echo command
    session
        .send_input(b"echo CAWIDE_TEST_OK\r\n")
        .expect("send_input failed");

    // Listen to broadcast receiver
    let mut accumulated = Vec::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Ok(bytes)) => {
                accumulated.extend_from_slice(&bytes);
                let text = String::from_utf8_lossy(&accumulated);
                if text.contains("CAWIDE_TEST_OK") {
                    break;
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => {
                // Timeout, check ring buffer directly
                let slice = session.read_slice(0);
                let text = String::from_utf8_lossy(&slice.data);
                if text.contains("CAWIDE_TEST_OK") {
                    break;
                }
            }
        }
    }

    let full_text = String::from_utf8_lossy(&accumulated);
    let slice = session.read_slice(0);
    let slice_text = String::from_utf8_lossy(&slice.data);
    assert!(
        full_text.contains("CAWIDE_TEST_OK") || slice_text.contains("CAWIDE_TEST_OK"),
        "expected output to contain CAWIDE_TEST_OK, got accumulated: {:?}, slice: {:?}",
        full_text,
        slice_text
    );

    // Test resize
    session.resize(120, 40).expect("resize failed");

    // Clean exit
    session.send_input(b"exit\r\n").expect("exit failed");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while session.is_alive() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!session.is_alive());
}

#[tokio::test]
async fn test_kill_lifecycle() {
    let opts = PtySpawnOptions {
        launch_cmd: None,
        ..Default::default()
    };
    let session = PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");
    assert!(session.is_alive());

    session.kill().expect("kill failed");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while session.is_alive() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!session.is_alive());
}

#[tokio::test]
async fn test_eof_signal_on_child_exit() {
    let opts = PtySpawnOptions {
        launch_cmd: if cfg!(windows) {
            Some("cmd.exe /c exit 0".to_string())
        } else {
            Some("/bin/sh -c \"exit 0\"".to_string())
        },
        ..Default::default()
    };
    let session = PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");
    let mut rx = session.subscribe_eof();

    let res = tokio::time::timeout(Duration::from_secs(3), rx.wait_for(|v| *v)).await;
    assert!(
        matches!(res, Ok(Ok(_))),
        "expected EOF signal to flip to true, got {:?}",
        res
    );
}

#[tokio::test]
async fn test_send_input_async_large_paste_roundtrip() {
    let opts = PtySpawnOptions {
        launch_cmd: Some("cat".to_string()),
        ..Default::default()
    };
    let session = PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");

    // Construct 8 KiB payload: 128 lines of 64 bytes each ending in '\n'
    let mut payload = Vec::with_capacity(8192);
    for i in 0..128 {
        let line = format!("LINE {:03}: {:<53}\n", i, "x");
        assert_eq!(line.len(), 64);
        payload.extend_from_slice(line.as_bytes());
    }
    assert_eq!(payload.len(), 8192);

    session
        .send_input_async(bytes::Bytes::from(payload))
        .await
        .expect("send_input_async failed");

    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    let mut slice = session.read_slice(0);
    while start.elapsed() < timeout {
        slice = session.read_slice(0);
        let text = String::from_utf8_lossy(&slice.data);
        if text.contains("LINE 127:") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let text = String::from_utf8_lossy(&slice.data);
    let mut last_idx = 0;
    for i in 0..128 {
        let marker = format!("LINE {:03}:", i);
        let idx = text[last_idx..].find(&marker).unwrap_or_else(|| {
            panic!("marker {marker} not found after index {last_idx} in output")
        });
        last_idx += idx + marker.len();
    }
    assert!(
        slice.data.len() >= 8192,
        "expected at least 8192 bytes in ring buffer, got {}",
        slice.data.len()
    );

    let _ = session.kill();
}
