use cawide_host::pty::session::{PtySession, PtySpawnOptions};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_pty_end_to_end_replay_and_underrun() {
    let opts = PtySpawnOptions {
        launch_cmd: None,
        ..Default::default()
    };
    let session = PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");

    // Head offset should start at 0
    assert_eq!(session.tail_offset(), 0);

    // Send a command that emits identifiable markers
    session
        .send_input(b"echo ALPHA_MARKER && echo BETA_MARKER\r\n")
        .expect("send_input failed");

    // Wait until output is buffered
    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    let mut found = false;
    while start.elapsed() < timeout {
        let slice = session.read_slice(0);
        let text = String::from_utf8_lossy(&slice.data);
        if text.contains("ALPHA_MARKER") && text.contains("BETA_MARKER") {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(found, "Markers not found in buffer");

    // Validate monotonic offset progression
    let head = session.head_offset();
    assert!(head > 0);

    // Query from offset 0: should return all data without underrun
    let slice0 = session.read_slice(0);
    assert!(!slice0.underrun);
    assert_eq!(slice0.start_offset, 0);
    assert_eq!(slice0.end_offset, head);

    // Query from head: should return empty data
    let slice_head = session.read_slice(head);
    assert!(!slice_head.underrun);
    assert!(slice_head.data.is_empty());
    assert_eq!(slice_head.start_offset, head);
    assert_eq!(slice_head.end_offset, head);

    // Clean exit
    session.send_input(b"exit\n").expect("exit failed");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while session.is_alive() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!session.is_alive());
}
