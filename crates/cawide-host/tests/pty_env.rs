use cawide_host::pty::session::{PtySession, PtySpawnOptions};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_pty_environment_deterministic_identity() {
    struct EnvGuard(&'static [&'static str]);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in self.0 {
                // SAFETY: Single-test binary cleanup after execution
                unsafe { std::env::remove_var(key) };
            }
        }
    }
    let _guard = EnvGuard(&[
        "TERM_PROGRAM",
        "GHOSTTY_RESOURCES_DIR",
        "CMUX_SURFACE_ID",
        "TERM_FEATURES",
    ]);
    // SAFETY: This integration test binary executes with a single test, isolating process environment mutations from concurrent reads or writes.
    unsafe {
        std::env::set_var("TERM_PROGRAM", "ghostty");
        std::env::set_var("GHOSTTY_RESOURCES_DIR", "/x");
        std::env::set_var("CMUX_SURFACE_ID", "s1");
        std::env::set_var("TERM_FEATURES", "Sy");
    }

    let opts = PtySpawnOptions {
        launch_cmd: None,
        ..Default::default()
    };
    let session = PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");

    session
        .send_input(
            b"printf 'ID=%s|%s|%s|%s|%s|%s|%s\\n' \"$TERM_PROGRAM\" \"${GHOSTTY_RESOURCES_DIR-unset}\" \"${CMUX_SURFACE_ID-unset}\" \"${TERM_FEATURES-unset}\" \"$PI_FORCE_IMAGE_PROTOCOL\" \"$PI_KITTY_PLACEHOLDERS\" \"$PI_FORCE_SYNC_OUTPUT\"\r\n",
        )
        .expect("send_input failed");

    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    let mut found = false;
    let expected = "ID=cawide|unset|unset|unset|kitty|1|1";
    while start.elapsed() < timeout {
        let slice = session.read_slice(0);
        let text = String::from_utf8_lossy(&slice.data);
        if text.contains(expected) {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let slice = session.read_slice(0);
    let output = String::from_utf8_lossy(&slice.data);
    assert!(
        found,
        "Expected marker {expected:?} not found. Buffer contained:\n{output}"
    );

    let _ = session.send_input(b"exit\n");
}
