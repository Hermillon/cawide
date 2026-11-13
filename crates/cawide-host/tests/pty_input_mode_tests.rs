#![cfg(unix)]

mod common;

use cawide_host::forge::ForgeHostConfig;
use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_protocol::{
    read_pty_attach_ack_chunked, write_pty_attach_header, PtyAttachHeader, PtyChunkDecoder,
    PtyFrame, StreamPurpose, PTY_INPUT_MODE_CANONICAL, PTY_INPUT_MODE_ECHO,
};
use common::{authorized_client, open, within};

async fn create_test_server(tmp_path: &std::path::Path) -> (CawideServer, tempfile::TempDir) {
    let conf = tmp_path.join("conf");
    let server = within(CawideServer::bind(CawideServerConfig {
        config_dir: conf,
        network_mode: NetworkMode::LocalOnly,
        workdir: tmp_path.to_path_buf(),
        launch_cmd: Some(
            "sh -c 'stty echo icanon; printf READY; read a; stty -echo; printf OFF; read b; stty echo; printf ON; sleep 30'".to_string(),
        ),
        upload_dir: None,
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: ForgeHostConfig::default(),
        git_env: Vec::new(),
    }))
    .await
    .unwrap();

    let dummy_dir = tempfile::tempdir().unwrap();
    (server, dummy_dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pty_input_mode_emission_on_echo_change() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let (server, _guard) = create_test_server(&tmp_path).await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Pty).await;
    let header = PtyAttachHeader {
        session_id: "input-mode-sess".to_string(),
        last_ack_offset: 0,
        resume: false,
        accept_compressed_snapshot: true,
        accept_chunked_output: true,
        accept_input_mode_frames: true,
    };
    within(write_pty_attach_header(&mut send, &header))
        .await
        .unwrap();

    let (_ack, chunked) = within(read_pty_attach_ack_chunked(&mut recv))
        .await
        .unwrap();
    assert!(chunked, "must negotiate chunked stream");

    let mut decoder = PtyChunkDecoder::new().unwrap();

    // 1. After READY, an InputMode frame with ECHO|CANONICAL has been received
    let mut saw_ready = false;
    let mut initial_mode = None;
    let expected_mode = PTY_INPUT_MODE_ECHO | PTY_INPUT_MODE_CANONICAL;

    let timeout = std::time::Duration::from_secs(5);
    let start = std::time::Instant::now();
    while (!saw_ready || initial_mode.is_none()) && start.elapsed() < timeout {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            decoder.read_frame(&mut recv),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("frame expected before EOF");
        match frame {
            PtyFrame::Output(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if text.contains("READY") {
                    saw_ready = true;
                }
            }
            PtyFrame::InputMode(mode) => {
                initial_mode = Some(mode);
            }
        }
    }
    assert!(saw_ready, "expected READY output");
    assert_eq!(
        initial_mode,
        Some(expected_mode),
        "expected initial ECHO|CANONICAL mode"
    );

    // 2. Write x\n; within 3 s an InputMode frame equal to CANONICAL (echo off) arrives and OFF is in the output
    tokio::io::AsyncWriteExt::write_all(&mut send, b"x\n")
        .await
        .unwrap();

    let mut saw_off = false;
    let mut echo_off_mode = None;
    let timeout3s = std::time::Duration::from_secs(3);
    let start = std::time::Instant::now();
    while (!saw_off || echo_off_mode.is_none()) && start.elapsed() < timeout3s {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            decoder.read_frame(&mut recv),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("frame expected before EOF");
        match frame {
            PtyFrame::Output(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if text.contains("OFF") {
                    saw_off = true;
                }
            }
            PtyFrame::InputMode(mode) => {
                echo_off_mode = Some(mode);
            }
        }
    }
    assert!(saw_off, "expected OFF output within 3s");
    assert_eq!(
        echo_off_mode,
        Some(PTY_INPUT_MODE_CANONICAL),
        "expected CANONICAL mode (echo off)"
    );

    // 3. Write secret\n; the output after OFF does not contain secret; within 3 s a frame with ECHO|CANONICAL arrives after ON
    tokio::io::AsyncWriteExt::write_all(&mut send, b"secret\n")
        .await
        .unwrap();

    let mut saw_on = false;
    let mut restored_mode = None;
    let mut output_after_off = Vec::new();
    let start = std::time::Instant::now();
    while (!saw_on || restored_mode.is_none()) && start.elapsed() < timeout3s {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            decoder.read_frame(&mut recv),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("frame expected before EOF");
        match frame {
            PtyFrame::Output(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                output_after_off.extend_from_slice(&bytes);
                if text.contains("ON") {
                    saw_on = true;
                }
            }
            PtyFrame::InputMode(mode) => {
                restored_mode = Some(mode);
            }
        }
    }
    assert!(saw_on, "expected ON output within 3s");
    assert_eq!(
        restored_mode,
        Some(expected_mode),
        "expected restored ECHO|CANONICAL mode after ON"
    );
    let after_off_text = String::from_utf8_lossy(&output_after_off);
    assert!(
        !after_off_text.contains("secret"),
        "output after OFF must not contain secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pty_input_mode_disabled_when_not_opted_in() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let (server, _guard) = create_test_server(&tmp_path).await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Pty).await;
    let header = PtyAttachHeader {
        session_id: "no-mode-sess".to_string(),
        last_ack_offset: 0,
        resume: false,
        accept_compressed_snapshot: true,
        accept_chunked_output: true,
        accept_input_mode_frames: false,
    };
    within(write_pty_attach_header(&mut send, &header))
        .await
        .unwrap();

    let (_ack, chunked) = within(read_pty_attach_ack_chunked(&mut recv))
        .await
        .unwrap();
    assert!(chunked, "must negotiate chunked stream");

    let mut decoder = PtyChunkDecoder::new().unwrap();

    // 1. Wait for READY
    let mut saw_ready = false;
    let timeout = std::time::Duration::from_secs(5);
    let start = std::time::Instant::now();
    while !saw_ready && start.elapsed() < timeout {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            decoder.read_frame(&mut recv),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("frame expected before EOF");
        match frame {
            PtyFrame::Output(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if text.contains("READY") {
                    saw_ready = true;
                }
            }
            PtyFrame::InputMode(m) => {
                panic!(
                    "unexpected InputMode frame {m:#04x} when accept_input_mode_frames is false"
                );
            }
        }
    }
    assert!(saw_ready, "expected READY");

    // 2. Write x\n, wait for OFF
    tokio::io::AsyncWriteExt::write_all(&mut send, b"x\n")
        .await
        .unwrap();

    let mut saw_off = false;
    let start = std::time::Instant::now();
    while !saw_off && start.elapsed() < timeout {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            decoder.read_frame(&mut recv),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("frame expected before EOF");
        match frame {
            PtyFrame::Output(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if text.contains("OFF") {
                    saw_off = true;
                }
            }
            PtyFrame::InputMode(m) => {
                panic!(
                    "unexpected InputMode frame {m:#04x} when accept_input_mode_frames is false"
                );
            }
        }
    }
    assert!(saw_off, "expected OFF");

    // 3. Write secret\n, wait for ON
    tokio::io::AsyncWriteExt::write_all(&mut send, b"secret\n")
        .await
        .unwrap();

    let mut saw_on = false;
    let start = std::time::Instant::now();
    while !saw_on && start.elapsed() < timeout {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            decoder.read_frame(&mut recv),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("frame expected before EOF");
        match frame {
            PtyFrame::Output(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if text.contains("ON") {
                    saw_on = true;
                }
            }
            PtyFrame::InputMode(m) => {
                panic!(
                    "unexpected InputMode frame {m:#04x} when accept_input_mode_frames is false"
                );
            }
        }
    }
    assert!(saw_on, "expected ON");
}
