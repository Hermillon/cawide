#![cfg(unix)]

mod common;

use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

use cawide_host::forge::ForgeHostConfig;
use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_protocol::{
    read_pty_attach_ack_chunked, write_pty_attach_header, PtyAttachHeader, PtyChunkDecoder,
    PtyFrame, StreamPurpose,
};
use common::{authorized_client, open, within};

struct CountingReader<R> {
    inner: R,
    count: usize,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, count: 0 }
    }

    fn bytes_read(&self) -> usize {
        self.count
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        self.count += after - before;
        res
    }
}

fn generate_fixture() -> String {
    let mut fixture = String::new();
    for i in 1..=400 {
        let _ = writeln!(
            fixture,
            "\x1b[38;2;10;20;30m{:04} hello world line with padding          \x1b[0m",
            i
        );
    }
    fixture
}

async fn create_test_server(tmp_path: &std::path::Path) -> (CawideServer, tempfile::TempDir) {
    let fixture_content = generate_fixture();
    std::fs::write(tmp_path.join("fixture.txt"), fixture_content.as_bytes()).unwrap();

    let conf = tmp_path.join("conf");
    let server = within(CawideServer::bind(CawideServerConfig {
        config_dir: conf,
        network_mode: NetworkMode::LocalOnly,
        workdir: tmp_path.to_path_buf(),
        launch_cmd: Some("/bin/sh -c 'sleep 0.3; cat fixture.txt; sleep 1'".to_string()),
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
async fn test_pty_chunked_output_compression() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let (server, _guard) = create_test_server(&tmp_path).await;
    let (_ep, conn) = authorized_client(&server).await;

    // First, run legacy attach on "legacy-sess" to get baseline output
    let (mut send_legacy, mut recv_legacy) = open(&conn, StreamPurpose::Pty).await;
    let legacy_header = PtyAttachHeader {
        session_id: "legacy-sess".to_string(),
        last_ack_offset: 0,
        resume: false,
        accept_compressed_snapshot: false,
        accept_chunked_output: false,
        accept_input_mode_frames: false,
    };
    within(write_pty_attach_header(&mut send_legacy, &legacy_header))
        .await
        .unwrap();
    let (_ack_legacy, chunked_legacy) = within(read_pty_attach_ack_chunked(&mut recv_legacy))
        .await
        .unwrap();
    assert!(!chunked_legacy, "legacy attach must not be chunked");

    let mut legacy_bytes = Vec::new();
    let mut raw_buf = [0u8; 4096];
    while !String::from_utf8_lossy(&legacy_bytes).contains("0400") {
        let n = within(recv_legacy.read(&mut raw_buf))
            .await
            .unwrap()
            .expect("unexpected EOF before 0400 in legacy stream");
        assert!(n > 0);
        legacy_bytes.extend_from_slice(&raw_buf[..n]);
    }

    // Now, run chunked attach on "chunked-sess"
    let (mut send_chunked, recv_chunked) = open(&conn, StreamPurpose::Pty).await;
    let chunked_header = PtyAttachHeader {
        session_id: "chunked-sess".to_string(),
        last_ack_offset: 0,
        resume: false,
        accept_compressed_snapshot: true,
        accept_chunked_output: true,
        accept_input_mode_frames: false,
    };
    within(write_pty_attach_header(&mut send_chunked, &chunked_header))
        .await
        .unwrap();

    let mut counting_recv = CountingReader::new(recv_chunked);
    let (_ack_chunked, chunked) = within(read_pty_attach_ack_chunked(&mut counting_recv))
        .await
        .unwrap();
    assert!(chunked, "expected chunked == true");

    let mut decoder = PtyChunkDecoder::new().unwrap();
    let mut decoded_all = Vec::new();
    let mut frame_count = 0;
    let mut framed_bytes_after_first = 0;

    while !String::from_utf8_lossy(&decoded_all).contains("0400") {
        let before = counting_recv.bytes_read();
        let frame = within(decoder.read_frame(&mut counting_recv))
            .await
            .unwrap()
            .expect("expected frame");
        let chunk = match frame {
            PtyFrame::Output(c) => c,
            PtyFrame::InputMode(_) => continue,
        };
        let frame_bytes = counting_recv.bytes_read() - before;
        if frame_count > 0 {
            framed_bytes_after_first += frame_bytes;
        }
        frame_count += 1;
        decoded_all.extend_from_slice(&chunk);
    }

    // Decoded bytes match output of legacy-header attach run on same config
    assert_eq!(
        decoded_all, legacy_bytes,
        "decoded chunked output must match legacy raw output"
    );

    // Total framed bytes after the first frame are < 50% of decoded bytes
    assert!(
        framed_bytes_after_first < decoded_all.len() / 2,
        "framed bytes ({framed_bytes_after_first}) must be < 50% of decoded bytes ({})",
        decoded_all.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pty_legacy_4field_header_unchunked() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let (server, _guard) = create_test_server(&tmp_path).await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Pty).await;

    // Send 4-field header: (session_id, last_ack_offset, resume, accept_compressed_snapshot)
    let v4_tuple = ("v4-sess".to_string(), 0u64, false, true);
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 2]);
    buf = postcard::to_extend(&v4_tuple, buf).unwrap();
    let payload_len = (buf.len() - 2) as u16;
    buf[..2].copy_from_slice(&payload_len.to_be_bytes());
    within(send.write_all(&buf)).await.unwrap();

    // Gets ack with chunked == false
    let (_ack, chunked) = within(read_pty_attach_ack_chunked(&mut recv))
        .await
        .unwrap();
    assert!(!chunked, "4-field header must receive chunked == false");

    // Receives raw stream directly
    let mut raw_bytes = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&raw_bytes).contains("0400") {
        let n = within(recv.read(&mut buf))
            .await
            .unwrap()
            .expect("unexpected EOF before 0400");
        assert!(n > 0);
        raw_bytes.extend_from_slice(&buf[..n]);
    }

    assert!(String::from_utf8_lossy(&raw_bytes).contains("0400"));
}
