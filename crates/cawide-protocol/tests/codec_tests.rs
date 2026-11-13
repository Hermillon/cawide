//! Codec framing, stream purpose, and boundary security tests

use cawide_protocol::*;
use tokio::io::{duplex, AsyncWriteExt};

#[tokio::test]
async fn test_stream_purpose_roundtrip_and_errors() {
    let (mut client, mut server) = duplex(64);

    // Write Pty purpose
    write_stream_purpose(&mut client, StreamPurpose::Pty)
        .await
        .expect("write failed");
    let received = read_stream_purpose(&mut server).await.expect("read failed");
    assert_eq!(received, Some(StreamPurpose::Pty));

    // Write Control purpose
    write_stream_purpose(&mut client, StreamPurpose::Control)
        .await
        .expect("write failed");
    let received = read_stream_purpose(&mut server).await.expect("read failed");
    assert_eq!(received, Some(StreamPurpose::Control));

    // Write Rpc purpose
    write_stream_purpose(&mut client, StreamPurpose::Rpc)
        .await
        .expect("write failed");
    let received = read_stream_purpose(&mut server).await.expect("read failed");
    assert_eq!(received, Some(StreamPurpose::Rpc));
    // Write Tunnel purpose
    write_stream_purpose(&mut client, StreamPurpose::Tunnel)
        .await
        .expect("write failed");
    let received = read_stream_purpose(&mut server).await.expect("read failed");
    assert_eq!(received, Some(StreamPurpose::Tunnel));

    // Purpose 0x01 is no longer valid; 0x04 is Pty
    assert!(matches!(
        StreamPurpose::try_from(0x01),
        Err(ProtocolError::InvalidStreamPurpose(0x01))
    ));
    assert!(matches!(
        StreamPurpose::try_from(0x04),
        Ok(StreamPurpose::Pty)
    ));
    assert!(matches!(
        StreamPurpose::try_from(0x05),
        Ok(StreamPurpose::Tunnel)
    ));

    // Write invalid purpose byte
    client.write_u8(0x99).await.expect("raw write failed");
    client.flush().await.expect("flush failed");
    let err = read_stream_purpose(&mut server).await.unwrap_err();
    match err {
        ProtocolError::InvalidStreamPurpose(b) => assert_eq!(b, 0x99),
        other => panic!("Unexpected error: {other:?}"),
    }

    // Clean EOF on close
    drop(client);
    let eof = read_stream_purpose(&mut server).await.expect("read failed");
    assert_eq!(eof, None);
}

#[tokio::test]
async fn test_pty_attach_header_codec() {
    let (mut client, mut server) = duplex(1024);

    let header = PtyAttachHeader::new("test-sess-001", 98765, false);

    write_pty_attach_header(&mut client, &header)
        .await
        .expect("write failed");
    let decoded = read_pty_attach_header(&mut server)
        .await
        .expect("read failed")
        .expect("expected header");
    assert_eq!(header, decoded);

    // Clean EOF
    drop(client);
    let eof = read_pty_attach_header(&mut server)
        .await
        .expect("read failed");
    assert_eq!(eof, None);
}
#[tokio::test]
async fn test_pty_attach_header_legacy_compat() {
    let (mut client, mut server) = duplex(1024);

    // Encode a 3-field tuple matching legacy (session_id, last_ack_offset, resume)
    let legacy_payload = (String::from("legacy-sess-123"), 12345u64, true);
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 2]);
    buf = postcard::to_extend(&legacy_payload, buf).expect("postcard serialization");
    let payload_len = (buf.len() - 2) as u16;
    buf[..2].copy_from_slice(&payload_len.to_be_bytes());

    tokio::io::AsyncWriteExt::write_all(&mut client, &buf)
        .await
        .expect("write failed");
    tokio::io::AsyncWriteExt::flush(&mut client)
        .await
        .expect("flush failed");

    let decoded = read_pty_attach_header(&mut server)
        .await
        .expect("read failed")
        .expect("expected header");
    assert_eq!(decoded.session_id, "legacy-sess-123");
    assert_eq!(decoded.last_ack_offset, 12345);
    assert!(decoded.resume);
    assert!(!decoded.accept_compressed_snapshot);
}

#[tokio::test]
async fn test_pty_attach_header_truncation() {
    // 1-byte partial header then EOF
    let (mut client, mut server) = duplex(1024);
    client.write_u8(0x00).await.expect("write failed");
    drop(client);
    let err = read_pty_attach_header(&mut server).await.unwrap_err();
    assert!(matches!(err, ProtocolError::UnexpectedEof));

    // Full 2-byte header with incomplete payload then EOF
    let (mut client2, mut server2) = duplex(1024);
    client2
        .write_all(&20u16.to_be_bytes())
        .await
        .expect("write failed");
    client2.write_all(b"short").await.expect("write failed");
    drop(client2);
    let err = read_pty_attach_header(&mut server2).await.unwrap_err();
    assert!(matches!(err, ProtocolError::UnexpectedEof));
}

#[tokio::test]
async fn test_control_message_codec_and_attack_prevention() {
    let (mut client, mut server) = duplex(4096);

    let msg = ControlMessage::Resize {
        cols: 160,
        rows: 48,
    };

    write_control_message(&mut client, &msg)
        .await
        .expect("write failed");
    let decoded = read_control_message(&mut server)
        .await
        .expect("read failed")
        .expect("expected msg");
    assert_eq!(msg, decoded);

    // Clean EOF
    let (client2, mut server2) = duplex(1024);
    drop(client2);
    let eof = read_control_message(&mut server2)
        .await
        .expect("read failed");
    assert_eq!(eof, None);

    // Truncated header
    let (mut client3, mut server3) = duplex(1024);
    client3
        .write_all(&[0x00, 0x01])
        .await
        .expect("write failed");
    drop(client3);
    let err = read_control_message(&mut server3).await.unwrap_err();
    assert!(matches!(err, ProtocolError::UnexpectedEof));

    // Oversized frame attack (exceeding MAX_CONTROL_FRAME_SIZE)
    let (mut client4, mut server4) = duplex(1024);
    let oversized_len = (MAX_CONTROL_FRAME_SIZE + 1) as u32;
    client4
        .write_all(&oversized_len.to_be_bytes())
        .await
        .expect("write failed");
    client4.flush().await.expect("flush failed");
    let err = read_control_message(&mut server4).await.unwrap_err();
    match err {
        ProtocolError::FrameTooLarge { size, max } => {
            assert_eq!(size, MAX_CONTROL_FRAME_SIZE + 1);
            assert_eq!(max, MAX_CONTROL_FRAME_SIZE);
        }
        other => panic!("Unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn test_rpc_wire_format_and_codec() {
    let (mut client, mut server) = duplex(8192);

    let req = RpcRequest::Git {
        root: "/repo".to_string(),
        op: GitOp::Status,
    };
    write_rpc_request(&mut client, 101, &req)
        .await
        .expect("write failed");

    // Read back frame
    let frame = read_rpc_request(&mut server)
        .await
        .expect("read failed")
        .expect("expected frame");
    assert_eq!(frame.request_id, 101);
    assert_eq!(frame.payload, req);

    // Test RPC Response
    let resp = RpcResponse::Git {
        result: Ok(GitReply::Status {
            status: GitRepoStatus {
                head: GitHead::Branch {
                    name: "feature/fast-pty".to_string(),
                    oid: Some("1234567".to_string()),
                },
                upstream: None,
                entries: vec![GitStatusEntry {
                    path: "crates/cawide-protocol/src/codec.rs".to_string(),
                    orig_path: None,
                    index: GitChange::Unmodified,
                    worktree: GitChange::Modified,
                    conflict: None,
                    staged_stats: None,
                    unstaged_stats: None,
                }],
                entries_truncated: false,
                total_entries: 1,
                operation: None,
                stash_count: 0,
                lfs: GitLfsState::NotUsed,
            },
        }),
    };
    write_rpc_response(&mut client, 101, &resp)
        .await
        .expect("write failed");

    let resp_frame = read_rpc_response(&mut server)
        .await
        .expect("read failed")
        .expect("expected frame");
    assert_eq!(resp_frame.request_id, 101);
    assert_eq!(resp_frame.payload, resp);

    // Verify raw wire format: [request_id: 4B BE][payload_length: 4B BE][postcard payload]
    let (mut raw_writer, mut raw_reader) = duplex(1024);
    let simple_req = RpcRequest::Git {
        root: "/repo".to_string(),
        op: GitOp::Status,
    };
    let expected_payload = postcard::to_allocvec(&simple_req).unwrap();
    write_rpc_request(&mut raw_writer, 777, &simple_req)
        .await
        .expect("write failed");

    let mut raw_bytes = vec![0u8; 8 + expected_payload.len()];
    use tokio::io::AsyncReadExt;
    raw_reader
        .read_exact(&mut raw_bytes)
        .await
        .expect("read raw failed");

    assert_eq!(&raw_bytes[0..4], &777u32.to_be_bytes());
    assert_eq!(
        &raw_bytes[4..8],
        &(expected_payload.len() as u32).to_be_bytes()
    );
    assert_eq!(&raw_bytes[8..], expected_payload.as_slice());

    // Clean EOF
    drop(raw_writer);
    let eof = read_rpc_request(&mut raw_reader)
        .await
        .expect("read failed");
    assert_eq!(eof, None);

    // Oversized RPC frame attack
    let (mut client_atk, mut server_atk) = duplex(1024);
    let oversized_len = (MAX_RPC_FRAME_SIZE + 1) as u32;
    client_atk.write_all(&555u32.to_be_bytes()).await.unwrap();
    client_atk
        .write_all(&oversized_len.to_be_bytes())
        .await
        .unwrap();
    client_atk.flush().await.unwrap();
    let err = read_rpc_request(&mut server_atk).await.unwrap_err();
    match err {
        ProtocolError::FrameTooLarge { size, max } => {
            assert_eq!(size, MAX_RPC_FRAME_SIZE + 1);
            assert_eq!(max, MAX_RPC_FRAME_SIZE);
        }
        other => panic!("Unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn test_large_rpc_payload_incremental_growth() {
    let (mut client, mut server) = duplex(256 * 1024);

    // Large payload (> 64KB, e.g. 100KB file content)
    let large_bytes = vec![0x7A; 100_000];
    let resp = RpcResponse::FsRead(Ok(FsReadResult {
        data: large_bytes.clone(),
        too_large: false,
        total_size: 100_000,
    }));

    write_rpc_response(&mut client, 999, &resp)
        .await
        .expect("write large failed");

    let frame = read_rpc_response(&mut server)
        .await
        .expect("read large failed")
        .expect("expected frame");

    assert_eq!(frame.request_id, 999);
    match frame.payload {
        RpcResponse::FsRead(Ok(FsReadResult {
            data: received_bytes,
            ..
        })) => {
            assert_eq!(received_bytes.len(), 100_000);
            assert_eq!(received_bytes, large_bytes);
        }
        _ => panic!("Unexpected payload"),
    }
}

#[tokio::test]
async fn test_pty_attach_ack_codec() {
    use std::io::Cursor;

    // 1. Replay variant round-trip
    let replay_ack = PtyAttachAck::Replay {
        offset: 0x0102_0304_0506_0708,
    };
    let mut buf = Vec::new();
    write_pty_attach_ack(&mut buf, &replay_ack)
        .await
        .expect("write replay ack failed");
    let mut cursor = Cursor::new(&buf);
    let decoded = read_pty_attach_ack(&mut cursor)
        .await
        .expect("read replay ack failed");
    assert_eq!(decoded, replay_ack);

    // 2. Snapshot variant round-trip
    let snapshot_ack = PtyAttachAck::Snapshot {
        offset: 999_999,
        history: b"\x1b[0mline 1\r\nline 2\x1b[0m".to_vec(),
        screen: b"\x1b[?1049h\x1b[H\x1b[2Jcontent".to_vec(),
    };
    let mut buf = Vec::new();
    write_pty_attach_ack(&mut buf, &snapshot_ack)
        .await
        .expect("write snapshot ack failed");
    let mut cursor = Cursor::new(&buf);
    let decoded = read_pty_attach_ack(&mut cursor)
        .await
        .expect("read snapshot ack failed");
    assert_eq!(decoded, snapshot_ack);

    // 3. Closed/empty reader returns UnexpectedEof
    let mut empty_cursor = Cursor::new(&[]);
    let err = read_pty_attach_ack(&mut empty_cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::UnexpectedEof));

    // 4. Truncated acknowledgement then EOF returns UnexpectedEof
    let mut trunc_cursor = Cursor::new(&[0x00, 0x00, 0x00]);
    let err = read_pty_attach_ack(&mut trunc_cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::UnexpectedEof));
}

#[tokio::test]
async fn test_length_prefixed_generic_roundtrip_and_limit() {
    const MAX_LEN: usize = 64;

    // Round-trip a small value within the limit.
    let (mut client, mut server) = duplex(1024);
    let header = PtyAttachHeader::new("generic-1", 4242, false);
    write_length_prefixed(&mut client, &header, MAX_LEN)
        .await
        .expect("write failed");
    let decoded: PtyAttachHeader = read_length_prefixed(&mut server, MAX_LEN)
        .await
        .expect("read failed")
        .expect("expected value");
    assert_eq!(header, decoded);

    // Oversized payload rejected on write.
    let (mut client2, _server2) = duplex(1024);
    let oversized = PtyAttachHeader::new("x".repeat(200), 0, false);
    let err = write_length_prefixed(&mut client2, &oversized, MAX_LEN)
        .await
        .unwrap_err();
    assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));

    // Hand-written prefix exceeding max_len rejected on read.
    let (mut client3, mut server3) = duplex(1024);
    let declared = (MAX_LEN + 1) as u32;
    client3
        .write_all(&declared.to_be_bytes())
        .await
        .expect("write failed");
    let err = read_length_prefixed::<_, PtyAttachHeader>(&mut server3, MAX_LEN)
        .await
        .unwrap_err();
    assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
}

#[tokio::test]
async fn test_tunnel_header_codec() {
    let (mut client, mut server) = duplex(1024);

    let req = TunnelOpen {
        host: "localhost".to_string(),
        port: 5173,
    };
    write_tunnel_open(&mut client, &req)
        .await
        .expect("write tunnel open failed");
    let decoded = read_tunnel_open(&mut server)
        .await
        .expect("read tunnel open failed")
        .expect("expected header");
    assert_eq!(req, decoded);

    let ack = TunnelAck::Connected;
    write_tunnel_ack(&mut server, &ack)
        .await
        .expect("write tunnel ack failed");
    let decoded_ack = read_tunnel_ack(&mut client)
        .await
        .expect("read tunnel ack failed");
    assert_eq!(ack, decoded_ack);

    let failed_ack = TunnelAck::Failed {
        reason: TunnelFailure::Refused,
        message: "connection refused".to_string(),
    };
    write_tunnel_ack(&mut server, &failed_ack)
        .await
        .expect("write tunnel ack failed");
    let decoded_failed_ack = read_tunnel_ack(&mut client)
        .await
        .expect("read tunnel ack failed");
    assert_eq!(failed_ack, decoded_failed_ack);

    // Clean EOF on open
    drop(client);
    let eof = read_tunnel_open(&mut server).await.expect("read failed");
    assert_eq!(eof, None);
}

#[tokio::test]
async fn test_tunnel_header_oversize() {
    let (mut client, _server) = duplex(2048);
    let oversize_req = TunnelOpen {
        host: "a".repeat(MAX_TUNNEL_HEADER_SIZE + 1),
        port: 8080,
    };
    let err = write_tunnel_open(&mut client, &oversize_req)
        .await
        .unwrap_err();
    assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
}

#[test]
fn test_alpn_constants() {
    assert_eq!(ALPN_CAWIDE, b"cawide/5");
    assert_eq!(ALPN_CAWIDE_LEGACY, [b"cawide/4", b"cawide/3"]);
}

#[tokio::test]
async fn test_rpc_legacy_host_decodes_caps_carrying_requests_back_to_back() {
    let req1 = RpcRequest::HostInfo;
    let req2 = RpcRequest::SessionList;
    let mut buf = Vec::new();
    write_rpc_request_with_caps(&mut buf, 10, &req1, RPC_CAP_ZSTD)
        .await
        .unwrap();
    write_rpc_request_with_caps(&mut buf, 20, &req2, RPC_CAP_ZSTD)
        .await
        .unwrap();

    let mut cursor = std::io::Cursor::new(buf);
    let f1 = read_rpc_request(&mut cursor)
        .await
        .unwrap()
        .expect("first frame");
    assert_eq!(f1.request_id, 10);
    assert_eq!(f1.payload, req1);

    let f2 = read_rpc_request(&mut cursor)
        .await
        .unwrap()
        .expect("second frame");
    assert_eq!(f2.request_id, 20);
    assert_eq!(f2.payload, req2);

    let f3 = read_rpc_request(&mut cursor).await.unwrap();
    assert!(f3.is_none());
}

#[tokio::test]
async fn test_rpc_legacy_bytes_identical_when_caps_zero() {
    let req = RpcRequest::HostInfo;
    let postcard_req = postcard::to_allocvec(&req).unwrap();
    let mut expected_req = Vec::new();
    expected_req.extend_from_slice(&77u32.to_be_bytes());
    expected_req.extend_from_slice(&(postcard_req.len() as u32).to_be_bytes());
    expected_req.extend_from_slice(&postcard_req);

    let mut actual_req = Vec::new();
    write_rpc_request_with_caps(&mut actual_req, 77, &req, 0)
        .await
        .unwrap();
    assert_eq!(actual_req, expected_req);

    let resp = RpcResponse::HostInfo(Ok(HostInfo {
        host_name: "test".into(),
        os: "macos".into(),
        arch: "arm64".into(),
        version: "1.0".into(),
        workdir: "/ws".into(),
    }));
    let postcard_resp = postcard::to_allocvec(&resp).unwrap();
    let mut expected_resp = Vec::new();
    expected_resp.extend_from_slice(&88u32.to_be_bytes());
    expected_resp.extend_from_slice(&(postcard_resp.len() as u32).to_be_bytes());
    expected_resp.extend_from_slice(&postcard_resp);

    let actual_resp = encode_rpc_response_frame(88, &resp, 0).unwrap();
    assert_eq!(actual_resp, expected_resp);
}

#[tokio::test]
async fn test_rpc_compression_roundtrip_128k_repetitive_fs_read() {
    let content = vec![b'x'; 128 * 1024];
    let resp = RpcResponse::FsRead(Ok(FsReadResult {
        data: content,
        too_large: false,
        total_size: 128 * 1024,
    }));
    let frame_bytes = encode_rpc_response_frame(42, &resp, RPC_CAP_ZSTD).unwrap();
    let wire_len_raw = u32::from_be_bytes([
        frame_bytes[4],
        frame_bytes[5],
        frame_bytes[6],
        frame_bytes[7],
    ]);
    assert_ne!(
        wire_len_raw & RPC_FLAG_COMPRESSED,
        0,
        "bit 31 must be set on length field"
    );
    assert!(
        frame_bytes.len() < 4096,
        "wire length must be < 4 KiB, was {}",
        frame_bytes.len()
    );

    let mut cursor = std::io::Cursor::new(frame_bytes);
    let decoded = read_rpc_response(&mut cursor)
        .await
        .unwrap()
        .expect("frame");
    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.payload, resp);
}

#[tokio::test]
async fn test_rpc_compression_threshold_512b_uncompressed() {
    let content = vec![b'y'; 512];
    let resp = RpcResponse::FsRead(Ok(FsReadResult {
        data: content,
        too_large: false,
        total_size: 512,
    }));
    let frame_bytes = encode_rpc_response_frame(43, &resp, RPC_CAP_ZSTD).unwrap();
    let wire_len_raw = u32::from_be_bytes([
        frame_bytes[4],
        frame_bytes[5],
        frame_bytes[6],
        frame_bytes[7],
    ]);
    assert_eq!(
        wire_len_raw & RPC_FLAG_COMPRESSED,
        0,
        "bit 31 must be clear for 512 B payload"
    );

    let mut cursor = std::io::Cursor::new(frame_bytes);
    let decoded = read_rpc_response(&mut cursor)
        .await
        .unwrap()
        .expect("frame");
    assert_eq!(decoded.payload, resp);
}

#[tokio::test]
async fn test_rpc_compression_incompressible_64k_random_uncompressed() {
    let mut rand_state = 123456789u64;
    let mut random_bytes = Vec::with_capacity(64 * 1024);
    for _ in 0..(64 * 1024) {
        rand_state = rand_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        random_bytes.push((rand_state >> 33) as u8);
    }
    let resp = RpcResponse::FsRead(Ok(FsReadResult {
        data: random_bytes,
        too_large: false,
        total_size: 64 * 1024,
    }));
    let frame_bytes = encode_rpc_response_frame(44, &resp, RPC_CAP_ZSTD).unwrap();
    let wire_len_raw = u32::from_be_bytes([
        frame_bytes[4],
        frame_bytes[5],
        frame_bytes[6],
        frame_bytes[7],
    ]);
    assert_eq!(
        wire_len_raw & RPC_FLAG_COMPRESSED,
        0,
        "bit 31 must be clear when compressed size is not strictly smaller"
    );

    let mut cursor = std::io::Cursor::new(frame_bytes);
    let decoded = read_rpc_response(&mut cursor)
        .await
        .unwrap()
        .expect("frame");
    assert_eq!(decoded.payload, resp);
}

#[tokio::test]
async fn test_rpc_hostile_frames_rejected() {
    // 1. uncompressed_len > 16 MiB
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&(14u32 | RPC_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&((MAX_RPC_FRAME_SIZE as u32) + 1).to_be_bytes());
    buf.extend_from_slice(&[0u8; 10]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = read_rpc_response(&mut cursor).await.unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::FrameTooLarge { .. } | ProtocolError::Decompress(_)
    ));

    // 2. decompressed size > declared
    let raw_uncompressed = vec![b'Z'; 2048];
    let compressed = zstd::bulk::compress(&raw_uncompressed, 3).unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(&2u32.to_be_bytes());
    let wire_len = (4 + compressed.len()) as u32;
    buf.extend_from_slice(&(wire_len | RPC_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&500u32.to_be_bytes());
    buf.extend_from_slice(&compressed);
    let mut cursor = std::io::Cursor::new(buf);
    let err = read_rpc_response(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::Decompress(_)));

    // 3. truncated zstd
    let mut buf = Vec::new();
    buf.extend_from_slice(&3u32.to_be_bytes());
    buf.extend_from_slice(&(10u32 | RPC_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&1024u32.to_be_bytes());
    buf.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = read_rpc_response(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::Decompress(_)));

    // 4. masked len < 4
    let mut buf = Vec::new();
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(&(2u32 | RPC_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&[0u8; 2]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = read_rpc_response(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::Decompress(_)));

    // 5. masked len > 16 MiB
    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.extend_from_slice(&(((MAX_RPC_FRAME_SIZE as u32) + 1) | RPC_FLAG_COMPRESSED).to_be_bytes());
    let mut cursor = std::io::Cursor::new(buf);
    let err = read_rpc_response(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
}

// ---------------------------------------------------------------------------
// PTY Chunk Codec & Ack Tests (TDD)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pty_chunk_round_trip_compressed() {
    let mut encoder = PtyChunkEncoder::new().expect("encoder init");
    let mut decoder = PtyChunkDecoder::new().expect("decoder init");

    // 48 KiB of repeated SGR-colored lines
    let sgr_line = "\x1b[32m[INFO]\x1b[0m 2026-11-10T12:00:00Z Connection accepted from peer\n";
    let repeat_count = (48 * 1024) / sgr_line.len() + 1;
    let raw_input = sgr_line.repeat(repeat_count).into_bytes();
    let raw_input = &raw_input[..48 * 1024];

    let frame = encoder.encode(raw_input).expect("encode failed");

    // Frame bit 31 set
    let prefix = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    assert_ne!(
        prefix & PTY_CHUNK_FLAG_COMPRESSED,
        0,
        "bit 31 must be set for compressed frame"
    );

    // Frame length under 40% of raw
    assert!(
        frame.len() < (raw_input.len() * 40 / 100),
        "frame len {} should be under 40% of raw len {}",
        frame.len(),
        raw_input.len()
    );

    // read_frame gives back equal bytes
    let mut cursor = std::io::Cursor::new(frame.to_vec());
    let decoded = decoder
        .read_frame(&mut cursor)
        .await
        .expect("read_frame failed")
        .expect("chunk present");
    assert_eq!(decoded, PtyFrame::Output(raw_input.to_vec()));
}

#[tokio::test]
async fn test_pty_chunk_512b_raw() {
    let mut encoder = PtyChunkEncoder::new().expect("encoder init");
    let mut decoder = PtyChunkDecoder::new().expect("decoder init");

    let raw_input = vec![b'x'; 512];
    let frame = encoder.encode(&raw_input).expect("encode failed");

    let prefix = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    assert_eq!(
        prefix & PTY_CHUNK_FLAG_COMPRESSED,
        0,
        "bit 31 must be clear for 512B input"
    );
    assert_eq!(prefix as usize, 512);

    let mut cursor = std::io::Cursor::new(frame.to_vec());
    let decoded = decoder
        .read_frame(&mut cursor)
        .await
        .expect("read_frame failed")
        .expect("chunk present");
    assert_eq!(decoded, PtyFrame::Output(raw_input));
}

#[tokio::test]
async fn test_pty_chunk_64k_random_raw() {
    let mut encoder = PtyChunkEncoder::new().expect("encoder init");
    let mut decoder = PtyChunkDecoder::new().expect("decoder init");

    let mut rand_state = 987654321u64;
    let mut raw_input = Vec::with_capacity(64 * 1024);
    for _ in 0..(64 * 1024) {
        rand_state = rand_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        raw_input.push((rand_state >> 33) as u8);
    }

    let frame = encoder.encode(&raw_input).expect("encode failed");

    let prefix = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    assert_eq!(
        prefix & PTY_CHUNK_FLAG_COMPRESSED,
        0,
        "bit 31 must be clear for incompressible 64k random input"
    );

    let mut cursor = std::io::Cursor::new(frame.to_vec());
    let decoded = decoder
        .read_frame(&mut cursor)
        .await
        .expect("read_frame failed")
        .expect("chunk present");
    assert_eq!(decoded, PtyFrame::Output(raw_input));
}

#[tokio::test]
async fn test_pty_chunk_hostile_frames_rejected() {
    let mut decoder = PtyChunkDecoder::new().expect("decoder init");

    // 1. raw_len = MAX + 1
    let mut buf = Vec::new();
    let masked_len = 14u32 | PTY_CHUNK_FLAG_COMPRESSED;
    buf.extend_from_slice(&masked_len.to_be_bytes());
    buf.extend_from_slice(&((MAX_PTY_CHUNK_RAW as u32) + 1).to_be_bytes());
    buf.extend_from_slice(&[0u8; 10]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = decoder.read_frame(&mut cursor).await.unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::FrameTooLarge { .. } | ProtocolError::Decompress(_)
    ));

    // 2. decompressed size != declared
    let raw = vec![b'A'; 2048];
    let compressed = zstd::bulk::compress(&raw, 1).expect("compress");
    let mut buf = Vec::new();
    let wire_len = (4 + compressed.len()) as u32;
    buf.extend_from_slice(&(wire_len | PTY_CHUNK_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&500u32.to_be_bytes()); // declared 500 but actually 2048
    buf.extend_from_slice(&compressed);
    let mut cursor = std::io::Cursor::new(buf);
    let err = decoder.read_frame(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::Decompress(_)));

    // 3. truncated zstd body
    let mut buf = Vec::new();
    buf.extend_from_slice(&(10u32 | PTY_CHUNK_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&1024u32.to_be_bytes());
    buf.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = decoder.read_frame(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::Decompress(_)));

    // 4. masked length < 4
    let mut buf = Vec::new();
    buf.extend_from_slice(&(2u32 | PTY_CHUNK_FLAG_COMPRESSED).to_be_bytes());
    buf.extend_from_slice(&[0u8; 2]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = decoder.read_frame(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::Decompress(_)));

    // 5. raw len > MAX_PTY_CHUNK_RAW
    let mut buf = Vec::new();
    buf.extend_from_slice(&((MAX_PTY_CHUNK_RAW as u32) + 1).to_be_bytes());
    buf.extend_from_slice(&[0u8; 10]);
    let mut cursor = std::io::Cursor::new(buf);
    let err = decoder.read_frame(&mut cursor).await.unwrap_err();
    assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
}

#[tokio::test]
async fn test_pty_chunk_eof_handling() {
    let mut decoder = PtyChunkDecoder::new().expect("decoder init");

    // EOF at frame boundary -> Ok(None)
    let mut empty = std::io::Cursor::new(Vec::new());
    let res = decoder.read_frame(&mut empty).await.expect("clean EOF");
    assert_eq!(res, None);

    // EOF mid-prefix -> UnexpectedEof
    let mut mid_prefix = std::io::Cursor::new(vec![0x00, 0x01]);
    let err = decoder.read_frame(&mut mid_prefix).await.unwrap_err();
    assert!(matches!(err, ProtocolError::UnexpectedEof));
}

#[tokio::test]
async fn test_pty_attach_header_compat() {
    let (mut client, mut server) = duplex(1024);

    // 1. 5-field decodes through 4-field struct
    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct TestLegacyHeaderV4 {
        session_id: String,
        last_ack_offset: u64,
        resume: bool,
        accept_compressed_snapshot: bool,
    }

    let header5 = PtyAttachHeader {
        session_id: "sess-v5".into(),
        last_ack_offset: 42,
        resume: true,
        accept_compressed_snapshot: true,
        accept_chunked_output: true,
        accept_input_mode_frames: false,
    };
    let encoded5 = postcard::to_allocvec(&header5).expect("postcard serialize");
    let decoded_as_v4: TestLegacyHeaderV4 =
        postcard::from_bytes(&encoded5).expect("deserialize as v4");
    assert_eq!(decoded_as_v4.session_id, "sess-v5");
    assert_eq!(decoded_as_v4.last_ack_offset, 42);
    assert!(decoded_as_v4.resume);
    assert!(decoded_as_v4.accept_compressed_snapshot);

    // 2. 4-field bytes decode on new reader with accept_chunked_output == false
    let v4_tuple = (String::from("sess-v4"), 999u64, true, true);
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 2]);
    buf = postcard::to_extend(&v4_tuple, buf).expect("postcard serialize");
    let payload_len = (buf.len() - 2) as u16;
    buf[..2].copy_from_slice(&payload_len.to_be_bytes());

    tokio::io::AsyncWriteExt::write_all(&mut client, &buf)
        .await
        .expect("write");
    tokio::io::AsyncWriteExt::flush(&mut client)
        .await
        .expect("flush");

    let decoded = read_pty_attach_header(&mut server)
        .await
        .expect("read header")
        .expect("present header");
    assert_eq!(decoded.session_id, "sess-v4");
    assert_eq!(decoded.last_ack_offset, 999);
    assert!(decoded.resume);
    assert!(decoded.accept_compressed_snapshot);
    assert!(!decoded.accept_chunked_output);
    assert!(!decoded.accept_input_mode_frames);
}

#[tokio::test]
async fn test_pty_attach_ack_compat() {
    let ack = PtyAttachAck::Replay { offset: 12345 };

    // write_pty_attach_ack_chunked(.., false) byte-identical to write_pty_attach_ack
    let mut buf1 = Vec::new();
    write_pty_attach_ack(&mut buf1, &ack)
        .await
        .expect("write default ack");

    let mut buf2 = Vec::new();
    write_pty_attach_ack_chunked(&mut buf2, &ack, false)
        .await
        .expect("write unchunked ack");
    assert_eq!(
        buf1, buf2,
        "write_pty_attach_ack and write_pty_attach_ack_chunked(.., false) must be byte-identical"
    );

    // chunked write round-trips to (ack, true)
    let mut buf3 = Vec::new();
    write_pty_attach_ack_chunked(&mut buf3, &ack, true)
        .await
        .expect("write chunked ack");
    let prefix = u32::from_be_bytes([buf3[0], buf3[1], buf3[2], buf3[3]]);
    assert_ne!(prefix & PTY_ACK_FLAG_CHUNKED, 0, "bit 31 must be set");

    let mut cursor = std::io::Cursor::new(buf3);
    let (decoded_ack, chunked) = read_pty_attach_ack_chunked(&mut cursor)
        .await
        .expect("read chunked ack");
    assert_eq!(decoded_ack, ack);
    assert!(chunked);
}

#[tokio::test]
async fn test_rpc_encode_byte_identity() {
    fn legacy_encode_rpc_response_frame(
        request_id: u32,
        resp: &RpcResponse,
        caps: u8,
    ) -> Result<Vec<u8>, ProtocolError> {
        let uncompressed = postcard::to_allocvec(resp)?;
        if (caps & RPC_CAP_ZSTD) != 0 && uncompressed.len() >= MIN_RPC_COMPRESS_SIZE {
            let compressed = zstd::bulk::compress(&uncompressed, 3)
                .map_err(|e| ProtocolError::Decompress(e.to_string()))?;
            if compressed.len() + 4 < uncompressed.len() {
                let wire_len = 4 + compressed.len();
                if wire_len > MAX_RPC_FRAME_SIZE {
                    return Err(ProtocolError::FrameTooLarge {
                        size: wire_len,
                        max: MAX_RPC_FRAME_SIZE,
                    });
                }
                let masked_len = (wire_len as u32) | RPC_FLAG_COMPRESSED;
                let mut buf = Vec::with_capacity(8 + 4 + compressed.len());
                buf.extend_from_slice(&request_id.to_be_bytes());
                buf.extend_from_slice(&masked_len.to_be_bytes());
                buf.extend_from_slice(&(uncompressed.len() as u32).to_be_bytes());
                buf.extend_from_slice(&compressed);
                return Ok(buf);
            }
        }

        let payload_len = uncompressed.len();
        if payload_len > MAX_RPC_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge {
                size: payload_len,
                max: MAX_RPC_FRAME_SIZE,
            });
        }
        let mut buf = Vec::with_capacity(8 + payload_len);
        buf.extend_from_slice(&request_id.to_be_bytes());
        buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
        buf.extend_from_slice(&uncompressed);
        Ok(buf)
    }

    // 1 MiB FsReadChunk
    let source_line =
        "pub fn calculate_metrics(data: &[f64]) -> Result<Summary, Error> {\n    // process loop\n";
    let chunk_repeat = (1024 * 1024) / source_line.len() + 1;
    let chunk_data = source_line.repeat(chunk_repeat).into_bytes();
    let chunk_resp = RpcResponse::FsReadChunk(Ok(FsChunk {
        data: chunk_data,
        too_large: false,
        total_size: 1024 * 1024,
        modified_unix_ns: 0,
    }));

    // 200 B response
    let small_resp = RpcResponse::FsRead(Ok(FsReadResult {
        data: b"hello world from small rpc response payload verifying byte identity".to_vec(),
        too_large: false,
        total_size: 67,
    }));

    for caps in [0, RPC_CAP_ZSTD] {
        let expected_chunk = legacy_encode_rpc_response_frame(10, &chunk_resp, caps).unwrap();
        let actual_chunk = encode_rpc_response_frame(10, &chunk_resp, caps).unwrap();
        assert_eq!(
            expected_chunk, actual_chunk,
            "1 MiB FsReadChunk with caps {caps} must be byte-identical"
        );

        let expected_small = legacy_encode_rpc_response_frame(20, &small_resp, caps).unwrap();
        let actual_small = encode_rpc_response_frame(20, &small_resp, caps).unwrap();
        assert_eq!(
            expected_small, actual_small,
            "200 B response with caps {caps} must be byte-identical"
        );
    }
}

#[tokio::test]
async fn test_pty_frame_roundtrip_output_mode_compressed() {
    let mut encoder = PtyChunkEncoder::new().unwrap();
    let mut decoder = PtyChunkDecoder::new().unwrap();
    let (mut client_write, mut client_read) = duplex(65536);

    // 1. Output (raw)
    let raw_out = encoder.encode(b"hello world").unwrap();
    client_write.write_all(raw_out).await.unwrap();

    // 2. InputMode
    let mode_out = encoder.encode_input_mode(PTY_INPUT_MODE_ECHO | PTY_INPUT_MODE_CANONICAL);
    client_write.write_all(mode_out).await.unwrap();

    // 3. Compressed Output
    let large_raw = vec![b'A'; 2048];
    let comp_out = encoder.encode(&large_raw).unwrap();
    client_write.write_all(comp_out).await.unwrap();

    drop(client_write);

    // Read 1: Output
    let f1 = decoder.read_frame(&mut client_read).await.unwrap();
    assert_eq!(f1, Some(PtyFrame::Output(b"hello world".to_vec())));

    // Read 2: InputMode
    let f2 = decoder.read_frame(&mut client_read).await.unwrap();
    assert_eq!(
        f2,
        Some(PtyFrame::InputMode(
            PTY_INPUT_MODE_ECHO | PTY_INPUT_MODE_CANONICAL
        ))
    );

    // Read 3: Compressed Output
    let f3 = decoder.read_frame(&mut client_read).await.unwrap();
    assert_eq!(f3, Some(PtyFrame::Output(large_raw)));

    // Clean EOF
    let f4 = decoder.read_frame(&mut client_read).await.unwrap();
    assert_eq!(f4, None);
}

#[tokio::test]
async fn test_pty_frame_input_mode_length_two_rejected() {
    let mut decoder = PtyChunkDecoder::new().unwrap();
    let (mut client_write, mut client_read) = duplex(1024);

    let prefix = 2u32 | PTY_CHUNK_FLAG_INPUT_MODE;
    client_write.write_all(&prefix.to_be_bytes()).await.unwrap();
    client_write.write_all(&[0x01, 0x02]).await.unwrap();

    let err = decoder.read_frame(&mut client_read).await.unwrap_err();
    match err {
        ProtocolError::FrameTooLarge { size, max } => {
            assert_eq!(size, 2);
            assert_eq!(max, 1);
        }
        other => panic!("expected FrameTooLarge, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_pty_frame_compressed_and_mode_flags_rejected() {
    let mut decoder = PtyChunkDecoder::new().unwrap();
    let (mut client_write, mut client_read) = duplex(1024);

    let prefix = 1u32 | PTY_CHUNK_FLAG_INPUT_MODE | PTY_CHUNK_FLAG_COMPRESSED;
    client_write.write_all(&prefix.to_be_bytes()).await.unwrap();
    client_write.write_all(&[0x01]).await.unwrap();

    let err = decoder.read_frame(&mut client_read).await.unwrap_err();
    match err {
        ProtocolError::Decompress(msg) => {
            assert_eq!(msg, "input-mode frame cannot be compressed");
        }
        other => panic!("expected Decompress error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_pty_frame_input_mode_unknown_bit_rejected() {
    let mut decoder = PtyChunkDecoder::new().unwrap();
    let (mut client_write, mut client_read) = duplex(1024);

    let prefix = 1u32 | PTY_CHUNK_FLAG_INPUT_MODE;
    client_write.write_all(&prefix.to_be_bytes()).await.unwrap();
    client_write.write_all(&[0x04]).await.unwrap();

    let err = decoder.read_frame(&mut client_read).await.unwrap_err();
    match err {
        ProtocolError::Decompress(msg) => {
            assert_eq!(msg, "unknown input-mode bits");
        }
        other => panic!("expected Decompress error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_pty_attach_header_v5_compat() {
    let (mut client, mut server) = duplex(1024);

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct TestHeaderV5 {
        session_id: String,
        last_ack_offset: u64,
        resume: bool,
        accept_compressed_snapshot: bool,
        accept_chunked_output: bool,
    }

    // 1. 6-field header payload decodes with postcard::from_bytes::<TestHeaderV5>
    let header6 = PtyAttachHeader {
        session_id: "sess-v6".into(),
        last_ack_offset: 123,
        resume: true,
        accept_compressed_snapshot: true,
        accept_chunked_output: true,
        accept_input_mode_frames: true,
    };
    let encoded6 = postcard::to_allocvec(&header6).expect("postcard serialize");
    let decoded_as_v5: TestHeaderV5 = postcard::from_bytes(&encoded6).expect("deserialize as v5");
    assert_eq!(decoded_as_v5.session_id, "sess-v6");
    assert_eq!(decoded_as_v5.last_ack_offset, 123);
    assert!(decoded_as_v5.resume);
    assert!(decoded_as_v5.accept_compressed_snapshot);
    assert!(decoded_as_v5.accept_chunked_output);

    // 2. TestHeaderV5 payload decodes via read_pty_attach_header with accept_input_mode_frames == false
    let v5_obj = TestHeaderV5 {
        session_id: "sess-v5".into(),
        last_ack_offset: 456,
        resume: false,
        accept_compressed_snapshot: true,
        accept_chunked_output: true,
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 2]);
    buf = postcard::to_extend(&v5_obj, buf).expect("postcard serialize");
    let payload_len = (buf.len() - 2) as u16;
    buf[..2].copy_from_slice(&payload_len.to_be_bytes());

    tokio::io::AsyncWriteExt::write_all(&mut client, &buf)
        .await
        .expect("write");
    tokio::io::AsyncWriteExt::flush(&mut client)
        .await
        .expect("flush");

    let decoded = read_pty_attach_header(&mut server)
        .await
        .expect("read header")
        .expect("present header");
    assert_eq!(decoded.session_id, "sess-v5");
    assert_eq!(decoded.last_ack_offset, 456);
    assert!(!decoded.resume);
    assert!(decoded.accept_compressed_snapshot);
    assert!(decoded.accept_chunked_output);
    assert!(!decoded.accept_input_mode_frames);
}
