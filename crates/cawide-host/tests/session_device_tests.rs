//! Integration tests for session lifecycle, attach claims, and device revocation (Brick 9).

mod common;

use std::path::Path;
use std::time::Duration;

use cawide_host::auth::AuthorizedKeysStore;
use cawide_host::net::{
    send_ipc_request, CawideServer, CawideServerConfig, IpcRequest, IpcResponse, NetworkMode,
};
use cawide_protocol::{
    read_control_message, read_pty_attach_ack, read_rpc_response, write_control_message,
    write_pty_attach_header, write_rpc_request, ControlMessage, HostEvent, PtyAttachAck,
    PtyAttachHeader, RpcRequest, RpcResponse, StreamPurpose, CLOSE_UNAUTHORIZED, STREAM_ERR_RESYNC,
    STREAM_ERR_SESSION_GONE, STREAM_ERR_SESSION_OCCUPIED, STREAM_ERR_SESSION_TAKEN,
};
use common::{authorized_client, client, connect, open, within};
use iroh::endpoint::{ConnectionError, VarInt};
use iroh::SecretKey;

fn nz(v: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(v).unwrap()
}

fn config(dir: &Path) -> CawideServerConfig {
    CawideServerConfig {
        config_dir: dir.join("conf"),
        network_mode: NetworkMode::LocalOnly,
        workdir: dir.to_path_buf(),
        launch_cmd: None,
        upload_dir: Some(dir.join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    }
}

async fn start_server() -> (CawideServer, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let server = within(CawideServer::bind(config(tmp.path())))
        .await
        .unwrap();
    (server, tmp)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_list_kill_rpc() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;

    // List initially: should be empty
    within(write_rpc_request(&mut rsend, 1, &RpcRequest::SessionList))
        .await
        .unwrap();
    let resp = match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionList(Ok(list)) => list,
        other => panic!("expected SessionList Ok, got {other:?}"),
    };
    assert!(resp.is_empty());

    // Create session "s1"
    within(write_rpc_request(
        &mut rsend,
        2,
        &RpcRequest::SessionCreate {
            session_id: "s1".into(),
            command: None,
            workdir: None,
        },
    ))
    .await
    .unwrap();
    let created = match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Ok(summary)) => summary,
        other => panic!("expected SessionCreate Ok, got {other:?}"),
    };
    assert_eq!(created.session_id, "s1");
    assert!(created.alive);

    // List should show s1
    within(write_rpc_request(&mut rsend, 3, &RpcRequest::SessionList))
        .await
        .unwrap();
    let resp = match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionList(Ok(list)) => list,
        other => panic!("expected SessionList Ok, got {other:?}"),
    };
    assert_eq!(resp.len(), 1);
    assert_eq!(resp[0].session_id, "s1");

    // Kill session "s1"
    within(write_rpc_request(
        &mut rsend,
        4,
        &RpcRequest::SessionKill {
            session_id: "s1".into(),
        },
    ))
    .await
    .unwrap();
    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionKill(Ok(())) => {}
        other => panic!("expected SessionKill Ok, got {other:?}"),
    };

    // List should be empty again
    within(write_rpc_request(&mut rsend, 5, &RpcRequest::SessionList))
        .await
        .unwrap();
    let resp = match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionList(Ok(list)) => list,
        other => panic!("expected SessionList Ok, got {other:?}"),
    };
    assert!(resp.is_empty());

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_duplicate_create_error() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;

    // Create session "dup-1"
    within(write_rpc_request(
        &mut rsend,
        1,
        &RpcRequest::SessionCreate {
            session_id: "dup-1".into(),
            command: None,
            workdir: None,
        },
    ))
    .await
    .unwrap();
    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Ok(_)) => {}
        other => panic!("expected SessionCreate Ok, got {other:?}"),
    };

    // Duplicate create should error
    within(write_rpc_request(
        &mut rsend,
        2,
        &RpcRequest::SessionCreate {
            session_id: "dup-1".into(),
            command: None,
            workdir: None,
        },
    ))
    .await
    .unwrap();
    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Err(msg)) => {
            assert!(
                msg.to_lowercase().contains("already")
                    || msg.to_lowercase().contains("duplicate")
                    || msg.to_lowercase().contains("exist"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected SessionCreate Err, got {other:?}"),
    };

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exit_code_tracking_and_sessions_changed() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;

    // Ping to ensure control stream is established
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 1 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv))
        .await
        .unwrap()
        .unwrap()
    {
        ControlMessage::Pong { .. } => {}
        other => panic!("expected Pong, got {other:?}"),
    }

    // Create session running sh -c 'exit 3'
    within(write_rpc_request(
        &mut rsend,
        1,
        &RpcRequest::SessionCreate {
            session_id: "exit-3-sess".into(),
            command: Some("sh -c 'exit 3'".into()),
            workdir: None,
        },
    ))
    .await
    .unwrap();
    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Ok(_)) => {}
        other => panic!("expected SessionCreate Ok, got {other:?}"),
    };

    // Wait for SessionsChanged event indicating process exit with code 3
    let mut saw_exit = false;
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(3), read_control_message(&mut crecv)).await {
            Ok(Ok(Some(ControlMessage::HostEvent(HostEvent::SessionsChanged)))) => {
                within(write_rpc_request(&mut rsend, 2, &RpcRequest::SessionList))
                    .await
                    .unwrap();
                let resp = match within(read_rpc_response(&mut rrecv))
                    .await
                    .unwrap()
                    .unwrap()
                    .payload
                {
                    RpcResponse::SessionList(Ok(list)) => list,
                    other => panic!("expected SessionList Ok, got {other:?}"),
                };
                if let Some(sess) = resp.iter().find(|s| s.session_id == "exit-3-sess") {
                    if !sess.alive && sess.exit_code == Some(3) {
                        saw_exit = true;
                        break;
                    }
                }
            }
            Ok(Ok(Some(_))) => continue,
            _ => break,
        }
    }
    assert!(
        saw_exit,
        "expected SessionsChanged event on process exit with exit code 3"
    );

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_max_sessions_limit_32() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;

    // Create 32 sessions
    for i in 0..32 {
        within(write_rpc_request(
            &mut rsend,
            i as u32 + 1,
            &RpcRequest::SessionCreate {
                session_id: format!("sess-{}", i),
                command: None,
                workdir: None,
            },
        ))
        .await
        .unwrap();
        match within(read_rpc_response(&mut rrecv))
            .await
            .unwrap()
            .unwrap()
            .payload
        {
            RpcResponse::SessionCreate(Ok(_)) => {}
            other => panic!("expected session {i} to be created, got {other:?}"),
        };
    }

    // 33rd session should be rejected with limit error
    within(write_rpc_request(
        &mut rsend,
        100,
        &RpcRequest::SessionCreate {
            session_id: "sess-32".into(),
            command: None,
            workdir: None,
        },
    ))
    .await
    .unwrap();
    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Err(msg)) => {
            assert!(
                msg.to_lowercase().contains("limit") || msg.contains("32"),
                "expected limit error message, got: {msg}"
            );
        }
        other => panic!("expected SessionCreate Err for 33rd session, got {other:?}"),
    };

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_second_device_attach_occupied() {
    let (server, _tmp) = start_server().await;

    // Device 1 connects and attaches
    let (_ep1, conn1) = authorized_client(&server).await;
    let (mut psend1, mut precv1) = open(&conn1, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend1,
        &PtyAttachHeader::new("occ-sess", 0, false),
    ))
    .await
    .unwrap();
    within(read_pty_attach_ack(&mut precv1)).await.unwrap();

    // Device 2 connects (different key) and tries to attach to same session
    let (_ep2, conn2) = authorized_client(&server).await;
    let (mut psend2, mut precv2) = open(&conn2, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend2,
        &PtyAttachHeader::new("occ-sess", 0, false),
    ))
    .await
    .unwrap();

    let mut buf = [0u8; 16];
    let res = within(precv2.read(&mut buf)).await;
    match res {
        Err(iroh::endpoint::ReadError::Reset(code)) => {
            assert_eq!(code, VarInt::from_u32(STREAM_ERR_SESSION_OCCUPIED));
        }
        other => panic!("expected reset STREAM_ERR_SESSION_OCCUPIED, got {other:?}"),
    }

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_same_device_reconnect_takeover() {
    let (server, _tmp) = start_server().await;

    let key = SecretKey::generate();
    server
        .auth_store()
        .add_key(*key.public().as_bytes(), "Same Device".into())
        .unwrap();
    let ep = client(key).await;

    // Stream 1 from device attaches
    let conn1 = connect(&ep, &server, cawide_protocol::ALPN_CAWIDE)
        .await
        .unwrap();
    let (mut psend1, mut precv1) = open(&conn1, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend1,
        &PtyAttachHeader::new("takeover-sess", 0, false),
    ))
    .await
    .unwrap();
    within(read_pty_attach_ack(&mut precv1)).await.unwrap();

    // Stream 2 from same device reconnects / takes over
    let conn2 = connect(&ep, &server, cawide_protocol::ALPN_CAWIDE)
        .await
        .unwrap();
    let (mut psend2, mut precv2) = open(&conn2, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend2,
        &PtyAttachHeader::new("takeover-sess", 0, true),
    ))
    .await
    .unwrap();
    within(read_pty_attach_ack(&mut precv2)).await.unwrap();

    // Old stream 1 should be reset with STREAM_ERR_SESSION_TAKEN (0x15)
    let mut buf = [0u8; 64];
    let reset_code = loop {
        match within(precv1.read(&mut buf)).await {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("stream 1 finished cleanly without reset"),
            Err(iroh::endpoint::ReadError::Reset(code)) => break code,
            Err(other) => panic!("expected reset, got {other:?}"),
        }
    };
    assert_eq!(reset_code, VarInt::from_u32(STREAM_ERR_SESSION_TAKEN));

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_revoke_device_closes_connection() {
    let (server, _tmp) = start_server().await;

    let key = SecretKey::generate();
    let node_id = *key.public().as_bytes();
    server
        .auth_store()
        .add_key(node_id, "Revoke Device".into())
        .unwrap();
    let ep = client(key).await;
    let conn = connect(&ep, &server, cawide_protocol::ALPN_CAWIDE)
        .await
        .unwrap();

    // Verify connection is alive
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 42 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv))
        .await
        .unwrap()
        .unwrap()
    {
        ControlMessage::Pong { client_ts: 42, .. } => {}
        other => panic!("expected Pong, got {other:?}"),
    }

    // Revoke device via IPC
    let socket = server.socket_path().to_path_buf();
    let resp = within(send_ipc_request(
        &socket,
        &IpcRequest::RevokeDevice {
            selector: hex::encode(node_id),
        },
    ))
    .await
    .unwrap();
    match resp {
        IpcResponse::Revoked {
            node_id: r_node, ..
        } => {
            assert_eq!(r_node, hex::encode(node_id));
        }
        other => panic!("expected IpcResponse::Revoked, got {other:?}"),
    }

    // Connection should close with 0x01 (CLOSE_UNAUTHORIZED) within 2 seconds
    let close_res = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
    let err = close_res.expect("connection should close within 2s");
    match err {
        ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code, VarInt::from_u32(CLOSE_UNAUTHORIZED));
        }
        other => panic!("expected ApplicationClosed(0x01), got {other:?}"),
    }

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ambiguous_prefix_selector_error() {
    let (server, _tmp) = start_server().await;

    // Two valid Ed25519 public keys sharing prefix "faf04598"
    let mut key1 = [0u8; 32];
    key1.copy_from_slice(
        &hex::decode("faf045985ca1eb38b7ab49300733d250f8386510b343d25ef1e66a08c9134b8f").unwrap(),
    );
    let mut key2 = [0u8; 32];
    key2.copy_from_slice(
        &hex::decode("faf045986affcc206384b3c884df90b9037c2abba7ac2fe54a7cd507a8ecd003").unwrap(),
    );
    let prefix = "faf04598".to_string();

    server
        .auth_store()
        .add_key(key1, "Device A".into())
        .unwrap();
    server
        .auth_store()
        .add_key(key2, "Device B".into())
        .unwrap();

    let socket = server.socket_path().to_path_buf();
    let resp = within(send_ipc_request(
        &socket,
        &IpcRequest::RevokeDevice { selector: prefix },
    ))
    .await
    .unwrap();

    match resp {
        IpcResponse::Error(msg) => {
            assert!(
                msg.to_lowercase().contains("ambiguous"),
                "expected ambiguous error message, got: {msg}"
            );
        }
        other => panic!("expected IpcResponse::Error, got {other:?}"),
    }

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_cli_devices_without_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path();

    // Populate authorized_keys directly
    let store = AuthorizedKeysStore::open_or_create(config_dir.join("authorized_keys")).unwrap();
    let k1 = *SecretKey::generate().public().as_bytes();
    let k2 = *SecretKey::generate().public().as_bytes();
    store.add_key(k1, "Device Alpha".into()).unwrap();
    store.add_key(k2, "Device Beta".into()).unwrap();
    drop(store);

    // Call cli_devices without daemon running
    cawide_host::devices::cli_devices(config_dir).await.unwrap();

    // Call cli_revoke without daemon running
    cawide_host::devices::cli_revoke(config_dir, "Device Alpha")
        .await
        .unwrap();

    // Verify key was removed
    let store2 = AuthorizedKeysStore::open_or_create(config_dir.join("authorized_keys")).unwrap();
    let remaining = store2.list_keys();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].device_name, "Device Beta");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resume_unknown_session_gone() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("unknown-sess-id", 0, true),
    ))
    .await
    .unwrap();

    let mut buf = [0u8; 16];
    let res = within(precv.read(&mut buf)).await;
    match res {
        Err(iroh::endpoint::ReadError::Reset(code)) => {
            assert_eq!(code, VarInt::from_u32(STREAM_ERR_SESSION_GONE));
        }
        other => panic!("expected STREAM_ERR_SESSION_GONE, got {other:?}"),
    }

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resume_dead_session_clean_finish() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // Create a short-lived process via RPC
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(
        &mut rsend,
        1,
        &RpcRequest::SessionCreate {
            session_id: "short-lived".into(),
            command: Some("sh -c 'echo replay-msg && exit 0'".into()),
            workdir: None,
        },
    ))
    .await
    .unwrap();
    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Ok(_)) => {}
        other => panic!("expected SessionCreate Ok, got {other:?}"),
    };

    // Poll SessionList until process has exited
    within(async {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            write_rpc_request(&mut rsend, 2, &RpcRequest::SessionList)
                .await
                .unwrap();
            if let Ok(Some(resp)) = read_rpc_response(&mut rrecv).await {
                if let RpcResponse::SessionList(Ok(list)) = resp.payload {
                    if let Some(s) = list.iter().find(|s| s.session_id == "short-lived") {
                        if !s.alive {
                            break;
                        }
                    }
                }
            }
        }
    })
    .await;

    // Resume attach to dead session
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("short-lived", 0, true),
    ))
    .await
    .unwrap();

    // Should receive ack
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    // Read replay data until clean EOF
    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    while let Some(n) = within(precv.read(&mut buf)).await.unwrap() {
        acc.extend_from_slice(&buf[..n]);
    }
    let output = String::from_utf8_lossy(&acc);
    assert!(
        output.contains("replay-msg"),
        "expected replay-msg in output, got: {output}"
    );

    // Verify session remains dead (did not respawn)
    within(write_rpc_request(&mut rsend, 3, &RpcRequest::SessionList))
        .await
        .unwrap();
    let list = match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionList(Ok(list)) => list,
        other => panic!("expected SessionList Ok, got {other:?}"),
    };
    let s = list
        .iter()
        .find(|s| s.session_id == "short-lived")
        .expect("session still listed");
    assert!(!s.alive, "session should NOT have respawned");

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_attach_below_ring_tail_returns_snapshot() {
    let (server, tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // 1. Attach "flood" (resume: false, offset 0) -> Replay { offset: 0 }
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("flood", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    // 2. Write the flood command with N = 400000. Then finish() the send side and stop the recv side.
    let flood_cmd = "sleep 1; awk 'BEGIN{printf \"\\033[?1049h\\033[H\\033[2J%s%s\\r\\n\", \"TUI\", \"-HEADER\"; for(i=0;i<400000;i++) printf \"\\033[2;1H\\033[2Kcount %d\", i; printf \"\\033[2;1H\\033[2K%s%s\", \"FLOOD\", \"-DONE\"}'; touch flood-done; sleep 600\n";
    within(psend.write_all(flood_cmd.as_bytes())).await.unwrap();
    let _ = psend.finish();
    let _ = precv.stop(VarInt::from_u32(0));

    // 3. Poll flood-done
    let done_path = tmp.path().join("flood-done");
    let start = std::time::Instant::now();
    while !done_path.exists() {
        if start.elapsed() > Duration::from_secs(60) {
            panic!("timed out waiting for flood-done");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 4. Open a new PTY stream with resume: true and last_ack_offset: 0.
    let (mut psend2, mut precv2) = open(&conn, StreamPurpose::Pty).await;
    let mut attach_hdr = PtyAttachHeader::new("flood", 0, true);
    attach_hdr.accept_compressed_snapshot = true;
    within(write_pty_attach_header(&mut psend2, &attach_hdr))
        .await
        .unwrap();

    let ack2 = within(read_pty_attach_ack(&mut precv2)).await.unwrap();
    let screen_bytes = match ack2 {
        PtyAttachAck::Snapshot { offset, screen, .. } => {
            assert!(
                offset > 4 * 1024 * 1024,
                "offset must be past ring capacity"
            );
            screen
        }
        PtyAttachAck::SnapshotGzip {
            offset,
            uncompressed_screen_len,
            screen: screen_gz,
            ..
        } => {
            assert!(
                offset > 4 * 1024 * 1024,
                "offset must be past ring capacity"
            );
            use std::io::Read;
            let mut screen = Vec::with_capacity(uncompressed_screen_len as usize);
            flate2::read::GzDecoder::new(&screen_gz[..])
                .read_to_end(&mut screen)
                .unwrap();
            screen
        }
        PtyAttachAck::Replay { .. } => panic!("expected snapshot on underrun"),
    };

    let mut replica = vt100::Parser::new(nz(24), nz(80), 0);
    replica.process(&screen_bytes);
    assert!(replica.screen().alternate_screen());
    assert!(replica.screen().contents().contains("TUI-HEADER"));

    // 5. Keep reading the stream into the replica (initialised with the snapshot) until it contains FLOOD-DONE.
    let mut buf = [0u8; 4096];
    let wait_start = std::time::Instant::now();
    while !replica.screen().contents().contains("FLOOD-DONE") {
        if wait_start.elapsed() > Duration::from_secs(10) {
            panic!(
                "timed out waiting for FLOOD-DONE in replica. Current contents: {:?}",
                replica.screen().contents()
            );
        }
        match tokio::time::timeout(Duration::from_millis(500), precv2.read(&mut buf)).await {
            Ok(Ok(Some(n))) => {
                replica.process(&buf[..n]);
            }
            Ok(Ok(None)) => break,
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => {}
        }
    }
    assert!(replica.screen().contents().contains("FLOOD-DONE"));

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}
async fn read_until(recv: &mut iroh::endpoint::RecvStream, needle: &str, acc: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    within(async {
        while !String::from_utf8_lossy(acc).contains(needle) {
            let n = recv.read(&mut buf).await.unwrap().unwrap();
            acc.extend_from_slice(&buf[..n]);
        }
    })
    .await;
}
#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_compression_gzip_end_to_end() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // 1. Attach to session and produce large scrollback (> 1024 bytes) in normal screen
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("snap-gzip", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    let cmd = "for i in $(seq 1 100); do echo \"LINE-$i-abcdefghijklmnopqrstuvwxyz0123456789\"; done; echo FINISHED-ALL-LINES\n";
    within(psend.write_all(cmd.as_bytes())).await.unwrap();

    let mut output = Vec::new();
    read_until(&mut precv, "LINE-100-", &mut output).await;
    read_until(&mut precv, "FINISHED-ALL-LINES\r\n", &mut output).await;

    // 2. Attach second client with future offset (> head) and accept_compressed_snapshot: true
    let (mut psend2, mut precv2) = open(&conn, StreamPurpose::Pty).await;
    let mut attach_hdr = PtyAttachHeader::new("snap-gzip", u64::MAX - 1, true);
    attach_hdr.accept_compressed_snapshot = true;
    within(write_pty_attach_header(&mut psend2, &attach_hdr))
        .await
        .unwrap();

    let ack2 = within(read_pty_attach_ack(&mut precv2)).await.unwrap();
    match ack2 {
        PtyAttachAck::SnapshotGzip {
            uncompressed_history_len,
            history: history_gz,
            uncompressed_screen_len,
            screen: screen_gz,
            ..
        } => {
            assert!(uncompressed_history_len > 1000 || uncompressed_screen_len > 1000);
            use std::io::Read;
            let mut decompressed_history = Vec::new();
            flate2::read::GzDecoder::new(&history_gz[..])
                .read_to_end(&mut decompressed_history)
                .unwrap();
            assert_eq!(
                decompressed_history.len(),
                uncompressed_history_len as usize
            );

            let mut decompressed_screen = Vec::new();
            flate2::read::GzDecoder::new(&screen_gz[..])
                .read_to_end(&mut decompressed_screen)
                .unwrap();
            assert_eq!(decompressed_screen.len(), uncompressed_screen_len as usize);
        }
        other => panic!("expected SnapshotGzip, got {other:?}"),
    }

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_stalled_reader_gets_resync_reset() {
    let (server, tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // 1. Attach and read the ack.
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("stall", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert_eq!(ack, PtyAttachAck::Replay { offset: 0 });

    // 2. Write the flood command with N = 1500000. Do not read.
    let flood_cmd = "sleep 1; awk 'BEGIN{printf \"\\033[?1049h\\033[H\\033[2J%s%s\\r\\n\", \"TUI\", \"-HEADER\"; for(i=0;i<1500000;i++) printf \"\\033[2;1H\\033[2Kcount %d\", i; printf \"\\033[2;1H\\033[2K%s%s\", \"FLOOD\", \"-DONE\"}'; touch flood-done; sleep 600\n";
    within(psend.write_all(flood_cmd.as_bytes())).await.unwrap();

    // 3. Poll flood-done
    let done_path = tmp.path().join("flood-done");
    let start = std::time::Instant::now();
    while !done_path.exists() {
        if start.elapsed() > Duration::from_secs(60) {
            panic!("timed out waiting for flood-done");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 4. Read until error. Assert matches!(err, ReadError::Reset(code) if code == VarInt::from_u32(STREAM_ERR_RESYNC))
    let mut buf = [0u8; 8192];
    let mut got_reset = false;
    let read_start = std::time::Instant::now();
    while read_start.elapsed() < Duration::from_secs(10) {
        match precv.read(&mut buf).await {
            Ok(Some(_)) => {
                // keep reading buffered data until the reset arrives
            }
            Ok(None) => panic!("stream closed without reset"),
            Err(iroh::endpoint::ReadError::Reset(code)) => {
                assert_eq!(code, VarInt::from_u32(STREAM_ERR_RESYNC));
                got_reset = true;
                break;
            }
            Err(other) => panic!("unexpected read error: {other:?}"),
        }
    }
    assert!(got_reset, "expected STREAM_ERR_RESYNC reset");

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_session_create_with_custom_workdir() {
    let (server, tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let sub_dir = tmp.path().join("my_subproject");
    std::fs::create_dir_all(&sub_dir).unwrap();
    let canonical_sub = sub_dir.canonicalize().unwrap();

    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;

    // Create session specifying workdir
    within(write_rpc_request(
        &mut rsend,
        1,
        &RpcRequest::SessionCreate {
            session_id: "custom-cwd-sess".into(),
            command: None,
            workdir: Some(canonical_sub.display().to_string()),
        },
    ))
    .await
    .unwrap();

    let created = match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Ok(summary)) => summary,
        other => panic!("expected SessionCreate Ok, got {other:?}"),
    };

    assert_eq!(created.session_id, "custom-cwd-sess");
    assert_eq!(created.workdir, canonical_sub.display().to_string());

    // Attach PTY and verify working directory via pwd
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("custom-cwd-sess", 0, false),
    ))
    .await
    .unwrap();
    let ack = within(read_pty_attach_ack(&mut precv)).await.unwrap();
    assert!(matches!(ack, PtyAttachAck::Replay { .. }));

    within(psend.write_all(b"pwd > pwd.out\n")).await.unwrap();

    let out_file = canonical_sub.join("pwd.out");
    let start = std::time::Instant::now();
    while !out_file.exists() {
        if start.elapsed() > Duration::from_secs(5) {
            panic!("timed out waiting for pwd.out in custom workdir");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let pwd_content = std::fs::read_to_string(&out_file).unwrap();
    assert_eq!(pwd_content.trim(), canonical_sub.display().to_string());

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_session_create_with_invalid_workdir() {
    let (server, tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;

    let non_existent = tmp.path().join("does_not_exist_at_all");
    within(write_rpc_request(
        &mut rsend,
        1,
        &RpcRequest::SessionCreate {
            session_id: "invalid-cwd-sess".into(),
            command: None,
            workdir: Some(non_existent.display().to_string()),
        },
    ))
    .await
    .unwrap();

    match within(read_rpc_response(&mut rrecv))
        .await
        .unwrap()
        .unwrap()
        .payload
    {
        RpcResponse::SessionCreate(Err(err)) => {
            assert!(err.contains("invalid workdir") || err.contains("No such file"));
        }
        other => panic!("expected SessionCreate Err for invalid workdir, got {other:?}"),
    };

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}
