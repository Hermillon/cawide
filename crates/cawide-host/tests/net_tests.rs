//! Integration tests for the Iroh QUIC listener, transport gate, dispatcher and IPC.

mod common;

use std::path::Path;

#[cfg(unix)]
use cawide_host::net::NetError;
use cawide_host::net::{
    send_ipc_request, CawideServer, CawideServerConfig, IpcRequest, IpcResponse, NetworkMode,
};
use cawide_protocol::{
    read_control_message, read_pty_attach_ack, read_rpc_response, write_control_message,
    write_pty_attach_header, write_rpc_request, ControlMessage, PtyAttachAck, PtyAttachHeader,
    RpcRequest, RpcResponse, StreamPurpose, ALPN_CAWIDE, ALPN_CAWIDE_PAIR, CLOSE_PAIRING_DISABLED,
    CLOSE_PAIRING_DONE, CLOSE_UNAUTHORIZED, STREAM_ERR_INVALID_SESSION, STREAM_ERR_PROTOCOL,
};
use common::{authorized_client, client, connect, open, within};
use iroh::endpoint::{ConnectingError, Connection, ConnectionError, RecvStream, VarInt};
use iroh::{Endpoint, SecretKey};

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

/// Asserts the server rejected the connection with `code` (either at connect or right after).
async fn assert_rejected(ep: &Endpoint, server: &CawideServer, alpn: &[u8], code: u32) {
    match connect(ep, server, alpn).await {
        Err(_) => {}
        Ok(conn) => match within(conn.closed()).await {
            ConnectionError::ApplicationClosed(c) => {
                assert_eq!(c.error_code, VarInt::from_u32(code), "close code")
            }
            other => panic!("expected application close, got {other:?}"),
        },
    }
}

async fn read_until(recv: &mut RecvStream, needle: &str, acc: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    within(async {
        while !String::from_utf8_lossy(acc).contains(needle) {
            let n = recv
                .read(&mut buf)
                .await
                .unwrap()
                .expect("stream ended early");
            acc.extend_from_slice(&buf[..n]);
        }
    })
    .await;
}

async fn pair_request(conn: &Connection, secret: [u8; 32], node_id: [u8; 32]) -> ControlMessage {
    let (mut send, mut recv) = open(conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut send,
        &ControlMessage::PairRequest {
            pairing_secret: secret,
            client_node_id: node_id,
            device_name: "iPhone Test".into(),
        },
    ))
    .await
    .unwrap();
    within(read_control_message(&mut recv))
        .await
        .unwrap()
        .expect("pair response")
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_key_rejected_at_transport() {
    let (server, _tmp) = start_server().await;
    let ep = client(SecretKey::generate()).await;
    assert_rejected(&ep, &server, ALPN_CAWIDE, CLOSE_UNAUTHORIZED).await;
    assert!(server.registry().is_empty());
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_alpn_rejected_without_ticket() {
    let (server, _tmp) = start_server().await;
    let ep = client(SecretKey::generate()).await;
    assert_rejected(&ep, &server, ALPN_CAWIDE_PAIR, CLOSE_PAIRING_DISABLED).await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_alpn_rejected_with_close_unsupported_alpn() {
    let (server, _tmp) = start_server().await;
    let key = SecretKey::generate();
    server
        .auth_store()
        .add_key(*key.public().as_bytes(), "Test Device".into())
        .unwrap();
    let ep = client(key).await;
    for legacy_alpn in [b"cawide/4", b"cawide/3"] {
        assert_rejected(
            &ep,
            &server,
            legacy_alpn,
            cawide_protocol::CLOSE_UNSUPPORTED_ALPN,
        )
        .await;
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_alpn_rejected_at_tls_with_crypto_0x78() {
    let (server, _tmp) = start_server().await;
    let key = SecretKey::generate();
    server
        .auth_store()
        .add_key(*key.public().as_bytes(), "Test Device".into())
        .unwrap();
    let ep = client(key).await;
    let err = ep
        .connect(server.endpoint().addr(), b"cawide/999")
        .await
        .unwrap_err();
    match &err {
        iroh::endpoint::ConnectError::Connecting {
            source:
                ConnectingError::ConnectionError {
                    source: ConnectionError::ConnectionClosed(c),
                    ..
                },
            ..
        } => {
            assert_eq!(u64::from(c.error_code), 0x178);
        }
        other => panic!("expected ConnectError::Connecting with crypto(0x78), got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_enrolls_tls_identity_then_session_alpn_accepts() {
    let (server, _tmp) = start_server().await;
    let key = SecretKey::generate();
    let node_id = *key.public().as_bytes();
    let ticket = server
        .pairing_manager()
        .start_pairing(server.node_id(), None, Vec::new())
        .unwrap();

    let ep = client(key).await;
    let conn = connect(&ep, &server, ALPN_CAWIDE_PAIR)
        .await
        .expect("pair connect");
    let resp = pair_request(&conn, ticket.pairing_secret, node_id).await;
    match resp {
        ControlMessage::PairResponse {
            success: true,
            error: None,
            host_name: Some(name),
        } => {
            assert!(
                !name.trim().is_empty() && name.chars().count() <= 64,
                "host_name must be non-empty trimmed and at most 64 chars, got {name:?}"
            );
        }
        other => panic!("expected successful PairResponse with host_name, got {other:?}"),
    }
    conn.close(VarInt::from_u32(CLOSE_PAIRING_DONE), b"pairing complete");

    assert!(server.auth_store().is_authorized(&node_id));
    assert!(
        server.pairing_manager().active_ticket().is_none(),
        "ticket is single-use"
    );

    let conn = connect(&ep, &server, ALPN_CAWIDE)
        .await
        .expect("session connect");
    let (mut send, mut recv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut send,
        &ControlMessage::Ping { client_ts: 7 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut recv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 7, .. }) => {}
        other => panic!("unexpected {other:?}"),
    }
    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_rejects_mismatched_node_id_without_consuming_ticket() {
    let (server, _tmp) = start_server().await;
    let key = SecretKey::generate();
    let other = SecretKey::generate();
    let ticket = server
        .pairing_manager()
        .start_pairing(server.node_id(), None, Vec::new())
        .unwrap();

    let ep = client(key).await;
    let conn = connect(&ep, &server, ALPN_CAWIDE_PAIR)
        .await
        .expect("pair connect");
    let resp = pair_request(&conn, ticket.pairing_secret, *other.public().as_bytes()).await;
    assert!(matches!(
        resp,
        ControlMessage::PairResponse { success: false, .. }
    ));
    conn.close(VarInt::from_u32(CLOSE_PAIRING_DONE), b"done");

    assert!(!server.auth_store().is_authorized(other.public().as_bytes()));
    assert!(server.auth_store().list_keys().is_empty());
    assert!(server.pairing_manager().active_ticket().is_some());
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_rejects_wrong_secret_without_consuming_ticket() {
    let (server, _tmp) = start_server().await;
    let key = SecretKey::generate();
    let node_id = *key.public().as_bytes();
    server
        .pairing_manager()
        .start_pairing(server.node_id(), None, Vec::new())
        .unwrap();

    let ep = client(key).await;
    let conn = connect(&ep, &server, ALPN_CAWIDE_PAIR)
        .await
        .expect("pair connect");
    let resp = pair_request(&conn, [0u8; 32], node_id).await;
    assert!(matches!(
        resp,
        ControlMessage::PairResponse { success: false, .. }
    ));
    conn.close(VarInt::from_u32(CLOSE_PAIRING_DONE), b"done");

    assert!(!server.auth_store().is_authorized(&node_id));
    assert!(server.pairing_manager().active_ticket().is_some());
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pty_attach_echo_control_and_replay() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // First attach.
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("s1", 0, false),
    ))
    .await
    .unwrap();
    assert_eq!(
        within(read_pty_attach_ack(&mut precv)).await.unwrap(),
        PtyAttachAck::Replay { offset: 0 }
    );
    within(psend.write_all(b"echo CAWIDE_QUIC_OK\n"))
        .await
        .unwrap();
    let mut acc = Vec::new();
    read_until(&mut precv, "CAWIDE_QUIC_OK", &mut acc).await;

    let start = std::time::Instant::now();
    let mut got_input = false;
    while start.elapsed() < std::time::Duration::from_secs(2) {
        if let Ok(IpcResponse::Status {
            last_input_unix, ..
        }) = send_ipc_request(server.socket_path(), &IpcRequest::Status).await
        {
            if last_input_unix > 0 {
                got_input = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(got_input, "expected last_input_unix > 0 within 2s");

    // Control stream: resize, ping, session query.
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Resize {
            cols: 120,
            rows: 40,
        },
    ))
    .await
    .unwrap();
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 42 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 42, .. }) => {}
        other => panic!("unexpected {other:?}"),
    }
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(&mut rsend, 1, &RpcRequest::SessionList))
        .await
        .unwrap();
    match within(read_rpc_response(&mut rrecv)).await.unwrap() {
        Some(frame) => match frame.payload {
            RpcResponse::SessionList(Ok(active_sessions)) => {
                assert!(active_sessions.iter().any(|s| s.session_id == "s1"));
            }
            other => panic!("unexpected {other:?}"),
        },
        None => panic!("unexpected EOF"),
    }
    let session = server.registry().get("s1").expect("session registered");
    assert_eq!(session.size().unwrap(), (120, 40));

    // Detach and re-attach: the session persists and replays from offset 0.
    within(async { psend.finish().unwrap() }).await;
    drop(precv);
    let (mut psend2, mut precv2) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend2,
        &PtyAttachHeader::new("s1", 0, false),
    ))
    .await
    .unwrap();
    assert_eq!(
        within(read_pty_attach_ack(&mut precv2)).await.unwrap(),
        PtyAttachAck::Replay { offset: 0 }
    );
    let mut replay = Vec::new();
    read_until(&mut precv2, "CAWIDE_QUIC_OK", &mut replay).await;

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_session_id_resets_stream() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("../etc", 0, false),
    ))
    .await
    .unwrap();
    let mut buf = [0u8; 16];
    let res = within(precv.read(&mut buf)).await;
    match res {
        Err(iroh::endpoint::ReadError::Reset(code)) => {
            assert_eq!(code, VarInt::from_u32(STREAM_ERR_INVALID_SESSION))
        }
        other => panic!("expected stream reset, got {other:?}"),
    }
    assert!(server.registry().is_empty());
    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn control_stream_protocol_error_resets_after_ping() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 9 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 9, .. }) => {}
        other => panic!("expected Pong, got {other:?}"),
    }
    // A length-prefixed frame whose payload is not a valid ControlMessage.
    within(csend.write_all(&[0, 0, 0, 2, 0xFF, 0xFF]))
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    match within(crecv.read(&mut buf)).await {
        Err(iroh::endpoint::ReadError::Reset(code)) => {
            assert_eq!(code, VarInt::from_u32(STREAM_ERR_PROTOCOL))
        }
        other => panic!("expected stream reset, got {other:?}"),
    }
    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_pipelined_requests_echo_request_ids() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Rpc).await;
    let root = server.registry().workdir().display().to_string();
    let list = RpcRequest::FsList {
        root: root.clone(),
        path: ".".into(),
        recursive: false,
    };
    let status = RpcRequest::Git {
        root,
        op: cawide_protocol::types::GitOp::Status,
    };
    within(write_rpc_request(&mut send, 7, &list))
        .await
        .unwrap();
    within(write_rpc_request(&mut send, 8, &status))
        .await
        .unwrap();

    let first = within(read_rpc_response(&mut recv))
        .await
        .unwrap()
        .expect("rpc response");
    assert_eq!(first.request_id, 7);
    match first.payload {
        RpcResponse::FsList(Ok(entries)) => {
            assert!(
                entries.iter().any(|e| e.name == "conf" && e.is_dir),
                "{entries:?}"
            )
        }
        other => panic!("unexpected {other:?}"),
    }
    let second = within(read_rpc_response(&mut recv))
        .await
        .unwrap()
        .expect("rpc response");
    assert_eq!(second.request_id, 8);
    // The temp workdir is not a git repository.
    assert!(
        matches!(second.payload, RpcResponse::Git { result: Err(_) }),
        "{:?}",
        second.payload
    );
    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn ipc_pair_status_stop_and_single_instance() {
    let (server, tmp) = start_server().await;
    let socket = server.socket_path().to_path_buf();

    match within(send_ipc_request(&socket, &IpcRequest::Pair))
        .await
        .unwrap()
    {
        IpcResponse::PairTicket { uri, qr_text, .. } => {
            assert!(uri.starts_with(&format!(
                "cawide://pair?node={}",
                hex::encode(server.node_id())
            )));
            assert!(!qr_text.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
    match within(send_ipc_request(&socket, &IpcRequest::Status))
        .await
        .unwrap()
    {
        IpcResponse::Status {
            pairing_active,
            node_id,
            active_connections,
            last_input_unix,
            ..
        } => {
            assert!(pairing_active);
            assert_eq!(node_id, hex::encode(server.node_id()));
            assert!(!active_connections);
            assert_eq!(last_input_unix, 0);
        }
        other => panic!("unexpected {other:?}"),
    }

    let second = within(CawideServer::bind(config(tmp.path()))).await;
    assert!(matches!(second, Err(NetError::DaemonAlreadyRunning(_))));
    // The failed second bind must not have disturbed the running daemon's socket.
    assert!(matches!(
        within(send_ipc_request(&socket, &IpcRequest::Status))
            .await
            .unwrap(),
        IpcResponse::Status { .. }
    ));

    assert_eq!(
        within(send_ipc_request(&socket, &IpcRequest::Stop))
            .await
            .unwrap(),
        IpcResponse::Ok
    );
    within(server.wait_for_stop_request()).await;
    server.shutdown().await.unwrap();
    assert!(!socket.exists());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn stale_socket_is_recovered() {
    let tmp = tempfile::tempdir().unwrap();
    let conf = tmp.path().join("conf");
    std::fs::create_dir_all(&conf).unwrap();
    let sock = conf.join("cawide.sock");
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());

    let server = within(CawideServer::bind(config(tmp.path())))
        .await
        .unwrap();
    assert!(matches!(
        within(send_ipc_request(&sock, &IpcRequest::Status))
            .await
            .unwrap(),
        IpcResponse::Status { .. }
    ));
    server.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn server_binds_with_port_and_external_addr() {
    let tmp = tempfile::tempdir().unwrap();
    let mut conf = config(tmp.path());
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    conf.port = Some(port);
    let ext_addr: std::net::SocketAddr = "203.0.113.7:20001".parse().unwrap();
    conf.external_addr = Some(ext_addr);

    let server = within(CawideServer::bind(conf)).await.unwrap();
    let addrs: Vec<std::net::SocketAddr> = server.endpoint().addr().ip_addrs().copied().collect();
    assert!(addrs.contains(&ext_addr));
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn host_identity_persists_across_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let server = within(CawideServer::bind(config(tmp.path())))
        .await
        .unwrap();
    let id = server.node_id();
    server.shutdown().await.unwrap();

    let server = within(CawideServer::bind(config(tmp.path())))
        .await
        .unwrap();
    assert_eq!(server.node_id(), id);
    server.shutdown().await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tmp.path().join("conf/host_key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_port_list_returns_ok() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(&mut send, 42, &RpcRequest::PortList))
        .await
        .unwrap();

    let frame = within(read_rpc_response(&mut recv))
        .await
        .unwrap()
        .expect("rpc response");
    assert_eq!(frame.request_id, 42);
    assert!(
        matches!(frame.payload, RpcResponse::PortList(Ok(_))),
        "expected PortList(Ok), got {:?}",
        frame.payload
    );

    server.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn ipc_open_url_broadcasts_to_connected_client() {
    let (server, _tmp) = start_server().await;
    let socket = server.socket_path().to_path_buf();

    // 1. No connections -> returns IpcResponse::Error(...)
    let req = IpcRequest::OpenUrl {
        url: "http://localhost:3000/".to_string(),
        session_id: Some("sess-1".to_string()),
    };
    let resp = within(send_ipc_request(&socket, &req)).await.unwrap();
    assert!(
        matches!(&resp, IpcResponse::Error(m) if m.contains("No phone is connected")),
        "expected error when no connections, got {resp:?}"
    );

    // 2. Authorized client connects, opens Control stream and Pings, waiting for Pong.
    let (_ep, conn) = authorized_client(&server).await;
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 42 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 42, .. }) => {}
        other => panic!("unexpected {other:?}"),
    }

    // 3. Send IPC OpenUrl -> IpcResponse::Ok
    let resp = within(send_ipc_request(&socket, &req)).await.unwrap();
    assert_eq!(resp, IpcResponse::Ok);

    // 4. Assert HostEvent::OpenUrl arrives on the control stream.
    let mut got_open_url = false;
    for _ in 0..10 {
        let msg = within(read_control_message(&mut crecv)).await.unwrap();
        if let Some(ControlMessage::HostEvent(cawide_protocol::types::HostEvent::OpenUrl {
            url,
            session_id,
        })) = msg
        {
            assert_eq!(url, "http://localhost:3000/");
            assert_eq!(session_id, Some("sess-1".to_string()));
            got_open_url = true;
            break;
        }
    }
    assert!(
        got_open_url,
        "expected HostEvent::OpenUrl on control stream"
    );

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn session_create_inherits_connection_resize_dimensions() {
    let (server, _tmp) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // 1. Send ControlMessage::Resize { cols: 112, rows: 41 }
    let (mut csend, mut crecv) = open(&conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Resize {
            cols: 112,
            rows: 41,
        },
    ))
    .await
    .unwrap();
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 42 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 42, .. }) => {}
        other => panic!("unexpected {other:?}"),
    }

    // 2. Call RpcRequest::SessionCreate
    let (mut rsend, mut rrecv) = open(&conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(
        &mut rsend,
        1,
        &RpcRequest::SessionCreate {
            session_id: "s_resize_test".into(),
            command: None,
            workdir: None,
        },
    ))
    .await
    .unwrap();
    let resp = within(read_rpc_response(&mut rrecv)).await.unwrap();
    assert!(
        matches!(
            resp,
            Some(cawide_protocol::RpcFrame {
                payload: RpcResponse::SessionCreate(Ok(_)),
                ..
            })
        ),
        "SessionCreate failed: {resp:?}"
    );

    // 3. Attach to the session
    let (mut psend, mut precv) = open(&conn, StreamPurpose::Pty).await;
    within(write_pty_attach_header(
        &mut psend,
        &PtyAttachHeader::new("s_resize_test", 0, false),
    ))
    .await
    .unwrap();
    assert_eq!(
        within(read_pty_attach_ack(&mut precv)).await.unwrap(),
        PtyAttachAck::Replay { offset: 0 }
    );

    // 4. Send stty size\n and assert output contains 41 112
    within(psend.write_all(b"stty size\n")).await.unwrap();
    let mut acc = Vec::new();
    read_until(&mut precv, "41 112", &mut acc).await;

    conn.close(VarInt::from_u32(0), b"bye");
    server.shutdown().await.unwrap();
}
