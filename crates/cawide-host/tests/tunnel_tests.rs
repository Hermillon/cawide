//! Integration tests for host web tunnel stream handling.

mod common;

use std::net::SocketAddr;

use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_protocol::{
    read_tunnel_ack, write_tunnel_open, StreamPurpose, TunnelAck, TunnelFailure, TunnelOpen,
};
use common::{authorized_client, open, within};
use tokio::net::TcpListener;

async fn start_server() -> (CawideServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = CawideServerConfig {
        config_dir: dir.path().join("conf"),
        network_mode: NetworkMode::LocalOnly,
        workdir: dir.path().to_path_buf(),
        launch_cmd: None,
        upload_dir: Some(dir.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };
    let server = CawideServer::bind(config).await.unwrap();
    (server, dir)
}

async fn start_echo_server(addr: &str) -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping echo server on {addr}: {e}");
            return None;
        }
    };
    let local_addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Some((local_addr, handle))
}

#[tokio::test]
async fn test_tunnel_echo_and_eof() {
    let (server, _dir) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (echo_addr, _echo_task) = start_echo_server("127.0.0.1:0")
        .await
        .expect("bind echo server");

    let (mut send, mut recv) = open(&conn, StreamPurpose::Tunnel).await;
    let open_req = TunnelOpen {
        host: "localhost".to_string(),
        port: echo_addr.port(),
    };
    within(write_tunnel_open(&mut send, &open_req))
        .await
        .unwrap();

    let ack = within(read_tunnel_ack(&mut recv)).await.unwrap();
    assert_eq!(ack, TunnelAck::Connected);

    // Echo bytes
    within(send.write_all(b"hello tunnel")).await.unwrap();
    let mut buf = vec![0u8; 12];
    within(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"hello tunnel");

    // Client finish reaches server as EOF, closing the stream
    within(async { send.finish().unwrap() }).await;
    let mut rest = [0u8; 16];
    let n = within(recv.read(&mut rest)).await.unwrap();
    assert_eq!(n, None);
}

#[tokio::test]
async fn test_tunnel_closed_port_refused() {
    let (server, _dir) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    // Pick an unused port by binding and immediately dropping listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let (mut send, mut recv) = open(&conn, StreamPurpose::Tunnel).await;
    let open_req = TunnelOpen {
        host: "localhost".to_string(),
        port,
    };
    within(write_tunnel_open(&mut send, &open_req))
        .await
        .unwrap();

    let ack = within(read_tunnel_ack(&mut recv)).await.unwrap();
    match ack {
        TunnelAck::Failed { reason, .. } => assert_eq!(reason, TunnelFailure::Refused),
        TunnelAck::Connected => panic!("expected Refused, got Connected"),
    }
}

#[tokio::test]
async fn test_tunnel_dns_failed() {
    let (server, _dir) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Tunnel).await;
    let open_req = TunnelOpen {
        host: "nonexistent.invalid".to_string(),
        port: 80,
    };
    within(write_tunnel_open(&mut send, &open_req))
        .await
        .unwrap();

    let ack = within(read_tunnel_ack(&mut recv)).await.unwrap();
    match ack {
        TunnelAck::Failed { reason, .. } => {
            assert!(
                matches!(reason, TunnelFailure::DnsFailed | TunnelFailure::TimedOut),
                "expected DnsFailed or TimedOut (if ISP hijacks NXDOMAIN), got {:?}",
                reason
            );
        }
        TunnelAck::Connected => panic!("expected failure, got Connected"),
    }
}

#[tokio::test]
async fn test_tunnel_invalid_target_empty() {
    let (server, _dir) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Tunnel).await;
    let open_req = TunnelOpen {
        host: "".to_string(),
        port: 80,
    };
    within(write_tunnel_open(&mut send, &open_req))
        .await
        .unwrap();

    let ack = within(read_tunnel_ack(&mut recv)).await.unwrap();
    match ack {
        TunnelAck::Failed { reason, .. } => assert_eq!(reason, TunnelFailure::InvalidTarget),
        TunnelAck::Connected => panic!("expected InvalidTarget, got Connected"),
    }
}

#[tokio::test]
async fn test_tunnel_ipv6_localhost() {
    let Some((echo_addr, _echo_task)) = start_echo_server("[::1]:0").await else {
        eprintln!("Skipping IPv6 localhost test: [::1]:0 cannot bind");
        return;
    };

    let (server, _dir) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (mut send, mut recv) = open(&conn, StreamPurpose::Tunnel).await;
    let open_req = TunnelOpen {
        host: "localhost".to_string(),
        port: echo_addr.port(),
    };
    within(write_tunnel_open(&mut send, &open_req))
        .await
        .unwrap();

    let ack = within(read_tunnel_ack(&mut recv)).await.unwrap();
    assert_eq!(ack, TunnelAck::Connected);

    within(send.write_all(b"ipv6 ping")).await.unwrap();
    let mut buf = vec![0u8; 9];
    within(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"ipv6 ping");
}

#[tokio::test]
async fn test_tunnel_dot_localhost_alias() {
    let (server, _dir) = start_server().await;
    let (_ep, conn) = authorized_client(&server).await;

    let (echo_addr, _echo_task) = start_echo_server("127.0.0.1:0")
        .await
        .expect("bind echo server");

    let (mut send, mut recv) = open(&conn, StreamPurpose::Tunnel).await;
    let open_req = TunnelOpen {
        host: "foo.localhost".to_string(),
        port: echo_addr.port(),
    };
    within(write_tunnel_open(&mut send, &open_req))
        .await
        .unwrap();

    let ack = within(read_tunnel_ack(&mut recv)).await.unwrap();
    assert_eq!(ack, TunnelAck::Connected);

    within(send.write_all(b"alias test")).await.unwrap();
    let mut buf = vec![0u8; 10];
    within(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"alias test");
}
