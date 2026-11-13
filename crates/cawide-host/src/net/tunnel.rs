//! Web tunnel stream handler: forwards raw bidirectional TCP traffic to target destinations.

use std::time::{Duration, Instant};

use cawide_protocol::{
    read_tunnel_open, write_tunnel_ack, TunnelAck, TunnelFailure, STREAM_ERR_PROTOCOL,
};
use iroh::endpoint::{RecvStream, SendStream, VarInt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::net::dispatcher::reset_stream;
use crate::net::HANDSHAKE_STEP_TIMEOUT;

const TOTAL_CONNECT_BUDGET: Duration = Duration::from_secs(9);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Handles an incoming bidirectional tunnel stream (purpose `0x05`).
pub async fn handle_tunnel_stream(mut send: SendStream, mut recv: RecvStream) {
    let open = match tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, read_tunnel_open(&mut recv)).await
    {
        Ok(Ok(Some(open))) => open,
        Ok(Ok(None)) | Err(_) => return,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "failed reading tunnel open header");
            reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
            return;
        }
    };

    let raw_host = open.host.trim();
    let mut host = raw_host;
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }

    let mut target_host = host.to_string();
    if target_host.to_ascii_lowercase().ends_with(".localhost") {
        target_host = "localhost".to_string();
    }

    // Validation
    let is_invalid = target_host.is_empty()
        || target_host.len() > 253
        || target_host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || open.port == 0;

    if is_invalid {
        let _ = write_tunnel_ack(
            &mut send,
            &TunnelAck::Failed {
                reason: TunnelFailure::InvalidTarget,
                message: "invalid target host or port".to_string(),
            },
        )
        .await;
        let _ = send.finish();
        return;
    }

    match connect_target(&target_host, open.port).await {
        Ok(tcp) => {
            let _ = tcp.set_nodelay(true);
            tracing::debug!(host = %target_host, port = open.port, "tunnel opened");
            if write_tunnel_ack(&mut send, &TunnelAck::Connected)
                .await
                .is_err()
            {
                return;
            }

            let (mut tr, mut tw) = tcp.into_split();
            let up = async {
                let _ = tokio::io::copy(&mut recv, &mut tw).await;
                let _ = tw.shutdown().await;
            };
            let down = async {
                let res = tokio::io::copy(&mut tr, &mut send).await;
                if res.is_err() {
                    let _ = send.reset(VarInt::from_u32(0));
                } else {
                    let _ = send.finish();
                }
            };
            tokio::pin!(up);
            tokio::pin!(down);
            tokio::select! {
                _ = &mut down => {}
                _ = &mut up => {
                    let _ = (&mut down).await;
                }
            }
        }
        Err((reason, message)) => {
            tracing::debug!(host = %target_host, port = open.port, ?reason, "tunnel failed");
            let _ = write_tunnel_ack(&mut send, &TunnelAck::Failed { reason, message }).await;
            let _ = send.finish();
        }
    }
}

async fn connect_target(host: &str, port: u16) -> Result<TcpStream, (TunnelFailure, String)> {
    let start = Instant::now();

    let lookup_res = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await;

    let addrs = match lookup_res {
        Ok(Ok(iter)) => {
            let vec: Vec<_> = iter.collect();
            if vec.is_empty() {
                return Err((
                    TunnelFailure::DnsFailed,
                    format!("no IP addresses found for {host}"),
                ));
            }
            vec
        }
        Ok(Err(e)) => {
            return Err((
                TunnelFailure::DnsFailed,
                format!("DNS lookup failed for {host}: {e}"),
            ));
        }
        Err(_) => {
            return Err((
                TunnelFailure::TimedOut,
                format!("DNS lookup timed out for {host}"),
            ));
        }
    };

    let mut last_err = None;
    for addr in addrs {
        let elapsed = start.elapsed();
        if elapsed >= TOTAL_CONNECT_BUDGET {
            return Err((
                TunnelFailure::TimedOut,
                format!("connect budget exceeded for {host}:{port}"),
            ));
        }
        let remaining = TOTAL_CONNECT_BUDGET - elapsed;
        match tokio::time::timeout(remaining, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                last_err = Some(e);
            }
            Err(_) => {
                return Err((
                    TunnelFailure::TimedOut,
                    format!("connection attempt timed out for {addr}"),
                ));
            }
        }
    }

    if let Some(err) = last_err {
        let failure = match err.kind() {
            std::io::ErrorKind::ConnectionRefused => TunnelFailure::Refused,
            std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
                TunnelFailure::Unreachable
            }
            std::io::ErrorKind::TimedOut => TunnelFailure::TimedOut,
            _ => TunnelFailure::Other,
        };
        Err((failure, err.to_string()))
    } else {
        Err((
            TunnelFailure::Unreachable,
            format!("could not connect to {host}:{port}"),
        ))
    }
}
