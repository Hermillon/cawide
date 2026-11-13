//! Property tests for cawide-protocol codecs, framing, and URI parsing.

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use cawide_protocol::codec::{
    read_control_message, read_pty_attach_ack, read_pty_attach_header, read_rpc_request,
    read_rpc_response, read_tunnel_ack, read_tunnel_open, write_control_message, write_rpc_request,
    write_rpc_response, write_rpc_response_with_caps, write_tunnel_ack, write_tunnel_open,
    MAX_CONTROL_FRAME_SIZE, MAX_PTY_ATTACH_HEADER_SIZE, MAX_RPC_FRAME_SIZE,
};
use cawide_protocol::error::ProtocolError;
use cawide_protocol::pairing::PairingUri;
use cawide_protocol::types::{
    AgentState, AgentStatus, ControlMessage, ForgeAccountOp, ForgeAccountReply, ForgeAccountsState,
    ForgeError, ForgeErrorKind, ForgeRepoOp, ForgeRepoReply, FsChunk, FsEntry, FsReadResult,
    FsSearchResult, GitError, GitErrorKind, GitOp, GitReply, HostEvent, HostInfo, ListeningPort,
    PushChannel, RpcFrame, RpcRequest, RpcResponse, SessionSummary, TunnelAck, TunnelFailure,
    TunnelOpen, VoiceCompileResult,
};
use proptest::prelude::*;

fn arb_agent_status() -> impl Strategy<Value = AgentStatus> {
    prop_oneof![
        Just(AgentStatus::Idle),
        any::<String>().prop_map(|task_desc| AgentStatus::Thinking { task_desc }),
        (
            any::<String>(),
            prop::collection::vec(any::<String>(), 0..4)
        )
            .prop_map(|(prompt, options)| AgentStatus::WaitingForInput { prompt, options }),
        any::<String>().prop_map(|summary| AgentStatus::Completed { summary }),
    ]
}

fn arb_agent_state() -> impl Strategy<Value = AgentState> {
    (any::<String>(), arb_agent_status(), any::<u64>()).prop_map(|(agent, status, updated_ts)| {
        AgentState {
            agent,
            status,
            updated_ts,
        }
    })
}

fn arb_host_event() -> impl Strategy<Value = HostEvent> {
    prop_oneof![
        any::<String>().prop_map(|root| HostEvent::GitChanged { root }),
        (
            any::<String>(),
            prop::collection::vec(any::<String>(), 0..8)
        )
            .prop_map(|(root, paths)| HostEvent::FsChanged { root, paths }),
        Just(HostEvent::SessionsChanged),
        arb_session_summary().prop_map(|summary| HostEvent::SessionUpdated { summary }),
        Just(HostEvent::Resync),
        prop::collection::vec(arb_listening_port(), 0..4)
            .prop_map(|ports| HostEvent::PortsChanged { ports }),
        (any::<String>(), any::<String>())
            .prop_map(|(session_id, url)| HostEvent::WebUrlDetected { session_id, url }),
        (any::<String>(), any::<Option<String>>())
            .prop_map(|(url, session_id)| HostEvent::OpenUrl { url, session_id }),
    ]
}

fn arb_control_message() -> impl Strategy<Value = ControlMessage> {
    prop_oneof![
        (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<String>()).prop_map(
            |(pairing_secret, client_node_id, device_name)| ControlMessage::PairRequest {
                pairing_secret,
                client_node_id,
                device_name,
            }
        ),
        (
            any::<bool>(),
            any::<Option<String>>(),
            any::<Option<String>>(),
        )
            .prop_map(|(success, error, host_name)| ControlMessage::PairResponse {
                success,
                error,
                host_name,
            }),
        (any::<u16>(), any::<u16>()).prop_map(|(cols, rows)| ControlMessage::Resize { cols, rows }),
        any::<u64>().prop_map(|client_ts| ControlMessage::Ping { client_ts }),
        (any::<u64>(), any::<u64>())
            .prop_map(|(client_ts, host_ts)| ControlMessage::Pong { client_ts, host_ts }),
        arb_host_event().prop_map(ControlMessage::HostEvent),
    ]
}

fn arb_rpc_request() -> impl Strategy<Value = RpcRequest> {
    prop_oneof![
        (any::<String>(), any::<String>(), any::<bool>()).prop_map(|(root, path, recursive)| {
            RpcRequest::FsList {
                root,
                path,
                recursive,
            }
        }),
        (any::<String>(), any::<String>(), any::<u64>(), any::<u32>(),).prop_map(
            |(root, path, offset, length)| {
                RpcRequest::FsRead {
                    root,
                    path,
                    offset,
                    length,
                }
            }
        ),
        (any::<String>(), any::<String>())
            .prop_map(|(root, query)| RpcRequest::FsSearch { root, query }),
        (any::<String>(), prop::collection::vec(any::<u8>(), 0..512))
            .prop_map(|(filename, data)| RpcRequest::FsUpload { filename, data }),
        (any::<String>(), any::<String>())
            .prop_map(|(root, target)| RpcRequest::RemoteOpen { root, target }),
        (any::<String>(), arb_git_op()).prop_map(|(root, op)| RpcRequest::Git { root, op }),
        arb_forge_account_op().prop_map(|op| RpcRequest::ForgeAccounts { op }),
        (
            any::<String>(),
            any::<Option<String>>(),
            arb_forge_repo_op()
        )
            .prop_map(|(root, account, op)| RpcRequest::Forge { root, account, op },),
        Just(RpcRequest::SessionList),
        (
            any::<String>(),
            any::<Option<String>>(),
            any::<Option<String>>(),
        )
            .prop_map(|(session_id, command, workdir)| {
                RpcRequest::SessionCreate {
                    session_id,
                    command,
                    workdir,
                }
            }),
        any::<String>().prop_map(|session_id| RpcRequest::SessionKill { session_id }),
        Just(RpcRequest::HostInfo),
        (any::<String>(), any::<String>(), any::<u64>(), any::<u32>(),).prop_map(
            |(root, path, offset, length)| RpcRequest::FsReadChunk {
                root,
                path,
                offset,
                length,
            }
        ),
        Just(RpcRequest::PortList),
        (
            any::<String>(),
            any::<String>(),
            any::<Option<String>>(),
            any::<String>(),
        )
            .prop_map(|(session_id, transcript, active_file, language_mode)| {
                RpcRequest::VoiceCompilePrompt {
                    session_id,
                    transcript,
                    active_file,
                    language_mode,
                }
            }),
        any::<Option<(String, String)>>().prop_map(|opt| RpcRequest::SetPushChannel {
            channel: opt.map(|(channel_id, secret)| PushChannel { channel_id, secret }),
        }),
    ]
}

fn arb_fs_entry() -> impl Strategy<Value = FsEntry> {
    (
        any::<String>(),
        any::<String>(),
        any::<bool>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(|(name, path, is_dir, size, modified_ts)| FsEntry {
            name,
            path,
            is_dir,
            size,
            modified_ts,
        })
}

fn arb_fs_read_result() -> impl Strategy<Value = FsReadResult> {
    (
        prop::collection::vec(any::<u8>(), 0..256),
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(|(data, too_large, total_size)| FsReadResult {
            data,
            too_large,
            total_size,
        })
}

fn arb_fs_search_result() -> impl Strategy<Value = FsSearchResult> {
    (
        any::<String>(),
        any::<u32>(),
        prop::collection::vec(any::<u32>(), 0..8),
    )
        .prop_map(|(path, score, match_indices)| FsSearchResult {
            path,
            score,
            match_indices,
        })
}

fn arb_git_op() -> impl Strategy<Value = GitOp> {
    prop_oneof![
        Just(GitOp::Status),
        Just(GitOp::Branches),
        Just(GitOp::Tags),
        Just(GitOp::Stashes),
        Just(GitOp::Remotes),
        Just(GitOp::Identity),
    ]
}

fn arb_forge_account_op() -> impl Strategy<Value = ForgeAccountOp> {
    Just(ForgeAccountOp::List)
}

fn arb_forge_repo_op() -> impl Strategy<Value = ForgeRepoOp> {
    Just(ForgeRepoOp::Repository)
}

fn arb_git_error() -> impl Strategy<Value = GitError> {
    (
        any::<String>(),
        any::<Option<String>>(),
        any::<Option<u16>>(),
    )
        .prop_map(|(message, host, port)| GitError {
            kind: GitErrorKind::Other,
            message,
            host,
            port,
        })
}

fn arb_forge_error() -> impl Strategy<Value = ForgeError> {
    (
        any::<String>(),
        any::<Option<String>>(),
        any::<Option<u16>>(),
    )
        .prop_map(|(message, host, port)| ForgeError {
            kind: ForgeErrorKind::NotFound,
            message,
            git_kind: None,
            host,
            port,
        })
}

fn arb_tunnel_failure() -> impl Strategy<Value = TunnelFailure> {
    prop_oneof![
        Just(TunnelFailure::Refused),
        Just(TunnelFailure::Unreachable),
        Just(TunnelFailure::DnsFailed),
        Just(TunnelFailure::TimedOut),
        Just(TunnelFailure::InvalidTarget),
        Just(TunnelFailure::Other),
    ]
}

fn arb_tunnel_open() -> impl Strategy<Value = TunnelOpen> {
    (
        prop::string::string_regex("[a-zA-Z0-9.-]{1,100}").unwrap(),
        any::<u16>(),
    )
        .prop_map(|(host, port)| TunnelOpen { host, port })
}

fn arb_tunnel_ack() -> impl Strategy<Value = TunnelAck> {
    prop_oneof![
        Just(TunnelAck::Connected),
        (
            arb_tunnel_failure(),
            prop::string::string_regex(".{0,100}").unwrap(),
        )
            .prop_map(|(reason, message)| TunnelAck::Failed { reason, message }),
    ]
}

fn arb_listening_port() -> impl Strategy<Value = ListeningPort> {
    (
        any::<u16>(),
        prop::collection::vec(any::<String>(), 0..3),
        any::<Option<u32>>(),
        any::<Option<String>>(),
        any::<Option<String>>(),
    )
        .prop_map(
            |(port, addresses, pid, process_name, session_id)| ListeningPort {
                port,
                addresses,
                pid,
                process_name,
                session_id,
            },
        )
}

fn arb_session_summary() -> impl Strategy<Value = SessionSummary> {
    (
        any::<String>(),
        any::<String>(),
        any::<Option<String>>(),
        any::<u64>(),
        any::<bool>(),
        any::<Option<i32>>(),
        any::<bool>(),
        prop::option::of(arb_agent_state()),
        any::<Option<String>>(),
        any::<Option<String>>(),
        any::<u64>(),
    )
        .prop_map(
            |(
                session_id,
                workdir,
                active_cmd,
                last_active_ts,
                alive,
                exit_code,
                attached,
                agent,
                git_root,
                title,
                revision,
            )| {
                SessionSummary {
                    session_id,
                    workdir,
                    active_cmd,
                    last_active_ts,
                    alive,
                    exit_code,
                    attached,
                    agent,
                    git_root,
                    title,
                    revision,
                }
            },
        )
}

fn arb_rpc_response() -> impl Strategy<Value = RpcResponse> {
    prop_oneof![
        (
            prop::collection::vec(arb_fs_entry(), 0..4),
            any::<Option<String>>()
        )
            .prop_map(|(items, err)| {
                let res = if let Some(e) = err { Err(e) } else { Ok(items) };
                RpcResponse::FsList(res)
            },),
        (
            prop::option::of(arb_fs_read_result()),
            any::<Option<String>>()
        )
            .prop_map(|(ok, err)| {
                let res = match (ok, err) {
                    (Some(v), _) => Ok(v),
                    (None, Some(e)) => Err(e),
                    (None, None) => Err("error".into()),
                };
                RpcResponse::FsRead(res)
            }),
        (
            prop::collection::vec(arb_fs_search_result(), 0..4),
            any::<Option<String>>()
        )
            .prop_map(|(items, err)| {
                let res = if let Some(e) = err { Err(e) } else { Ok(items) };
                RpcResponse::FsSearch(res)
            },),
        any::<Result<String, String>>().prop_map(RpcResponse::FsUpload),
        any::<Result<(), String>>().prop_map(RpcResponse::RemoteOpen),
        (any::<bool>(), arb_git_error()).prop_map(|(ok, err)| {
            let result = if ok { Ok(GitReply::Done) } else { Err(err) };
            RpcResponse::Git { result }
        }),
        (any::<bool>(), arb_forge_error()).prop_map(|(ok, err)| {
            let result = if ok {
                Ok(ForgeAccountReply::Accounts {
                    state: ForgeAccountsState {
                        accounts: vec![],
                        device_sign_in_hosts: vec![],
                    },
                })
            } else {
                Err(err)
            };
            RpcResponse::ForgeAccounts { result }
        }),
        (any::<bool>(), arb_forge_error()).prop_map(|(ok, err)| {
            let result = if ok {
                Ok(ForgeRepoReply::Done)
            } else {
                Err(err)
            };
            RpcResponse::Forge { result }
        }),
        (
            prop::collection::vec(arb_session_summary(), 0..4),
            any::<Option<String>>()
        )
            .prop_map(|(items, err)| {
                let res = if let Some(e) = err { Err(e) } else { Ok(items) };
                RpcResponse::SessionList(res)
            }),
        (
            prop::option::of(arb_session_summary()),
            any::<Option<String>>()
        )
            .prop_map(|(ok, err)| {
                let res = match (ok, err) {
                    (Some(v), _) => Ok(v),
                    (None, Some(e)) => Err(e),
                    (None, None) => Err("error".into()),
                };
                RpcResponse::SessionCreate(res)
            }),
        any::<Result<(), String>>().prop_map(RpcResponse::SessionKill),
        (
            any::<bool>(),
            (
                any::<String>(),
                any::<String>(),
                any::<String>(),
                any::<String>(),
                any::<String>(),
            ),
            any::<String>(),
        )
            .prop_map(|(ok, (host_name, os, arch, version, workdir), err)| {
                RpcResponse::HostInfo(if ok {
                    Ok(HostInfo {
                        host_name,
                        os,
                        arch,
                        version,
                        workdir,
                    })
                } else {
                    Err(err)
                })
            }),
        (
            any::<bool>(),
            (
                prop::collection::vec(any::<u8>(), 0..64),
                any::<bool>(),
                any::<u64>(),
                any::<u64>(),
            ),
            any::<String>(),
        )
            .prop_map(
                |(ok, (data, too_large, total_size, modified_unix_ns), err)| {
                    RpcResponse::FsReadChunk(if ok {
                        Ok(FsChunk {
                            data,
                            too_large,
                            total_size,
                            modified_unix_ns,
                        })
                    } else {
                        Err(err)
                    })
                }
            ),
        (
            prop::collection::vec(arb_listening_port(), 0..4),
            any::<Option<String>>(),
        )
            .prop_map(|(ports, err)| {
                let res = if let Some(e) = err { Err(e) } else { Ok(ports) };
                RpcResponse::PortList(res)
            }),
        (
            any::<bool>(),
            (any::<String>(), any::<String>()),
            any::<String>(),
        )
            .prop_map(|(ok, (clean_prompt, detected_language), err)| {
                RpcResponse::VoiceCompilePrompt(if ok {
                    Ok(VoiceCompileResult {
                        clean_prompt,
                        detected_language,
                    })
                } else {
                    Err(err)
                })
            }),
        any::<Result<(), String>>().prop_map(RpcResponse::SetPushChannel),
    ]
}

fn arb_socket_addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>()).prop_map(|(octets, port)| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
        }),
        (any::<[u8; 16]>(), any::<u16>()).prop_map(|(octets, port)| {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }),
    ]
}

fn arb_pairing_uri() -> impl Strategy<Value = PairingUri> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        prop::option::of("[a-zA-Z0-9_.-]{1,32}"),
        prop::collection::vec(arb_socket_addr(), 0..=8),
    )
        .prop_map(
            |(host_node_id, pairing_secret, relay_url, direct_addrs)| PairingUri {
                host_node_id,
                pairing_secret,
                relay_url,
                direct_addrs,
            },
        )
}

fn rt() -> &'static tokio::runtime::Runtime {
    use std::sync::LazyLock;
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    });
    &RT
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        rt().block_on(async {

            let mut c1 = Cursor::new(&bytes[..]);
            let _ = read_pty_attach_header(&mut c1).await;

            let mut c2 = Cursor::new(&bytes[..]);
            let _ = read_pty_attach_ack(&mut c2).await;

            let mut c3 = Cursor::new(&bytes[..]);
            let _ = read_control_message(&mut c3).await;

            let mut c4 = Cursor::new(&bytes[..]);
            let _ = read_rpc_request(&mut c4).await;

            let mut c5 = Cursor::new(&bytes[..]);
            let _ = read_rpc_response(&mut c5).await;
        });
    }

    #[test]
    fn prop_declared_lengths_above_max_return_frame_too_large(
        pty_len in (MAX_PTY_ATTACH_HEADER_SIZE as u16 + 1)..=u16::MAX,
        control_len in (MAX_CONTROL_FRAME_SIZE as u32 + 1)..=10_000_000u32,
        rpc_req_len in (MAX_RPC_FRAME_SIZE as u32 + 1)..=100_000_000u32,
        rpc_resp_len in (MAX_RPC_FRAME_SIZE as u32 + 1)..=100_000_000u32,
        req_id in any::<u32>(),
    ) {
        rt().block_on(async {
            // PTY Attach Header
            let pty_bytes = pty_len.to_be_bytes();
            let mut c_pty = Cursor::new(&pty_bytes[..]);
            match read_pty_attach_header(&mut c_pty).await {
                Err(ProtocolError::FrameTooLarge { size, max }) => {
                    prop_assert_eq!(size, pty_len as usize);
                    prop_assert_eq!(max, MAX_PTY_ATTACH_HEADER_SIZE);
                }
                other => panic!("expected FrameTooLarge, got {other:?}"),
            }

            // Control Message
            let ctrl_bytes = control_len.to_be_bytes();
            let mut c_ctrl = Cursor::new(&ctrl_bytes[..]);
            match read_control_message(&mut c_ctrl).await {
                Err(ProtocolError::FrameTooLarge { size, max }) => {
                    prop_assert_eq!(size, control_len as usize);
                    prop_assert_eq!(max, MAX_CONTROL_FRAME_SIZE);
                }
                other => panic!("expected FrameTooLarge, got {other:?}"),
            }

            // RPC Request
            let mut req_bytes = Vec::new();
            req_bytes.extend_from_slice(&req_id.to_be_bytes());
            req_bytes.extend_from_slice(&rpc_req_len.to_be_bytes());
            let mut c_req = Cursor::new(&req_bytes[..]);
            match read_rpc_request(&mut c_req).await {
                Err(ProtocolError::FrameTooLarge { size, max }) => {
                    prop_assert_eq!(size, rpc_req_len as usize);
                    prop_assert_eq!(max, MAX_RPC_FRAME_SIZE);
                }
                other => panic!("expected FrameTooLarge, got {other:?}"),
            }

            // RPC Response
            let mut resp_bytes = Vec::new();
            resp_bytes.extend_from_slice(&req_id.to_be_bytes());
            resp_bytes.extend_from_slice(&rpc_resp_len.to_be_bytes());
            let mut c_resp = Cursor::new(&resp_bytes[..]);
            match read_rpc_response(&mut c_resp).await {
                Err(ProtocolError::FrameTooLarge { size, max }) => {
                    prop_assert_eq!(size, rpc_resp_len as usize);
                    prop_assert_eq!(max, MAX_RPC_FRAME_SIZE);
                }
                other => panic!("expected FrameTooLarge, got {other:?}"),
            }
            Ok(())
        })?;
    }

    #[test]
    fn prop_control_message_roundtrip(msg in arb_control_message()) {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_control_message(&mut buf, &msg).await.expect("write_control_message");
            let mut cursor = Cursor::new(&buf);
            let decoded = read_control_message(&mut cursor).await.expect("read_control_message");
            prop_assert_eq!(decoded, Some(msg));
            Ok(())
        })?;
    }

    #[test]
    fn prop_rpc_request_roundtrip(req_id in any::<u32>(), req in arb_rpc_request()) {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_rpc_request(&mut buf, req_id, &req).await.expect("write_rpc_request");
            let mut cursor = Cursor::new(&buf);
            let frame = read_rpc_request(&mut cursor).await.expect("read_rpc_request");
            prop_assert_eq!(frame, Some(RpcFrame { request_id: req_id, payload: req }));
            Ok(())
        })?;
    }

    #[test]
    fn prop_rpc_response_roundtrip(req_id in any::<u32>(), resp in arb_rpc_response()) {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_rpc_response(&mut buf, req_id, &resp).await.expect("write_rpc_response");
            let mut cursor = Cursor::new(&buf);
            let frame = read_rpc_response(&mut cursor).await.expect("read_rpc_response");
            prop_assert_eq!(frame, Some(RpcFrame { request_id: req_id, payload: resp }));
            Ok(())
        })?;
    }

    #[test]
    fn prop_rpc_response_with_caps_roundtrip(
        req_id in any::<u32>(),
        resp in arb_rpc_response(),
        caps in any::<u8>(),
    ) {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_rpc_response_with_caps(&mut buf, req_id, &resp, caps)
                .await
                .expect("write_rpc_response_with_caps");
            let mut cursor = Cursor::new(&buf);
            let frame = read_rpc_response(&mut cursor).await.expect("read_rpc_response");
            prop_assert_eq!(frame, Some(RpcFrame { request_id: req_id, payload: resp }));
            Ok(())
        })?;
    }

    #[test]
    fn prop_pairing_uri_roundtrip(uri in arb_pairing_uri()) {
        let encoded = uri.to_uri();
        let parsed = PairingUri::parse(&encoded).expect("parse encoded uri");
        prop_assert_eq!(parsed, uri);
    }

    #[test]
    fn prop_pairing_uri_parse_arbitrary_never_panics(s in any::<String>()) {
        let _ = PairingUri::parse(&s);
    }

    #[test]
    fn prop_tunnel_open_roundtrip(open in arb_tunnel_open()) {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_tunnel_open(&mut buf, &open).await.expect("write_tunnel_open");
            let mut cursor = Cursor::new(&buf);
            let decoded = read_tunnel_open(&mut cursor).await.expect("read_tunnel_open");
            prop_assert_eq!(decoded, Some(open));
            Ok(())
        })?;
    }

    #[test]
    fn prop_tunnel_ack_roundtrip(ack in arb_tunnel_ack()) {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_tunnel_ack(&mut buf, &ack).await.expect("write_tunnel_ack");
            let mut cursor = Cursor::new(&buf);
            let decoded = read_tunnel_ack(&mut cursor).await.expect("read_tunnel_ack");
            prop_assert_eq!(decoded, ack);
            Ok(())
        })?;
    }
}
