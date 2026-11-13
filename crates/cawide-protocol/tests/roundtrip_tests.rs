//! Postcard serialization round-trip tests for all domain types and pairing URI tests

use std::net::SocketAddr;

use cawide_protocol::*;

#[test]
fn test_pty_attach_header_roundtrip() {
    let header = PtyAttachHeader::new("sess-test-uuid-42", 133742, false);

    let bytes = postcard::to_allocvec(&header).expect("serialization failed");
    let decoded: PtyAttachHeader = postcard::from_bytes(&bytes).expect("deserialization failed");
    assert_eq!(header, decoded);

    let header_resume = PtyAttachHeader::new("sess-test-resume", 42, true);
    let bytes = postcard::to_allocvec(&header_resume).expect("serialization failed");
    let decoded: PtyAttachHeader = postcard::from_bytes(&bytes).expect("deserialization failed");
    assert_eq!(header_resume, decoded);
}

#[test]
fn test_control_messages_roundtrip() {
    let messages = vec![
        ControlMessage::PairRequest {
            pairing_secret: [0x42; 32],
            client_node_id: [0x99; 32],
            device_name: "iPhone 15 Pro".to_string(),
        },
        ControlMessage::PairResponse {
            success: true,
            error: None,
            host_name: Some("MacBook Pro".into()),
        },
        ControlMessage::PairResponse {
            success: false,
            error: Some("Invalid pairing secret".to_string()),
            host_name: None,
        },
        ControlMessage::Resize {
            cols: 120,
            rows: 35,
        },
        ControlMessage::Ping {
            client_ts: 1_700_000_000,
        },
        ControlMessage::Pong {
            client_ts: 1_700_000_000,
            host_ts: 1_700_000_005,
        },
        ControlMessage::HostEvent(HostEvent::GitChanged {
            root: "/Users/dev/repo".to_string(),
        }),
        ControlMessage::HostEvent(HostEvent::FsChanged {
            root: "/Users/dev/repo".to_string(),
            paths: vec!["src/lib.rs".to_string(), "Cargo.toml".to_string()],
        }),
        ControlMessage::HostEvent(HostEvent::SessionsChanged),
        ControlMessage::HostEvent(HostEvent::SessionUpdated {
            summary: SessionSummary {
                session_id: "sess-1".to_string(),
                workdir: "/Users/dev/repo".to_string(),
                active_cmd: None,
                last_active_ts: 1_700_000_050,
                alive: true,
                exit_code: None,
                attached: false,
                agent: Some(AgentState {
                    agent: "claude-code".to_string(),
                    status: AgentStatus::Thinking {
                        task_desc: "Analyzing git diff".to_string(),
                    },
                    updated_ts: 1_700_000_050,
                }),
                git_root: Some("/Users/dev/repo".to_string()),
                title: Some("my title".to_string()),
                revision: 42,
            },
        }),
        ControlMessage::HostEvent(HostEvent::Resync),
        ControlMessage::HostEvent(HostEvent::PortsChanged {
            ports: vec![ListeningPort {
                port: 3000,
                addresses: vec!["127.0.0.1".to_string()],
                pid: Some(1234),
                process_name: Some("node".to_string()),
                session_id: Some("sess-1".to_string()),
            }],
        }),
        ControlMessage::HostEvent(HostEvent::WebUrlDetected {
            session_id: "sess-1".to_string(),
            url: "http://localhost:5173/".to_string(),
        }),
        ControlMessage::HostEvent(HostEvent::OpenUrl {
            url: "http://localhost:5173/app".to_string(),
            session_id: Some("sess-1".to_string()),
        }),
        ControlMessage::HostEvent(HostEvent::OpenUrl {
            url: "https://example.com/".to_string(),
            session_id: None,
        }),
    ];

    for msg in messages {
        let bytes = postcard::to_allocvec(&msg).expect("serialization failed");
        let decoded: ControlMessage = postcard::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(msg, decoded);
    }
}

#[test]
fn test_rpc_requests_and_responses_roundtrip() {
    let requests = vec![
        RpcRequest::FsList {
            root: "/repo".to_string(),
            path: "src/".to_string(),
            recursive: false,
        },
        RpcRequest::FsRead {
            root: "/repo".to_string(),
            path: "Cargo.toml".to_string(),
            offset: 0,
            length: 1024,
        },
        RpcRequest::FsSearch {
            root: "/repo".to_string(),
            query: "test".to_string(),
        },
        RpcRequest::FsUpload {
            filename: "patch.diff".to_string(),
            data: vec![1, 2, 3, 4],
        },
        RpcRequest::RemoteOpen {
            root: "/repo".to_string(),
            target: "https://cawide.dev".to_string(),
        },
        RpcRequest::Git {
            root: "/repo".to_string(),
            op: GitOp::Status,
        },
        RpcRequest::Git {
            root: "/repo".to_string(),
            op: GitOp::Diff {
                target: GitDiffTarget::Unstaged {
                    path: "src/main.rs".to_string(),
                },
            },
        },
        RpcRequest::Git {
            root: "/repo".to_string(),
            op: GitOp::Stage {
                paths: vec![".".to_string()],
            },
        },
        RpcRequest::Git {
            root: "/repo".to_string(),
            op: GitOp::Unstage {
                paths: vec!["src/main.rs".to_string()],
            },
        },
        RpcRequest::Git {
            root: "/repo".to_string(),
            op: GitOp::Commit {
                message: "feat: x\n\nbody".to_string(),
                amend: false,
                stage_tracked: false,
            },
        },
        RpcRequest::ForgeAccounts {
            op: ForgeAccountOp::List,
        },
        RpcRequest::Forge {
            root: "/repo".to_string(),
            account: None,
            op: ForgeRepoOp::Repository,
        },
        RpcRequest::SessionList,
        RpcRequest::SessionCreate {
            session_id: "sess-new".to_string(),
            command: Some("sh".to_string()),
            workdir: Some("/workspace/subdir".to_string()),
        },
        RpcRequest::SessionKill {
            session_id: "sess-kill".to_string(),
        },
        RpcRequest::HostInfo,
        RpcRequest::FsReadChunk {
            root: "/r".into(),
            path: "a.pdf".into(),
            offset: 4_194_304,
            length: 1_048_576,
        },
        RpcRequest::PortList,
        RpcRequest::SetPushChannel {
            channel: Some(PushChannel {
                channel_id: "chan-123".to_string(),
                secret: "secret-456".to_string(),
            }),
        },
        RpcRequest::SetPushChannel { channel: None },
    ];

    for req in requests {
        let bytes = postcard::to_allocvec(&req).expect("serialization failed");
        let decoded: RpcRequest = postcard::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(req, decoded);
    }

    let responses = vec![
        RpcResponse::FsList(Ok(vec![
            FsEntry {
                name: "main.rs".to_string(),
                path: "src/main.rs".to_string(),
                is_dir: false,
                size: 2048,
                modified_ts: 1_700_000_000,
            },
            FsEntry {
                name: "pty".to_string(),
                path: "src/pty".to_string(),
                is_dir: true,
                size: 0,
                modified_ts: 1_700_000_010,
            },
        ])),
        RpcResponse::FsList(Err("Directory not found".to_string())),
        RpcResponse::FsRead(Ok(FsReadResult {
            data: b"Hello world payload".to_vec(),
            too_large: false,
            total_size: 19,
        })),
        RpcResponse::FsRead(Err("Permission denied".to_string())),
        RpcResponse::Git {
            result: Ok(GitReply::Status {
                status: GitRepoStatus {
                    head: GitHead::Branch {
                        name: "main".to_string(),
                        oid: Some("abc1234".to_string()),
                    },
                    upstream: None,
                    entries: vec![GitStatusEntry {
                        path: "src/lib.rs".to_string(),
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
        },
        RpcResponse::Git {
            result: Ok(GitReply::Diff {
                diff: GitFileDiff {
                    path: "src/lib.rs".to_string(),
                    old_path: None,
                    binary: false,
                    too_large: false,
                    lfs: false,
                    total_bytes: 100,
                    hunks: vec![DiffHunk {
                        file_path: "src/lib.rs".to_string(),
                        old_start: 10,
                        old_lines: 5,
                        new_start: 10,
                        new_lines: 7,
                        header: "@@ -10,5 +10,7 @@".to_string(),
                        lines: vec![
                            DiffLine {
                                kind: DiffLineKind::Context,
                                content: " fn foo() {".to_string(),
                            },
                            DiffLine {
                                kind: DiffLineKind::Deletion,
                                content: "-    bar();".to_string(),
                            },
                            DiffLine {
                                kind: DiffLineKind::Addition,
                                content: "+    bar_v2();".to_string(),
                            },
                        ],
                        content_hash: "abcd".to_string(),
                    }],
                },
            }),
        },
        RpcResponse::Git {
            result: Err(GitError {
                kind: GitErrorKind::NotARepository,
                message: "Not a git repository".to_string(),
                host: None,
                port: None,
            }),
        },
        RpcResponse::FsSearch(Ok(vec![FsSearchResult {
            path: "src/auth_controller.rs".to_string(),
            score: 140,
            match_indices: vec![4, 5, 6, 7, 9, 10],
        }])),
        RpcResponse::FsUpload(Ok("/home/u/.cache/cawide/uploads/1_2_shot.png".to_string())),
        RpcResponse::RemoteOpen(Err("prohibited URL scheme".to_string())),
        RpcResponse::ForgeAccounts {
            result: Ok(ForgeAccountReply::Accounts {
                state: ForgeAccountsState {
                    accounts: vec![],
                    device_sign_in_hosts: vec![],
                },
            }),
        },
        RpcResponse::Forge {
            result: Err(ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: "Repository not found".to_string(),
                git_kind: None,
                host: None,
                port: None,
            }),
        },
        RpcResponse::SessionList(Ok(vec![SessionSummary {
            session_id: "s1".to_string(),
            workdir: "/Users/dev".to_string(),
            active_cmd: Some("cargo test".to_string()),
            last_active_ts: 1_700_000_100,
            alive: true,
            exit_code: None,
            attached: false,
            agent: Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 1_700_000_100,
            }),
            git_root: Some("/Users/dev".to_string()),
            title: Some("term".to_string()),
            revision: 1,
        }])),
        RpcResponse::SessionCreate(Ok(SessionSummary {
            session_id: "s2".to_string(),
            workdir: "/tmp".to_string(),
            active_cmd: None,
            last_active_ts: 1_700_000_200,
            alive: true,
            exit_code: None,
            attached: false,
            agent: None,
            git_root: None,
            title: None,
            revision: 2,
        })),
        RpcResponse::SessionKill(Ok(())),
        RpcResponse::HostInfo(Ok(HostInfo {
            host_name: "MacBook Pro".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            version: "0.5.0".into(),
            workdir: "/Users/me/project".into(),
        })),
        RpcResponse::HostInfo(Err("boom".into())),
        RpcResponse::FsReadChunk(Ok(FsChunk {
            data: vec![1, 2, 3],
            too_large: false,
            total_size: 9_000_000,
            modified_unix_ns: 1_730_000_000_123_456_789,
        })),
        RpcResponse::FsReadChunk(Err("boom".into())),
        RpcResponse::PortList(Ok(vec![ListeningPort {
            port: 5173,
            addresses: vec!["0.0.0.0".into(), "::".into()],
            pid: Some(4567),
            process_name: Some("vite".into()),
            session_id: None,
        }])),
        RpcResponse::PortList(Err("scan failed".into())),
        RpcResponse::SetPushChannel(Ok(())),
        RpcResponse::SetPushChannel(Err("push registration failed".into())),
    ];

    for resp in responses {
        let bytes = postcard::to_allocvec(&resp).expect("serialization failed");
        let decoded: RpcResponse = postcard::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(resp, decoded);
    }
}

#[test]
fn test_pairing_uri_valid_roundtrip() {
    let uri_obj = PairingUri {
        host_node_id: [0x11; 32],
        pairing_secret: [0x22; 32],
        relay_url: Some("https://relay.cawide.dev?token=abc%20123".to_string()),
        direct_addrs: vec![
            "192.168.1.100:4433".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:8443".parse::<SocketAddr>().unwrap(),
        ],
    };

    let uri_str = uri_obj.to_uri();
    let parsed = PairingUri::parse(&uri_str).expect("parse valid uri");
    assert_eq!(uri_obj, parsed);
}

#[test]
fn test_pairing_uri_rejections() {
    let valid_node = "11".repeat(32);
    let valid_secret = "22".repeat(32);

    // 1. Wrong scheme
    let res = PairingUri::parse(&format!(
        "https://pair?node={valid_node}&secret={valid_secret}"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 2. Wrong host
    let res = PairingUri::parse(&format!(
        "cawide://connect?node={valid_node}&secret={valid_secret}"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 3. Missing node
    let res = PairingUri::parse(&format!("cawide://pair?secret={valid_secret}"));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 4. Duplicate node
    let res = PairingUri::parse(&format!(
        "cawide://pair?node={valid_node}&secret={valid_secret}&node={valid_node}"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 5. Missing secret
    let res = PairingUri::parse(&format!("cawide://pair?node={valid_node}"));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 6. Duplicate secret
    let res = PairingUri::parse(&format!(
        "cawide://pair?node={valid_node}&secret={valid_secret}&secret={valid_secret}"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 7. Non-64-hex node
    let res = PairingUri::parse(&format!("cawide://pair?node=1234&secret={valid_secret}"));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    let invalid_hex = "zz".repeat(32);
    let res = PairingUri::parse(&format!(
        "cawide://pair?node={invalid_hex}&secret={valid_secret}"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 8. Non-64-hex secret
    let res = PairingUri::parse(&format!("cawide://pair?node={valid_node}&secret=1234"));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 9. More than 8 addrs
    let mut nine_addrs = format!("cawide://pair?node={valid_node}&secret={valid_secret}");
    for i in 1..=9 {
        nine_addrs.push_str(&format!("&addr=127.0.0.1%3A{}", 8000 + i));
    }
    let res = PairingUri::parse(&nine_addrs);
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 10. Unparsable addr
    let res = PairingUri::parse(&format!(
        "cawide://pair?node={valid_node}&secret={valid_secret}&addr=not-an-ip"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 11. Invalid percent escapes
    let res = PairingUri::parse(&format!(
        "cawide://pair?node={valid_node}&secret={valid_secret}&relay=bad%2"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));

    // 12. Unknown query keys
    let res = PairingUri::parse(&format!(
        "cawide://pair?node={valid_node}&secret={valid_secret}&unknown_param=val"
    ));
    assert!(matches!(res, Err(ProtocolError::InvalidPairingUri(_))));
}

#[test]
fn test_tunnel_types_roundtrip() {
    let open = TunnelOpen {
        host: "localhost".to_string(),
        port: 8080,
    };
    let bytes = postcard::to_allocvec(&open).expect("serialize open");
    let decoded: TunnelOpen = postcard::from_bytes(&bytes).expect("deserialize open");
    assert_eq!(open, decoded);

    let acks = vec![
        TunnelAck::Connected,
        TunnelAck::Failed {
            reason: TunnelFailure::Refused,
            message: "connection refused".to_string(),
        },
        TunnelAck::Failed {
            reason: TunnelFailure::Unreachable,
            message: "host unreachable".to_string(),
        },
        TunnelAck::Failed {
            reason: TunnelFailure::DnsFailed,
            message: "dns failed".to_string(),
        },
        TunnelAck::Failed {
            reason: TunnelFailure::TimedOut,
            message: "timed out".to_string(),
        },
        TunnelAck::Failed {
            reason: TunnelFailure::InvalidTarget,
            message: "invalid target".to_string(),
        },
        TunnelAck::Failed {
            reason: TunnelFailure::Other,
            message: "unknown error".to_string(),
        },
    ];

    for ack in acks {
        let bytes = postcard::to_allocvec(&ack).expect("serialize ack");
        let decoded: TunnelAck = postcard::from_bytes(&bytes).expect("deserialize ack");
        assert_eq!(ack, decoded);
    }
}

#[test]
fn test_git_and_forge_all_variants_roundtrip() {
    let git_ops = vec![
        GitOp::Status,
        GitOp::Diff {
            target: GitDiffTarget::Unstaged {
                path: "a.txt".into(),
            },
        },
        GitOp::Stage {
            paths: vec!["a.txt".into()],
        },
        GitOp::Unstage {
            paths: vec!["b.txt".into()],
        },
        GitOp::Commit {
            message: "msg".into(),
            amend: true,
            stage_tracked: false,
        },
        GitOp::Discard {
            paths: vec!["a.txt".into()],
            scope: GitDiscardScope::All,
        },
        GitOp::ApplyPatch {
            patch: GitPatchRequest {
                path: "f.rs".into(),
                source: GitPatchSource::Unstaged,
                hunk_index: 0,
                hunk_hash: "h1".into(),
                line_indices: vec![1],
                action: GitPatchAction::Stage,
            },
        },
        GitOp::Identity,
        GitOp::SetIdentity {
            name: "Alice".into(),
            email: "alice@example.com".into(),
            scope: GitConfigScope::Global,
        },
        GitOp::Log {
            query: GitLogQuery {
                scope: GitLogScope::Head,
                path: None,
                skip: 0,
                limit: 10,
            },
        },
        GitOp::CommitDetail { oid: "123".into() },
        GitOp::Branches,
        GitOp::Checkout {
            target: GitCheckoutTarget::Branch { name: "dev".into() },
        },
        GitOp::CreateBranch {
            name: "feat".into(),
            start_point: Some("main".into()),
            checkout: false,
        },
        GitOp::DeleteBranch {
            name: "old".into(),
            force: false,
        },
        GitOp::Tags,
        GitOp::CreateTag {
            name: "v1.0.0".into(),
            target: "123".into(),
            message: Some("release".into()),
        },
        GitOp::DeleteTag {
            name: "v0.9.0".into(),
        },
        GitOp::Stashes,
        GitOp::StashPush {
            message: Some("wip".into()),
            include_untracked: true,
        },
        GitOp::StashApply {
            index: 0,
            oid: "abc".into(),
            pop: false,
        },
        GitOp::StashDrop {
            index: 1,
            oid: "def".into(),
        },
        GitOp::Remotes,
        GitOp::Fetch {
            remote: Some("origin".into()),
            account: None,
        },
        GitOp::Pull {
            mode: GitPullMode::Merge,
            account: None,
        },
        GitOp::Push {
            remote: "origin".into(),
            local_branch: "main".into(),
            remote_branch: "main".into(),
            set_upstream: true,
            force_with_lease: false,
            account: None,
        },
        GitOp::PushTag {
            remote: "origin".into(),
            name: "v1.0.0".into(),
            account: None,
        },
        GitOp::DeleteRemoteRef {
            remote: "origin".into(),
            full_ref: "refs/heads/temp".into(),
            account: None,
        },
        GitOp::Sequencer {
            action: GitSequencerAction::Continue,
        },
        GitOp::ResolveConflict {
            path: "c.txt".into(),
            resolution: GitConflictResolution::Ours,
        },
        GitOp::Reset {
            oid: "HEAD~1".into(),
            mode: GitResetMode::Mixed,
        },
        GitOp::RestoreBlobs { items: vec![] },
    ];

    for op in git_ops {
        let bytes = postcard::to_allocvec(&op).expect("serialize git op");
        let decoded: GitOp = postcard::from_bytes(&bytes).expect("deserialize git op");
        assert_eq!(op, decoded);
    }

    let forge_ops = vec![
        ForgeAccountOp::List,
        ForgeAccountOp::SignInStart {
            kind: ForgeKind::GitHub,
            host: "github.com".into(),
        },
        ForgeAccountOp::SignInPoll {
            session_id: "sess1".into(),
        },
        ForgeAccountOp::AddToken {
            kind: ForgeKind::Gitea,
            scheme: ForgeScheme::Https,
            host: "gitea.com".into(),
            login: Some("user".into()),
            token: "tok".into(),
            azure_org: None,
            verify_url: None,
        },
        ForgeAccountOp::Remove {
            account_id: "acc1".into(),
        },
    ];

    for op in forge_ops {
        let bytes = postcard::to_allocvec(&op).expect("serialize forge account op");
        let decoded: ForgeAccountOp =
            postcard::from_bytes(&bytes).expect("deserialize forge account op");
        assert_eq!(op, decoded);
    }

    let forge_repo_ops = vec![
        ForgeRepoOp::Repository,
        ForgeRepoOp::ListPullRequests {
            filter: ForgePrFilter::Open,
            limit: 20,
        },
        ForgeRepoOp::PullRequest { number: 42 },
        ForgeRepoOp::CreateDefaults {
            head_branch: "feat".into(),
            base: Some("main".into()),
        },
        ForgeRepoOp::Create {
            request: ForgeCreateRequest {
                title: "PR Title".into(),
                body: "Body text".into(),
                base: "main".into(),
                head_branch: "feat".into(),
                draft: false,
                reviewers: vec![],
            },
        },
        ForgeRepoOp::SetState {
            number: 42,
            change: ForgePrStateChange::Close,
        },
        ForgeRepoOp::Merge {
            request: ForgeMergeRequest {
                number: 42,
                method: ForgeMergeMethod::Squash,
                delete_branch: true,
                auto: false,
                head_oid: "abc".into(),
                subject: Some("Title".into()),
                body: Some("Msg".into()),
            },
        },
        ForgeRepoOp::SubmitReview {
            review: ForgeReviewSubmission {
                number: 42,
                head_oid: "abc".into(),
                event: ForgeReviewEvent::Approve,
                body: "LGTM".into(),
                threads: vec![],
            },
        },
        ForgeRepoOp::Comment {
            number: 42,
            body: "comment".into(),
        },
        ForgeRepoOp::ResolveThread {
            number: 42,
            thread_id: "t1".into(),
            resolved: true,
        },
        ForgeRepoOp::PullRequestWithChecks { number: 42 },
    ];

    for op in forge_repo_ops {
        let bytes = postcard::to_allocvec(&op).expect("serialize forge repo op");
        let decoded: ForgeRepoOp = postcard::from_bytes(&bytes).expect("deserialize forge repo op");
        assert_eq!(op, decoded);
    }
}

#[test]
fn forge_reply_pull_request_with_checks_roundtrip() {
    let detail = ForgePrDetail {
        summary: ForgePrSummary {
            number: 42,
            title: "PR Title".into(),
            author: "alice".into(),
            state: ForgePrState::Open,
            is_draft: false,
            head_ref: "feature".into(),
            base_ref: "main".into(),
            updated_at: "2026-03-30T10:00:00Z".into(),
            review_decision: Some(ForgeReviewDecision::Approved),
            checks: ForgeChecksRollup::Pending,
            url: "https://forge.example/pr/42".into(),
        },
        body: "PR description".into(),
        body_truncated: false,
        head_oid: "0123456789abcdef".into(),
        head_owner: "alice".into(),
        is_cross_repository: false,
        additions: Some(10),
        deletions: Some(2),
        changed_files: Some(1),
        mergeable: ForgeMergeable::Mergeable,
        merge_state: ForgeMergeState::Clean,
        auto_merge_enabled: false,
        created_at: "2026-03-30T09:00:00Z".into(),
        commits: vec![ForgePrCommit {
            oid: "0123456789abcdef".into(),
            headline: "initial commit".into(),
            author: "alice".into(),
            authored_at: "2026-03-30T09:00:00Z".into(),
        }],
        reviews: vec![],
        comments: vec![],
    };
    let checks = vec![ForgeCheck {
        name: "test".into(),
        group: "ci".into(),
        bucket: ForgeCheckBucket::Skipping,
        link: "https://ci.example/1".into(),
        started_at: "2026-03-30T09:05:00Z".into(),
        completed_at: "2026-03-30T09:06:00Z".into(),
        description: "skipped job".into(),
    }];
    let reply = ForgeRepoReply::PullRequestWithChecks { detail, checks };
    let bytes = postcard::to_allocvec(&reply).expect("serialize reply");
    let decoded: ForgeRepoReply = postcard::from_bytes(&bytes).expect("deserialize reply");
    assert_eq!(reply, decoded);
}

#[test]
fn forge_repo_op_variant_indices_are_append_only() {
    let set_state = ForgeRepoOp::SetState {
        number: 1,
        change: ForgePrStateChange::Close,
    };
    let bytes_set_state = postcard::to_allocvec(&set_state).expect("serialize set state");
    assert_eq!(bytes_set_state[0], 16, "SetState variant index must be 16");

    let pr_with_checks = ForgeRepoOp::PullRequestWithChecks { number: 1 };
    let bytes_pr_with_checks =
        postcard::to_allocvec(&pr_with_checks).expect("serialize pr with checks");
    assert_eq!(
        bytes_pr_with_checks[0], 17,
        "PullRequestWithChecks variant index must be 17"
    );

    let reply_done = ForgeRepoReply::Done;
    let bytes_done = postcard::to_allocvec(&reply_done).expect("serialize reply done");
    assert_eq!(bytes_done[0], 11, "Done reply variant index must be 11");

    let reply_with_checks = ForgeRepoReply::PullRequestWithChecks {
        detail: ForgePrDetail {
            summary: ForgePrSummary {
                number: 1,
                title: String::new(),
                author: String::new(),
                state: ForgePrState::Open,
                is_draft: false,
                head_ref: String::new(),
                base_ref: String::new(),
                updated_at: String::new(),
                review_decision: None,
                checks: ForgeChecksRollup::NoChecks,
                url: String::new(),
            },
            body: String::new(),
            body_truncated: false,
            head_oid: String::new(),
            head_owner: String::new(),
            is_cross_repository: false,
            additions: None,
            deletions: None,
            changed_files: None,
            mergeable: ForgeMergeable::Unknown,
            merge_state: ForgeMergeState::Unknown,
            auto_merge_enabled: false,
            created_at: String::new(),
            commits: Vec::new(),
            reviews: Vec::new(),
            comments: Vec::new(),
        },
        checks: Vec::new(),
    };
    let bytes_reply_with_checks =
        postcard::to_allocvec(&reply_with_checks).expect("serialize reply with checks");
    assert_eq!(
        bytes_reply_with_checks[0], 12,
        "PullRequestWithChecks reply variant index must be 12"
    );
}

#[test]
fn test_voice_compile_rpc_roundtrip() {
    let req = RpcRequest::VoiceCompilePrompt {
        session_id: "sess-1".to_string(),
        transcript: "tạo hàm mới chấm".to_string(),
        active_file: Some("src/main.rs".to_string()),
        language_mode: "vi-en".to_string(),
    };
    let bytes = postcard::to_allocvec(&req).expect("serialize voice compile req");
    let decoded: RpcRequest = postcard::from_bytes(&bytes).expect("deserialize voice compile req");
    assert_eq!(req, decoded);

    let result = VoiceCompileResult {
        clean_prompt: "Create a new function.".to_string(),
        detected_language: "vi".to_string(),
    };
    let resp = RpcResponse::VoiceCompilePrompt(Ok(result.clone()));
    let bytes = postcard::to_allocvec(&resp).expect("serialize voice compile resp");
    let decoded: RpcResponse =
        postcard::from_bytes(&bytes).expect("deserialize voice compile resp");
    assert_eq!(resp, decoded);

    let err_resp = RpcResponse::VoiceCompilePrompt(Err("timeout".to_string()));
    let bytes = postcard::to_allocvec(&err_resp).expect("serialize voice compile err resp");
    let decoded: RpcResponse =
        postcard::from_bytes(&bytes).expect("deserialize voice compile err resp");
    assert_eq!(err_resp, decoded);
}
