//! End-to-end tests for the Host RPC engine (stream purpose 0x03) over loopback QUIC.

mod common;

use cawide_protocol::types::{
    DiffLine, DiffLineKind, GitChange, GitDiffTarget, GitDiscardScope, GitErrorKind, GitHead,
    GitOp, GitPatchAction, GitPatchRequest, GitPatchSource, GitReply,
};
use cawide_protocol::{
    read_control_message, write_control_message, ControlMessage, HostEvent, RpcRequest,
    RpcResponse, StreamPurpose, FS_READ_CHUNK_MAX_BYTES, FS_UPLOAD_MAX_BYTES,
    MAX_CHUNKED_FILE_SIZE, MAX_DIFF_BYTES, MAX_FILE_SIZE,
};
use common::{open, within, Env};
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

#[cfg(not(unix))]
fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(_original: P, _link: Q) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(p: &Path, m: u32) {
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(m));
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _m: u32) {}
use std::path::{Path, PathBuf};
use std::process::Command;

fn assert_denied<T: std::fmt::Debug>(r: Result<T, String>) {
    match r {
        Err(e) => assert!(e.contains("access denied"), "unexpected error: {e}"),
        Ok(v) => panic!("expected access denied, got {v:?}"),
    }
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn fs_list_respects_workspace_jail_and_skipped_dirs() {
    let mut env = Env::start().await;
    env.write("src/main.rs", b"fn main() {}\n");
    env.write("README.md", b"# hi\n");
    env.write(".env", b"K=V\n");
    for d in [".git", "target", "node_modules", "build", "dist"] {
        env.write(&format!("{d}/junk.rs"), b"x");
    }

    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: env.root(),
            path: ".".into(),
            recursive: false,
        })
        .await
    else {
        panic!("wrong variant")
    };
    let entries = r.unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["src", ".env", "README.md"],
        "dirs first, then by name"
    );
    let readme = &entries[2];
    assert_eq!(
        (readme.path.as_str(), readme.is_dir, readme.size),
        ("README.md", false, 5)
    );
    assert!(readme.modified_ts > 1_600_000_000);

    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: env.root(),
            path: "src".into(),
            recursive: false,
        })
        .await
    else {
        panic!("wrong variant")
    };
    assert_eq!(r.unwrap()[0].path, "src/main.rs");

    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: env.root(),
            path: "/".into(),
            recursive: true,
        })
        .await
    else {
        panic!("wrong variant")
    };
    let mut paths: Vec<String> = r.unwrap().into_iter().map(|e| e.path).collect();
    paths.sort();
    assert_eq!(paths, vec![".env", "README.md", "src", "src/main.rs"]);

    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: env.root(),
            path: "../../../etc".into(),
            recursive: false,
        })
        .await
    else {
        panic!("wrong variant")
    };
    assert_denied(r);

    symlink("/etc", env.ws.join("hostetc")).unwrap();
    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: env.root(),
            path: "hostetc".into(),
            recursive: false,
        })
        .await
    else {
        panic!("wrong variant")
    };
    assert_denied(r);

    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: env.root(),
            path: "README.md".into(),
            recursive: false,
        })
        .await
    else {
        panic!("wrong variant")
    };
    assert_eq!(r, Err("not a directory".into()));
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fs_read_bounded_and_too_large_rejection() {
    let mut env = Env::start().await;
    env.write("hello.txt", b"hello world");
    env.write("big.bin", &vec![b'z'; (MAX_FILE_SIZE + 1) as usize]);
    env.write("dir/x", b"");

    let root = env.root();
    let read = |path: &str, offset, length| RpcRequest::FsRead {
        root: root.clone(),
        path: path.into(),
        offset,
        length,
    };
    let RpcResponse::FsRead(r) = env.call(read("hello.txt", 0, 4096)).await else {
        panic!()
    };
    let r = r.unwrap();
    assert_eq!(
        (r.data.as_slice(), r.too_large, r.total_size),
        (&b"hello world"[..], false, 11)
    );

    let RpcResponse::FsRead(r) = env.call(read("hello.txt", 6, 3)).await else {
        panic!()
    };
    assert_eq!(r.unwrap().data, b"wor");

    let RpcResponse::FsRead(r) = env.call(read("hello.txt", 11, 10)).await else {
        panic!()
    };
    let r = r.unwrap();
    assert!(r.data.is_empty() && !r.too_large && r.total_size == 11);

    let RpcResponse::FsRead(r) = env.call(read("big.bin", 0, 10)).await else {
        panic!()
    };
    let r = r.unwrap();
    assert!(r.too_large && r.data.is_empty());
    assert_eq!(r.total_size, MAX_FILE_SIZE + 1);

    let RpcResponse::FsRead(r) = env.call(read("../../etc/hosts", 0, 10)).await else {
        panic!()
    };
    assert_denied(r);

    let RpcResponse::FsRead(r) = env.call(read("dir", 0, 10)).await else {
        panic!()
    };
    assert_eq!(r, Err("target is not a regular file".into()));
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fs_read_chunk_serves_large_files_in_bounded_slices() {
    let mut env = Env::start().await;
    let big_data: Vec<u8> = (0..1_500_000).map(|i| (i % 251) as u8).collect();
    env.write("big.bin", &big_data);

    let huge_len = FS_READ_CHUNK_MAX_BYTES as usize + 7;
    env.write("huge.bin", &vec![0xaa; huge_len]);

    std::fs::File::create(env.ws.join("sparse.bin"))
        .unwrap()
        .set_len(MAX_CHUNKED_FILE_SIZE + 1)
        .unwrap();

    env.write("dir/x", b"");

    let root = env.root();
    let read_chunk = |path: &str, offset, length| RpcRequest::FsReadChunk {
        root: root.clone(),
        path: path.into(),
        offset,
        length,
    };

    // Stat call (length 0) on big.bin
    let RpcResponse::FsReadChunk(r) = env.call(read_chunk("big.bin", 0, 0)).await else {
        panic!("wrong variant")
    };
    let stat = r.unwrap();
    assert!(stat.data.is_empty());
    assert!(!stat.too_large);
    assert_eq!(stat.total_size, 1_500_000);
    assert!(stat.modified_unix_ns > 0);

    // Read slices at 0, 600_000, 1_200_000
    let mut assembled = Vec::new();
    for offset in [0, 600_000, 1_200_000] {
        let RpcResponse::FsReadChunk(r) = env.call(read_chunk("big.bin", offset, 600_000)).await
        else {
            panic!("wrong variant")
        };
        let chunk = r.unwrap();
        assert!(!chunk.too_large);
        assert_eq!(chunk.total_size, 1_500_000);
        assert_eq!(chunk.modified_unix_ns, stat.modified_unix_ns);
        assembled.extend_from_slice(&chunk.data);
    }
    assert_eq!(assembled, big_data);

    // Offset at total_size returns empty data with too_large == false
    let RpcResponse::FsReadChunk(r) = env.call(read_chunk("big.bin", 1_500_000, 1024)).await else {
        panic!("wrong variant")
    };
    let chunk = r.unwrap();
    assert!(chunk.data.is_empty() && !chunk.too_large && chunk.total_size == 1_500_000);

    // huge.bin clamp to FS_READ_CHUNK_MAX_BYTES
    let RpcResponse::FsReadChunk(r) = env.call(read_chunk("huge.bin", 0, u32::MAX)).await else {
        panic!("wrong variant")
    };
    let chunk = r.unwrap();
    assert_eq!(chunk.data.len(), FS_READ_CHUNK_MAX_BYTES as usize);

    // sparse.bin over MAX_CHUNKED_FILE_SIZE
    let RpcResponse::FsReadChunk(r) = env.call(read_chunk("sparse.bin", 0, 1024)).await else {
        panic!("wrong variant")
    };
    let chunk = r.unwrap();
    assert!(chunk.too_large);
    assert!(chunk.data.is_empty());
    assert_eq!(chunk.total_size, MAX_CHUNKED_FILE_SIZE + 1);

    // Path traversal denied
    let RpcResponse::FsReadChunk(r) = env.call(read_chunk("../../etc/hosts", 0, 1024)).await else {
        panic!("wrong variant")
    };
    assert_denied(r);

    // Target is directory
    let RpcResponse::FsReadChunk(r) = env.call(read_chunk("dir", 0, 1024)).await else {
        panic!("wrong variant")
    };
    assert_eq!(r, Err("target is not a regular file".into()));

    // Legacy FsRead of big.bin still rejects with too_large == true
    let RpcResponse::FsRead(r) = env
        .call(RpcRequest::FsRead {
            root: root.clone(),
            path: "big.bin".into(),
            offset: 0,
            length: 1024,
        })
        .await
    else {
        panic!("wrong variant")
    };
    let r = r.unwrap();
    assert!(r.too_large && r.data.is_empty());

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fs_search_fuzzy_matching_and_indices() {
    let mut env = Env::start().await;
    env.write("src/auth_controller.rs", b"");
    env.write("src/views/auth.rs", b"");
    env.write("docs/readme.md", b"");
    env.write("target/auth_ctrl_exact.rs", b"");

    let RpcResponse::FsSearch(r) = env
        .call(RpcRequest::FsSearch {
            root: env.root(),
            query: "auth_ctrl".into(),
        })
        .await
    else {
        panic!()
    };
    let hits = r.unwrap();
    assert!(!hits.is_empty());
    let top = &hits[0];
    assert_eq!(top.path, "src/auth_controller.rs");
    assert!(
        hits.iter().all(|h| !h.path.starts_with("target/")),
        "{hits:?}"
    );
    // One index per query char, strictly increasing, each pointing at that char.
    let chars: Vec<char> = top.path.chars().collect();
    assert_eq!(top.match_indices.len(), "auth_ctrl".len());
    assert!(top.match_indices.windows(2).all(|w| w[0] < w[1]));
    let matched: String = top
        .match_indices
        .iter()
        .map(|&i| chars[i as usize])
        .collect();
    assert_eq!(matched, "auth_ctrl");
    assert!(hits.windows(2).all(|w| w[0].score >= w[1].score));
    let RpcResponse::FsSearch(r) = env
        .call(RpcRequest::FsSearch {
            root: env.root(),
            query: "  ".into(),
        })
        .await
    else {
        panic!()
    };
    assert_eq!(r, Ok(vec![]));
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fs_upload_in_isolated_cache() {
    let mut env = Env::start().await;
    let data = vec![7u8; 1024];
    let RpcResponse::FsUpload(r) = env
        .call(RpcRequest::FsUpload {
            filename: "../../photo shot.png".into(),
            data: data.clone(),
        })
        .await
    else {
        panic!()
    };
    let stored = PathBuf::from(r.unwrap());
    assert_eq!(stored.parent(), Some(env.uploads.as_path()), "{stored:?}");
    let name = stored.file_name().unwrap().to_str().unwrap();
    assert!(name.ends_with("_photo_shot.png"), "{name}");
    assert_eq!(std::fs::read(&stored).unwrap(), data);
    #[cfg(unix)]
    {
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&stored), 0o600);
        assert_eq!(mode(&env.uploads), 0o700);
    }

    let RpcResponse::FsUpload(r) = env
        .call(RpcRequest::FsUpload {
            filename: "..".into(),
            data: vec![1],
        })
        .await
    else {
        panic!()
    };
    assert!(PathBuf::from(r.unwrap())
        .to_str()
        .unwrap()
        .ends_with("_upload.bin"));

    let RpcResponse::FsUpload(r) = env
        .call(RpcRequest::FsUpload {
            filename: "big.bin".into(),
            data: vec![0; FS_UPLOAD_MAX_BYTES + 1],
        })
        .await
    else {
        panic!()
    };
    assert!(r.is_err());
    assert_eq!(
        std::fs::read_dir(&env.uploads).unwrap().count(),
        2,
        "no partial files left"
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_open_validates_urls_and_jailed_paths() {
    let mut env = Env::start().await;
    // Set modes on test files
    env.write("script.sh", b"#!/bin/sh\n");
    set_mode(&env.ws.join("script.sh"), 0o755);
    env.write("tool", b"bin");
    set_mode(&env.ws.join("tool"), 0o755);
    env.write("evil.SH", b"echo\n");
    set_mode(&env.ws.join("evil.SH"), 0o644);
    env.write("notes.txt", b"notes");
    set_mode(&env.ws.join("notes.txt"), 0o644);
    std::fs::create_dir(env.ws.join("folder")).unwrap();

    let root = env.root();
    let mut open_target = async |t: &str| match env
        .call(RpcRequest::RemoteOpen {
            root: root.clone(),
            target: t.into(),
        })
        .await
    {
        RpcResponse::RemoteOpen(r) => r,
        other => panic!("wrong variant {other:?}"),
    };
    assert_eq!(open_target("https://example.com").await, Ok(()));
    for bad in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://exa mple.com",
        "https://example.com/\n",
        "script.sh",
        "tool",
        "evil.SH",
        "folder",
        "../outside.txt",
        "missing.txt",
    ] {
        assert!(open_target(bad).await.is_err(), "{bad:?} must be rejected");
    }
    assert_eq!(open_target("notes.txt").await, Ok(()));

    let opened = env.opened.lock().clone();
    assert_eq!(
        opened,
        vec![
            "https://example.com".to_string(),
            env.ws.join("notes.txt").display().to_string()
        ]
    );
    env.shutdown().await;
}

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn git_status_porcelain_v2_parsing() {
    let mut env = Env::start().await;
    env.init_repo();
    for f in ["a.txt", "b.txt", "c.txt", "old name.txt"] {
        env.write(f, b"base\n");
    }
    env.git(&["add", "."]);
    env.git(&["commit", "-q", "-m", "init"]);

    env.write("a.txt", b"staged\n");
    env.git(&["add", "a.txt"]);
    env.write("b.txt", b"unstaged\n");
    env.write("c.txt", b"staged\n");
    env.git(&["add", "c.txt"]);
    env.write("c.txt", b"staged then modified\n");
    env.git(&["mv", "old name.txt", "new name.txt"]);
    env.write("my file.txt", b"new\n");
    let reply = env.git_op(GitOp::Status).await.unwrap();
    let GitReply::Status { status: s } = reply else {
        panic!()
    };
    match &s.head {
        GitHead::Branch { name, .. } => assert_eq!(name, "main"),
        _ => panic!("expected branch"),
    }
    let mut staged: Vec<String> = s
        .entries
        .iter()
        .filter(|e| e.index != GitChange::Unmodified)
        .map(|e| e.path.clone())
        .collect();
    staged.sort();
    assert_eq!(staged, vec!["a.txt", "c.txt", "new name.txt"]);
    let mut modified: Vec<String> = s
        .entries
        .iter()
        .filter(|e| e.worktree != GitChange::Unmodified && e.worktree != GitChange::Untracked)
        .map(|e| e.path.clone())
        .collect();
    modified.sort();
    assert_eq!(modified, vec!["b.txt", "c.txt"]);
    let untracked: Vec<String> = s
        .entries
        .iter()
        .filter(|e| e.worktree == GitChange::Untracked)
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(untracked, vec!["my file.txt"]);
    assert!(s.entries.iter().all(|e| e.conflict.is_none()));
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn git_status_reports_conflicts_and_detached_head() {
    let mut env = Env::start().await;
    env.init_repo();
    env.write("x.txt", b"base\n");
    env.git(&["add", "."]);
    env.git(&["commit", "-q", "-m", "init"]);
    env.git(&["checkout", "-q", "-b", "feature"]);
    env.write("x.txt", b"feature\n");
    env.git(&["commit", "-q", "-am", "feature"]);
    env.git(&["checkout", "-q", "main"]);
    env.write("x.txt", b"main\n");
    env.git(&["commit", "-q", "-am", "main"]);
    let merge = Command::new("git")
        .current_dir(&env.ws)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["merge", "-q", "feature"])
        .output()
        .unwrap();
    assert!(!merge.status.success(), "merge must conflict");
    let reply = env.git_op(GitOp::Status).await.unwrap();
    let GitReply::Status { status: s } = reply else {
        panic!()
    };
    let conflicted: Vec<String> = s
        .entries
        .iter()
        .filter(|e| e.conflict.is_some())
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(conflicted, vec!["x.txt"]);
    assert!(s.entries.iter().all(|e| e.index == GitChange::Unmodified
        && (e.worktree == GitChange::Unmodified || e.worktree == GitChange::Untracked)));

    env.git(&["merge", "--abort"]);
    env.git(&["checkout", "-q", "--detach", "HEAD"]);
    let reply = env.git_op(GitOp::Status).await.unwrap();
    let GitReply::Status { status: s } = reply else {
        panic!()
    };
    assert!(matches!(s.head, GitHead::Detached { .. }));
    env.shutdown().await;
}

fn line(kind: DiffLineKind, content: &str) -> DiffLine {
    DiffLine {
        kind,
        content: content.into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn git_diff_unified_hunks_and_too_large_cap() {
    let mut env = Env::start().await;
    env.init_repo();
    let base: String = (1..=10).map(|i| format!("line{i}\n")).collect();
    env.write("test.txt", base.as_bytes());
    env.git(&["add", "."]);
    env.git(&["commit", "-q", "-m", "init"]);
    env.write("test.txt", base.replace("line5\n", "LINE5\n").as_bytes());
    let diff = |f: &str| GitOp::Diff {
        target: GitDiffTarget::Unstaged { path: f.into() },
    };
    let GitReply::Diff { diff: d } = env.git_op(diff("test.txt")).await.unwrap() else {
        panic!()
    };
    assert!(!d.too_large);
    assert_eq!(d.hunks.len(), 1);
    let h = &d.hunks[0];
    assert_eq!(
        (h.old_start, h.old_lines, h.new_start, h.new_lines),
        (2, 7, 2, 7)
    );
    assert!(h.header.starts_with("@@ -2,7 +2,7 @@"), "{}", h.header);
    use DiffLineKind::*;
    assert_eq!(
        h.lines,
        vec![
            line(Context, "line2"),
            line(Context, "line3"),
            line(Context, "line4"),
            line(Deletion, "line5"),
            line(Addition, "LINE5"),
            line(Context, "line6"),
            line(Context, "line7"),
            line(Context, "line8"),
        ]
    );

    // Untracked file with a space in its name: diffed against /dev/null.
    env.write("new file.txt", b"n1\nn2\n");
    let GitReply::Diff { diff: d } = env.git_op(diff("new file.txt")).await.unwrap() else {
        panic!()
    };
    assert_eq!(d.hunks.len(), 1);
    let h = &d.hunks[0];
    assert_eq!(
        (h.old_start, h.old_lines, h.new_start, h.new_lines),
        (0, 0, 1, 2)
    );
    assert_eq!(h.lines, vec![line(Addition, "n1"), line(Addition, "n2")]);

    // Whole-repo diff covers staged + unstaged tracked changes, not untracked files.
    env.write("staged.txt", b"s\n");
    env.git(&["add", "staged.txt"]);
    let GitReply::Diff { diff: d } = env
        .git_op(GitOp::Diff {
            target: GitDiffTarget::Staged {
                path: "staged.txt".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(d.path, "staged.txt");

    // Jail and argument hardening.
    symlink("/etc/hosts", env.ws.join("leak")).unwrap();
    for bad in ["../../etc/hosts", "leak"] {
        let r = env.git_op(diff(bad)).await;
        assert!(r.is_err());
    }
    for bad in ["-rf", ":(exclude)x", "missing.txt"] {
        let r = env.git_op(diff(bad)).await;
        assert!(r.is_err(), "{bad:?} must be rejected, got {r:?}");
    }

    // Size cap.
    let big: String = (0..30_000).map(|i| format!("row {i:08}\n")).collect();
    assert!(big.len() > MAX_DIFF_BYTES);
    env.write("big.txt", big.as_bytes());
    env.git(&["add", "big.txt"]);
    let GitReply::Diff { diff: d } = env
        .git_op(GitOp::Diff {
            target: GitDiffTarget::Staged {
                path: "big.txt".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(d.too_large && d.hunks.is_empty());
    assert!(d.total_bytes > MAX_DIFF_BYTES as u64);
}

#[tokio::test(flavor = "multi_thread")]
async fn git_stage_unstage_commit_and_event_broadcast() {
    let mut env = Env::start().await;
    env.init_repo();
    env.write("test.txt", b"one\n");

    let (mut csend, mut crecv) = open(&env.conn, StreamPurpose::Control).await;
    within(write_control_message(
        &mut csend,
        &ControlMessage::Ping { client_ts: 1 },
    ))
    .await
    .unwrap();
    match within(read_control_message(&mut crecv)).await.unwrap() {
        Some(ControlMessage::Pong { client_ts: 1, .. }) => {}
        other => panic!("expected Pong, got {other:?}"),
    }
    let root = env.root();
    let r_clone = root.clone();
    let mut expect_event = async || {
        assert_eq!(
            within(read_control_message(&mut crecv)).await.unwrap(),
            Some(ControlMessage::HostEvent(HostEvent::GitChanged {
                root: r_clone.clone(),
            }))
        );
    };
    // Unborn branch (no HEAD yet).
    assert!(env
        .git_op(GitOp::Stage {
            paths: vec!["test.txt".into()]
        })
        .await
        .is_ok());
    expect_event().await;
    assert!(env
        .git_op(GitOp::Unstage {
            paths: vec!["test.txt".into()]
        })
        .await
        .is_ok());
    expect_event().await;
    let GitReply::Status { status: s } = env.git_op(GitOp::Status).await.unwrap() else {
        panic!()
    };
    assert!(s.entries.iter().all(|e| e.index == GitChange::Unmodified));
    assert!(s
        .entries
        .iter()
        .any(|e| e.path == "test.txt" && e.worktree == GitChange::Untracked));
    assert!(env
        .git_op(GitOp::Stage {
            paths: vec!["test.txt".into()]
        })
        .await
        .is_ok());
    expect_event().await;
    let GitReply::Committed { oid: hash } = env
        .git_op(GitOp::Commit {
            message: "test commit".into(),
            amend: false,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(hash.len(), 40);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(env.git(&["rev-parse", "HEAD"]).trim(), hash);
    assert_eq!(env.git(&["log", "-1", "--format=%s"]).trim(), "test commit");
    expect_event().await;

    // With HEAD: stage all, then unstage one path.
    env.write("test.txt", b"two\n");
    env.write("other.txt", b"o\n");
    assert!(env
        .git_op(GitOp::Stage {
            paths: vec![".".into()]
        })
        .await
        .is_ok());
    expect_event().await;
    assert!(env
        .git_op(GitOp::Unstage {
            paths: vec!["test.txt".into()]
        })
        .await
        .is_ok());
    expect_event().await;
    let GitReply::Status { status: s } = env.git_op(GitOp::Status).await.unwrap() else {
        panic!()
    };
    assert!(s
        .entries
        .iter()
        .any(|e| e.path == "other.txt" && e.index != GitChange::Unmodified));
    assert!(s.entries.iter().any(|e| e.path == "test.txt"
        && e.worktree != GitChange::Unmodified
        && e.worktree != GitChange::Untracked));
    // Rejections.
    let _r = env
        .git_op(GitOp::Commit {
            message: " \n".into(),
            amend: false,
            stage_tracked: false,
        })
        .await;
    let r = env
        .git_op(GitOp::Stage {
            paths: vec!["../escape".into()],
        })
        .await;
    assert!(r.is_err());
    // The file exists, so only the explicit guard (not "pathspec did not match") rejects it.
    env.write("--all", b"x");
    let r = env
        .git_op(GitOp::Stage {
            paths: vec!["--all".into()],
        })
        .await;
    assert!(r.is_err());
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn git_cve_mitigation_verification() {
    let mut env = Env::start().await;
    env.init_repo();
    let canary = env.ws.parent().unwrap().join("canary");
    std::fs::create_dir(&canary).unwrap();
    let c = canary.display();
    env.write("a.txt", b"base\n");
    env.git(&["add", "."]);
    env.git(&["commit", "-q", "-m", "init"]);

    let hooks = env.ws.parent().unwrap().join("hooks");
    std::fs::create_dir(&hooks).unwrap();
    for hook in [
        "pre-commit",
        "post-commit",
        "post-index-change",
        "commit-msg",
    ] {
        let p = hooks.join(hook);
        std::fs::write(&p, format!("#!/bin/sh\ntouch {c}/hook-{hook}\n")).unwrap();
        set_mode(&p, 0o755);
    }
    let ext = env.ws.parent().unwrap().join("ext.sh");
    std::fs::write(&ext, format!("#!/bin/sh\ntouch {c}/external\n")).unwrap();
    set_mode(&ext, 0o755);
    let inc = env.ws.parent().unwrap().join("evil.inc");
    std::fs::write(
        &inc,
        format!("[filter \"a.b\"]\n\tclean = touch {c}/dotted; cat\n\trequired = true\n"),
    )
    .unwrap();

    let cfg: Vec<(String, String)> = vec![
        (
            "core.fsmonitor".into(),
            format!("touch {c}/fsmonitor; false"),
        ),
        ("core.hooksPath".into(), hooks.display().to_string()),
        ("filter.evil.clean".into(), format!("touch {c}/clean; cat")),
        (
            "filter.evil.smudge".into(),
            format!("touch {c}/smudge; cat"),
        ),
        ("filter.evil.process".into(), format!("touch {c}/process")),
        ("filter.evil.required".into(), "true".into()),
        ("diff.external".into(), ext.display().to_string()),
        (
            "diff.evil.textconv".into(),
            format!("touch {c}/textconv; cat"),
        ),
        ("diff.evil.command".into(), ext.display().to_string()),
        ("commit.gpgSign".into(), "true".into()),
        ("gpg.program".into(), ext.display().to_string()),
        ("include.path".into(), inc.display().to_string()),
    ];
    for (k, v) in &cfg {
        env.git(&["config", k, v]);
    }
    env.write(
        ".gitattributes",
        b"*.txt filter=evil diff=evil\n*.md filter=a.b\n",
    );
    env.write("a.txt", b"changed\n");
    env.write("r.md", b"readme\n");

    env.git_op(GitOp::Status).await.unwrap();
    env.git_op(GitOp::Diff {
        target: GitDiffTarget::Unstaged {
            path: "a.txt".into(),
        },
    })
    .await
    .unwrap();
    env.git_op(GitOp::Diff {
        target: GitDiffTarget::Unstaged {
            path: "r.md".into(),
        },
    })
    .await
    .unwrap();
    assert!(env
        .git_op(GitOp::Stage {
            paths: vec![".".into()]
        })
        .await
        .is_ok());
    env.git_op(GitOp::Commit {
        message: "x".into(),
        amend: false,
        stage_tracked: false,
    })
    .await
    .unwrap();
    assert!(env
        .git_op(GitOp::Unstage {
            paths: vec!["a.txt".into()]
        })
        .await
        .is_ok());

    let fired: Vec<String> = std::fs::read_dir(&canary)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        fired.is_empty(),
        "attacker-controlled commands executed: {fired:?}"
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn host_info_reports_platform_and_workspace() {
    let mut env = Env::start().await;
    match env.call(RpcRequest::HostInfo).await {
        RpcResponse::HostInfo(Ok(info)) => {
            assert_eq!(info.os, std::env::consts::OS);
            assert_eq!(info.arch, std::env::consts::ARCH);
            assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
            assert_eq!(info.workdir, env.ws.display().to_string());
            assert!(!info.host_name.trim().is_empty() && info.host_name.chars().count() <= 64);
        }
        other => panic!("expected HostInfo Ok, got {other:?}"),
    }
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fs_and_git_accept_any_session_root() {
    let mut env = Env::start().await;
    let other_tmp = tempfile::tempdir().unwrap();
    let other_root = other_tmp.path().canonicalize().unwrap();
    std::fs::write(other_root.join("hello.txt"), "hello other").unwrap();

    let root_str = other_root.display().to_string();
    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: root_str.clone(),
            path: ".".into(),
            recursive: false,
        })
        .await
    else {
        panic!()
    };
    let entries = r.unwrap();
    assert!(entries.iter().any(|e| e.name == "hello.txt"));

    // Init git repo in other_root
    Command::new("git")
        .current_dir(&other_root)
        .args(["init", "-q", "-b", "main"])
        .output()
        .unwrap();

    let reply = env
        .call(RpcRequest::Git {
            root: root_str,
            op: GitOp::Status,
        })
        .await;
    let RpcResponse::Git {
        result: Ok(GitReply::Status { status }),
    } = reply
    else {
        panic!()
    };
    assert!(status
        .entries
        .iter()
        .any(|e| e.path == "hello.txt" && e.worktree == GitChange::Untracked));

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_rejects_invalid_roots() {
    let mut env = Env::start().await;

    // Relative root
    let RpcResponse::FsList(r) = env
        .call(RpcRequest::FsList {
            root: "relative/path".into(),
            path: ".".into(),
            recursive: false,
        })
        .await
    else {
        panic!()
    };
    assert_eq!(r, Err("invalid root: must be an absolute path".into()));

    // Missing directory root
    let reply = env
        .call(RpcRequest::Git {
            root: "/does_not_exist_at_all_xyz_123".into(),
            op: GitOp::Status,
        })
        .await;
    let RpcResponse::Git { result: Err(err) } = reply else {
        panic!()
    };
    assert_eq!(err.kind, GitErrorKind::InvalidArgument);

    // Null byte in root
    let RpcResponse::FsSearch(r) = env
        .call(RpcRequest::FsSearch {
            root: "/tmp/a\0b".into(),
            query: "test".into(),
        })
        .await
    else {
        panic!()
    };
    assert_eq!(r, Err("invalid path: contains null byte".into()));

    env.shutdown().await;
}

#[tokio::test]
async fn rpc_tests_smoke() {
    let mut env = Env::start().await;
    let resp = env.call(RpcRequest::HostInfo).await;
    match resp {
        RpcResponse::HostInfo(Ok(info)) => {
            assert!(!info.os.is_empty());
        }
        other => panic!("expected HostInfo response, got {:?}", other),
    }
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn git_discard_unstaged_and_restore_blobs() {
    let mut env = Env::start().await;
    env.init_repo();
    env.write("foo.txt", b"original\n");
    env.git(&["add", "foo.txt"]);
    env.git(&["commit", "-q", "-m", "init foo"]);

    env.write("foo.txt", b"modified\n");
    env.write("bar.txt", b"untracked\n");
    let sym = env.ws.join("link.txt");
    symlink(env.ws.join("foo.txt"), &sym).unwrap();

    // Discarding symlink fails with InvalidArgument
    let err = env
        .git_op(GitOp::Discard {
            paths: vec!["link.txt".into()],
            scope: GitDiscardScope::Unstaged,
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind, GitErrorKind::InvalidArgument);
    assert!(err.message.contains("cannot discard symlink"));

    // Discard unstaged changes
    let GitReply::Discarded { items } = env
        .git_op(GitOp::Discard {
            paths: vec!["foo.txt".into(), "bar.txt".into()],
            scope: GitDiscardScope::Unstaged,
        })
        .await
        .unwrap()
    else {
        panic!("expected Discarded");
    };

    assert_eq!(items.len(), 2);
    assert_eq!(items[0].path, "foo.txt");
    assert!(items[0].blob_oid.is_some());
    assert_eq!(items[1].path, "bar.txt");
    assert!(items[1].blob_oid.is_some());

    // foo.txt should be reverted to original
    assert_eq!(
        std::fs::read(env.ws.join("foo.txt")).unwrap(),
        b"original\n"
    );
    // bar.txt should be deleted
    assert!(!env.ws.join("bar.txt").exists());

    // Restore blobs (undo discard)
    let GitReply::Done = env.git_op(GitOp::RestoreBlobs { items }).await.unwrap() else {
        panic!("expected Done");
    };

    // foo.txt should be back to modified
    assert_eq!(
        std::fs::read(env.ws.join("foo.txt")).unwrap(),
        b"modified\n"
    );
    // bar.txt should be restored
    assert_eq!(
        std::fs::read(env.ws.join("bar.txt")).unwrap(),
        b"untracked\n"
    );

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn git_discard_all_with_staged_changes() {
    let mut env = Env::start().await;
    env.init_repo();
    env.write("foo.txt", b"init\n");
    env.git(&["add", "foo.txt"]);
    env.git(&["commit", "-q", "-m", "init"]);

    env.write("foo.txt", b"staged\n");
    env.git(&["add", "foo.txt"]);
    env.write("new.txt", b"new staged\n");
    env.git(&["add", "new.txt"]);

    let GitReply::Discarded { items } = env
        .git_op(GitOp::Discard {
            paths: vec!["foo.txt".into(), "new.txt".into()],
            scope: GitDiscardScope::All,
        })
        .await
        .unwrap()
    else {
        panic!("expected Discarded");
    };
    assert_eq!(items.len(), 2);

    // foo.txt is back to init in both worktree and index
    assert_eq!(std::fs::read(env.ws.join("foo.txt")).unwrap(), b"init\n");
    // new.txt is removed from disk and index
    assert!(!env.ws.join("new.txt").exists());

    let GitReply::Status { status } = env.git_op(GitOp::Status).await.unwrap() else {
        panic!("expected status");
    };
    assert!(status.entries.is_empty());

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn git_apply_patch_stage_and_discard() {
    let mut env = Env::start().await;
    env.init_repo();
    env.write("file.txt", b"line 1\nline 2\nline 3\n");
    env.git(&["add", "file.txt"]);
    env.git(&["commit", "-q", "-m", "init file"]);

    env.write("file.txt", b"line 1\nline 2 edited\nline 3\nline 4 added\n");

    let GitReply::Diff { diff } = env
        .git_op(GitOp::Diff {
            target: GitDiffTarget::Unstaged {
                path: "file.txt".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Diff");
    };

    assert_eq!(diff.hunks.len(), 1);
    let hunk = &diff.hunks[0];
    let hunk_hash = hunk.content_hash.clone();

    // Stage line 1 and 2 (line 2 edited, which is deletion of line 2 and addition of line 2 edited)
    // Hunk lines:
    // 0: " line 1" (context)
    // 1: "-line 2" (deletion)
    // 2: "+line 2 edited" (addition)
    // 3: " line 3" (context)
    // 4: "+line 4 added" (addition)
    let GitReply::Done = env
        .git_op(GitOp::ApplyPatch {
            patch: GitPatchRequest {
                source: GitPatchSource::Unstaged,
                action: GitPatchAction::Stage,
                path: "file.txt".into(),
                hunk_index: 0,
                hunk_hash: hunk_hash.clone(),
                line_indices: vec![1, 2],
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Done");
    };

    // Verify staged diff has only line 2 edited
    let GitReply::Diff { diff: staged_diff } = env
        .git_op(GitOp::Diff {
            target: GitDiffTarget::Staged {
                path: "file.txt".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Staged diff");
    };
    assert!(!staged_diff.hunks.is_empty());
    let staged_lines: Vec<String> = staged_diff.hunks[0]
        .lines
        .iter()
        .map(|l| {
            format!(
                "{}{}",
                match l.kind {
                    DiffLineKind::Context => ' ',
                    DiffLineKind::Addition => '+',
                    DiffLineKind::Deletion => '-',
                },
                l.content
            )
        })
        .collect();
    assert!(staged_lines.contains(&"+line 2 edited".to_string()));
    assert!(!staged_lines.contains(&"+line 4 added".to_string()));

    // Verify stale diff error when wrong hash is given
    let err = env
        .git_op(GitOp::ApplyPatch {
            patch: GitPatchRequest {
                source: GitPatchSource::Unstaged,
                action: GitPatchAction::Discard,
                path: "file.txt".into(),
                hunk_index: 0,
                hunk_hash: "wrong_hash".into(),
                line_indices: vec![],
            },
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind, GitErrorKind::StaleDiff);

    // Discard the remaining unstaged change
    let GitReply::Diff {
        diff: unstaged_diff,
    } = env
        .git_op(GitOp::Diff {
            target: GitDiffTarget::Unstaged {
                path: "file.txt".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Unstaged diff");
    };
    let GitReply::Discarded { .. } = env
        .git_op(GitOp::ApplyPatch {
            patch: GitPatchRequest {
                source: GitPatchSource::Unstaged,
                action: GitPatchAction::Discard,
                path: "file.txt".into(),
                hunk_index: 0,
                hunk_hash: unstaged_diff.hunks[0].content_hash.clone(),
                line_indices: vec![],
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Discarded");
    };

    // Now worktree has no unstaged diff
    let GitReply::Diff { diff: clean_diff } = env
        .git_op(GitOp::Diff {
            target: GitDiffTarget::Unstaged {
                path: "file.txt".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Diff");
    };
    assert!(clean_diff.hunks.is_empty());

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn voice_compile_prompt_fallback_and_symbols() {
    let mut env = Env::start().await;
    env.write(
        "WorkspaceView.swift",
        b"import SwiftUI\nstruct WorkspaceView: View {}\n",
    );

    let resp = env
        .call(RpcRequest::VoiceCompilePrompt {
            session_id: "non-existent-session".into(),
            transcript: "mở file WorkspaceView . swift rồi sửa phiên bản 2 . 5".into(),
            active_file: Some("WorkspaceView.swift".into()),
            language_mode: "vi".into(),
        })
        .await;

    let RpcResponse::VoiceCompilePrompt(res) = resp else {
        panic!("expected VoiceCompilePrompt variant");
    };

    let compile_result = res.expect("voice compilation should succeed via fallback or provider");
    assert_eq!(
        compile_result.clean_prompt,
        "mở file WorkspaceView.swift rồi sửa phiên bản 2.5"
    );
    assert_eq!(compile_result.detected_language, "vi");

    env.shutdown().await;
}
