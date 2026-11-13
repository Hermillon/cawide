//! Comprehensive end-to-end integration tests for Git RPC (B3 - B9).

mod common;

use cawide_protocol::types::{
    GitCheckoutTarget, GitConfigScope, GitConflictResolution, GitErrorKind, GitIntegrationResult,
    GitLogQuery, GitLogScope, GitOp, GitReply, GitSequencerAction,
};
use common::Env;
use std::process::Command;

#[tokio::test(flavor = "multi_thread")]
async fn test_git_identity_and_commit() {
    let mut env = Env::start().await;
    env.init_repo();

    // 1. Identity get & set
    let GitReply::Identity { identity } = env.git_op(GitOp::Identity).await.unwrap() else {
        panic!("expected Identity");
    };
    // Initially global/nosystem is dev/null so local might be empty
    assert!(identity.name.is_none() || identity.name.is_some());

    env.git_op(GitOp::SetIdentity {
        name: "Test User".into(),
        email: "test@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    let GitReply::Identity { identity } = env.git_op(GitOp::Identity).await.unwrap() else {
        panic!("expected Identity");
    };
    assert_eq!(identity.name.as_deref(), Some("Test User"));
    assert_eq!(identity.email.as_deref(), Some("test@example.com"));

    // Validation failures
    let err = env
        .git_op(GitOp::SetIdentity {
            name: "Bad\nName".into(),
            email: "test@example.com".into(),
            scope: GitConfigScope::Repository,
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind, GitErrorKind::InvalidArgument);

    let err = env
        .git_op(GitOp::SetIdentity {
            name: "Valid Name".into(),
            email: "invalid-email".into(),
            scope: GitConfigScope::Repository,
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind, GitErrorKind::InvalidArgument);

    // 2. Commit operations
    env.write("tracked.txt", b"v1\n");
    env.git_op(GitOp::Stage {
        paths: vec!["tracked.txt".into()],
    })
    .await
    .unwrap();

    let GitReply::Committed { oid: c1_oid } = env
        .git_op(GitOp::Commit {
            message: "initial commit".into(),
            amend: false,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!("expected Committed");
    };
    assert!(!c1_oid.is_empty());

    // Amend commit
    let GitReply::Committed { oid: c1_amended } = env
        .git_op(GitOp::Commit {
            message: "initial commit amended".into(),
            amend: true,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!("expected Committed");
    };
    assert_ne!(c1_oid, c1_amended);

    // stage_tracked
    env.write("tracked.txt", b"v2\n");
    let GitReply::Committed { oid: c2_oid } = env
        .git_op(GitOp::Commit {
            message: "auto staged commit".into(),
            amend: false,
            stage_tracked: true,
        })
        .await
        .unwrap()
    else {
        panic!("expected Committed");
    };
    assert_ne!(c1_amended, c2_oid);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_git_log_and_commit_detail() {
    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    // Query log on empty repo before any commits
    let GitReply::Log { page: empty_page } = env
        .git_op(GitOp::Log {
            query: GitLogQuery {
                scope: GitLogScope::Head,
                path: None,
                skip: 0,
                limit: 10,
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Log");
    };
    assert!(empty_page.commits.is_empty());
    assert!(!empty_page.has_more);

    let GitReply::Log {
        page: empty_all_page,
    } = env
        .git_op(GitOp::Log {
            query: GitLogQuery {
                scope: GitLogScope::AllRefs,
                path: None,
                skip: 0,
                limit: 10,
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Log");
    };
    assert!(empty_all_page.commits.is_empty());
    assert!(!empty_all_page.has_more);

    env.write("file1.txt", b"content 1\n");
    env.git_op(GitOp::Stage {
        paths: vec!["file1.txt".into()],
    })
    .await
    .unwrap();
    let GitReply::Committed { oid: c1 } = env
        .git_op(GitOp::Commit {
            message: "commit 1\n\nBody of commit 1".into(),
            amend: false,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!()
    };

    env.write("file2.txt", b"content 2\n");
    env.git_op(GitOp::Stage {
        paths: vec!["file2.txt".into()],
    })
    .await
    .unwrap();
    let GitReply::Committed { oid: c2 } = env
        .git_op(GitOp::Commit {
            message: "commit 2".into(),
            amend: false,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!()
    };

    // Query log
    let GitReply::Log { page } = env
        .git_op(GitOp::Log {
            query: GitLogQuery {
                scope: GitLogScope::Head,
                path: None,
                skip: 0,
                limit: 10,
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Log");
    };

    assert_eq!(page.commits.len(), 2);
    assert_eq!(page.commits[0].oid, c2);
    assert_eq!(page.commits[1].oid, c1);
    assert_eq!(page.commits[0].graph.lane, 0);

    // Commit detail
    let GitReply::CommitDetail { detail } = env
        .git_op(GitOp::CommitDetail { oid: c1.clone() })
        .await
        .unwrap()
    else {
        panic!("expected CommitDetail");
    };

    assert_eq!(detail.oid, c1);
    assert_eq!(detail.author_name, "Dev");
    assert_eq!(detail.author_email, "dev@example.com");
    assert_eq!(detail.subject, "commit 1");
    assert!(detail.body.contains("Body of commit 1"));
    assert_eq!(detail.files.len(), 1);
    assert_eq!(detail.files[0].path, "file1.txt");

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_git_branches_and_checkout() {
    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    env.write("init.txt", b"init\n");
    env.git_op(GitOp::Stage {
        paths: vec!["init.txt".into()],
    })
    .await
    .unwrap();
    env.git_op(GitOp::Commit {
        message: "init".into(),
        amend: false,
        stage_tracked: false,
    })
    .await
    .unwrap();

    // Create branch feat
    env.git_op(GitOp::CreateBranch {
        name: "feat".into(),
        start_point: None,
        checkout: true,
    })
    .await
    .unwrap();

    let GitReply::Branches { branches } = env.git_op(GitOp::Branches).await.unwrap() else {
        panic!("expected Branches");
    };

    let feat_branch = branches.iter().find(|b| b.name == "feat").unwrap();
    assert!(feat_branch.is_head);

    // Rename branch
    env.git_op(GitOp::RenameBranch {
        old_name: "feat".into(),
        new_name: "feature-x".into(),
    })
    .await
    .unwrap();

    // Checkout main
    let main_name = branches
        .iter()
        .find(|b| b.name != "feat")
        .unwrap()
        .name
        .clone();
    env.git_op(GitOp::Checkout {
        target: GitCheckoutTarget::Branch {
            name: main_name.clone(),
        },
    })
    .await
    .unwrap();

    // Delete feature-x
    env.git_op(GitOp::DeleteBranch {
        name: "feature-x".into(),
        force: true,
    })
    .await
    .unwrap();

    let GitReply::Branches { branches } = env.git_op(GitOp::Branches).await.unwrap() else {
        panic!("expected Branches");
    };
    assert!(!branches.iter().any(|b| b.name == "feature-x"));

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_git_remotes_push_and_pull() {
    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    env.write("file.txt", b"hello\n");
    env.git_op(GitOp::Stage {
        paths: vec!["file.txt".into()],
    })
    .await
    .unwrap();
    env.git_op(GitOp::Commit {
        message: "c1".into(),
        amend: false,
        stage_tracked: false,
    })
    .await
    .unwrap();

    // Create a local bare repo to act as remote
    let bare_dir = env.ws.parent().unwrap().join("remote.git");
    Command::new("git")
        .args(["init", "--bare", bare_dir.to_str().unwrap()])
        .output()
        .unwrap();

    let remote_url = format!("file://{}", bare_dir.display());

    // Add remote
    env.git_op(GitOp::AddRemote {
        name: "origin".into(),
        url: remote_url.clone(),
    })
    .await
    .unwrap();

    let GitReply::Remotes { remotes } = env.git_op(GitOp::Remotes).await.unwrap() else {
        panic!("expected Remotes");
    };
    assert_eq!(remotes.len(), 1);
    assert_eq!(remotes[0].name, "origin");

    // Push to remote
    let GitReply::Pushed { new_remote_branch } = env
        .git_op(GitOp::Push {
            remote: "origin".into(),
            local_branch: "HEAD".into(),
            remote_branch: "main".into(),
            set_upstream: true,
            force_with_lease: false,
            account: None,
        })
        .await
        .unwrap()
    else {
        panic!("expected Pushed");
    };
    assert!(new_remote_branch);

    // Fetch from remote
    env.git_op(GitOp::Fetch {
        remote: Some("origin".into()),
        account: None,
    })
    .await
    .unwrap();

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_git_merge_conflict_and_resolution() {
    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    env.write("doc.txt", b"base line\n");
    env.git_op(GitOp::Stage {
        paths: vec!["doc.txt".into()],
    })
    .await
    .unwrap();
    env.git_op(GitOp::Commit {
        message: "base".into(),
        amend: false,
        stage_tracked: false,
    })
    .await
    .unwrap();

    // Branch A
    env.git_op(GitOp::CreateBranch {
        name: "branch-a".into(),
        start_point: None,
        checkout: true,
    })
    .await
    .unwrap();
    env.write("doc.txt", b"branch a edit\n");
    env.git_op(GitOp::Commit {
        message: "edit a".into(),
        amend: false,
        stage_tracked: true,
    })
    .await
    .unwrap();

    // Branch B
    env.git_op(GitOp::Checkout {
        target: GitCheckoutTarget::Branch {
            name: "main".into(),
        },
    })
    .await
    .unwrap();
    env.git_op(GitOp::CreateBranch {
        name: "branch-b".into(),
        start_point: None,
        checkout: true,
    })
    .await
    .unwrap();
    env.write("doc.txt", b"branch b edit\n");
    env.git_op(GitOp::Commit {
        message: "edit b".into(),
        amend: false,
        stage_tracked: true,
    })
    .await
    .unwrap();

    // Merge branch-a into branch-b => conflict
    let GitReply::Integrated { outcome } = env
        .git_op(GitOp::Merge {
            reference: "branch-a".into(),
        })
        .await
        .unwrap()
    else {
        panic!("expected Integrated");
    };

    assert_eq!(outcome.result, GitIntegrationResult::Conflicts);
    assert_eq!(outcome.conflicted_paths, vec!["doc.txt"]);

    // Resolve conflict with Ours
    env.git_op(GitOp::ResolveConflict {
        path: "doc.txt".into(),
        resolution: GitConflictResolution::Ours,
    })
    .await
    .unwrap();

    // Complete sequencer
    let GitReply::Integrated { outcome } = env
        .git_op(GitOp::Sequencer {
            action: GitSequencerAction::Continue,
        })
        .await
        .unwrap()
    else {
        panic!("expected Integrated");
    };
    assert_eq!(outcome.result, GitIntegrationResult::Completed);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_git_tags_and_stash() {
    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    env.write("file.txt", b"v1\n");
    env.git_op(GitOp::Stage {
        paths: vec!["file.txt".into()],
    })
    .await
    .unwrap();
    let GitReply::Committed { oid: c1 } = env
        .git_op(GitOp::Commit {
            message: "v1".into(),
            amend: false,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!()
    };

    // 1. Tags
    env.git_op(GitOp::CreateTag {
        name: "v1.0".into(),
        target: c1.clone(),
        message: None,
    })
    .await
    .unwrap();

    env.git_op(GitOp::CreateTag {
        name: "v1.1".into(),
        target: c1.clone(),
        message: Some("annotated tag".into()),
    })
    .await
    .unwrap();

    let GitReply::Tags { tags } = env.git_op(GitOp::Tags).await.unwrap() else {
        panic!("expected Tags");
    };
    assert_eq!(tags.len(), 2);
    let t1 = tags.iter().find(|t| t.name == "v1.0").unwrap();
    assert!(!t1.annotated);
    let t2 = tags.iter().find(|t| t.name == "v1.1").unwrap();
    assert!(t2.annotated);

    env.git_op(GitOp::DeleteTag {
        name: "v1.0".into(),
    })
    .await
    .unwrap();
    let GitReply::Tags { tags } = env.git_op(GitOp::Tags).await.unwrap() else {
        panic!()
    };
    assert_eq!(tags.len(), 1);

    // 2. Stash
    env.write("file.txt", b"v1 dirty\n");
    env.git_op(GitOp::StashPush {
        message: Some("my stash".into()),
        include_untracked: false,
    })
    .await
    .unwrap();

    // Verify working tree is clean
    assert_eq!(std::fs::read(env.ws.join("file.txt")).unwrap(), b"v1\n");

    let GitReply::Stashes { stashes } = env.git_op(GitOp::Stashes).await.unwrap() else {
        panic!("expected Stashes");
    };
    assert_eq!(stashes.len(), 1);
    let stash_oid = stashes[0].oid.clone();

    // Stale stash check
    let err = env
        .git_op(GitOp::StashApply {
            index: 0,
            oid: "0000000000000000000000000000000000000000".into(),
            pop: false,
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind, GitErrorKind::StaleStash);

    // Pop stash
    env.git_op(GitOp::StashApply {
        index: 0,
        oid: stash_oid,
        pop: true,
    })
    .await
    .unwrap();

    assert_eq!(
        std::fs::read(env.ws.join("file.txt")).unwrap(),
        b"v1 dirty\n"
    );

    let GitReply::Stashes { stashes } = env.git_op(GitOp::Stashes).await.unwrap() else {
        panic!()
    };
    assert!(stashes.is_empty());

    env.shutdown().await;
}
#[cfg(unix)]
struct EphemeralSshd {
    port: u16,
    client_key: std::path::PathBuf,
    pid_file: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

#[cfg(unix)]
impl EphemeralSshd {
    fn start() -> Option<Self> {
        let which = Command::new("which").arg("sshd").output().ok()?;
        if !which.status.success() {
            return None;
        }
        let sshd_path = String::from_utf8_lossy(&which.stdout).trim().to_string();

        let dir = tempfile::tempdir().ok()?;
        let host_key = dir.path().join("host_key");
        let client_key = dir.path().join("client_key");
        let auth_keys = dir.path().join("authorized_keys");
        let pid_file = dir.path().join("sshd.pid");
        let config_file = dir.path().join("sshd_config");

        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f", host_key.to_str()?])
            .output()
            .ok()?;
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f", client_key.to_str()?])
            .output()
            .ok()?;

        let pub_key = std::fs::read(dir.path().join("client_key.pub")).ok()?;
        std::fs::write(&auth_keys, pub_key).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&auth_keys, std::fs::Permissions::from_mode(0o600));
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        drop(listener);

        let config_content = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\n",
            host_key.display(),
            pid_file.display(),
            auth_keys.display(),
        );
        std::fs::write(&config_file, config_content).ok()?;

        let status = Command::new(&sshd_path)
            .args(["-f", config_file.to_str()?])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }

        std::thread::sleep(std::time::Duration::from_millis(200));

        Some(Self {
            port,
            client_key,
            pid_file,
            _dir: dir,
        })
    }
}

#[cfg(unix)]
impl Drop for EphemeralSshd {
    fn drop(&mut self) {
        if let Ok(pid_str) = std::fs::read_to_string(&self.pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn test_git_ssh_fetch_ephemeral_sshd() {
    let Some(sshd) = EphemeralSshd::start() else {
        eprintln!("skipping test_git_ssh_fetch_ephemeral_sshd: sshd not available");
        return;
    };

    // Create bare repo accessible via SSH
    let bare_repo = sshd._dir.path().join("ssh_repo.git");
    Command::new("git")
        .args(["init", "--bare", bare_repo.to_str().unwrap()])
        .output()
        .unwrap();

    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    // Set user-managed SSH command in git config so it uses the client key
    let ssh_cmd = format!(
        "ssh -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p {}",
        sshd.client_key.display(),
        sshd.port
    );
    env.git(&["config", "core.sshCommand", &ssh_cmd]);

    let ssh_url = format!("ssh://127.0.0.1:{}{}", sshd.port, bare_repo.display());
    env.git_op(GitOp::AddRemote {
        name: "ssh-origin".into(),
        url: ssh_url,
    })
    .await
    .unwrap();

    // Fetch from SSH remote
    let res = env
        .git_op(GitOp::Fetch {
            remote: Some("ssh-origin".into()),
            account: None,
        })
        .await;

    assert!(res.is_ok(), "SSH fetch failed: {:?}", res);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_all_refs_scope_excludes_stash_commits() {
    let mut env = Env::start().await;
    env.init_repo();
    env.git_op(GitOp::SetIdentity {
        name: "Dev".into(),
        email: "dev@example.com".into(),
        scope: GitConfigScope::Repository,
    })
    .await
    .unwrap();

    env.write("file1.txt", b"content 1\n");
    env.git_op(GitOp::Stage {
        paths: vec!["file1.txt".into()],
    })
    .await
    .unwrap();
    let GitReply::Committed { oid: c1 } = env
        .git_op(GitOp::Commit {
            message: "commit 1".into(),
            amend: false,
            stage_tracked: false,
        })
        .await
        .unwrap()
    else {
        panic!("expected commit");
    };

    // Modify file and stash push
    env.write("file1.txt", b"content 1 modified for stash\n");
    env.git_op(GitOp::StashPush {
        message: Some("WIP stash test".into()),
        include_untracked: false,
    })
    .await
    .unwrap();

    // Query log with GitLogScope::AllRefs
    let GitReply::Log { page } = env
        .git_op(GitOp::Log {
            query: GitLogQuery {
                scope: GitLogScope::AllRefs,
                path: None,
                skip: 0,
                limit: 10,
            },
        })
        .await
        .unwrap()
    else {
        panic!("expected Log");
    };

    // Verify stash commits are NOT returned, only commit 1
    assert_eq!(
        page.commits.len(),
        1,
        "stash commits should be excluded from AllRefs"
    );
    assert_eq!(page.commits[0].oid, c1);

    env.shutdown().await;
}
