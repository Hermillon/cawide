use super::GitEngine;
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{GitError, GitErrorKind, MAX_COMMIT_MESSAGE_BYTES};
use std::time::Duration;

pub async fn commit(
    engine: &GitEngine,
    message: &str,
    amend: bool,
    stage_tracked: bool,
) -> Result<String, GitError> {
    if message.len() > MAX_COMMIT_MESSAGE_BYTES {
        return Err(GitError {
            kind: GitErrorKind::InvalidArgument,
            message: format!(
                "commit message exceeds maximum size of {} bytes",
                MAX_COMMIT_MESSAGE_BYTES
            ),
            host: None,
            port: None,
        });
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    if stage_tracked {
        let add_cmd = engine.git_cmd(&ctx, &["add", "-u"]);
        let out = run(
            add_cmd,
            RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_secs(30),
            },
        )
        .await
        .map_err(|e| GitError {
            kind: GitErrorKind::Other,
            message: e.to_string(),
            host: None,
            port: None,
        })?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let kind = super::errors::classify(&stderr, Some(out.status), false);
            return Err(GitError {
                kind,
                message: stderr.trim().to_string(),
                host: None,
                port: None,
            });
        }
    }

    let mut args = vec!["commit", "-q"];
    if amend {
        args.push("--amend");
    }

    let trimmed = message.trim();
    let mut stdin_bytes: Option<&[u8]> = None;

    if !trimmed.is_empty() {
        args.extend(["-F", "-"]);
        stdin_bytes = Some(message.as_bytes());
    } else if amend {
        args.push("--no-edit");
    } else {
        // Check for MERGE_MSG
        let merge_msg_path = engine.root().join(".git").join("MERGE_MSG");
        if merge_msg_path.exists() {
            args.extend(["-F", ".git/MERGE_MSG"]);
        } else {
            return Err(GitError {
                kind: GitErrorKind::InvalidArgument,
                message: "commit message cannot be empty".into(),
                host: None,
                port: None,
            });
        }
    }

    let commit_cmd = engine.git_cmd(&ctx, &args);
    let out = run(
        commit_cmd,
        RunOpts {
            stdin: stdin_bytes,
            stdout_cap: 1024,
            timeout: Duration::from_secs(30),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let kind = super::errors::classify(&stderr, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    let rev_cmd = engine.git_cmd(&ctx, &["rev-parse", "HEAD"]);
    let rev_out = run(
        rev_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 256,
            timeout: Duration::from_secs(10),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    if !rev_out.status.success() {
        return Err(GitError {
            kind: GitErrorKind::Other,
            message: "failed to resolve HEAD after commit".into(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    let oid = String::from_utf8_lossy(&rev_out.stdout).trim().to_string();
    Ok(oid)
}
