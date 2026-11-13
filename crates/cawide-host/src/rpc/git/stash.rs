use super::{validate::validate_oid, GitEngine};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{GitError, GitErrorKind, GitStashEntry};
use std::time::Duration;

pub async fn list_stashes(engine: &GitEngine) -> Result<Vec<GitStashEntry>, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(
        &ctx,
        &["stash", "list", "--format=%gd%x1f%H%x1f%at%x1f%gs", "-z"],
    );
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(15),
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

    let mut stashes = Vec::new();
    let records = out.stdout.split(|&b| b == 0).filter(|b| !b.is_empty());

    for rec in records {
        let rec_str = String::from_utf8_lossy(rec);
        let fields: Vec<&str> = rec_str.split('\x1f').collect();
        if fields.len() < 4 {
            continue;
        }

        let gd = fields[0].trim();
        let index = gd
            .strip_prefix("stash@{")
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let oid = fields[1].trim().to_string();
        let time = fields[2].trim().parse::<i64>().unwrap_or(0);
        let message = fields[3].to_string();

        stashes.push(GitStashEntry {
            index,
            oid,
            time,
            message,
        });
    }

    Ok(stashes)
}

pub async fn stash_push(
    engine: &GitEngine,
    message: Option<&str>,
    include_untracked: bool,
) -> Result<(), GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mut args = vec!["stash", "push"];
    if include_untracked {
        args.push("-u");
    }
    if let Some(msg) = message {
        args.extend(["-m", msg]);
    }

    let cmd = engine.git_cmd(&ctx, &args);
    let out = run(
        cmd,
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

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(())
}

async fn verify_stash_oid(
    engine: &GitEngine,
    ctx: &super::GitRequestCtx,
    index: u32,
    oid: &str,
) -> Result<(), GitError> {
    validate_oid(oid)?;

    let stash_ref = format!("stash@{{{index}}}");
    let cmd = engine.git_cmd(ctx, &["rev-parse", "--verify", &stash_ref]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(5),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    let actual = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || actual != oid {
        return Err(GitError {
            kind: GitErrorKind::StaleStash,
            message: format!("stash@{index} is stale (expected {oid}, found {actual})"),
            host: None,
            port: None,
        });
    }

    Ok(())
}

pub async fn stash_apply(
    engine: &GitEngine,
    index: u32,
    oid: &str,
    pop: bool,
) -> Result<(), GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    verify_stash_oid(engine, &ctx, index, oid).await?;

    let action = if pop { "pop" } else { "apply" };
    let stash_ref = format!("stash@{{{index}}}");
    let cmd = engine.git_cmd(&ctx, &["stash", action, &stash_ref]);
    let out = run(
        cmd,
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

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(())
}

pub async fn stash_drop(engine: &GitEngine, index: u32, oid: &str) -> Result<(), GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    verify_stash_oid(engine, &ctx, index, oid).await?;

    let stash_ref = format!("stash@{{{index}}}");
    let cmd = engine.git_cmd(&ctx, &["stash", "drop", &stash_ref]);
    let out = run(
        cmd,
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

    Ok(())
}
