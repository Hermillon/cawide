use super::{
    validate::{validate_oid, validate_ref_name},
    GitEngine,
};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{
    GitBranch, GitBranchKind, GitCheckoutTarget, GitError, GitErrorKind, GitUpstream,
};
use std::time::Duration;

pub async fn list_branches(engine: &GitEngine) -> Result<Vec<GitBranch>, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(
        &ctx,
        &[
            "for-each-ref",
            "--format=%(refname)\x1f%(objectname)\x1f%(HEAD)\x1f%(upstream)\x1f%(upstream:track)\x1f%(committerdate:raw)\x1f%(subject)",
            "refs/heads",
            "refs/remotes",
        ],
    );

    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
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

    let mut branches = Vec::new();
    let records = out.stdout.split(|&b| b == b'\n').filter(|b| !b.is_empty());

    for rec in records {
        let rec_str = String::from_utf8_lossy(rec);
        let fields: Vec<&str> = rec_str.split('\x1f').collect();
        if fields.len() < 7 {
            continue;
        }

        let full_ref = fields[0].to_string();
        let oid = fields[1].to_string();
        let is_head = fields[2].trim() == "*";
        let upstream_ref = fields[3].trim();
        let track_str = fields[4].trim();
        let date_str = fields[5].trim();
        let subject = fields[6].to_string();

        let last_commit_time = date_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        // Distinguish local vs remote
        let (name, kind) = if let Some(local_name) = full_ref.strip_prefix("refs/heads/") {
            (local_name.to_string(), GitBranchKind::Local)
        } else if let Some(remote_path) = full_ref.strip_prefix("refs/remotes/") {
            if remote_path.ends_with("/HEAD") {
                continue; // Skip remote HEAD pointer
            }
            let remote_name = remote_path
                .split('/')
                .next()
                .unwrap_or("origin")
                .to_string();
            (
                remote_path.to_string(),
                GitBranchKind::Remote {
                    remote: remote_name,
                },
            )
        } else {
            continue;
        };

        let upstream = if !upstream_ref.is_empty() {
            let u_name = upstream_ref
                .strip_prefix("refs/remotes/")
                .or_else(|| upstream_ref.strip_prefix("refs/heads/"))
                .unwrap_or(upstream_ref)
                .to_string();

            let gone = track_str.contains("gone");
            let mut ahead = 0u32;
            let mut behind = 0u32;

            if let Some(pos) = track_str.find("ahead ") {
                let rest = &track_str[pos + 6..];
                let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                ahead = num_str.parse().unwrap_or(0);
            }
            if let Some(pos) = track_str.find("behind ") {
                let rest = &track_str[pos + 7..];
                let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                behind = num_str.parse().unwrap_or(0);
            }

            Some(GitUpstream {
                name: u_name,
                ahead,
                behind,
                gone,
            })
        } else {
            None
        };

        branches.push(GitBranch {
            name,
            full_ref,
            kind,
            oid,
            is_head,
            upstream,
            last_commit_time,
            subject,
        });
    }

    // Sort: HEAD first, then Local branches, then Remote branches
    branches.sort_by(|a, b| {
        if a.is_head != b.is_head {
            return b.is_head.cmp(&a.is_head);
        }
        match (&a.kind, &b.kind) {
            (GitBranchKind::Local, GitBranchKind::Remote { .. }) => std::cmp::Ordering::Less,
            (GitBranchKind::Remote { .. }, GitBranchKind::Local) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        }
    });

    Ok(branches)
}

pub async fn create_branch(
    engine: &GitEngine,
    name: &str,
    start_point: Option<&str>,
    checkout: bool,
) -> Result<(), GitError> {
    validate_ref_name(name)?;
    if let Some(sp) = start_point {
        validate_ref_name(sp)?;
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mut args = if checkout {
        vec!["checkout", "-b", name]
    } else {
        vec!["branch", name]
    };

    if let Some(sp) = start_point {
        args.push(sp);
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

pub async fn checkout(engine: &GitEngine, target: GitCheckoutTarget) -> Result<(), GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let args: Vec<String> = match target {
        GitCheckoutTarget::Branch { name } => {
            validate_ref_name(&name)?;
            vec!["checkout".to_string(), name]
        }
        GitCheckoutTarget::RemoteBranch {
            remote_branch,
            local_name,
        } => {
            validate_ref_name(&remote_branch)?;
            validate_ref_name(&local_name)?;
            vec![
                "checkout".to_string(),
                "-b".to_string(),
                local_name,
                "--track".to_string(),
                remote_branch,
            ]
        }
        GitCheckoutTarget::Detached { oid } => {
            validate_oid(&oid)?;
            vec!["checkout".to_string(), "--detach".to_string(), oid]
        }
    };

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

pub async fn rename_branch(
    engine: &GitEngine,
    old_name: &str,
    new_name: &str,
) -> Result<(), GitError> {
    validate_ref_name(old_name)?;
    validate_ref_name(new_name)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["branch", "-m", old_name, new_name]);
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

pub async fn delete_branch(engine: &GitEngine, name: &str, force: bool) -> Result<(), GitError> {
    validate_ref_name(name)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let flag = if force { "-D" } else { "-d" };
    let cmd = engine.git_cmd(&ctx, &["branch", flag, name]);
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
