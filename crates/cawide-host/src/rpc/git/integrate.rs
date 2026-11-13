use super::{
    validate::{validate_oid, validate_paths, validate_ref_name},
    GitEngine,
};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{
    GitConflictResolution, GitError, GitErrorKind, GitIntegrationOutcome, GitIntegrationResult,
    GitResetMode, GitSequencerAction,
};
use std::time::Duration;

fn invalid_arg(msg: impl Into<String>) -> GitError {
    GitError {
        kind: GitErrorKind::InvalidArgument,
        message: msg.into(),
        host: None,
        port: None,
    }
}

pub async fn merge(engine: &GitEngine, reference: &str) -> Result<GitIntegrationOutcome, GitError> {
    validate_ref_name(reference)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["merge", reference]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let stderr_str = String::from_utf8_lossy(&out.stderr);

    if !out.status.success() {
        let conflicts = get_conflicted_paths(engine, &ctx).await;
        if !conflicts.is_empty() {
            super::lfs::invalidate_lfs_cache(engine.root());
            return Ok(GitIntegrationOutcome {
                result: GitIntegrationResult::Conflicts,
                conflicted_paths: conflicts,
            });
        }

        let kind = super::errors::classify(&stderr_str, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    let result = if stdout_str.contains("Already up to date") {
        GitIntegrationResult::UpToDate
    } else if stdout_str.contains("Fast-forward") {
        GitIntegrationResult::FastForward
    } else {
        GitIntegrationResult::Completed
    };

    Ok(GitIntegrationOutcome {
        result,
        conflicted_paths: Vec::new(),
    })
}

pub async fn rebase(engine: &GitEngine, onto: &str) -> Result<GitIntegrationOutcome, GitError> {
    validate_ref_name(onto)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["rebase", onto]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let stderr_str = String::from_utf8_lossy(&out.stderr);

    if !out.status.success() {
        let conflicts = get_conflicted_paths(engine, &ctx).await;
        if !conflicts.is_empty() {
            super::lfs::invalidate_lfs_cache(engine.root());
            return Ok(GitIntegrationOutcome {
                result: GitIntegrationResult::Conflicts,
                conflicted_paths: conflicts,
            });
        }

        let kind = super::errors::classify(&stderr_str, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    let result = if stdout_str.contains("is up to date") || stdout_str.contains("up to date") {
        GitIntegrationResult::UpToDate
    } else if stdout_str.contains("Fast-forwarded") {
        GitIntegrationResult::FastForward
    } else {
        GitIntegrationResult::Completed
    };

    Ok(GitIntegrationOutcome {
        result,
        conflicted_paths: Vec::new(),
    })
}

pub async fn sequencer(
    engine: &GitEngine,
    action: GitSequencerAction,
) -> Result<GitIntegrationOutcome, GitError> {
    let git_dir = super::status::get_git_dir(engine)
        .await
        .unwrap_or_else(|| engine.root().join(".git"));
    let is_rebase = git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists();
    let is_merge = git_dir.join("MERGE_HEAD").exists();
    let is_cherry_pick = git_dir.join("CHERRY_PICK_HEAD").exists();
    let is_revert = git_dir.join("REVERT_HEAD").exists();

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd_args: Vec<&str> = match action {
        GitSequencerAction::Continue => {
            if is_rebase {
                vec!["rebase", "--continue"]
            } else if is_merge {
                vec!["commit", "--no-edit"]
            } else if is_cherry_pick {
                vec!["cherry-pick", "--continue"]
            } else if is_revert {
                vec!["revert", "--continue"]
            } else {
                return Err(invalid_arg(
                    "no rebase, merge, cherry-pick, or revert in progress",
                ));
            }
        }
        GitSequencerAction::Abort => {
            if is_rebase {
                vec!["rebase", "--abort"]
            } else if is_merge {
                vec!["merge", "--abort"]
            } else if is_cherry_pick {
                vec!["cherry-pick", "--abort"]
            } else if is_revert {
                vec!["revert", "--abort"]
            } else {
                return Err(invalid_arg(
                    "no rebase, merge, cherry-pick, or revert in progress",
                ));
            }
        }
        GitSequencerAction::Skip => {
            if is_rebase {
                vec!["rebase", "--skip"]
            } else if is_cherry_pick {
                vec!["cherry-pick", "--skip"]
            } else if is_revert {
                vec!["revert", "--skip"]
            } else {
                return Err(invalid_arg("skip is not supported for merge"));
            }
        }
    };

    let cmd = engine.git_cmd(&ctx, &cmd_args);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    let stderr_str = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let conflicts = get_conflicted_paths(engine, &ctx).await;
        if !conflicts.is_empty() {
            super::lfs::invalidate_lfs_cache(engine.root());
            return Ok(GitIntegrationOutcome {
                result: GitIntegrationResult::Conflicts,
                conflicted_paths: conflicts,
            });
        }

        let kind = super::errors::classify(&stderr_str, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(GitIntegrationOutcome {
        result: GitIntegrationResult::Completed,
        conflicted_paths: Vec::new(),
    })
}

pub async fn resolve_conflict(
    engine: &GitEngine,
    path: &str,
    resolution: GitConflictResolution,
) -> Result<(), GitError> {
    validate_paths(&[path.to_string()])?;
    let rel = engine.validate_and_relativize(path).map_err(invalid_arg)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    match resolution {
        GitConflictResolution::Ours => {
            let checkout_cmd = engine.git_cmd(&ctx, &["checkout", "--ours", "--", &rel]);
            let _ = run(
                checkout_cmd,
                RunOpts {
                    stdin: None,
                    stdout_cap: 1024,
                    timeout: Duration::from_secs(15),
                },
            )
            .await;
        }
        GitConflictResolution::Theirs => {
            let checkout_cmd = engine.git_cmd(&ctx, &["checkout", "--theirs", "--", &rel]);
            let _ = run(
                checkout_cmd,
                RunOpts {
                    stdin: None,
                    stdout_cap: 1024,
                    timeout: Duration::from_secs(15),
                },
            )
            .await;
        }
        GitConflictResolution::MarkResolved => {}
    }

    // Now either git add or git rm depending on whether file exists on disk
    let target = engine.root().join(&rel);
    let stage_args = if target.exists() {
        vec!["add", "--", &rel]
    } else {
        vec!["rm", "-f", "--", &rel]
    };

    let stage_cmd = engine.git_cmd(&ctx, &stage_args);
    let out = run(
        stage_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
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
        return Err(GitError {
            kind: GitErrorKind::Other,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(())
}

pub async fn cherry_pick(engine: &GitEngine, oid: &str) -> Result<GitIntegrationOutcome, GitError> {
    validate_oid(oid)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["cherry-pick", oid]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    let stderr_str = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let conflicts = get_conflicted_paths(engine, &ctx).await;
        if !conflicts.is_empty() {
            super::lfs::invalidate_lfs_cache(engine.root());
            return Ok(GitIntegrationOutcome {
                result: GitIntegrationResult::Conflicts,
                conflicted_paths: conflicts,
            });
        }

        let kind = super::errors::classify(&stderr_str, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(GitIntegrationOutcome {
        result: GitIntegrationResult::Completed,
        conflicted_paths: Vec::new(),
    })
}

pub async fn revert(engine: &GitEngine, oid: &str) -> Result<GitIntegrationOutcome, GitError> {
    validate_oid(oid)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["revert", "--no-edit", oid]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    let stderr_str = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let conflicts = get_conflicted_paths(engine, &ctx).await;
        if !conflicts.is_empty() {
            super::lfs::invalidate_lfs_cache(engine.root());
            return Ok(GitIntegrationOutcome {
                result: GitIntegrationResult::Conflicts,
                conflicted_paths: conflicts,
            });
        }

        let kind = super::errors::classify(&stderr_str, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(GitIntegrationOutcome {
        result: GitIntegrationResult::Completed,
        conflicted_paths: Vec::new(),
    })
}

pub async fn reset(engine: &GitEngine, oid: &str, mode: GitResetMode) -> Result<(), GitError> {
    validate_oid(oid)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mode_flag = match mode {
        GitResetMode::Soft => "--soft",
        GitResetMode::Mixed => "--mixed",
        GitResetMode::Hard => "--hard",
    };

    let cmd = engine.git_cmd(&ctx, &["reset", mode_flag, oid]);
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

async fn get_conflicted_paths(engine: &GitEngine, ctx: &super::GitRequestCtx) -> Vec<String> {
    let cmd = engine.git_cmd(ctx, &["diff", "--name-only", "--diff-filter=U", "-z"]);
    if let Ok(out) = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024 * 1024,
            timeout: Duration::from_secs(10),
        },
    )
    .await
    {
        if out.status.success() {
            return out
                .stdout
                .split(|&b| b == 0)
                .filter(|b| !b.is_empty())
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect();
        }
    }
    Vec::new()
}
