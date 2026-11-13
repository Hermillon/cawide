use super::adapters::CheckoutSource;
use crate::rpc::git::GitEngine;
use cawide_protocol::types::{ForgeError, ForgeErrorKind};
use std::time::Duration;

pub async fn run_checkout(
    engine: &GitEngine,
    source: &CheckoutSource,
    reset_existing: bool,
) -> Result<String, ForgeError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| ForgeError {
        kind: ForgeErrorKind::GitFailed,
        message: e,
        git_kind: None,
        host: None,
        port: None,
    })?;

    // 1. git fetch <fetch_from> +<refspec>
    let refspec_arg = format!("+{}", source.refspec);
    let fetch_cmd = engine.git_cmd(&ctx, &["fetch", &source.fetch_from, &refspec_arg]);
    let out = crate::rpc::process::run(
        fetch_cmd,
        crate::rpc::process::RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: Duration::from_secs(60),
        },
    )
    .await
    .map_err(|e| ForgeError {
        kind: ForgeErrorKind::GitFailed,
        message: e.to_string(),
        git_kind: None,
        host: None,
        port: None,
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let git_kind = crate::rpc::git::errors::classify(&stderr, Some(out.status), false);
        return Err(ForgeError {
            kind: ForgeErrorKind::GitFailed,
            message: format!("fetch pull request ref failed: {}", stderr.trim()),
            git_kind: Some(git_kind),
            host: None,
            port: None,
        });
    }

    // 2. Check local branch state
    let branch_ref = format!("refs/heads/{}", source.local_branch);
    let check_cmd = engine.git_cmd(&ctx, &["rev-parse", "--verify", "-q", &branch_ref]);
    let check_out = crate::rpc::process::run(
        check_cmd,
        crate::rpc::process::RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
        },
    )
    .await
    .map_err(|e| ForgeError {
        kind: ForgeErrorKind::GitFailed,
        message: e.to_string(),
        git_kind: None,
        host: None,
        port: None,
    })?;

    let branch_exists = check_out.status.success();

    if !branch_exists {
        // git switch -c <local_branch> FETCH_HEAD
        let switch_cmd =
            engine.git_cmd(&ctx, &["switch", "-c", &source.local_branch, "FETCH_HEAD"]);
        let s_out = crate::rpc::process::run(
            switch_cmd,
            crate::rpc::process::RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_secs(30),
            },
        )
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::GitFailed,
            message: e.to_string(),
            git_kind: None,
            host: None,
            port: None,
        })?;

        if !s_out.status.success() {
            let stderr = String::from_utf8_lossy(&s_out.stderr);
            let git_kind = crate::rpc::git::errors::classify(&stderr, Some(s_out.status), false);
            return Err(ForgeError {
                kind: ForgeErrorKind::GitFailed,
                message: stderr.trim().to_string(),
                git_kind: Some(git_kind),
                host: None,
                port: None,
            });
        }
    } else {
        // Branch exists: check if ancestor of FETCH_HEAD
        let ancestor_cmd = engine.git_cmd(
            &ctx,
            &["merge-base", "--is-ancestor", &branch_ref, "FETCH_HEAD"],
        );
        let a_out = crate::rpc::process::run(
            ancestor_cmd,
            crate::rpc::process::RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_secs(10),
            },
        )
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::GitFailed,
            message: e.to_string(),
            git_kind: None,
            host: None,
            port: None,
        })?;

        let is_ancestor = a_out.status.success();

        if is_ancestor {
            // git switch <local_branch> && git merge --ff-only FETCH_HEAD
            let switch_cmd = engine.git_cmd(&ctx, &["switch", &source.local_branch]);
            let s_out = crate::rpc::process::run(
                switch_cmd,
                crate::rpc::process::RunOpts {
                    stdin: None,
                    stdout_cap: 1024,
                    timeout: Duration::from_secs(30),
                },
            )
            .await
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::GitFailed,
                message: e.to_string(),
                git_kind: None,
                host: None,
                port: None,
            })?;

            if !s_out.status.success() {
                let stderr = String::from_utf8_lossy(&s_out.stderr);
                let git_kind =
                    crate::rpc::git::errors::classify(&stderr, Some(s_out.status), false);
                return Err(ForgeError {
                    kind: ForgeErrorKind::GitFailed,
                    message: stderr.trim().to_string(),
                    git_kind: Some(git_kind),
                    host: None,
                    port: None,
                });
            }

            let merge_cmd = engine.git_cmd(&ctx, &["merge", "--ff-only", "FETCH_HEAD"]);
            let m_out = crate::rpc::process::run(
                merge_cmd,
                crate::rpc::process::RunOpts {
                    stdin: None,
                    stdout_cap: 1024,
                    timeout: Duration::from_secs(30),
                },
            )
            .await
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::GitFailed,
                message: e.to_string(),
                git_kind: None,
                host: None,
                port: None,
            })?;

            if !m_out.status.success() {
                let stderr = String::from_utf8_lossy(&m_out.stderr);
                let git_kind =
                    crate::rpc::git::errors::classify(&stderr, Some(m_out.status), false);
                return Err(ForgeError {
                    kind: ForgeErrorKind::GitFailed,
                    message: stderr.trim().to_string(),
                    git_kind: Some(git_kind),
                    host: None,
                    port: None,
                });
            }
        } else if !reset_existing {
            return Err(ForgeError {
                kind: ForgeErrorKind::AlreadyExists,
                message: format!("{} has local commits", source.local_branch),
                git_kind: None,
                host: None,
                port: None,
            });
        } else {
            // git switch -C <local_branch> FETCH_HEAD
            let reset_cmd =
                engine.git_cmd(&ctx, &["switch", "-C", &source.local_branch, "FETCH_HEAD"]);
            let r_out = crate::rpc::process::run(
                reset_cmd,
                crate::rpc::process::RunOpts {
                    stdin: None,
                    stdout_cap: 1024,
                    timeout: Duration::from_secs(30),
                },
            )
            .await
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::GitFailed,
                message: e.to_string(),
                git_kind: None,
                host: None,
                port: None,
            })?;

            if !r_out.status.success() {
                let stderr = String::from_utf8_lossy(&r_out.stderr);
                let git_kind =
                    crate::rpc::git::errors::classify(&stderr, Some(r_out.status), false);
                return Err(ForgeError {
                    kind: ForgeErrorKind::GitFailed,
                    message: stderr.trim().to_string(),
                    git_kind: Some(git_kind),
                    host: None,
                    port: None,
                });
            }
        }
    }

    crate::rpc::git::lfs::invalidate_lfs_cache(engine.root());
    Ok(source.local_branch.clone())
}
