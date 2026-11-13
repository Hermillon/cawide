use super::{validate::validate_paths, GitEngine};
use crate::rpc::process::{run, run_to_writer, RunOpts};
use cawide_protocol::types::{GitDiscardScope, GitError, GitErrorKind, GitLfsState, GitUndoItem};
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

fn invalid_arg(msg: impl Into<String>) -> GitError {
    GitError {
        kind: GitErrorKind::InvalidArgument,
        message: msg.into(),
        host: None,
        port: None,
    }
}

pub async fn stage_paths(engine: &GitEngine, paths: &[String]) -> Result<(), GitError> {
    if paths.is_empty() {
        return Ok(());
    }
    validate_paths(paths)?;

    let lfs_state = super::lfs::lfs_state(engine).await?;
    if lfs_state == GitLfsState::Unavailable && super::lfs::check_paths_lfs(engine, paths).await? {
        return Err(GitError {
            kind: GitErrorKind::LfsUnavailable,
            message: "Git LFS is not configured or unavailable on this system".into(),
            host: None,
            port: None,
        });
    }

    let mut rels = Vec::new();
    for p in paths {
        let rel = engine.validate_and_relativize(p).map_err(invalid_arg)?;
        rels.push(rel);
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mut stdin_bytes = Vec::new();
    for r in &rels {
        stdin_bytes.extend_from_slice(r.as_bytes());
        stdin_bytes.push(0);
    }

    let cmd = engine.git_cmd(
        &ctx,
        &["add", "-A", "--pathspec-from-file=-", "--pathspec-file-nul"],
    );

    let out = run(
        cmd,
        RunOpts {
            stdin: Some(&stdin_bytes),
            stdout_cap: 1024,
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

    if !out.status.success() {
        return Err(GitError {
            kind: GitErrorKind::Other,
            message: String::from_utf8_lossy(&out.stderr).to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(())
}

pub async fn unstage_paths(engine: &GitEngine, paths: &[String]) -> Result<(), GitError> {
    if paths.is_empty() {
        return Ok(());
    }
    validate_paths(paths)?;

    let lfs_state = super::lfs::lfs_state(engine).await?;
    if lfs_state == GitLfsState::Unavailable && super::lfs::check_paths_lfs(engine, paths).await? {
        return Err(GitError {
            kind: GitErrorKind::LfsUnavailable,
            message: "Git LFS is not configured or unavailable on this system".into(),
            host: None,
            port: None,
        });
    }

    let mut rels = Vec::new();
    for p in paths {
        let rel = engine.validate_and_relativize(p).map_err(invalid_arg)?;
        rels.push(rel);
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mut stdin_bytes = Vec::new();
    for r in &rels {
        stdin_bytes.extend_from_slice(r.as_bytes());
        stdin_bytes.push(0);
    }

    let has_head = engine.has_head(&ctx).await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = if has_head {
        engine.git_cmd(
            &ctx,
            &[
                "restore",
                "--staged",
                "--pathspec-from-file=-",
                "--pathspec-file-nul",
            ],
        )
    } else {
        engine.git_cmd(
            &ctx,
            &[
                "rm",
                "-r",
                "-f",
                "-q",
                "--cached",
                "--pathspec-from-file=-",
                "--pathspec-file-nul",
            ],
        )
    };

    let out = run(
        cmd,
        RunOpts {
            stdin: Some(&stdin_bytes),
            stdout_cap: 1024,
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

    if !out.status.success() {
        return Err(GitError {
            kind: GitErrorKind::Other,
            message: String::from_utf8_lossy(&out.stderr).to_string(),
            host: None,
            port: None,
        });
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(())
}

pub async fn discard(
    engine: &GitEngine,
    paths: &[String],
    scope: GitDiscardScope,
) -> Result<Vec<GitUndoItem>, GitError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    validate_paths(paths)?;

    for p in paths {
        let path_in_root = engine.root().join(p);
        if std::fs::symlink_metadata(&path_in_root)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(invalid_arg("cannot discard symlink"));
        }
    }

    let lfs_state = super::lfs::lfs_state(engine).await?;
    if lfs_state == GitLfsState::Unavailable && super::lfs::check_paths_lfs(engine, paths).await? {
        return Err(GitError {
            kind: GitErrorKind::LfsUnavailable,
            message: "Git LFS is not configured or unavailable on this system".into(),
            host: None,
            port: None,
        });
    }

    let mut rels = Vec::with_capacity(paths.len());
    for p in paths {
        rels.push(engine.validate_and_relativize(p).map_err(invalid_arg)?);
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    // Back up existing regular files in ONE process
    let mut backup_paths = Vec::new();
    let mut executable_map = HashMap::new();
    for (orig_p, rel) in paths.iter().zip(rels.iter()) {
        let full = engine.root().join(rel);
        if let Ok(meta) = full.metadata() {
            if meta.is_file() {
                backup_paths.push(rel.clone());
                #[cfg(unix)]
                let is_exec = meta.permissions().mode() & 0o111 != 0;
                #[cfg(not(unix))]
                let is_exec = false;
                executable_map.insert(orig_p.clone(), is_exec);
            }
        }
    }

    let mut blob_oid_map = HashMap::new();
    if !backup_paths.is_empty() {
        let mut stdin_bytes = Vec::new();
        for p in &backup_paths {
            stdin_bytes.extend_from_slice(p.as_bytes());
            stdin_bytes.push(b'\n');
        }

        let hash_cmd = engine.git_cmd(
            &ctx,
            &["hash-object", "--no-filters", "-w", "--stdin-paths"],
        );
        let out = run(
            hash_cmd,
            RunOpts {
                stdin: Some(&stdin_bytes),
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

        if !out.status.success() {
            return Err(GitError {
                kind: GitErrorKind::Other,
                message: String::from_utf8_lossy(&out.stderr).to_string(),
                host: None,
                port: None,
            });
        }

        let oids: Vec<&str> = std::str::from_utf8(&out.stdout)
            .map_err(|e| invalid_arg(e.to_string()))?
            .lines()
            .collect();

        for (rel, oid) in backup_paths.iter().zip(oids.iter()) {
            blob_oid_map.insert(rel.clone(), oid.trim().to_string());
        }
    }

    let mut undo_items = Vec::with_capacity(paths.len());
    for (orig_p, rel) in paths.iter().zip(rels.iter()) {
        let blob_oid = blob_oid_map.get(rel).cloned();
        let executable = executable_map.get(orig_p).copied().unwrap_or(false);
        undo_items.push(GitUndoItem {
            path: orig_p.clone(),
            blob_oid,
            executable,
        });
    }

    // Now execute discard according to scope
    let mut stdin_nul_bytes = Vec::new();
    for r in &rels {
        stdin_nul_bytes.extend_from_slice(r.as_bytes());
        stdin_nul_bytes.push(0);
    }

    match scope {
        GitDiscardScope::Unstaged => {
            let mut check_stdin = Vec::new();
            for r in &rels {
                check_stdin.extend_from_slice(format!(":{r}\n").as_bytes());
            }
            let check_cmd = engine.git_cmd(&ctx, &["cat-file", "--batch-check"]);
            let check_out = run(
                check_cmd,
                RunOpts {
                    stdin: Some(&check_stdin),
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

            let check_lines: Vec<&str> = std::str::from_utf8(&check_out.stdout)
                .unwrap_or("")
                .lines()
                .collect();

            let mut tracked_bytes = Vec::new();
            for (r, line) in rels.iter().zip(check_lines.iter()) {
                if !line.ends_with("missing") {
                    tracked_bytes.extend_from_slice(r.as_bytes());
                    tracked_bytes.push(0);
                } else {
                    let target = engine.root().join(r);
                    let _ = tokio::fs::remove_file(&target).await;
                }
            }

            if !tracked_bytes.is_empty() {
                let restore_cmd = engine.git_cmd(
                    &ctx,
                    &[
                        "restore",
                        "--worktree",
                        "--pathspec-from-file=-",
                        "--pathspec-file-nul",
                    ],
                );
                let _ = run(
                    restore_cmd,
                    RunOpts {
                        stdin: Some(&tracked_bytes),
                        stdout_cap: 1024,
                        timeout: Duration::from_secs(60),
                    },
                )
                .await;
            }
        }
        GitDiscardScope::All => {
            let has_head = engine.has_head(&ctx).await.unwrap_or(false);
            if has_head {
                // Split paths using cat-file --batch-check
                let mut check_stdin = Vec::new();
                for r in &rels {
                    check_stdin.extend_from_slice(format!("HEAD:{r}\n").as_bytes());
                }
                let check_cmd = engine.git_cmd(&ctx, &["cat-file", "--batch-check"]);
                let check_out = run(
                    check_cmd,
                    RunOpts {
                        stdin: Some(&check_stdin),
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

                let check_lines: Vec<&str> = std::str::from_utf8(&check_out.stdout)
                    .unwrap_or("")
                    .lines()
                    .collect();

                let mut in_head_bytes = Vec::new();
                let mut not_in_head_bytes = Vec::new();

                for (r, line) in rels.iter().zip(check_lines.iter()) {
                    if line.ends_with("missing") {
                        not_in_head_bytes.extend_from_slice(r.as_bytes());
                        not_in_head_bytes.push(0);
                    } else {
                        in_head_bytes.extend_from_slice(r.as_bytes());
                        in_head_bytes.push(0);
                    }
                }

                if !in_head_bytes.is_empty() {
                    let restore_cmd = engine.git_cmd(
                        &ctx,
                        &[
                            "restore",
                            "--staged",
                            "--worktree",
                            "--source=HEAD",
                            "--pathspec-from-file=-",
                            "--pathspec-file-nul",
                        ],
                    );
                    let _ = run(
                        restore_cmd,
                        RunOpts {
                            stdin: Some(&in_head_bytes),
                            stdout_cap: 1024,
                            timeout: Duration::from_secs(60),
                        },
                    )
                    .await;
                }

                if !not_in_head_bytes.is_empty() {
                    let rm_cmd = engine.git_cmd(
                        &ctx,
                        &[
                            "rm",
                            "-f",
                            "-q",
                            "--cached",
                            "--ignore-unmatch",
                            "--pathspec-from-file=-",
                            "--pathspec-file-nul",
                        ],
                    );
                    let _ = run(
                        rm_cmd,
                        RunOpts {
                            stdin: Some(&not_in_head_bytes),
                            stdout_cap: 1024,
                            timeout: Duration::from_secs(60),
                        },
                    )
                    .await;
                }

                // In-process removal for not-in-head files
                for (r, line) in rels.iter().zip(check_lines.iter()) {
                    if line.ends_with("missing") {
                        let target = engine.root().join(r);
                        let _ = tokio::fs::remove_file(&target).await;
                    }
                }
            } else {
                // Unborn HEAD: remove from index then remove from disk
                let rm_cmd = engine.git_cmd(
                    &ctx,
                    &[
                        "rm",
                        "-f",
                        "-q",
                        "--cached",
                        "--ignore-unmatch",
                        "--pathspec-from-file=-",
                        "--pathspec-file-nul",
                    ],
                );
                let _ = run(
                    rm_cmd,
                    RunOpts {
                        stdin: Some(&stdin_nul_bytes),
                        stdout_cap: 1024,
                        timeout: Duration::from_secs(60),
                    },
                )
                .await;

                for r in &rels {
                    let target = engine.root().join(r);
                    let _ = tokio::fs::remove_file(&target).await;
                }
            }
        }
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(undo_items)
}

pub async fn restore_blobs(engine: &GitEngine, items: &[GitUndoItem]) -> Result<(), GitError> {
    if items.is_empty() {
        return Ok(());
    }

    let paths: Vec<String> = items.iter().map(|i| i.path.clone()).collect();
    validate_paths(&paths)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    for item in items {
        let rel = engine
            .validate_and_relativize(&item.path)
            .map_err(invalid_arg)?;
        let target = engine.root().join(&rel);

        if let Some(oid) = &item.blob_oid {
            super::validate::validate_oid(oid)?;

            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| GitError {
                        kind: GitErrorKind::Other,
                        message: format!("create parent dirs: {e}"),
                        host: None,
                        port: None,
                    })?;
            }

            let rnd = rand::random::<u64>();
            let tmp_path = target.with_file_name(format!(".tmp_restore_{rnd}"));
            let mut tmp_file = tokio::fs::File::create(&tmp_path)
                .await
                .map_err(|e| GitError {
                    kind: GitErrorKind::Other,
                    message: format!("create tmp file: {e}"),
                    host: None,
                    port: None,
                })?;

            let cmd = engine.git_cmd(&ctx, &["cat-file", "blob", oid]);
            let (status, stderr) = run_to_writer(cmd, &mut tmp_file, Duration::from_secs(60))
                .await
                .map_err(|e| GitError {
                    kind: GitErrorKind::Other,
                    message: e.to_string(),
                    host: None,
                    port: None,
                })?;

            if !status.success() {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(GitError {
                    kind: GitErrorKind::Other,
                    message: String::from_utf8_lossy(&stderr).to_string(),
                    host: None,
                    port: None,
                });
            }

            #[cfg(unix)]
            {
                let mode = if item.executable { 0o755 } else { 0o644 };
                let _ =
                    tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))
                        .await;
            }
            tokio::fs::rename(&tmp_path, &target)
                .await
                .map_err(|e| GitError {
                    kind: GitErrorKind::Other,
                    message: format!("rename restored file: {e}"),
                    host: None,
                    port: None,
                })?;
        } else if target.exists() {
            let _ = tokio::fs::remove_file(&target).await;
        }
    }

    super::lfs::invalidate_lfs_cache(engine.root());
    Ok(())
}
