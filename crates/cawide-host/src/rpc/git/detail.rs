use super::{log::parse_ref_decorations, validate::validate_oid, GitEngine};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{
    GitChange, GitCommitDetail, GitCommitFile, GitError, GitErrorKind, GitLineStats,
    MAX_COMMIT_FILES,
};
use std::collections::HashMap;
use std::time::Duration;

pub async fn commit_detail(engine: &GitEngine, oid: &str) -> Result<GitCommitDetail, GitError> {
    validate_oid(oid)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let header_cmd = engine.git_cmd(
        &ctx,
        &[
            "log",
            "-n",
            "1",
            "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%cn%x1f%ce%x1f%ct%x1f%s%x1f%B%x1f%D",
            "-z",
            oid,
        ],
    );

    let out = run(
        header_cmd,
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

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = stdout_str.split('\x1f').collect();
    if fields.len() < 11 {
        return Err(GitError {
            kind: GitErrorKind::Other,
            message: "unexpected git log format".into(),
            host: None,
            port: None,
        });
    }

    let parsed_oid = fields[0].trim().to_string();
    let parents: Vec<String> = fields[1].split_whitespace().map(str::to_string).collect();
    let author_name = fields[2].to_string();
    let author_email = fields[3].to_string();
    let author_time = fields[4].parse::<i64>().unwrap_or(0);
    let committer_name = fields[5].to_string();
    let committer_email = fields[6].to_string();
    let commit_time = fields[7].parse::<i64>().unwrap_or(0);
    let subject = fields[8].to_string();
    let body = fields[9].to_string();
    let decor_str = fields[10].trim_end_matches('\0');
    let refs = parse_ref_decorations(decor_str);

    // Fetch file list with status and numstat
    let (name_status_args, numstat_args) = if let Some(parent) = parents.first() {
        (
            vec![
                "diff-tree",
                "-r",
                "--no-commit-id",
                "--name-status",
                "-M",
                "-z",
                parent.as_str(),
                oid,
            ],
            vec![
                "diff-tree",
                "-r",
                "--no-commit-id",
                "--numstat",
                "-M",
                "-z",
                parent.as_str(),
                oid,
            ],
        )
    } else {
        (
            vec![
                "diff-tree",
                "--root",
                "-r",
                "--no-commit-id",
                "--name-status",
                "-M",
                "-z",
                oid,
            ],
            vec![
                "diff-tree",
                "--root",
                "-r",
                "--no-commit-id",
                "--numstat",
                "-M",
                "-z",
                oid,
            ],
        )
    };

    let name_status_out = run(
        engine.git_cmd(&ctx, &name_status_args),
        RunOpts {
            stdin: None,
            stdout_cap: 16 * 1024 * 1024,
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
    if !name_status_out.status.success() {
        let stderr = String::from_utf8_lossy(&name_status_out.stderr);
        let kind = super::errors::classify(&stderr, Some(name_status_out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    let numstat_out = run(
        engine.git_cmd(&ctx, &numstat_args),
        RunOpts {
            stdin: None,
            stdout_cap: 16 * 1024 * 1024,
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
    if !numstat_out.status.success() {
        let stderr = String::from_utf8_lossy(&numstat_out.stderr);
        let kind = super::errors::classify(&stderr, Some(numstat_out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    // Parse numstat into map of path -> GitLineStats
    let mut stats_map: HashMap<String, GitLineStats> = HashMap::new();
    let mut numstat_parts = numstat_out.stdout.split(|&b| b == 0);
    while let Some(part) = numstat_parts.next() {
        if part.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(part);
        let cols: Vec<&str> = s.split('\t').collect();
        if cols.len() >= 3 {
            let add_str = cols[0];
            let del_str = cols[1];
            let path = cols[2];

            let (binary, additions, deletions) = if add_str == "-" && del_str == "-" {
                (true, 0, 0)
            } else {
                (
                    false,
                    add_str.parse::<u32>().unwrap_or(0),
                    del_str.parse::<u32>().unwrap_or(0),
                )
            };

            let final_path = if path.is_empty() {
                // Rename in -z numstat: next two parts are old_path, new_path
                let _old_p = numstat_parts.next().map(String::from_utf8_lossy);
                let new_p = numstat_parts.next().map(String::from_utf8_lossy);
                new_p.map(|p| p.to_string()).unwrap_or_default()
            } else {
                path.to_string()
            };

            if !final_path.is_empty() {
                stats_map.insert(
                    final_path,
                    GitLineStats {
                        additions,
                        deletions,
                        binary,
                    },
                );
            }
        }
    }

    // Parse name-status
    let mut files = Vec::new();
    let mut files_truncated = false;
    let mut status_parts = name_status_out.stdout.split(|&b| b == 0);

    while let Some(status_field) = status_parts.next() {
        if status_field.is_empty() {
            continue;
        }
        let status_str = String::from_utf8_lossy(status_field);
        let first_char = status_str.chars().next().unwrap_or('M');

        let (change, old_path, path) = match first_char {
            'A' => {
                let p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                (GitChange::Added, None, p)
            }
            'D' => {
                let p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                (GitChange::Deleted, None, p)
            }
            'R' => {
                let old_p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                let new_p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                (GitChange::Renamed, Some(old_p), new_p)
            }
            'C' => {
                let old_p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                let new_p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                (GitChange::Copied, Some(old_p), new_p)
            }
            'T' => {
                let p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                (GitChange::TypeChanged, None, p)
            }
            _ => {
                let p = status_parts
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                (GitChange::Modified, None, p)
            }
        };

        if files.len() < MAX_COMMIT_FILES {
            let stats = stats_map.remove(&path).unwrap_or(GitLineStats {
                additions: 0,
                deletions: 0,
                binary: false,
            });
            files.push(GitCommitFile {
                path,
                old_path,
                change,
                stats,
            });
        } else {
            files_truncated = true;
            break;
        }
    }

    Ok(GitCommitDetail {
        oid: parsed_oid,
        parents,
        author_name,
        author_email,
        author_time,
        committer_name,
        committer_email,
        commit_time,
        subject,
        body,
        refs,
        files,
        files_truncated,
    })
}
