use super::{diff::parse_unified_diff, validate::validate_paths, GitEngine};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{
    GitError, GitErrorKind, GitPatchAction, GitPatchRequest, GitPatchSource, GitUndoItem,
};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchDirection {
    Forward,
    Reverse,
}

fn invalid_arg(msg: impl Into<String>) -> GitError {
    GitError {
        kind: GitErrorKind::InvalidArgument,
        message: msg.into(),
        host: None,
        port: None,
    }
}

pub fn build_patch(
    file_header: &str,
    raw_hunk_lines: &[&str],
    selected_indices: Option<&BTreeSet<u32>>,
    direction: PatchDirection,
) -> Result<String, GitError> {
    if raw_hunk_lines.is_empty() {
        return Err(invalid_arg("empty hunk lines"));
    }
    let header_line = raw_hunk_lines[0];
    if !header_line.starts_with("@@ ") {
        return Err(invalid_arg("invalid hunk header"));
    }

    let after_at = &header_line[3..];
    let end_at = after_at
        .find(" @@")
        .ok_or_else(|| invalid_arg("invalid hunk header format"))?;
    let ranges_str = &after_at[..end_at];
    let suffix = &after_at[end_at + 3..];

    let (old_range_str, new_range_str) = ranges_str
        .split_once(' ')
        .ok_or_else(|| invalid_arg("malformed ranges in header"))?;
    let old_start: u32 = old_range_str
        .strip_prefix('-')
        .and_then(|r| r.split_once(',').map(|(s, _)| s).unwrap_or(r).parse().ok())
        .ok_or_else(|| invalid_arg("invalid old start"))?;
    let new_start: u32 = new_range_str
        .strip_prefix('+')
        .and_then(|r| r.split_once(',').map(|(s, _)| s).unwrap_or(r).parse().ok())
        .ok_or_else(|| invalid_arg("invalid new start"))?;

    let mut parsed_idx = 0u32;
    let mut emitted_lines: Vec<String> = Vec::new();
    let mut selected_changes = 0u32;
    let mut prev_line_kept = false;

    for &line in &raw_hunk_lines[1..] {
        if line.starts_with('\\') {
            if prev_line_kept {
                emitted_lines.push(line.to_string());
            }
            continue;
        }

        let first = line.chars().next().unwrap_or(' ');
        let is_selected = selected_indices
            .map(|s| s.contains(&parsed_idx))
            .unwrap_or(true);
        parsed_idx += 1;

        match first {
            ' ' => {
                emitted_lines.push(line.to_string());
                prev_line_kept = true;
            }
            '+' => match direction {
                PatchDirection::Forward => {
                    if is_selected {
                        emitted_lines.push(line.to_string());
                        selected_changes += 1;
                        prev_line_kept = true;
                    } else {
                        prev_line_kept = false;
                    }
                }
                PatchDirection::Reverse => {
                    if is_selected {
                        emitted_lines.push(line.to_string());
                        selected_changes += 1;
                        prev_line_kept = true;
                    } else {
                        let mut converted = String::from(" ");
                        converted.push_str(&line[1..]);
                        emitted_lines.push(converted);
                        prev_line_kept = true;
                    }
                }
            },
            '-' => match direction {
                PatchDirection::Forward => {
                    if is_selected {
                        emitted_lines.push(line.to_string());
                        selected_changes += 1;
                        prev_line_kept = true;
                    } else {
                        let mut converted = String::from(" ");
                        converted.push_str(&line[1..]);
                        emitted_lines.push(converted);
                        prev_line_kept = true;
                    }
                }
                PatchDirection::Reverse => {
                    if is_selected {
                        emitted_lines.push(line.to_string());
                        selected_changes += 1;
                        prev_line_kept = true;
                    } else {
                        prev_line_kept = false;
                    }
                }
            },
            _ => {
                emitted_lines.push(line.to_string());
                prev_line_kept = true;
            }
        }
    }

    if selected_indices.is_some() && selected_changes == 0 {
        return Err(invalid_arg("no changed lines selected"));
    }

    let mut old_count = 0u32;
    let mut new_count = 0u32;
    for l in &emitted_lines {
        if l.starts_with(' ') {
            old_count += 1;
            new_count += 1;
        } else if l.starts_with('-') {
            old_count += 1;
        } else if l.starts_with('+') {
            new_count += 1;
        }
    }

    let new_header = format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@{suffix}");

    let mut patch = String::new();
    if !file_header.is_empty() {
        patch.push_str(file_header);
        if !file_header.ends_with('\n') {
            patch.push('\n');
        }
    }
    patch.push_str(&new_header);
    patch.push('\n');
    for l in emitted_lines {
        patch.push_str(&l);
        patch.push('\n');
    }
    Ok(patch)
}

pub async fn apply_patch(
    engine: &GitEngine,
    patch: GitPatchRequest,
) -> Result<Option<GitUndoItem>, GitError> {
    match (&patch.source, &patch.action) {
        (GitPatchSource::Unstaged, GitPatchAction::Stage)
        | (GitPatchSource::Unstaged, GitPatchAction::Discard)
        | (GitPatchSource::Staged, GitPatchAction::Unstage) => {}
        _ => {
            return Err(invalid_arg(
                "unsupported patch source and action combination",
            ));
        }
    }

    validate_paths(std::slice::from_ref(&patch.path))?;

    if super::lfs::check_paths_lfs(engine, std::slice::from_ref(&patch.path)).await? {
        return Err(invalid_arg("Stage the whole file (Git LFS)"));
    }

    let rel = engine
        .validate_and_relativize(&patch.path)
        .map_err(|e| invalid_arg(format!("invalid path: {e}")))?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let diff_args: Vec<&str> = match patch.source {
        GitPatchSource::Unstaged => vec![
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=3",
            "--",
            &rel,
        ],
        GitPatchSource::Staged => vec![
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--cached",
            "-M",
            "--unified=3",
            "--",
            &rel,
        ],
    };

    let diff_out = run(
        engine.git_cmd(&ctx, &diff_args),
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

    let diff_text = String::from_utf8_lossy(&diff_out.stdout);
    let hunks = parse_unified_diff(&diff_text);

    let hunk = hunks
        .get(patch.hunk_index as usize)
        .ok_or_else(|| GitError {
            kind: GitErrorKind::StaleDiff,
            message: "diff hunk is stale".into(),
            host: None,
            port: None,
        })?;

    if hunk.content_hash != patch.hunk_hash {
        return Err(GitError {
            kind: GitErrorKind::StaleDiff,
            message: "diff hunk is stale".into(),
            host: None,
            port: None,
        });
    }

    let (file_header, raw_hunk_lines) = extract_raw_hunk(&diff_text, patch.hunk_index as usize)
        .ok_or_else(|| GitError {
            kind: GitErrorKind::StaleDiff,
            message: "diff hunk lines missing".into(),
            host: None,
            port: None,
        })?;

    let selected = if patch.line_indices.is_empty() {
        None
    } else {
        Some(patch.line_indices.into_iter().collect::<BTreeSet<u32>>())
    };

    let direction = match (&patch.source, &patch.action) {
        (GitPatchSource::Unstaged, GitPatchAction::Stage) => PatchDirection::Forward,
        (GitPatchSource::Unstaged, GitPatchAction::Discard) => PatchDirection::Reverse,
        (GitPatchSource::Staged, GitPatchAction::Unstage) => PatchDirection::Reverse,
        _ => unreachable!(),
    };

    let patch_content = build_patch(&file_header, &raw_hunk_lines, selected.as_ref(), direction)?;

    match (&patch.source, &patch.action) {
        (GitPatchSource::Unstaged, GitPatchAction::Stage) => {
            let cmd = engine.git_cmd(
                &ctx,
                &["apply", "--cached", "--recount", "--whitespace=nowarn", "-"],
            );
            let out = run(
                cmd,
                RunOpts {
                    stdin: Some(patch_content.as_bytes()),
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
                return Err(GitError {
                    kind: GitErrorKind::Other,
                    message: String::from_utf8_lossy(&out.stderr).to_string(),
                    host: None,
                    port: None,
                });
            }
            Ok(None)
        }
        (GitPatchSource::Staged, GitPatchAction::Unstage) => {
            let cmd = engine.git_cmd(
                &ctx,
                &[
                    "apply",
                    "--cached",
                    "--reverse",
                    "--recount",
                    "--whitespace=nowarn",
                    "-",
                ],
            );
            let out = run(
                cmd,
                RunOpts {
                    stdin: Some(patch_content.as_bytes()),
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
                return Err(GitError {
                    kind: GitErrorKind::Other,
                    message: String::from_utf8_lossy(&out.stderr).to_string(),
                    host: None,
                    port: None,
                });
            }
            Ok(None)
        }
        (GitPatchSource::Unstaged, GitPatchAction::Discard) => {
            #[cfg(unix)]
            let executable = engine
                .root()
                .join(&rel)
                .metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            #[cfg(not(unix))]
            let executable = false;

            let hash_cmd = engine.git_cmd(&ctx, &["hash-object", "--no-filters", "-w", "--", &rel]);
            let hash_out = run(
                hash_cmd,
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
            if !hash_out.status.success() {
                return Err(GitError {
                    kind: GitErrorKind::Other,
                    message: format!(
                        "failed to backup file before discard: {}",
                        String::from_utf8_lossy(&hash_out.stderr).trim()
                    ),
                    host: None,
                    port: None,
                });
            }

            let blob_oid = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();

            let apply_cmd = engine.git_cmd(
                &ctx,
                &[
                    "apply",
                    "--reverse",
                    "--recount",
                    "--whitespace=nowarn",
                    "-",
                ],
            );
            let out = run(
                apply_cmd,
                RunOpts {
                    stdin: Some(patch_content.as_bytes()),
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
                return Err(GitError {
                    kind: GitErrorKind::Other,
                    message: String::from_utf8_lossy(&out.stderr).to_string(),
                    host: None,
                    port: None,
                });
            }

            Ok(Some(GitUndoItem {
                path: patch.path,
                blob_oid: Some(blob_oid),
                executable,
            }))
        }
        _ => unreachable!(),
    }
}

fn extract_raw_hunk(diff_text: &str, target_hunk_index: usize) -> Option<(String, Vec<&str>)> {
    let mut current_header = Vec::new();
    let mut current_hunk_idx = 0usize;
    let mut lines = diff_text.lines().peekable();

    while let Some(line) = lines.next() {
        if line.starts_with("diff --git ") {
            current_header.clear();
            current_header.push(line);
            while let Some(&next_line) = lines.peek() {
                if next_line.starts_with("@@ ") {
                    break;
                }
                current_header.push(lines.next().unwrap());
            }
        } else if line.starts_with("@@ ") {
            if current_hunk_idx == target_hunk_index {
                let mut hunk_lines = vec![line];
                while let Some(&next_line) = lines.peek() {
                    if next_line.starts_with("@@ ") || next_line.starts_with("diff --git ") {
                        break;
                    }
                    hunk_lines.push(lines.next().unwrap());
                }
                return Some((current_header.join("\n"), hunk_lines));
            }
            current_hunk_idx += 1;
        } else if current_hunk_idx == 0 {
            current_header.push(line);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_patch_forward_whole_hunk() {
        let file_header = "diff --git a/test.txt b/test.txt\n--- a/test.txt\n+++ b/test.txt\n";
        let raw_hunk = [
            "@@ -1,3 +1,3 @@ func()",
            " line1",
            "-old2",
            "+new2",
            " line3",
        ];
        let patch = build_patch(file_header, &raw_hunk, None, PatchDirection::Forward).unwrap();
        assert!(patch.starts_with(file_header));
        assert!(patch.contains("@@ -1,3 +1,3 @@ func()"));
        assert!(patch.contains("-old2\n+new2"));
    }

    #[test]
    fn test_build_patch_partial_selection() {
        let file_header = "diff --git a/test.txt b/test.txt\n--- a/test.txt\n+++ b/test.txt\n";
        let raw_hunk = ["@@ -1,3 +1,4 @@", " ctx1", "+add1", "+add2", " ctx2"];
        // Select only add1 (parsed index 1: ctx1 is 0, add1 is 1, add2 is 2, ctx2 is 3)
        let mut set = BTreeSet::new();
        set.insert(1);
        let patch =
            build_patch(file_header, &raw_hunk, Some(&set), PatchDirection::Forward).unwrap();
        // add2 should be dropped, so hunk is: ctx1, +add1, ctx2
        // old: 2 lines (ctx1, ctx2). new: 3 lines (ctx1, add1, ctx2)
        assert!(patch.contains("@@ -1,2 +1,3 @@"));
        assert!(patch.contains("+add1"));
        assert!(!patch.contains("+add2"));
    }
}
