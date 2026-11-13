use super::GitEngine;
use crate::rpc::process::run_records;
use cawide_protocol::types::{
    GitChange, GitConflictKind, GitError, GitErrorKind, GitHead, GitLfsState, GitLineStats,
    GitOperation, GitRepoStatus, GitStatusEntry, GitUpstream, MAX_STATUS_ENTRIES,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn char_to_change(c: char) -> GitChange {
    match c {
        'M' => GitChange::Modified,
        'A' => GitChange::Added,
        'D' => GitChange::Deleted,
        'R' => GitChange::Renamed,
        'C' => GitChange::Copied,
        'T' => GitChange::TypeChanged,
        '?' => GitChange::Untracked,
        _ => GitChange::Unmodified,
    }
}

pub struct StatusCollector {
    head_oid: String,
    head_name: Option<String>,
    is_detached: bool,
    upstream_name: Option<String>,
    ahead: u32,
    behind: u32,
    has_ab: bool,
    stash_count: u32,
    entries: Vec<GitStatusEntry>,
    total_entries: u32,
    entries_truncated: bool,
    expecting_orig_path_for: Option<usize>,
    ignore_next_orig_path: bool,
}

impl StatusCollector {
    pub fn new() -> Self {
        Self {
            head_oid: String::new(),
            head_name: None,
            is_detached: false,
            upstream_name: None,
            ahead: 0,
            behind: 0,
            has_ab: false,
            stash_count: 0,
            entries: Vec::new(),
            total_entries: 0,
            entries_truncated: false,
            expecting_orig_path_for: None,
            ignore_next_orig_path: false,
        }
    }

    pub fn handle_record(&mut self, rec: &[u8]) {
        if self.ignore_next_orig_path {
            self.ignore_next_orig_path = false;
            return;
        }

        if let Some(idx) = self.expecting_orig_path_for.take() {
            if let Some(entry) = self.entries.get_mut(idx) {
                entry.orig_path = Some(String::from_utf8_lossy(rec).to_string());
            }
            return;
        }

        if rec.is_empty() {
            return;
        }

        let s = String::from_utf8_lossy(rec);

        if let Some(oid) = s.strip_prefix("# branch.oid ") {
            self.head_oid = oid.trim().to_string();
            return;
        }
        if let Some(h) = s.strip_prefix("# branch.head ") {
            let h = h.trim();
            if h == "(detached)" {
                self.is_detached = true;
                self.head_name = None;
            } else {
                self.head_name = Some(h.to_string());
            }
            return;
        }
        if let Some(u) = s.strip_prefix("# branch.upstream ") {
            self.upstream_name = Some(u.trim().to_string());
            return;
        }
        if let Some(ab) = s.strip_prefix("# branch.ab ") {
            let mut parts = ab.split_whitespace();
            if let Some(a_str) = parts.next().and_then(|p| p.strip_prefix('+')) {
                self.ahead = a_str.parse().unwrap_or(0);
            }
            if let Some(b_str) = parts.next().and_then(|p| p.strip_prefix('-')) {
                self.behind = b_str.parse().unwrap_or(0);
            }
            self.has_ab = true;
            return;
        }
        if let Some(st) = s.strip_prefix("# stash ") {
            self.stash_count = st.trim().parse().unwrap_or(0);
            return;
        }

        if let Some(path) = s.strip_prefix("? ") {
            self.total_entries += 1;
            if self.entries.len() < MAX_STATUS_ENTRIES {
                self.entries.push(GitStatusEntry {
                    path: path.to_string(),
                    orig_path: None,
                    index: GitChange::Unmodified,
                    worktree: GitChange::Untracked,
                    conflict: None,
                    staged_stats: None,
                    unstaged_stats: None,
                });
            } else {
                self.entries_truncated = true;
            }
            return;
        }

        match rec.first() {
            Some(b'1') => {
                self.total_entries += 1;
                let mut it = s.splitn(9, ' ');
                if let (Some(xy), Some(path)) = (it.nth(1), it.nth(6)) {
                    if self.entries.len() < MAX_STATUS_ENTRIES {
                        let mut chars = xy.chars();
                        let x = chars.next().unwrap_or('.');
                        let y = chars.next().unwrap_or('.');
                        self.entries.push(GitStatusEntry {
                            path: path.to_string(),
                            orig_path: None,
                            index: char_to_change(x),
                            worktree: char_to_change(y),
                            conflict: None,
                            staged_stats: None,
                            unstaged_stats: None,
                        });
                    } else {
                        self.entries_truncated = true;
                    }
                }
            }
            Some(b'2') => {
                self.total_entries += 1;
                let mut it = s.splitn(10, ' ');
                if let (Some(xy), Some(path)) = (it.nth(1), it.nth(7)) {
                    if self.entries.len() < MAX_STATUS_ENTRIES {
                        let mut chars = xy.chars();
                        let x = chars.next().unwrap_or('.');
                        let y = chars.next().unwrap_or('.');
                        self.entries.push(GitStatusEntry {
                            path: path.to_string(),
                            orig_path: None,
                            index: char_to_change(x),
                            worktree: char_to_change(y),
                            conflict: None,
                            staged_stats: None,
                            unstaged_stats: None,
                        });
                        self.expecting_orig_path_for = Some(self.entries.len() - 1);
                    } else {
                        self.entries_truncated = true;
                        self.ignore_next_orig_path = true;
                    }
                }
            }
            Some(b'u') => {
                self.total_entries += 1;
                let mut it = s.splitn(11, ' ');
                if let (Some(xy), Some(path)) = (it.nth(1), it.nth(8)) {
                    if self.entries.len() < MAX_STATUS_ENTRIES {
                        let conflict = match xy {
                            "DD" => Some(GitConflictKind::BothDeleted),
                            "AU" => Some(GitConflictKind::AddedByUs),
                            "UD" => Some(GitConflictKind::DeletedByThem),
                            "UA" => Some(GitConflictKind::AddedByThem),
                            "DU" => Some(GitConflictKind::DeletedByUs),
                            "AA" => Some(GitConflictKind::BothAdded),
                            "UU" => Some(GitConflictKind::BothModified),
                            _ => Some(GitConflictKind::BothModified),
                        };
                        self.entries.push(GitStatusEntry {
                            path: path.to_string(),
                            orig_path: None,
                            index: GitChange::Unmodified,
                            worktree: GitChange::Unmodified,
                            conflict,
                            staged_stats: None,
                            unstaged_stats: None,
                        });
                    } else {
                        self.entries_truncated = true;
                    }
                }
            }
            _ => {}
        }
    }

    pub fn finish(self, operation: Option<GitOperation>, lfs: GitLfsState) -> GitRepoStatus {
        let head = if self.is_detached {
            GitHead::Detached { oid: self.head_oid }
        } else {
            let name = self.head_name.unwrap_or_else(|| "HEAD".to_string());
            let oid = if self.head_oid.is_empty()
                || self.head_oid == "(initial)"
                || self.head_oid.chars().all(|c| c == '0')
            {
                None
            } else {
                Some(self.head_oid)
            };
            GitHead::Branch { name, oid }
        };

        let upstream = self.upstream_name.map(|name| GitUpstream {
            name,
            ahead: self.ahead,
            behind: self.behind,
            gone: !self.has_ab,
        });

        GitRepoStatus {
            head,
            upstream,
            entries: self.entries,
            entries_truncated: self.entries_truncated,
            total_entries: self.total_entries,
            operation,
            stash_count: self.stash_count,
            lfs,
        }
    }
}

impl Default for StatusCollector {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn collect_status(engine: &GitEngine) -> Result<GitRepoStatus, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(
        &ctx,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--branch",
            "--show-stash",
            "--untracked-files=all",
        ],
    );

    let mut collector = StatusCollector::new();
    let status_res = run_records(cmd, None, 0, Duration::from_secs(60), |rec| {
        collector.handle_record(rec);
    })
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    if !status_res.success() {
        return Err(GitError {
            kind: GitErrorKind::Other,
            message: "git status failed".into(),
            host: None,
            port: None,
        });
    }

    // Attach stats if total_entries <= 1000
    let has_unstaged = collector
        .entries
        .iter()
        .any(|e| e.worktree != GitChange::Unmodified && e.worktree != GitChange::Untracked);
    let has_staged = collector
        .entries
        .iter()
        .any(|e| e.index != GitChange::Unmodified);

    let (unstaged_stats, staged_stats, operation) =
        if collector.total_entries <= 1000 && !collector.entries.is_empty() {
            let unstaged_fut = async {
                if has_unstaged {
                    collect_numstats(engine, &ctx, false).await
                } else {
                    HashMap::new()
                }
            };
            let staged_fut = async {
                if has_staged {
                    collect_numstats(engine, &ctx, true).await
                } else {
                    HashMap::new()
                }
            };
            let op_fut = detect_operation(engine);
            tokio::join!(unstaged_fut, staged_fut, op_fut)
        } else {
            let op = detect_operation(engine).await;
            (HashMap::new(), HashMap::new(), op)
        };

    if !unstaged_stats.is_empty() || !staged_stats.is_empty() {
        for entry in &mut collector.entries {
            entry.unstaged_stats = unstaged_stats.get(&entry.path).cloned();
            entry.staged_stats = staged_stats.get(&entry.path).cloned();
        }
    }

    let lfs = ctx.lfs_state;
    Ok(collector.finish(operation, lfs))
}

async fn collect_numstats(
    engine: &GitEngine,
    ctx: &super::GitRequestCtx,
    staged: bool,
) -> HashMap<String, GitLineStats> {
    let mut args = vec!["diff", "--numstat", "-z"];
    if staged {
        args.push("--cached");
        args.push("-M");
    }
    let cmd = engine.git_cmd(ctx, &args);
    let mut stats = HashMap::new();
    let mut pending_rename_stats: Option<(u32, u32, bool)> = None;
    let mut expecting_new_path_for: Option<GitLineStats> = None;

    let _ = run_records(cmd, None, 0, Duration::from_secs(30), |rec| {
        if let Some(line_stats) = expecting_new_path_for.take() {
            let path = String::from_utf8_lossy(rec).to_string();
            stats.insert(path, line_stats);
            return;
        }

        if let Some((add, del, bin)) = pending_rename_stats.take() {
            // This record is old_path
            expecting_new_path_for = Some(GitLineStats {
                additions: add,
                deletions: del,
                binary: bin,
            });
            return;
        }

        let s = String::from_utf8_lossy(rec);
        let mut parts = s.split('\t');
        if let (Some(adds_str), Some(dels_str), Some(path_or_empty)) =
            (parts.next(), parts.next(), parts.next())
        {
            let binary = adds_str == "-";
            let additions = adds_str.parse().unwrap_or(0);
            let deletions = dels_str.parse().unwrap_or(0);
            let line_stats = GitLineStats {
                additions,
                deletions,
                binary,
            };

            if path_or_empty.is_empty() {
                // Rename record follows: \0old\0new
                pending_rename_stats = Some((additions, deletions, binary));
            } else {
                stats.insert(path_or_empty.to_string(), line_stats);
            }
        }
    })
    .await;

    stats
}

async fn detect_operation(engine: &GitEngine) -> Option<GitOperation> {
    let git_dir = get_git_dir(engine).await?;

    if git_dir.join("MERGE_HEAD").exists() {
        let msg = tokio::fs::read(git_dir.join("MERGE_MSG"))
            .await
            .ok()
            .map(|b| {
                let len = b.len().min(8192);
                String::from_utf8_lossy(&b[..len]).to_string()
            });
        return Some(GitOperation::Merge { message: msg });
    }

    let rebase_merge = git_dir.join("rebase-merge");
    if rebase_merge.exists() {
        let step = read_file_num(&rebase_merge.join("msgnum")).await;
        let total = read_file_num(&rebase_merge.join("end")).await;
        let onto = tokio::fs::read_to_string(rebase_merge.join("onto"))
            .await
            .ok()
            .map(|s| s.trim().to_string());
        return Some(GitOperation::Rebase { step, total, onto });
    }

    let rebase_apply = git_dir.join("rebase-apply");
    if rebase_apply.exists() {
        let step = read_file_num(&rebase_apply.join("next")).await;
        let total = read_file_num(&rebase_apply.join("last")).await;
        return Some(GitOperation::Rebase {
            step,
            total,
            onto: None,
        });
    }

    if git_dir.join("CHERRY_PICK_HEAD").exists() {
        return Some(GitOperation::CherryPick);
    }

    if git_dir.join("REVERT_HEAD").exists() {
        return Some(GitOperation::Revert);
    }

    None
}

async fn read_file_num(path: &Path) -> Option<u32> {
    let s = tokio::fs::read_to_string(path).await.ok()?;
    s.trim().parse().ok()
}

pub(crate) async fn get_git_dir(engine: &GitEngine) -> Option<PathBuf> {
    if let Some(git_dir) = super::resolve_git_dir(engine.root()) {
        return Some(git_dir);
    }
    let mut cmd = engine.base_cmd();
    cmd.args(super::HARDENING_ARGS);
    cmd.args(["rev-parse", "--git-dir"]);
    let opts = crate::rpc::process::RunOpts {
        stdin: None,
        stdout_cap: 1024,
        timeout: Duration::from_secs(10),
    };
    let out = crate::rpc::process::run(cmd, opts).await.ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let path = PathBuf::from(p);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(engine.root().join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_porcelain_records() {
        let mut collector = StatusCollector::new();
        collector.handle_record(b"# branch.oid 1234567890abcdef1234567890abcdef12345678");
        collector.handle_record(b"# branch.head main");
        collector.handle_record(b"# branch.upstream origin/main");
        collector.handle_record(b"# branch.ab +2 -1");
        collector.handle_record(b"# stash 3");
        collector.handle_record(b"1 M. N... 100644 100644 100644 abc def modified.txt");
        collector.handle_record(b"1 .M N... 100644 100644 100644 abc def unstaged.txt");
        collector.handle_record(b"? untracked.txt");
        collector.handle_record(b"u UU N... 100644 100644 100644 100644 abc def ghi conflict.txt");

        let status = collector.finish(None, GitLfsState::NotUsed);
        assert_eq!(status.stash_count, 3);
        assert_eq!(status.total_entries, 4);
        assert!(!status.entries_truncated);
        match status.head {
            GitHead::Branch { name, oid } => {
                assert_eq!(name, "main");
                assert_eq!(
                    oid,
                    Some("1234567890abcdef1234567890abcdef12345678".to_string())
                );
            }
            _ => panic!("expected branch"),
        }
        let u = status.upstream.unwrap();
        assert_eq!(u.name, "origin/main");
        assert_eq!(u.ahead, 2);
        assert_eq!(u.behind, 1);
        assert!(!u.gone);
    }

    #[test]
    fn test_large_stream_truncation() {
        let mut collector = StatusCollector::new();
        collector.handle_record(b"# branch.head main");
        for i in 0..10_000 {
            let rec = format!("? file_{i}.txt");
            collector.handle_record(rec.as_bytes());
        }
        let status = collector.finish(None, GitLfsState::NotUsed);
        assert_eq!(status.entries.len(), MAX_STATUS_ENTRIES);
        assert_eq!(status.total_entries, 10_000);
        assert!(status.entries_truncated);
    }
}
