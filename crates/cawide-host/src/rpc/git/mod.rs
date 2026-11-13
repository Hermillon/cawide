//! Hardened Git CLI engine (INV-GIT-001/002).
//!
//! Every invocation runs with repository-controlled code execution disabled:
//! hooks, fsmonitor, external diff/textconv, pagers, GPG signing, and every
//! configured `filter.<driver>` (neutralized per request via `GIT_CONFIG_COUNT`,
//! because `-c filter.*.clean=` wildcards are not supported by Git).

use cawide_protocol::types::{
    GitDiffTarget, GitFileDiff, GitLfsState, GitRepoStatus, MAX_DIFF_BYTES,
};
use env::GitHostEnv;
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;

use crate::rpc::jail::{resolve_jailed_path, ESCAPE};

pub mod branches;
pub mod commit;
pub mod detail;
pub mod diff;
pub mod dispatch;
pub mod env;
pub mod errors;
pub mod graph;
pub mod identity;
pub mod integrate;
pub mod lfs;
pub mod log;
pub mod network;
pub mod patch;
pub mod remote_url;
pub mod remotes;
pub mod staging;
pub mod stash;
pub mod status;
pub mod tags;
pub mod validate;

pub use diff::parse_unified_diff;

const GIT_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Hardening flags placed before every subcommand.
const HARDENING_ARGS: [&str; 26] = [
    "--no-pager",
    "--literal-pathspecs",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.filemode=false",
    "-c",
    "diff.external=",
    "-c",
    "commit.gpgSign=false",
    "-c",
    "tag.gpgSign=false",
    "-c",
    "core.quotePath=false",
    "-c",
    "color.ui=false",
    "-c",
    "core.askPass=",
    "-c",
    "credential.interactive=never",
    "-c",
    "protocol.ext.allow=never",
];
/// Inherited variables that would redirect Git or inject configuration.
const STRIPPED_ENV: [&str; 5] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_EXTERNAL_DIFF",
];
/// Filter driver always neutralized, even when not configured in this repo.
const DEFAULT_FILTER_DRIVERS: [&str; 1] = ["lfs"];
/// Upper bound on captured stderr (error messages only).
const MAX_STDERR_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct GitEngine {
    workspace_root: PathBuf,
    pub env: Arc<GitHostEnv>,
}

type RequestCtxCacheEntry = (Option<Vec<u8>>, GitLfsState, GitRequestCtx, Instant);
static REQUEST_CTX_CACHE: Mutex<Option<HashMap<PathBuf, RequestCtxCacheEntry>>> = Mutex::new(None);

pub(crate) fn resolve_git_dir(workspace_root: &Path) -> Option<PathBuf> {
    let dot_git = workspace_root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    if dot_git.is_file() {
        if let Ok(content) = std::fs::read_to_string(&dot_git) {
            if let Some(rest) = content.strip_prefix("gitdir:") {
                let gitdir_str = rest.trim();
                let path = Path::new(gitdir_str);
                let full = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    workspace_root.join(path)
                };
                if full.is_dir() {
                    return Some(full);
                }
            }
        }
    }
    None
}

pub(crate) fn read_git_config_bytes(workspace_root: &Path) -> Option<Vec<u8>> {
    let gitdir = resolve_git_dir(workspace_root)?;
    if let Ok(bytes) = std::fs::read(gitdir.join("config")) {
        return Some(bytes);
    }
    if let Ok(common) = std::fs::read_to_string(gitdir.join("commondir")) {
        let common_path = common.trim();
        let common_dir = if Path::new(common_path).is_absolute() {
            PathBuf::from(common_path)
        } else {
            gitdir.join(common_path)
        };
        return std::fs::read(common_dir.join("config")).ok();
    }
    None
}

/// Per-request environment neutralizing all configured filter drivers.
#[derive(Debug, Clone)]
pub(crate) struct GitRequestCtx {
    env_overrides: Vec<(String, String)>,
    pub(crate) lfs_state: GitLfsState,
}
struct GitOutput {
    status: ExitStatus,
    /// At most the requested cap.
    stdout: Vec<u8>,
    /// Full stdout length, including bytes beyond the cap.
    stdout_total: usize,
    stderr: Vec<u8>,
}

impl GitOutput {
    /// Git's message for a failed command (stderr, else stdout, e.g. "nothing to commit").
    fn error(&self) -> String {
        let msg = String::from_utf8_lossy(if self.stderr.is_empty() {
            &self.stdout
        } else {
            &self.stderr
        });
        let msg = msg.trim();
        if msg.is_empty() {
            format!("git failed: {}", self.status)
        } else {
            msg.to_string()
        }
    }

    fn ok(self) -> Result<Self, String> {
        if self.status.success() {
            Ok(self)
        } else {
            Err(self.error())
        }
    }
}

/// Runs `cmd`, optionally writing `stdin`, capturing stdout up to `stdout_cap`.
async fn run(cmd: Command, stdin: Option<&[u8]>, stdout_cap: usize) -> Result<GitOutput, String> {
    let opts = crate::rpc::process::RunOpts {
        stdin,
        stdout_cap,
        timeout: GIT_CMD_TIMEOUT,
    };
    let out = crate::rpc::process::run(cmd, opts)
        .await
        .map_err(|e| format!("failed to run git: {e}"))?;
    Ok(GitOutput {
        status: out.status,
        stdout: out.stdout,
        stdout_total: out.stdout_total,
        stderr: out.stderr,
    })
}

impl GitEngine {
    pub fn new(workspace_root: PathBuf, env: Arc<GitHostEnv>) -> Self {
        Self {
            workspace_root,
            env,
        }
    }

    pub fn root(&self) -> &Path {
        &self.workspace_root
    }

    fn base_cmd(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.workspace_root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_EDITOR", "true")
            .env("GIT_SEQUENCE_EDITOR", "true")
            .env("GIT_MERGE_AUTOEDIT", "no")
            .env("SSH_ASKPASS_REQUIRE", "never")
            .env("LC_MESSAGES", "C");
        for var in STRIPPED_ENV {
            cmd.env_remove(var);
        }
        for var in [
            "LC_ALL",
            "LANGUAGE",
            "SSH_ASKPASS",
            "GIT_ASKPASS",
            "GIT_SSH_COMMAND",
        ] {
            cmd.env_remove(var);
        }
        for (k, v) in &self.env.extra_env {
            cmd.env(k, v);
        }
        cmd
    }

    /// Discovers every configured filter driver (including via `include.path`) and
    /// overrides its commands to empty and `required` to false.
    pub(crate) async fn build_request_ctx(&self) -> Result<GitRequestCtx, String> {
        let root = self.workspace_root.clone();
        let config_bytes = read_git_config_bytes(&root);
        {
            let lock = REQUEST_CTX_CACHE.lock();
            if let Some(map) = lock.as_ref() {
                if let Some((cached_cfg, _, ctx, ts)) = map.get(&root) {
                    if ts.elapsed() < Duration::from_secs(30) && *cached_cfg == config_bytes {
                        return Ok(ctx.clone());
                    }
                }
            }
        }

        let lfs_state = lfs::lfs_state(self).await.unwrap_or(GitLfsState::NotUsed);

        let mut cmd = self.base_cmd();
        cmd.args([
            "--no-pager",
            "config",
            "--includes",
            "--null",
            "--name-only",
            "--get-regexp",
        ])
        .arg(r"^filter\.");
        // Exit 1 = no matching keys; any other failure resurfaces in the real command.
        let out = run(cmd, None, MAX_STDERR_BYTES).await?;
        let lfs_enabled = lfs_state == GitLfsState::Enabled;

        let mut drivers: BTreeSet<String> = DEFAULT_FILTER_DRIVERS
            .iter()
            .map(|d| d.to_string())
            .collect();
        for key in out.stdout.split(|&b| b == 0) {
            let key = String::from_utf8_lossy(key);
            // `filter.<driver>.<action>`; the driver name may itself contain dots.
            if let Some((driver, _action)) =
                key.strip_prefix("filter.").and_then(|r| r.rsplit_once('.'))
            {
                drivers.insert(driver.to_string());
            }
        }
        if lfs_enabled {
            drivers.remove("lfs");
        }

        let mut env_overrides = Vec::with_capacity(drivers.len() * 8 + 9);
        let mut count = 0usize;
        for driver in &drivers {
            for (action, value) in [
                ("clean", ""),
                ("smudge", ""),
                ("process", ""),
                ("required", "false"),
            ] {
                env_overrides.push((
                    format!("GIT_CONFIG_KEY_{count}"),
                    format!("filter.{driver}.{action}"),
                ));
                env_overrides.push((format!("GIT_CONFIG_VALUE_{count}"), value.to_string()));
                count += 1;
            }
        }
        if lfs_enabled {
            for (action, value) in [
                ("clean", "git-lfs clean -- %f"),
                ("smudge", "git-lfs smudge -- %f"),
                ("process", "git-lfs filter-process"),
                ("required", "true"),
            ] {
                env_overrides.push((
                    format!("GIT_CONFIG_KEY_{count}"),
                    format!("filter.lfs.{action}"),
                ));
                env_overrides.push((format!("GIT_CONFIG_VALUE_{count}"), value.to_string()));
                count += 1;
            }
        }
        env_overrides.push(("GIT_CONFIG_COUNT".to_string(), count.to_string()));
        let ctx = GitRequestCtx {
            env_overrides,
            lfs_state: lfs_state.clone(),
        };

        {
            let mut lock = REQUEST_CTX_CACHE.lock();
            let map = lock.get_or_insert_with(HashMap::new);
            map.insert(root, (config_bytes, lfs_state, ctx.clone(), Instant::now()));
        }

        Ok(ctx)
    }

    pub(crate) fn git_cmd<S: AsRef<std::ffi::OsStr>>(
        &self,
        ctx: &GitRequestCtx,
        args: &[S],
    ) -> Command {
        let mut cmd = self.base_cmd();
        cmd.args(HARDENING_ARGS).args(args);
        cmd.envs(ctx.env_overrides.iter().map(|(k, v)| (k, v)));
        cmd
    }

    /// Validates a client path and converts it to a workspace-relative pathspec.
    fn validate_and_relativize(&self, path_str: &str) -> Result<String, String> {
        if path_str.is_empty() {
            return Err("invalid path: empty".into());
        }
        if path_str.starts_with('-') {
            return Err("invalid path: leading '-'".into());
        }
        if path_str.starts_with(':') {
            return Err("invalid path: leading ':'".into());
        }
        let canonical = resolve_jailed_path(&self.workspace_root, path_str)?;
        let rel = canonical
            .strip_prefix(&self.workspace_root)
            .map_err(|_| ESCAPE.to_string())?;
        if rel.as_os_str().is_empty() {
            return Ok(".".into());
        }
        rel.to_str()
            .map(|s| s.replace('\\', "/"))
            .ok_or_else(|| "invalid path: not valid UTF-8".into())
    }

    async fn has_head(&self, ctx: &GitRequestCtx) -> Result<bool, String> {
        let out = run(
            self.git_cmd(ctx, &["rev-parse", "--verify", "-q", "HEAD"]),
            None,
            256,
        )
        .await?;
        Ok(out.status.success())
    }

    pub async fn status(&self) -> Result<GitRepoStatus, String> {
        status::collect_status(self).await.map_err(|e| e.message)
    }

    pub async fn diff_target(&self, target: &GitDiffTarget) -> Result<GitFileDiff, String> {
        let ctx = self.build_request_ctx().await?;
        const DIFF: [&str; 4] = ["diff", "--no-ext-diff", "--no-textconv", "--unified=3"];
        let diff_args = |staged: bool, tail: &[&str]| -> Vec<String> {
            let mut v = vec![DIFF[0]];
            if staged {
                v.push("--staged");
            }
            v.extend_from_slice(&DIFF[1..]);
            v.extend_from_slice(tail);
            v.into_iter().map(str::to_string).collect()
        };

        match target {
            GitDiffTarget::Unstaged { path } => {
                let rel = self.validate_and_relativize(path)?;
                let ls = run(
                    self.git_cmd(&ctx, &["ls-files", "--error-unmatch", "--", &rel]),
                    None,
                    0,
                )
                .await?;
                let out = if ls.status.success() {
                    self.run_diff(&ctx, &diff_args(false, &["--", &rel]))
                        .await?
                } else {
                    let meta = tokio::fs::metadata(self.workspace_root.join(&rel)).await;
                    if !meta.is_ok_and(|m| m.is_file()) {
                        return Err(format!("not a tracked path or regular file: {rel}"));
                    }
                    let args = diff_args(false, &["--no-index", "--", "/dev/null", &rel]);
                    let out = run(self.git_cmd(&ctx, &args), None, MAX_DIFF_BYTES).await?;
                    if out.status.code().is_some_and(|c| c > 1) || out.status.code().is_none() {
                        return Err(out.error());
                    }
                    out
                };
                let too_large = out.stdout_total > MAX_DIFF_BYTES;
                let hunks = if too_large {
                    Vec::new()
                } else {
                    parse_unified_diff(&String::from_utf8_lossy(&out.stdout))
                };
                Ok(GitFileDiff {
                    path: rel,
                    old_path: None,
                    binary: false,
                    too_large,
                    lfs: false,
                    total_bytes: out.stdout_total as u64,
                    hunks,
                })
            }
            GitDiffTarget::Staged { path } => {
                let rel = self.validate_and_relativize(path)?;
                let out = self.run_diff(&ctx, &diff_args(true, &["--", &rel])).await?;
                let too_large = out.stdout_total > MAX_DIFF_BYTES;
                let hunks = if too_large {
                    Vec::new()
                } else {
                    parse_unified_diff(&String::from_utf8_lossy(&out.stdout))
                };
                Ok(GitFileDiff {
                    path: rel,
                    old_path: None,
                    binary: false,
                    too_large,
                    lfs: false,
                    total_bytes: out.stdout_total as u64,
                    hunks,
                })
            }
            GitDiffTarget::Untracked { path } => {
                let rel = self.validate_and_relativize(path)?;
                let meta = tokio::fs::metadata(self.workspace_root.join(&rel)).await;
                if !meta.is_ok_and(|m| m.is_file()) {
                    return Err(format!("not a regular file: {rel}"));
                }
                let args = diff_args(false, &["--no-index", "--", "/dev/null", &rel]);
                let out = run(self.git_cmd(&ctx, &args), None, MAX_DIFF_BYTES).await?;
                if out.status.code().is_some_and(|c| c > 1) || out.status.code().is_none() {
                    return Err(out.error());
                }
                let too_large = out.stdout_total > MAX_DIFF_BYTES;
                let hunks = if too_large {
                    Vec::new()
                } else {
                    parse_unified_diff(&String::from_utf8_lossy(&out.stdout))
                };
                Ok(GitFileDiff {
                    path: rel,
                    old_path: None,
                    binary: false,
                    too_large,
                    lfs: false,
                    total_bytes: out.stdout_total as u64,
                    hunks,
                })
            }
            GitDiffTarget::Commit {
                oid,
                path,
                old_path,
            } => {
                crate::rpc::git::validate::validate_oid(oid).map_err(|e| e.message)?;
                let rel = self.validate_and_relativize(path)?;
                let rel_old = match old_path {
                    Some(op) => Some(self.validate_and_relativize(op)?),
                    None => None,
                };

                let parent_cmd = self.git_cmd(&ctx, &["rev-list", "--parents", "-n", "1", oid]);
                let parent_out = run(parent_cmd, None, 1024).await?.ok()?;
                let line = String::from_utf8_lossy(&parent_out.stdout);
                let parts: Vec<&str> = line.split_whitespace().collect();
                let out = if parts.len() > 1 {
                    let p0 = parts[1];
                    let mut args = vec![
                        "diff",
                        "--no-ext-diff",
                        "--no-textconv",
                        "-M",
                        "--unified=3",
                        p0,
                        oid,
                        "--",
                    ];
                    if let Some(ref o) = rel_old {
                        args.push(o);
                    }
                    args.push(&rel);
                    let args: Vec<String> = args.into_iter().map(str::to_string).collect();
                    self.run_diff(&ctx, &args).await?
                } else {
                    let mut args = vec![
                        "diff-tree",
                        "--root",
                        "-p",
                        "-M",
                        "--no-ext-diff",
                        "--no-textconv",
                        oid,
                        "--",
                    ];
                    if let Some(ref o) = rel_old {
                        args.push(o);
                    }
                    args.push(&rel);
                    let args: Vec<String> = args.into_iter().map(str::to_string).collect();
                    self.run_diff(&ctx, &args).await?
                };
                let too_large = out.stdout_total > MAX_DIFF_BYTES;
                let hunks = if too_large {
                    Vec::new()
                } else {
                    parse_unified_diff(&String::from_utf8_lossy(&out.stdout))
                };
                Ok(GitFileDiff {
                    path: rel,
                    old_path: old_path.clone(),
                    binary: false,
                    too_large,
                    lfs: false,
                    total_bytes: out.stdout_total as u64,
                    hunks,
                })
            }
        }
    }

    pub async fn diff(&self, file: Option<String>) -> Result<Vec<GitFileDiff>, String> {
        let ctx = self.build_request_ctx().await?;
        const DIFF: [&str; 4] = ["diff", "--no-ext-diff", "--no-textconv", "--unified=3"];
        let diff_args = |staged: bool, tail: &[&str]| -> Vec<String> {
            let mut v = vec![DIFF[0]];
            if staged {
                v.push("--staged");
            }
            v.extend_from_slice(&DIFF[1..]);
            v.extend_from_slice(tail);
            v.into_iter().map(str::to_string).collect()
        };
        let mut outputs = Vec::with_capacity(2);
        let single_file_rel = match file {
            None => {
                for staged in [true, false] {
                    outputs.push(self.run_diff(&ctx, &diff_args(staged, &["--"])).await?);
                }
                None
            }
            Some(f) => {
                let rel = self.validate_and_relativize(&f)?;
                let ls = run(
                    self.git_cmd(&ctx, &["ls-files", "--error-unmatch", "--", &rel]),
                    None,
                    0,
                )
                .await?;
                if ls.status.success() {
                    for staged in [true, false] {
                        outputs.push(
                            self.run_diff(&ctx, &diff_args(staged, &["--", &rel]))
                                .await?,
                        );
                    }
                } else {
                    let meta = tokio::fs::metadata(self.workspace_root.join(&rel)).await;
                    if !meta.is_ok_and(|m| m.is_file()) {
                        return Err(format!("not a tracked path or regular file: {rel}"));
                    }
                    let args = diff_args(false, &["--no-index", "--", "/dev/null", &rel]);
                    let out = run(self.git_cmd(&ctx, &args), None, MAX_DIFF_BYTES).await?;
                    if out.status.code().is_some_and(|c| c > 1) || out.status.code().is_none() {
                        return Err(out.error());
                    }
                    outputs.push(out);
                }
                Some(rel)
            }
        };

        let total_bytes = outputs.iter().map(|o| o.stdout_total).sum::<usize>();
        let too_large = total_bytes > MAX_DIFF_BYTES;

        let mut hunks = Vec::new();
        if !too_large {
            for out in &outputs {
                hunks.extend(parse_unified_diff(&String::from_utf8_lossy(&out.stdout)));
            }
        }

        let mut file_map: std::collections::BTreeMap<
            String,
            Vec<cawide_protocol::types::DiffHunk>,
        > = std::collections::BTreeMap::new();
        for h in hunks {
            file_map.entry(h.file_path.clone()).or_default().push(h);
        }

        if too_large {
            for out in &outputs {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some(rest) = line.strip_prefix("diff --git a/") {
                        if let Some((path, _)) = rest.split_once(" b/") {
                            file_map.entry(path.to_string()).or_default();
                        }
                    }
                }
            }
            if file_map.is_empty() {
                file_map.entry(String::new()).or_default();
            }
        }

        if let Some(target) = single_file_rel {
            let hunks = file_map.remove(&target).unwrap_or_default();
            Ok(vec![GitFileDiff {
                path: target,
                old_path: None,
                binary: false,
                too_large,
                lfs: false,
                total_bytes: total_bytes as u64,
                hunks,
            }])
        } else {
            let mut diffs = Vec::new();
            for (path, hunks) in file_map {
                diffs.push(GitFileDiff {
                    path,
                    old_path: None,
                    binary: false,
                    too_large,
                    lfs: false,
                    total_bytes: total_bytes as u64,
                    hunks,
                });
            }
            Ok(diffs)
        }
    }

    async fn run_diff(&self, ctx: &GitRequestCtx, args: &[String]) -> Result<GitOutput, String> {
        // Output beyond the cap is counted (`stdout_total`) but never buffered.
        run(self.git_cmd(ctx, args), None, MAX_DIFF_BYTES)
            .await?
            .ok()
    }

    /// Stages `path` (file or directory, including deletions); `.` stages everything.
    pub async fn stage(&self, path: &str) -> Result<(), String> {
        staging::stage_paths(self, &[path.to_string()])
            .await
            .map_err(|e| e.message)
    }

    /// Unstages `path`; `.` unstages everything. The worktree is never modified.
    pub async fn unstage(&self, path: &str) -> Result<(), String> {
        staging::unstage_paths(self, &[path.to_string()])
            .await
            .map_err(|e| e.message)
    }

    pub async fn stage_paths(
        &self,
        paths: &[String],
    ) -> Result<(), cawide_protocol::types::GitError> {
        staging::stage_paths(self, paths).await
    }

    pub async fn unstage_paths(
        &self,
        paths: &[String],
    ) -> Result<(), cawide_protocol::types::GitError> {
        staging::unstage_paths(self, paths).await
    }

    pub async fn discard(
        &self,
        paths: &[String],
        scope: cawide_protocol::types::GitDiscardScope,
    ) -> Result<Vec<cawide_protocol::types::GitUndoItem>, cawide_protocol::types::GitError> {
        staging::discard(self, paths, scope).await
    }

    pub async fn restore_blobs(
        &self,
        items: &[cawide_protocol::types::GitUndoItem],
    ) -> Result<(), cawide_protocol::types::GitError> {
        staging::restore_blobs(self, items).await
    }

    pub async fn apply_patch(
        &self,
        patch: cawide_protocol::types::GitPatchRequest,
    ) -> Result<Option<cawide_protocol::types::GitUndoItem>, cawide_protocol::types::GitError> {
        patch::apply_patch(self, patch).await
    }

    pub async fn commit(&self, message: &str) -> Result<String, String> {
        if message.trim().is_empty() {
            return Err("commit message cannot be empty".into());
        }
        let ctx = self.build_request_ctx().await?;
        // `-q` skips the post-commit diffstat (no textconv); `-F -` avoids any editor.
        let cmd = self.git_cmd(&ctx, &["commit", "-q", "-F", "-"]);
        run(cmd, Some(message.as_bytes()), MAX_STDERR_BYTES)
            .await?
            .ok()?;
        let head = run(self.git_cmd(&ctx, &["rev-parse", "HEAD"]), None, 256)
            .await?
            .ok()?;
        Ok(String::from_utf8_lossy(&head.stdout).trim().to_string())
    }
}

#[cfg(test)]
fn parse_status(stdout: &str) -> GitRepoStatus {
    let mut collector = status::StatusCollector::new();
    for r in stdout.split('\0').filter(|r| !r.is_empty()) {
        collector.handle_record(r.as_bytes());
    }
    collector.finish(None, GitLfsState::NotUsed)
}

pub fn find_git_root(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|a| a.join(".git").exists())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawide_protocol::types::GitHead;
    #[test]
    fn parse_status_tolerates_malformed_records() {
        let s = parse_status("# branch.head dev\x001 M.\x00? ok.txt\x00");
        match s.head {
            GitHead::Branch { name, .. } => assert_eq!(name, "dev"),
            _ => panic!("expected branch"),
        }
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].path, "ok.txt");
    }

    #[test]
    fn test_find_git_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let git_dir = temp.path().join(".git");
        std::fs::create_dir(&git_dir).expect("create .git");
        let nested = temp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).expect("create nested");

        let root = find_git_root(&nested);
        assert_eq!(root, Some(temp.path().to_path_buf()));

        let non_git = tempfile::tempdir().expect("tempdir non-git");
        assert_eq!(find_git_root(non_git.path()), None);
    }
}

#[cfg(test)]
mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn prop_parse_status_arbitrary_never_panics(s in any::<String>()) {
            let _ = parse_status(&s);
        }
    }
}
