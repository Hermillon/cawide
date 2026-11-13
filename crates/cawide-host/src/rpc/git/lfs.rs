use super::{GitEngine, HARDENING_ARGS};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{GitError, GitErrorKind, GitLfsState};
use parking_lot::Mutex;
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

static GLOBAL_LFS_CACHE: Mutex<Option<HashMap<PathBuf, (GitLfsState, Instant)>>> = Mutex::new(None);

pub fn invalidate_lfs_cache(root: &Path) {
    let mut guard = GLOBAL_LFS_CACHE.lock();
    if let Some(map) = guard.as_mut() {
        map.remove(root);
    }
}

pub fn lfs_args_minus_literal_pathspecs() -> Vec<&'static str> {
    HARDENING_ARGS
        .iter()
        .copied()
        .filter(|&a| a != "--literal-pathspecs")
        .collect()
}

pub fn find_executable_on_path(exe: &str, extra_env: &[(String, String)]) -> Option<PathBuf> {
    let path_val = extra_env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var("PATH").ok())?;

    for dir in std::env::split_paths(&path_val) {
        #[cfg(windows)]
        {
            let candidates =
                if exe.ends_with(".exe") || exe.ends_with(".cmd") || exe.ends_with(".bat") {
                    vec![dir.join(exe)]
                } else {
                    vec![dir.join(format!("{exe}.exe")), dir.join(exe)]
                };
            for p in candidates {
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let p = dir.join(exe);
            if p.is_file() {
                if let Ok(meta) = p.metadata() {
                    #[cfg(unix)]
                    if meta.permissions().mode() & 0o111 != 0 {
                        return Some(p);
                    }
                    #[cfg(not(unix))]
                    return Some(p);
                }
            }
        }
    }
    None
}

pub async fn check_paths_lfs(engine: &GitEngine, paths: &[String]) -> Result<bool, GitError> {
    if paths.is_empty() {
        return Ok(false);
    }
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mut stdin_bytes = Vec::new();
    for p in paths {
        stdin_bytes.extend_from_slice(p.as_bytes());
        stdin_bytes.push(b'\0');
    }

    let cmd = engine.git_cmd(&ctx, &["check-attr", "-z", "--stdin", "filter"]);

    let opts = RunOpts {
        stdin: Some(&stdin_bytes),
        stdout_cap: 256 * 1024,
        timeout: Duration::from_secs(30),
    };

    let out = run(cmd, opts).await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    // Output is path\0info\0value\0
    let mut parts = out.stdout.split(|&b| b == 0);
    while let (Some(_path), Some(_attr), Some(val)) = (parts.next(), parts.next(), parts.next()) {
        if val == b"lfs" {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn lfs_state(engine: &GitEngine) -> Result<GitLfsState, GitError> {
    let root = engine.root().to_path_buf();
    {
        let mut guard = GLOBAL_LFS_CACHE.lock();
        let map = guard.get_or_insert_with(HashMap::new);
        if let Some((state, ts)) = map.get(&root) {
            if ts.elapsed() < Duration::from_secs(30) {
                return Ok(state.clone());
            }
        }
    }

    let state = detect_lfs_state(engine).await?;

    {
        let mut guard = GLOBAL_LFS_CACHE.lock();
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(root, (state.clone(), Instant::now()));
    }

    Ok(state)
}

async fn detect_lfs_state(engine: &GitEngine) -> Result<GitLfsState, GitError> {
    let hardening = lfs_args_minus_literal_pathspecs();
    let mut cmd = engine.base_cmd();
    cmd.args(&hardening);
    cmd.args(["ls-files", "-z", "--", ":(attr:filter=lfs)"]);

    let opts = RunOpts {
        stdin: None,
        stdout_cap: 4096,
        timeout: Duration::from_secs(30),
    };

    let out = run(cmd, opts).await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e.to_string(),
        host: None,
        port: None,
    })?;

    if out.stdout.is_empty() {
        return Ok(GitLfsState::NotUsed);
    }

    // Repo uses LFS. Check global/system canonical filter config.
    let clean = read_config_global_system(engine, "filter.lfs.clean").await;
    let smudge = read_config_global_system(engine, "filter.lfs.smudge").await;
    let process = read_config_global_system(engine, "filter.lfs.process").await;

    let canonical = clean.as_deref() == Some("git-lfs clean -- %f")
        && smudge.as_deref() == Some("git-lfs smudge -- %f")
        && (process.is_none() || process.as_deref() == Some("git-lfs filter-process"));

    if canonical && find_executable_on_path("git-lfs", &engine.env.extra_env).is_some() {
        Ok(GitLfsState::Enabled)
    } else {
        Ok(GitLfsState::Unavailable)
    }
}

async fn read_config_global_system(engine: &GitEngine, key: &str) -> Option<String> {
    for scope in ["--global", "--system"] {
        let mut cmd = engine.base_cmd();
        cmd.args(HARDENING_ARGS);
        cmd.args(["config", scope, "--get", key]);
        let opts = RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
        };
        if let Ok(out) = run(cmd, opts).await {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::git::HARDENING_ARGS;

    #[test]
    fn test_lfs_args_differs_only_by_literal_pathspecs() {
        let args = lfs_args_minus_literal_pathspecs();
        let mut expected: Vec<&str> = HARDENING_ARGS.to_vec();
        expected.retain(|&a| a != "--literal-pathspecs");
        assert_eq!(args, expected);
    }
}
