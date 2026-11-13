use super::{
    remote_url::parse_remote_url,
    validate::{validate_ref_name, validate_remote_name},
    GitEngine,
};
use crate::forge::credentials::ForgeCredentialSource;
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{
    GitError, GitErrorKind, GitIntegrationOutcome, GitIntegrationResult, GitPullMode,
};
use std::path::PathBuf;
use std::time::Duration;

pub const GIT_NETWORK_TIMEOUT: Duration = Duration::from_secs(120);

pub fn auth_for(
    _engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    remote_url: &str,
    account: Option<&str>,
) -> (Vec<String>, Vec<(String, String)>) {
    let injection = creds.auth_for(remote_url, account);
    (injection.config_args, injection.env)
}

fn url_host(url_info: Option<&super::remote_url::ParsedRemoteUrl>) -> Option<String> {
    url_info.map(|u| u.host.clone())
}

fn url_port(url_info: Option<&super::remote_url::ParsedRemoteUrl>) -> Option<u16> {
    url_info.and_then(|u| u.port)
}

fn git_net_cmd<S: AsRef<std::ffi::OsStr>>(
    engine: &GitEngine,
    ctx: &super::GitRequestCtx,
    auth_args: &[String],
    subcommand_and_args: &[S],
) -> tokio::process::Command {
    let mut cmd = engine.base_cmd();
    cmd.args(super::HARDENING_ARGS);
    for arg in auth_args {
        cmd.arg(arg);
    }
    cmd.args(subcommand_and_args);
    cmd.envs(ctx.env_overrides.iter().map(|(k, v)| (k, v)));
    cmd
}

fn cawide_ssh_command() -> String {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("~"));
    let config_dir = std::env::var("CAWIDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".config/cawide"));
    let home_kh = home.join(".ssh/known_hosts");
    let cawide_kh = config_dir.join("ssh/known_hosts");
    format!(
        "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\"{}\" -o UserKnownHostsFile=\"{}\"",
        home_kh.display(),
        cawide_kh.display()
    )
}

async fn is_user_managed_ssh(engine: &GitEngine) -> (bool, Option<String>) {
    if let Some(ref cmd) = engine.env.user_ssh_command {
        return (true, Some(cmd.clone()));
    }
    if let Some((_, v)) = engine
        .env
        .extra_env
        .iter()
        .find(|(k, _)| k == "GIT_SSH_COMMAND")
    {
        return (true, Some(v.clone()));
    }

    let ctx = match engine.build_request_ctx().await {
        Ok(c) => c,
        Err(_) => return (false, None),
    };
    let cmd = engine.git_cmd(&ctx, &["config", "--get", "core.sshCommand"]);
    if let Ok(out) = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(5),
        },
    )
    .await
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return (true, Some(s));
            }
        }
    }
    (false, None)
}

async fn get_remote_url(engine: &GitEngine, remote: &str) -> Option<String> {
    let ctx = engine.build_request_ctx().await.ok()?;
    let config_key = format!("remote.{remote}.url");
    let cmd = engine.git_cmd(&ctx, &["config", "--get", &config_key]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(5),
        },
    )
    .await
    .ok()?;
    if out.status.success() {
        let u = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !u.is_empty() {
            return Some(u);
        }
    }
    None
}

pub async fn fetch(
    engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    remote: Option<&str>,
    account: Option<&str>,
) -> Result<(), GitError> {
    let remote_name = remote.unwrap_or("origin");
    validate_remote_name(remote_name)?;

    let remote_url = get_remote_url(engine, remote_name)
        .await
        .unwrap_or_else(|| remote_name.to_string());
    let url_info = parse_remote_url(&remote_url);

    let (auth_args, auth_env) = auth_for(engine, creds, &remote_url, account);
    let (user_ssh, ssh_cmd) = is_user_managed_ssh(engine).await;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    let mut cmd = git_net_cmd(engine, &ctx, &auth_args, &["fetch", remote_name]);
    for (k, v) in &auth_env {
        cmd.env(k, v);
    }
    if !user_ssh {
        cmd.env("GIT_SSH_COMMAND", cawide_ssh_command());
    } else if let Some(ref c) = ssh_cmd {
        cmd.env("GIT_SSH_COMMAND", c);
    }

    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: GIT_NETWORK_TIMEOUT,
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Timeout,
        message: e.to_string(),
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let kind = super::errors::classify(&stderr, Some(out.status), user_ssh);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: url_host(url_info.as_ref()),
            port: url_port(url_info.as_ref()),
        });
    }

    Ok(())
}

pub async fn pull(
    engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    mode: GitPullMode,
    account: Option<&str>,
) -> Result<GitIntegrationOutcome, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    // Check upstream tracking branch
    let upstream_cmd = engine.git_cmd(
        &ctx,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    );
    let u_out = run(
        upstream_cmd,
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

    if !u_out.status.success() {
        return Err(GitError {
            kind: GitErrorKind::NoUpstream,
            message: "There is no tracking information for the current branch.".into(),
            host: None,
            port: None,
        });
    }

    let upstream = String::from_utf8_lossy(&u_out.stdout).trim().to_string();
    let remote = upstream.split('/').next().unwrap_or("origin");
    let remote_url = get_remote_url(engine, remote)
        .await
        .unwrap_or_else(|| remote.to_string());
    let url_info = parse_remote_url(&remote_url);

    let (auth_args, auth_env) = auth_for(engine, creds, &remote_url, account);
    let (user_ssh, ssh_cmd) = is_user_managed_ssh(engine).await;

    let mode_arg = match mode {
        GitPullMode::FastForwardOnly => "--ff-only",
        GitPullMode::Rebase => "--rebase",
        GitPullMode::Merge => "--no-rebase",
    };

    let mut cmd = git_net_cmd(engine, &ctx, &auth_args, &["pull", mode_arg]);
    for (k, v) in &auth_env {
        cmd.env(k, v);
    }
    if !user_ssh {
        cmd.env("GIT_SSH_COMMAND", cawide_ssh_command());
    } else if let Some(ref c) = ssh_cmd {
        cmd.env("GIT_SSH_COMMAND", c);
    }

    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: GIT_NETWORK_TIMEOUT,
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Timeout,
        message: e.to_string(),
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let stderr_str = String::from_utf8_lossy(&out.stderr);

    if !out.status.success() {
        // Check if there are merge/rebase conflicts
        let conflicts = get_conflicted_paths(engine, &ctx).await;
        if !conflicts.is_empty() {
            super::lfs::invalidate_lfs_cache(engine.root());
            return Ok(GitIntegrationOutcome {
                result: GitIntegrationResult::Conflicts,
                conflicted_paths: conflicts,
            });
        }

        let kind = super::errors::classify(&stderr_str, Some(out.status), user_ssh);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: url_host(url_info.as_ref()),
            port: url_port(url_info.as_ref()),
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

#[allow(clippy::too_many_arguments)]
pub async fn push(
    engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    remote: &str,
    local_branch: &str,
    remote_branch: &str,
    set_upstream: bool,
    force_with_lease: bool,
    account: Option<&str>,
) -> Result<bool, GitError> {
    validate_remote_name(remote)?;
    validate_ref_name(local_branch)?;
    validate_ref_name(remote_branch)?;

    let remote_url = get_remote_url(engine, remote)
        .await
        .unwrap_or_else(|| remote.to_string());
    let url_info = parse_remote_url(&remote_url);

    let (auth_args, auth_env) = auth_for(engine, creds, &remote_url, account);
    let (user_ssh, ssh_cmd) = is_user_managed_ssh(engine).await;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    let refspec = format!("{local_branch}:{remote_branch}");
    let mut args = vec!["push", "--porcelain"];
    if set_upstream {
        args.push("-u");
    }
    if force_with_lease {
        args.push("--force-with-lease");
    }
    args.push(remote);
    args.push(&refspec);

    let mut cmd = git_net_cmd(engine, &ctx, &auth_args, &args);
    for (k, v) in &auth_env {
        cmd.env(k, v);
    }
    if !user_ssh {
        cmd.env("GIT_SSH_COMMAND", cawide_ssh_command());
    } else if let Some(ref c) = ssh_cmd {
        cmd.env("GIT_SSH_COMMAND", c);
    }

    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: GIT_NETWORK_TIMEOUT,
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Timeout,
        message: e.to_string(),
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let stderr_str = String::from_utf8_lossy(&out.stderr);

    if !out.status.success() {
        let kind = super::errors::classify(&stderr_str, Some(out.status), user_ssh);
        return Err(GitError {
            kind,
            message: stderr_str.trim().to_string(),
            host: url_host(url_info.as_ref()),
            port: url_port(url_info.as_ref()),
        });
    }

    let mut new_remote_branch = false;
    for line in stdout_str.lines() {
        if line.starts_with('*') && line.contains("[new branch]") {
            new_remote_branch = true;
            break;
        }
    }

    Ok(new_remote_branch)
}

pub async fn push_tag(
    engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    remote: &str,
    name: &str,
    account: Option<&str>,
) -> Result<(), GitError> {
    validate_remote_name(remote)?;
    validate_ref_name(name)?;

    let remote_url = get_remote_url(engine, remote)
        .await
        .unwrap_or_else(|| remote.to_string());
    let url_info = parse_remote_url(&remote_url);

    let (auth_args, auth_env) = auth_for(engine, creds, &remote_url, account);
    let (user_ssh, ssh_cmd) = is_user_managed_ssh(engine).await;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    let tag_ref = format!("refs/tags/{name}");
    let mut cmd = git_net_cmd(engine, &ctx, &auth_args, &["push", remote, &tag_ref]);
    for (k, v) in &auth_env {
        cmd.env(k, v);
    }
    if !user_ssh {
        cmd.env("GIT_SSH_COMMAND", cawide_ssh_command());
    } else if let Some(ref c) = ssh_cmd {
        cmd.env("GIT_SSH_COMMAND", c);
    }

    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: GIT_NETWORK_TIMEOUT,
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Timeout,
        message: e.to_string(),
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let kind = super::errors::classify(&stderr, Some(out.status), user_ssh);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: url_host(url_info.as_ref()),
            port: url_port(url_info.as_ref()),
        });
    }

    Ok(())
}

pub async fn delete_remote_ref(
    engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    remote: &str,
    full_ref: &str,
    account: Option<&str>,
) -> Result<(), GitError> {
    validate_remote_name(remote)?;
    validate_ref_name(full_ref)?;

    let remote_url = get_remote_url(engine, remote)
        .await
        .unwrap_or_else(|| remote.to_string());
    let url_info = parse_remote_url(&remote_url);

    let (auth_args, auth_env) = auth_for(engine, creds, &remote_url, account);
    let (user_ssh, ssh_cmd) = is_user_managed_ssh(engine).await;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    let mut cmd = git_net_cmd(
        engine,
        &ctx,
        &auth_args,
        &["push", remote, "--delete", full_ref],
    );
    for (k, v) in &auth_env {
        cmd.env(k, v);
    }
    if !user_ssh {
        cmd.env("GIT_SSH_COMMAND", cawide_ssh_command());
    } else if let Some(ref c) = ssh_cmd {
        cmd.env("GIT_SSH_COMMAND", c);
    }

    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 8 * 1024 * 1024,
            timeout: GIT_NETWORK_TIMEOUT,
        },
    )
    .await
    .map_err(|e| GitError {
        kind: GitErrorKind::Timeout,
        message: e.to_string(),
        host: url_host(url_info.as_ref()),
        port: url_port(url_info.as_ref()),
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let kind = super::errors::classify(&stderr, Some(out.status), user_ssh);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: url_host(url_info.as_ref()),
            port: url_port(url_info.as_ref()),
        });
    }

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
