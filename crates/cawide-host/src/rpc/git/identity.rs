use super::GitEngine;
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{GitConfigScope, GitError, GitErrorKind, GitIdentity};
use std::time::Duration;

fn invalid_arg(msg: impl Into<String>) -> GitError {
    GitError {
        kind: GitErrorKind::InvalidArgument,
        message: msg.into(),
        host: None,
        port: None,
    }
}

pub async fn get_identity(engine: &GitEngine) -> Result<GitIdentity, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let name_cmd = engine.git_cmd(&ctx, &["config", "--get", "user.name"]);
    let name_out = run(
        name_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
        },
    )
    .await
    .ok();

    let name = name_out.and_then(|out| {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        }
    });

    let email_cmd = engine.git_cmd(&ctx, &["config", "--get", "user.email"]);
    let email_out = run(
        email_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
        },
    )
    .await
    .ok();

    let email = email_out.and_then(|out| {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        }
    });

    Ok(GitIdentity { name, email })
}

pub async fn set_identity(
    engine: &GitEngine,
    name: &str,
    email: &str,
    scope: GitConfigScope,
) -> Result<(), GitError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid_arg("author name cannot be empty"));
    }
    if name.chars().any(|c| c.is_control() || c == '\n') {
        return Err(invalid_arg(
            "author name cannot contain newlines or control characters",
        ));
    }

    let email = email.trim();
    if email.is_empty() {
        return Err(invalid_arg("author email cannot be empty"));
    }
    if !email.contains('@') {
        return Err(invalid_arg("author email must contain '@'"));
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid_arg(
            "author email cannot contain whitespace or control characters",
        ));
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let scope_flag = match scope {
        GitConfigScope::Repository => "--local",
        GitConfigScope::Global => "--global",
    };

    let set_name_cmd = engine.git_cmd(&ctx, &["config", scope_flag, "user.name", name]);
    let out = run(
        set_name_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
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
            message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            host: None,
            port: None,
        });
    }

    let set_email_cmd = engine.git_cmd(&ctx, &["config", scope_flag, "user.email", email]);
    let out = run(
        set_email_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
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
            message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            host: None,
            port: None,
        });
    }

    Ok(())
}
