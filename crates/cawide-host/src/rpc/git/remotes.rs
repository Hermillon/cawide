use super::{
    remote_url::parse_remote_url,
    validate::{validate_remote_name, validate_remote_url},
    GitEngine,
};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{GitError, GitErrorKind, GitRemote, GitRemoteScheme};
use std::collections::HashMap;
use std::time::Duration;

pub async fn list_remotes(engine: &GitEngine) -> Result<Vec<GitRemote>, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["remote", "-v"]);
    let out = run(
        cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 1024 * 1024,
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
        let kind = super::errors::classify(&stderr, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    let mut remotes_map: HashMap<String, (String, String)> = HashMap::new();
    let stdout_str = String::from_utf8_lossy(&out.stdout);

    for line in stdout_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let name = parts[0];
            let url = parts[1];
            let kind = parts[2];

            let entry = remotes_map
                .entry(name.to_string())
                .or_insert_with(|| (String::new(), String::new()));

            if kind.contains("fetch") {
                entry.0 = url.to_string();
            } else if kind.contains("push") {
                entry.1 = url.to_string();
            }
        }
    }

    let mut remotes = Vec::new();
    for (name, (fetch_url, mut push_url)) in remotes_map {
        if push_url.is_empty() {
            push_url = fetch_url.clone();
        }
        let url_to_parse = if !fetch_url.is_empty() {
            &fetch_url
        } else {
            &push_url
        };

        let parsed = parse_remote_url(url_to_parse);
        let (scheme, host, port, https_url) = if let Some(info) = parsed {
            let s = match info.scheme.as_str() {
                "https" => GitRemoteScheme::Https,
                "http" => GitRemoteScheme::Http,
                "ssh" => GitRemoteScheme::Ssh,
                "file" => GitRemoteScheme::File,
                _ => GitRemoteScheme::Git,
            };
            let h = if info.host.is_empty() {
                None
            } else {
                Some(info.host.clone())
            };
            (s, h, info.port, info.https_equivalent())
        } else {
            (GitRemoteScheme::Git, None, None, None)
        };

        remotes.push(GitRemote {
            name,
            fetch_url,
            push_url,
            scheme,
            host,
            port,
            https_url,
        });
    }

    remotes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(remotes)
}

pub async fn add_remote(engine: &GitEngine, name: &str, url: &str) -> Result<(), GitError> {
    validate_remote_name(name)?;
    validate_remote_url(url)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["remote", "add", name, url]);
    let out = run(
        cmd,
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
        let kind = super::errors::classify(&stderr, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    Ok(())
}

pub async fn remove_remote(engine: &GitEngine, name: &str) -> Result<(), GitError> {
    validate_remote_name(name)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["remote", "remove", name]);
    let out = run(
        cmd,
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
        let kind = super::errors::classify(&stderr, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    Ok(())
}

pub async fn set_remote_url(engine: &GitEngine, name: &str, url: &str) -> Result<(), GitError> {
    validate_remote_name(name)?;
    validate_remote_url(url)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["remote", "set-url", name, url]);
    let out = run(
        cmd,
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
        let kind = super::errors::classify(&stderr, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    Ok(())
}
