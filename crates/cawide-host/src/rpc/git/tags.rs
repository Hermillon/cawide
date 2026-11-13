use super::{
    validate::{validate_oid, validate_ref_name},
    GitEngine,
};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{GitError, GitErrorKind, GitTag};
use std::time::Duration;

pub async fn list_tags(engine: &GitEngine) -> Result<Vec<GitTag>, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(
        &ctx,
        &[
            "tag",
            "-l",
            "--format=%(refname:strip=2)\x1f%(objectname)\x1f%(*objectname)\x1f%(creatordate:raw)\x1f%(subject)",
        ],
    );

    let out = run(
        cmd,
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

    let mut tags = Vec::new();
    let records = out.stdout.split(|&b| b == b'\n').filter(|b| !b.is_empty());

    for rec in records {
        let rec_str = String::from_utf8_lossy(rec);
        let fields: Vec<&str> = rec_str.split('\x1f').collect();
        if fields.len() < 5 {
            continue;
        }

        let name = fields[0].to_string();
        let objectname = fields[1].to_string();
        let peeled = fields[2].trim();
        let date_str = fields[3].trim();
        let subject = fields[4].to_string();

        let time = date_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let (annotated, target_oid) = if !peeled.is_empty() {
            (true, peeled.to_string())
        } else {
            (false, objectname)
        };

        tags.push(GitTag {
            name,
            target_oid,
            annotated,
            time,
            subject,
        });
    }

    // Sort newest first
    tags.sort_by_key(|a| std::cmp::Reverse(a.time));
    Ok(tags)
}

pub async fn create_tag(
    engine: &GitEngine,
    name: &str,
    target: &str,
    message: Option<&str>,
) -> Result<(), GitError> {
    validate_ref_name(name)?;
    if validate_ref_name(target).is_err() && validate_oid(target).is_err() {
        return Err(GitError {
            kind: GitErrorKind::InvalidArgument,
            message: format!("invalid tag target: {target}"),
            host: None,
            port: None,
        });
    }

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let mut args = vec!["tag"];
    if let Some(msg) = message {
        args.extend(["-a", "-m", msg, name, target]);
    } else {
        args.extend([name, target]);
    }

    let cmd = engine.git_cmd(&ctx, &args);
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

pub async fn delete_tag(engine: &GitEngine, name: &str) -> Result<(), GitError> {
    validate_ref_name(name)?;

    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let cmd = engine.git_cmd(&ctx, &["tag", "-d", name]);
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
