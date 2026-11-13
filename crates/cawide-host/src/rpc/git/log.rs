use super::{
    graph::{compute_commit_graph, RawCommitInfo},
    validate::validate_ref_name,
    GitEngine,
};
use crate::rpc::process::{run, RunOpts};
use cawide_protocol::types::{
    GitCommitRow, GitError, GitErrorKind, GitLogPage, GitLogQuery, GitLogScope, GitRefKind,
    GitRefLabel, MAX_LOG_WINDOW,
};
use std::time::Duration;

pub async fn log(engine: &GitEngine, query: GitLogQuery) -> Result<GitLogPage, GitError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| GitError {
        kind: GitErrorKind::Other,
        message: e,
        host: None,
        port: None,
    })?;

    let skip = query.skip;
    let limit = query.limit.max(1);
    let window = (skip + limit).min(MAX_LOG_WINDOW);
    let fetch_count = window + 1; // +1 to detect has_more

    let mut args = vec![
        "log".to_string(),
        "--topo-order".to_string(),
        "--decorate=full".to_string(),
        "-z".to_string(),
        "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s%x1f%D".to_string(),
        format!("--max-count={fetch_count}"),
    ];

    match &query.scope {
        GitLogScope::AllRefs => {
            args.push("--exclude=refs/stash*".to_string());
            args.push("--exclude=refs/cmux/*".to_string());
            args.push("--exclude=refs/notes/*".to_string());
            args.push("--exclude=refs/bisect/*".to_string());
            args.push("--exclude=refs/prefetch/*".to_string());
            args.push("--all".to_string());
        }
        GitLogScope::Head => {
            args.push("HEAD".to_string());
        }
        GitLogScope::Ref { name } => {
            validate_ref_name(name)?;
            args.push(name.clone());
        }
    }

    let is_path_query = query.path.is_some();
    if let Some(ref path) = query.path {
        let rel = engine.validate_and_relativize(path).map_err(|e| GitError {
            kind: GitErrorKind::InvalidArgument,
            message: e,
            host: None,
            port: None,
        })?;
        args.push("--".to_string());
        args.push(rel);
    }

    let log_cmd = engine.git_cmd(&ctx, &args);
    let out = run(
        log_cmd,
        RunOpts {
            stdin: None,
            stdout_cap: 32 * 1024 * 1024,
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
        if stderr.contains("does not have any commits yet")
            || stderr.contains("bad default revision 'HEAD'")
            || (matches!(query.scope, GitLogScope::Head)
                && stderr.contains("ambiguous argument 'HEAD'"))
        {
            return Ok(GitLogPage {
                commits: Vec::new(),
                has_more: false,
                max_lane: 0,
            });
        }
        let kind = super::errors::classify(&stderr, Some(out.status), false);
        return Err(GitError {
            kind,
            message: stderr.trim().to_string(),
            host: None,
            port: None,
        });
    }

    let mut raw_commits = Vec::new();
    let mut commit_rows_data = Vec::new();

    let records = out.stdout.split(|&b| b == 0).filter(|b| !b.is_empty());

    for rec in records {
        let rec_str = String::from_utf8_lossy(rec);
        let fields: Vec<&str> = rec_str.split('\x1f').collect();
        if fields.len() < 7 {
            continue;
        }

        let oid = fields[0].trim().to_string();
        let parents: Vec<String> = fields[1].split_whitespace().map(str::to_string).collect();
        let author_name = fields[2].to_string();
        let author_email = fields[3].to_string();
        let author_time = fields[4].parse::<i64>().unwrap_or(0);
        let subject = fields[5].to_string();
        let decor_str = fields[6];

        let refs = parse_ref_decorations(decor_str);
        let short_oid = if oid.len() >= 7 {
            oid[..7].to_string()
        } else {
            oid.clone()
        };

        raw_commits.push(RawCommitInfo {
            oid: oid.clone(),
            parents: parents.clone(),
        });

        commit_rows_data.push((
            oid,
            short_oid,
            parents,
            author_name,
            author_email,
            author_time,
            subject,
            refs,
        ));
    }

    let total_fetched = commit_rows_data.len();
    let has_more = total_fetched > (skip + limit) as usize;

    let (graph_rows, max_lane) = compute_commit_graph(&raw_commits, is_path_query);

    let start_idx = (skip as usize).min(total_fetched);
    let end_idx = ((skip + limit) as usize).min(total_fetched);

    let mut commits = Vec::with_capacity(end_idx - start_idx);

    for (data, graph) in commit_rows_data
        .into_iter()
        .zip(graph_rows)
        .skip(start_idx)
        .take(end_idx - start_idx)
    {
        commits.push(GitCommitRow {
            oid: data.0,
            short_oid: data.1,
            parents: data.2,
            author_name: data.3,
            author_email: data.4,
            author_time: data.5,
            subject: data.6,
            refs: data.7,
            graph,
        });
    }

    Ok(GitLogPage {
        commits,
        has_more,
        max_lane,
    })
}

pub(crate) fn parse_ref_decorations(decor: &str) -> Vec<GitRefLabel> {
    let mut labels = Vec::new();
    let trimmed = decor.trim();
    if trimmed.is_empty() {
        return labels;
    }

    for part in trimmed.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }

        if let Some(rest) = p.strip_prefix("HEAD -> refs/heads/") {
            labels.push(GitRefLabel {
                name: rest.to_string(),
                kind: GitRefKind::CurrentBranch,
            });
        } else if let Some(rest) = p.strip_prefix("HEAD -> ") {
            labels.push(GitRefLabel {
                name: rest.to_string(),
                kind: GitRefKind::CurrentBranch,
            });
        } else if p == "HEAD" {
            labels.push(GitRefLabel {
                name: "HEAD".to_string(),
                kind: GitRefKind::DetachedHead,
            });
        } else if let Some(rest) = p.strip_prefix("tag: refs/tags/") {
            labels.push(GitRefLabel {
                name: rest.to_string(),
                kind: GitRefKind::Tag,
            });
        } else if let Some(rest) = p.strip_prefix("refs/heads/") {
            labels.push(GitRefLabel {
                name: rest.to_string(),
                kind: GitRefKind::LocalBranch,
            });
        } else if let Some(rest) = p.strip_prefix("refs/remotes/") {
            labels.push(GitRefLabel {
                name: rest.to_string(),
                kind: GitRefKind::RemoteBranch,
            });
        }
    }

    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ref_decorations() {
        let decor = "HEAD -> refs/heads/main, refs/remotes/origin/main, tag: refs/tags/v1.0";
        let labels = parse_ref_decorations(decor);
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[0].name, "main");
        assert_eq!(labels[0].kind, GitRefKind::CurrentBranch);
        assert_eq!(labels[1].name, "origin/main");
        assert_eq!(labels[1].kind, GitRefKind::RemoteBranch);
        assert_eq!(labels[2].name, "v1.0");
        assert_eq!(labels[2].kind, GitRefKind::Tag);
    }
}
