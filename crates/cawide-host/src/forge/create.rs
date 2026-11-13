use super::repo::ResolvedRepo;
use crate::rpc::git::GitEngine;
use cawide_protocol::types::{
    ForgeCreateDefaults, ForgeError, ForgeErrorKind, ForgeKind, ForgePrTemplate,
};
use std::path::Path;
use std::time::Duration;

pub async fn create_defaults(
    engine: &GitEngine,
    repo: &ResolvedRepo,
    head_branch: &str,
    base: Option<&str>,
) -> Result<ForgeCreateDefaults, ForgeError> {
    let ctx = engine.build_request_ctx().await.map_err(|e| ForgeError {
        kind: ForgeErrorKind::GitFailed,
        message: e,
        git_kind: None,
        host: None,
        port: None,
    })?;

    let base_branch = base
        .map(str::to_string)
        .unwrap_or_else(|| "main".to_string());

    // 1. Check head_pushed: git rev-parse --verify -q refs/remotes/<remote>/<head_branch>
    let remote_ref = format!("refs/remotes/{}/{}", repo.remote_name, head_branch);
    let check_cmd = engine.git_cmd(&ctx, &["rev-parse", "--verify", "-q", &remote_ref]);
    let check_out = crate::rpc::process::run(
        check_cmd,
        crate::rpc::process::RunOpts {
            stdin: None,
            stdout_cap: 1024,
            timeout: Duration::from_secs(10),
        },
    )
    .await
    .map_err(|e| ForgeError {
        kind: ForgeErrorKind::GitFailed,
        message: e.to_string(),
        git_kind: None,
        host: None,
        port: None,
    })?;

    let head_pushed = check_out.status.success();

    // 2. Fetch commits: git log --reverse --format=%s%x1f%b%x1e <remote>/<base>..<head_branch>
    let range = format!("{}/{}..{}", repo.remote_name, base_branch, head_branch);
    let log_cmd = engine.git_cmd(&ctx, &["log", "--reverse", "--format=%s\x1f%b\x1e", &range]);
    let log_out = crate::rpc::process::run(
        log_cmd,
        crate::rpc::process::RunOpts {
            stdin: None,
            stdout_cap: 2 * 1024 * 1024,
            timeout: Duration::from_secs(15),
        },
    )
    .await;

    let mut commit_items = Vec::new();
    if let Ok(out) = log_out {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for rec in s.split('\x1e') {
                let rec = rec.trim();
                if rec.is_empty() {
                    continue;
                }
                if let Some((subj, b)) = rec.split_once('\x1f') {
                    commit_items.push((subj.trim().to_string(), b.trim().to_string()));
                } else {
                    commit_items.push((rec.to_string(), String::new()));
                }
            }
        }
    }

    let commits_ahead = commit_items.len() as u32;

    // 3. Title: with 1 commit => subject; otherwise humanized branch
    let title = if commit_items.len() == 1 {
        commit_items[0].0.clone()
    } else {
        humanize_branch(head_branch)
    };

    // 4. Discover templates
    let templates = discover_templates(engine, repo.kind.clone()).await;

    // 5. Body: first template; else with 1 commit, its body; else - <subject> lines
    let body = if let Some(first_tpl) = templates.first() {
        first_tpl.body.clone()
    } else if commit_items.len() == 1 {
        commit_items[0].1.clone()
    } else if !commit_items.is_empty() {
        let lines: Vec<String> = commit_items.iter().map(|(s, _)| format!("- {s}")).collect();
        lines.join("\n")
    } else {
        String::new()
    };

    Ok(ForgeCreateDefaults {
        base: base_branch,
        head_branch: head_branch.to_string(),
        title,
        body,
        commits_ahead,
        head_pushed,
        templates,
    })
}

pub fn humanize_branch(branch: &str) -> String {
    let leaf = branch.split('/').next_back().unwrap_or(branch);
    let replaced = leaf.replace(['-', '_'], " ");
    let mut chars = replaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

async fn discover_templates(engine: &GitEngine, kind: ForgeKind) -> Vec<ForgePrTemplate> {
    let candidates: Vec<&str> = match kind {
        ForgeKind::GitHub => vec![
            ".github/pull_request_template.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            "pull_request_template.md",
            "PULL_REQUEST_TEMPLATE.md",
            "docs/pull_request_template.md",
            "docs/PULL_REQUEST_TEMPLATE.md",
        ],
        ForgeKind::GitLab => vec![],
        ForgeKind::Gitea => vec![
            ".gitea/pull_request_template.md",
            ".github/pull_request_template.md",
        ],
        ForgeKind::AzureDevOps => vec![
            ".azuredevops/pull_request_template.md",
            ".vsts/pull_request_template.md",
            "docs/pull_request_template.md",
        ],
        ForgeKind::Bitbucket | ForgeKind::Generic => vec![],
    };

    let mut templates = Vec::new();
    for rel_path in candidates {
        let full = engine.root().join(rel_path);
        if full.is_file() {
            if let Ok(meta) = full.metadata() {
                if meta.len() <= 64 * 1024 {
                    if let Ok(content) = tokio::fs::read_to_string(&full).await {
                        let name = Path::new(rel_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(rel_path)
                            .to_string();
                        templates.push(ForgePrTemplate {
                            name,
                            body: content,
                        });
                        break;
                    }
                }
            }
        }
    }

    // Also scan .github/PULL_REQUEST_TEMPLATE/ or .gitlab/merge_request_templates/
    let dir_candidates: Vec<&str> = match kind {
        ForgeKind::GitHub => vec![".github/PULL_REQUEST_TEMPLATE"],
        ForgeKind::GitLab => vec![".gitlab/merge_request_templates"],
        _ => vec![],
    };

    for dir_rel in dir_candidates {
        let dir_full = engine.root().join(dir_rel);
        if dir_full.is_dir() {
            if let Ok(mut entries) = tokio::fs::read_dir(&dir_full).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("md") {
                        if let Ok(meta) = path.metadata() {
                            if meta.len() <= 64 * 1024 {
                                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                                    let name = path
                                        .file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("template")
                                        .to_string();
                                    templates.push(ForgePrTemplate {
                                        name,
                                        body: content,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    templates
}

pub async fn get_head_spec(
    engine: &GitEngine,
    repo: &ResolvedRepo,
    head_branch: &str,
) -> Result<String, ForgeError> {
    let ctx = engine.build_request_ctx().await.ok();
    let mut push_remote = None;

    if let Some(ref c) = ctx {
        let key = format!("branch.{head_branch}.pushRemote");
        let cmd = engine.git_cmd(c, &["config", "--get", &key]);
        if let Ok(out) = crate::rpc::process::run(
            cmd,
            crate::rpc::process::RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_secs(5),
            },
        )
        .await
        {
            if out.status.success() {
                let r = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !r.is_empty() {
                    push_remote = Some(r);
                }
            }
        }
    }

    let remote_name = push_remote.as_deref().unwrap_or(&repo.remote_name);

    if remote_name != repo.remote_name {
        // Different remote: check if fork
        let remotes = crate::rpc::git::remotes::list_remotes(engine)
            .await
            .unwrap_or_default();
        if let Some(r) = remotes.iter().find(|r| r.name == remote_name) {
            if let Some(parsed) = crate::rpc::git::remote_url::parse_remote_url(&r.fetch_url) {
                if let Ok((ns, _)) =
                    super::repo::parse_coordinates(repo.kind.clone(), &parsed.path, &parsed.host)
                {
                    if ns != repo.namespace {
                        match repo.kind {
                            ForgeKind::GitHub | ForgeKind::Gitea => {
                                return Ok(format!("{ns}:{head_branch}"));
                            }
                            ForgeKind::GitLab => {
                                return Ok(ns);
                            }
                            ForgeKind::Bitbucket => {
                                return Ok(format!("{ns}/{}", repo.name));
                            }
                            ForgeKind::AzureDevOps => {
                                return Err(ForgeError {
                                    kind: ForgeErrorKind::Unsupported,
                                    message: "cross-repository pull requests are not supported for Azure DevOps".into(),
                                    git_kind: None,
                                    host: Some(repo.host.clone()),
                                    port: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(head_branch.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_humanize_branch() {
        assert_eq!(humanize_branch("feat/add-login-button"), "Add login button");
        assert_eq!(humanize_branch("fix_issue_123"), "Fix issue 123");
        assert_eq!(humanize_branch("main"), "Main");
    }
}
