use super::http::ForgeHttp;
use crate::rpc::git::GitEngine;
use cawide_protocol::types::{ForgeError, ForgeErrorKind, ForgeKind, ForgeScheme};
use parking_lot::Mutex;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

static PROBE_CACHE: Mutex<Option<HashMap<String, ForgeKind>>> = Mutex::new(None);
type ResolvedRepoCacheEntry = (
    Option<Vec<u8>>,
    Vec<(String, ForgeKind)>,
    ResolvedRepo,
    Instant,
);
static RESOLVED_REPO_CACHE: Mutex<Option<HashMap<PathBuf, ResolvedRepoCacheEntry>>> =
    Mutex::new(None);

pub fn detect_builtin_kind(host: &str) -> Option<ForgeKind> {
    let h = host.to_ascii_lowercase();
    let host_only = h.split(':').next().unwrap_or(&h);

    if host_only == "github.com" {
        Some(ForgeKind::GitHub)
    } else if host_only == "gitlab.com" {
        Some(ForgeKind::GitLab)
    } else if host_only == "bitbucket.org" {
        Some(ForgeKind::Bitbucket)
    } else if host_only == "dev.azure.com"
        || host_only == "ssh.dev.azure.com"
        || host_only.ends_with(".visualstudio.com")
    {
        Some(ForgeKind::AzureDevOps)
    } else if host_only == "codeberg.org" {
        Some(ForgeKind::Gitea)
    } else {
        None
    }
}

pub async fn detect_kind(
    http: &ForgeHttp,
    host: &str,
    scheme: ForgeScheme,
    known_accounts: &[ForgeKind],
) -> ForgeKind {
    if let Some(kind) = detect_builtin_kind(host) {
        return kind;
    }

    if let Some(kind) = known_accounts.first().cloned() {
        if kind != ForgeKind::Generic {
            return kind;
        }
    }

    let cache_key = format!(
        "{}:{}",
        match scheme {
            ForgeScheme::Https => "https",
            ForgeScheme::Http => "http",
        },
        host
    );
    {
        let lock = PROBE_CACHE.lock();
        if let Some(ref cache) = *lock {
            if let Some(k) = cache.get(&cache_key).cloned() {
                return k;
            }
        }
    }

    let scheme_str = match scheme {
        ForgeScheme::Https => "https",
        ForgeScheme::Http => "http",
    };

    let kind = probe_host(http, host, scheme_str).await;

    {
        let mut lock = PROBE_CACHE.lock();
        let cache = lock.get_or_insert_with(HashMap::new);
        cache.insert(cache_key, kind.clone());
    }

    kind
}

async fn probe_host(http: &ForgeHttp, host: &str, scheme_str: &str) -> ForgeKind {
    // 1. Probe GitLab: GET /api/v4/version
    let gl_url = http.url(host, scheme_str, "/api/v4/version");
    if let Ok(rb) = http
        .client()
        .get(&gl_url)
        .timeout(Duration::from_secs(5))
        .build()
    {
        if let Ok((status, _, bytes)) = http.send(rb, false).await {
            if status == StatusCode::OK || status == StatusCode::UNAUTHORIZED {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if json.is_object() {
                        return ForgeKind::GitLab;
                    }
                }
            }
        }
    }

    // 2. Probe Gitea: GET /api/v1/version
    let gitea_url = http.url(host, scheme_str, "/api/v1/version");
    if let Ok(rb) = http
        .client()
        .get(&gitea_url)
        .timeout(Duration::from_secs(5))
        .build()
    {
        if let Ok((status, _, bytes)) = http.send(rb, false).await {
            if status == StatusCode::OK {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if json.get("version").is_some() {
                        return ForgeKind::Gitea;
                    }
                }
            }
        }
    }

    // 3. Probe GitHub Enterprise: GET /api/v3/meta
    let gh_url = http.url(host, scheme_str, "/api/v3/meta");
    if let Ok(rb) = http
        .client()
        .get(&gh_url)
        .timeout(Duration::from_secs(5))
        .build()
    {
        if let Ok((status, _, bytes)) = http.send(rb, false).await {
            if status == StatusCode::OK {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if json.get("verifiable_password_authentication").is_some() {
                        return ForgeKind::GitHub;
                    }
                }
            }
        }
    }

    ForgeKind::Generic
}

#[derive(Debug, Clone)]
pub struct ResolvedRepo {
    pub kind: ForgeKind,
    pub scheme: ForgeScheme,
    pub host: String,
    pub namespace: String,
    pub name: String,
    pub remote_name: String,
    pub remote_url: String,
}

pub fn parse_coordinates(
    kind: ForgeKind,
    raw_path: &str,
    host: &str,
) -> Result<(String, String), ForgeError> {
    let clean = raw_path
        .trim_start_matches('/')
        .strip_suffix(".git")
        .unwrap_or(raw_path.trim_start_matches('/'));

    match kind {
        ForgeKind::AzureDevOps => {
            // Azure formats:
            // https://dev.azure.com/{org}/{project}/_git/{repo}
            // https://{org}.visualstudio.com/{project}/_git/{repo}
            // git@ssh.dev.azure.com:v3/{org}/{project}/{repo}
            if let Some(rest) = clean.strip_prefix("v3/") {
                let parts: Vec<&str> = rest.split('/').collect();
                if parts.len() >= 3 {
                    return Ok((format!("{}/{}", parts[0], parts[1]), parts[2].to_string()));
                }
            }

            if let Some((prefix, repo)) = clean.split_once("/_git/") {
                if host.ends_with(".visualstudio.com") {
                    let org = host.strip_suffix(".visualstudio.com").unwrap_or(host);
                    let project = prefix.trim_matches('/');
                    return Ok((format!("{org}/{project}"), repo.to_string()));
                } else {
                    let parts: Vec<&str> = prefix.split('/').filter(|s| !s.is_empty()).collect();
                    if parts.len() >= 2 {
                        return Ok((format!("{}/{}", parts[0], parts[1]), repo.to_string()));
                    }
                }
            }

            let parts: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() >= 3 {
                return Ok((format!("{}/{}", parts[0], parts[1]), parts[2].to_string()));
            }

            Err(ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: format!("cannot parse Azure DevOps coordinates from path: {clean}"),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })
        }
        ForgeKind::GitLab => {
            let parts: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() < 2 {
                return Err(ForgeError {
                    kind: ForgeErrorKind::InvalidArgument,
                    message: format!(
                        "GitLab repository path must have at least 2 segments: {clean}"
                    ),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }
            let name = parts.last().unwrap().to_string();
            let namespace = parts[..parts.len() - 1].join("/");
            Ok((namespace, name))
        }
        _ => {
            // GitHub, Gitea, Bitbucket, Generic: exactly 2 segments namespace/name
            let parts: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() == 2 {
                Ok((parts[0].to_string(), parts[1].to_string()))
            } else if parts.len() > 2 {
                // Take first as namespace, rest or last as name
                let name = parts.last().unwrap().to_string();
                let namespace = parts[0].to_string();
                Ok((namespace, name))
            } else {
                Err(ForgeError {
                    kind: ForgeErrorKind::InvalidArgument,
                    message: format!(
                        "repository path must have 2 segments (namespace/name): {clean}"
                    ),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })
            }
        }
    }
}

pub async fn resolve_repo(
    engine: &GitEngine,
    http: &ForgeHttp,
    known_accounts: &[(String, ForgeKind)],
) -> Result<ResolvedRepo, ForgeError> {
    let root = engine.root().to_path_buf();
    let config_bytes = crate::rpc::git::read_git_config_bytes(&root);

    {
        let lock = RESOLVED_REPO_CACHE.lock();
        if let Some(cache) = lock.as_ref() {
            if let Some((cached_cfg, cached_accts, res, ts)) = cache.get(&root) {
                if ts.elapsed() < Duration::from_secs(30)
                    && *cached_cfg == config_bytes
                    && cached_accts.as_slice() == known_accounts
                {
                    return Ok(res.clone());
                }
            }
        }
    }

    let remotes = crate::rpc::git::remotes::list_remotes(engine)
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::GitFailed,
            message: e.message,
            git_kind: Some(e.kind),
            host: e.host,
            port: e.port,
        })?;

    if remotes.is_empty() {
        return Err(ForgeError {
            kind: ForgeErrorKind::NoForgeRemote,
            message: "no git remotes found in repository".into(),
            git_kind: None,
            host: None,
            port: None,
        });
    }

    // Check custom cawide-forge config
    let ctx = engine.build_request_ctx().await.ok();
    let mut configured_remote_name = None;
    if let Some(ref c) = ctx {
        let cmd = engine.git_cmd(
            c,
            &["config", "--get-regexp", r"^remote\..*\.cawide-forge$"],
        );
        if let Ok(out) = crate::rpc::process::run(
            cmd,
            crate::rpc::process::RunOpts {
                stdin: None,
                stdout_cap: 4096,
                timeout: Duration::from_secs(5),
            },
        )
        .await
        {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    let mut parts = line.split_whitespace();
                    if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                        let is_enabled = matches!(
                            val.trim().to_ascii_lowercase().as_str(),
                            "true" | "yes" | "1" | "on"
                        );
                        if is_enabled {
                            if let Some(remote) = key
                                .strip_prefix("remote.")
                                .and_then(|k| k.strip_suffix(".cawide-forge"))
                            {
                                if remotes.iter().any(|r| r.name == remote) {
                                    configured_remote_name = Some(remote.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Map each remote to detected kind
    let mut candidates = Vec::new();
    for r in &remotes {
        let (host, raw_path, scheme) =
            match crate::rpc::git::remote_url::parse_remote_url(&r.fetch_url) {
                Some(p) => {
                    let host_str = match p.port {
                        Some(port) => format!("{}:{}", p.host, port),
                        None => p.host,
                    };
                    let scheme_enum = if p.scheme == "http" {
                        ForgeScheme::Http
                    } else {
                        ForgeScheme::Https
                    };
                    (host_str, p.path, scheme_enum)
                }
                None => continue,
            };

        if host.is_empty() {
            continue;
        }

        let matching_kinds: Vec<ForgeKind> = known_accounts
            .iter()
            .filter(|(h, _)| h == &host)
            .map(|(_, k)| k.clone())
            .collect();

        let kind = detect_kind(http, &host, scheme.clone(), &matching_kinds).await;
        if kind != ForgeKind::Generic {
            if let Ok((namespace, name)) = parse_coordinates(kind.clone(), &raw_path, &host) {
                candidates.push(ResolvedRepo {
                    kind,
                    scheme,
                    host,
                    namespace,
                    name,
                    remote_name: r.name.clone(),
                    remote_url: r.fetch_url.clone(),
                });
            }
        }
    }

    if candidates.is_empty() {
        return Err(ForgeError {
            kind: ForgeErrorKind::NoForgeRemote,
            message: "no forge remote candidates found".into(),
            git_kind: None,
            host: None,
            port: None,
        });
    }

    // Priority: configured remote -> upstream -> origin -> first candidate
    let chosen = if let Some(ref target) = configured_remote_name {
        if let Some(c) = candidates.iter().find(|c| &c.remote_name == target) {
            c.clone()
        } else if let Some(c) = candidates.iter().find(|c| c.remote_name == "upstream") {
            c.clone()
        } else if let Some(c) = candidates.iter().find(|c| c.remote_name == "origin") {
            c.clone()
        } else {
            candidates[0].clone()
        }
    } else if let Some(c) = candidates.iter().find(|c| c.remote_name == "upstream") {
        c.clone()
    } else if let Some(c) = candidates.iter().find(|c| c.remote_name == "origin") {
        c.clone()
    } else {
        candidates[0].clone()
    };

    {
        let mut lock = RESOLVED_REPO_CACHE.lock();
        let cache = lock.get_or_insert_with(HashMap::new);
        cache.insert(
            root,
            (
                config_bytes,
                known_accounts.to_vec(),
                chosen.clone(),
                Instant::now(),
            ),
        );
    }

    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coordinates_github() {
        let (ns, name) =
            parse_coordinates(ForgeKind::GitHub, "/owner/repo.git", "github.com").unwrap();
        assert_eq!(ns, "owner");
        assert_eq!(name, "repo");
    }

    #[test]
    fn test_parse_coordinates_gitlab_subgroups() {
        let (ns, name) = parse_coordinates(
            ForgeKind::GitLab,
            "/group/sub/sub2/project.git",
            "gitlab.com",
        )
        .unwrap();
        assert_eq!(ns, "group/sub/sub2");
        assert_eq!(name, "project");
    }

    #[test]
    fn test_parse_coordinates_azure() {
        let (ns, name) = parse_coordinates(
            ForgeKind::AzureDevOps,
            "/myorg/myproj/_git/myrepo",
            "dev.azure.com",
        )
        .unwrap();
        assert_eq!(ns, "myorg/myproj");
        assert_eq!(name, "myrepo");
    }
}
