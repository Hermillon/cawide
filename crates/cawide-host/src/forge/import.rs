use cawide_protocol::types::{
    ForgeAccount, ForgeAccountSource, ForgeError, ForgeErrorKind, ForgeKind, ForgeScheme,
};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

static IMPORT_CACHE: Mutex<Option<(Vec<ForgeAccount>, Instant)>> = Mutex::new(None);
static TOKEN_CACHE: Mutex<Option<HashMap<String, (String, Instant)>>> = Mutex::new(None);

pub fn find_executable(name: &str, custom_path: Option<&str>) -> Option<PathBuf> {
    let full_path = match custom_path {
        Some("") => String::new(),
        Some(cp) => {
            let sys_path = std::env::var("PATH").unwrap_or_default();
            #[cfg(unix)]
            {
                format!("{cp}:{sys_path}:/opt/homebrew/bin:/usr/local/bin")
            }
            #[cfg(not(unix))]
            {
                format!("{cp};{sys_path}")
            }
        }
        None => {
            let sys_path = std::env::var("PATH").unwrap_or_default();
            #[cfg(unix)]
            {
                format!("{sys_path}:/opt/homebrew/bin:/usr/local/bin")
            }
            #[cfg(not(unix))]
            {
                sys_path
            }
        }
    };

    for dir in std::env::split_paths(&full_path) {
        #[cfg(windows)]
        {
            let candidates =
                if name.ends_with(".exe") || name.ends_with(".cmd") || name.ends_with(".bat") {
                    vec![dir.join(name)]
                } else {
                    vec![dir.join(format!("{name}.exe")), dir.join(name)]
                };
            for p in candidates {
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let p = dir.join(name);
            if p.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(m) = p.metadata() {
                        if m.permissions().mode() & 0o111 != 0 {
                            return Some(p);
                        }
                    }
                }
                #[cfg(not(unix))]
                return Some(p);
            }
        }
    }
    None
}

pub async fn list_imported_accounts(
    custom_path: Option<&str>,
    has_cawide_default: &(dyn Fn(&str) -> bool + Send + Sync),
) -> Vec<ForgeAccount> {
    // Check cache (30s)
    {
        let lock = IMPORT_CACHE.lock();
        if let Some((accounts, ts)) = lock.as_ref() {
            if ts.elapsed() < Duration::from_secs(30) && custom_path.is_none() {
                return accounts.clone();
            }
        }
    }

    let mut accounts = Vec::new();

    // 1. Try gh CLI
    if let Some(gh_exe) = find_executable("gh", custom_path) {
        if let Ok(gh_accounts) = import_gh_accounts(&gh_exe, has_cawide_default).await {
            accounts.extend(gh_accounts);
        }
    }

    // 2. Try glab CLI
    if let Some(glab_exe) = find_executable("glab", custom_path) {
        if let Ok(glab_accounts) = import_glab_accounts(&glab_exe, has_cawide_default).await {
            accounts.extend(glab_accounts);
        }
    }
    // 3. Try environment tokens (unless isolated via empty custom_path)
    if custom_path != Some("") {
        if let Ok(tok) = std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")) {
            if !tok.trim().is_empty() {
                let is_default = !has_cawide_default("github.com")
                    && !accounts
                        .iter()
                        .any(|a| a.host == "github.com" && a.is_default);
                accounts.push(ForgeAccount {
                    id: "env:github.com:token".to_string(),
                    kind: ForgeKind::GitHub,
                    scheme: ForgeScheme::Https,
                    host: "github.com".to_string(),
                    login: "token".to_string(),
                    // Reuses GhCli source variant as environment token proxy
                    source: ForgeAccountSource::GhCli,
                    is_default,
                    healthy: true,
                    terminal_helper: false,
                    existing_terminal_helper: false,
                });
            }
        }
        if let Ok(tok) = std::env::var("GLAB_TOKEN").or_else(|_| std::env::var("GITLAB_TOKEN")) {
            if !tok.trim().is_empty() {
                let is_default = !has_cawide_default("gitlab.com")
                    && !accounts
                        .iter()
                        .any(|a| a.host == "gitlab.com" && a.is_default);
                accounts.push(ForgeAccount {
                    id: "env:gitlab.com:token".to_string(),
                    kind: ForgeKind::GitLab,
                    scheme: ForgeScheme::Https,
                    host: "gitlab.com".to_string(),
                    login: "token".to_string(),
                    // Reuses GlabCli source variant as environment token proxy
                    source: ForgeAccountSource::GlabCli,
                    is_default,
                    healthy: true,
                    terminal_helper: false,
                    existing_terminal_helper: false,
                });
            }
        }
    }

    if custom_path.is_none() {
        let mut lock = IMPORT_CACHE.lock();
        *lock = Some((accounts.clone(), Instant::now()));
    }
    accounts
}

async fn import_gh_accounts(
    gh_exe: &Path,
    has_cawide_default: &(dyn Fn(&str) -> bool + Send + Sync),
) -> Result<Vec<ForgeAccount>, ()> {
    let mut cmd = tokio::process::Command::new(gh_exe);
    cmd.args(["auth", "status", "--json", "hosts"]);
    let out = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    if !out.status.success() {
        return Err(());
    }

    let json: Value = serde_json::from_slice(&out.stdout).map_err(|_| ())?;
    let mut accounts = Vec::new();

    let hosts_obj = if let Some(h) = json.get("hosts").and_then(|h| h.as_object()) {
        h
    } else if let Some(obj) = json.as_object() {
        obj
    } else {
        return Ok(accounts);
    };

    for (host, users_val) in hosts_obj {
        let users_arr = match users_val {
            Value::Array(arr) => arr.clone(),
            Value::Object(_) => vec![users_val.clone()],
            _ => continue,
        };

        for u in users_arr {
            let login = u
                .get("login")
                .or_else(|| u.get("user"))
                .or_else(|| u.get("username"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if login.is_empty() {
                continue;
            }

            let active = u.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
            let healthy = u
                .get("state")
                .and_then(|v| v.as_str())
                .map(|s| s == "success")
                .unwrap_or(true);

            let is_default = active && !has_cawide_default(host);
            accounts.push(ForgeAccount {
                id: format!("gh:{host}:{login}"),
                kind: ForgeKind::GitHub,
                scheme: ForgeScheme::Https,
                host: host.clone(),
                login,
                source: ForgeAccountSource::GhCli,
                is_default,
                healthy,
                terminal_helper: false,
                existing_terminal_helper: false,
            });
        }
    }

    Ok(accounts)
}

async fn import_glab_accounts(
    glab_exe: &Path,
    has_cawide_default: &(dyn Fn(&str) -> bool + Send + Sync),
) -> Result<Vec<ForgeAccount>, ()> {
    let mut cmd = tokio::process::Command::new(glab_exe);
    cmd.args(["auth", "status", "--all", "--output", "json"]);
    let out = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    if !out.status.success() {
        return Err(());
    }

    let json: Value = serde_json::from_slice(&out.stdout).map_err(|_| ())?;
    let mut accounts = Vec::new();

    if let Some(obj) = json.as_object() {
        for (host, users_val) in obj {
            let users_arr = match users_val {
                Value::Array(arr) => arr.clone(),
                Value::Object(_) => vec![users_val.clone()],
                _ => continue,
            };

            for u in users_arr {
                let login = u
                    .get("username")
                    .or_else(|| u.get("user"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();

                if login.is_empty() {
                    continue;
                }

                let is_default = !has_cawide_default(host);
                accounts.push(ForgeAccount {
                    id: format!("glab:{host}:{login}"),
                    kind: ForgeKind::GitLab,
                    scheme: ForgeScheme::Https,
                    host: host.clone(),
                    login,
                    source: ForgeAccountSource::GlabCli,
                    is_default,
                    healthy: true,
                    terminal_helper: false,
                    existing_terminal_helper: false,
                });
            }
        }
    }

    Ok(accounts)
}

pub async fn fetch_imported_token(
    account_id: &str,
    host: &str,
    login: &str,
    custom_path: Option<&str>,
) -> Result<String, ForgeError> {
    // Check token cache (30s TTL)
    if custom_path.is_none() {
        let lock = TOKEN_CACHE.lock();
        if let Some(cache) = lock.as_ref() {
            if let Some((token, ts)) = cache.get(account_id) {
                if ts.elapsed() < Duration::from_secs(30) {
                    return Ok(token.clone());
                }
            }
        }
    }

    if account_id.starts_with("env:") {
        let token = if host == "github.com" || account_id == "env:github.com:token" {
            std::env::var("GH_TOKEN")
                .or_else(|_| std::env::var("GITHUB_TOKEN"))
                .ok()
        } else if host == "gitlab.com" || account_id == "env:gitlab.com:token" {
            std::env::var("GLAB_TOKEN")
                .or_else(|_| std::env::var("GITLAB_TOKEN"))
                .ok()
        } else {
            None
        };
        let token = token
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::NotAuthenticated,
                message: format!("environment token not found for {host}"),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;
        if custom_path.is_none() {
            let mut lock = TOKEN_CACHE.lock();
            let cache = lock.get_or_insert_with(HashMap::new);
            cache.insert(account_id.to_string(), (token.clone(), Instant::now()));
        }
        Ok(token)
    } else if account_id.starts_with("gh:") {
        let gh_exe = find_executable("gh", custom_path).ok_or_else(|| ForgeError {
            kind: ForgeErrorKind::NotAuthenticated,
            message: "gh CLI not found on system PATH".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        })?;

        let mut cmd = tokio::process::Command::new(&gh_exe);
        cmd.args(["auth", "token", "--hostname", host, "--user", login]);
        let out = tokio::time::timeout(Duration::from_secs(10), cmd.output())
            .await
            .map_err(|_| ForgeError {
                kind: ForgeErrorKind::Timeout,
                message: "gh auth token timed out".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

        if !out.status.success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotAuthenticated,
                message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            });
        }

        let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if token.is_empty() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotAuthenticated,
                message: "empty token returned by gh auth token".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            });
        }
        if custom_path.is_none() {
            let mut lock = TOKEN_CACHE.lock();
            let cache = lock.get_or_insert_with(HashMap::new);
            cache.insert(account_id.to_string(), (token.clone(), Instant::now()));
        }
        Ok(token)
    } else if account_id.starts_with("glab:") {
        let glab_exe = find_executable("glab", custom_path).ok_or_else(|| ForgeError {
            kind: ForgeErrorKind::NotAuthenticated,
            message: "glab CLI not found on system PATH".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        })?;

        let mut cmd = tokio::process::Command::new(&glab_exe);
        cmd.args(["config", "get", "token", "--host", host]);
        let out = tokio::time::timeout(Duration::from_secs(10), cmd.output())
            .await
            .map_err(|_| ForgeError {
                kind: ForgeErrorKind::Timeout,
                message: "glab config get token timed out".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

        if !out.status.success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotAuthenticated,
                message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            });
        }

        let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if token.is_empty() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotAuthenticated,
                message: "empty token returned by glab config get token".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            });
        }
        if custom_path.is_none() {
            let mut lock = TOKEN_CACHE.lock();
            let cache = lock.get_or_insert_with(HashMap::new);
            cache.insert(account_id.to_string(), (token.clone(), Instant::now()));
        }
        Ok(token)
    } else {
        Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: format!("not an imported account id: {account_id}"),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_import_gh_accounts_parses_login_field() {
        let tmp = tempfile::tempdir().unwrap();
        let gh_path = tmp.path().join("gh");
        let script = r#"#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
    cat <<'EOF'
{
  "hosts": {
    "github.com": [
      {
        "login": "octocat",
        "state": "success",
        "active": true
      }
    ]
  }
}
EOF
fi
"#;
        std::fs::write(&gh_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let accounts = import_gh_accounts(&gh_path, &|_| false).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].login, "octocat");
        assert!(accounts[0].healthy);
    }
}
