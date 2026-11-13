use super::http::ForgeHttp;
use super::import::list_imported_accounts;
use super::store::{generate_cawide_account_id, with_locked_store, StoreAccount};
use cawide_protocol::types::{
    ForgeAccount, ForgeAccountsState, ForgeError, ForgeErrorKind, ForgeKind, ForgeScheme,
};
use regex::Regex;
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn validate_host(host: &str) -> Result<(), ForgeError> {
    if host.is_empty() || host.len() > 255 {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "host length must be between 1 and 255 characters".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        });
    }

    let re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?$").unwrap();
    if !re.is_match(host) {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "invalid host format".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        });
    }

    if let Some((_, port_str)) = host.split_once(':') {
        if let Ok(p) = port_str.parse::<u32>() {
            if !(1..=65535).contains(&p) {
                return Err(ForgeError {
                    kind: ForgeErrorKind::InvalidArgument,
                    message: "port must be between 1 and 65535".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }
        } else {
            return Err(ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "invalid port".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            });
        }
    }

    Ok(())
}

pub async fn list(
    config_dir: &Path,
    client_ids: &HashMap<String, String>,
    custom_path: Option<&str>,
) -> Result<ForgeAccountsState, ForgeError> {
    let store_accounts = with_locked_store(config_dir, |store| Ok(store.accounts.clone()))?;

    let _cawide_hosts: Vec<String> = store_accounts.iter().map(|a| a.host.clone()).collect();
    let has_cawide_default = |host: &str| {
        store_accounts
            .iter()
            .any(|a| a.host == host && a.is_default)
    };

    let imported = list_imported_accounts(custom_path, &has_cawide_default).await;

    let mut accounts = Vec::new();

    // Map store accounts
    for sa in store_accounts {
        let existing_terminal_helper = check_existing_terminal_helper(&sa.host, &sa.scheme).await;
        accounts.push(sa.to_protocol(true, existing_terminal_helper));
    }

    // Append imported accounts
    accounts.extend(imported);

    let mut device_sign_in_hosts = Vec::new();
    if client_ids
        .get("github.com")
        .is_some_and(|s| !s.trim().is_empty())
    {
        device_sign_in_hosts.push("github.com".to_string());
    }
    if client_ids
        .get("gitlab.com")
        .is_some_and(|s| !s.trim().is_empty())
    {
        device_sign_in_hosts.push("gitlab.com".to_string());
    }

    Ok(ForgeAccountsState {
        accounts,
        device_sign_in_hosts,
    })
}

async fn check_existing_terminal_helper(host: &str, scheme: &str) -> bool {
    let key = format!("credential.{scheme}://{host}.helper");
    let mut cmd = tokio::process::Command::new("git");
    cmd.args(["config", "--global", "--get-all", &key]);
    if let Ok(out) = cmd.output().await {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            return s
                .lines()
                .any(|l| !l.trim().is_empty() && !l.contains("git-credential"));
        }
    }
    false
}
#[allow(clippy::too_many_arguments)]
pub async fn add_token(
    http: &ForgeHttp,
    config_dir: &Path,
    kind: ForgeKind,
    scheme: ForgeScheme,
    host: &str,
    login_input: Option<String>,
    token: &str,
    azure_org: Option<String>,
    verify_url: Option<String>,
) -> Result<ForgeAccount, ForgeError> {
    validate_host(host)?;

    let token = token.trim();
    if token.is_empty() || token.len() > 4096 {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "token must be between 1 and 4096 characters".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        });
    }

    let scheme_str = match scheme {
        ForgeScheme::Https => "https",
        ForgeScheme::Http => "http",
    };

    let (login, user_id) = match kind {
        ForgeKind::GitHub => {
            let url = http.url(host, scheme_str, "/user");
            let resp = http
                .client()
                .get(&url)
                .header(reqwest::header::USER_AGENT, "cawide")
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if resp.status() == StatusCode::UNAUTHORIZED {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotAuthenticated,
                    message: "invalid GitHub token".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            let json: Value = resp.json().await.map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let login = json
                .get("login")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let uid = json.get("id").map(|v| v.to_string());
            (login, uid)
        }
        ForgeKind::GitLab => {
            let url = http.url(host, scheme_str, "/api/v4/user");
            let resp = http
                .client()
                .get(&url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if resp.status() == StatusCode::UNAUTHORIZED {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotAuthenticated,
                    message: "invalid GitLab token".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            let json: Value = resp.json().await.map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let login = json
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let uid = json.get("id").map(|v| v.to_string());
            (login, uid)
        }
        ForgeKind::Gitea => {
            let url = http.url(host, scheme_str, "/api/v1/user");
            let resp = http
                .client()
                .get(&url)
                .header(reqwest::header::AUTHORIZATION, format!("token {token}"))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if resp.status() == StatusCode::UNAUTHORIZED {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotAuthenticated,
                    message: "invalid Gitea token".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            let json: Value = resp.json().await.map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let login = json
                .get("login")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let uid = json.get("id").map(|v| v.to_string());
            (login, uid)
        }
        ForgeKind::Bitbucket => {
            let login = login_input.ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "login email is required for Bitbucket".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let url = http.url("api.bitbucket.org", "https", "/2.0/user");
            let resp = http
                .client()
                .get(&url)
                .basic_auth(&login, Some(token))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if resp.status() == StatusCode::UNAUTHORIZED {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotAuthenticated,
                    message: "invalid Bitbucket credentials".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            let json: Value = resp.json().await.map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let account_id = json
                .get("account_id")
                .or_else(|| json.get("uuid"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            (login, Some(account_id))
        }
        ForgeKind::AzureDevOps => {
            let org = azure_org.clone().ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "azure_org is required for Azure DevOps".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let url = http.url(host, "https", &format!("/{org}/_apis/connectionData"));
            let resp = http
                .client()
                .get(&url)
                .basic_auth("", Some(token))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if resp.status() == StatusCode::UNAUTHORIZED {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotAuthenticated,
                    message: "invalid Azure DevOps PAT".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            let json: Value = resp.json().await.map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: e.to_string(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let user_obj = json.get("authenticatedUser");
            let login = user_obj
                .and_then(|u| u.get("providerDisplayName"))
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let uid = user_obj.and_then(|u| u.get("id")).map(|v| v.to_string());
            (login, uid)
        }
        ForgeKind::Generic => {
            let login = login_input.ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "login is required for generic git remote".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            let vurl = verify_url.ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "verify_url is required for generic git remote".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;

            crate::rpc::git::validate::validate_remote_url(&vurl).map_err(|e| ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: e.message,
                git_kind: Some(e.kind),
                host: Some(host.to_string()),
                port: None,
            })?;

            if !vurl.starts_with("http://") && !vurl.starts_with("https://") {
                return Err(ForgeError {
                    kind: ForgeErrorKind::InvalidArgument,
                    message: "generic verify_url must be http or https".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            // Verify with git ls-remote --heads <vurl>
            let mut cmd = tokio::process::Command::new("git");
            cmd.current_dir(config_dir);
            cmd.args(["ls-remote", "--heads", &vurl]);
            cmd.env("GIT_TERMINAL_PROMPT", "0");
            cmd.env("CAWIDE_VERIFY_USER", &login);
            cmd.env("CAWIDE_VERIFY_TOKEN", token);
            cmd.env("GIT_CONFIG_COUNT", "1");
            let helper_key = format!("credential.{scheme_str}://{host}.helper");
            let helper_val = "!f(){ echo username=\"$CAWIDE_VERIFY_USER\"; echo password=\"$CAWIDE_VERIFY_TOKEN\"; }; f";
            cmd.env("GIT_CONFIG_KEY_0", helper_key);
            cmd.env("GIT_CONFIG_VALUE_0", helper_val);

            let out = tokio::time::timeout(Duration::from_secs(25), cmd.output())
                .await
                .map_err(|_| ForgeError {
                    kind: ForgeErrorKind::Timeout,
                    message: "generic git verification timed out".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let git_kind = crate::rpc::git::errors::classify(&stderr, Some(out.status), false);
                let forge_kind = match git_kind {
                    cawide_protocol::types::GitErrorKind::AuthenticationFailed => {
                        ForgeErrorKind::NotAuthenticated
                    }
                    _ => ForgeErrorKind::Other,
                };
                return Err(ForgeError {
                    kind: forge_kind,
                    message: stderr.trim().to_string(),
                    git_kind: Some(git_kind),
                    host: Some(host.to_string()),
                    port: None,
                });
            }

            (login, None)
        }
    };

    let kind_str = match kind {
        ForgeKind::GitHub => "github",
        ForgeKind::GitLab => "gitlab",
        ForgeKind::Gitea => "gitea",
        ForgeKind::Bitbucket => "bitbucket",
        ForgeKind::AzureDevOps => "azuredevops",
        ForgeKind::Generic => "generic",
    };

    let id = generate_cawide_account_id();
    let store_acct = StoreAccount {
        id: id.clone(),
        kind: kind_str.into(),
        scheme: scheme_str.into(),
        host: host.to_string(),
        login: login.clone(),
        token: token.to_string(),
        refresh_token: None,
        expires_at: None,
        user_id,
        azure_org,
        is_default: false,
        terminal_helper: false,
    };

    let account = with_locked_store(config_dir, |store| {
        let is_first = !store.accounts.iter().any(|a| a.host == host);
        let mut a = store_acct;
        a.is_default = is_first;
        store.accounts.push(a.clone());
        Ok(a.to_protocol(true, false))
    })?;

    Ok(account)
}

pub fn remove(config_dir: &Path, account_id: &str) -> Result<(), ForgeError> {
    if !account_id.starts_with("cw:") {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "Sign out with gh/glab on the computer".into(),
            git_kind: None,
            host: None,
            port: None,
        });
    }

    let mut removed_host: Option<(String, String, bool)> = None;

    with_locked_store(config_dir, |store| {
        if let Some(pos) = store.accounts.iter().position(|a| a.id == account_id) {
            let acct = store.accounts.remove(pos);
            let host = acct.host.clone();
            let remaining_cawide_for_host = store.accounts.iter().any(|a| a.host == host);
            removed_host = Some((
                acct.host,
                acct.scheme,
                !remaining_cawide_for_host && acct.terminal_helper,
            ));
            if acct.is_default {
                if let Some(first_other) = store.accounts.iter_mut().find(|a| a.host == host) {
                    first_other.is_default = true;
                }
            }
        }
        Ok(())
    })?;

    if let Some((host, _scheme, should_unset_helper)) = removed_host {
        if should_unset_helper {
            let _ = set_terminal_helper_sync(config_dir, &host, false);
        }
    }

    Ok(())
}

pub fn set_default(config_dir: &Path, account_id: &str) -> Result<(), ForgeError> {
    if !account_id.starts_with("cw:") {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "only Cawide accounts can be set as default".into(),
            git_kind: None,
            host: None,
            port: None,
        });
    }

    with_locked_store(config_dir, |store| {
        let target_host = store
            .accounts
            .iter()
            .find(|a| a.id == account_id)
            .map(|a| a.host.clone())
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: "account not found".into(),
                git_kind: None,
                host: None,
                port: None,
            })?;

        for a in &mut store.accounts {
            if a.host == target_host {
                a.is_default = a.id == account_id;
            }
        }
        Ok(())
    })
}

pub fn set_terminal_helper(config_dir: &Path, host: &str, enabled: bool) -> Result<(), ForgeError> {
    set_terminal_helper_sync(config_dir, host, enabled)
}

fn set_terminal_helper_sync(
    config_dir: &Path,
    host: &str,
    enabled: bool,
) -> Result<(), ForgeError> {
    let (scheme, _exe) = with_locked_store(config_dir, |store| {
        let acct = store
            .accounts
            .iter()
            .find(|a| a.host == host)
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: format!("no account found for host {host}"),
                git_kind: None,
                host: Some(host.to_string()),
                port: None,
            })?;
        Ok((acct.scheme.clone(), ()))
    })?;

    let helper_key = format!("credential.{scheme}://{host}.helper");
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cawide"));

    if enabled {
        // 1. Read existing helpers and backup
        let mut get_cmd = std::process::Command::new("git");
        get_cmd.args(["config", "--global", "--get-all", &helper_key]);
        let existing_helpers: Vec<String> = if let Ok(out) = get_cmd.output() {
            if out.status.success() {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.contains("git-credential"))
                    .map(str::to_string)
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        with_locked_store(config_dir, |store| {
            let key = format!("{scheme}://{host}");
            store.helper_backups.insert(key, existing_helpers);
            for a in &mut store.accounts {
                if a.host == host {
                    a.terminal_helper = true;
                }
            }
            Ok(())
        })?;

        // 2. Unset all
        let _ = std::process::Command::new("git")
            .args(["config", "--global", "--unset-all", &helper_key])
            .output();

        // 3. Add ''
        let _ = std::process::Command::new("git")
            .args(["config", "--global", "--add", &helper_key, ""])
            .output();

        // 4. Add helper command
        let helper_cmd = format!(
            "!'{}' git-credential --config-dir '{}'",
            current_exe.display(),
            config_dir.display()
        );
        let _ = std::process::Command::new("git")
            .args(["config", "--global", "--add", &helper_key, &helper_cmd])
            .output();
    } else {
        // Disabled: unset all and restore backups
        let _ = std::process::Command::new("git")
            .args(["config", "--global", "--unset-all", &helper_key])
            .output();

        let backups = with_locked_store(config_dir, |store| {
            let key = format!("{scheme}://{host}");
            let b = store.helper_backups.remove(&key).unwrap_or_default();
            for a in &mut store.accounts {
                if a.host == host {
                    a.terminal_helper = false;
                }
            }
            Ok(b)
        })?;

        for b in backups {
            let _ = std::process::Command::new("git")
                .args(["config", "--global", "--add", &helper_key, &b])
                .output();
        }
    }

    Ok(())
}
