use super::import::fetch_imported_token;
use super::store::{normalize_authority, with_locked_store};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn run_git_credential(action: &str, config_dir: Option<PathBuf>) {
    let cfg = config_dir.unwrap_or_else(|| {
        std::env::var_os("CAWIDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("~"));
                home.join(".config/cawide")
            })
    });

    match action {
        "get" => handle_get(&cfg),
        "store" | "erase" => {
            // No-op for git-credential store / erase
            std::process::exit(0);
        }
        _ => {
            eprintln!("unknown git-credential action: {action}");
            std::process::exit(0);
        }
    }
}

fn handle_get(config_dir: &Path) {
    let stdin = io::stdin();
    let mut protocol = String::new();
    let mut host = String::new();

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            break;
        }

        if let Some((k, v)) = line.split_once('=') {
            match k {
                "protocol" => protocol = v.trim().to_ascii_lowercase(),
                "host" => host = v.trim().to_string(),
                _ => {}
            }
        }
    }

    if protocol.is_empty() || host.is_empty() {
        std::process::exit(0);
    }

    let authority = normalize_authority(&host, &protocol);
    let explicit_account_id = std::env::var("CAWIDE_FORGE_ACCOUNT").ok();

    // Check Cawide accounts in store
    let resolved_cawide = with_locked_store(config_dir, |store| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let matching_idx = if let Some(ref explicit_id) = explicit_account_id {
            store.accounts.iter().position(|a| {
                a.id == *explicit_id
                    && a.scheme == protocol
                    && normalize_authority(&a.host, &a.scheme) == authority
            })
        } else {
            store.accounts.iter().position(|a| {
                a.is_default
                    && a.scheme == protocol
                    && normalize_authority(&a.host, &a.scheme) == authority
            })
        };

        if let Some(idx) = matching_idx {
            let acct = &mut store.accounts[idx];

            // Check if token refresh is needed (GitLab OAuth expires within 60s)
            if let (Some(ref refresh_tok), Some(expires_at)) =
                (&acct.refresh_token, acct.expires_at)
            {
                if expires_at - now < 60 {
                    // Attempt synchronous token refresh if refresh_token is present
                    if let Ok(new_token) =
                        refresh_gitlab_token_sync(&acct.host, &acct.scheme, refresh_tok)
                    {
                        acct.token = new_token.0;
                        if let Some(new_ref) = new_token.1 {
                            acct.refresh_token = Some(new_ref);
                        }
                        if let Some(new_exp) = new_token.2 {
                            acct.expires_at = Some(now + new_exp);
                        }
                    }
                }
            }

            Ok(Some(acct.clone()))
        } else {
            Ok(None)
        }
    });

    if let Ok(Some(acct)) = resolved_cawide {
        let username = git_username_for_kind(&acct.kind, &acct.login);
        print_credential(&username, &acct.token);
        std::process::exit(0);
    }

    // If not in Cawide store, check if it's an imported account
    if let Some(ref explicit_id) = explicit_account_id {
        if explicit_id.starts_with("gh:") || explicit_id.starts_with("glab:") {
            let parts: Vec<&str> = explicit_id.split(':').collect();
            if parts.len() >= 3 {
                let imp_host = parts[1];
                let imp_login = parts[2];
                if normalize_authority(imp_host, &protocol) == authority {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    if let Ok(rt) = rt {
                        if let Ok(token) = rt.block_on(fetch_imported_token(
                            explicit_id,
                            imp_host,
                            imp_login,
                            None,
                        )) {
                            let kind = if explicit_id.starts_with("gh:") {
                                "github"
                            } else {
                                "gitlab"
                            };
                            let username = git_username_for_kind(kind, imp_login);
                            print_credential(&username, &token);
                            std::process::exit(0);
                        }
                    }
                }
            }
        }
    }

    // No credential found -> exit 0 with empty stdout
    std::process::exit(0);
}

fn print_credential(username: &str, token: &str) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "username={username}");
    let _ = writeln!(stdout, "password={token}");
    let _ = stdout.flush();
}

pub fn git_username_for_kind(kind: &str, login: &str) -> String {
    match kind.to_ascii_lowercase().as_str() {
        "github" => "x-access-token".to_string(),
        "gitlab" => "oauth2".to_string(),
        "bitbucket" => "x-bitbucket-api-token-auth".to_string(),
        _ => login.to_string(),
    }
}

fn refresh_gitlab_token_sync(
    host: &str,
    scheme: &str,
    refresh_token: &str,
) -> Result<(String, Option<String>, Option<i64>), ()> {
    let client_id = std::env::var("CAWIDE_GITLAB_OAUTH_CLIENT_ID")
        .ok()
        .or_else(|| option_env!("CAWIDE_GITLAB_OAUTH_CLIENT_ID").map(str::to_string))
        .unwrap_or_default();

    if client_id.is_empty() {
        return Err(());
    }

    let url = format!("{scheme}://{host}/oauth/token");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;

    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| ())?;

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &client_id),
        ];

        let body = crate::forge::http::form_encode(&params);
        let res = client
            .post(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(|_| ())?;
        if !res.status().is_success() {
            return Err(());
        }

        let json: serde_json::Value = res.json().await.map_err(|_| ())?;
        let access_tok = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or(())?
            .to_string();
        let new_ref = json
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let expires_in = json.get("expires_in").and_then(|v| v.as_i64());

        Ok((access_tok, new_ref, expires_in))
    })
}
