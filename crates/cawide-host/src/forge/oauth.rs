use super::http::ForgeHttp;
use super::store::{with_locked_store, StoreAccount};
use cawide_protocol::types::{
    ForgeError, ForgeErrorKind, ForgeKind, ForgeSignInChallenge, ForgeSignInState,
};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone)]
#[allow(dead_code)]
struct DeviceSession {
    kind: ForgeKind,
    host: String,
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    interval: u64,
    created_at: Instant,
    expires_in_secs: u32,
    state: ForgeSignInState,
}

static SESSIONS: Mutex<Option<HashMap<String, DeviceSession>>> = Mutex::new(None);

pub fn generate_session_id() -> String {
    let mut bytes = [0u8; 16];
    for b in &mut bytes {
        *b = rand::random();
    }
    hex::encode(bytes)
}

pub async fn start_sign_in(
    http: &ForgeHttp,
    client_ids: &HashMap<String, String>,
    kind: ForgeKind,
    host: &str,
) -> Result<ForgeSignInChallenge, ForgeError> {
    let client_id = client_ids.get(host).ok_or_else(|| ForgeError {
        kind: ForgeErrorKind::SignInUnavailable,
        message: format!("no OAuth client ID configured for host {host}"),
        git_kind: None,
        host: Some(host.to_string()),
        port: None,
    })?;

    if client_id.trim().is_empty() {
        return Err(ForgeError {
            kind: ForgeErrorKind::SignInUnavailable,
            message: format!("empty OAuth client ID configured for host {host}"),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        });
    }

    match kind {
        ForgeKind::GitHub => {
            let url = http.url(host, "https", "/login/device/code");
            let params = [
                ("client_id", client_id.as_str()),
                ("scope", "repo read:org workflow write:public_key"),
            ];

            let resp = http
                .client()
                .post(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(crate::forge::http::form_encode(&params))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if !resp.status().is_success() {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: format!("GitHub device sign in failed: {}", resp.status()),
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

            let device_code = json
                .get("device_code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: "missing device_code in response".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?
                .to_string();

            let user_code = json
                .get("user_code")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let verification_uri = json
                .get("verification_uri")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let verification_uri_complete = json
                .get("verification_uri_complete")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let expires_in_secs = json
                .get("expires_in")
                .and_then(|v| v.as_u64())
                .unwrap_or(900) as u32;
            let interval = json.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);

            let session_id = generate_session_id();
            let session = DeviceSession {
                kind,
                host: host.to_string(),
                device_code,
                user_code: user_code.clone(),
                verification_uri: verification_uri.clone(),
                verification_uri_complete: verification_uri_complete.clone(),
                interval,
                created_at: Instant::now(),
                expires_in_secs,
                state: ForgeSignInState::Pending,
            };

            {
                let mut lock = SESSIONS.lock();
                let map = lock.get_or_insert_with(HashMap::new);
                // Cancel any previous session for this host
                map.retain(|_, s| {
                    s.host != host || s.created_at.elapsed() > Duration::from_secs(600)
                });
                map.insert(session_id.clone(), session);
            }

            Ok(ForgeSignInChallenge {
                session_id,
                user_code,
                verification_uri,
                verification_uri_complete,
                expires_in_secs,
            })
        }
        ForgeKind::GitLab => {
            let url = http.url(host, "https", "/oauth/authorize_device");
            let params = [
                ("client_id", client_id.as_str()),
                ("scope", "api read_user write_repository"),
            ];

            let resp = http
                .client()
                .post(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(crate::forge::http::form_encode(&params))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?;

            if !resp.status().is_success() {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: format!("GitLab device sign in failed: {}", resp.status()),
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

            let device_code = json
                .get("device_code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: "missing device_code in response".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: None,
                })?
                .to_string();

            let user_code = json
                .get("user_code")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let verification_uri = json
                .get("verification_uri")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let verification_uri_complete = json
                .get("verification_uri_complete")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let expires_in_secs = json
                .get("expires_in")
                .and_then(|v| v.as_u64())
                .unwrap_or(300) as u32;
            let interval = json.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);

            let session_id = generate_session_id();
            let session = DeviceSession {
                kind,
                host: host.to_string(),
                device_code,
                user_code: user_code.clone(),
                verification_uri: verification_uri.clone(),
                verification_uri_complete: verification_uri_complete.clone(),
                interval,
                created_at: Instant::now(),
                expires_in_secs,
                state: ForgeSignInState::Pending,
            };

            {
                let mut lock = SESSIONS.lock();
                let map = lock.get_or_insert_with(HashMap::new);
                map.retain(|_, s| {
                    s.host != host || s.created_at.elapsed() > Duration::from_secs(600)
                });
                map.insert(session_id.clone(), session);
            }

            Ok(ForgeSignInChallenge {
                session_id,
                user_code,
                verification_uri,
                verification_uri_complete,
                expires_in_secs,
            })
        }
        _ => Err(ForgeError {
            kind: ForgeErrorKind::SignInUnavailable,
            message: "device sign-in only supported for GitHub and GitLab".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: None,
        }),
    }
}

pub async fn poll_sign_in(
    http: &ForgeHttp,
    client_ids: &HashMap<String, String>,
    config_dir: &std::path::Path,
    session_id: &str,
) -> Result<ForgeSignInState, ForgeError> {
    let session = {
        let lock = SESSIONS.lock();
        if let Some(ref map) = *lock {
            if let Some(s) = map.get(session_id) {
                s.clone()
            } else {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotFound,
                    message: "sign-in session not found".into(),
                    git_kind: None,
                    host: None,
                    port: None,
                });
            }
        } else {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: "sign-in session not found".into(),
                git_kind: None,
                host: None,
                port: None,
            });
        }
    };

    if !matches!(session.state, ForgeSignInState::Pending) {
        return Ok(session.state.clone());
    }

    if session.created_at.elapsed() > Duration::from_secs(session.expires_in_secs as u64) {
        let mut lock = SESSIONS.lock();
        if let Some(ref mut map) = *lock {
            if let Some(s) = map.get_mut(session_id) {
                s.state = ForgeSignInState::Expired;
            }
        }
        return Ok(ForgeSignInState::Expired);
    }

    let client_id = client_ids.get(&session.host).cloned().unwrap_or_default();

    match session.kind {
        ForgeKind::GitHub => {
            let url = http.url(&session.host, "https", "/login/oauth/access_token");
            let params = [
                ("client_id", client_id.as_str()),
                ("device_code", session.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ];

            let resp = http
                .client()
                .post(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(crate::forge::http::form_encode(&params))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(session.host.clone()),
                    port: None,
                })?;

            let json: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(err) = json.get("error").and_then(|v| v.as_str()) {
                match err {
                    "authorization_pending" => Ok(ForgeSignInState::Pending),
                    "slow_down" => Ok(ForgeSignInState::Pending),
                    "expired_token" => {
                        update_session_state(session_id, ForgeSignInState::Expired);
                        Ok(ForgeSignInState::Expired)
                    }
                    "access_denied" => {
                        let st = ForgeSignInState::Failed {
                            message: "access denied by user".into(),
                        };
                        update_session_state(session_id, st.clone());
                        Ok(st)
                    }
                    other => {
                        let desc = json
                            .get("error_description")
                            .and_then(|v| v.as_str())
                            .unwrap_or(other);
                        let st = ForgeSignInState::Failed {
                            message: desc.to_string(),
                        };
                        update_session_state(session_id, st.clone());
                        Ok(st)
                    }
                }
            } else if let Some(access_tok) = json.get("access_token").and_then(|v| v.as_str()) {
                // Fetch user info
                let user_url = http.url(&session.host, "https", "/user");
                let user_resp = http
                    .client()
                    .get(&user_url)
                    .header(reqwest::header::USER_AGENT, "cawide")
                    .header(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {access_tok}"),
                    )
                    .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                    .send()
                    .await
                    .map_err(|e| ForgeError {
                        kind: ForgeErrorKind::Network,
                        message: e.to_string(),
                        git_kind: None,
                        host: Some(session.host.clone()),
                        port: None,
                    })?;

                let user_json: Value = user_resp.json().await.unwrap_or(Value::Null);
                let login = user_json
                    .get("login")
                    .and_then(|v| v.as_str())
                    .unwrap_or("user")
                    .to_string();
                let user_id = user_json.get("id").map(|v| v.to_string());

                let id = super::store::generate_cawide_account_id();
                let store_acct = StoreAccount {
                    id: id.clone(),
                    kind: "github".into(),
                    scheme: "https".into(),
                    host: session.host.clone(),
                    login: login.clone(),
                    token: access_tok.to_string(),
                    refresh_token: None,
                    expires_at: None,
                    user_id,
                    azure_org: None,
                    is_default: false,
                    terminal_helper: false,
                };

                // Store account
                let account = with_locked_store(config_dir, |store| {
                    let is_first = !store.accounts.iter().any(|a| a.host == session.host);
                    let mut a = store_acct;
                    a.is_default = is_first;
                    store.accounts.push(a.clone());
                    Ok(a.to_protocol(true, false))
                })?;

                let st = ForgeSignInState::Succeeded { account };
                update_session_state(session_id, st.clone());
                Ok(st)
            } else {
                Ok(ForgeSignInState::Pending)
            }
        }
        ForgeKind::GitLab => {
            let url = http.url(&session.host, "https", "/oauth/token");
            let params = [
                ("client_id", client_id.as_str()),
                ("device_code", session.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ];

            let resp = http
                .client()
                .post(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(crate::forge::http::form_encode(&params))
                .send()
                .await
                .map_err(|e| ForgeError {
                    kind: ForgeErrorKind::Network,
                    message: e.to_string(),
                    git_kind: None,
                    host: Some(session.host.clone()),
                    port: None,
                })?;

            let json: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(err) = json.get("error").and_then(|v| v.as_str()) {
                match err {
                    "authorization_pending" => Ok(ForgeSignInState::Pending),
                    "slow_down" => Ok(ForgeSignInState::Pending),
                    "expired_token" => {
                        update_session_state(session_id, ForgeSignInState::Expired);
                        Ok(ForgeSignInState::Expired)
                    }
                    "access_denied" => {
                        let st = ForgeSignInState::Failed {
                            message: "access denied by user".into(),
                        };
                        update_session_state(session_id, st.clone());
                        Ok(st)
                    }
                    other => {
                        let desc = json
                            .get("error_description")
                            .and_then(|v| v.as_str())
                            .unwrap_or(other);
                        let st = ForgeSignInState::Failed {
                            message: desc.to_string(),
                        };
                        update_session_state(session_id, st.clone());
                        Ok(st)
                    }
                }
            } else if let Some(access_tok) = json.get("access_token").and_then(|v| v.as_str()) {
                let refresh_token = json
                    .get("refresh_token")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let expires_in = json
                    .get("expires_in")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(7200);

                let user_url = http.url(&session.host, "https", "/api/v4/user");
                let user_resp = http
                    .client()
                    .get(&user_url)
                    .header(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {access_tok}"),
                    )
                    .send()
                    .await
                    .map_err(|e| ForgeError {
                        kind: ForgeErrorKind::Network,
                        message: e.to_string(),
                        git_kind: None,
                        host: Some(session.host.clone()),
                        port: None,
                    })?;

                let user_json: Value = user_resp.json().await.unwrap_or(Value::Null);
                let login = user_json
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("user")
                    .to_string();
                let user_id = user_json.get("id").map(|v| v.to_string());

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let id = super::store::generate_cawide_account_id();
                let store_acct = StoreAccount {
                    id: id.clone(),
                    kind: "gitlab".into(),
                    scheme: "https".into(),
                    host: session.host.clone(),
                    login: login.clone(),
                    token: access_tok.to_string(),
                    refresh_token,
                    expires_at: Some(now + expires_in),
                    user_id,
                    azure_org: None,
                    is_default: false,
                    terminal_helper: false,
                };

                let account = with_locked_store(config_dir, |store| {
                    let is_first = !store.accounts.iter().any(|a| a.host == session.host);
                    let mut a = store_acct;
                    a.is_default = is_first;
                    store.accounts.push(a.clone());
                    Ok(a.to_protocol(true, false))
                })?;

                let st = ForgeSignInState::Succeeded { account };
                update_session_state(session_id, st.clone());
                Ok(st)
            } else {
                Ok(ForgeSignInState::Pending)
            }
        }
        _ => Ok(ForgeSignInState::Failed {
            message: "unsupported provider".into(),
        }),
    }
}

pub fn cancel_sign_in(session_id: &str) -> Result<(), ForgeError> {
    let mut lock = SESSIONS.lock();
    if let Some(ref mut map) = *lock {
        map.remove(session_id);
    }
    Ok(())
}

fn update_session_state(session_id: &str, state: ForgeSignInState) {
    let mut lock = SESSIONS.lock();
    if let Some(ref mut map) = *lock {
        if let Some(s) = map.get_mut(session_id) {
            s.state = state;
        }
    }
}
