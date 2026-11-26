use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::agent::observe::{uses_private_server, verified_id};
use crate::net::ipc::{send_ipc_request_with_timeout, IpcRequest, IpcResponse};

#[cfg(unix)]
fn exec_process(cmd: &str, args: &[String]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(cmd).args(args).exec();
    eprintln!("cawide: failed to exec {cmd}: {err}");
    std::process::exit(127);
}

#[cfg(windows)]
fn exec_process(cmd: &str, args: &[String]) -> ! {
    match std::process::Command::new(cmd).args(args).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("cawide: failed to spawn {cmd}: {err}");
            std::process::exit(127);
        }
    }
}

fn opencode_state_dir() -> PathBuf {
    if let Some(s) = std::env::var_os("XDG_STATE_HOME") {
        if !s.is_empty() {
            return PathBuf::from(s).join("opencode");
        }
    }
    if let Ok(h) = crate::net::ipc::home_dir() {
        return h.join(".local").join("state").join("opencode");
    }
    PathBuf::from(".local").join("state").join("opencode")
}

async fn check_opencode_service_live(state_dir: &Path) -> bool {
    let service_json = state_dir.join("service.json");
    let Ok(content) = std::fs::read_to_string(&service_json) else {
        return false;
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    let Some(url) = val.get("url").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(expected_pid) = val.get("pid").and_then(|v| v.as_u64()) else {
        return false;
    };
    let password = val.get("password").and_then(|v| v.as_str());

    let Ok(client) = reqwest::Client::builder().no_proxy().build() else {
        return false;
    };
    let info_url = format!("{}/api/info", url.trim_end_matches('/'));
    let mut req = client.get(&info_url).timeout(Duration::from_secs(2));
    if let Some(pw) = password {
        req = req.basic_auth("opencode", Some(pw));
    }
    let Ok(resp) = req.send().await else {
        return false;
    };
    if resp.status() != reqwest::StatusCode::OK {
        return false;
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return false;
    };
    body.get("pid").and_then(|v| v.as_u64()) == Some(expected_pid)
}

pub fn run_agent(agent: &str, args: &[String]) -> ! {
    if !matches!(agent, "codex" | "opencode") {
        eprintln!("cawide: unsupported agent '{agent}' (expected 'codex' or 'opencode')");
        std::process::exit(2);
    }

    let cawide_session_id = std::env::var("CAWIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let cawide_socket = std::env::var("CAWIDE_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());

    let plain_exec = cawide_session_id.is_none()
        || cawide_socket.is_none()
        || uses_private_server(agent, args)
        || verified_id(agent, args).is_some()
        || (agent == "codex"
            && std::env::var_os("CODEX_EXEC_SERVER_URL").is_some_and(|v| !v.is_empty()));

    if plain_exec {
        exec_process(agent, args);
    }

    let socket_path = PathBuf::from(cawide_socket.unwrap());
    let cwd = std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .unwrap_or_else(|_| PathBuf::from("."));

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cawide: phone status unavailable for {agent} ({e}); starting without it");
            exec_process(agent, args);
        }
    };

    let prepare_result = rt.block_on(async {
        if agent == "codex" {
            let _ = tokio::time::timeout(
                Duration::from_secs(60),
                tokio::process::Command::new("codex")
                    .args(["app-server", "daemon", "start"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status(),
            )
            .await;
        } else if agent == "opencode" {
            let state_dir = opencode_state_dir();
            if !check_opencode_service_live(&state_dir).await {
                let _ = tokio::time::timeout(
                    Duration::from_secs(60),
                    tokio::process::Command::new("opencode")
                        .args(["service", "start"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status(),
                )
                .await;
            }
        }

        let req = IpcRequest::PrepareAgentSession {
            agent: agent.to_string(),
            cwd,
        };
        send_ipc_request_with_timeout(&socket_path, &req, Duration::from_secs(25)).await
    });

    // Drop the tokio runtime BEFORE execing!
    drop(rt);

    match prepare_result {
        Ok(IpcResponse::AgentPrepared { id }) => {
            let mut final_args = Vec::new();
            if agent == "codex" {
                final_args.push("resume".to_string());
                final_args.push(id);
            } else {
                final_args.push("-s".to_string());
                final_args.push(id);
            }
            final_args.extend_from_slice(args);
            exec_process(agent, &final_args);
        }
        Ok(IpcResponse::Error(err)) => {
            eprintln!("cawide: phone status unavailable for {agent} ({err}); starting without it");
            exec_process(agent, args);
        }
        Ok(other) => {
            eprintln!("cawide: phone status unavailable for {agent} (unexpected response {other:?}); starting without it");
            exec_process(agent, args);
        }
        Err(err) => {
            eprintln!("cawide: phone status unavailable for {agent} ({err}); starting without it");
            exec_process(agent, args);
        }
    }
}
