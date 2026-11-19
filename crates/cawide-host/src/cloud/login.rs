use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use super::account::{self, Account};
use super::client::{CloudClient, CloudConfig};

pub async fn run_login(config_dir: &Path) -> anyhow::Result<()> {
    let cfg = CloudConfig::from_env()?;
    let client = CloudClient::new(&cfg)?;

    let host = crate::net::dispatcher::host_display_name();
    let start_payload = serde_json::json!({
        "client_name": format!("cawide CLI on {host}"),
    });

    let resp = client
        .post_json("/api/v1/auth/device/start", &start_payload, None)
        .await?;

    if resp.status != 200 {
        anyhow::bail!("{}", resp.error_message());
    }

    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).context("failed to parse device start response")?;

    let device_code = val
        .get("device_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing device_code in response"))?
        .to_string();
    let user_code = val
        .get("user_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing user_code in response"))?
        .to_string();
    let expires_in = val
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(600);
    let interval = val.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);

    println!(
        "To link this computer, open the Cawide app → Account → Link a Computer and enter:\n\n    {user_code}\n\nOnly approve a code you see on your own computer.\nWaiting for approval (expires in 10 minutes)..."
    );

    let start_time = tokio::time::Instant::now();
    let timeout = Duration::from_secs(expires_in);

    loop {
        if start_time.elapsed() >= timeout {
            anyhow::bail!("The login code expired. Run `cawide login` again.");
        }

        tokio::time::sleep(Duration::from_secs(interval)).await;

        let token_payload = serde_json::json!({
            "device_code": &device_code,
        });

        let token_resp = client
            .post_json("/api/v1/auth/device/token", &token_payload, None)
            .await?;

        if token_resp.status == 200 {
            let auth_val: serde_json::Value = serde_json::from_slice(&token_resp.body)
                .context("failed to parse auth response")?;

            let access_token = auth_val
                .get("access_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing access_token"))?
                .to_string();
            let refresh_token = auth_val
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing refresh_token"))?
                .to_string();
            let user_id = auth_val
                .pointer("/user/id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing user.id"))?
                .to_string();
            let email = auth_val
                .pointer("/user/email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing user.email"))?
                .to_string();

            let account = Account {
                user_id,
                email: email.clone(),
                access_token,
                refresh_token,
            };

            account::save(config_dir, &account)?;
            println!("Logged in as {email}");
            return Ok(());
        }

        if token_resp.status == 400 {
            let err_msg = token_resp.error_message();
            if err_msg == "authorization_pending" {
                continue;
            }
            if err_msg == "expired_token" {
                anyhow::bail!("The login code expired. Run `cawide login` again.");
            }
            anyhow::bail!("{err_msg}");
        }

        if token_resp.status == 403 {
            anyhow::bail!("Login was denied in the Cawide app.");
        }

        anyhow::bail!("{}", token_resp.error_message());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkOutcome {
    Unlinked,
    NotLinked,
    DaemonTooOld,
}

pub async fn unlink_this_computer(config_dir: &Path) -> anyhow::Result<UnlinkOutcome> {
    let socket = match std::env::var_os("CAWIDE_SOCKET") {
        Some(s) if !s.is_empty() => std::path::PathBuf::from(s),
        _ => crate::net::default_ipc_path(config_dir),
    };
    unlink_at_socket(config_dir, &socket).await
}

async fn unlink_at_socket(config_dir: &Path, socket: &Path) -> anyhow::Result<UnlinkOutcome> {
    match crate::net::send_ipc_request(socket, &crate::net::IpcRequest::AccountUnlink).await {
        Ok(crate::net::IpcResponse::Unlinked { was_linked }) => Ok(if was_linked {
            UnlinkOutcome::Unlinked
        } else {
            UnlinkOutcome::NotLinked
        }),
        Ok(crate::net::IpcResponse::Error(m)) => Err(anyhow::anyhow!(m)),
        Ok(_) => Err(anyhow::anyhow!("unexpected response")),
        Err(crate::net::NetError::DaemonNotRunning(_)) => {
            let auth_path = config_dir.join("authorized_keys");
            let (was_linked, _) = tokio::task::spawn_blocking(move || {
                let store = crate::auth::AuthorizedKeysStore::open_or_create(auth_path)?;
                store.mark_unlinked_local(true)
            })
            .await
            .context("unlink task failed")??;
            Ok(if was_linked {
                UnlinkOutcome::Unlinked
            } else {
                UnlinkOutcome::NotLinked
            })
        }
        Err(crate::net::NetError::UnexpectedIpcResponse(_)) => Ok(UnlinkOutcome::DaemonTooOld),
        Err(e) => Err(e.into()),
    }
}

pub async fn run_logout(config_dir: &Path) -> anyhow::Result<()> {
    match unlink_this_computer(config_dir).await {
        Ok(UnlinkOutcome::Unlinked) => {
            println!("✔ Unlinked this computer from your Cawide account");
        }
        Ok(UnlinkOutcome::NotLinked) => {}
        Ok(UnlinkOutcome::DaemonTooOld) => {
            println!("daemon too old; update cawide to unlink this computer");
        }
        Err(e) => {
            eprintln!("warning: could not unlink this computer: {e:#}");
        }
    }

    let existing = account::load(config_dir)?;
    let account = match existing {
        Some(a) => a,
        None => {
            println!("Not logged in.");
            return Ok(());
        }
    };

    if let Ok(cfg) = CloudConfig::from_env() {
        if let Ok(client) = CloudClient::new(&cfg) {
            let logout_payload = serde_json::json!({
                "refresh_token": account.refresh_token,
            });
            let res = client
                .post_json(
                    "/api/v1/auth/logout",
                    &logout_payload,
                    Some(&account.access_token),
                )
                .await;
            match res {
                Ok(r) if r.status == 200 || r.status == 204 => {}
                _ => {
                    eprintln!("warning: could not reach Cawide Cloud; removed local login only");
                }
            }
        }
    }

    account::delete(config_dir)?;
    println!("Logged out.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthorizedKeysStore;
    use crate::net::{
        bind_ipc_listener, default_ipc_path, IpcRequest, IpcResponse, MAX_IPC_FRAME_SIZE,
    };
    use cawide_account::{public_key_of, HostTrustSnapshot};
    use cawide_protocol::{read_length_prefixed, write_length_prefixed};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn unlink_this_computer_offline_store() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = default_ipc_path(tmp.path());
        assert_eq!(
            unlink_at_socket(tmp.path(), &sock).await.unwrap(),
            UnlinkOutcome::NotLinked
        );

        let store =
            AuthorizedKeysStore::open_or_create(tmp.path().join("authorized_keys")).unwrap();
        let pk = public_key_of(&[1u8; 32]);
        store.add_key(pk, "Phone".into()).unwrap();
        store.begin_claim(&pk, "acct-1", false, 100).unwrap();
        store
            .apply_account_sync(
                &HostTrustSnapshot {
                    version: 1,
                    account_id: "acct-1".into(),
                    locked: false,
                    devices: vec![],
                    links: vec![],
                    revoked: vec![],
                },
                100,
            )
            .unwrap();
        drop(store);

        assert_eq!(
            unlink_at_socket(tmp.path(), &sock).await.unwrap(),
            UnlinkOutcome::Unlinked
        );
        let reopened =
            AuthorizedKeysStore::open_or_create(tmp.path().join("authorized_keys")).unwrap();
        assert!(reopened.account_link().is_none());
        assert!(reopened.pending_unlink());
    }

    #[tokio::test]
    async fn unlink_this_computer_ipc_and_old_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = default_ipc_path(tmp.path());
        let mut listener = bind_ipc_listener(&sock).unwrap();

        let srv = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let req: Option<IpcRequest> = read_length_prefixed(&mut stream, MAX_IPC_FRAME_SIZE)
                .await
                .unwrap();
            assert_eq!(req, Some(IpcRequest::AccountUnlink));
            write_length_prefixed(
                &mut stream,
                &IpcResponse::Unlinked { was_linked: true },
                MAX_IPC_FRAME_SIZE,
            )
            .await
            .unwrap();
            drop(stream);

            // Second connection simulates an old daemon closing on unknown variant.
            let mut stream2 = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = stream2.read(&mut buf).await;
            drop(stream2);
        });

        assert_eq!(
            unlink_at_socket(tmp.path(), &sock).await.unwrap(),
            UnlinkOutcome::Unlinked
        );
        assert_eq!(
            unlink_at_socket(tmp.path(), &sock).await.unwrap(),
            UnlinkOutcome::DaemonTooOld
        );
        srv.await.unwrap();
    }
}
