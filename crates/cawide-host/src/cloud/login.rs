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

pub async fn run_logout(config_dir: &Path) -> anyhow::Result<()> {
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
