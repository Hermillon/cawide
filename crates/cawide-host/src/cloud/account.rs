use std::future::Future;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::client::{ApiResponse, CloudClient};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub user_id: String,
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub fn account_path(config_dir: &Path) -> PathBuf {
    config_dir.join("account.json")
}

pub fn load(config_dir: &Path) -> anyhow::Result<Option<Account>> {
    let path = account_path(config_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let account: Account = serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse account from {}", path.display()))?;
            Ok(Some(account))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("failed to read account from {}", path.display()))),
    }
}

pub fn save(config_dir: &Path, account: &Account) -> anyhow::Result<()> {
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)
            .with_context(|| format!("failed to create config dir {}", config_dir.display()))?;
        #[cfg(unix)]
        let _ = std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700));
    }

    let target = account_path(config_dir);
    let mut temp = tempfile::NamedTempFile::new_in(config_dir).with_context(|| {
        format!(
            "failed to create temporary account file in {}",
            config_dir.display()
        )
    })?;

    let bytes = serde_json::to_vec_pretty(account).context("failed to serialize account")?;
    temp.write_all(&bytes)
        .context("failed to write account data")?;
    temp.flush().context("failed to flush account data")?;

    #[cfg(unix)]
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("failed to set 0600 permissions on account file")?;

    temp.persist(&target)
        .with_context(|| format!("failed to persist account file to {}", target.display()))?;

    Ok(())
}

pub fn delete(config_dir: &Path) -> anyhow::Result<()> {
    let path = account_path(config_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("failed to remove account file {}", path.display()))),
    }
}

pub async fn authed<F, Fut>(
    client: &CloudClient,
    config_dir: &Path,
    account: &mut Account,
    send: F,
) -> anyhow::Result<ApiResponse>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = anyhow::Result<ApiResponse>>,
{
    let resp = send(account.access_token.clone()).await?;
    if resp.status != 401 {
        return Ok(resp);
    }

    // On 401, refresh tokens
    let refresh_body = serde_json::json!({
        "refresh_token": account.refresh_token,
    });

    let refresh_resp = client
        .post_json("/api/v1/auth/refresh", &refresh_body, None)
        .await?;

    if refresh_resp.status == 200 {
        let val: serde_json::Value = serde_json::from_slice(&refresh_resp.body)
            .context("failed to parse refresh response JSON")?;
        let new_access = val
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing access_token in refresh response"))?
            .to_string();
        let new_refresh = val
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing refresh_token in refresh response"))?
            .to_string();

        account.access_token = new_access.clone();
        account.refresh_token = new_refresh;
        save(config_dir, account)?;

        return send(new_access).await;
    }

    if refresh_resp.status == 400 || refresh_resp.status == 401 {
        let _ = delete(config_dir);
        anyhow::bail!("Your Cawide login has expired. Run `cawide login` again.");
    }

    anyhow::bail!("{}", refresh_resp.error_message());
}
