use cawide_protocol::types::{
    ForgeAccount, ForgeAccountSource, ForgeError, ForgeErrorKind, ForgeKind, ForgeScheme,
};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ForgeAccountsStore {
    pub version: u32,
    pub accounts: Vec<StoreAccount>,
    #[serde(default)]
    pub helper_backups: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoreAccount {
    pub id: String,
    pub kind: String,
    pub scheme: String,
    pub host: String,
    pub login: String,
    pub token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub azure_org: Option<String>,
    pub is_default: bool,
    #[serde(default)]
    pub terminal_helper: bool,
}

impl StoreAccount {
    pub fn to_protocol(&self, healthy: bool, existing_terminal_helper: bool) -> ForgeAccount {
        let kind = match self.kind.as_str() {
            "github" => ForgeKind::GitHub,
            "gitlab" => ForgeKind::GitLab,
            "gitea" => ForgeKind::Gitea,
            "bitbucket" => ForgeKind::Bitbucket,
            "azuredevops" | "azure" => ForgeKind::AzureDevOps,
            _ => ForgeKind::Generic,
        };

        let scheme = match self.scheme.as_str() {
            "http" => ForgeScheme::Http,
            _ => ForgeScheme::Https,
        };

        ForgeAccount {
            id: self.id.clone(),
            kind,
            scheme,
            host: self.host.clone(),
            login: self.login.clone(),
            source: ForgeAccountSource::Cawide,
            is_default: self.is_default,
            healthy,
            terminal_helper: self.terminal_helper,
            existing_terminal_helper,
        }
    }
}

pub fn normalize_authority(host: &str, scheme: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    if let Some((h, port_str)) = trimmed.split_once(':') {
        if let Ok(p) = port_str.parse::<u16>() {
            if (scheme == "https" && p == 443) || (scheme == "http" && p == 80) {
                return h.to_string();
            }
        }
    }
    trimmed
}

pub fn generate_cawide_account_id() -> String {
    let mut bytes = [0u8; 8];
    for b in &mut bytes {
        *b = rand::random();
    }
    format!("cw:{}", hex::encode(bytes))
}

pub fn with_locked_store<F, R>(config_dir: &Path, f: F) -> Result<R, ForgeError>
where
    F: FnOnce(&mut ForgeAccountsStore) -> Result<R, ForgeError>,
{
    if !config_dir.exists() {
        let _ = std::fs::create_dir_all(config_dir);
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700));
        }
    }

    let lock_path = config_dir.join("forge-accounts.lock");
    let mut lock_opts = OpenOptions::new();
    lock_opts
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    lock_opts.mode(0o600);
    let lock_file = lock_opts.open(&lock_path).map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("failed to open lock file: {e}"),
        git_kind: None,
        host: None,
        port: None,
    })?;

    // Acquire exclusive file lock
    lock_file.lock_exclusive().map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("failed to acquire store lock: {e}"),
        git_kind: None,
        host: None,
        port: None,
    })?;

    struct LockGuard(File);
    impl Drop for LockGuard {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }
    let _guard = LockGuard(lock_file);

    let store_path = config_dir.join("forge-accounts.json");
    let mut store: ForgeAccountsStore = if store_path.exists() {
        match std::fs::read(&store_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(ForgeAccountsStore {
                version: 1,
                accounts: Vec::new(),
                helper_backups: HashMap::new(),
            }),
            Err(_) => ForgeAccountsStore {
                version: 1,
                accounts: Vec::new(),
                helper_backups: HashMap::new(),
            },
        }
    } else {
        ForgeAccountsStore {
            version: 1,
            accounts: Vec::new(),
            helper_backups: HashMap::new(),
        }
    };

    let result = f(&mut store)?;

    // Atomic write
    let json_bytes = serde_json::to_vec_pretty(&store).map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("failed to serialize store: {e}"),
        git_kind: None,
        host: None,
        port: None,
    })?;

    let rand_suffix: u64 = rand::random();
    let tmp_path = config_dir.join(format!(".forge-accounts.tmp.{rand_suffix}"));
    {
        let mut tmp_opts = OpenOptions::new();
        tmp_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        tmp_opts.mode(0o600);
        let mut tmp_file = tmp_opts.open(&tmp_path).map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("failed to open tmp store file: {e}"),
            git_kind: None,
            host: None,
            port: None,
        })?;

        use std::io::Write;
        tmp_file.write_all(&json_bytes).map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("failed to write store: {e}"),
            git_kind: None,
            host: None,
            port: None,
        })?;
        tmp_file.flush().map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("failed to flush store: {e}"),
            git_kind: None,
            host: None,
            port: None,
        })?;
        let _ = tmp_file.sync_all();
    }

    std::fs::rename(&tmp_path, &store_path).map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("failed to rename store file: {e}"),
        git_kind: None,
        host: None,
        port: None,
    })?;

    Ok(result)
}

pub async fn with_locked_store_async<F, R>(config_dir: PathBuf, f: F) -> Result<R, ForgeError>
where
    F: FnOnce(&mut ForgeAccountsStore) -> Result<R, ForgeError> + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || with_locked_store(&config_dir, f))
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: e.to_string(),
            git_kind: None,
            host: None,
            port: None,
        })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_roundtrip_and_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path();

        with_locked_store(cfg, |store| {
            store.accounts.push(StoreAccount {
                id: "cw:1122334455667788".into(),
                kind: "github".into(),
                scheme: "https".into(),
                host: "github.com".into(),
                login: "alice".into(),
                token: "token123".into(),
                refresh_token: None,
                expires_at: None,
                user_id: Some("12345".into()),
                azure_org: None,
                is_default: true,
                terminal_helper: false,
            });
            Ok(())
        })
        .unwrap();

        let store_path = cfg.join("forge-accounts.json");
        assert!(store_path.exists());

        #[cfg(unix)]
        {
            let meta = std::fs::metadata(&store_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let loaded = with_locked_store(cfg, |store| {
            assert_eq!(store.accounts.len(), 1);
            assert_eq!(store.accounts[0].login, "alice");
            Ok(())
        });
        assert!(loaded.is_ok());
    }

    #[test]
    fn test_store_concurrency_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().to_path_buf();

        // Initialize store with counter in version field
        with_locked_store(&cfg, |store| {
            store.version = 0;
            Ok(())
        })
        .unwrap();

        let cfg1 = cfg.clone();
        let t1 = std::thread::spawn(move || {
            for _ in 0..100 {
                with_locked_store(&cfg1, |store| {
                    store.version += 1;
                    Ok(())
                })
                .unwrap();
            }
        });

        let cfg2 = cfg.clone();
        let t2 = std::thread::spawn(move || {
            for _ in 0..100 {
                with_locked_store(&cfg2, |store| {
                    store.version += 1;
                    Ok(())
                })
                .unwrap();
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        with_locked_store(&cfg, |store| {
            assert_eq!(store.version, 200);
            Ok(())
        })
        .unwrap();
    }
}
