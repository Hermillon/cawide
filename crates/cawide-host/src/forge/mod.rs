pub mod accounts;
pub mod adapters;
pub mod capabilities;
pub mod checkout;
pub mod config;
pub mod create;
pub mod credentials;
pub mod dispatch;
pub mod helper;
pub mod http;
pub mod import;
pub mod oauth;
pub mod repo;
pub mod ssh;
pub mod store;
pub mod text;

pub use config::ForgeHostConfig;
pub use credentials::{ForgeCredentialSource, GitAuthInjection, NoForgeCredentials};
pub use dispatch::{handle_accounts, handle_repo};

use crate::forge::http::ForgeHttp;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ForgeService {
    config_dir: PathBuf,
    pub config: ForgeHostConfig,
    http: ForgeHttp,
}

impl ForgeService {
    pub fn new(config_dir: PathBuf, config: ForgeHostConfig) -> Self {
        let http = ForgeHttp::new(config.endpoint_overrides.clone());
        Self {
            config_dir,
            config,
            http,
        }
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn http(&self) -> &ForgeHttp {
        &self.http
    }
}

impl ForgeCredentialSource for ForgeService {
    fn auth_for(&self, remote_url: &str, account: Option<&str>) -> GitAuthInjection {
        let parsed = match crate::rpc::git::remote_url::parse_remote_url(remote_url) {
            Some(p) => p,
            None => return GitAuthInjection::default(),
        };

        if parsed.scheme == "https" || parsed.scheme == "http" {
            let found = store::with_locked_store(&self.config_dir, |s| {
                if let Some(acc) = account {
                    Ok(s.accounts
                        .iter()
                        .find(|a| a.id == acc && a.host == parsed.host)
                        .cloned())
                } else {
                    Ok(s.accounts
                        .iter()
                        .find(|a| a.host == parsed.host && a.is_default)
                        .or_else(|| s.accounts.iter().find(|a| a.host == parsed.host))
                        .cloned())
                }
            })
            .unwrap_or(None);

            if found.is_some() {
                let helper_exe = self.config.helper_exe.clone().unwrap_or_else(|| {
                    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cawide"))
                });
                let mut config_args = Vec::new();
                config_args.push("-c".into());
                config_args.push(format!(
                    "credential.{remote_url}.helper=!\"{}\" git-credential --config-dir \"{}\"",
                    helper_exe.display(),
                    self.config_dir.display()
                ));
                config_args.push("-c".into());
                config_args.push(format!("credential.{remote_url}.useHttpPath=true"));
                return GitAuthInjection {
                    config_args,
                    env: Vec::new(),
                };
            }
        } else if parsed.scheme == "ssh" {
            let key_path = self.config_dir.join("ssh/id_ed25519");
            let kh_path = self.config_dir.join("ssh/known_hosts");
            if key_path.exists() {
                let cmd = format!(
                    "ssh -o IdentityFile=\"{}\" -o IdentitiesOnly=yes -o UserKnownHostsFile=\"{}\"",
                    key_path.display(),
                    kh_path.display()
                );
                return GitAuthInjection {
                    config_args: Vec::new(),
                    env: vec![("GIT_SSH_COMMAND".into(), cmd)],
                };
            }
        }

        GitAuthInjection::default()
    }
}
