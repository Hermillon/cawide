use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use super::login_policy::sanitize_codex_auth;

pub trait SecretStore: Send + Sync {
    fn read_generic_password(&self, service: &str, account: &str)
        -> anyhow::Result<Option<String>>;
}

pub struct MacKeychain;

impl SecretStore for MacKeychain {
    fn read_generic_password(
        &self,
        service: &str,
        account: &str,
    ) -> anyhow::Result<Option<String>> {
        let output = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-a", account, "-w", "-s", service])
            .output()?;

        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            return Ok(Some(s.trim_end_matches(['\r', '\n']).to_string()));
        }

        // Exit status 44 = errSecItemNotFound
        if output.status.code() == Some(44) {
            return Ok(None);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{stderr}")
    }
}

pub struct NoSecretStore;

impl SecretStore for NoSecretStore {
    fn read_generic_password(
        &self,
        _service: &str,
        _account: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
}

pub fn codex_keychain_account(codex_home: &Path) -> String {
    let path_str = match std::fs::canonicalize(codex_home) {
        Ok(canon) => canon.to_string_lossy().to_string(),
        Err(_) => codex_home.to_string_lossy().to_string(),
    };
    let hash = Sha256::digest(path_str.as_bytes());
    let hex_hash = hex::encode(hash);
    format!("cli|{}", &hex_hash[..16])
}

pub struct CollectedCredentials {
    pub codex_auth: Option<String>,
    pub credential_entries: Vec<String>,
    pub notices: Vec<String>,
}

pub fn collect_credentials(store: &dyn SecretStore, codex_root: &Path) -> CollectedCredentials {
    let mut codex_auth = None;
    let mut credential_entries = Vec::new();
    let mut notices = Vec::new();

    let codex_auth_file = codex_root.join("auth.json");
    if codex_auth_file.is_file() {
        if let Ok(content) = std::fs::read_to_string(&codex_auth_file) {
            if let Some(sanitized) = sanitize_codex_auth(&content) {
                codex_auth = Some(sanitized);
                credential_entries.push("Codex API key (file)".to_string());
            }
        }
    } else {
        let account = codex_keychain_account(codex_root);
        match store.read_generic_password("Codex Auth", &account) {
            Ok(Some(val)) => {
                if let Some(sanitized) = sanitize_codex_auth(&val) {
                    codex_auth = Some(sanitized);
                    credential_entries.push("Codex API key (macOS Keychain)".to_string());
                }
            }
            Ok(None) => {}
            Err(e) => {
                notices.push(format!(
                    "could not read Codex login from the macOS Keychain: {e}"
                ));
            }
        }
    }

    CollectedCredentials {
        codex_auth,
        credential_entries,
        notices,
    }
}
