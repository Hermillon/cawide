use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::auth::error::AuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedEntry {
    pub public_key: [u8; 32],
    pub device_name: String,
    pub added_at_ts: u64,
}

pub struct AuthorizedKeysStore {
    file_path: PathBuf,
    keys: RwLock<HashMap<[u8; 32], AuthorizedEntry>>,
}

pub fn validate_device_name(name: &str) -> Result<(), AuthError> {
    if name.trim().is_empty() || name.len() > 64 {
        return Err(AuthError::InvalidDeviceName(name.to_string()));
    }
    for b in name.bytes() {
        if b <= 0x1F || b == 0x7F {
            return Err(AuthError::InvalidDeviceName(name.to_string()));
        }
    }
    Ok(())
}

fn persist_atomic(
    file_path: &Path,
    keys: &HashMap<[u8; 32], AuthorizedEntry>,
) -> Result<(), AuthError> {
    let parent = file_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent directory"))?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("authorized_keys");
    let rand_suffix: u32 = rand::random();
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        rand_suffix
    ));

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let write_res = (|| -> Result<(), AuthError> {
        let mut file = opts.open(&temp_path)?;
        for entry in keys.values() {
            writeln!(
                file,
                "{} {} {}",
                hex::encode(entry.public_key),
                entry.added_at_ts,
                entry.device_name
            )?;
        }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, file_path)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_res
}

impl AuthorizedKeysStore {
    pub fn open_or_create(path: PathBuf) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = std::fs::DirBuilder::new();
                    builder.recursive(true).mode(0o700);
                    builder.create(parent)?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::create_dir_all(parent)?;
                }
            }
        }

        let mut map = HashMap::new();

        if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);

            for line_res in reader.lines() {
                let line = line_res?;
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
                if parts.len() != 3 {
                    return Err(AuthError::CorruptStore(format!(
                        "Invalid column count in line: {trimmed}"
                    )));
                }

                let pk_bytes = hex::decode(parts[0])?;
                if pk_bytes.len() != 32 {
                    return Err(AuthError::CorruptStore(format!(
                        "Public key length not 32 bytes: {}",
                        parts[0]
                    )));
                }

                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&pk_bytes);

                ed25519_dalek::VerifyingKey::from_bytes(&public_key)
                    .map_err(|e| AuthError::CorruptStore(format!("Invalid public key: {e}")))?;

                let added_at_ts = parts[1]
                    .parse::<u64>()
                    .map_err(|e| AuthError::CorruptStore(e.to_string()))?;

                let device_name = parts[2].to_string();
                validate_device_name(&device_name)?;

                map.insert(
                    public_key,
                    AuthorizedEntry {
                        public_key,
                        device_name,
                        added_at_ts,
                    },
                );
            }
        } else {
            // Create the initial empty file with mode 0600 on Unix
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);

            let file = opts.open(&path)?;
            drop(file);
        }

        Ok(Self {
            file_path: path,
            keys: RwLock::new(map),
        })
    }

    pub fn is_authorized(&self, public_key: &[u8; 32]) -> bool {
        self.keys.read().contains_key(public_key)
    }

    pub fn add_key(&self, public_key: [u8; 32], device_name: String) -> Result<(), AuthError> {
        validate_device_name(&device_name)?;

        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|e| AuthError::InvalidPublicKey(e.to_string()))?;

        let mut lock = self.keys.write();
        if lock.contains_key(&public_key) {
            return Err(AuthError::KeyAlreadyAuthorized(hex::encode(public_key)));
        }

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = AuthorizedEntry {
            public_key,
            device_name,
            added_at_ts: now_ts,
        };
        lock.insert(public_key, entry);

        if let Err(e) = persist_atomic(&self.file_path, &lock) {
            lock.remove(&public_key);
            return Err(e);
        }
        Ok(())
    }

    pub fn remove_key(&self, public_key: &[u8; 32]) -> Result<bool, AuthError> {
        let mut lock = self.keys.write();
        if let Some(removed_entry) = lock.remove(public_key) {
            if let Err(e) = persist_atomic(&self.file_path, &lock) {
                lock.insert(*public_key, removed_entry);
                return Err(e);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn list_keys(&self) -> Vec<AuthorizedEntry> {
        self.keys.read().values().cloned().collect()
    }
}

impl std::fmt::Debug for AuthorizedKeysStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedKeysStore")
            .field("file_path", &self.file_path)
            .field("keys", &self.keys.read().len())
            .finish()
    }
}
