use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use cawide_account::{
    expand_trust, parse_public_key_hex, validate_account_id, validate_name, DeviceLink,
    HostTrustSnapshot, MAX_SNAPSHOT_DEVICES, MAX_SNAPSHOT_LINKS, MAX_SNAPSHOT_REVOKED,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::auth::error::AuthError;

const CLAIM_GRACE_SECS: u64 = 600;
pub const LEASE_SECS: u64 = 120;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedBinding {
    pub account_id: String,
    pub epoch: u64,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedPairedKey {
    pub public_key: String,
    pub device_name: String,
    pub added_at_ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Paired,
    Account { link_id: [u8; 16], issued_at: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedEntry {
    pub public_key: [u8; 32],
    pub device_name: String,
    pub added_at_ts: u64,
    pub source: KeySource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLink {
    pub account_id: String,
    pub claimed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingLink {
    account_id: String,
    claimed_at: u64,
}

#[derive(Clone)]
struct TrustState {
    managed_binding: Option<ManagedBinding>,
    managed_paired: HashMap<[u8; 32], AuthorizedEntry>,
    pending_unlink_epoch: Option<u64>,
    lease_until: Option<tokio::time::Instant>,
    snapshot_devices: HashSet<[u8; 32]>,
    paired: HashMap<[u8; 32], AuthorizedEntry>,
    account: HashMap<[u8; 32], AuthorizedEntry>,
    local_denied: HashSet<[u8; 32]>,
    denied_corrupt: bool,
    link: Option<AccountLink>,
    pending_link: Option<PendingLink>,
    claims_disabled: bool,
    pending_unlink: bool,
    tombstones: HashMap<[u8; 32], u64>,
    version: u64,
    /// In-memory denial that is not yet durable; `retry_persist_trust` retries the write.
    pending_revocation_persist: bool,
}

/// Result of applying one managed `sync-managed` response to the store.
pub enum ManagedSyncOutcome {
    /// The response no longer matches the current binding (epoch/account/revocation changed).
    Stale,
    /// The account has not yet activated this host; no lease is granted.
    Pending,
    /// Binding was revoked. `persist_failed` means denial is in memory only and must be retried.
    Removed {
        removed: Vec<[u8; 32]>,
        persist_failed: bool,
    },
    /// Active snapshot applied; `removed` keys must be closed.
    Active { removed: Vec<[u8; 32]> },
}

pub struct AuthorizedKeysStore {
    file_path: PathBuf,
    keys: RwLock<TrustState>,
}

#[derive(Serialize, Deserialize)]
struct AccountTrustFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_binding: Option<ManagedBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_paired: Option<Vec<ManagedPairedKey>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_unlink_epoch: Option<u64>,
    account_id: Option<String>,
    claimed_at: u64,
    version: u64,
    pending_link: Option<PendingLinkFile>,
    claims_disabled: bool,
    pending_unlink: bool,
    keys: Vec<AccountKeyFile>,
    tombstones: Vec<TombstoneFile>,
}

#[derive(Serialize, Deserialize)]
struct PendingLinkFile {
    account_id: String,
    claimed_at: u64,
}

#[derive(Serialize, Deserialize)]
struct AccountKeyFile {
    public_key: String,
    name: String,
    link_id: String,
    issued_at: u64,
    added_at_ts: u64,
}

#[derive(Serialize, Deserialize)]
struct TombstoneFile {
    public_key: String,
    revoked_at: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn write_atomic(file_path: &Path, bytes: &[u8]) -> Result<(), AuthError> {
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
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, file_path)?;
        #[cfg(unix)]
        {
            if let Ok(dir_file) = File::open(parent) {
                let _ = dir_file.sync_all();
            }
        }
        Ok(())
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_res
}

fn persist_paired(
    file_path: &Path,
    paired: &HashMap<[u8; 32], AuthorizedEntry>,
) -> Result<(), AuthError> {
    let mut buf = Vec::new();
    let mut entries: Vec<&AuthorizedEntry> = paired.values().collect();
    entries.sort_by_key(|e| e.public_key);
    for entry in entries {
        writeln!(
            buf,
            "{} {} {}",
            hex::encode(entry.public_key),
            entry.added_at_ts,
            entry.device_name
        )?;
    }
    write_atomic(file_path, &buf)
}

fn persist_denied(file_path: &Path, denied: &HashSet<[u8; 32]>) -> Result<(), AuthError> {
    let mut buf = Vec::new();
    let mut keys: Vec<&[u8; 32]> = denied.iter().collect();
    keys.sort();
    for pk in keys {
        writeln!(buf, "{}", hex::encode(pk))?;
    }
    write_atomic(&file_path.with_file_name("denied_keys"), &buf)
}

fn persist_account_trust(file_path: &Path, state: &TrustState) -> Result<(), AuthError> {
    let mut keys: Vec<AccountKeyFile> = state
        .account
        .values()
        .filter_map(|entry| match entry.source {
            KeySource::Account { link_id, issued_at } => Some(AccountKeyFile {
                public_key: hex::encode(entry.public_key),
                name: entry.device_name.clone(),
                link_id: hex::encode(link_id),
                issued_at,
                added_at_ts: entry.added_at_ts,
            }),
            KeySource::Paired => None,
        })
        .collect();
    keys.sort_by(|a, b| a.public_key.cmp(&b.public_key));

    let mut tombstones: Vec<TombstoneFile> = state
        .tombstones
        .iter()
        .map(|(pk, revoked_at)| TombstoneFile {
            public_key: hex::encode(pk),
            revoked_at: *revoked_at,
        })
        .collect();
    tombstones.sort_by(|a, b| a.public_key.cmp(&b.public_key));

    let file = AccountTrustFile {
        managed_binding: state.managed_binding.clone(),
        managed_paired: if state.managed_binding.is_some() {
            let mut keys: Vec<ManagedPairedKey> = state
                .managed_paired
                .values()
                .map(|e| ManagedPairedKey {
                    public_key: hex::encode(e.public_key),
                    device_name: e.device_name.clone(),
                    added_at_ts: e.added_at_ts,
                })
                .collect();
            keys.sort_by(|a, b| a.public_key.cmp(&b.public_key));
            Some(keys)
        } else {
            None
        },
        pending_unlink_epoch: state.pending_unlink_epoch,
        account_id: state.link.as_ref().map(|l| l.account_id.clone()),
        claimed_at: state.link.as_ref().map_or(0, |l| l.claimed_at),
        version: state.version,
        pending_link: state.pending_link.as_ref().map(|p| PendingLinkFile {
            account_id: p.account_id.clone(),
            claimed_at: p.claimed_at,
        }),
        claims_disabled: state.claims_disabled,
        pending_unlink: state.pending_unlink,
        keys,
        tombstones,
    };

    let bytes = serde_json::to_vec_pretty(&file)
        .map_err(|e| AuthError::AccountSync(format!("serialize account trust: {e}")))?;
    write_atomic(&file_path.with_file_name("account_trust.json"), &bytes)
}

fn load_paired(path: &Path) -> Result<HashMap<[u8; 32], AuthorizedEntry>, AuthError> {
    let mut map = HashMap::new();
    if path.exists() {
        let file = File::open(path)?;
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
                    source: KeySource::Paired,
                },
            );
        }
    } else {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let file = opts.open(path)?;
        drop(file);
    }
    Ok(map)
}

fn parse_denied_line(trimmed: &str) -> Result<[u8; 32], ()> {
    let mut parts = trimmed.split_whitespace();
    let pk_hex = parts.next().ok_or(())?;
    let pk = parse_public_key_hex(pk_hex).map_err(|_| ())?;
    if let Some(ts_str) = parts.next() {
        ts_str.parse::<u64>().map_err(|_| ())?;
    }
    Ok(pk)
}

fn load_denied(path: &Path) -> Result<(HashSet<[u8; 32]>, bool), AuthError> {
    let denied_path = path.with_file_name("denied_keys");
    let mut denied = HashSet::new();
    let mut corrupt = false;
    if !denied_path.exists() {
        return Ok((denied, false));
    }
    let file = File::open(&denied_path)?;
    let reader = BufReader::new(file);
    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_denied_line(trimmed) {
            Ok(pk) => {
                denied.insert(pk);
            }
            Err(()) => {
                tracing::warn!(path = %denied_path.display(), line = %trimmed, "corrupt line in denied_keys");
                corrupt = true;
            }
        }
    }
    Ok((denied, corrupt))
}

#[derive(Default)]
struct LoadedAccountTrust {
    managed_binding: Option<ManagedBinding>,
    managed_paired: Option<HashMap<[u8; 32], AuthorizedEntry>>,
    pending_unlink_epoch: Option<u64>,
    account: HashMap<[u8; 32], AuthorizedEntry>,
    link: Option<AccountLink>,
    pending_link: Option<PendingLink>,
    claims_disabled: bool,
    pending_unlink: bool,
    tombstones: HashMap<[u8; 32], u64>,
    version: u64,
}

fn parse_account_trust_bytes(bytes: &[u8]) -> Result<LoadedAccountTrust, AuthError> {
    let file: AccountTrustFile = serde_json::from_slice(bytes)
        .map_err(|e| AuthError::CorruptStore(format!("failed to parse account_trust.json: {e}")))?;
    if let Some(id) = &file.account_id {
        validate_account_id(id).map_err(|e| AuthError::CorruptStore(e.to_string()))?;
    }
    if let Some(p) = &file.pending_link {
        validate_account_id(&p.account_id).map_err(|e| AuthError::CorruptStore(e.to_string()))?;
    }
    if let Some(b) = &file.managed_binding {
        validate_account_id(&b.account_id).map_err(|e| AuthError::CorruptStore(e.to_string()))?;
        if file.managed_paired.is_none() {
            return Err(AuthError::CorruptStore(
                "missing mandatory managed_paired in managed account_trust.json".into(),
            ));
        }
    }
    let managed_paired = if let Some(m_paired) = file.managed_paired {
        let mut map = HashMap::with_capacity(m_paired.len());
        for k in m_paired {
            let pk = parse_public_key_hex(&k.public_key)
                .map_err(|e| AuthError::CorruptStore(e.to_string()))?;
            validate_device_name(&k.device_name)?;
            map.insert(
                pk,
                AuthorizedEntry {
                    public_key: pk,
                    device_name: k.device_name,
                    added_at_ts: k.added_at_ts,
                    source: KeySource::Paired,
                },
            );
        }
        Some(map)
    } else {
        None
    };
    let mut account = HashMap::with_capacity(file.keys.len());
    for k in file.keys {
        let pk = parse_public_key_hex(&k.public_key)
            .map_err(|e| AuthError::CorruptStore(e.to_string()))?;
        validate_name(&k.name).map_err(|e| AuthError::CorruptStore(e.to_string()))?;
        let link_bytes =
            hex::decode(&k.link_id).map_err(|e| AuthError::CorruptStore(e.to_string()))?;
        if link_bytes.len() != 16 {
            return Err(AuthError::CorruptStore("invalid link_id length".into()));
        }
        let mut link_id = [0u8; 16];
        link_id.copy_from_slice(&link_bytes);
        account.insert(
            pk,
            AuthorizedEntry {
                public_key: pk,
                device_name: k.name,
                added_at_ts: k.added_at_ts,
                source: KeySource::Account {
                    link_id,
                    issued_at: k.issued_at,
                },
            },
        );
    }
    let mut tombstones = HashMap::with_capacity(file.tombstones.len());
    for t in file.tombstones {
        let pk = parse_public_key_hex(&t.public_key)
            .map_err(|e| AuthError::CorruptStore(e.to_string()))?;
        tombstones.insert(pk, t.revoked_at);
    }
    Ok(LoadedAccountTrust {
        managed_binding: file.managed_binding,
        managed_paired,
        pending_unlink_epoch: file.pending_unlink_epoch,
        account,
        link: file.account_id.map(|account_id| AccountLink {
            account_id,
            claimed_at: file.claimed_at,
        }),
        pending_link: file.pending_link.map(|p| PendingLink {
            account_id: p.account_id,
            claimed_at: p.claimed_at,
        }),
        claims_disabled: file.claims_disabled,
        pending_unlink: file.pending_unlink,
        tombstones,
        version: file.version,
    })
}

fn load_account_trust(
    path: &Path,
    legacy_paired: &HashMap<[u8; 32], AuthorizedEntry>,
) -> Result<LoadedAccountTrust, AuthError> {
    let trust_path = path.with_file_name("account_trust.json");
    if !trust_path.exists() {
        return Ok(LoadedAccountTrust::default());
    }
    let bytes = std::fs::read(&trust_path)?;
    match parse_account_trust_bytes(&bytes) {
        Ok(loaded) => Ok(loaded),
        Err(err) => {
            let was_managed = match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => v.get("managed_binding").is_some_and(|b| !b.is_null()),
                Err(_) => {
                    bytes.windows(15).any(|w| w == b"managed_binding")
                        && !bytes.windows(22).any(|w| w == b"\"managed_binding\":null")
                }
            };
            if was_managed || legacy_paired.is_empty() {
                return Err(err);
            }
            let corrupt_path = path.with_file_name("account_trust.json.corrupt");
            let _ = std::fs::rename(&trust_path, &corrupt_path);
            tracing::warn!(
                path = %trust_path.display(),
                "account trust state corrupt; starting unlinked"
            );
            Ok(LoadedAccountTrust::default())
        }
    }
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

        let legacy_paired = load_paired(&path)?;
        let (local_denied, denied_corrupt) = load_denied(&path)?;
        let mut trust = load_account_trust(&path, &legacy_paired)?;

        let (paired, managed_paired) = if trust.managed_binding.is_some() {
            let m_paired = trust.managed_paired.take().ok_or_else(|| {
                AuthError::CorruptStore("missing managed_paired for managed host".into())
            })?;
            let mut p = m_paired.clone();
            if trust.managed_binding.as_ref().is_some_and(|b| b.revoked) {
                p.clear();
                trust.account.clear();
            } else {
                p.retain(|pk, _| !local_denied.contains(pk));
                trust
                    .account
                    .retain(|pk, _| !local_denied.contains(pk) && !p.contains_key(pk));
            }
            if !legacy_paired.is_empty() {
                let _ = persist_paired(&path, &HashMap::new());
            }
            (p, m_paired)
        } else {
            if denied_corrupt || trust.link.is_none() {
                trust.account.clear();
            } else {
                trust
                    .account
                    .retain(|pk, _| !local_denied.contains(pk) && !legacy_paired.contains_key(pk));
            }
            (legacy_paired, HashMap::new())
        };

        let state = TrustState {
            managed_binding: trust.managed_binding,
            managed_paired,
            pending_unlink_epoch: trust.pending_unlink_epoch,
            lease_until: None,
            snapshot_devices: HashSet::new(),
            paired,
            account: trust.account,
            local_denied,
            denied_corrupt,
            link: trust.link,
            pending_link: trust.pending_link,
            claims_disabled: trust.claims_disabled,
            pending_unlink: trust.pending_unlink,
            tombstones: trust.tombstones,
            version: trust.version,
            pending_revocation_persist: false,
        };

        Ok(Self {
            file_path: path,
            keys: RwLock::new(state),
        })
    }

    pub fn is_authorized(&self, public_key: &[u8; 32]) -> bool {
        let lock = self.keys.read();
        if let Some(ref b) = lock.managed_binding {
            if b.revoked || lock.local_denied.contains(public_key) {
                return false;
            }
            return lock.managed_paired.contains_key(public_key)
                || lock.account.contains_key(public_key);
        }
        lock.paired.contains_key(public_key) || lock.account.contains_key(public_key)
    }

    pub fn is_session_authorized(&self, public_key: &[u8; 32]) -> bool {
        let lock = self.keys.read();
        // Only account-managed hosts are lease-gated; unmanaged/legacy hosts admit by key membership.
        let Some(ref b) = lock.managed_binding else {
            return lock.paired.contains_key(public_key) || lock.account.contains_key(public_key);
        };
        if b.revoked {
            return false;
        }
        let lease_active = lock
            .lease_until
            .is_some_and(|u| tokio::time::Instant::now() < u);
        if !lease_active {
            return false;
        }
        lock.snapshot_devices.contains(public_key)
            && !lock.local_denied.contains(public_key)
            && (lock.paired.contains_key(public_key) || lock.account.contains_key(public_key))
    }

    pub fn add_key(&self, public_key: [u8; 32], device_name: String) -> Result<(), AuthError> {
        validate_device_name(&device_name)?;
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|e| AuthError::InvalidPublicKey(e.to_string()))?;

        let mut lock = self.keys.write();
        if lock.managed_binding.is_some() {
            return Err(AuthError::AccountSync(
                "Update Cawide and pair from your account".into(),
            ));
        }
        if lock.paired.contains_key(&public_key) {
            return Err(AuthError::KeyAlreadyAuthorized(hex::encode(public_key)));
        }

        let old_state = lock.clone();
        let now_ts = now_secs();
        lock.paired.insert(
            public_key,
            AuthorizedEntry {
                public_key,
                device_name,
                added_at_ts: now_ts,
                source: KeySource::Paired,
            },
        );
        let account_removed = lock.account.remove(&public_key).is_some();
        let denied_removed = lock.local_denied.remove(&public_key);
        let tombstone_removed = lock.tombstones.remove(&public_key).is_some();

        let res = (|| -> Result<(), AuthError> {
            persist_paired(&self.file_path, &lock.paired)?;
            if denied_removed && !lock.denied_corrupt {
                persist_denied(&self.file_path, &lock.local_denied)?;
            }
            if account_removed || tombstone_removed {
                persist_account_trust(&self.file_path, &lock)?;
            }
            Ok(())
        })();

        if let Err(e) = res {
            *lock = old_state;
            return Err(e);
        }
        Ok(())
    }

    pub fn remove_key(&self, public_key: &[u8; 32]) -> Result<bool, AuthError> {
        let mut lock = self.keys.write();
        let old_state = lock.clone();

        if lock.managed_binding.is_some() {
            let removed_managed = lock.managed_paired.remove(public_key).is_some();
            let removed_paired = lock.paired.remove(public_key).is_some();
            let removed_account = lock.account.remove(public_key).is_some();
            let added_denied = lock.local_denied.insert(*public_key);
            let res = (|| -> Result<(), AuthError> {
                if removed_managed || removed_account {
                    persist_account_trust(&self.file_path, &lock)?;
                }
                if added_denied && !lock.denied_corrupt {
                    persist_denied(&self.file_path, &lock.local_denied)?;
                }
                Ok(())
            })();
            if let Err(e) = res {
                *lock = old_state;
                return Err(e);
            }
            return Ok(removed_managed || removed_paired || removed_account);
        }

        let removed_paired = lock.paired.remove(public_key).is_some();
        let removed_account = lock.account.remove(public_key).is_some();
        let added_denied = lock.local_denied.insert(*public_key);

        let res = (|| -> Result<(), AuthError> {
            if removed_paired {
                persist_paired(&self.file_path, &lock.paired)?;
            }
            if removed_account {
                persist_account_trust(&self.file_path, &lock)?;
            }
            if added_denied && !lock.denied_corrupt {
                persist_denied(&self.file_path, &lock.local_denied)?;
            }
            Ok(())
        })();

        if let Err(e) = res {
            *lock = old_state;
            return Err(e);
        }
        Ok(removed_paired || removed_account)
    }

    pub fn account_link(&self) -> Option<AccountLink> {
        self.keys.read().link.clone()
    }

    pub fn sync_target(&self) -> Option<(AccountLink, bool)> {
        let lock = self.keys.read();
        let now = now_secs();
        if let Some(p) = &lock.pending_link {
            if now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS {
                return Some((
                    AccountLink {
                        account_id: p.account_id.clone(),
                        claimed_at: p.claimed_at,
                    },
                    true,
                ));
            }
        }
        lock.link.as_ref().map(|l| (l.clone(), false))
    }

    pub fn account_version(&self) -> u64 {
        let lock = self.keys.read();
        let now = now_secs();
        if lock
            .pending_link
            .as_ref()
            .is_some_and(|p| now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS)
        {
            0
        } else {
            lock.version
        }
    }

    pub fn pending_unlink(&self) -> bool {
        self.keys.read().pending_unlink
    }

    pub fn claims_disabled(&self) -> bool {
        self.keys.read().claims_disabled
    }

    pub fn is_managed(&self) -> bool {
        self.keys.read().managed_binding.is_some()
    }

    pub fn requires_lease(&self) -> bool {
        self.keys.read().managed_binding.is_some()
    }

    pub fn managed_binding(&self) -> Option<ManagedBinding> {
        self.keys.read().managed_binding.clone()
    }

    /// `(account_id, epoch)` a managed host polls while its binding is live.
    pub fn managed_sync_target(&self) -> Option<(String, u64)> {
        let lock = self.keys.read();
        lock.managed_binding
            .as_ref()
            .filter(|b| !b.revoked)
            .map(|b| (b.account_id.clone(), b.epoch))
    }

    /// `(account_id, epoch)` of a revoked managed binding whose HTTP unlink is still unacknowledged.
    pub fn pending_managed_unlink(&self) -> Option<(String, u64)> {
        let lock = self.keys.read();
        let b = lock.managed_binding.as_ref()?;
        if !b.revoked || !lock.pending_unlink {
            return None;
        }
        lock.pending_unlink_epoch
            .map(|epoch| (b.account_id.clone(), epoch))
    }

    /// Drops the lease immediately (fail-closed), regardless of its deadline.
    pub fn revoke_lease(&self) {
        let mut lock = self.keys.write();
        lock.lease_until = None;
        lock.snapshot_devices.clear();
    }

    pub fn lease_until(&self) -> Option<tokio::time::Instant> {
        self.keys.read().lease_until
    }

    /// Clears the in-memory lease once it has passed. Returns whether a lease was cleared.
    pub fn expire_lease(&self) -> bool {
        let mut lock = self.keys.write();
        match lock.lease_until {
            Some(until) if tokio::time::Instant::now() >= until => {
                lock.lease_until = None;
                lock.snapshot_devices.clear();
                true
            }
            _ => false,
        }
    }

    /// Managed enrollment for `client_node_id` under `account_id`/`epoch`.
    /// Returns `Ok(true)` when a new binding replaced any previous state, so the
    /// caller must close existing connections; `Ok(false)` for an idempotent re-pair.
    pub fn begin_managed_pair(
        &self,
        client_node_id: [u8; 32],
        device_name: String,
        account_id: &str,
        epoch: u64,
        now: u64,
    ) -> Result<bool, String> {
        validate_account_id(account_id).map_err(|e| e.to_string())?;
        validate_device_name(&device_name).map_err(|e| e.to_string())?;
        ed25519_dalek::VerifyingKey::from_bytes(&client_node_id)
            .map_err(|e| AuthError::InvalidPublicKey(e.to_string()).to_string())?;
        let mut lock = self.keys.write();
        let same_binding = match &lock.managed_binding {
            Some(b) if epoch < b.epoch => return Err("stale managed enrollment epoch".into()),
            Some(b) if epoch == b.epoch && b.account_id != account_id => {
                return Err("managed enrollment account mismatch".into())
            }
            Some(b) if epoch == b.epoch && b.revoked => {
                return Err("managed binding is revoked".into())
            }
            Some(b) => epoch == b.epoch,
            None => false,
        };
        let entry = AuthorizedEntry {
            public_key: client_node_id,
            device_name,
            added_at_ts: now,
            source: KeySource::Paired,
        };
        let old_state = lock.clone();

        if same_binding {
            lock.managed_paired.insert(client_node_id, entry.clone());
            lock.account.remove(&client_node_id);
            let denied_removed = lock.local_denied.remove(&client_node_id);
            if lock.snapshot_devices.contains(&client_node_id) {
                lock.paired.insert(client_node_id, entry);
            }
            let res = (|| -> Result<(), AuthError> {
                persist_account_trust(&self.file_path, &lock)?;
                if denied_removed && !lock.denied_corrupt {
                    persist_denied(&self.file_path, &lock.local_denied)?;
                }
                Ok(())
            })();
            if let Err(e) = res {
                *lock = old_state;
                return Err(e.to_string());
            }
            return Ok(false);
        }

        // Linked epoch-0 migration: an existing link to this same account carries its
        // locally paired roots into the managed binding. They stay unadmitted until a
        // verified snapshot re-admits them (`lease_until` / `snapshot_devices` are cleared).
        let migrate_linked_roots = epoch == 0
            && lock
                .link
                .as_ref()
                .is_some_and(|l| l.account_id == account_id);
        let mut managed_paired = if migrate_linked_roots {
            lock.paired.clone()
        } else {
            HashMap::new()
        };
        managed_paired.insert(client_node_id, entry);
        let denied_removed = lock.local_denied.remove(&client_node_id);
        lock.managed_binding = Some(ManagedBinding {
            account_id: account_id.to_string(),
            epoch,
            revoked: false,
        });
        lock.managed_paired = managed_paired;
        lock.lease_until = None;
        lock.snapshot_devices.clear();
        lock.paired.clear();
        lock.account.clear();
        lock.link = None;
        lock.pending_link = None;
        lock.claims_disabled = false;
        lock.pending_unlink = false;
        lock.pending_unlink_epoch = None;
        lock.pending_revocation_persist = false;
        lock.tombstones.clear();
        lock.version = 0;
        let res = (|| -> Result<(), AuthError> {
            persist_account_trust(&self.file_path, &lock)?;
            if denied_removed && !lock.denied_corrupt {
                persist_denied(&self.file_path, &lock.local_denied)?;
            }
            Ok(())
        })();
        if let Err(e) = res {
            *lock = old_state;
            return Err(e.to_string());
        }
        let _ = persist_paired(&self.file_path, &HashMap::new());
        Ok(true)
    }

    /// Adopts a locally paired host into a managed binding at epoch 0, seeding
    /// `managed_paired` with only the authenticated adopting key.
    pub fn begin_managed_adopt(
        &self,
        client_node_id: &[u8; 32],
        account_id: &str,
        epoch: u64,
        now: u64,
    ) -> Result<(), String> {
        validate_account_id(account_id).map_err(|e| e.to_string())?;
        if epoch != 0 {
            return Err("managed adoption requires epoch 0".into());
        }
        let mut lock = self.keys.write();
        if lock.managed_binding.is_some() {
            return Err("Update Cawide and pair from your account".into());
        }
        if lock.link.is_some() {
            return Err("linked to an account; unlink before adopting".into());
        }
        if lock
            .pending_link
            .as_ref()
            .is_some_and(|p| now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS)
        {
            return Err("account claim in progress".into());
        }
        let Some(seed) = lock.paired.get(client_node_id).cloned() else {
            return Err("adopting device is not locally paired".into());
        };

        let old_state = lock.clone();
        lock.managed_binding = Some(ManagedBinding {
            account_id: account_id.to_string(),
            epoch: 0,
            revoked: false,
        });
        lock.managed_paired = HashMap::from([(*client_node_id, seed)]);
        lock.lease_until = None;
        lock.snapshot_devices.clear();
        lock.paired.clear();
        lock.account.clear();
        lock.pending_link = None;
        lock.claims_disabled = false;
        lock.pending_unlink = false;
        lock.pending_unlink_epoch = None;
        lock.tombstones.clear();
        lock.version = 0;
        if let Err(e) = persist_account_trust(&self.file_path, &lock) {
            *lock = old_state;
            return Err(e.to_string());
        }
        let _ = persist_paired(&self.file_path, &HashMap::new());
        Ok(())
    }

    pub fn managed_epoch_or_zero(&self) -> u64 {
        self.keys
            .read()
            .managed_binding
            .as_ref()
            .map_or(0, |b| b.epoch)
    }

    /// True when the host is still bound to a live (not revoked) managed binding at `epoch`.
    /// Push producers call this immediately before sending, so an enqueued job cannot leak
    /// after a revocation or epoch change.
    pub fn epoch_still_current(&self, epoch: u64) -> bool {
        let lock = self.keys.read();
        match &lock.managed_binding {
            // Unmanaged hosts are captured at epoch 0 and stay eligible.
            None => epoch == 0,
            Some(b) => !b.revoked && b.epoch == epoch,
        }
    }

    pub fn has_pending_revocation_persist(&self) -> bool {
        self.keys.read().pending_revocation_persist
    }

    /// Retries a failed managed-revocation write. Denial is already in memory.
    pub fn retry_persist_trust(&self) -> Result<(), AuthError> {
        let mut lock = self.keys.write();
        if !lock.pending_revocation_persist {
            return Ok(());
        }
        persist_account_trust(&self.file_path, &lock)?;
        let _ = persist_paired(&self.file_path, &HashMap::new());
        lock.pending_revocation_persist = false;
        Ok(())
    }

    /// Applies one `sync-managed` response for the binding `(expected_account_id, expected_epoch)`.
    /// `lease_until` is the deadline granted by this response (request start + `LEASE_SECS`).
    pub fn apply_managed_sync(
        &self,
        expected_account_id: &str,
        expected_epoch: u64,
        resp: cawide_account::ManagedHostSyncResponse,
        lease_until: tokio::time::Instant,
        now: u64,
    ) -> Result<ManagedSyncOutcome, AuthError> {
        let mut lock = self.keys.write();
        let matches = lock.managed_binding.as_ref().is_some_and(|b| {
            !b.revoked && b.account_id == expected_account_id && b.epoch == expected_epoch
        });
        if !matches {
            return Ok(ManagedSyncOutcome::Stale);
        }

        match resp {
            cawide_account::ManagedHostSyncResponse::Pending => {
                lock.lease_until = None;
                lock.snapshot_devices.clear();
                Ok(ManagedSyncOutcome::Pending)
            }
            cawide_account::ManagedHostSyncResponse::Removed => {
                let old_state = lock.clone();
                if let Some(b) = &mut lock.managed_binding {
                    b.revoked = true;
                }
                lock.lease_until = None;
                lock.snapshot_devices.clear();
                let mut removed: Vec<[u8; 32]> = lock
                    .paired
                    .keys()
                    .chain(lock.account.keys())
                    .chain(lock.managed_paired.keys())
                    .copied()
                    .collect();
                removed.sort();
                removed.dedup();
                lock.paired.clear();
                lock.managed_paired.clear();
                lock.account.clear();
                lock.link = None;
                lock.pending_link = None;
                lock.pending_unlink = false;
                lock.pending_unlink_epoch = None;
                lock.tombstones.clear();
                // Denial is applied in memory first; a failed write is retried, never rolled back.
                let persisted = persist_account_trust(&self.file_path, &lock);
                let _ = old_state;
                lock.pending_revocation_persist = persisted.is_err();
                let _ = persist_paired(&self.file_path, &HashMap::new());
                Ok(ManagedSyncOutcome::Removed {
                    removed,
                    persist_failed: persisted.is_err(),
                })
            }
            cawide_account::ManagedHostSyncResponse::Active { snapshot } => {
                if snapshot.devices.len() > MAX_SNAPSHOT_DEVICES
                    || snapshot.links.len() > MAX_SNAPSHOT_LINKS
                    || snapshot.revoked.len() > MAX_SNAPSHOT_REVOKED
                {
                    return Err(AuthError::AccountSync(
                        "snapshot exceeds size limits".into(),
                    ));
                }
                if snapshot.account_id != expected_account_id {
                    return Err(AuthError::AccountSync("account mismatch".into()));
                }

                let mut active = HashMap::with_capacity(snapshot.devices.len());
                for d in &snapshot.devices {
                    if let Ok(pk) = parse_public_key_hex(&d.public_key) {
                        if validate_name(&d.name).is_ok() {
                            active.insert(pk, d.name.clone());
                        }
                    }
                }

                let mut parsed_revoked = Vec::with_capacity(snapshot.revoked.len());
                for r in &snapshot.revoked {
                    if let Ok(pk) = parse_public_key_hex(&r.public_key) {
                        parsed_revoked.push((pk, r.revoked_at));
                    }
                }

                let mut verified_links = Vec::with_capacity(snapshot.links.len());
                for link_hex in &snapshot.links {
                    if let Ok(bytes) = hex::decode(link_hex) {
                        if let Ok(link) = DeviceLink::from_bytes(&bytes) {
                            if link.verify().is_ok() {
                                verified_links.push(link);
                            }
                        }
                    }
                }

                let old_state = lock.clone();
                let before: HashSet<[u8; 32]> = lock
                    .paired
                    .keys()
                    .chain(lock.account.keys())
                    .copied()
                    .collect();

                for (pk, revoked_at) in parsed_revoked {
                    let entry = lock.tombstones.entry(pk).or_insert(0);
                    if revoked_at > *entry {
                        *entry = revoked_at;
                    }
                    if let Some(me) = lock.managed_paired.get(&pk) {
                        if me.added_at_ts <= revoked_at {
                            lock.managed_paired.remove(&pk);
                        }
                    }
                    if let Some(account_entry) = lock.account.get(&pk) {
                        if let KeySource::Account { issued_at, .. } = account_entry.source {
                            if issued_at <= revoked_at {
                                lock.account.remove(&pk);
                            }
                        }
                    }
                }

                if lock.denied_corrupt || snapshot.locked {
                    lock.lease_until = None;
                    lock.snapshot_devices.clear();
                    lock.paired.clear();
                    lock.account.clear();
                    lock.version = snapshot.version;
                    if let Err(e) = persist_account_trust(&self.file_path, &lock) {
                        *lock = old_state;
                        lock.lease_until = None;
                        lock.snapshot_devices.clear();
                        lock.paired.clear();
                        lock.account.clear();
                        return Err(e);
                    }
                    let removed = before
                        .into_iter()
                        .filter(|pk| {
                            !lock.paired.contains_key(pk) && !lock.account.contains_key(pk)
                        })
                        .collect();
                    return Ok(ManagedSyncOutcome::Active { removed });
                }

                lock.paired = lock
                    .managed_paired
                    .iter()
                    .filter(|(pk, e)| {
                        active.contains_key(*pk)
                            && !lock.local_denied.contains(*pk)
                            && lock.tombstones.get(*pk).is_none_or(|t| e.added_at_ts > *t)
                    })
                    .map(|(pk, e)| (*pk, e.clone()))
                    .collect();
                lock.account.clear();

                let filtered_links: Vec<DeviceLink> = verified_links
                    .into_iter()
                    .filter(|l| l.body.account_id == expected_account_id)
                    .collect();
                let mut trusted: HashSet<[u8; 32]> = lock.paired.keys().copied().collect();
                let state = &mut *lock;
                let admitted = expand_trust(&mut trusted, &filtered_links, |k, l| {
                    active.contains_key(k)
                        && !state.local_denied.contains(k)
                        && state
                            .tombstones
                            .get(k)
                            .is_none_or(|t| l.body.issued_at > *t)
                });
                for (far, link_idx) in admitted {
                    let link = &filtered_links[link_idx];
                    if let Some(name) = active.get(&far) {
                        state.account.insert(
                            far,
                            AuthorizedEntry {
                                public_key: far,
                                device_name: name.clone(),
                                added_at_ts: now,
                                source: KeySource::Account {
                                    link_id: link.body.link_id,
                                    issued_at: link.body.issued_at,
                                },
                            },
                        );
                    }
                }

                let local_denied = &state.local_denied;
                let paired = &state.paired;
                state.account.retain(|pk, _| {
                    active.contains_key(pk)
                        && !local_denied.contains(pk)
                        && !paired.contains_key(pk)
                });
                state.snapshot_devices = active.keys().copied().collect();
                state.lease_until = Some(lease_until);
                state.version = snapshot.version;

                if let Err(e) = persist_account_trust(&self.file_path, &lock) {
                    *lock = old_state;
                    lock.lease_until = None;
                    lock.snapshot_devices.clear();
                    return Err(e);
                }
                let removed = before
                    .into_iter()
                    .filter(|pk| !lock.paired.contains_key(pk) && !lock.account.contains_key(pk))
                    .collect();
                Ok(ManagedSyncOutcome::Active { removed })
            }
        }
    }

    pub fn list_keys(&self) -> Vec<AuthorizedEntry> {
        let lock = self.keys.read();
        if let Some(ref b) = lock.managed_binding {
            if b.revoked {
                return Vec::new();
            }
            return lock
                .managed_paired
                .values()
                .filter(|e| !lock.local_denied.contains(&e.public_key))
                .chain(
                    lock.account
                        .values()
                        .filter(|e| !lock.managed_paired.contains_key(&e.public_key)),
                )
                .cloned()
                .collect();
        }
        lock.paired
            .values()
            .chain(lock.account.values())
            .cloned()
            .collect()
    }

    pub fn begin_claim(
        &self,
        client: &[u8; 32],
        account_id: &str,
        takeover: bool,
        now: u64,
    ) -> Result<bool, String> {
        cawide_account::validate_account_id(account_id).map_err(|e| e.to_string())?;
        let mut lock = self.keys.write();
        if lock.managed_binding.is_some() {
            return Err("Update Cawide and pair from your account".into());
        }
        let unexpired_pending_other = lock.pending_link.as_ref().is_some_and(|p| {
            p.account_id != account_id && now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS
        });
        let unexpired_pending_same = lock.pending_link.as_ref().is_some_and(|p| {
            p.account_id == account_id && now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS
        });

        if lock.paired.contains_key(client) {
            if !takeover && lock.claims_disabled {
                return Err("disabled on this computer".into());
            }
            if !takeover
                && (lock
                    .link
                    .as_ref()
                    .is_some_and(|l| l.account_id != account_id)
                    || unexpired_pending_other)
            {
                return Err("linked to another account".into());
            }

            let old_state = lock.clone();
            if takeover {
                lock.claims_disabled = false;
                lock.pending_unlink = false;
            }

            let same_link = lock
                .link
                .as_ref()
                .is_some_and(|l| l.account_id == account_id);
            let result = if same_link && !unexpired_pending_other {
                if takeover {
                    if let Some(link) = &mut lock.link {
                        link.claimed_at = now;
                    }
                }
                false
            } else if unexpired_pending_same {
                false
            } else {
                lock.pending_link = Some(PendingLink {
                    account_id: account_id.to_string(),
                    claimed_at: now,
                });
                true
            };

            if trust_persisted_changed(&lock, &old_state) {
                if let Err(e) = persist_account_trust(&self.file_path, &lock) {
                    *lock = old_state;
                    return Err(e.to_string());
                }
            }
            Ok(result)
        } else if lock.account.contains_key(client) {
            let same_link = lock
                .link
                .as_ref()
                .is_some_and(|l| l.account_id == account_id);
            if !same_link || unexpired_pending_other {
                return Err("linked to another account".into());
            }
            // Never let an Account-sourced key refresh `link.claimed_at` (even
            // with `takeover == true`), or a revoked/unlinked account key could
            // indefinitely extend the 600s unlink grace window.
            Ok(false)
        } else {
            Err("not permitted".into())
        }
    }

    pub fn mark_unlinked_local(
        &self,
        pending_http: bool,
    ) -> Result<(bool, Vec<[u8; 32]>), AuthError> {
        let mut lock = self.keys.write();
        let old_state = lock.clone();

        if let Some(b) = &mut lock.managed_binding {
            let was_linked = !b.revoked;
            b.revoked = true;
            let epoch = b.epoch;
            lock.lease_until = None;
            lock.snapshot_devices.clear();
            let mut removed: Vec<[u8; 32]> = lock
                .paired
                .keys()
                .chain(lock.account.keys())
                .chain(lock.managed_paired.keys())
                .copied()
                .collect();
            removed.sort();
            removed.dedup();
            lock.paired.clear();
            lock.managed_paired.clear();
            lock.account.clear();
            lock.claims_disabled = true;
            lock.pending_unlink = pending_http;
            lock.pending_unlink_epoch = Some(epoch);
            // Admission stays denied in memory even if the write fails; the write is retried.
            let persisted = persist_account_trust(&self.file_path, &lock);
            lock.pending_revocation_persist = persisted.is_err();
            let _ = persist_paired(&self.file_path, &HashMap::new());
            persisted?;
            return Ok((was_linked, removed));
        }

        let now = now_secs();
        let was_linked = lock.link.is_some()
            || lock
                .pending_link
                .as_ref()
                .is_some_and(|p| now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS);

        let removed: Vec<[u8; 32]> = lock.account.keys().copied().collect();
        lock.link = None;
        lock.pending_link = None;
        lock.lease_until = None;
        lock.snapshot_devices.clear();
        lock.account.clear();
        if was_linked {
            lock.claims_disabled = true;
            lock.pending_unlink = pending_http;
        }

        if trust_persisted_changed(&lock, &old_state) {
            if let Err(e) = persist_account_trust(&self.file_path, &lock) {
                *lock = old_state;
                return Err(e);
            }
        }
        Ok((was_linked, removed))
    }

    pub fn clear_pending_unlink(&self) -> Result<(), AuthError> {
        let mut lock = self.keys.write();
        if !lock.pending_unlink && lock.pending_unlink_epoch.is_none() {
            return Ok(());
        }
        let old_state = lock.clone();
        lock.pending_unlink = false;
        lock.pending_unlink_epoch = None;
        if let Err(e) = persist_account_trust(&self.file_path, &lock) {
            *lock = old_state;
            return Err(e);
        }
        Ok(())
    }

    pub fn clear_managed_pending_unlink(
        &self,
        expected_account_id: &str,
        expected_epoch: u64,
    ) -> Result<(), AuthError> {
        let mut lock = self.keys.write();
        let matches = lock.managed_binding.as_ref().is_some_and(|b| {
            b.revoked
                && b.account_id == expected_account_id
                && lock.pending_unlink_epoch == Some(expected_epoch)
        });
        if !matches || !lock.pending_unlink {
            return Ok(());
        }
        let old_state = lock.clone();
        lock.pending_unlink = false;
        lock.pending_unlink_epoch = None;
        if let Err(e) = persist_account_trust(&self.file_path, &lock) {
            *lock = old_state;
            return Err(e);
        }
        Ok(())
    }
    pub fn clear_account_link(
        &self,
        expected_account_id: &str,
        now: u64,
    ) -> Result<(bool, Vec<[u8; 32]>), AuthError> {
        let mut lock = self.keys.write();
        let should_clear = lock.link.as_ref().is_some_and(|l| {
            l.account_id == expected_account_id
                && now.saturating_sub(l.claimed_at) >= CLAIM_GRACE_SECS
        });
        if !should_clear {
            return Ok((false, Vec::new()));
        }
        let old_state = lock.clone();
        let removed: Vec<[u8; 32]> = lock.account.keys().copied().collect();
        lock.link = None;
        lock.lease_until = None;
        lock.snapshot_devices.clear();
        lock.account.clear();
        if let Err(e) = persist_account_trust(&self.file_path, &lock) {
            *lock = old_state;
            return Err(e);
        }
        Ok((true, removed))
    }

    pub fn apply_account_sync(
        &self,
        snap: &HostTrustSnapshot,
        now: u64,
    ) -> Result<Vec<[u8; 32]>, AuthError> {
        if snap.devices.len() > MAX_SNAPSHOT_DEVICES
            || snap.links.len() > MAX_SNAPSHOT_LINKS
            || snap.revoked.len() > MAX_SNAPSHOT_REVOKED
        {
            return Err(AuthError::AccountSync(
                "snapshot exceeds size limits".into(),
            ));
        }

        let mut active = HashMap::with_capacity(snap.devices.len());
        for d in &snap.devices {
            if let Ok(pk) = parse_public_key_hex(&d.public_key) {
                if validate_name(&d.name).is_ok() {
                    active.insert(pk, d.name.clone());
                }
            }
        }

        let mut parsed_revoked = Vec::with_capacity(snap.revoked.len());
        for r in &snap.revoked {
            if let Ok(pk) = parse_public_key_hex(&r.public_key) {
                parsed_revoked.push((pk, r.revoked_at));
            }
        }

        let mut verified_links = Vec::with_capacity(snap.links.len());
        for link_hex in &snap.links {
            if let Ok(bytes) = hex::decode(link_hex) {
                if let Ok(link) = DeviceLink::from_bytes(&bytes) {
                    if link.verify().is_ok() {
                        verified_links.push(link);
                    }
                }
            }
        }

        let mut lock = self.keys.write();
        let old_state = lock.clone();
        let before: HashSet<[u8; 32]> = lock
            .paired
            .keys()
            .chain(lock.account.keys())
            .copied()
            .collect();

        let promote_pending = lock.pending_link.as_ref().is_some_and(|p| {
            now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS && snap.account_id == p.account_id
        });
        if promote_pending {
            if let Some(p) = lock.pending_link.take() {
                let switched_account = lock
                    .link
                    .as_ref()
                    .is_some_and(|l| l.account_id != p.account_id);
                lock.link = Some(AccountLink {
                    account_id: p.account_id,
                    claimed_at: p.claimed_at,
                });
                lock.account.clear();
                if switched_account {
                    lock.tombstones.clear();
                }
                lock.version = 0;
            }
        } else if !lock
            .link
            .as_ref()
            .is_some_and(|l| l.account_id == snap.account_id)
        {
            return Err(AuthError::AccountSync("account mismatch".into()));
        }

        for (pk, revoked_at) in parsed_revoked {
            let entry = lock.tombstones.entry(pk).or_insert(0);
            if revoked_at > *entry {
                *entry = revoked_at;
            }
            if let Some(paired_entry) = lock.paired.get(&pk) {
                if paired_entry.added_at_ts <= revoked_at {
                    lock.paired.remove(&pk);
                }
            }
            if let Some(account_entry) = lock.account.get(&pk) {
                if let KeySource::Account { issued_at, .. } = account_entry.source {
                    if issued_at <= revoked_at {
                        lock.account.remove(&pk);
                    }
                }
            }
        }

        if lock.denied_corrupt || snap.locked {
            lock.account.clear();
            let paired_changed = lock.paired != old_state.paired;
            let trust_changed = trust_persisted_changed(&lock, &old_state);
            lock.version = snap.version;
            let res = (|| -> Result<(), AuthError> {
                if paired_changed {
                    persist_paired(&self.file_path, &lock.paired)?;
                }
                if trust_changed {
                    persist_account_trust(&self.file_path, &lock)?;
                }
                Ok(())
            })();
            if let Err(e) = res {
                *lock = old_state;
                return Err(e);
            }
            lock.snapshot_devices.clear();
            lock.lease_until = None;
            let removed = before
                .into_iter()
                .filter(|pk| !lock.paired.contains_key(pk) && !lock.account.contains_key(pk))
                .collect();
            return Ok(removed);
        }

        let state = &mut *lock;
        state
            .account
            .retain(|pk, _| active.contains_key(pk) && !state.local_denied.contains(pk));

        let current_account_id = state
            .link
            .as_ref()
            .map(|l| l.account_id.as_str())
            .ok_or_else(|| AuthError::AccountSync("account mismatch".into()))?;
        let filtered_links: Vec<DeviceLink> = verified_links
            .into_iter()
            .filter(|l| l.body.account_id == current_account_id)
            .collect();

        let mut trusted: HashSet<[u8; 32]> = state
            .paired
            .keys()
            .chain(state.account.keys())
            .copied()
            .collect();
        let admitted = expand_trust(&mut trusted, &filtered_links, |k, l| {
            active.contains_key(k)
                && !state.local_denied.contains(k)
                && state
                    .tombstones
                    .get(k)
                    .is_none_or(|t| l.body.issued_at > *t)
        });

        for (far, link_idx) in admitted {
            let link = &filtered_links[link_idx];
            if let Some(name) = active.get(&far) {
                state.account.insert(
                    far,
                    AuthorizedEntry {
                        public_key: far,
                        device_name: name.clone(),
                        added_at_ts: now,
                        source: KeySource::Account {
                            link_id: link.body.link_id,
                            issued_at: link.body.issued_at,
                        },
                    },
                );
            }
        }

        let paired_changed = lock.paired != old_state.paired;
        let trust_changed = trust_persisted_changed(&lock, &old_state);
        lock.version = snap.version;

        let res = (|| -> Result<(), AuthError> {
            if paired_changed {
                persist_paired(&self.file_path, &lock.paired)?;
            }
            if trust_changed {
                persist_account_trust(&self.file_path, &lock)?;
            }
            Ok(())
        })();
        if let Err(e) = res {
            *lock = old_state;
            return Err(e);
        }

        let removed = before
            .into_iter()
            .filter(|pk| !lock.paired.contains_key(pk) && !lock.account.contains_key(pk))
            .collect();
        Ok(removed)
    }
}

fn trust_persisted_changed(a: &TrustState, b: &TrustState) -> bool {
    a.account != b.account
        || a.tombstones != b.tombstones
        || a.link != b.link
        || a.pending_link != b.pending_link
        || a.claims_disabled != b.claims_disabled
        || a.pending_unlink != b.pending_unlink
        || a.managed_binding != b.managed_binding
        || a.managed_paired != b.managed_paired
        || a.pending_unlink_epoch != b.pending_unlink_epoch
}

impl std::fmt::Debug for AuthorizedKeysStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lock = self.keys.read();
        f.debug_struct("AuthorizedKeysStore")
            .field("file_path", &self.file_path)
            .field("paired_keys", &lock.paired.len())
            .field("account_keys", &lock.account.len())
            .field("link", &lock.link)
            .finish()
    }
}
