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

#[derive(Clone, PartialEq, Eq)]
struct TrustState {
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
}

pub struct AuthorizedKeysStore {
    file_path: PathBuf,
    keys: RwLock<TrustState>,
}

#[derive(Serialize, Deserialize)]
struct AccountTrustFile {
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
    account: HashMap<[u8; 32], AuthorizedEntry>,
    link: Option<AccountLink>,
    pending_link: Option<PendingLink>,
    claims_disabled: bool,
    pending_unlink: bool,
    tombstones: HashMap<[u8; 32], u64>,
    version: u64,
}

fn parse_account_trust_bytes(bytes: &[u8]) -> Result<LoadedAccountTrust, ()> {
    let file: AccountTrustFile = serde_json::from_slice(bytes).map_err(|_| ())?;
    if let Some(id) = &file.account_id {
        validate_account_id(id).map_err(|_| ())?;
    }
    if let Some(p) = &file.pending_link {
        validate_account_id(&p.account_id).map_err(|_| ())?;
    }
    let mut account = HashMap::with_capacity(file.keys.len());
    for k in file.keys {
        let pk = parse_public_key_hex(&k.public_key).map_err(|_| ())?;
        validate_name(&k.name).map_err(|_| ())?;
        let link_bytes = hex::decode(&k.link_id).map_err(|_| ())?;
        if link_bytes.len() != 16 {
            return Err(());
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
        let pk = parse_public_key_hex(&t.public_key).map_err(|_| ())?;
        tombstones.insert(pk, t.revoked_at);
    }
    Ok(LoadedAccountTrust {
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

fn load_account_trust(path: &Path) -> Result<LoadedAccountTrust, AuthError> {
    let trust_path = path.with_file_name("account_trust.json");
    if !trust_path.exists() {
        return Ok(LoadedAccountTrust::default());
    }
    let bytes = std::fs::read(&trust_path)?;
    match parse_account_trust_bytes(&bytes) {
        Ok(loaded) => Ok(loaded),
        Err(()) => {
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

        let paired = load_paired(&path)?;
        let (local_denied, denied_corrupt) = load_denied(&path)?;
        let mut trust = load_account_trust(&path)?;
        if denied_corrupt || trust.link.is_none() {
            trust.account.clear();
        } else {
            trust
                .account
                .retain(|pk, _| !local_denied.contains(pk) && !paired.contains_key(pk));
        }

        let state = TrustState {
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
        };

        Ok(Self {
            file_path: path,
            keys: RwLock::new(state),
        })
    }

    pub fn is_authorized(&self, public_key: &[u8; 32]) -> bool {
        let lock = self.keys.read();
        lock.paired.contains_key(public_key) || lock.account.contains_key(public_key)
    }

    pub fn add_key(&self, public_key: [u8; 32], device_name: String) -> Result<(), AuthError> {
        validate_device_name(&device_name)?;
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|e| AuthError::InvalidPublicKey(e.to_string()))?;

        let mut lock = self.keys.write();
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

    pub fn list_keys(&self) -> Vec<AuthorizedEntry> {
        let lock = self.keys.read();
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
        let now = now_secs();
        let was_linked = lock.link.is_some()
            || lock
                .pending_link
                .as_ref()
                .is_some_and(|p| now.saturating_sub(p.claimed_at) < CLAIM_GRACE_SECS);

        let old_state = lock.clone();
        let removed: Vec<[u8; 32]> = lock.account.keys().copied().collect();
        lock.link = None;
        lock.pending_link = None;
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
        if !lock.pending_unlink {
            return Ok(());
        }
        let old_state = lock.clone();
        lock.pending_unlink = false;
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
