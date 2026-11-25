//! Account device-trust statements shared by the Cawide host, the Cawide
//! Cloud API, and the client core.
//!
//! Every signed statement is `CONTEXT_* ‖ postcard(body)`. Keys are raw
//! Ed25519 public keys (the iroh node id of each device or host).

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CONTEXT_REGISTER: &[u8] = b"cawide/device-register/1\0";
pub const CONTEXT_LINK: &[u8] = b"cawide/device-link/1\0";
pub const CONTEXT_CLAIM: &[u8] = b"cawide/machine-claim/1\0";
pub const CONTEXT_CLAIM_ACCEPT: &[u8] = b"cawide/machine-claim-accept/1\0";
pub const CONTEXT_REVOKE: &[u8] = b"cawide/device-revoke/1\0";
pub const CONTEXT_REMOVE: &[u8] = b"cawide/device-remove/1\0";
pub const CONTEXT_HOST_REQUEST: &[u8] = b"cawide/host-request/1\0";
pub const CONTEXT_COMMIT: &[u8] = b"cawide/approval-commit/1\0";
pub const CONTEXT_SAS: &[u8] = b"cawide/approval-sas/1\0";
pub const CONTEXT_MANAGED_CLAIM: &[u8] = b"cawide/managed-claim/1\0";
pub const CONTEXT_MANAGED_CLAIM_ACCEPT: &[u8] = b"cawide/managed-claim-accept/1\0";
pub const CONTEXT_SESSION_REGISTER: &[u8] = b"cawide/device-session-register/1\0";

pub const MAX_ACCOUNT_ID_LEN: usize = 64;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_STATEMENT_BYTES: usize = 1024;

pub const MAX_SNAPSHOT_DEVICES: usize = 64;
pub const MAX_SNAPSHOT_LINKS: usize = 256;
pub const MAX_SNAPSHOT_REVOKED: usize = 1024;

pub const HOST_SYNC_PATH: &str = "/api/v1/host/sync";
pub const HOST_UNLINK_PATH: &str = "/api/v1/host/unlink";
pub const MANAGED_HOST_SYNC_PATH: &str = "/api/v1/host/sync-managed";
pub const MANAGED_HOST_UNLINK_PATH: &str = "/api/v1/host/unlink-managed";
pub const HEADER_HOST: &str = "x-cawide-host";
pub const HEADER_TIMESTAMP: &str = "x-cawide-timestamp";
pub const HEADER_SIGNATURE: &str = "x-cawide-signature";

pub type PublicKey = [u8; 32];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountError {
    #[error("malformed statement")]
    Malformed,
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("bad signature")]
    BadSignature,
}

/// 1..=64 bytes of ASCII alphanumerics or `-`.
pub fn validate_account_id(id: &str) -> Result<(), AccountError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ACCOUNT_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(AccountError::Invalid("account id"))
    }
}

/// Trimmed non-empty, at most 64 bytes, no control characters (C0 or C1).
pub fn validate_name(name: &str) -> Result<(), AccountError> {
    let ok = !name.trim().is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.chars().any(char::is_control);
    if ok {
        Ok(())
    } else {
        Err(AccountError::Invalid("name"))
    }
}

/// Trims whitespace, strips control characters, and truncates on a `char`
/// boundary to at most `max_bytes` bytes.
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_bytes));
    for c in s.trim().chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out.trim_end().to_owned()
}

pub fn validate_platform(p: &str) -> Result<(), AccountError> {
    match p {
        "iphone" | "ipad" | "android" | "other" => Ok(()),
        _ => Err(AccountError::Invalid("platform")),
    }
}

/// 64 lowercase-or-uppercase hex chars encoding a valid Ed25519 point.
pub fn parse_public_key_hex(s: &str) -> Result<PublicKey, AccountError> {
    if s.len() != 64 {
        return Err(AccountError::Invalid("public key"));
    }
    let mut pk = [0u8; 32];
    hex::decode_to_slice(s, &mut pk).map_err(|_| AccountError::Invalid("public key"))?;
    VerifyingKey::from_bytes(&pk).map_err(|_| AccountError::Invalid("public key"))?;
    Ok(pk)
}

/// Byte-compatible with `iroh::SecretKey`, which wraps the same seed.
pub fn public_key_of(secret: &[u8; 32]) -> PublicKey {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

pub fn sign(secret: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(secret).sign(msg).to_bytes()
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), AccountError> {
    let sig = Signature::from_slice(sig).map_err(|_| AccountError::BadSignature)?;
    let key = VerifyingKey::from_bytes(pk).map_err(|_| AccountError::Invalid("public key"))?;
    key.verify_strict(msg, &sig)
        .map_err(|_| AccountError::BadSignature)
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("postcard serialization of plain structs is infallible")
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AccountError> {
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err(AccountError::Malformed);
    }
    match postcard::take_from_bytes(bytes) {
        Ok((value, [])) => Ok(value),
        _ => Err(AccountError::Malformed),
    }
}

fn context_message<T: Serialize>(context: &[u8], body: &T) -> Vec<u8> {
    let mut msg = context.to_vec();
    msg.extend_from_slice(&encode(body));
    msg
}

macro_rules! statement_bytes {
    ($($ty:ty),* $(,)?) => {$(
        impl $ty {
            pub fn to_bytes(&self) -> Vec<u8> {
                encode(self)
            }

            /// Rejects input over `MAX_STATEMENT_BYTES` or with trailing bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccountError> {
                decode(bytes)
            }
        }
    )*};
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceSessionRegistration {
    pub account_id: String,
    pub public_key: PublicKey,
    pub name: String,
    pub platform: String,
    pub issued_at: u64,
    pub session_id: String,
}

impl DeviceSessionRegistration {
    pub fn signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_SESSION_REGISTER, self)
    }

    pub fn validate(&self) -> Result<(), AccountError> {
        validate_account_id(&self.account_id)?;
        validate_name(&self.name)?;
        validate_platform(&self.platform)?;
        if self.session_id.trim().is_empty()
            || self.session_id.len() > 128
            || self.session_id.chars().any(char::is_control)
        {
            return Err(AccountError::Invalid("session id"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRegistration {
    pub account_id: String,
    pub public_key: PublicKey,
    pub name: String,
    pub platform: String,
    pub issued_at: u64,
}

impl DeviceRegistration {
    pub fn signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_REGISTER, self)
    }

    pub fn validate(&self) -> Result<(), AccountError> {
        validate_account_id(&self.account_id)?;
        validate_name(&self.name)?;
        validate_platform(&self.platform)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkBody {
    pub account_id: String,
    pub link_id: [u8; 16],
    pub issuer: PublicKey,
    pub subject: PublicKey,
    pub subject_name: String,
    pub issued_at: u64,
}

impl DeviceLinkBody {
    pub fn new(
        account_id: String,
        issuer: PublicKey,
        subject: PublicKey,
        subject_name: String,
        issued_at: u64,
    ) -> Self {
        Self {
            account_id,
            link_id: rand::random(),
            issuer,
            subject,
            subject_name,
            issued_at,
        }
    }

    pub fn signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_LINK, self)
    }

    pub fn validate(&self) -> Result<(), AccountError> {
        validate_account_id(&self.account_id)?;
        validate_name(&self.subject_name)?;
        if self.issuer == self.subject {
            return Err(AccountError::Invalid("link"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceLink {
    pub body: DeviceLinkBody,
    pub issuer_sig: Vec<u8>,
    pub subject_sig: Vec<u8>,
}

impl DeviceLink {
    pub fn verify(&self) -> Result<(), AccountError> {
        self.body.validate()?;
        let msg = self.body.signing_message();
        verify(&self.body.issuer, &msg, &self.issuer_sig)?;
        verify(&self.body.subject, &msg, &self.subject_sig)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MachineClaimBody {
    pub account_id: String,
    pub host: PublicKey,
    pub claimer: PublicKey,
    pub issued_at: u64,
}

impl MachineClaimBody {
    pub fn host_signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_CLAIM, self)
    }

    pub fn claimer_signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_CLAIM_ACCEPT, self)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MachineClaim {
    pub body: MachineClaimBody,
    pub host_sig: Vec<u8>,
    pub claimer_sig: Vec<u8>,
}

impl MachineClaim {
    pub fn verify(&self) -> Result<(), AccountError> {
        validate_account_id(&self.body.account_id)?;
        verify(
            &self.body.host,
            &self.body.host_signing_message(),
            &self.host_sig,
        )?;
        verify(
            &self.body.claimer,
            &self.body.claimer_signing_message(),
            &self.claimer_sig,
        )
    }
}

/// The host half of a `MachineClaim`, returned by the `AccountClaim` RPC.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HostClaimProof {
    pub body: MachineClaimBody,
    pub host_sig: Vec<u8>,
}

impl HostClaimProof {
    pub fn verify(&self) -> Result<(), AccountError> {
        validate_account_id(&self.body.account_id)?;
        verify(
            &self.body.host,
            &self.body.host_signing_message(),
            &self.host_sig,
        )
    }
}

/// Revocation of `target` signed by another device of the account.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRevocation {
    pub account_id: String,
    pub target: PublicKey,
    pub issued_at: u64,
}

impl DeviceRevocation {
    pub fn signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_REVOKE, self)
    }

    /// Checks the statement shape for `signer`; the signature is checked
    /// separately with [`verify`] over [`Self::signing_message`].
    pub fn verify(&self, signer: &PublicKey) -> Result<(), AccountError> {
        validate_account_id(&self.account_id)?;
        if *signer == self.target {
            return Err(AccountError::Invalid("signer"));
        }
        Ok(())
    }
}

/// Self-removal of `target`, signed by `target`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRemoval {
    pub account_id: String,
    pub target: PublicKey,
    pub issued_at: u64,
}

impl DeviceRemoval {
    pub fn signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_REMOVE, self)
    }

    pub fn validate(&self) -> Result<(), AccountError> {
        validate_account_id(&self.account_id)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedClaimBody {
    pub account_id: String,
    pub host: PublicKey,
    pub claimer: PublicKey,
    pub epoch: u64,
    pub nonce: [u8; 32],
    pub fresh_pair: bool,
}

impl ManagedClaimBody {
    pub fn host_signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_MANAGED_CLAIM, self)
    }

    pub fn claimer_signing_message(&self) -> Vec<u8> {
        context_message(CONTEXT_MANAGED_CLAIM_ACCEPT, self)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedHostProof {
    pub body: ManagedClaimBody,
    pub host_sig: Vec<u8>,
}

impl ManagedHostProof {
    pub fn verify(&self) -> Result<(), AccountError> {
        validate_account_id(&self.body.account_id)?;
        verify(
            &self.body.host,
            &self.body.host_signing_message(),
            &self.host_sig,
        )?;
        if self.body.host == self.body.claimer {
            return Err(AccountError::Invalid("claim"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedClaim {
    pub body: ManagedClaimBody,
    pub host_sig: Vec<u8>,
    pub claimer_sig: Vec<u8>,
}

impl ManagedClaim {
    pub fn verify(&self) -> Result<(), AccountError> {
        validate_account_id(&self.body.account_id)?;
        verify(
            &self.body.host,
            &self.body.host_signing_message(),
            &self.host_sig,
        )?;
        verify(
            &self.body.claimer,
            &self.body.claimer_signing_message(),
            &self.claimer_sig,
        )?;
        if self.body.host == self.body.claimer {
            return Err(AccountError::Invalid("claim"));
        }
        Ok(())
    }
}

statement_bytes!(
    DeviceRegistration,
    DeviceSessionRegistration,
    DeviceLinkBody,
    DeviceLink,
    MachineClaimBody,
    MachineClaim,
    HostClaimProof,
    DeviceRevocation,
    DeviceRemoval,
    ManagedClaimBody,
    ManagedHostProof,
    ManagedClaim,
);

/// `CONTEXT_HOST_REQUEST ‖ method ‖ "\n" ‖ path ‖ "\n" ‖ timestamp ‖ "\n" ‖ sha256(body)`.
pub fn host_request_message(method: &str, path: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut msg = CONTEXT_HOST_REQUEST.to_vec();
    msg.extend_from_slice(method.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(path.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(&Sha256::digest(body));
    msg
}

pub fn approval_commit(nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTEXT_COMMIT);
    h.update(nonce);
    h.finalize().into()
}

/// 12-digit short authentication string over both keys and both nonces.
pub fn approval_sas(
    subject: &PublicKey,
    approver: &PublicKey,
    subject_nonce: &[u8; 32],
    approver_nonce: &[u8; 32],
) -> String {
    let mut h = Sha256::new();
    h.update(CONTEXT_SAS);
    h.update(subject);
    h.update(approver);
    h.update(subject_nonce);
    h.update(approver_nonce);
    let digest = h.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    format!("{:012}", u64::from_be_bytes(head) % 1_000_000_000_000)
}

/// Trust fixpoint over pre-verified links. Each pass, for both directions of
/// every link, admits the far end when the near end is trusted and `admit`
/// agrees. Returns `(admitted key, link index)` in admission order.
pub fn expand_trust(
    trusted: &mut HashSet<PublicKey>,
    links: &[DeviceLink],
    mut admit: impl FnMut(&PublicKey, &DeviceLink) -> bool,
) -> Vec<(PublicKey, usize)> {
    let mut admitted = Vec::new();
    loop {
        let mut progressed = false;
        for (index, link) in links.iter().enumerate() {
            let ends = [
                (link.body.issuer, link.body.subject),
                (link.body.subject, link.body.issuer),
            ];
            for (near, far) in ends {
                if trusted.contains(&near) && !trusted.contains(&far) && admit(&far, link) {
                    trusted.insert(far);
                    admitted.push((far, index));
                    progressed = true;
                }
            }
        }
        if !progressed {
            return admitted;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HostSyncRequest {
    pub version: u64,
    pub wait: bool,
    pub host_name: String,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HostTrustSnapshot {
    pub version: u64,
    pub account_id: String,
    pub locked: bool,
    pub devices: Vec<SnapshotDevice>,
    pub links: Vec<String>,
    pub revoked: Vec<SnapshotRevocation>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotDevice {
    pub public_key: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRevocation {
    pub public_key: String,
    pub revoked_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedHostSyncRequest {
    pub account_id: String,
    pub epoch: u64,
    pub sync: HostSyncRequest,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ManagedHostSyncResponse {
    Active { snapshot: HostTrustSnapshot },
    Pending,
    Removed,
}

/// Body of `MANAGED_HOST_UNLINK_PATH`. Epoch-gated: a stale epoch cannot remove a newer owner.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedHostUnlinkRequest {
    pub account_id: String,
    pub epoch: u64,
}

#[cfg(test)]
mod tests;
