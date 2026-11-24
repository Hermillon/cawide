use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use cawide_protocol::types::{
    AgentState, AgentStatus, PushChannel, PushChannelV2, PUSH_CAP_E2E_CONTENT,
    PUSH_CAP_LIVE_ACTIVITY, PUSH_CAP_PUSH_TO_START,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use parking_lot::Mutex;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

use crate::auth::AuthorizedKeysStore;
use crate::cloud::client::{CloudClient, CloudConfig};

const MAX_ENC_BASE64_LEN: usize = 2800;
const MAX_PLAINTEXT_JSON_BYTES: usize = (MAX_ENC_BASE64_LEN / 4) * 3 - 28;
const TOOL_STEP_COALESCE_WINDOW: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAlertKind {
    NeedsApproval,
    NeedsInput,
    NeedsReview,
    Finished,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlertDetail {
    pub actionable: bool,
    pub project: Option<String>,
    pub session_title: Option<String>,
    pub prompt: Option<String>,
    pub options: Vec<String>,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAlert {
    pub session_id: String,
    pub agent: String,
    pub kind: AgentAlertKind,
    pub attention_id: u64,
    pub detail: AlertDetail,
}

impl AgentAlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeedsApproval => "needs_approval",
            Self::NeedsInput => "needs_input",
            Self::NeedsReview => "needs_review",
            Self::Finished => "finished",
            Self::Failed => "failed",
        }
    }

    pub fn legacy_str(self) -> &'static str {
        match self {
            Self::NeedsApproval | Self::NeedsInput | Self::NeedsReview => "needs_approval",
            Self::Finished => "finished",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityPhase {
    Working,
    Waiting,
    Done,
    Failed,
}

impl ActivityPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Waiting => "waiting",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityEventKind {
    Update,
    End,
}

impl ActivityEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::End => "end",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityUpdateEvent {
    pub session_id: String,
    pub agent: String,
    pub phase: ActivityPhase,
    pub event: ActivityEventKind,
    pub ts: u64,
    pub started_at: u64,
    pub prompt_id: Option<u64>,
    pub is_tool_step: bool,
    pub detail: AlertDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertPlaintext {
    pub host_node_id: String,
    pub session_id: String,
    pub prompt_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub actionable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

pub fn encrypt_push_payload(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<String, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(combined))
}

fn truncate_chars_ellipsis(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

fn shrink_opt_string(field: &mut Option<String>, target_chars: usize) -> bool {
    let Some(s) = field else {
        return false;
    };
    if target_chars == 0 {
        *field = None;
        return true;
    }
    if s.chars().count() > target_chars {
        *s = truncate_chars_ellipsis(s, target_chars);
        return true;
    }
    false
}

fn serialize_bounded_plaintext(mut pt: AlertPlaintext) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
    if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
        return Ok(bytes);
    }

    for limit in [400usize, 160, 64, 0] {
        if shrink_opt_string(&mut pt.prompt, limit) {
            bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
            if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
                return Ok(bytes);
            }
        }
    }
    for limit in [240usize, 120, 48, 0] {
        if shrink_opt_string(&mut pt.summary, limit) {
            bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
            if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
                return Ok(bytes);
            }
        }
    }
    if pt.options.is_some() {
        if let Some(opts) = &mut pt.options {
            for opt in opts.iter_mut() {
                if opt.chars().count() > 40 {
                    *opt = truncate_chars_ellipsis(opt, 40);
                }
            }
        }
        loop {
            bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
            if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
                return Ok(bytes);
            }
            let empty_now = if let Some(opts) = &mut pt.options {
                opts.pop();
                opts.is_empty()
            } else {
                true
            };
            if empty_now {
                pt.options = None;
                break;
            }
        }
        bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
        if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
            return Ok(bytes);
        }
    }
    for limit in [240usize, 120, 48, 0] {
        if shrink_opt_string(&mut pt.error, limit) {
            bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
            if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
                return Ok(bytes);
            }
        }
    }
    for limit in [64usize, 0] {
        let _ = shrink_opt_string(&mut pt.session_title, limit);
        let _ = shrink_opt_string(&mut pt.project, limit);
        let _ = shrink_opt_string(&mut pt.host_name, limit);
        bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
        if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
            return Ok(bytes);
        }
    }
    if pt.duration_secs.take().is_some() {
        bytes = serde_json::to_vec(&pt).map_err(|e| e.to_string())?;
        if bytes.len() <= MAX_PLAINTEXT_JSON_BYTES {
            return Ok(bytes);
        }
    }
    Err("encrypted push payload exceeds size limit".into())
}

fn encrypt_alert_plaintext(
    key_bytes: &[u8],
    aad: &str,
    pt: AlertPlaintext,
) -> Result<String, String> {
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid content key length".to_string())?;
    let plaintext = serialize_bounded_plaintext(pt)?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    encrypt_push_payload(&key, &nonce, aad.as_bytes(), &plaintext)
}

pub fn build_notify_payload(
    channel: &PushChannelV2,
    host_node_id: &str,
    host_name: &str,
    alert: &AgentAlert,
) -> Result<serde_json::Value, String> {
    if (channel.caps & PUSH_CAP_E2E_CONTENT) != 0 {
        if channel.content_key.len() != 32 {
            return Err("invalid content key".into());
        }
        let kind_str = alert.kind.as_str();
        let aad = format!(
            "cawide-push/1|{host_node_id}|{}|{}|{kind_str}",
            alert.session_id, alert.attention_id
        );
        let pt = AlertPlaintext {
            host_node_id: host_node_id.to_string(),
            session_id: alert.session_id.clone(),
            prompt_id: alert.attention_id,
            kind: Some(kind_str.to_string()),
            phase: None,
            actionable: alert.detail.actionable,
            host_name: Some(host_name.to_string()),
            project: alert.detail.project.clone(),
            session_title: alert.detail.session_title.clone(),
            prompt: alert.detail.prompt.clone(),
            options: (!alert.detail.options.is_empty()).then(|| alert.detail.options.clone()),
            summary: alert.detail.summary.clone(),
            error: alert.detail.error.clone(),
            duration_secs: alert.detail.duration_secs,
        };
        let enc = encrypt_alert_plaintext(&channel.content_key, &aad, pt)?;
        Ok(serde_json::json!({
            "channel_id": channel.channel_id,
            "host_node_id": host_node_id,
            "session_id": alert.session_id,
            "agent": alert.agent,
            "kind": kind_str,
            "prompt_id": alert.attention_id,
            "enc": enc,
        }))
    } else {
        Ok(serde_json::json!({
            "channel_id": channel.channel_id,
            "host_node_id": host_node_id,
            "host_name": host_name,
            "session_id": alert.session_id,
            "agent": alert.agent,
            "kind": alert.kind.legacy_str(),
        }))
    }
}

pub fn build_activity_payload(
    channel: &PushChannelV2,
    host_node_id: &str,
    host_name: &str,
    ev: &ActivityUpdateEvent,
) -> Result<serde_json::Value, String> {
    let phase_str = ev.phase.as_str();
    let prompt_id_or_zero = ev.prompt_id.unwrap_or(0);
    let enc = if (channel.caps & PUSH_CAP_E2E_CONTENT) != 0 {
        if channel.content_key.len() != 32 {
            return Err("invalid content key".into());
        }
        let aad = format!(
            "cawide-la/1|{host_node_id}|{}|{prompt_id_or_zero}|{phase_str}",
            ev.session_id
        );
        let pt = AlertPlaintext {
            host_node_id: host_node_id.to_string(),
            session_id: ev.session_id.clone(),
            prompt_id: prompt_id_or_zero,
            kind: None,
            phase: Some(phase_str.to_string()),
            actionable: ev.detail.actionable,
            host_name: Some(host_name.to_string()),
            project: ev.detail.project.clone(),
            session_title: ev.detail.session_title.clone(),
            prompt: ev.detail.prompt.clone(),
            options: (!ev.detail.options.is_empty()).then(|| ev.detail.options.clone()),
            summary: ev.detail.summary.clone(),
            error: ev.detail.error.clone(),
            duration_secs: ev.detail.duration_secs,
        };
        Some(encrypt_alert_plaintext(&channel.content_key, &aad, pt)?)
    } else {
        None
    };

    let mut content_state = serde_json::Map::new();
    content_state.insert("v".into(), serde_json::json!(1));
    content_state.insert("phase".into(), serde_json::json!(phase_str));
    content_state.insert("agent".into(), serde_json::json!(ev.agent));
    content_state.insert("startedAt".into(), serde_json::json!(ev.started_at));
    if let Some(pid) = ev.prompt_id {
        content_state.insert("promptId".into(), serde_json::json!(pid));
    }
    if let Some(enc_str) = enc {
        content_state.insert("enc".into(), serde_json::json!(enc_str));
    }

    let mut body = serde_json::Map::new();
    body.insert("channel_id".into(), serde_json::json!(channel.channel_id));
    body.insert("host_node_id".into(), serde_json::json!(host_node_id));
    body.insert("session_id".into(), serde_json::json!(ev.session_id));
    body.insert("event".into(), serde_json::json!(ev.event.as_str()));
    body.insert("ts".into(), serde_json::json!(ev.ts));
    body.insert(
        "content_state".into(),
        serde_json::Value::Object(content_state),
    );
    if (channel.caps & PUSH_CAP_PUSH_TO_START) != 0 && ev.event == ActivityEventKind::Update {
        body.insert(
            "start_attributes".into(),
            serde_json::json!({
                "hostNodeId": host_node_id,
                "sessionId": ev.session_id,
                "agent": ev.agent,
            }),
        );
    }
    Ok(serde_json::Value::Object(body))
}

pub fn alert_for_transition(
    old: Option<&AgentState>,
    new: Option<&AgentState>,
) -> Option<AgentAlertKind> {
    let Some(new_s) = new else {
        if let Some(old_s) = old {
            match old_s.status {
                AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. } => {
                    return Some(AgentAlertKind::Failed);
                }
                AgentStatus::Idle | AgentStatus::Completed { .. } => return None,
            }
        }
        return None;
    };

    match &new_s.status {
        AgentStatus::WaitingForInput { .. } => {
            if let Some(old_s) = old {
                if old_s.agent == new_s.agent
                    && matches!(old_s.status, AgentStatus::WaitingForInput { .. })
                {
                    return None;
                }
            }
            Some(AgentAlertKind::NeedsApproval)
        }
        AgentStatus::Completed { .. } => {
            if let Some(old_s) = old {
                if old_s.agent == new_s.agent
                    && (matches!(old_s.status, AgentStatus::Thinking { .. })
                        || matches!(old_s.status, AgentStatus::WaitingForInput { .. }))
                {
                    return Some(AgentAlertKind::Finished);
                }
            }
            None
        }
        _ => None,
    }
}

pub fn alert_kind_for_attention(kind: &crate::agent::map::AttentionKind) -> AgentAlertKind {
    match kind {
        crate::agent::map::AttentionKind::Approval => AgentAlertKind::NeedsApproval,
        crate::agent::map::AttentionKind::Ask { .. }
        | crate::agent::map::AttentionKind::TextQuestion => AgentAlertKind::NeedsInput,
        crate::agent::map::AttentionKind::Plan { .. } => AgentAlertKind::NeedsReview,
    }
}

pub fn alert_for_tracker_transition(
    old: Option<&AgentState>,
    new: Option<&AgentState>,
    old_head_id: Option<u64>,
    new_head: Option<&crate::agent::tracker::Attention>,
    outcome: &crate::agent::map::TurnOutcome,
    old_turn_started_at: Option<u64>,
    now_secs: u64,
) -> Option<AgentAlertKind> {
    let Some(new_s) = new else {
        if let Some(old_s) = old {
            if matches!(
                old_s.status,
                AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
            ) {
                return Some(AgentAlertKind::Failed);
            }
        }
        return None;
    };

    match &new_s.status {
        AgentStatus::WaitingForInput { .. } => {
            if let Some(head) = new_head {
                if old_head_id != Some(head.id) {
                    return Some(alert_kind_for_attention(&head.kind));
                }
                return None;
            }
            if let Some(old_s) = old {
                if old_s.agent == new_s.agent
                    && matches!(old_s.status, AgentStatus::WaitingForInput { .. })
                {
                    return None;
                }
            }
            Some(AgentAlertKind::NeedsApproval)
        }
        AgentStatus::Completed { .. } => {
            if matches!(outcome, crate::agent::map::TurnOutcome::Failed { .. }) {
                let already_same = old.is_some_and(|old_s| {
                    old_s.agent == new_s.agent && old_s.status == new_s.status
                });
                return (!already_same).then_some(AgentAlertKind::Failed);
            }
            let had_active_turn = old.is_some_and(|old_s| {
                old_s.agent == new_s.agent
                    && matches!(
                        old_s.status,
                        AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
                    )
            }) || old_turn_started_at
                .is_some_and(|started| now_secs.saturating_sub(started) < 1800);
            if had_active_turn {
                Some(AgentAlertKind::Finished)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredChannel {
    channel_id: String,
    secret: String,
    #[serde(default)]
    content_key: Vec<u8>,
    #[serde(default)]
    caps: u32,
}

impl From<StoredChannel> for PushChannelV2 {
    fn from(s: StoredChannel) -> Self {
        Self {
            channel_id: s.channel_id,
            secret: s.secret,
            content_key: s.content_key,
            caps: s.caps,
        }
    }
}

impl From<&PushChannelV2> for StoredChannel {
    fn from(c: &PushChannelV2) -> Self {
        Self {
            channel_id: c.channel_id.clone(),
            secret: c.secret.clone(),
            content_key: c.content_key.clone(),
            caps: c.caps,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ChannelsFile {
    channels: HashMap<String, StoredChannel>,
}

fn validate_channel_id_and_secret(channel_id: &str, secret: &str) -> Result<(), String> {
    if channel_id.is_empty()
        || channel_id.len() > 64
        || !channel_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("invalid push channel".into());
    }
    if secret.len() != 64
        || !secret
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err("invalid push channel".into());
    }
    Ok(())
}

fn validate_channel(channel: &PushChannel) -> Result<(), String> {
    validate_channel_id_and_secret(&channel.channel_id, &channel.secret)
}

fn validate_channel_v2(channel: &PushChannelV2) -> Result<(), String> {
    validate_channel_id_and_secret(&channel.channel_id, &channel.secret)?;
    if channel.caps & PUSH_CAP_E2E_CONTENT != 0 {
        if channel.content_key.len() != 32 {
            return Err("invalid content key".into());
        }
    } else if !channel.content_key.is_empty() {
        return Err("invalid content key".into());
    }
    Ok(())
}

fn save_channels_atomic(
    config_dir: &Path,
    channels: &HashMap<String, PushChannelV2>,
) -> Result<(), String> {
    if !config_dir.exists() {
        let _ = std::fs::create_dir_all(config_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let file = ChannelsFile {
        channels: channels
            .iter()
            .map(|(k, v)| (k.clone(), StoredChannel::from(v)))
            .collect(),
    };
    let content = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    let path = config_dir.join("push-channels.json");
    let mut temp = tempfile::NamedTempFile::new_in(config_dir)
        .map_err(|e| format!("failed to create temp file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = temp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    temp.write_all(&content)
        .map_err(|e| format!("failed to write channels file: {e}"))?;
    temp.flush()
        .map_err(|e| format!("failed to flush channels file: {e}"))?;
    temp.persist(&path)
        .map_err(|e| format!("failed to persist channels file: {e}"))?;
    Ok(())
}

struct PrunedChannels {
    snapshot: Option<HashMap<String, PushChannelV2>>,
    deliverable: Vec<(String, PushChannelV2)>,
}

pub struct PushService {
    config_dir: PathBuf,
    auth: Arc<AuthorizedKeysStore>,
    host_node_id: [u8; 32],
    channels: Mutex<HashMap<String, PushChannelV2>>,
    cloud: Option<Arc<CloudClient>>,
}

impl std::fmt::Debug for PushService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushService")
            .field("host_node_id", &self.host_node_id)
            .field("channels_count", &self.channels.lock().len())
            .finish()
    }
}

impl PushService {
    pub fn open(
        config_dir: &Path,
        auth: Arc<AuthorizedKeysStore>,
        host_node_id: [u8; 32],
    ) -> Arc<Self> {
        let cloud = CloudConfig::from_env()
            .ok()
            .and_then(|cfg| CloudClient::new(&cfg).ok())
            .map(Arc::new);
        Self::open_with_cloud(config_dir, auth, host_node_id, cloud)
    }

    pub fn open_with_cloud(
        config_dir: &Path,
        auth: Arc<AuthorizedKeysStore>,
        host_node_id: [u8; 32],
        cloud: Option<Arc<CloudClient>>,
    ) -> Arc<Self> {
        let channels_path = config_dir.join("push-channels.json");
        let initial_channels = if channels_path.exists() {
            match std::fs::read(&channels_path) {
                Ok(bytes) => match serde_json::from_slice::<ChannelsFile>(&bytes) {
                    Ok(file) => file
                        .channels
                        .into_iter()
                        .filter_map(|(k, v)| {
                            let ch = PushChannelV2::from(v);
                            match validate_channel_v2(&ch) {
                                Ok(()) => Some((k, ch)),
                                Err(e) => {
                                    tracing::warn!(client = %k, error = %e, "ignoring invalid stored push channel");
                                    None
                                }
                            }
                        })
                        .collect(),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse push-channels.json");
                        HashMap::new()
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read push-channels.json");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        Arc::new(Self {
            config_dir: config_dir.to_path_buf(),
            auth,
            host_node_id,
            channels: Mutex::new(initial_channels),
            cloud,
        })
    }

    pub async fn set_channel(
        &self,
        client: [u8; 32],
        channel: Option<PushChannel>,
    ) -> Result<(), String> {
        if let Some(ch) = &channel {
            validate_channel(ch)?;
        }
        let v2 = channel.map(|ch| PushChannelV2 {
            channel_id: ch.channel_id,
            secret: ch.secret,
            content_key: Vec::new(),
            caps: 0,
        });
        self.store_channel(client, v2).await
    }

    pub async fn set_channel_v2(
        &self,
        client: [u8; 32],
        channel: Option<PushChannelV2>,
    ) -> Result<(), String> {
        if let Some(ch) = &channel {
            validate_channel_v2(ch)?;
        }
        self.store_channel(client, channel).await
    }

    async fn store_channel(
        &self,
        client: [u8; 32],
        channel: Option<PushChannelV2>,
    ) -> Result<(), String> {
        let client_hex = hex::encode(client);
        let snapshot = {
            let mut map = self.channels.lock();
            if let Some(ch) = channel {
                map.insert(client_hex, ch);
            } else {
                map.remove(&client_hex);
            }
            map.clone()
        };
        let config_dir = self.config_dir.clone();
        tokio::task::spawn_blocking(move || save_channels_atomic(&config_dir, &snapshot))
            .await
            .map_err(|e| e.to_string())?
    }

    async fn remove_channel_if_matches(
        &self,
        client_hex: &str,
        expected: &PushChannelV2,
    ) -> Result<(), String> {
        let snapshot = {
            let mut map = self.channels.lock();
            let matches = map.get(client_hex).is_some_and(|cur| {
                cur.channel_id == expected.channel_id && cur.secret == expected.secret
            });
            if !matches {
                return Ok(());
            }
            map.remove(client_hex);
            map.clone()
        };
        let config_dir = self.config_dir.clone();
        tokio::task::spawn_blocking(move || save_channels_atomic(&config_dir, &snapshot))
            .await
            .map_err(|e| e.to_string())?
    }
    pub fn deliverable_channels(&self) -> Vec<(String, PushChannel)> {
        self.deliverable_channels_v2()
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    PushChannel {
                        channel_id: v.channel_id,
                        secret: v.secret,
                    },
                )
            })
            .collect()
    }

    fn prune_and_snapshot_channels(&self) -> PrunedChannels {
        let mut map = self.channels.lock();
        let mut pruned = false;
        map.retain(|client_hex, _| {
            let mut key = [0u8; 32];
            if hex::decode_to_slice(client_hex, &mut key).is_ok() && self.auth.is_authorized(&key) {
                true
            } else {
                pruned = true;
                false
            }
        });
        let deliverable = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        PrunedChannels {
            snapshot: pruned.then(|| map.clone()),
            deliverable,
        }
    }

    pub fn deliverable_channels_v2(&self) -> Vec<(String, PushChannelV2)> {
        let PrunedChannels {
            snapshot,
            deliverable,
        } = self.prune_and_snapshot_channels();
        if let Some(snapshot) = snapshot {
            if let Err(e) = save_channels_atomic(&self.config_dir, &snapshot) {
                tracing::warn!("failed to save pruned push channels: {e}");
            }
        }
        deliverable
    }

    async fn deliverable_channels_v2_async(&self) -> Vec<(String, PushChannelV2)> {
        let PrunedChannels {
            snapshot,
            deliverable,
        } = self.prune_and_snapshot_channels();
        if let Some(snapshot) = snapshot {
            let config_dir = self.config_dir.clone();
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    if let Err(e) = handle
                        .spawn_blocking(move || save_channels_atomic(&config_dir, &snapshot))
                        .await
                    {
                        tracing::warn!("failed to save pruned push channels: {e}");
                    }
                }
                Err(_) => {
                    if let Err(e) = save_channels_atomic(&config_dir, &snapshot) {
                        tracing::warn!("failed to save pruned push channels: {e}");
                    }
                }
            }
        }
        deliverable
    }

    pub fn spawn_dispatcher(self: &Arc<Self>, mut rx: tokio::sync::mpsc::Receiver<AgentAlert>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(alert) = rx.recv().await {
                let channels = this.deliverable_channels_v2_async().await;
                if channels.is_empty() {
                    continue;
                }
                let Some(cloud) = &this.cloud else {
                    tracing::debug!("push notification dropped: cloud client not configured");
                    continue;
                };

                let host_node_id = hex::encode(this.host_node_id);
                let host_name = crate::net::dispatcher::host_display_name();

                for (client_hex, channel) in channels {
                    let payload =
                        match build_notify_payload(&channel, &host_node_id, &host_name, &alert) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to build push notify payload");
                                continue;
                            }
                        };
                    let cloud = Arc::clone(cloud);
                    let this_sub = Arc::clone(&this);
                    let channel_for_remove = channel.clone();
                    let secret = channel.secret;

                    tokio::spawn(async move {
                        match cloud
                            .post_json("/api/v1/push/notify", &payload, Some(&secret))
                            .await
                        {
                            Ok(resp) => {
                                if resp.status == 202 {
                                    tracing::debug!("push notification accepted");
                                } else if resp.status == 401
                                    || resp.status == 404
                                    || resp.status == 410
                                {
                                    tracing::info!(
                                        status = resp.status,
                                        client = %client_hex,
                                        "push channel invalid or gone; removing"
                                    );
                                    let _ = this_sub
                                        .remove_channel_if_matches(&client_hex, &channel_for_remove)
                                        .await;
                                } else {
                                    tracing::warn!(
                                        status = resp.status,
                                        error = %resp.error_message(),
                                        "push notification failed"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "push notification request failed");
                            }
                        }
                    });
                }
            }
        });
    }

    pub fn spawn_activity_dispatcher(
        self: &Arc<Self>,
        mut rx: tokio::sync::mpsc::Receiver<ActivityUpdateEvent>,
    ) {
        struct ActivityJob {
            client_hex: String,
            channel: PushChannelV2,
            event: ActivityUpdateEvent,
        }
        struct WorkerHandle {
            tx: tokio::sync::mpsc::Sender<ActivityJob>,
            last_tool_step_at: Option<Instant>,
            last_ts: u64,
            last_used: Instant,
            ended: bool,
        }

        fn spawn_worker(
            this: &Arc<PushService>,
            host_node_id: &str,
            host_name: &str,
        ) -> WorkerHandle {
            let (wtx, mut wrx) = tokio::sync::mpsc::channel::<ActivityJob>(32);
            let this_w = Arc::clone(this);
            let host_node_id_w = host_node_id.to_string();
            let host_name_w = host_name.to_string();
            tokio::spawn(async move {
                while let Some(job) = wrx.recv().await {
                    let Some(cloud) = &this_w.cloud else {
                        continue;
                    };
                    let body = match build_activity_payload(
                        &job.channel,
                        &host_node_id_w,
                        &host_name_w,
                        &job.event,
                    ) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to build activity payload");
                            continue;
                        }
                    };
                    match cloud
                        .post_json("/api/v1/push/activity", &body, Some(&job.channel.secret))
                        .await
                    {
                        Ok(resp) => {
                            if (200..300).contains(&resp.status) {
                                if let Ok(v) =
                                    serde_json::from_slice::<serde_json::Value>(&resp.body)
                                {
                                    if matches!(
                                        v.get("status").and_then(|s| s.as_str()),
                                        Some("no_activity" | "stale")
                                    ) {
                                        tracing::debug!(
                                            status = ?v.get("status"),
                                            "live activity update ignored by server"
                                        );
                                    }
                                }
                            } else if resp.status == 401 || resp.status == 404 || resp.status == 410
                            {
                                tracing::info!(
                                    status = resp.status,
                                    client = %job.client_hex,
                                    "push channel invalid or gone; removing"
                                );
                                let _ = this_w
                                    .remove_channel_if_matches(&job.client_hex, &job.channel)
                                    .await;
                            } else {
                                tracing::warn!(
                                    status = resp.status,
                                    error = %resp.error_message(),
                                    "live activity update failed"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "live activity request failed");
                        }
                    }
                }
            });
            WorkerHandle {
                tx: wtx,
                last_tool_step_at: None,
                last_ts: 0,
                last_used: Instant::now(),
                ended: false,
            }
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut workers: HashMap<(String, String), WorkerHandle> = HashMap::new();
            while let Some(ev) = rx.recv().await {
                let channels = this.deliverable_channels_v2_async().await;
                let active_channel_ids: HashSet<&str> = channels
                    .iter()
                    .filter(|(_, ch)| (ch.caps & PUSH_CAP_LIVE_ACTIVITY) != 0)
                    .map(|(_, ch)| ch.channel_id.as_str())
                    .collect();
                workers.retain(|(cid, _), w| {
                    !w.tx.is_closed()
                        && active_channel_ids.contains(cid.as_str())
                        && !(w.ended && w.last_used.elapsed() > Duration::from_secs(300))
                });
                if channels.is_empty() || this.cloud.is_none() {
                    continue;
                }
                let host_node_id = hex::encode(this.host_node_id);
                let host_name = crate::net::dispatcher::host_display_name();

                for (client_hex, channel) in channels {
                    if (channel.caps & PUSH_CAP_LIVE_ACTIVITY) == 0 {
                        continue;
                    }
                    let key = (channel.channel_id.clone(), ev.session_id.clone());
                    let worker = workers
                        .entry(key)
                        .or_insert_with(|| spawn_worker(&this, &host_node_id, &host_name));
                    if worker.tx.is_closed() {
                        *worker = spawn_worker(&this, &host_node_id, &host_name);
                    }

                    if ev.is_tool_step
                        && worker
                            .last_tool_step_at
                            .is_some_and(|t| t.elapsed() < TOOL_STEP_COALESCE_WINDOW)
                    {
                        continue;
                    }

                    let mut ev_send = ev.clone();
                    ev_send.ts = ev_send.ts.max(worker.last_ts);
                    let send_ts = ev_send.ts;
                    let job = ActivityJob {
                        client_hex,
                        channel,
                        event: ev_send,
                    };
                    match worker.tx.try_send(job) {
                        Ok(()) => {
                            worker.last_ts = send_ts;
                            worker.last_used = Instant::now();
                            worker.ended = ev.event == ActivityEventKind::End;
                            if ev.is_tool_step {
                                worker.last_tool_step_at = Some(Instant::now());
                            } else {
                                worker.last_tool_step_at = None;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(job)) => {
                            *worker = spawn_worker(&this, &host_node_id, &host_name);
                            if worker.tx.try_send(job).is_ok() {
                                worker.last_ts = send_ts;
                                worker.last_used = Instant::now();
                                worker.ended = ev.event == ActivityEventKind::End;
                                if ev.is_tool_step {
                                    worker.last_tool_step_at = Some(Instant::now());
                                } else {
                                    worker.last_tool_step_at = None;
                                }
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                session = %ev.session_id,
                                "live activity worker queue full; dropping update"
                            );
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::detect::Foreground;
    use crate::agent::tracker::AgentTracker;

    #[test]
    fn test_alert_for_transition_table() {
        let thinking = AgentState {
            agent: "claude".into(),
            status: AgentStatus::Thinking {
                task_desc: "planning".into(),
            },
            updated_ts: 100,
        };
        let waiting = AgentState {
            agent: "claude".into(),
            status: AgentStatus::WaitingForInput {
                prompt: "approve?".into(),
                options: Vec::new(),
            },
            updated_ts: 101,
        };
        let waiting_codex = AgentState {
            agent: "codex".into(),
            status: AgentStatus::WaitingForInput {
                prompt: "run command?".into(),
                options: Vec::new(),
            },
            updated_ts: 102,
        };
        let completed = AgentState {
            agent: "claude".into(),
            status: AgentStatus::Completed {
                summary: "done".into(),
            },
            updated_ts: 103,
        };
        let idle = AgentState {
            agent: "claude".into(),
            status: AgentStatus::Idle,
            updated_ts: 104,
        };

        // Thinking -> Waiting = NeedsApproval
        assert_eq!(
            alert_for_transition(Some(&thinking), Some(&waiting)),
            Some(AgentAlertKind::NeedsApproval)
        );

        // Waiting -> Waiting same agent = None
        assert_eq!(alert_for_transition(Some(&waiting), Some(&waiting)), None);

        // Waiting(claude) -> Waiting(codex) = NeedsApproval
        assert_eq!(
            alert_for_transition(Some(&waiting), Some(&waiting_codex)),
            Some(AgentAlertKind::NeedsApproval)
        );

        // Thinking -> Completed = Finished
        assert_eq!(
            alert_for_transition(Some(&thinking), Some(&completed)),
            Some(AgentAlertKind::Finished)
        );

        // Idle -> Completed = None
        assert_eq!(alert_for_transition(Some(&idle), Some(&completed)), None);

        // None -> Completed = None
        assert_eq!(alert_for_transition(None, Some(&completed)), None);

        // Thinking -> None = Failed
        assert_eq!(
            alert_for_transition(Some(&thinking), None),
            Some(AgentAlertKind::Failed)
        );

        // Waiting -> None = Failed
        assert_eq!(
            alert_for_transition(Some(&waiting), None),
            Some(AgentAlertKind::Failed)
        );

        // Idle -> None = None
        assert_eq!(alert_for_transition(Some(&idle), None), None);

        // Completed -> None = None
        assert_eq!(alert_for_transition(Some(&completed), None), None);
    }

    #[test]
    fn test_alert_for_tracker_transition_rich_kinds() {
        let idle = AgentState {
            agent: "omp".into(),
            status: AgentStatus::Idle,
            updated_ts: 100,
        };
        let completed = AgentState {
            agent: "omp".into(),
            status: AgentStatus::Completed {
                summary: "done".into(),
            },
            updated_ts: 200,
        };
        let waiting = AgentState {
            agent: "omp".into(),
            status: AgentStatus::WaitingForInput {
                prompt: "Pick".into(),
                options: vec!["A".into()],
            },
            updated_ts: 150,
        };
        let ask_head = crate::agent::tracker::Attention {
            id: 10,
            key: None,
            kind: crate::agent::map::AttentionKind::Ask {
                multi: false,
                initial: 0,
            },
            opened_at_ms: 150_000,
            prompt: "Pick".into(),
            options: vec!["A".into()],
            actionable: true,
        };
        let plan_head = crate::agent::tracker::Attention {
            id: 11,
            key: Some("rev-1".into()),
            kind: crate::agent::map::AttentionKind::Plan {
                review_id: "rev-1".into(),
                option_ids: vec!["execute".into()],
            },
            opened_at_ms: 151_000,
            prompt: "Review".into(),
            options: vec!["Execute".into()],
            actionable: true,
        };

        assert_eq!(
            alert_for_tracker_transition(
                Some(&idle),
                Some(&waiting),
                None,
                Some(&ask_head),
                &crate::agent::map::TurnOutcome::None,
                None,
                150,
            ),
            Some(AgentAlertKind::NeedsInput)
        );
        assert_eq!(
            alert_for_tracker_transition(
                Some(&waiting),
                Some(&waiting),
                Some(10),
                Some(&plan_head),
                &crate::agent::map::TurnOutcome::None,
                None,
                151,
            ),
            Some(AgentAlertKind::NeedsReview)
        );
        // Idle -> Done within 30 min of turn_started_at emits Finished
        assert_eq!(
            alert_for_tracker_transition(
                Some(&idle),
                Some(&completed),
                None,
                None,
                &crate::agent::map::TurnOutcome::Done,
                Some(100),
                200,
            ),
            Some(AgentAlertKind::Finished)
        );
        // Idle -> Done after >= 30 min does not emit Finished
        assert_eq!(
            alert_for_tracker_transition(
                Some(&idle),
                Some(&completed),
                None,
                None,
                &crate::agent::map::TurnOutcome::Done,
                Some(100),
                1900,
            ),
            None
        );
    }

    #[test]
    fn test_probe_path_tracker_to_failed() {
        let mut tracker = AgentTracker::default();
        let now = 1000;
        // Drive tracker to Thinking
        tracker.on_probe(Some(Foreground::Agent("claude")), true, now);
        let current = tracker.current().expect("agent state present");
        assert!(matches!(current.status, AgentStatus::Thinking { .. }));

        let old = tracker.current();
        tracker.on_probe(Some(Foreground::Shell), false, now + 1);
        let new = tracker.current();
        assert_eq!(new, None);

        assert_eq!(
            alert_for_transition(old.as_ref(), new.as_ref()),
            Some(AgentAlertKind::Failed)
        );
    }

    #[tokio::test]
    async fn test_set_channel_persistence_and_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let host_node_id = [0x42u8; 32];

        let service = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);

        let client = [0x01u8; 32];
        let secret = "0123456789abcdef".repeat(4); // gitleaks:allow
        let channel = PushChannel {
            channel_id: "chan-abc-123".into(),
            secret: secret.clone(),
        };

        service
            .set_channel(client, Some(channel.clone()))
            .await
            .expect("set channel should succeed");

        // Reload from disk
        let reloaded = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);
        let client_hex = hex::encode(client);
        assert_eq!(
            reloaded.channels.lock().get(&client_hex),
            Some(&PushChannelV2 {
                channel_id: channel.channel_id,
                secret: channel.secret,
                content_key: Vec::new(),
                caps: 0,
            })
        );
    }

    #[tokio::test]
    async fn test_none_removes_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let host_node_id = [0x42u8; 32];

        let service = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);

        let client = [0x02u8; 32];
        let secret = "abcdef0123456789".repeat(4); // gitleaks:allow
        let channel = PushChannel {
            channel_id: "chan-xyz".into(),
            secret,
        };

        service
            .set_channel(client, Some(channel))
            .await
            .expect("set channel");

        let client_hex = hex::encode(client);
        assert!(service.channels.lock().contains_key(&client_hex));

        service
            .set_channel(client, None)
            .await
            .expect("remove channel");

        assert!(!service.channels.lock().contains_key(&client_hex));

        // Reload and verify disk also does not contain it
        let reloaded = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);
        assert!(!reloaded.channels.lock().contains_key(&client_hex));
    }

    #[tokio::test]
    async fn test_pruning_unauthorized_clients() {
        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let host_node_id = [0x42u8; 32];

        let client_authorized = [0x11u8; 32];
        let client_unauthorized = [0x22u8; 32];

        auth.add_key(client_authorized, "Authorized Device".into())
            .unwrap();

        let service = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);

        let secret = "0123456789abcdef".repeat(4); // gitleaks:allow
        let chan1 = PushChannel {
            channel_id: "chan-auth".into(),
            secret: secret.clone(),
        };
        let chan2 = PushChannel {
            channel_id: "chan-unauth".into(),
            secret,
        };

        service
            .set_channel(client_authorized, Some(chan1.clone()))
            .await
            .unwrap();
        service
            .set_channel(client_unauthorized, Some(chan2))
            .await
            .unwrap();

        assert_eq!(service.channels.lock().len(), 2);

        let deliverable = service.deliverable_channels();
        assert_eq!(deliverable.len(), 1);
        assert_eq!(deliverable[0].0, hex::encode(client_authorized));
        assert_eq!(deliverable[0].1, chan1);

        // In-memory channels should have pruned client_unauthorized
        assert_eq!(service.channels.lock().len(), 1);

        // Reload and check disk
        let reloaded = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);
        assert_eq!(reloaded.channels.lock().len(), 1);
        assert!(reloaded
            .channels
            .lock()
            .contains_key(&hex::encode(client_authorized)));
    }

    #[tokio::test]
    async fn test_channel_validation_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let service = PushService::open(tmp.path(), auth, [0x55u8; 32]);
        let client = [0x99u8; 32];

        let valid_secret = "0123456789abcdef".repeat(4); // gitleaks:allow

        // Empty channel_id
        let err = service
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "".into(),
                    secret: valid_secret.clone(),
                }),
            )
            .await;
        assert!(err.is_err());

        // Channel_id too long (> 64 chars)
        let err = service
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "a".repeat(65),
                    secret: valid_secret.clone(),
                }),
            )
            .await;
        assert!(err.is_err());

        // Channel_id invalid chars (underscore or space)
        let err = service
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "chan_invalid".into(),
                    secret: valid_secret.clone(),
                }),
            )
            .await;
        assert!(err.is_err());

        // Secret too short
        let err = service
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "valid-chan".into(),
                    secret: "a".repeat(63),
                }),
            )
            .await;
        assert!(err.is_err());

        // Secret uppercase hex
        let err = service
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "valid-chan".into(),
                    secret: "A".repeat(64),
                }),
            )
            .await;
        assert!(err.is_err());

        // Secret invalid char
        let err = service
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "valid-chan".into(),
                    secret: format!("{}g", &valid_secret[..63]),
                }),
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_set_channel_v2_validation_and_v1_compat() {
        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let host_node_id = [0x42u8; 32];
        let client = [0x33u8; 32];
        let secret = "0123456789abcdef".repeat(4); // gitleaks:allow

        // Legacy V1 JSON file loads with empty content_key and caps 0
        let legacy_json = serde_json::json!({
            "channels": {
                hex::encode(client): {
                    "channel_id": "chan-v1",
                    "secret": secret,
                }
            }
        });
        std::fs::write(
            tmp.path().join("push-channels.json"),
            serde_json::to_vec(&legacy_json).unwrap(),
        )
        .unwrap();

        let service = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);
        auth.add_key(client, "Phone".into()).unwrap();
        let loaded = service.deliverable_channels_v2();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.content_key, Vec::<u8>::new());
        assert_eq!(loaded[0].1.caps, 0);

        // E2E cap requires 32-byte key
        let bad_len = service
            .set_channel_v2(
                client,
                Some(PushChannelV2 {
                    channel_id: "chan-v2".into(),
                    secret: secret.clone(),
                    content_key: vec![1u8; 16],
                    caps: PUSH_CAP_E2E_CONTENT,
                }),
            )
            .await;
        assert!(bad_len.is_err());

        // Non-E2E cap requires empty key
        let bad_non_e2e = service
            .set_channel_v2(
                client,
                Some(PushChannelV2 {
                    channel_id: "chan-v2".into(),
                    secret: secret.clone(),
                    content_key: vec![1u8; 32],
                    caps: 0,
                }),
            )
            .await;
        assert!(bad_non_e2e.is_err());

        // Valid V2 channel persists and reloads
        let key = vec![0xABu8; 32];
        service
            .set_channel_v2(
                client,
                Some(PushChannelV2 {
                    channel_id: "chan-v2".into(),
                    secret: secret.clone(),
                    content_key: key.clone(),
                    caps: PUSH_CAP_E2E_CONTENT | cawide_protocol::types::PUSH_CAP_ACTIONS,
                }),
            )
            .await
            .unwrap();
        let reloaded = PushService::open(tmp.path(), Arc::clone(&auth), host_node_id);
        let v2 = reloaded.deliverable_channels_v2();
        assert_eq!(v2[0].1.content_key, key);
        assert_eq!(
            v2[0].1.caps,
            PUSH_CAP_E2E_CONTENT | cawide_protocol::types::PUSH_CAP_ACTIONS
        );

        // V1 set_channel clears key and caps
        reloaded
            .set_channel(
                client,
                Some(PushChannel {
                    channel_id: "chan-v1-again".into(),
                    secret,
                }),
            )
            .await
            .unwrap();
        let after_v1 = reloaded.deliverable_channels_v2();
        assert_eq!(after_v1[0].1.content_key, Vec::<u8>::new());
        assert_eq!(after_v1[0].1.caps, 0);
    }

    #[test]
    fn test_cross_language_crypto_vector() {
        let key: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
        let nonce: [u8; 12] = std::array::from_fn(|i| (0x11 + i) as u8);
        let aad = b"cawide-push/1|node123|sess1|42|needs_approval";
        let plaintext = br#"{"host_node_id":"node123","session_id":"sess1","prompt_id":42,"kind":"needs_approval","actionable":true,"host_name":"MacBook","project":"cawide","prompt":"Run ls?"}"#;

        let enc = encrypt_push_payload(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(
            enc,
            "ERITFBUWFxgZGhscIpb3aw5zl6CRtpt74msaGe0HdD8WRSNitDIgfHGEu8OSAxUzsFRUwgJvbwfMSuo+yMRkTkoOCpis/cMS13dzJ5AfOXkhLmKkyZLVUcKUA05ycMQJsW+26DuWFF1BQguiThLu6UlGiCR/JSXB/DIPdllRnX04Kr33b4yAY5PDxtD3tUFgFuzL0chChqLxNcL3GlMTeeHQAErtaKyDAOIELn8OwgBceGQEuaZuLihdKHY1F5WQ"
        );
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&enc)
            .unwrap();
        assert_eq!(&raw[..12], &nonce);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let decrypted = cipher
            .decrypt(
                Nonce::from_slice(&raw[..12]),
                Payload {
                    msg: &raw[12..],
                    aad,
                },
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
        // Wrong AAD must fail authentication
        assert!(cipher
            .decrypt(
                Nonce::from_slice(&raw[..12]),
                Payload {
                    msg: &raw[12..],
                    aad: b"cawide-push/1|node123|sess1|43|needs_approval",
                },
            )
            .is_err());
    }

    #[test]
    fn test_notify_payload_v2_e2e_and_truncation() {
        let key = vec![0x42u8; 32];
        let ch_v2 = PushChannelV2 {
            channel_id: "ch-v2".into(),
            secret: "sec".into(),
            content_key: key.clone(),
            caps: PUSH_CAP_E2E_CONTENT | cawide_protocol::types::PUSH_CAP_ACTIONS,
        };
        let alert = AgentAlert {
            session_id: "sess-1".into(),
            agent: "omp".into(),
            kind: AgentAlertKind::NeedsInput,
            attention_id: 99,
            detail: AlertDetail {
                actionable: true,
                project: Some("cawide-production".into()),
                session_title: Some("Fix push".into()),
                prompt: Some("x".repeat(5000)),
                options: vec!["Option A".into(), "Option B".into()],
                summary: Some("y".repeat(2000)),
                error: None,
                duration_secs: Some(12),
            },
        };
        let payload = build_notify_payload(&ch_v2, "nodeabc", "SecretHost", &alert).unwrap();
        assert!(payload.get("host_name").is_none());
        assert_eq!(payload["kind"], "needs_input");
        assert_eq!(payload["prompt_id"], 99);
        let enc = payload["enc"].as_str().unwrap();
        assert!(enc.len() <= MAX_ENC_BASE64_LEN, "enc len {}", enc.len());

        let raw = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let aad = b"cawide-push/1|nodeabc|sess-1|99|needs_input";
        let pt_bytes = cipher
            .decrypt(
                Nonce::from_slice(&raw[..12]),
                Payload {
                    msg: &raw[12..],
                    aad,
                },
            )
            .unwrap();
        let pt: AlertPlaintext = serde_json::from_slice(&pt_bytes).unwrap();
        assert_eq!(pt.host_node_id, "nodeabc");
        assert_eq!(pt.session_id, "sess-1");
        assert_eq!(pt.prompt_id, 99);
        assert_eq!(pt.kind.as_deref(), Some("needs_input"));
        assert_eq!(pt.host_name.as_deref(), Some("SecretHost"));
        assert_eq!(pt.project.as_deref(), Some("cawide-production"));
        assert!(pt.actionable);

        // V1 channel omits enc/prompt_id and maps NeedsInput -> needs_approval
        let ch_v1 = PushChannelV2 {
            channel_id: "ch-v1".into(),
            secret: "sec".into(),
            content_key: Vec::new(),
            caps: 0,
        };
        let v1_payload = build_notify_payload(&ch_v1, "nodeabc", "SecretHost", &alert).unwrap();
        assert_eq!(v1_payload["host_name"], "SecretHost");
        assert_eq!(v1_payload["kind"], "needs_approval");
        assert!(v1_payload.get("enc").is_none());
        assert!(v1_payload.get("prompt_id").is_none());
    }

    #[test]
    fn test_activity_payload_aad_and_start_attributes() {
        let key = vec![0x77u8; 32];
        let ch_pts = PushChannelV2 {
            channel_id: "ch-la".into(),
            secret: "sec".into(),
            content_key: key.clone(),
            caps: PUSH_CAP_E2E_CONTENT | PUSH_CAP_LIVE_ACTIVITY | PUSH_CAP_PUSH_TO_START,
        };
        let ev_update = ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Working,
            event: ActivityEventKind::Update,
            ts: 1764000010,
            started_at: 1764000000,
            prompt_id: None,
            is_tool_step: false,
            detail: AlertDetail {
                project: Some("cawide".into()),
                session_title: Some("main".into()),
                prompt: Some("Running tests".into()),
                ..Default::default()
            },
        };
        let body = build_activity_payload(&ch_pts, "node1", "Mac", &ev_update).unwrap();
        assert_eq!(body["event"], "update");
        assert_eq!(body["ts"], 1764000010);
        assert_eq!(body["start_attributes"]["hostNodeId"], "node1");
        assert_eq!(body["start_attributes"]["sessionId"], "s1");
        assert_eq!(body["start_attributes"]["agent"], "omp");
        assert_eq!(body["content_state"]["v"], 1);
        assert_eq!(body["content_state"]["phase"], "working");
        assert_eq!(body["content_state"]["startedAt"], 1764000000);
        assert!(body["content_state"].get("promptId").is_none());

        let enc = body["content_state"]["enc"].as_str().unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let pt_bytes = cipher
            .decrypt(
                Nonce::from_slice(&raw[..12]),
                Payload {
                    msg: &raw[12..],
                    aad: b"cawide-la/1|node1|s1|0|working",
                },
            )
            .unwrap();
        let pt: AlertPlaintext = serde_json::from_slice(&pt_bytes).unwrap();
        assert_eq!(pt.phase.as_deref(), Some("working"));
        assert_eq!(pt.prompt_id, 0);

        // End event omits start_attributes even when PUSH_CAP_PUSH_TO_START is set
        let ev_end = ActivityUpdateEvent {
            phase: ActivityPhase::Done,
            event: ActivityEventKind::End,
            prompt_id: Some(55),
            ..ev_update.clone()
        };
        let end_body = build_activity_payload(&ch_pts, "node1", "Mac", &ev_end).unwrap();
        assert!(end_body.get("start_attributes").is_none());
        assert_eq!(end_body["content_state"]["promptId"], 55);

        // Without PUSH_CAP_PUSH_TO_START, update omits start_attributes
        let ch_no_pts = PushChannelV2 {
            caps: PUSH_CAP_E2E_CONTENT | PUSH_CAP_LIVE_ACTIVITY,
            ..ch_pts
        };
        let no_pts_body = build_activity_payload(&ch_no_pts, "node1", "Mac", &ev_update).unwrap();
        assert!(no_pts_body.get("start_attributes").is_none());
    }

    #[tokio::test]
    async fn test_activity_dispatcher_coalescing_fifo_and_status_handling() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let received_srv = Arc::clone(&received);

        let srv = tokio::spawn(async move {
            let mut idx = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 16384];
                let mut total = 0usize;
                loop {
                    let n = sock.read(&mut buf[total..]).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    total += n;
                    if let Some(hdr_end) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                        let hdrs = String::from_utf8_lossy(&buf[..hdr_end]);
                        let content_len = hdrs
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        let body_start = hdr_end + 4;
                        if total >= body_start + content_len {
                            let body: serde_json::Value =
                                serde_json::from_slice(&buf[body_start..body_start + content_len])
                                    .unwrap();
                            received_srv.lock().push(body);
                            break;
                        }
                    }
                }
                idx += 1;
                let resp = if idx == 1 {
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"status\":\"no_activity\"}"
                } else if idx == 2 {
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"status\":\"stale\"}"
                } else if idx == 3 {
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"
                } else {
                    "HTTP/1.1 410 Gone\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                };
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let client = [0x55u8; 32];
        auth.add_key(client, "iPhone".into()).unwrap();
        let cloud = Arc::new(CloudClient::new_insecure_for_test(format!("http://{addr}")));
        let service =
            PushService::open_with_cloud(tmp.path(), Arc::clone(&auth), [0x11u8; 32], Some(cloud));
        service
            .set_channel_v2(
                client,
                Some(PushChannelV2 {
                    channel_id: "ch-1".into(),
                    secret: "0123456789abcdef".repeat(4),
                    content_key: vec![0x99u8; 32],
                    caps: PUSH_CAP_E2E_CONTENT | PUSH_CAP_LIVE_ACTIVITY | PUSH_CAP_PUSH_TO_START,
                }),
            )
            .await
            .unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        service.spawn_activity_dispatcher(rx);

        // 1. Working start (sent)
        tx.send(ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Working,
            event: ActivityEventKind::Update,
            ts: 100,
            started_at: 100,
            prompt_id: None,
            is_tool_step: false,
            detail: AlertDetail::default(),
        })
        .await
        .unwrap();
        // 2. First tool step (sent)
        tx.send(ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Working,
            event: ActivityEventKind::Update,
            ts: 101,
            started_at: 100,
            prompt_id: None,
            is_tool_step: true,
            detail: AlertDetail {
                prompt: Some("Read a.rs".into()),
                ..Default::default()
            },
        })
        .await
        .unwrap();
        // 3. Second tool step within 20s (coalesced!)
        tx.send(ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Working,
            event: ActivityEventKind::Update,
            ts: 102,
            started_at: 100,
            prompt_id: None,
            is_tool_step: true,
            detail: AlertDetail {
                prompt: Some("Edit b.rs".into()),
                ..Default::default()
            },
        })
        .await
        .unwrap();
        // 4. Waiting phase transition (never coalesced; ts clamped monotonic if lower)
        tx.send(ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Waiting,
            event: ActivityEventKind::Update,
            ts: 99,
            started_at: 100,
            prompt_id: Some(7),
            is_tool_step: false,
            detail: AlertDetail {
                actionable: true,
                prompt: Some("Allow?".into()),
                ..Default::default()
            },
        })
        .await
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        while received.lock().len() < 3 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Give a brief moment to ensure coalesced event wasn't sent and channel wasn't dropped on 200 no_activity/stale
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(received.lock().len(), 3);
        assert_eq!(service.deliverable_channels_v2().len(), 1);
        {
            let reqs = received.lock();
            assert_eq!(reqs[0]["content_state"]["phase"], "working");
            assert_eq!(reqs[0]["ts"], 100);
            assert_eq!(reqs[1]["content_state"]["phase"], "working");
            assert_eq!(reqs[1]["ts"], 101);
            assert_eq!(reqs[2]["content_state"]["phase"], "waiting");
            assert_eq!(reqs[2]["ts"], 101); // monotonic clamp from 99 -> 101
        }

        // 5. End event triggers 410 Gone -> channel dropped
        tx.send(ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Done,
            event: ActivityEventKind::End,
            ts: 105,
            started_at: 100,
            prompt_id: None,
            is_tool_step: false,
            detail: AlertDetail::default(),
        })
        .await
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        while !service.deliverable_channels_v2().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(service.deliverable_channels_v2().is_empty());
        srv.abort();
    }

    #[test]
    fn test_e2e_cap_fails_closed_on_invalid_key_and_reload_rejects_corrupt_channel() {
        let bad_ch = PushChannelV2 {
            channel_id: "ch-bad".into(),
            secret: "0123456789abcdef".repeat(4),
            content_key: vec![1u8; 16],
            caps: PUSH_CAP_E2E_CONTENT | PUSH_CAP_LIVE_ACTIVITY,
        };
        let alert = AgentAlert {
            session_id: "s1".into(),
            agent: "omp".into(),
            kind: AgentAlertKind::NeedsApproval,
            attention_id: 1,
            detail: AlertDetail::default(),
        };
        assert!(build_notify_payload(&bad_ch, "node1", "Mac", &alert).is_err());

        let ev = ActivityUpdateEvent {
            session_id: "s1".into(),
            agent: "omp".into(),
            phase: ActivityPhase::Working,
            event: ActivityEventKind::Update,
            ts: 100,
            started_at: 100,
            prompt_id: None,
            is_tool_step: false,
            detail: AlertDetail::default(),
        };
        assert!(build_activity_payload(&bad_ch, "node1", "Mac", &ev).is_err());

        let tmp = tempfile::tempdir().unwrap();
        let auth_path = tmp.path().join("authorized_keys");
        let auth = Arc::new(AuthorizedKeysStore::open_or_create(auth_path).unwrap());
        let client = [0x33u8; 32];
        auth.add_key(client, "Phone".into()).unwrap();
        let corrupt_json = serde_json::json!({
            "channels": {
                hex::encode(client): {
                    "channel_id": "ch-bad",
                    "secret": "0123456789abcdef".repeat(4),
                    "content_key": [1, 2, 3],
                    "caps": PUSH_CAP_E2E_CONTENT
                }
            }
        });
        std::fs::write(
            tmp.path().join("push-channels.json"),
            serde_json::to_vec(&corrupt_json).unwrap(),
        )
        .unwrap();
        let reloaded = PushService::open_with_cloud(tmp.path(), auth, [0x11u8; 32], None);
        assert!(reloaded.deliverable_channels_v2().is_empty());
    }
}
