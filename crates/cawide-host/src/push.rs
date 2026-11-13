use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cawide_protocol::types::{AgentState, AgentStatus, PushChannel};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::auth::AuthorizedKeysStore;
use crate::cloud::client::{CloudClient, CloudConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAlertKind {
    NeedsApproval,
    Finished,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAlert {
    pub session_id: String,
    pub agent: String,
    pub kind: AgentAlertKind,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ChannelsFile {
    channels: HashMap<String, PushChannel>,
}

fn validate_channel(channel: &PushChannel) -> Result<(), String> {
    if channel.channel_id.is_empty()
        || channel.channel_id.len() > 64
        || !channel
            .channel_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("invalid push channel".into());
    }
    if channel.secret.len() != 64
        || !channel
            .secret
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err("invalid push channel".into());
    }
    Ok(())
}

fn save_channels_atomic(
    config_dir: &Path,
    channels: &HashMap<String, PushChannel>,
) -> Result<(), String> {
    if !config_dir.exists() {
        let _ = std::fs::create_dir_all(config_dir);
    }
    let file = ChannelsFile {
        channels: channels.clone(),
    };
    let content = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    let path = config_dir.join("push-channels.json");
    let mut temp = tempfile::NamedTempFile::new_in(config_dir)
        .map_err(|e| format!("failed to create temp file: {e}"))?;
    temp.write_all(&content)
        .map_err(|e| format!("failed to write channels file: {e}"))?;
    temp.flush()
        .map_err(|e| format!("failed to flush channels file: {e}"))?;
    temp.persist(&path)
        .map_err(|e| format!("failed to persist channels file: {e}"))?;
    Ok(())
}

pub struct PushService {
    config_dir: PathBuf,
    auth: Arc<AuthorizedKeysStore>,
    host_node_id: [u8; 32],
    channels: Mutex<HashMap<String, PushChannel>>,
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
        let channels_path = config_dir.join("push-channels.json");
        let initial_channels = if channels_path.exists() {
            match std::fs::read(&channels_path) {
                Ok(bytes) => match serde_json::from_slice::<ChannelsFile>(&bytes) {
                    Ok(file) => file.channels,
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

        let cloud = CloudConfig::from_env()
            .ok()
            .and_then(|cfg| CloudClient::new(&cfg).ok())
            .map(Arc::new);

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

    async fn remove_channel_by_hex(&self, client_hex: &str) -> Result<(), String> {
        let snapshot = {
            let mut map = self.channels.lock();
            map.remove(client_hex);
            map.clone()
        };
        let config_dir = self.config_dir.clone();
        tokio::task::spawn_blocking(move || save_channels_atomic(&config_dir, &snapshot))
            .await
            .map_err(|e| e.to_string())?
    }

    pub fn deliverable_channels(&self) -> Vec<(String, PushChannel)> {
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
        if pruned {
            if let Err(e) = save_channels_atomic(&self.config_dir, &map) {
                tracing::warn!("failed to save pruned push channels: {e}");
            }
        }
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn spawn_dispatcher(self: &Arc<Self>, mut rx: tokio::sync::mpsc::Receiver<AgentAlert>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(alert) = rx.recv().await {
                let channels = this.deliverable_channels();
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
                    let cloud = Arc::clone(cloud);
                    let this_sub = Arc::clone(&this);
                    let payload = serde_json::json!({
                        "channel_id": channel.channel_id,
                        "host_node_id": host_node_id,
                        "host_name": host_name,
                        "session_id": alert.session_id,
                        "agent": alert.agent,
                        "kind": alert.kind,
                    });
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
                                    let _ = this_sub.remove_channel_by_hex(&client_hex).await;
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
        assert_eq!(reloaded.channels.lock().get(&client_hex), Some(&channel));
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
}
