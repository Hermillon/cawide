//! Registry of long-lived PTY sessions keyed by client-chosen session id.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::agent::detect::{classify, Foreground};
use crate::agent::map::{AgentSignal, SignalResolution, TurnOutcome};
use crate::agent::tracker::{AgentTracker, Attention, TrackerAlert};
use crate::net::broadcaster::HostEventBroadcaster;
use crate::pty::output::TerminalSignals;
use crate::pty::process::{proc_cwd, proc_info, ProcScratch};
use crate::pty::{PtyError, PtySession, PtySpawnOptions};
use crate::rpc::git::find_git_root;
use cawide_protocol::types::{AgentStatus, SessionSummary};
pub const MAX_SESSIONS: usize = 32;

pub struct AttachClaim {
    pub owner: [u8; 32],
    pub token: u64,
    pub kick_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

pub enum ClaimResult {
    Success {
        token: u64,
        kick_rx: tokio::sync::oneshot::Receiver<()>,
    },
    Occupied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudePendingKind {
    Approval,
    Ask,
    Plan,
}

pub struct PendingPermission {
    pub reply_tx: tokio::sync::oneshot::Sender<crate::net::ipc::ClaudeReply>,
    pub kind: ClaudePendingKind,
    pub tool_use_id: Option<String>,
    pub tool_name: String,
    pub anchor: Option<crate::agent::claude::PermissionAnchor>,
    pub anchor_seen_on_attach: bool,
}

pub struct ClaudeRegisteredInfo {
    pub request_key: String,
    pub tool_use_id: Option<String>,
}

pub struct SessionEntry {
    pub session: Arc<PtySession>,
    pub cwd: PathBuf,
    pub git_root: Option<PathBuf>,
    pub title: Option<String>,
    pub revision: u64,
    pub active_cmd: Option<String>,
    pub last_active_ts: Arc<AtomicU64>,
    pub tracker: AgentTracker,
    pub claim: Option<AttachClaim>,
    pub exit_alerted: bool,
    pub agent_stream: Option<(
        u64,
        tokio::sync::mpsc::Sender<crate::net::ipc::IpcStreamOut>,
    )>,
    pub respond_lock: Arc<tokio::sync::Mutex<()>>,
    pub claude_state: crate::agent::claude::ClaudeSessionState,
    pub pending_permissions: HashMap<String, PendingPermission>,
    pub last_anchor_check_ms: u64,
}
pub struct SessionRegistry {
    sessions: parking_lot::RwLock<HashMap<String, SessionEntry>>,
    workdir: PathBuf,
    launch_cmd: Option<String>,
    base_env: Vec<(String, String)>,
    broadcaster: Arc<HostEventBroadcaster>,
    next_claim_token: AtomicU64,
    next_revision: AtomicU64,
    next_stream_id: AtomicU64,
    last_input_unix: AtomicU64,
    config_dir: Option<PathBuf>,
    alerts: Option<tokio::sync::mpsc::Sender<crate::push::AgentAlert>>,
    activities: Option<tokio::sync::mpsc::Sender<crate::push::ActivityUpdateEvent>>,
}

pub struct RespondSnapshot {
    pub session: Arc<PtySession>,
    pub agent_state: Option<cawide_protocol::types::AgentState>,
    pub head_attention: Option<Attention>,
    pub claude_pending: Option<(String, ClaudePendingKind)>,
}
/// Session ids: 1..=64 bytes of `[A-Za-z0-9_-]`.
pub fn validate_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(1)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn project_name(entry: &SessionEntry) -> Option<String> {
    let root = entry.git_root.as_deref().unwrap_or(&entry.cwd);
    root.file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn tab_title(session_id: &str, entry: &SessionEntry) -> Option<String> {
    if let Some(title) = entry
        .title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(title.to_string());
    }
    if let Some(dir_name) = entry
        .cwd
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
    {
        return Some(dir_name.to_string());
    }
    Some(session_id.to_string())
}

fn session_failed_error(entry: &SessionEntry) -> Option<String> {
    let _ = entry.session.is_alive();
    entry
        .session
        .exit_code()
        .filter(|&c| c != 0)
        .map(|c| format!("Process exited with code {c}"))
}

fn summary(id: &str, e: &SessionEntry) -> SessionSummary {
    SessionSummary {
        session_id: id.to_string(),
        workdir: e.cwd.display().to_string(),
        active_cmd: e.active_cmd.clone(),
        last_active_ts: e.last_active_ts.load(Ordering::Relaxed),
        alive: e.session.is_alive(),
        exit_code: e.session.exit_code(),
        attached: e.claim.is_some(),
        agent: e.tracker.current(),
        git_root: e.git_root.as_ref().map(|p| p.display().to_string()),
        title: e.title.clone(),
        revision: e.revision,
    }
}
fn sweep_pending(entry: &mut SessionEntry) {
    let attention_keys = entry.tracker.attention_keys();
    let attention_set: std::collections::HashSet<&str> =
        attention_keys.iter().map(String::as_str).collect();
    entry
        .pending_permissions
        .retain(|k, _| attention_set.contains(k.as_str()));
    entry
        .claude_state
        .open_perms
        .retain(|p| attention_set.contains(p.key.as_str()));
}

pub enum HookOutcome {
    UnknownSession,
    Ignored,
    Updated(Box<SessionSummary>),
}

pub struct ProbeOutcome {
    pub changed: Vec<SessionSummary>,
    pub roots: BTreeSet<PathBuf>,
    pub detected_urls: Vec<(String, String)>,
}
fn is_zsh(cmd: Option<&str>) -> bool {
    if let Some(c) = cmd {
        let first = c.split_whitespace().next().unwrap_or("");
        let file = Path::new(first)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(first);
        file == "zsh" || file.starts_with("zsh")
    } else {
        let shell = std::env::var("SHELL").unwrap_or_default();
        if !shell.is_empty() {
            let file = Path::new(&shell)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&shell);
            file == "zsh" || file.starts_with("zsh")
        } else {
            cfg!(target_os = "macos") || Path::new("/bin/zsh").exists()
        }
    }
}

fn inject_zsh_integration(
    cmd: Option<&str>,
    config_dir: Option<&Path>,
    env: &mut Vec<(String, String)>,
) {
    if !is_zsh(cmd) {
        return;
    }
    let zsh_dir = config_dir.map(|cfg| cfg.join("shell").join("zsh"));
    let orig_zdotdir = std::env::var("ZDOTDIR")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            env.iter()
                .find(|(k, _)| k == "ZDOTDIR")
                .map(|(_, v)| v.clone())
        })
        .filter(|orig| {
            if let Some(zd) = &zsh_dir {
                Path::new(orig) != zd
            } else {
                true
            }
        });
    if let Some(orig) = orig_zdotdir {
        env.retain(|(k, _)| k != "CAWIDE_ORIG_ZDOTDIR");
        env.push(("CAWIDE_ORIG_ZDOTDIR".to_string(), orig));
    }
    if let Some(zd) = zsh_dir {
        env.retain(|(k, _)| k != "ZDOTDIR");
        env.push(("ZDOTDIR".to_string(), zd.display().to_string()));
    }
}

impl SessionRegistry {
    pub fn new(
        workdir: PathBuf,
        launch_cmd: Option<String>,
        base_env: Vec<(String, String)>,
        broadcaster: Arc<HostEventBroadcaster>,
    ) -> Self {
        Self {
            sessions: parking_lot::RwLock::new(HashMap::new()),
            workdir,
            launch_cmd,
            base_env,
            broadcaster,
            next_claim_token: AtomicU64::new(1),
            next_revision: AtomicU64::new(now_micros()),
            next_stream_id: AtomicU64::new(1),
            last_input_unix: AtomicU64::new(0),
            config_dir: crate::net::config_dir().ok(),
            alerts: None,
            activities: None,
        }
    }

    pub fn with_config_dir(mut self, config_dir: PathBuf) -> Self {
        self.config_dir = Some(config_dir);
        self
    }
    pub fn with_alert_sender(
        mut self,
        tx: tokio::sync::mpsc::Sender<crate::push::AgentAlert>,
    ) -> Self {
        self.alerts = Some(tx);
        self
    }

    fn emit_alert(&self, session_id: &str, entry: &SessionEntry, mut alert: TrackerAlert) {
        if let Some(tx) = &self.alerts {
            alert.detail.project = project_name(entry);
            alert.detail.session_title = tab_title(session_id, entry);
            if let Err(e) = tx.try_send(crate::push::AgentAlert {
                session_id: session_id.to_string(),
                agent: alert.agent,
                kind: alert.kind,
                attention_id: alert.attention_id,
                detail: alert.detail,
            }) {
                tracing::debug!(session = %session_id, error = %e, "dropped agent alert");
            }
        }
    }

    pub fn with_activity_sender(
        mut self,
        tx: tokio::sync::mpsc::Sender<crate::push::ActivityUpdateEvent>,
    ) -> Self {
        self.activities = Some(tx);
        self
    }

    fn emit_activity(
        &self,
        session_id: &str,
        entry: &SessionEntry,
        mut activity: crate::agent::tracker::TrackerActivity,
        ts: u64,
    ) {
        if let Some(tx) = &self.activities {
            activity.detail.project = project_name(entry);
            activity.detail.session_title = tab_title(session_id, entry);
            if let Err(e) = tx.try_send(crate::push::ActivityUpdateEvent {
                session_id: session_id.to_string(),
                agent: activity.agent,
                phase: activity.phase,
                event: activity.event,
                ts,
                started_at: activity.started_at,
                prompt_id: activity.prompt_id,
                is_tool_step: activity.is_tool_step,
                dismiss_immediately: activity.dismiss_immediately,
                detail: activity.detail,
            }) {
                tracing::debug!(session = %session_id, error = %e, "dropped activity update");
            }
        }
    }

    fn emit_exit_activity(
        &self,
        session_id: &str,
        entry: &SessionEntry,
        failed_error: Option<String>,
        dismiss_immediately: bool,
        ts: u64,
    ) {
        let Some(state) = entry.tracker.current() else {
            return;
        };
        let should_emit = match state.status {
            AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. } => true,
            AgentStatus::Completed { .. } => dismiss_immediately,
            AgentStatus::Idle => false,
        };
        if !should_emit {
            return;
        }
        let started_at = entry.tracker.turn_started_at().unwrap_or(ts);
        let duration_secs = entry
            .tracker
            .turn_started_at()
            .map(|s| ts.saturating_sub(s));
        let phase = if failed_error.is_some() {
            crate::push::ActivityPhase::Failed
        } else {
            crate::push::ActivityPhase::Done
        };
        self.emit_activity(
            session_id,
            entry,
            crate::agent::tracker::TrackerActivity {
                agent: state.agent,
                phase,
                event: crate::push::ActivityEventKind::End,
                started_at,
                prompt_id: None,
                is_tool_step: false,
                dismiss_immediately,
                detail: crate::push::AlertDetail {
                    error: failed_error,
                    duration_secs,
                    ..Default::default()
                },
            },
            ts,
        );
    }

    fn emit_removed_exit_activity(
        &self,
        session_id: &str,
        entry: &SessionEntry,
        include_exit_error: bool,
        ts: u64,
    ) {
        if !entry.exit_alerted {
            let failed_error = include_exit_error
                .then(|| session_failed_error(entry))
                .flatten();
            let dismiss_immediately = failed_error.is_none();
            self.emit_exit_activity(session_id, entry, failed_error, dismiss_immediately, ts);
        }
    }

    fn handle_dead_session_exit(
        &self,
        session_id: &str,
        entry: &mut SessionEntry,
        emit_failed_alert: bool,
        ts: u64,
    ) {
        if !entry.exit_alerted {
            entry.exit_alerted = true;
            let failed_error = session_failed_error(entry);
            if emit_failed_alert {
                if let Some(err) = &failed_error {
                    if let Some(state) = entry.tracker.current() {
                        if matches!(
                            state.status,
                            AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
                        ) {
                            self.emit_alert(
                                session_id,
                                entry,
                                TrackerAlert {
                                    agent: state.agent,
                                    kind: crate::push::AgentAlertKind::Failed,
                                    attention_id: 0,
                                    detail: crate::push::AlertDetail {
                                        error: Some(err.clone()),
                                        ..Default::default()
                                    },
                                },
                            );
                        }
                    }
                }
            }
            let dismiss_immediately = failed_error.is_none();
            self.emit_exit_activity(session_id, entry, failed_error, dismiss_immediately, ts);
        }
    }

    fn bump(&self) -> u64 {
        self.next_revision.fetch_add(1, Ordering::Relaxed)
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    fn watch_session_eof(&self, session: &Arc<PtySession>) {
        let mut eof_rx = session.subscribe_eof();
        let broadcaster = Arc::clone(&self.broadcaster);
        tokio::spawn(async move {
            let _ = eof_rx.wait_for(|&v| v).await;
            broadcaster.broadcast(cawide_protocol::HostEvent::SessionsChanged);
        });
    }

    /// Returns the live session, replacing a dead one, or spawns a new one.
    ///
    /// The write lock is held across check-and-spawn so concurrent attaches never spawn twice.
    pub fn get_or_create(
        &self,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<PtySession>, PtyError> {
        let mut sessions = self.sessions.write();
        if let Some(entry) = sessions.get_mut(session_id) {
            if entry.session.is_alive() {
                return Ok(Arc::clone(&entry.session));
            }
            self.handle_dead_session_exit(session_id, entry, false, now_secs());
        }
        if !sessions.contains_key(session_id) && sessions.len() >= MAX_SESSIONS {
            return Err(PtyError::MaxSessions(MAX_SESSIONS));
        }
        let mut env = self.base_env.clone();
        env.push(("CAWIDE_SESSION_ID".to_string(), session_id.to_string()));
        inject_zsh_integration(
            self.launch_cmd.as_deref(),
            self.config_dir.as_deref(),
            &mut env,
        );
        let session = PtySession::spawn(
            cols,
            rows,
            PtySpawnOptions {
                workdir: Some(self.workdir.clone()),
                launch_cmd: self.launch_cmd.clone(),
                env,
            },
        )?;
        sessions.insert(
            session_id.to_string(),
            SessionEntry {
                session: Arc::clone(&session),
                cwd: self.workdir.clone(),
                git_root: find_git_root(&self.workdir),
                title: None,
                revision: self.bump(),
                active_cmd: self.launch_cmd.clone(),
                last_active_ts: Arc::new(AtomicU64::new(now_secs())),
                tracker: AgentTracker::default(),
                claim: None,
                exit_alerted: false,
                agent_stream: None,
                respond_lock: Arc::new(tokio::sync::Mutex::new(())),
                claude_state: crate::agent::claude::ClaudeSessionState::default(),
                pending_permissions: HashMap::new(),
                last_anchor_check_ms: 0,
            },
        );
        drop(sessions);
        self.watch_session_eof(&session);
        Ok(session)
    }

    pub fn create_session(
        &self,
        session_id: &str,
        command: Option<String>,
        workdir: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<SessionSummary, String> {
        if !validate_session_id(session_id) {
            return Err(format!("invalid session id: '{session_id}'"));
        }

        let target_dir = match workdir {
            Some(dir) => {
                let p = Path::new(dir);
                let full = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    self.workdir.join(p)
                };
                match full.canonicalize() {
                    Ok(can) if can.is_dir() => can,
                    Ok(_) => return Err("specified workdir is not a directory".into()),
                    Err(e) => return Err(format!("invalid workdir '{dir}': {e}")),
                }
            }
            None => self.workdir.clone(),
        };

        let mut sessions = self.sessions.write();
        if sessions.contains_key(session_id) {
            return Err(format!("session already exists: {session_id}"));
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(format!("maximum session limit reached ({MAX_SESSIONS})"));
        }
        let cmd = command.or_else(|| self.launch_cmd.clone());
        let mut env = self.base_env.clone();
        env.push(("CAWIDE_SESSION_ID".to_string(), session_id.to_string()));
        inject_zsh_integration(cmd.as_deref(), self.config_dir.as_deref(), &mut env);
        let session = PtySession::spawn(
            cols,
            rows,
            PtySpawnOptions {
                workdir: Some(target_dir.clone()),
                launch_cmd: cmd.clone(),
                env,
            },
        )
        .map_err(|e| e.to_string())?;

        let now = now_secs();
        let entry = SessionEntry {
            session: Arc::clone(&session),
            cwd: target_dir.clone(),
            git_root: find_git_root(&target_dir),
            title: None,
            revision: self.bump(),
            active_cmd: cmd,
            last_active_ts: Arc::new(AtomicU64::new(now)),
            tracker: AgentTracker::default(),
            claim: None,
            exit_alerted: false,
            agent_stream: None,
            respond_lock: Arc::new(tokio::sync::Mutex::new(())),
            claude_state: crate::agent::claude::ClaudeSessionState::default(),
            pending_permissions: HashMap::new(),
            last_anchor_check_ms: 0,
        };
        let sum = summary(session_id, &entry);
        sessions.insert(session_id.to_string(), entry);
        drop(sessions);
        self.watch_session_eof(&session);
        self.broadcaster
            .broadcast(cawide_protocol::HostEvent::SessionsChanged);
        Ok(sum)
    }

    pub fn kill_session(&self, session_id: &str) -> Result<(), String> {
        let entry = {
            let mut sessions = self.sessions.write();
            sessions.remove(session_id)
        };
        let Some(entry) = entry else {
            return Err(format!("session not found: {session_id}"));
        };
        self.emit_removed_exit_activity(session_id, &entry, false, now_secs());
        if let Err(e) = entry.session.kill() {
            tracing::debug!(session = %session_id, error = %e, "kill failed (process may have exited)");
        }
        self.broadcaster
            .broadcast(cawide_protocol::HostEvent::SessionsChanged);
        Ok(())
    }

    pub fn claim_attach(&self, session_id: &str, owner: [u8; 32]) -> Result<ClaimResult, PtyError> {
        let mut sessions = self.sessions.write();
        let entry = sessions
            .get_mut(session_id)
            .ok_or_else(|| PtyError::Process("session not found".into()))?;

        if let Some(existing) = &mut entry.claim {
            if existing.owner == owner {
                // Same device takeover: kick old stream
                if let Some(kick) = existing.kick_tx.take() {
                    let _ = kick.send(());
                }
                let token = self.next_claim_token.fetch_add(1, Ordering::Relaxed);
                let (kick_tx, kick_rx) = tokio::sync::oneshot::channel();
                *existing = AttachClaim {
                    owner,
                    token,
                    kick_tx: Some(kick_tx),
                };
                drop(sessions);
                self.broadcaster
                    .broadcast(cawide_protocol::HostEvent::SessionsChanged);
                return Ok(ClaimResult::Success { token, kick_rx });
            } else {
                return Ok(ClaimResult::Occupied);
            }
        }

        let token = self.next_claim_token.fetch_add(1, Ordering::Relaxed);
        let (kick_tx, kick_rx) = tokio::sync::oneshot::channel();
        entry.claim = Some(AttachClaim {
            owner,
            token,
            kick_tx: Some(kick_tx),
        });
        drop(sessions);
        self.broadcaster
            .broadcast(cawide_protocol::HostEvent::SessionsChanged);
        Ok(ClaimResult::Success { token, kick_rx })
    }

    pub fn release_claim(&self, session_id: &str, token: u64) {
        let released = {
            let mut sessions = self.sessions.write();
            if let Some(entry) = sessions.get_mut(session_id) {
                if entry.claim.as_ref().is_some_and(|c| c.token == token) {
                    entry.claim = None;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if released {
            self.broadcaster
                .broadcast(cawide_protocol::HostEvent::SessionsChanged);
        }
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<PtySession>> {
        self.sessions
            .read()
            .get(session_id)
            .map(|e| Arc::clone(&e.session))
    }

    pub fn respond_lock(&self, session_id: &str) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.sessions
            .read()
            .get(session_id)
            .map(|e| Arc::clone(&e.respond_lock))
    }

    pub fn respond_snapshot(&self, session_id: &str) -> Option<RespondSnapshot> {
        let sessions = self.sessions.read();
        let entry = sessions.get(session_id)?;
        if !entry.session.is_alive() {
            return None;
        }
        let claude_pending = entry
            .tracker
            .head_attention()
            .and_then(|h| h.key.as_deref())
            .and_then(|k| {
                entry
                    .pending_permissions
                    .get(k)
                    .map(|p| (k.to_string(), p.kind))
            });
        Some(RespondSnapshot {
            session: Arc::clone(&entry.session),
            agent_state: entry.tracker.current(),
            head_attention: entry.tracker.head_attention().cloned(),
            claude_pending,
        })
    }

    pub fn register_agent_stream(
        &self,
        session_id: &str,
        tx: tokio::sync::mpsc::Sender<crate::net::ipc::IpcStreamOut>,
    ) -> Option<u64> {
        let mut sessions = self.sessions.write();
        let entry = sessions.get_mut(session_id)?;
        if !entry.session.is_alive() {
            return None;
        }
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        entry.agent_stream = Some((stream_id, tx));
        Some(stream_id)
    }

    pub fn unregister_agent_stream(&self, session_id: &str, stream_id: u64) {
        let mut sessions = self.sessions.write();
        if let Some(entry) = sessions.get_mut(session_id) {
            if entry
                .agent_stream
                .as_ref()
                .is_some_and(|(id, _)| *id == stream_id)
            {
                entry.agent_stream = None;
            }
        }
    }

    pub fn send_plan_review_resolution(
        &self,
        session_id: &str,
        review_id: &str,
        choice: &str,
    ) -> Result<(), String> {
        let tx = {
            let sessions = self.sessions.read();
            let Some(entry) = sessions.get(session_id) else {
                return Err("session not found".into());
            };
            entry
                .agent_stream
                .as_ref()
                .map(|(_, tx)| tx.clone())
                .ok_or_else(|| "agent stream unavailable".to_string())?
        };
        match tx.try_send(crate::net::ipc::IpcStreamOut::ResolvePlanReview {
            review_id: review_id.to_string(),
            choice: choice.to_string(),
        }) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                let mut sessions = self.sessions.write();
                if let Some(entry) = sessions.get_mut(session_id) {
                    if entry
                        .agent_stream
                        .as_ref()
                        .is_some_and(|(_, cur)| cur.same_channel(&tx))
                    {
                        entry.agent_stream = None;
                    }
                }
                Err("agent stream unavailable".to_string())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                Err("agent stream unavailable".to_string())
            }
        }
    }

    pub fn apply_hook(&self, session_id: &str, agent: &str, status: AgentStatus) -> HookOutcome {
        self.apply_hook_signal(session_id, agent, AgentSignal::from_status(status))
    }

    pub fn apply_hook_signal(
        &self,
        session_id: &str,
        agent: &str,
        signal: AgentSignal,
    ) -> HookOutcome {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return HookOutcome::UnknownSession;
        };
        let osc_seq = entry.session.osc_seq();
        let ts = now_secs();
        let res = entry
            .tracker
            .on_hook_signal(agent, signal, ts, now_millis(), osc_seq);
        if let Some(alert) = res.alert {
            self.emit_alert(session_id, entry, alert);
        }
        if let Some(activity) = res.activity {
            self.emit_activity(session_id, entry, activity, ts);
        }
        sweep_pending(entry);
        if res.changed {
            entry.revision = self.bump();
            HookOutcome::Updated(Box::new(summary(session_id, entry)))
        } else {
            HookOutcome::Ignored
        }
    }

    pub fn probe(&self, scratch: &mut ProcScratch) -> ProbeOutcome {
        let session_arcs: Vec<(String, Arc<PtySession>)> = {
            let sessions = self.sessions.read();
            sessions
                .iter()
                .map(|(id, e)| (id.clone(), Arc::clone(&e.session)))
                .collect()
        };

        struct Obs {
            id: String,
            session: Arc<PtySession>,
            fg: Option<Foreground>,
            cwd: Option<PathBuf>,
            git_root: Option<PathBuf>,
            signals: TerminalSignals,
        }

        let mut observations = Vec::new();
        let mut detected_urls = Vec::new();
        for (id, session) in session_arcs {
            for url in session.take_detected_urls() {
                detected_urls.push((id.clone(), url));
            }
            if !session.is_alive() {
                continue;
            }
            let pgid = session.foreground_pgid();
            let info = pgid.and_then(|p| proc_info(p, scratch));
            let fg = info.as_ref().map(classify);
            let cwd = if matches!(fg, Some(Foreground::Shell | Foreground::Agent(_))) {
                pgid.and_then(proc_cwd)
            } else {
                session.root_pid().and_then(proc_cwd)
            }
            .and_then(|p| p.canonicalize().ok());
            let git_root = cwd.as_deref().and_then(find_git_root);
            let signals = session.terminal_signals();
            observations.push(Obs {
                id,
                session,
                fg,
                cwd,
                git_root,
                signals,
            });
        }

        let mut sessions = self.sessions.write();
        let mut changed = Vec::new();
        for obs in observations {
            if let Some(entry) = sessions.get_mut(&obs.id) {
                if Arc::ptr_eq(&entry.session, &obs.session) {
                    let old_cwd = entry.cwd.clone();
                    let old_git_root = entry.git_root.clone();
                    let old_title = entry.title.clone();
                    let old_agent = entry.tracker.current();

                    if let Some(c) = obs.cwd {
                        entry.cwd = c;
                        entry.git_root = obs.git_root;
                    }
                    entry.title = obs.signals.title.clone();
                    let ts = now_secs();
                    let res =
                        entry
                            .tracker
                            .on_probe_signals(obs.fg, &obs.signals, ts, now_millis());
                    if obs.fg == Some(Foreground::Shell) && entry.tracker.current().is_none() {
                        obs.session.clear_progress();
                    }
                    if let Some(alert) = res.alert {
                        self.emit_alert(&obs.id, entry, alert);
                    }
                    if let Some(activity) = res.activity {
                        self.emit_activity(&obs.id, entry, activity, ts);
                    }
                    if entry.cwd != old_cwd
                        || entry.git_root != old_git_root
                        || entry.title != old_title
                        || res.changed
                        || entry.tracker.current() != old_agent
                    {
                        entry.revision = self.bump();
                        changed.push(summary(&obs.id, entry));
                    }
                    sweep_pending(entry);
                }
            }
        }
        let ts = now_secs();
        for (id, entry) in sessions.iter_mut() {
            if !entry.session.is_alive() {
                self.handle_dead_session_exit(id, entry, true, ts);
            }
        }

        let mut roots = BTreeSet::new();
        roots.insert(self.workdir.clone());
        for entry in sessions.values() {
            roots.insert(entry.cwd.clone());
            if let Some(ref g) = entry.git_root {
                roots.insert(g.clone());
            }
        }
        ProbeOutcome {
            changed,
            roots,
            detected_urls,
        }
    }

    pub fn touch(&self, session_id: &str) {
        if let Some(entry) = self.sessions.read().get(session_id) {
            entry.last_active_ts.store(now_secs(), Ordering::Relaxed);
        }
    }

    pub fn mark_input(&self) {
        self.last_input_unix.store(now_secs(), Ordering::Relaxed);
    }

    pub fn last_input_unix(&self) -> u64 {
        self.last_input_unix.load(Ordering::Relaxed)
    }

    pub fn remove(&self, session_id: &str) -> Option<Arc<PtySession>> {
        let entry = self.sessions.write().remove(session_id)?;
        self.emit_removed_exit_activity(session_id, &entry, true, now_secs());
        Some(entry.session)
    }

    /// Removes `session_id` only if it still maps to exactly `session`.
    pub fn remove_if_same(&self, session_id: &str, session: &Arc<PtySession>) {
        let removed = {
            let mut sessions = self.sessions.write();
            if sessions
                .get(session_id)
                .is_some_and(|e| Arc::ptr_eq(&e.session, session))
            {
                sessions.remove(session_id)
            } else {
                None
            }
        };
        if let Some(entry) = removed {
            self.emit_removed_exit_activity(session_id, &entry, true, now_secs());
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.read().is_empty()
    }

    pub fn broadcaster(&self) -> &Arc<HostEventBroadcaster> {
        &self.broadcaster
    }

    pub fn list(&self) -> Vec<SessionSummary> {
        let mut out: Vec<SessionSummary> = self
            .sessions
            .read()
            .iter()
            .map(|(id, e)| summary(id, e))
            .collect();
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        out
    }

    pub fn root_pids(&self) -> HashMap<u32, String> {
        let mut roots = HashMap::new();
        let sessions = self.sessions.read();
        for (id, entry) in sessions.iter() {
            if entry.session.is_alive() {
                if let Some(pid) = entry.session.root_pid() {
                    if pid > 0 {
                        roots.insert(pid as u32, id.clone());
                    }
                }
            }
        }
        roots
    }

    /// Kills every session and clears the registry.
    pub fn kill_all(&self) {
        let drained: Vec<(String, SessionEntry)> = self.sessions.write().drain().collect();
        let ts = now_secs();
        for (id, entry) in drained {
            self.emit_removed_exit_activity(&id, &entry, false, ts);
            if let Err(e) = entry.session.kill() {
                tracing::debug!(session = %id, error = %e, "failed to kill session");
            }
        }
    }
    pub fn apply_claude_event(
        &self,
        session_id: &str,
        ev: crate::net::ipc::ClaudeHookEvent,
    ) -> HookOutcome {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return HookOutcome::UnknownSession;
        };
        let effects = entry.claude_state.apply(ev, None);
        let mut changed = false;
        let ts = now_secs();
        let now_ms = now_millis();
        let osc_seq = entry.session.osc_seq();

        let signal_resolves = effects
            .signal
            .as_ref()
            .is_some_and(|s| !matches!(s.resolution, SignalResolution::None));
        if !effects.dismiss.is_empty() && !signal_resolves {
            let res = entry.tracker.resolve_keys(&effects.dismiss, ts, now_ms);
            if let Some(alert) = res.alert {
                self.emit_alert(session_id, entry, alert);
            }
            if let Some(activity) = res.activity {
                self.emit_activity(session_id, entry, activity, ts);
            }
            if res.changed {
                changed = true;
            }
        }

        if let Some(signal) = effects.signal {
            let res = entry
                .tracker
                .on_hook_signal("claude", signal, ts, now_ms, osc_seq);
            if let Some(alert) = res.alert {
                self.emit_alert(session_id, entry, alert);
            }
            if let Some(activity) = res.activity {
                self.emit_activity(session_id, entry, activity, ts);
            }
            if res.changed {
                changed = true;
            }
        }

        sweep_pending(entry);

        if changed {
            entry.revision = self.bump();
            HookOutcome::Updated(Box::new(summary(session_id, entry)))
        } else {
            HookOutcome::Ignored
        }
    }

    pub fn register_claude_permission(
        &self,
        session_id: &str,
        ev: crate::net::ipc::ClaudeHookEvent,
        att: crate::agent::map::AttentionSpec,
        reply_tx: tokio::sync::oneshot::Sender<crate::net::ipc::ClaudeReply>,
    ) -> Result<ClaudeRegisteredInfo, String> {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return Err("session not found".into());
        };

        let tool_name = ev.tool_name.clone().unwrap_or_default();
        let kind = match att.kind {
            crate::agent::map::AttentionKind::Approval => ClaudePendingKind::Approval,
            crate::agent::map::AttentionKind::Ask { .. } => ClaudePendingKind::Ask,
            crate::agent::map::AttentionKind::Plan { .. } => ClaudePendingKind::Plan,
            crate::agent::map::AttentionKind::TextQuestion => ClaudePendingKind::Approval,
        };
        let anchor = crate::agent::claude::permission_dialog_anchor(&tool_name, &att.prompt);

        let effects = entry.claude_state.apply(ev, Some(att));
        let Some(req_key) = effects.request_key else {
            return Err("permission request refused by claude state".into());
        };
        let tool_use_id = effects.registered_tool_use_id;

        let ts = now_secs();
        let now_ms = now_millis();
        let osc_seq = entry.session.osc_seq();

        let mut changed = false;
        let signal_resolves = effects
            .signal
            .as_ref()
            .is_some_and(|s| !matches!(s.resolution, SignalResolution::None));
        if !effects.dismiss.is_empty() && !signal_resolves {
            let res = entry.tracker.resolve_keys(&effects.dismiss, ts, now_ms);
            if let Some(alert) = res.alert {
                self.emit_alert(session_id, entry, alert);
            }
            if let Some(activity) = res.activity {
                self.emit_activity(session_id, entry, activity, ts);
            }
            if res.changed {
                changed = true;
            }
        }

        if let Some(signal) = effects.signal {
            let res = entry
                .tracker
                .on_hook_signal("claude", signal, ts, now_ms, osc_seq);
            if let Some(alert) = res.alert {
                self.emit_alert(session_id, entry, alert);
            }
            if let Some(activity) = res.activity {
                self.emit_activity(session_id, entry, activity, ts);
            }
            if res.changed {
                changed = true;
            }
        }

        let screen = entry.session.screen_contents();
        let anchor_seen_on_attach = anchor
            .as_ref()
            .is_some_and(|a| crate::agent::claude::anchor_visible_on_screen(&screen, a));

        entry.pending_permissions.insert(
            req_key.clone(),
            PendingPermission {
                reply_tx,
                kind,
                tool_use_id: tool_use_id.clone(),
                tool_name,
                anchor,
                anchor_seen_on_attach,
            },
        );

        sweep_pending(entry);
        let retained = entry.pending_permissions.contains_key(&req_key);
        if !retained {
            entry.claude_state.open_perms.retain(|p| p.key != req_key);
        }

        if changed {
            entry.revision = self.bump();
            let sum = summary(session_id, entry);
            drop(sessions);
            self.broadcaster
                .broadcast(cawide_protocol::HostEvent::SessionUpdated { summary: sum });
        }

        if !retained {
            return Err("permission request was not accepted into attention queue".into());
        }

        Ok(ClaudeRegisteredInfo {
            request_key: req_key,
            tool_use_id,
        })
    }

    pub fn resolve_claude_hook_frame(
        &self,
        session_id: &str,
        key: &str,
        frame: Option<crate::net::ipc::ClaudeHookFrame>,
    ) {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return;
        };
        let ts = now_secs();
        let now_ms = now_millis();
        let osc_seq = entry.session.osc_seq();

        let mut changed = false;
        match frame {
            Some(crate::net::ipc::ClaudeHookFrame::Interrupted) => {
                if entry.pending_permissions.remove(key).is_some() {
                    entry.claude_state.open_perms.clear();
                    entry.claude_state.open_notifs.clear();
                    entry.claude_state.currently_thinking_base = None;
                    let signal = AgentSignal {
                        status: AgentStatus::Idle,
                        attention: None,
                        outcome: TurnOutcome::Aborted,
                        resolution: SignalResolution::ClearAll,
                        seq: None,
                        epoch: None,
                    };
                    let res = entry
                        .tracker
                        .on_hook_signal("claude", signal, ts, now_ms, osc_seq);
                    if let Some(alert) = res.alert {
                        self.emit_alert(session_id, entry, alert);
                    }
                    if let Some(activity) = res.activity {
                        self.emit_activity(session_id, entry, activity, ts);
                    }
                    sweep_pending(entry);
                    changed = true;
                }
            }
            Some(crate::net::ipc::ClaudeHookFrame::AnsweredElsewhere) | None => {
                if entry.pending_permissions.remove(key).is_some() {
                    entry.claude_state.open_perms.retain(|p| p.key != key);
                    let res = entry.tracker.resolve_keys(&[key.to_string()], ts, now_ms);
                    if let Some(alert) = res.alert {
                        self.emit_alert(session_id, entry, alert);
                    }
                    if let Some(activity) = res.activity {
                        self.emit_activity(session_id, entry, activity, ts);
                    }
                    sweep_pending(entry);
                    changed = true;
                }
            }
        }

        if changed {
            entry.revision = self.bump();
            let sum = summary(session_id, entry);
            drop(sessions);
            self.broadcaster
                .broadcast(cawide_protocol::HostEvent::SessionUpdated { summary: sum });
        }
    }

    pub fn send_claude_reply(
        &self,
        session_id: &str,
        key: &str,
        expected_id: u64,
        reply: crate::net::ipc::ClaudeReply,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return Err("session not found".into());
        };

        if expected_id != 0
            && !entry
                .tracker
                .head_attention()
                .is_some_and(|h| h.id == expected_id)
        {
            return Err("prompt no longer open".into());
        }

        let Some(pending) = entry.pending_permissions.get(key) else {
            return Err("prompt no longer open".into());
        };
        if pending.reply_tx.is_closed() {
            return Err("permission hook disconnected".into());
        }

        let pending = entry
            .pending_permissions
            .remove(key)
            .expect("checked above");

        entry.claude_state.open_perms.retain(|p| p.key != key);
        let ts = now_secs();
        let now_ms = now_millis();
        let res = entry.tracker.resolve_keys(&[key.to_string()], ts, now_ms);
        if let Some(alert) = res.alert {
            self.emit_alert(session_id, entry, alert);
        }
        if let Some(activity) = res.activity {
            self.emit_activity(session_id, entry, activity, ts);
        }
        sweep_pending(entry);
        entry.revision = self.bump();
        let sum = summary(session_id, entry);
        drop(sessions);
        self.broadcaster
            .broadcast(cawide_protocol::HostEvent::SessionUpdated { summary: sum });

        pending
            .reply_tx
            .send(reply)
            .map_err(|_| "permission hook disconnected".to_string())
    }

    pub fn maybe_schedule_claude_anchor_check(self: &Arc<Self>, session_id: &str, input: &[u8]) {
        let is_trigger =
            input.contains(&b'\r') || input.iter().any(|b| b.is_ascii_digit()) || input == b"\x1b";
        if !is_trigger {
            return;
        }

        {
            let sessions = self.sessions.read();
            let Some(entry) = sessions.get(session_id) else {
                return;
            };
            if entry.pending_permissions.is_empty() {
                return;
            }
        }

        let should_spawn = {
            let mut sessions = self.sessions.write();
            let Some(entry) = sessions.get_mut(session_id) else {
                return;
            };
            if entry.pending_permissions.is_empty() {
                return;
            }
            let has_watched_pending = entry
                .pending_permissions
                .values()
                .any(|p| p.anchor.is_some() && p.anchor_seen_on_attach);
            if !has_watched_pending {
                let screen = entry.session.screen_contents();
                for pending in entry.pending_permissions.values_mut() {
                    if let Some(ref a) = pending.anchor {
                        if !pending.anchor_seen_on_attach
                            && crate::agent::claude::anchor_visible_on_screen(&screen, a)
                        {
                            pending.anchor_seen_on_attach = true;
                        }
                    }
                }
                let has_now = entry
                    .pending_permissions
                    .values()
                    .any(|p| p.anchor.is_some() && p.anchor_seen_on_attach);
                if !has_now {
                    return;
                }
            }
            let now = now_millis();
            if now.saturating_sub(entry.last_anchor_check_ms) < 300 {
                return;
            }
            entry.last_anchor_check_ms = now;
            true
        };

        if should_spawn {
            let reg = Arc::clone(self);
            let s_id = session_id.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                reg.perform_claude_anchor_check(&s_id);
            });
        }
    }

    fn perform_claude_anchor_check(&self, session_id: &str) {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return;
        };
        let screen = entry.session.screen_contents();
        let mut dismissed_keys = Vec::new();
        for (key, pending) in &mut entry.pending_permissions {
            if let Some(ref a) = pending.anchor {
                if pending.anchor_seen_on_attach {
                    if !crate::agent::claude::anchor_visible_on_screen(&screen, a) {
                        dismissed_keys.push(key.clone());
                    }
                } else if crate::agent::claude::anchor_visible_on_screen(&screen, a) {
                    pending.anchor_seen_on_attach = true;
                }
            }
        }

        if dismissed_keys.is_empty() {
            return;
        }

        for k in &dismissed_keys {
            entry.pending_permissions.remove(k);
            entry.claude_state.open_perms.retain(|p| &p.key != k);
        }

        let ts = now_secs();
        let now_ms = now_millis();
        let res = entry.tracker.resolve_keys(&dismissed_keys, ts, now_ms);
        if let Some(alert) = res.alert {
            self.emit_alert(session_id, entry, alert);
        }
        if let Some(activity) = res.activity {
            self.emit_activity(session_id, entry, activity, ts);
        }
        sweep_pending(entry);
        entry.revision = self.bump();
        let sum = summary(session_id, entry);
        drop(sessions);
        self.broadcaster
            .broadcast(cawide_protocol::HostEvent::SessionUpdated { summary: sum });
    }
}

impl std::fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRegistry")
            .field("sessions", &self.sessions.read().len())
            .field("workdir", &self.workdir)
            .field("launch_cmd", &self.launch_cmd)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_revision_ordering() {
        let broadcaster = Arc::new(HostEventBroadcaster::new(16));
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().canonicalize().expect("canonical");
        let reg1 = SessionRegistry::new(canonical.clone(), None, Vec::new(), broadcaster.clone());
        std::thread::sleep(std::time::Duration::from_millis(2));
        let reg2 = SessionRegistry::new(canonical, None, Vec::new(), broadcaster);
        assert!(reg2.bump() > reg1.bump());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_registry_emits_activity_events_and_project_title() {
        use crate::agent::map::{AttentionKind, AttentionSpec, SignalResolution, TurnOutcome};
        use crate::push::{ActivityEventKind, ActivityPhase};

        let broadcaster = Arc::new(HostEventBroadcaster::new(16));
        let dir = tempfile::tempdir().expect("tempdir");
        let proj_dir = dir.path().join("my-project");
        std::fs::create_dir_all(&proj_dir).unwrap();
        let canonical = proj_dir.canonicalize().unwrap();
        let (act_tx, mut act_rx) = tokio::sync::mpsc::channel(32);
        let reg = SessionRegistry::new(canonical, None, Vec::new(), broadcaster)
            .with_activity_sender(act_tx);

        reg.create_session("s1", Some("sleep 30".into()), None, 80, 24)
            .unwrap();
        {
            let mut sessions = reg.sessions.write();
            sessions.get_mut("s1").unwrap().title = Some("Fix bug".into());
        }

        // 1. Thinking start
        reg.apply_hook_signal(
            "s1",
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: String::new(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
        );
        let ev1 = act_rx.try_recv().unwrap();
        assert_eq!(ev1.phase, ActivityPhase::Working);
        assert_eq!(ev1.event, ActivityEventKind::Update);
        assert!(!ev1.is_tool_step);
        assert_eq!(ev1.detail.project.as_deref(), Some("my-project"));
        assert_eq!(ev1.detail.session_title.as_deref(), Some("Fix bug"));

        // 2. Tool step while Thinking
        reg.apply_hook_signal(
            "s1",
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "Read main.rs".into(),
                },
                attention: None,
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: Some(2),
                epoch: Some(1),
            },
        );
        let ev2 = act_rx.try_recv().unwrap();
        assert_eq!(ev2.phase, ActivityPhase::Working);
        assert!(ev2.is_tool_step);
        assert_eq!(ev2.detail.prompt.as_deref(), Some("Read main.rs"));

        // 3. Waiting
        reg.apply_hook_signal(
            "s1",
            "omp",
            AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: "Allow?".into(),
                    options: vec!["Allow".into(), "Deny".into()],
                },
                attention: Some(AttentionSpec {
                    key: Some("k1".into()),
                    kind: AttentionKind::Approval,
                    prompt: "Allow?".into(),
                    options: vec!["Allow".into(), "Deny".into()],
                    actionable: true,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: Some(3),
                epoch: Some(1),
            },
        );
        let ev3 = act_rx.try_recv().unwrap();
        assert_eq!(ev3.phase, ActivityPhase::Waiting);
        assert_eq!(ev3.event, ActivityEventKind::Update);
        assert!(!ev3.is_tool_step);
        assert!(ev3.prompt_id.is_some());

        // 4. Kill session while Waiting -> End
        reg.kill_session("s1").unwrap();
        let ev4 = act_rx.try_recv().unwrap();
        assert_eq!(ev4.phase, ActivityPhase::Done);
        assert_eq!(ev4.event, ActivityEventKind::End);
        assert_eq!(ev4.detail.project.as_deref(), Some("my-project"));
        assert_eq!(ev4.detail.session_title.as_deref(), Some("Fix bug"));

        // 5. EOF exit with non-zero exit code in probe -> Failed End
        reg.create_session("s2", Some("sh -c 'exit 2'".into()), None, 80, 24)
            .unwrap();
        reg.apply_hook_signal(
            "s2",
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: String::new(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
        );
        let _ = act_rx.try_recv().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while reg.get("s2").unwrap().is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut scratch = ProcScratch::default();
        reg.probe(&mut scratch);
        let ev5 = act_rx.try_recv().unwrap();
        assert_eq!(ev5.session_id, "s2");
        assert_eq!(ev5.phase, ActivityPhase::Failed);
        assert_eq!(ev5.event, ActivityEventKind::End);
        assert!(!ev5.dismiss_immediately);
        assert!(ev5
            .detail
            .error
            .as_deref()
            .is_some_and(|e| e.contains("code 2")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_kill_session_and_clean_eof_after_completed_dismiss_immediately() {
        use crate::agent::map::{SignalResolution, TurnOutcome};
        use crate::push::{ActivityEventKind, ActivityPhase};

        let broadcaster = Arc::new(HostEventBroadcaster::new(16));
        let dir = tempfile::tempdir().expect("tempdir");
        let proj_dir = dir.path().join("tab-proj");
        std::fs::create_dir_all(&proj_dir).unwrap();
        let canonical = proj_dir.canonicalize().unwrap();
        let (act_tx, mut act_rx) = tokio::sync::mpsc::channel(32);
        let (alert_tx, mut alert_rx) = tokio::sync::mpsc::channel(32);
        let reg = SessionRegistry::new(canonical, None, Vec::new(), broadcaster)
            .with_activity_sender(act_tx)
            .with_alert_sender(alert_tx);

        // 1. kill_session after Completed emits End with dismiss_immediately: true
        reg.create_session("s-kill", Some("sleep 30".into()), None, 80, 24)
            .unwrap();
        reg.apply_hook_signal(
            "s-kill",
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: String::new(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
        );
        let ev_start = act_rx.try_recv().unwrap();
        // No title set -> falls back to cwd dir name
        assert_eq!(ev_start.detail.session_title.as_deref(), Some("tab-proj"));

        reg.apply_hook_signal(
            "s-kill",
            "omp",
            AgentSignal {
                status: AgentStatus::Completed {
                    summary: "done".into(),
                },
                attention: None,
                outcome: TurnOutcome::Done,
                resolution: SignalResolution::ClearNonPlan,
                seq: Some(2),
                epoch: Some(1),
            },
        );
        let ev_done = act_rx.try_recv().unwrap();
        assert_eq!(ev_done.event, ActivityEventKind::End);
        assert!(!ev_done.dismiss_immediately);
        let alert_done = alert_rx.try_recv().unwrap();
        assert_eq!(alert_done.detail.session_title.as_deref(), Some("tab-proj"));

        reg.kill_session("s-kill").unwrap();
        let ev_kill = act_rx.try_recv().unwrap();
        assert_eq!(ev_kill.session_id, "s-kill");
        assert_eq!(ev_kill.phase, ActivityPhase::Done);
        assert_eq!(ev_kill.event, ActivityEventKind::End);
        assert!(ev_kill.dismiss_immediately);

        // 2. Clean EOF exit (exit 0) in probe after Completed emits End with dismiss_immediately: true
        reg.create_session("s-eof", Some("sh -c 'exit 0'".into()), None, 80, 24)
            .unwrap();
        reg.apply_hook_signal(
            "s-eof",
            "omp",
            AgentSignal {
                status: AgentStatus::Completed {
                    summary: "done".into(),
                },
                attention: None,
                outcome: TurnOutcome::Done,
                resolution: SignalResolution::ClearNonPlan,
                seq: Some(1),
                epoch: Some(1),
            },
        );
        let _ = act_rx.try_recv().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while reg.get("s-eof").unwrap().is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut scratch = ProcScratch::default();
        reg.probe(&mut scratch);
        let ev_eof = act_rx.try_recv().unwrap();
        assert_eq!(ev_eof.session_id, "s-eof");
        assert_eq!(ev_eof.phase, ActivityPhase::Done);
        assert_eq!(ev_eof.event, ActivityEventKind::End);
        assert!(ev_eof.dismiss_immediately);

        // 3. kill_session while Idle emits no exit activity
        reg.create_session("s-idle", Some("sleep 30".into()), None, 80, 24)
            .unwrap();
        reg.apply_hook_signal("s-idle", "omp", AgentSignal::from_status(AgentStatus::Idle));
        assert!(act_rx.try_recv().is_err());
        reg.kill_session("s-idle").unwrap();
        assert!(act_rx.try_recv().is_err());

        // 4. remove after non-zero exit while Thinking emits Failed End with dismiss_immediately: false
        reg.create_session("s-rem-fail", Some("sh -c 'exit 3'".into()), None, 80, 24)
            .unwrap();
        reg.apply_hook_signal(
            "s-rem-fail",
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: String::new(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
        );
        let _ = act_rx.try_recv().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while reg.get("s-rem-fail").unwrap().is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(reg.remove("s-rem-fail").is_some());
        let ev_rem_fail = act_rx.try_recv().unwrap();
        assert_eq!(ev_rem_fail.session_id, "s-rem-fail");
        assert_eq!(ev_rem_fail.phase, ActivityPhase::Failed);
        assert_eq!(ev_rem_fail.event, ActivityEventKind::End);
        assert!(!ev_rem_fail.dismiss_immediately);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_tab_title_fallback_order() {
        let session = PtySession::spawn(
            80,
            24,
            PtySpawnOptions {
                workdir: None,
                launch_cmd: Some("true".into()),
                env: Vec::new(),
            },
        )
        .unwrap();
        let mut entry = SessionEntry {
            session,
            cwd: PathBuf::from("/tmp/my-repo"),
            git_root: None,
            title: Some("  Custom Tab  ".into()),
            revision: 1,
            active_cmd: None,
            last_active_ts: Arc::new(AtomicU64::new(0)),
            tracker: AgentTracker::default(),
            claim: None,
            exit_alerted: false,
            agent_stream: None,
            respond_lock: Arc::new(tokio::sync::Mutex::new(())),
            claude_state: crate::agent::claude::ClaudeSessionState::default(),
            pending_permissions: HashMap::new(),
            last_anchor_check_ms: 0,
        };
        assert_eq!(tab_title("sess-1", &entry).as_deref(), Some("Custom Tab"));

        entry.title = Some("   ".into());
        assert_eq!(tab_title("sess-1", &entry).as_deref(), Some("my-repo"));

        entry.title = None;
        assert_eq!(tab_title("sess-1", &entry).as_deref(), Some("my-repo"));

        entry.cwd = PathBuf::from("/");
        assert_eq!(tab_title("sess-1", &entry).as_deref(), Some("sess-1"));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn test_claude_permission_guards_and_stale_interrupted() {
        use crate::agent::map::{AttentionKind, AttentionSpec};
        use crate::net::ipc::{ClaudeEventKind, ClaudeHookEvent, ClaudeHookFrame, ClaudeReply};

        let tmp = tempfile::tempdir().unwrap();
        let broadcaster = Arc::new(HostEventBroadcaster::new(16));
        let reg = SessionRegistry::new(
            tmp.path().to_path_buf(),
            Some("cat".into()),
            Vec::new(),
            Arc::clone(&broadcaster),
        );
        reg.create_session("s-claude-guards", None, None, 80, 24)
            .unwrap();

        // Start a turn so tracker is Thinking
        reg.apply_claude_event(
            "s-claude-guards",
            ClaudeHookEvent {
                session_id: "s-claude-guards".into(),
                claude_session_id: "cc-1".into(),
                kind: ClaudeEventKind::UserPromptSubmit,
                source: None,
                tool_name: None,
                tool_use_id: None,
                input_hash: None,
                agent_id: None,
                notification_type: None,
                text: Some("run ls".into()),
                background_count: 0,
            },
        );

        // 1. Register permission, then drop reply_rx -> send_claude_reply fails BEFORE mutating state
        let (tx1, rx1) = tokio::sync::oneshot::channel();
        let info1 = reg
            .register_claude_permission(
                "s-claude-guards",
                ClaudeHookEvent {
                    session_id: "s-claude-guards".into(),
                    claude_session_id: "cc-1".into(),
                    kind: ClaudeEventKind::PermissionRequest,
                    source: None,
                    tool_name: Some("Bash".into()),
                    tool_use_id: Some("t1".into()),
                    input_hash: Some(1),
                    agent_id: None,
                    notification_type: None,
                    text: None,
                    background_count: 0,
                },
                AttentionSpec {
                    key: None,
                    kind: AttentionKind::Approval,
                    prompt: "Allow Bash: ls?".into(),
                    options: vec!["Allow".into(), "Deny".into()],
                    actionable: true,
                },
                tx1,
            )
            .unwrap();

        let snap_before = reg.respond_snapshot("s-claude-guards").unwrap();
        let head_id = snap_before.head_attention.as_ref().unwrap().id;

        // Mismatched expected_id rejected
        assert_eq!(
            reg.send_claude_reply(
                "s-claude-guards",
                &info1.request_key,
                head_id + 999,
                ClaudeReply::Allow,
            ),
            Err("prompt no longer open".into())
        );
        assert!(reg
            .respond_snapshot("s-claude-guards")
            .unwrap()
            .claude_pending
            .is_some());

        // Closed reply_tx rejected without mutating tracker/pending
        drop(rx1);
        assert_eq!(
            reg.send_claude_reply(
                "s-claude-guards",
                &info1.request_key,
                head_id,
                ClaudeReply::Allow,
            ),
            Err("permission hook disconnected".into())
        );
        assert!(reg
            .respond_snapshot("s-claude-guards")
            .unwrap()
            .claude_pending
            .is_some());

        // Clean up perm-1 via AnsweredElsewhere
        reg.resolve_claude_hook_frame(
            "s-claude-guards",
            &info1.request_key,
            Some(ClaudeHookFrame::AnsweredElsewhere),
        );
        assert!(matches!(
            reg.respond_snapshot("s-claude-guards")
                .unwrap()
                .agent_state
                .unwrap()
                .status,
            AgentStatus::Thinking { .. }
        ));

        // 2. Stale Interrupted frame for already-resolved key must NOT wipe active Thinking state
        reg.resolve_claude_hook_frame(
            "s-claude-guards",
            &info1.request_key,
            Some(ClaudeHookFrame::Interrupted),
        );
        assert!(matches!(
            reg.respond_snapshot("s-claude-guards")
                .unwrap()
                .agent_state
                .unwrap()
                .status,
            AgentStatus::Thinking { .. }
        ));
    }
}
