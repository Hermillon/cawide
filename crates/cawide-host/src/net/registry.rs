//! Registry of long-lived PTY sessions keyed by client-chosen session id.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::agent::detect::{classify, Foreground};
use crate::agent::map::AgentSignal;
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
            alert.detail.session_title = entry.title.clone();
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
            activity.detail.session_title = entry.title.clone();
            if let Err(e) = tx.try_send(crate::push::ActivityUpdateEvent {
                session_id: session_id.to_string(),
                agent: activity.agent,
                phase: activity.phase,
                event: activity.event,
                ts,
                started_at: activity.started_at,
                prompt_id: activity.prompt_id,
                is_tool_step: activity.is_tool_step,
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
        ts: u64,
    ) {
        let Some(state) = entry.tracker.current() else {
            return;
        };
        if !matches!(
            state.status,
            AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
        ) {
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
                detail: crate::push::AlertDetail {
                    error: failed_error,
                    duration_secs,
                    ..Default::default()
                },
            },
            ts,
        );
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
            if !entry.exit_alerted {
                entry.exit_alerted = true;
                let failed_error = entry
                    .session
                    .exit_code()
                    .filter(|&c| c != 0)
                    .map(|c| format!("Process exited with code {c}"));
                self.emit_exit_activity(session_id, entry, failed_error, now_secs());
            }
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
        if !entry.exit_alerted {
            self.emit_exit_activity(session_id, &entry, None, now_secs());
        }
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
        Some(RespondSnapshot {
            session: Arc::clone(&entry.session),
            agent_state: entry.tracker.current(),
            head_attention: entry.tracker.head_attention().cloned(),
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
                }
            }
        }
        let ts = now_secs();
        for (id, entry) in sessions.iter_mut() {
            if !entry.session.is_alive() && !entry.exit_alerted {
                entry.exit_alerted = true;
                let failed_error = entry
                    .session
                    .exit_code()
                    .filter(|&c| c != 0)
                    .map(|c| format!("Process exited with code {c}"));
                if let Some(err) = &failed_error {
                    if let Some(state) = entry.tracker.current() {
                        if matches!(
                            state.status,
                            AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
                        ) {
                            self.emit_alert(
                                id,
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
                self.emit_exit_activity(id, entry, failed_error, ts);
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
        if !entry.exit_alerted {
            let failed_error = entry
                .session
                .exit_code()
                .filter(|&c| c != 0)
                .map(|c| format!("Process exited with code {c}"));
            self.emit_exit_activity(session_id, &entry, failed_error, now_secs());
        }
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
            if !entry.exit_alerted {
                let failed_error = entry
                    .session
                    .exit_code()
                    .filter(|&c| c != 0)
                    .map(|c| format!("Process exited with code {c}"));
                self.emit_exit_activity(session_id, &entry, failed_error, now_secs());
            }
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
            if !entry.exit_alerted {
                self.emit_exit_activity(&id, &entry, None, ts);
            }
            if let Err(e) = entry.session.kill() {
                tracing::debug!(session = %id, error = %e, "failed to kill session");
            }
        }
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
        assert!(ev5
            .detail
            .error
            .as_deref()
            .is_some_and(|e| e.contains("code 2")));
    }
}
