//! Registry of long-lived PTY sessions keyed by client-chosen session id.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::agent::detect::{classify, Foreground};
use crate::agent::tracker::AgentTracker;
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
}

pub struct SessionRegistry {
    sessions: parking_lot::RwLock<HashMap<String, SessionEntry>>,
    workdir: PathBuf,
    launch_cmd: Option<String>,
    base_env: Vec<(String, String)>,
    broadcaster: Arc<HostEventBroadcaster>,
    next_claim_token: AtomicU64,
    next_revision: AtomicU64,
    last_input_unix: AtomicU64,
    config_dir: Option<PathBuf>,
    alerts: Option<tokio::sync::mpsc::Sender<crate::push::AgentAlert>>,
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
            last_input_unix: AtomicU64::new(0),
            config_dir: crate::net::config_dir().ok(),
            alerts: None,
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

    fn emit_alert(&self, session_id: &str, agent: &str, kind: crate::push::AgentAlertKind) {
        if let Some(tx) = &self.alerts {
            let _ = tx.try_send(crate::push::AgentAlert {
                session_id: session_id.to_string(),
                agent: agent.to_string(),
                kind,
            });
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
        if let Some(entry) = sessions.get(session_id) {
            if entry.session.is_alive() {
                return Ok(Arc::clone(&entry.session));
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

    pub fn apply_hook(&self, session_id: &str, agent: &str, status: AgentStatus) -> HookOutcome {
        let mut sessions = self.sessions.write();
        let Some(entry) = sessions.get_mut(session_id) else {
            return HookOutcome::UnknownSession;
        };
        let old = entry.tracker.current();
        if entry.tracker.on_hook(agent, status, now_secs()) {
            entry.revision = self.bump();
            if let Some(new) = entry.tracker.current() {
                if let Some(kind) = crate::push::alert_for_transition(old.as_ref(), Some(&new)) {
                    self.emit_alert(session_id, &new.agent, kind);
                }
            }
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
            if fg == Some(Foreground::Shell) {
                session.clear_progress();
            }
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
                    entry.title = obs.signals.title;
                    entry
                        .tracker
                        .on_probe(obs.fg, obs.signals.progress_active, now_secs());

                    let new = entry.tracker.current();
                    if let Some(kind) =
                        crate::push::alert_for_transition(old_agent.as_ref(), new.as_ref())
                    {
                        let agent = new
                            .as_ref()
                            .or(old_agent.as_ref())
                            .map(|s| s.agent.clone())
                            .unwrap_or_default();
                        self.emit_alert(&obs.id, &agent, kind);
                    }
                    if entry.cwd != old_cwd
                        || entry.git_root != old_git_root
                        || entry.title != old_title
                        || entry.tracker.current() != old_agent
                    {
                        entry.revision = self.bump();
                        changed.push(summary(&obs.id, entry));
                    }
                }
            }
        }
        for (id, entry) in sessions.iter_mut() {
            if !entry.session.is_alive() && !entry.exit_alerted {
                entry.exit_alerted = true;
                if let Some(c) = entry.session.exit_code() {
                    if c != 0 {
                        if let Some(state) = entry.tracker.current() {
                            if matches!(
                                state.status,
                                AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
                            ) {
                                self.emit_alert(
                                    id,
                                    &state.agent,
                                    crate::push::AgentAlertKind::Failed,
                                );
                            }
                        }
                    }
                }
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
        self.sessions.write().remove(session_id).map(|e| e.session)
    }

    /// Removes `session_id` only if it still maps to exactly `session`.
    pub fn remove_if_same(&self, session_id: &str, session: &Arc<PtySession>) {
        let mut sessions = self.sessions.write();
        if sessions
            .get(session_id)
            .is_some_and(|e| Arc::ptr_eq(&e.session, session))
        {
            sessions.remove(session_id);
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

    pub fn find_by_workdir(&self, workdir: &Path) -> Option<String> {
        let workdir_canon = workdir
            .canonicalize()
            .ok()
            .unwrap_or_else(|| workdir.to_path_buf());
        let sessions = self.sessions.read();

        // 1. Exact match on entry.cwd (or canonicalized entry.cwd)
        for (id, entry) in sessions.iter() {
            if entry.cwd == workdir || entry.cwd == workdir_canon {
                return Some(id.clone());
            }
            if let Ok(canon) = entry.cwd.canonicalize() {
                if canon == workdir_canon {
                    return Some(id.clone());
                }
            }
        }

        // 2. Match on entry.git_root
        for (id, entry) in sessions.iter() {
            if let Some(git_root) = &entry.git_root {
                if git_root == workdir || git_root == &workdir_canon {
                    return Some(id.clone());
                }
                if let Ok(canon) = git_root.canonicalize() {
                    if canon == workdir_canon {
                        return Some(id.clone());
                    }
                }
            }
        }

        // 3. Prefix match: workdir inside session cwd or session cwd inside workdir
        for (id, entry) in sessions.iter() {
            let entry_canon = entry
                .cwd
                .canonicalize()
                .ok()
                .unwrap_or_else(|| entry.cwd.clone());
            if workdir_canon.starts_with(&entry_canon) || entry_canon.starts_with(&workdir_canon) {
                return Some(id.clone());
            }
        }

        None
    }
    pub fn get_session_context(
        &self,
        session_id: &str,
    ) -> Option<(Arc<PtySession>, PathBuf, Option<String>)> {
        let sessions = self.sessions.read();
        sessions
            .get(session_id)
            .map(|e| (Arc::clone(&e.session), e.cwd.clone(), e.active_cmd.clone()))
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
        for (id, entry) in drained {
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
}
