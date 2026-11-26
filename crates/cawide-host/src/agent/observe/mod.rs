pub mod codex;
pub mod codex_rollout;
pub mod opencode;
pub mod opencode_db;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cawide_protocol::types::{AgentChoice, AgentStatus};
use tokio::sync::{mpsc, oneshot, watch};

use crate::agent::map::{
    summarize_head, truncate_chars, AgentSignal, AttentionKind, AttentionSpec, SignalResolution,
    TurnOutcome,
};
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::registry::SessionRegistry;

pub const OBSERVER_KEY_PREFIX: &str = "obs:";
const ADAPTER_IDLE_STOP_TICKS: u32 = 30;
const ADAPTER_CHANNEL_CAP: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub session_id: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedEvent {
    TurnStarted,
    Activity {
        desc: String,
    },
    Attention {
        key: String,
        kind: AttentionKind,
        prompt: String,
        options: Vec<String>,
        actionable: bool,
    },
    AttentionResolved {
        key: String,
    },
    TurnCompleted {
        summary: String,
    },
    TurnFailed {
        error: String,
    },
    TurnInterrupted,
    Detached,
}

pub fn to_signal(ev: ObservedEvent) -> AgentSignal {
    match ev {
        ObservedEvent::TurnStarted => AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: "Working".into(),
            },
            attention: None,
            outcome: TurnOutcome::Started,
            resolution: SignalResolution::ClearNonPlan,
            seq: None,
            epoch: None,
        },
        ObservedEvent::Activity { desc } => AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: truncate_chars(&desc, 280),
            },
            attention: None,
            outcome: TurnOutcome::None,
            resolution: SignalResolution::None,
            seq: None,
            epoch: None,
        },
        ObservedEvent::Attention {
            key,
            kind,
            prompt,
            options,
            actionable,
        } => {
            let prompt = truncate_chars(&prompt, 280);
            AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: prompt.clone(),
                    options: options.clone(),
                },
                attention: Some(AttentionSpec {
                    key: Some(key),
                    kind,
                    prompt,
                    options,
                    actionable,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: None,
                epoch: None,
            }
        }
        ObservedEvent::AttentionResolved { key } => AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: "Working".into(),
            },
            attention: None,
            outcome: TurnOutcome::None,
            resolution: SignalResolution::ByKey(key),
            seq: None,
            epoch: None,
        },
        ObservedEvent::TurnCompleted { summary } => AgentSignal {
            status: AgentStatus::Completed {
                summary: summarize_head(&summary),
            },
            attention: None,
            outcome: TurnOutcome::Done,
            resolution: SignalResolution::ClearNonPlan,
            seq: None,
            epoch: None,
        },
        ObservedEvent::TurnFailed { error } => AgentSignal {
            status: AgentStatus::Completed {
                summary: truncate_chars(&format!("Error: {error}"), 280),
            },
            attention: None,
            outcome: TurnOutcome::Failed {
                error: truncate_chars(&error, 500),
            },
            resolution: SignalResolution::ClearNonPlan,
            seq: None,
            epoch: None,
        },
        ObservedEvent::TurnInterrupted => AgentSignal {
            status: AgentStatus::Idle,
            attention: None,
            outcome: TurnOutcome::Aborted,
            resolution: SignalResolution::ClearNonPlan,
            seq: None,
            epoch: None,
        },
        ObservedEvent::Detached => AgentSignal {
            status: AgentStatus::Idle,
            attention: None,
            outcome: TurnOutcome::None,
            resolution: SignalResolution::ClearAll,
            seq: None,
            epoch: None,
        },
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExtState {
    pub active_turn: bool,
    pub attentions: Vec<(String, ObservedEvent)>,
    pub last_text: String,
}

#[derive(Debug)]
pub struct RootTracker {
    agent: &'static str,
    pub roots: HashMap<String, ExtState>,
    verified_sessions: HashMap<String, String>,
}

impl RootTracker {
    pub fn new(agent: &'static str) -> Self {
        Self {
            agent,
            roots: HashMap::new(),
            verified_sessions: HashMap::new(),
        }
    }

    pub fn reconcile_candidates(
        &mut self,
        candidates: &[Candidate],
        registry: &SessionRegistry,
        broadcaster: &HostEventBroadcaster,
    ) {
        let mut next_verified = HashMap::new();
        for c in candidates {
            if let Some(root_id) = verified_id(self.agent, &c.argv) {
                let is_new_binding = self
                    .verified_sessions
                    .get(&c.session_id)
                    .is_none_or(|prev| prev != &root_id);
                if is_new_binding {
                    if let Some(st) = self.roots.get(&root_id) {
                        if st.active_turn {
                            crate::agent::ingest(
                                registry,
                                broadcaster,
                                &c.session_id,
                                self.agent,
                                to_signal(ObservedEvent::TurnStarted),
                            );
                        }
                        for (_, att) in &st.attentions {
                            crate::agent::ingest(
                                registry,
                                broadcaster,
                                &c.session_id,
                                self.agent,
                                to_signal(att.clone()),
                            );
                        }
                    }
                }
                next_verified.insert(c.session_id.clone(), root_id);
            }
        }
        let active_root_ids: std::collections::HashSet<&str> =
            next_verified.values().map(String::as_str).collect();
        self.roots.retain(|rid, st| {
            active_root_ids.contains(rid.as_str()) || st.active_turn || !st.attentions.is_empty()
        });
        self.verified_sessions = next_verified;
    }

    pub fn emit(
        &mut self,
        root_id: &str,
        ev: ObservedEvent,
        registry: &SessionRegistry,
        broadcaster: &HostEventBroadcaster,
    ) {
        let is_detached = matches!(ev, ObservedEvent::Detached);
        match &ev {
            ObservedEvent::TurnStarted => {
                let st = self.roots.entry(root_id.to_string()).or_default();
                st.active_turn = true;
                st.attentions.clear();
                st.last_text.clear();
            }
            ObservedEvent::Attention { key, .. } => {
                let st = self.roots.entry(root_id.to_string()).or_default();
                if let Some(pos) = st.attentions.iter().position(|(k, _)| k == key) {
                    st.attentions[pos].1 = ev.clone();
                } else {
                    st.attentions.push((key.clone(), ev.clone()));
                }
            }
            ObservedEvent::AttentionResolved { key } => {
                let Some(st) = self.roots.get_mut(root_id) else {
                    return;
                };
                if let Some(pos) = st.attentions.iter().position(|(k, _)| k == key) {
                    st.attentions.remove(pos);
                } else {
                    return;
                }
            }
            ObservedEvent::TurnCompleted { .. }
            | ObservedEvent::TurnFailed { .. }
            | ObservedEvent::TurnInterrupted => {
                let st = self.roots.entry(root_id.to_string()).or_default();
                st.active_turn = false;
                st.attentions.clear();
            }
            ObservedEvent::Activity { .. } => {
                self.roots.entry(root_id.to_string()).or_default();
            }
            ObservedEvent::Detached => {
                self.roots.remove(root_id);
            }
        }

        let target_sessions: Vec<String> = self
            .verified_sessions
            .iter()
            .filter(|&(_, rid)| rid == root_id)
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in target_sessions {
            crate::agent::ingest(
                registry,
                broadcaster,
                &sid,
                self.agent,
                to_signal(ev.clone()),
            );
        }
        if is_detached {
            self.roots.remove(root_id);
        }
    }

    pub fn emit_transport_down(
        &mut self,
        registry: &SessionRegistry,
        broadcaster: &HostEventBroadcaster,
    ) {
        let mut updates: Vec<(String, ObservedEvent)> = Vec::new();
        for (root_id, st) in &mut self.roots {
            for (_, att) in &mut st.attentions {
                if let ObservedEvent::Attention {
                    key,
                    kind,
                    prompt,
                    options,
                    actionable,
                } = att
                {
                    if *actionable {
                        *actionable = false;
                        updates.push((
                            root_id.clone(),
                            ObservedEvent::Attention {
                                key: key.clone(),
                                kind: kind.clone(),
                                prompt: prompt.clone(),
                                options: options.clone(),
                                actionable: false,
                            },
                        ));
                    }
                }
            }
        }
        for (root_id, ev) in updates {
            for (sid, rid) in &self.verified_sessions {
                if rid == &root_id {
                    crate::agent::ingest(
                        registry,
                        broadcaster,
                        sid,
                        self.agent,
                        to_signal(ev.clone()),
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObserverPaths {
    pub codex_home: PathBuf,
    pub opencode_state: PathBuf,
    pub opencode_data: PathBuf,
}

impl ObserverPaths {
    pub fn from_env() -> Option<Self> {
        let home = crate::net::ipc::home_dir().ok()?;
        let codex_home = non_empty_env_path("CODEX_HOME").unwrap_or_else(|| home.join(".codex"));
        let opencode_state = non_empty_env_path("XDG_STATE_HOME")
            .unwrap_or_else(|| home.join(".local/state"))
            .join("opencode");
        let opencode_data = non_empty_env_path("XDG_DATA_HOME")
            .unwrap_or_else(|| home.join(".local/share"))
            .join("opencode");
        Some(Self {
            codex_home,
            opencode_state,
            opencode_data,
        })
    }
}

fn non_empty_env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub enum ObserverCommand {
    Respond {
        key: String,
        choice: AgentChoice,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Prepare {
        agent: &'static str,
        cwd: PathBuf,
        reply: oneshot::Sender<Result<String, String>>,
    },
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct AdapterSlot {
    tx: mpsc::Sender<ObserverCommand>,
    candidates_tx: watch::Sender<Vec<Candidate>>,
    has_prepared: Arc<AtomicBool>,
    idle_ticks: u32,
    _task: AbortOnDrop,
}

pub struct ObserverHub {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ObserverHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ObserverHub {
    pub fn spawn(
        registry: Arc<SessionRegistry>,
        broadcaster: Arc<HostEventBroadcaster>,
        paths: ObserverPaths,
        commands: mpsc::Receiver<ObserverCommand>,
    ) -> Self {
        let task = tokio::spawn(run_hub(registry, broadcaster, paths, commands));
        Self { task }
    }
}

fn ensure_adapter<'a>(
    slot: &'a mut Option<AdapterSlot>,
    agent: &'static str,
    initial_candidates: Vec<Candidate>,
    registry: &Arc<SessionRegistry>,
    broadcaster: &Arc<HostEventBroadcaster>,
    paths: &ObserverPaths,
) -> &'a mut AdapterSlot {
    if slot.is_none() {
        let (tx, rx) = mpsc::channel(ADAPTER_CHANNEL_CAP);
        let (candidates_tx, candidates_rx) = watch::channel(initial_candidates);
        let has_prepared = Arc::new(AtomicBool::new(false));
        let task = spawn_adapter_task(
            agent,
            Arc::clone(registry),
            Arc::clone(broadcaster),
            paths.clone(),
            candidates_rx,
            rx,
            Arc::clone(&has_prepared),
        );
        *slot = Some(AdapterSlot {
            tx,
            candidates_tx,
            has_prepared,
            idle_ticks: 0,
            _task: AbortOnDrop(task),
        });
    }
    slot.as_mut().expect("adapter slot initialized above")
}

fn spawn_adapter_task(
    agent: &'static str,
    registry: Arc<SessionRegistry>,
    broadcaster: Arc<HostEventBroadcaster>,
    paths: ObserverPaths,
    candidates_rx: watch::Receiver<Vec<Candidate>>,
    mut commands_rx: mpsc::Receiver<ObserverCommand>,
    has_prepared: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    match agent {
        "codex" => codex::spawn_codex_adapter(
            registry,
            broadcaster,
            paths.codex_home,
            candidates_rx,
            commands_rx,
            has_prepared,
        ),
        "opencode" => opencode::spawn_opencode_adapter(
            registry,
            broadcaster,
            paths.opencode_state,
            paths.opencode_data,
            candidates_rx,
            commands_rx,
            has_prepared,
        ),
        _ => tokio::spawn(async move {
            while let Some(cmd) = commands_rx.recv().await {
                match cmd {
                    ObserverCommand::Respond { reply, .. } => {
                        let _ = reply.send(Err("agent connection unavailable".into()));
                    }
                    ObserverCommand::Prepare { reply, .. } => {
                        let _ = reply.send(Err("agent server unavailable".into()));
                    }
                }
            }
        }),
    }
}

async fn run_hub(
    registry: Arc<SessionRegistry>,
    broadcaster: Arc<HostEventBroadcaster>,
    paths: ObserverPaths,
    mut commands: mpsc::Receiver<ObserverCommand>,
) {
    let mut codex: Option<AdapterSlot> = None;
    let mut opencode: Option<AdapterSlot> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                for (agent, slot) in [("codex", &mut codex), ("opencode", &mut opencode)] {
                    let cands = registry.observer_candidates(agent);
                    if cands.is_empty() {
                        if let Some(s) = slot.as_mut() {
                            let _ = s.candidates_tx.send_replace(cands);
                            if s.has_prepared.load(Ordering::Acquire) {
                                s.idle_ticks = 0;
                            } else {
                                s.idle_ticks += 1;
                                if s.idle_ticks >= ADAPTER_IDLE_STOP_TICKS {
                                    *slot = None;
                                }
                            }
                        }
                    } else {
                        let s = ensure_adapter(slot, agent, cands.clone(), &registry, &broadcaster, &paths);
                        let _ = s.candidates_tx.send_replace(cands);
                        s.idle_ticks = 0;
                    }
                }
            }
            cmd = commands.recv() => {
                let Some(cmd) = cmd else {
                    break;
                };
                match cmd {
                    ObserverCommand::Respond { key, choice, reply } => {
                        let target = if key.starts_with("obs:codex:") {
                            codex.as_mut()
                        } else if key.starts_with("obs:opencode:") {
                            opencode.as_mut()
                        } else {
                            let _ = reply.send(Err("unsupported choice".into()));
                            continue;
                        };
                        let Some(s) = target else {
                            let _ = reply.send(Err("agent connection unavailable".into()));
                            continue;
                        };
                        if let Err(err) = s.tx.try_send(ObserverCommand::Respond { key, choice, reply }) {
                            if let ObserverCommand::Respond { reply, .. } = err.into_inner() {
                                let _ = reply.send(Err("agent connection unavailable".into()));
                            }
                        }
                    }
                    ObserverCommand::Prepare { agent, cwd, reply } => {
                        let (agent_static, slot) = match agent {
                            "codex" => ("codex", &mut codex),
                            "opencode" => ("opencode", &mut opencode),
                            _ => {
                                let _ = reply.send(Err("unsupported agent".into()));
                                continue;
                            }
                        };
                        let cands = registry.observer_candidates(agent_static);
                        let s = ensure_adapter(slot, agent_static, cands, &registry, &broadcaster, &paths);
                        s.idle_ticks = 0;
                        if let Err(err) = s.tx.try_send(ObserverCommand::Prepare { agent: agent_static, cwd, reply }) {
                            if let ObserverCommand::Prepare { reply, .. } = err.into_inner() {
                                let _ = reply.send(Err("agent connection unavailable".into()));
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_uuid_8_4_4_4_12(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &ch) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if ch != b'-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

pub fn verified_id(agent: &str, argv: &[String]) -> Option<String> {
    match agent {
        "codex" => {
            let pos = argv.iter().position(|a| a == "resume")?;
            let next = argv.get(pos + 1)?;
            is_uuid_8_4_4_4_12(next).then(|| next.clone())
        }
        "opencode" => {
            let mut i = 0;
            while i < argv.len() {
                let arg = &argv[i];
                if arg == "-s" || arg == "--session" {
                    if let Some(next) = argv.get(i + 1) {
                        if next.starts_with("ses") {
                            return Some(next.clone());
                        }
                    }
                } else if let Some(val) = arg.strip_prefix("--session=") {
                    if val.starts_with("ses") {
                        return Some(val.to_string());
                    }
                }
                i += 1;
            }
            None
        }
        _ => None,
    }
}

pub fn uses_private_server(agent: &str, argv: &[String]) -> bool {
    match agent {
        "codex" => argv.iter().any(|arg| {
            let flag = arg.split_once('=').map_or(arg.as_str(), |(k, _)| k);
            matches!(
                flag,
                "--no-daemon"
                    | "--oss"
                    | "-p"
                    | "--profile"
                    | "-c"
                    | "--config"
                    | "--enable"
                    | "--disable"
                    | "--search"
                    | "--strict-config"
                    | "--dangerously-bypass-hook-trust"
            )
        }),
        "opencode" => argv.iter().any(|arg| {
            let flag = arg.split_once('=').map_or(arg.as_str(), |(k, _)| k);
            matches!(flag, "--standalone" | "--server")
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verified_id_codex_and_opencode() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
        assert_eq!(
            verified_id(
                "codex",
                &s(&[
                    "node",
                    "/x/codex.js",
                    "resume",
                    "01a211ba-6ad0-7230-8009-0401d46a4787"
                ])
            ),
            Some("01a211ba-6ad0-7230-8009-0401d46a4787".to_string())
        );
        assert_eq!(
            verified_id(
                "codex",
                &s(&["codex", "fork", "01a211ba-6ad0-7230-8009-0401d46a4787"])
            ),
            None
        );
        assert_eq!(verified_id("codex", &s(&["codex"])), None);
        assert_eq!(
            verified_id("codex", &s(&["codex", "resume", "not-a-uuid"])),
            None
        );

        assert_eq!(
            verified_id("opencode", &s(&["opencode", "-s", "ses_abc"])),
            Some("ses_abc".to_string())
        );
        assert_eq!(
            verified_id("opencode", &s(&["opencode", "--session=ses_xyz"])),
            Some("ses_xyz".to_string())
        );
        assert_eq!(
            verified_id("opencode", &s(&["opencode", "session", "list"])),
            None
        );
        assert_eq!(
            verified_id(
                "claude",
                &s(&["claude", "resume", "01a211ba-6ad0-7230-8009-0401d46a4787"])
            ),
            None
        );
    }

    #[test]
    fn test_uses_private_server() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
        assert!(uses_private_server(
            "codex",
            &s(&["codex", "--no-daemon", "resume", "x"])
        ));
        assert!(uses_private_server("codex", &s(&["codex", "--oss"])));
        assert!(uses_private_server("codex", &s(&["codex", "-p", "work"])));
        assert!(uses_private_server(
            "codex",
            &s(&["codex", "--profile=work"])
        ));
        assert!(uses_private_server("codex", &s(&["codex", "-c", "a=b"])));
        assert!(uses_private_server("codex", &s(&["codex", "--config=a=b"])));
        assert!(uses_private_server(
            "codex",
            &s(&["codex", "--enable", "hooks"])
        ));
        assert!(uses_private_server("codex", &s(&["codex", "--disable=x"])));
        assert!(uses_private_server("codex", &s(&["codex", "--search"])));
        assert!(uses_private_server(
            "codex",
            &s(&["codex", "--strict-config"])
        ));
        assert!(uses_private_server(
            "codex",
            &s(&["codex", "--dangerously-bypass-hook-trust"])
        ));
        assert!(!uses_private_server(
            "codex",
            &s(&["codex", "resume", "01a211ba-6ad0-7230-8009-0401d46a4787"])
        ));

        assert!(uses_private_server(
            "opencode",
            &s(&["opencode", "--standalone", "-s", "ses_1"])
        ));
        assert!(uses_private_server(
            "opencode",
            &s(&["opencode", "--server"])
        ));
        assert!(!uses_private_server(
            "opencode",
            &s(&["opencode", "-s", "ses_1"])
        ));
    }

    #[test]
    fn test_to_signal_table() {
        let ts = to_signal(ObservedEvent::TurnStarted);
        assert_eq!(ts.outcome, TurnOutcome::Started);
        assert_eq!(ts.resolution, SignalResolution::ClearNonPlan);

        let act = to_signal(ObservedEvent::Activity {
            desc: "x".repeat(300),
        });
        match act.status {
            AgentStatus::Thinking { task_desc } => assert_eq!(task_desc.chars().count(), 280),
            other => panic!("unexpected {other:?}"),
        }

        let att = to_signal(ObservedEvent::Attention {
            key: "obs:codex:r:1".into(),
            kind: AttentionKind::Approval,
            prompt: "Run: ls".into(),
            options: vec!["Allow once".into(), "Deny".into()],
            actionable: true,
        });
        assert_eq!(
            att.attention.as_ref().and_then(|a| a.key.as_deref()),
            Some("obs:codex:r:1")
        );

        let res = to_signal(ObservedEvent::AttentionResolved {
            key: "obs:codex:r:1".into(),
        });
        assert_eq!(
            res.resolution,
            SignalResolution::ByKey("obs:codex:r:1".into())
        );

        let done = to_signal(ObservedEvent::TurnCompleted {
            summary: "\nLine 1\nLine 2\n".into(),
        });
        assert_eq!(done.outcome, TurnOutcome::Done);
        assert_eq!(
            done.status,
            AgentStatus::Completed {
                summary: "Line 1 Line 2".into()
            }
        );

        let fail = to_signal(ObservedEvent::TurnFailed {
            error: "boom".into(),
        });
        assert_eq!(
            fail.outcome,
            TurnOutcome::Failed {
                error: "boom".into()
            }
        );

        let int = to_signal(ObservedEvent::TurnInterrupted);
        assert_eq!(int.outcome, TurnOutcome::Aborted);
        assert_eq!(int.status, AgentStatus::Idle);

        let det = to_signal(ObservedEvent::Detached);
        assert_eq!(det.resolution, SignalResolution::ClearAll);
        assert_eq!(det.status, AgentStatus::Idle);
    }

    #[test]
    fn test_observer_paths_from_env_uses_overrides_when_non_empty() {
        let prev_home = std::env::var_os("HOME");
        let prev_codex = std::env::var_os("CODEX_HOME");
        let prev_state = std::env::var_os("XDG_STATE_HOME");
        let prev_data = std::env::var_os("XDG_DATA_HOME");

        std::env::set_var("HOME", "/tmp/h");
        std::env::set_var("CODEX_HOME", "");
        std::env::set_var("XDG_STATE_HOME", "/tmp/st");
        std::env::set_var("XDG_DATA_HOME", "");

        let p = ObserverPaths::from_env().unwrap();
        assert_eq!(p.codex_home, PathBuf::from("/tmp/h/.codex"));
        assert_eq!(p.opencode_state, PathBuf::from("/tmp/st/opencode"));
        assert_eq!(
            p.opencode_data,
            PathBuf::from("/tmp/h/.local/share/opencode")
        );

        let restore = |k: &str, v: Option<std::ffi::OsString>| match v {
            Some(x) => std::env::set_var(k, x),
            None => std::env::remove_var(k),
        };
        restore("HOME", prev_home);
        restore("CODEX_HOME", prev_codex);
        restore("XDG_STATE_HOME", prev_state);
        restore("XDG_DATA_HOME", prev_data);
    }
}
