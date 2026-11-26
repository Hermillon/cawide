use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cawide_protocol::types::AgentChoice;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch};

use super::codex_rollout::RolloutTailer;
use super::{
    uses_private_server, verified_id, Candidate, ObservedEvent, ObserverCommand, RootTracker,
    OBSERVER_KEY_PREFIX,
};
use crate::agent::map::AttentionKind;
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::registry::SessionRegistry;

pub struct DaemonConn {
    pub rx: mpsc::Receiver<String>,
    pub tx: mpsc::Sender<String>,
}

#[cfg(unix)]
pub async fn connect_daemon(socket: &Path) -> Option<DaemonConn> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::UnixStream;
    use tokio_websockets::{ClientBuilder, Message};

    let stream = UnixStream::connect(socket).await.ok()?;
    let (ws_stream, _) = ClientBuilder::new()
        .uri("ws://localhost/")
        .ok()?
        .connect_on(stream)
        .await
        .ok()?;
    let (mut write_half, mut read_half) = ws_stream.split();
    let (tx_in, rx_in) = mpsc::channel::<String>(128);
    let (tx_out, mut rx_out) = mpsc::channel::<String>(128);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                inbound = read_half.next() => {
                    match inbound {
                        Some(Ok(msg)) => {
                            if let Some(text) = msg.as_text() {
                                if tx_in.send(text.to_string()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
                outbound = rx_out.recv() => {
                    match outbound {
                        Some(text) => {
                            if write_half.send(Message::text(text)).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    Some(DaemonConn {
        rx: rx_in,
        tx: tx_out,
    })
}

#[cfg(not(unix))]
pub async fn connect_daemon(_socket: &Path) -> Option<DaemonConn> {
    None
}

#[derive(Debug, Default)]
pub struct CodexState {
    pub root_by_thread: HashMap<String, String>,
    pub active_turn: HashMap<String, bool>,
    pub last_text: HashMap<String, String>,
}

impl CodexState {
    pub fn resolve_root(&self, thread_id: &str) -> Option<&str> {
        self.root_by_thread.get(thread_id).map(|s| s.as_str())
    }

    pub fn register_thread(&mut self, thread_id: &str, session_id: &str) {
        self.root_by_thread
            .insert(thread_id.to_string(), session_id.to_string());
    }
}

pub fn make_codex_key(root_id: &str, req_id: &Value) -> String {
    format!(
        "{OBSERVER_KEY_PREFIX}codex:{root_id}:{}",
        serde_json::to_string(req_id).unwrap_or_default()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingCodexRequest {
    Approval { options_len: usize },
    Ask { qid: String, options: Vec<String> },
    TextQuestion { qid: String },
    NonActionable,
}

pub fn translate_request(
    id: Value,
    method: &str,
    params: &Value,
    state: &CodexState,
) -> Option<(String, ObservedEvent, PendingCodexRequest)> {
    let thread_id = params.get("threadId").and_then(|v| v.as_str())?;
    let root = state.resolve_root(thread_id)?;
    let key = make_codex_key(root, &id);

    match method {
        "item/commandExecution/requestApproval" => {
            let cmd = params.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let kind = params
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("command");
            let prompt = if !cmd.is_empty() {
                format!("Run: {cmd}")
            } else if !reason.is_empty() {
                format!("Approve command: {reason}")
            } else {
                "Approve command".to_string()
            };
            let options = if kind == "humanCommand" {
                vec!["Allow once".into(), "Deny".into()]
            } else {
                vec![
                    "Allow once".into(),
                    "Deny".into(),
                    "Allow for session".into(),
                ]
            };
            let options_len = options.len();
            Some((
                root.to_string(),
                ObservedEvent::Attention {
                    key,
                    kind: AttentionKind::Approval,
                    prompt,
                    options,
                    actionable: true,
                },
                PendingCodexRequest::Approval { options_len },
            ))
        }
        "item/fileChange/requestApproval" => {
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let prompt = if !reason.is_empty() {
                format!("Apply file changes: {reason}")
            } else {
                "Apply file changes".to_string()
            };
            let options = vec![
                "Allow once".into(),
                "Deny".into(),
                "Allow for session".into(),
            ];
            let options_len = options.len();
            Some((
                root.to_string(),
                ObservedEvent::Attention {
                    key,
                    kind: AttentionKind::Approval,
                    prompt,
                    options,
                    actionable: true,
                },
                PendingCodexRequest::Approval { options_len },
            ))
        }
        "item/tool/requestUserInput" => {
            let questions = params.get("questions").and_then(|v| v.as_array())?;
            if questions.len() == 1 {
                let q = &questions[0];
                let qid = q
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let is_secret = q.get("isSecret").and_then(|v| v.as_bool()).unwrap_or(false);
                let q_text = q.get("question").and_then(|v| v.as_str()).unwrap_or("");
                if !is_secret {
                    if let Some(opts) = q.get("options").and_then(|v| v.as_array()) {
                        if !opts.is_empty() {
                            let labels: Vec<String> = opts
                                .iter()
                                .take(8)
                                .map(|o| {
                                    o.get("label")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string()
                                })
                                .collect();
                            let options_copy = labels.clone();
                            return Some((
                                root.to_string(),
                                ObservedEvent::Attention {
                                    key,
                                    kind: AttentionKind::Ask {
                                        multi: false,
                                        initial: 0,
                                    },
                                    prompt: q_text.to_string(),
                                    options: labels,
                                    actionable: true,
                                },
                                PendingCodexRequest::Ask {
                                    qid,
                                    options: options_copy,
                                },
                            ));
                        }
                    }
                    return Some((
                        root.to_string(),
                        ObservedEvent::Attention {
                            key,
                            kind: AttentionKind::TextQuestion,
                            prompt: q_text.to_string(),
                            options: Vec::new(),
                            actionable: true,
                        },
                        PendingCodexRequest::TextQuestion { qid },
                    ));
                }
            }
            Some((
                root.to_string(),
                ObservedEvent::Attention {
                    key,
                    kind: AttentionKind::TextQuestion,
                    prompt: format!("Codex is asking {} questions", questions.len()),
                    options: Vec::new(),
                    actionable: false,
                },
                PendingCodexRequest::NonActionable,
            ))
        }
        "item/permissions/requestApproval" => {
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let prompt = if !reason.is_empty() {
                format!("Codex requests additional permissions: {reason}")
            } else {
                "Codex requests additional permissions".to_string()
            };
            Some((
                root.to_string(),
                ObservedEvent::Attention {
                    key,
                    kind: AttentionKind::Approval,
                    prompt,
                    options: Vec::new(),
                    actionable: false,
                },
                PendingCodexRequest::NonActionable,
            ))
        }
        "mcpServer/elicitation/request" => {
            let srv = params
                .get("serverName")
                .and_then(|v| v.as_str())
                .unwrap_or("MCP server");
            Some((
                root.to_string(),
                ObservedEvent::Attention {
                    key,
                    kind: AttentionKind::TextQuestion,
                    prompt: format!("{srv} requests input"),
                    options: Vec::new(),
                    actionable: false,
                },
                PendingCodexRequest::NonActionable,
            ))
        }
        _ => None,
    }
}

pub fn translate_notification(
    method: &str,
    params: &Value,
    state: &mut CodexState,
) -> Vec<(String, ObservedEvent)> {
    let mut out = Vec::new();
    let thread_id = params
        .get("threadId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let root = match state.resolve_root(thread_id) {
        Some(r) => r.to_string(),
        None => return out,
    };
    let is_root = thread_id == root;

    match method {
        "turn/started" => {
            if is_root {
                state.active_turn.insert(root.clone(), true);
                state.last_text.entry(root.clone()).or_default().clear();
                out.push((root, ObservedEvent::TurnStarted));
            }
        }
        "item/started" => {
            if is_root {
                if let Some(item) = params.get("item") {
                    let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match item_type {
                        "userMessage" => {
                            if let Some(text) = item
                                .get("content")
                                .and_then(|c| c.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|obj| obj.get("text"))
                                .and_then(|v| v.as_str())
                            {
                                out.push((
                                    root,
                                    ObservedEvent::Activity {
                                        desc: text.to_string(),
                                    },
                                ));
                            }
                        }
                        "commandExecution" => {
                            let cmd = item.get("command").and_then(|v| v.as_str()).unwrap_or("");
                            out.push((
                                root,
                                ObservedEvent::Activity {
                                    desc: cmd.to_string(),
                                },
                            ));
                        }
                        "fileChange" => {
                            let count = item
                                .get("changes")
                                .and_then(|v| v.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            out.push((
                                root,
                                ObservedEvent::Activity {
                                    desc: format!("Editing {count} file(s)"),
                                },
                            ));
                        }
                        "mcpToolCall" => {
                            let server = item.get("server").and_then(|v| v.as_str()).unwrap_or("");
                            let tool = item.get("tool").and_then(|v| v.as_str()).unwrap_or("");
                            out.push((
                                root,
                                ObservedEvent::Activity {
                                    desc: format!("{server}.{tool}"),
                                },
                            ));
                        }
                        "dynamicToolCall" => {
                            let tool = item.get("tool").and_then(|v| v.as_str()).unwrap_or("");
                            out.push((
                                root,
                                ObservedEvent::Activity {
                                    desc: tool.to_string(),
                                },
                            ));
                        }
                        "webSearch" => {
                            let q = item.get("query").and_then(|v| v.as_str()).unwrap_or("");
                            out.push((
                                root,
                                ObservedEvent::Activity {
                                    desc: format!("Searching: {q}"),
                                },
                            ));
                        }
                        "contextCompaction" => {
                            out.push((
                                root,
                                ObservedEvent::Activity {
                                    desc: "Compacting context…".into(),
                                },
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
        "item/completed" => {
            if is_root {
                if let Some(item) = params.get("item") {
                    if item.get("type").and_then(|v| v.as_str()) == Some("agentMessage") {
                        if let Some(txt) = item.get("text").and_then(|v| v.as_str()) {
                            state.last_text.insert(root, txt.to_string());
                        }
                    }
                }
            }
        }
        "turn/completed" => {
            if is_root {
                state.active_turn.insert(root.clone(), false);
                let turn = params.get("turn");
                let status = turn
                    .and_then(|t| t.get("status"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("completed");
                match status {
                    "completed" => {
                        let mut summary = state.last_text.get(&root).cloned().unwrap_or_default();
                        if summary.is_empty() {
                            if let Some(items) =
                                turn.and_then(|t| t.get("items")).and_then(|v| v.as_array())
                            {
                                for it in items.iter().rev() {
                                    if it.get("type").and_then(|v| v.as_str())
                                        == Some("agentMessage")
                                    {
                                        if let Some(txt) = it.get("text").and_then(|v| v.as_str()) {
                                            summary = txt.to_string();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        out.push((root, ObservedEvent::TurnCompleted { summary }));
                    }
                    "interrupted" => {
                        out.push((root, ObservedEvent::TurnInterrupted));
                    }
                    "failed" => {
                        let error = turn
                            .and_then(|t| t.get("error"))
                            .and_then(|e| e.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Codex turn failed")
                            .to_string();
                        out.push((root, ObservedEvent::TurnFailed { error }));
                    }
                    _ => {}
                }
            }
        }
        "error" => {
            if params.get("willRetry").and_then(|v| v.as_bool()) == Some(true) {
                let msg = params
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("error");
                out.push((
                    root,
                    ObservedEvent::Activity {
                        desc: format!("Retrying: {msg}"),
                    },
                ));
            }
        }
        "serverRequest/resolved" => {
            if let Some(req_id) = params.get("requestId") {
                let key = make_codex_key(&root, req_id);
                out.push((root, ObservedEvent::AttentionResolved { key }));
            }
        }
        "thread/closed" if is_root => {
            out.push((root, ObservedEvent::Detached));
        }
        _ => {}
    }
    out
}

pub fn build_codex_reply(
    choice: AgentChoice,
    pending: &PendingCodexRequest,
) -> Result<Value, String> {
    match pending {
        PendingCodexRequest::Approval { options_len } => match choice {
            AgentChoice::Option { index } => match index {
                0 => Ok(json!({ "decision": "accept" })),
                1 => Ok(json!({ "decision": "decline" })),
                2 if *options_len == 3 => Ok(json!({ "decision": "acceptForSession" })),
                _ => Err("unsupported choice".into()),
            },
            AgentChoice::Text { .. } => Err("unsupported choice".into()),
        },
        PendingCodexRequest::Ask { qid, options } => match choice {
            AgentChoice::Option { index } => {
                let idx = index as usize;
                let label = options
                    .get(idx)
                    .ok_or_else(|| "unsupported choice".to_string())?;
                Ok(json!({ "answers": { qid: { "answers": [label] } } }))
            }
            AgentChoice::Text { text } => {
                let sanitized = crate::agent::respond::sanitize_reply_text(&text)?;
                Ok(json!({ "answers": { qid: { "answers": [sanitized] } } }))
            }
        },
        PendingCodexRequest::TextQuestion { qid } => match choice {
            AgentChoice::Option { .. } => Err("unsupported choice".into()),
            AgentChoice::Text { text } => {
                let sanitized = crate::agent::respond::sanitize_reply_text(&text)?;
                Ok(json!({ "answers": { qid: { "answers": [sanitized] } } }))
            }
        },
        PendingCodexRequest::NonActionable => Err("unsupported choice".into()),
    }
}
pub fn spawn_codex_adapter(
    registry: Arc<SessionRegistry>,
    broadcaster: Arc<HostEventBroadcaster>,
    codex_home: PathBuf,
    candidates_rx: watch::Receiver<Vec<Candidate>>,
    commands_rx: mpsc::Receiver<ObserverCommand>,
    has_prepared: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_codex_adapter(
        registry,
        broadcaster,
        codex_home,
        candidates_rx,
        commands_rx,
        has_prepared,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RpcKind {
    Initialize { with_human_approval: bool },
    ThreadStart,
    ThreadNameSet { thread_id: String },
    ThreadLoadedList { is_first_page: bool },
    ThreadResume,
    ThreadRead,
    ThreadTurnsList { root_id: String },
}

#[allow(dead_code)]
enum RpcReply {
    Value(oneshot::Sender<Result<Value, String>>),
    ThreadId(oneshot::Sender<Result<String, String>>),
}

struct PendingRpc {
    kind: RpcKind,
    reply: Option<RpcReply>,
}

struct AdapterCtx {
    state: CodexState,
    tracker: RootTracker,
    subscribed_threads: HashSet<String>,
    loaded_threads: HashSet<String>,
    loaded_accum: HashSet<String>,
    loaded_list_ready: bool,
    loaded_list_in_flight: bool,
    opt_out_sent: bool,
    init_retry_after: Option<Instant>,
    verified_roots: HashSet<String>,
    rollout_only_roots: HashSet<String>,
    prepared_map: HashMap<String, Instant>,
    pending_requests: HashMap<String, PendingCodexRequest>,
}

impl AdapterCtx {
    fn new() -> Self {
        Self {
            state: CodexState::default(),
            tracker: RootTracker::new("codex"),
            subscribed_threads: HashSet::new(),
            loaded_threads: HashSet::new(),
            loaded_accum: HashSet::new(),
            loaded_list_ready: false,
            loaded_list_in_flight: false,
            opt_out_sent: false,
            init_retry_after: None,
            verified_roots: HashSet::new(),
            rollout_only_roots: HashSet::new(),
            prepared_map: HashMap::new(),
            pending_requests: HashMap::new(),
        }
    }

    fn is_wanted_root(&self, root_id: &str) -> bool {
        self.verified_roots.contains(root_id) || self.prepared_map.contains_key(root_id)
    }

    fn update_candidates(&mut self, candidates: &[Candidate]) {
        let mut by_root: HashMap<String, Vec<&Candidate>> = HashMap::new();
        for c in candidates {
            if let Some(root_id) = verified_id("codex", &c.argv) {
                by_root.entry(root_id).or_default().push(c);
            }
        }
        self.verified_roots = by_root.keys().cloned().collect();
        self.rollout_only_roots = by_root
            .into_iter()
            .filter_map(|(root_id, cands)| {
                cands
                    .iter()
                    .all(|c| uses_private_server("codex", &c.argv))
                    .then_some(root_id)
            })
            .collect();
    }
}

fn build_initialize_request(id: u64, with_human_approval: bool) -> Value {
    let mut capabilities = json!({
        "experimentalApi": true,
        "optOutNotificationMethods": [
            "item/agentMessage/delta",
            "item/reasoning/textDelta",
            "item/reasoning/summaryTextDelta",
            "item/reasoning/summaryPartAdded",
            "item/commandExecution/outputDelta",
            "item/fileChange/outputDelta",
            "item/plan/delta",
            "command/exec/outputDelta",
            "process/outputDelta",
            "thread/tokenUsage/updated",
            "turn/diff/updated"
        ]
    });
    if with_human_approval {
        if let Some(obj) = capabilities.as_object_mut() {
            obj.insert("requiredHumanApproval".into(), json!(true));
        }
    }
    json!({
        "id": id,
        "method": "initialize",
        "params": {
            "clientInfo": {
                "name": "cawide",
                "title": "Cawide",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": capabilities
        }
    })
}

async fn send_rpc(
    conn: &DaemonConn,
    next_id: &mut u64,
    pending: &mut HashMap<u64, PendingRpc>,
    kind: RpcKind,
    method: &str,
    params: Value,
    reply: Option<RpcReply>,
) {
    let req_id = *next_id;
    *next_id += 1;
    pending.insert(req_id, PendingRpc { kind, reply });
    let req = json!({
        "id": req_id,
        "method": method,
        "params": params,
    });
    let _ = conn.tx.send(req.to_string()).await;
}

async fn send_unsubscribe(conn: &DaemonConn, next_id: &mut u64, thread_id: &str) {
    let req_id = *next_id;
    *next_id += 1;
    let req = json!({
        "id": req_id,
        "method": "thread/unsubscribe",
        "params": { "threadId": thread_id }
    });
    let _ = conn.tx.send(req.to_string()).await;
}

fn close_out_from_turn(turn: &Value, state: &mut CodexState, root: &str) -> Option<ObservedEvent> {
    let status = turn.get("status").and_then(|v| v.as_str())?;
    match status {
        "completed" => {
            state.active_turn.insert(root.to_string(), false);
            let mut summary = String::new();
            if let Some(items) = turn.get("items").and_then(|v| v.as_array()) {
                for it in items.iter().rev() {
                    if it.get("type").and_then(|v| v.as_str()) == Some("agentMessage") {
                        if let Some(txt) = it.get("text").and_then(|v| v.as_str()) {
                            summary = txt.to_string();
                            break;
                        }
                    }
                }
            }
            if summary.is_empty() {
                summary = state.last_text.get(root).cloned().unwrap_or_default();
            }
            Some(ObservedEvent::TurnCompleted { summary })
        }
        "failed" => {
            state.active_turn.insert(root.to_string(), false);
            let error = turn
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("Codex turn failed")
                .to_string();
            Some(ObservedEvent::TurnFailed { error })
        }
        "interrupted" => {
            state.active_turn.insert(root.to_string(), false);
            Some(ObservedEvent::TurnInterrupted)
        }
        _ => None,
    }
}
async fn run_codex_adapter(
    registry: Arc<SessionRegistry>,
    broadcaster: Arc<HostEventBroadcaster>,
    codex_home: PathBuf,
    mut candidates_rx: watch::Receiver<Vec<Candidate>>,
    mut commands_rx: mpsc::Receiver<ObserverCommand>,
    has_prepared: Arc<AtomicBool>,
) {
    let socket_path = codex_home
        .join("app-server-control")
        .join("app-server-control.sock");
    let mut ctx = AdapterCtx::new();
    let codex_home_backup = codex_home.clone();
    let mut rollout = RolloutTailer::new(codex_home);
    let mut conn: Option<DaemonConn> = None;
    let mut next_id = 1u64;
    let mut pending: HashMap<u64, PendingRpc> = HashMap::new();
    let mut queued_prepares: VecDeque<(PathBuf, oneshot::Sender<Result<String, String>>)> =
        VecDeque::new();
    let mut disconnect_timer: Option<Instant> = None;
    let mut transport_reemitted = false;

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let candidates = candidates_rx.borrow().clone();
                ctx.update_candidates(&candidates);
                ctx.tracker.reconcile_candidates(&candidates, &registry, &broadcaster);

                let now = Instant::now();
                let expired: Vec<String> = ctx
                    .prepared_map
                    .iter()
                    .filter(|&(_, t)| now.duration_since(*t) > Duration::from_secs(60))
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in expired {
                    ctx.prepared_map.remove(&id);
                    if !ctx.verified_roots.contains(&id) {
                        if let Some(c) = &conn {
                            if ctx.subscribed_threads.remove(&id) {
                                send_unsubscribe(c, &mut next_id, &id).await;
                            }
                        }
                    }
                }
                has_prepared.store(!ctx.prepared_map.is_empty(), Ordering::Release);

                if conn.is_none() {
                    let can_connect = ctx
                        .init_retry_after
                        .is_none_or(|deadline| now >= deadline);
                    if can_connect {
                        if let Some(c) = connect_daemon(&socket_path).await {
                            ctx.opt_out_sent = false;
                            ctx.loaded_list_ready = false;
                            ctx.loaded_threads.clear();
                            ctx.loaded_accum.clear();
                            ctx.subscribed_threads.clear();
                            ctx.init_retry_after = None;
                            disconnect_timer = None;
                            transport_reemitted = false;

                            let req_id = next_id;
                            next_id += 1;
                            pending.insert(
                                req_id,
                                PendingRpc {
                                    kind: RpcKind::Initialize {
                                        with_human_approval: true,
                                    },
                                    reply: None,
                                },
                            );
                            let init_req = build_initialize_request(req_id, true);
                            let _ = c.tx.send(init_req.to_string()).await;
                            conn = Some(c);
                        } else if let Some(down_since) = disconnect_timer {
                            if !transport_reemitted && now.duration_since(down_since) >= Duration::from_secs(10) {
                                ctx.tracker.emit_transport_down(&registry, &broadcaster);
                                transport_reemitted = true;
                            }
                        } else {
                            disconnect_timer = Some(now);
                        }
                    }
                }

                if let Some(c) = &conn {
                    if ctx.opt_out_sent {
                        // Unsubscribe roots (and their sub-agents) that are rollout-only or no longer wanted.
                        let to_unsub: Vec<String> = ctx
                            .subscribed_threads
                            .iter()
                            .filter(|tid| {
                                let root = ctx
                                    .state
                                    .resolve_root(tid)
                                    .map(str::to_string)
                                    .unwrap_or_else(|| (*tid).clone());
                                ctx.rollout_only_roots.contains(&root) || !ctx.is_wanted_root(&root)
                            })
                            .cloned()
                            .collect();
                        for tid in to_unsub {
                            ctx.subscribed_threads.remove(&tid);
                            send_unsubscribe(c, &mut next_id, &tid).await;
                        }

                        while let Some((cwd, reply)) = queued_prepares.pop_front() {
                            send_rpc(
                                c,
                                &mut next_id,
                                &mut pending,
                                RpcKind::ThreadStart,
                                "thread/start",
                                json!({ "cwd": cwd }),
                                Some(RpcReply::ThreadId(reply)),
                            )
                            .await;
                        }

                        // Poll thread/loaded/list (first page)
                        if !ctx.loaded_list_in_flight {
                            ctx.loaded_list_in_flight = true;
                            ctx.loaded_accum.clear();
                            send_rpc(
                                c,
                                &mut next_id,
                                &mut pending,
                                RpcKind::ThreadLoadedList { is_first_page: true },
                                "thread/loaded/list",
                                json!({}),
                                None,
                            )
                            .await;
                        }

                        // Sub-agents & unsubscribed loaded threads: read every loaded id not currently subscribed
                        // that is either unknown or a known sub-agent of a subscribed root.
                        let loaded_snapshot: Vec<String> = ctx.loaded_threads.iter().cloned().collect();
                        for tid in loaded_snapshot {
                            if ctx.subscribed_threads.contains(&tid) || ctx.rollout_only_roots.contains(&tid) {
                                continue;
                            }
                            let should_probe = match ctx.state.resolve_root(&tid) {
                                None => true,
                                Some(root) => root != tid && ctx.subscribed_threads.contains(root),
                            };
                            if should_probe {
                                send_rpc(
                                    c,
                                    &mut next_id,
                                    &mut pending,
                                    RpcKind::ThreadRead,
                                    "thread/read",
                                    json!({ "threadId": tid, "includeTurns": false }),
                                    None,
                                )
                                .await;
                            }
                        }
                    }
                }

                // Rollout tailing for rollout-only roots, or daemon-source roots while daemon is unreachable
                // or root is not in loaded_threads.
                let daemon_ready = conn.is_some() && ctx.opt_out_sent && ctx.loaded_list_ready;
                let rollout_roots: Vec<String> = ctx
                    .verified_roots
                    .iter()
                    .filter(|root_id| {
                        ctx.rollout_only_roots.contains(*root_id)
                            || !daemon_ready
                            || !ctx.loaded_threads.contains(*root_id)
                    })
                    .cloned()
                    .collect();
                rollout.retain_roots(&rollout_roots);
                if !rollout_roots.is_empty() {
                    let backup_home = codex_home_backup.clone();
                    let (polled_events, returned_rollout) = tokio::task::spawn_blocking(move || {
                        let mut all_events = Vec::new();
                        for root_id in &rollout_roots {
                            let events = rollout.poll_root(root_id);
                            all_events.push((root_id.clone(), events));
                        }
                        (all_events, rollout)
                    })
                    .await
                    .unwrap_or_else(|_| (Vec::new(), RolloutTailer::new(backup_home)));
                    rollout = returned_rollout;
                    for (root_id, events) in polled_events {
                        for ev in events {
                            match &ev {
                                ObservedEvent::TurnStarted => {
                                    ctx.state.active_turn.insert(root_id.clone(), true);
                                    ctx.state.last_text.entry(root_id.clone()).or_default().clear();
                                }
                                ObservedEvent::TurnCompleted { summary } => {
                                    ctx.state.active_turn.insert(root_id.clone(), false);
                                    ctx.state.last_text.insert(root_id.clone(), summary.clone());
                                }
                                ObservedEvent::TurnFailed { .. } | ObservedEvent::TurnInterrupted => {
                                    ctx.state.active_turn.insert(root_id.clone(), false);
                                }
                                _ => {}
                            }
                            ctx.tracker.emit(&root_id, ev, &registry, &broadcaster);
                        }
                    }
                }
            }
            changed = candidates_rx.changed() => {
                if changed.is_ok() {
                    let candidates = candidates_rx.borrow().clone();
                    ctx.update_candidates(&candidates);
                    ctx.tracker.reconcile_candidates(&candidates, &registry, &broadcaster);
                }
            }
            inbound = async {
                match conn.as_mut() {
                    Some(c) => c.rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match inbound {
                    Some(raw) => {
                        let keep_conn = handle_inbound_message(
                            &raw,
                            &mut conn,
                            &mut next_id,
                            &mut pending,
                            &mut ctx,
                            &registry,
                            &broadcaster,
                            &has_prepared,
                        ).await;
                        if !keep_conn {
                            conn = None;
                            pending.clear();
                            ctx.subscribed_threads.clear();
                            ctx.loaded_threads.clear();
                            ctx.loaded_accum.clear();
                            ctx.loaded_list_ready = false;
                            ctx.loaded_list_in_flight = false;
                            disconnect_timer = Some(Instant::now());
                        }
                    }
                    None => {
                        conn = None;
                        pending.clear();
                        ctx.subscribed_threads.clear();
                        ctx.loaded_threads.clear();
                        ctx.loaded_accum.clear();
                        ctx.loaded_list_ready = false;
                        ctx.loaded_list_in_flight = false;
                        ctx.opt_out_sent = false;
                    }
                }
            }
            cmd = commands_rx.recv() => {
                let Some(cmd) = cmd else {
                    break;
                };
                match cmd {
                    ObserverCommand::Respond { key, choice, reply } => {
                        if let Some(c) = &conn {
                            // Key shape: obs:codex:{root}:{raw_id_json}
                            let parts: Vec<&str> = key.splitn(4, ':').collect();
                            if parts.len() == 4 {
                                let raw_id_res: Result<Value, _> = serde_json::from_str(parts[3]);
                                if let Ok(req_id) = raw_id_res {
                                    let root_str = parts[2].to_string();
                                    let Some(pending_req) = ctx.pending_requests.get(&key).cloned() else {
                                        let _ = reply.send(Err("prompt no longer open".into()));
                                        continue;
                                    };
                                    match build_codex_reply(choice, &pending_req) {
                                        Ok(result) => {
                                            let resp = json!({
                                                "id": req_id,
                                                "result": result
                                            });
                                            if c.tx.send(resp.to_string()).await.is_err() {
                                                let _ = reply.send(Err(
                                                    "agent connection unavailable".into(),
                                                ));
                                                continue;
                                            }
                                            let _ = reply.send(Ok(()));
                                            ctx.pending_requests.remove(&key);
                                            ctx.tracker.emit(
                                                &root_str,
                                                ObservedEvent::AttentionResolved { key },
                                                &registry,
                                                &broadcaster,
                                            );
                                            continue;
                                        }
                                        Err(e) => {
                                            let _ = reply.send(Err(e));
                                            continue;
                                        }
                                    }
                                }
                            }
                            let _ = reply.send(Err("unsupported choice".into()));
                        } else {
                            let _ = reply.send(Err("agent connection unavailable".into()));
                        }
                    }
                    ObserverCommand::Prepare { agent: _, cwd, reply } => {
                        if let Some(c) = &conn {
                            if ctx.opt_out_sent {
                                send_rpc(
                                    c,
                                    &mut next_id,
                                    &mut pending,
                                    RpcKind::ThreadStart,
                                    "thread/start",
                                    json!({ "cwd": cwd }),
                                    Some(RpcReply::ThreadId(reply)),
                                )
                                .await;
                            } else {
                                queued_prepares.push_back((cwd, reply));
                            }
                        } else {
                            queued_prepares.push_back((cwd, reply));
                        }
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound_message(
    raw: &str,
    conn: &mut Option<DaemonConn>,
    next_id: &mut u64,
    pending: &mut HashMap<u64, PendingRpc>,
    ctx: &mut AdapterCtx,
    registry: &SessionRegistry,
    broadcaster: &HostEventBroadcaster,
    has_prepared: &AtomicBool,
) -> bool {
    let Ok(val) = serde_json::from_str::<Value>(raw) else {
        return true;
    };

    // Response
    if let Some(id_u64) = val
        .get("id")
        .filter(|_| val.get("method").is_none())
        .and_then(|v| v.as_u64())
    {
        if let Some(mut rpc) = pending.remove(&id_u64) {
            if let Some(err) = val.get("error") {
                let msg = err
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("RPC error");
                if let RpcKind::ThreadStart = rpc.kind {
                    if let Some(RpcReply::ThreadId(reply)) = rpc.reply {
                        let _ = reply.send(Err(msg.to_string()));
                    }
                } else if let RpcKind::ThreadNameSet { ref thread_id } = rpc.kind {
                    ctx.prepared_map.remove(thread_id);
                    has_prepared.store(!ctx.prepared_map.is_empty(), Ordering::Release);
                    if let Some(RpcReply::ThreadId(reply)) = rpc.reply {
                        let _ = reply.send(Err(msg.to_string()));
                    }
                } else if let Some(RpcReply::Value(reply)) = rpc.reply {
                    let _ = reply.send(Err(msg.to_string()));
                }
                if let RpcKind::Initialize {
                    with_human_approval,
                } = rpc.kind
                {
                    if with_human_approval {
                        if let Some(c) = conn {
                            let req_id = *next_id;
                            *next_id += 1;
                            pending.insert(
                                req_id,
                                PendingRpc {
                                    kind: RpcKind::Initialize {
                                        with_human_approval: false,
                                    },
                                    reply: None,
                                },
                            );
                            let retry_req = build_initialize_request(req_id, false);
                            let _ = c.tx.send(retry_req.to_string()).await;
                            return true;
                        }
                    } else {
                        tracing::warn!("codex initialize failed twice: {msg}");
                        ctx.init_retry_after = Some(Instant::now() + Duration::from_secs(30));
                        return false;
                    }
                }
                if matches!(rpc.kind, RpcKind::ThreadLoadedList { .. }) {
                    ctx.loaded_list_in_flight = false;
                }
            } else if let Some(res) = val.get("result") {
                match rpc.kind {
                    RpcKind::Initialize { .. } => {
                        ctx.opt_out_sent = true;
                        if let Some(c) = conn {
                            let init_notif = json!({
                                "method": "initialized",
                                "params": {}
                            });
                            let _ = c.tx.send(init_notif.to_string()).await;
                        }
                    }
                    RpcKind::ThreadStart => {
                        if let Some(id) = res
                            .get("thread")
                            .and_then(|t| t.get("id"))
                            .and_then(|v| v.as_str())
                        {
                            ctx.prepared_map.insert(id.to_string(), Instant::now());
                            ctx.state.register_thread(id, id);
                            has_prepared.store(true, Ordering::Release);
                            if let Some(c) = conn {
                                send_rpc(
                                    c,
                                    next_id,
                                    pending,
                                    RpcKind::ThreadNameSet {
                                        thread_id: id.to_string(),
                                    },
                                    "thread/name/set",
                                    json!({
                                        "threadId": id,
                                        "name": "cawide"
                                    }),
                                    rpc.reply.take(),
                                )
                                .await;
                            }
                        } else if let Some(RpcReply::ThreadId(reply)) = rpc.reply.take() {
                            let _ = reply.send(Err("invalid thread/start response".into()));
                        }
                    }
                    RpcKind::ThreadNameSet { thread_id } => {
                        has_prepared.store(true, Ordering::Release);
                        if let Some(RpcReply::ThreadId(reply)) = rpc.reply.take() {
                            let _ = reply.send(Ok(thread_id));
                        }
                    }
                    RpcKind::ThreadLoadedList { is_first_page } => {
                        if is_first_page {
                            ctx.loaded_accum.clear();
                        }
                        if let Some(data) = res.get("data").and_then(|v| v.as_array()) {
                            for t in data {
                                if let Some(tid) = t.as_str() {
                                    ctx.loaded_accum.insert(tid.to_string());
                                }
                            }
                        }
                        let next_cursor = res
                            .get("nextCursor")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty());
                        if let Some(cursor) = next_cursor {
                            if let Some(c) = conn {
                                send_rpc(
                                    c,
                                    next_id,
                                    pending,
                                    RpcKind::ThreadLoadedList {
                                        is_first_page: false,
                                    },
                                    "thread/loaded/list",
                                    json!({ "cursor": cursor }),
                                    None,
                                )
                                .await;
                            }
                        } else {
                            ctx.loaded_list_in_flight = false;
                            ctx.loaded_threads = std::mem::take(&mut ctx.loaded_accum);
                            ctx.loaded_list_ready = true;

                            // Drop subscriptions for threads no longer loaded.
                            let unloaded_subs: Vec<String> = ctx
                                .subscribed_threads
                                .iter()
                                .filter(|tid| !ctx.loaded_threads.contains(*tid))
                                .cloned()
                                .collect();
                            for tid in unloaded_subs {
                                ctx.subscribed_threads.remove(&tid);
                            }

                            // For any root with active_turn == true that is no longer loaded, close out via thread/turns/list.
                            let stale_active_roots: Vec<String> = ctx
                                .state
                                .active_turn
                                .iter()
                                .filter(|&(root, active)| {
                                    *active
                                        && !ctx.rollout_only_roots.contains(root)
                                        && !ctx.loaded_threads.contains(root)
                                })
                                .map(|(root, _)| root.clone())
                                .collect();
                            if let Some(c) = conn {
                                for root in stale_active_roots {
                                    send_rpc(
                                        c,
                                        next_id,
                                        pending,
                                        RpcKind::ThreadTurnsList {
                                            root_id: root.clone(),
                                        },
                                        "thread/turns/list",
                                        json!({
                                            "threadId": root,
                                            "limit": 1,
                                            "itemsView": "full"
                                        }),
                                        None,
                                    )
                                    .await;
                                }

                                // Subscribe to wanted daemon roots that are loaded and not yet subscribed.
                                let to_subscribe: Vec<String> = ctx
                                    .loaded_threads
                                    .iter()
                                    .filter(|tid| {
                                        ctx.is_wanted_root(tid)
                                            && !ctx.rollout_only_roots.contains(*tid)
                                            && !ctx.subscribed_threads.contains(*tid)
                                    })
                                    .cloned()
                                    .collect();
                                for tid in to_subscribe {
                                    ctx.subscribed_threads.insert(tid.clone());
                                    ctx.state.register_thread(&tid, &tid);
                                    send_rpc(
                                        c,
                                        next_id,
                                        pending,
                                        RpcKind::ThreadResume,
                                        "thread/resume",
                                        json!({
                                            "threadId": tid,
                                            "excludeTurns": true
                                        }),
                                        None,
                                    )
                                    .await;
                                    send_rpc(
                                        c,
                                        next_id,
                                        pending,
                                        RpcKind::ThreadRead,
                                        "thread/read",
                                        json!({
                                            "threadId": tid,
                                            "includeTurns": false
                                        }),
                                        None,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    RpcKind::ThreadResume => {
                        if let Some(thread) = res.get("thread") {
                            if let (Some(tid), Some(sid)) = (
                                thread.get("id").and_then(|v| v.as_str()),
                                thread.get("sessionId").and_then(|v| v.as_str()),
                            ) {
                                ctx.state.register_thread(tid, sid);
                            }
                        }
                    }
                    RpcKind::ThreadRead => {
                        if let Some(thread) = res.get("thread") {
                            let tid = thread.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let sid = thread
                                .get("sessionId")
                                .and_then(|v| v.as_str())
                                .unwrap_or(tid);
                            if !tid.is_empty() && !ctx.rollout_only_roots.contains(sid) {
                                ctx.state.register_thread(tid, sid);
                                let status_type = thread
                                    .get("status")
                                    .and_then(|s| s.get("type"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if tid == sid {
                                    if status_type == "notLoaded" {
                                        ctx.subscribed_threads.remove(tid);
                                        if let Some(c) = conn {
                                            send_unsubscribe(c, next_id, tid).await;
                                        }
                                    } else {
                                        let was_active = ctx
                                            .state
                                            .active_turn
                                            .get(sid)
                                            .copied()
                                            .unwrap_or(false);
                                        let is_active = status_type == "active";
                                        ctx.state.active_turn.insert(sid.to_string(), is_active);
                                        if is_active {
                                            ctx.tracker.emit(
                                                sid,
                                                ObservedEvent::TurnStarted,
                                                registry,
                                                broadcaster,
                                            );
                                        } else if was_active {
                                            if let Some(c) = conn {
                                                send_rpc(
                                                    c,
                                                    next_id,
                                                    pending,
                                                    RpcKind::ThreadTurnsList {
                                                        root_id: sid.to_string(),
                                                    },
                                                    "thread/turns/list",
                                                    json!({
                                                        "threadId": sid,
                                                        "limit": 1,
                                                        "itemsView": "full"
                                                    }),
                                                    None,
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                } else if status_type == "active"
                                    && ctx.subscribed_threads.contains(sid)
                                    && !ctx.subscribed_threads.contains(tid)
                                {
                                    ctx.subscribed_threads.insert(tid.to_string());
                                    if let Some(c) = conn {
                                        send_rpc(
                                            c,
                                            next_id,
                                            pending,
                                            RpcKind::ThreadResume,
                                            "thread/resume",
                                            json!({
                                                "threadId": tid,
                                                "excludeTurns": true
                                            }),
                                            None,
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                    }
                    RpcKind::ThreadTurnsList { root_id } => {
                        if let Some(turn) = res
                            .get("data")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                        {
                            if let Some(ev) = close_out_from_turn(turn, &mut ctx.state, &root_id) {
                                let prefix = format!("{OBSERVER_KEY_PREFIX}codex:{root_id}:");
                                ctx.pending_requests.retain(|k, _| !k.starts_with(&prefix));
                                ctx.tracker.emit(&root_id, ev, registry, broadcaster);
                            }
                        }
                    }
                }
                if let Some(RpcReply::Value(reply)) = rpc.reply {
                    let _ = reply.send(Ok(res.clone()));
                }
            }
        }
        return true;
    }

    // Request from server to client
    if let (Some(id_val), Some(method)) =
        (val.get("id"), val.get("method").and_then(|v| v.as_str()))
    {
        let params = val.get("params").unwrap_or(&Value::Null);
        if let Some((root, ev, pending_req)) =
            translate_request(id_val.clone(), method, params, &ctx.state)
        {
            if let ObservedEvent::Attention { key, .. } = &ev {
                ctx.pending_requests.insert(key.clone(), pending_req);
            }
            ctx.tracker.emit(&root, ev, registry, broadcaster);
        }
        return true;
    }

    // Notification
    if let Some(method) = val.get("method").and_then(|v| v.as_str()) {
        let params = val.get("params").unwrap_or(&Value::Null);
        let thread_id = params
            .get("threadId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let resolved_root = ctx.state.resolve_root(thread_id).map(str::to_string);

        if method == "thread/status/changed" {
            if let Some(root) = resolved_root.as_deref() {
                if thread_id == root {
                    let status_type = params
                        .get("status")
                        .and_then(|s| s.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let was_active = ctx.state.active_turn.get(root).copied().unwrap_or(false);
                    if matches!(status_type, "idle" | "systemError") && was_active {
                        if let Some(c) = conn {
                            send_rpc(
                                c,
                                next_id,
                                pending,
                                RpcKind::ThreadTurnsList {
                                    root_id: root.to_string(),
                                },
                                "thread/turns/list",
                                json!({
                                    "threadId": root,
                                    "limit": 1,
                                    "itemsView": "full"
                                }),
                                None,
                            )
                            .await;
                        }
                    }
                }
            }
            return true;
        }

        // Sub-agent lifecycle: unsubscribe on their turn/completed or thread/closed.
        if let Some(root) = resolved_root.as_deref() {
            if thread_id != root && matches!(method, "turn/completed" | "thread/closed") {
                if ctx.subscribed_threads.remove(thread_id) {
                    if let Some(c) = conn {
                        send_unsubscribe(c, next_id, thread_id).await;
                    }
                }
                return true;
            }
        }

        if let Some(root) = resolved_root.as_deref() {
            if matches!(method, "turn/started" | "turn/completed" | "thread/closed") {
                let prefix = format!("{OBSERVER_KEY_PREFIX}codex:{root}:");
                ctx.pending_requests.retain(|k, _| !k.starts_with(&prefix));
            }
        }

        let events = translate_notification(method, params, &mut ctx.state);
        for (root, ev) in events {
            if let ObservedEvent::AttentionResolved { key } = &ev {
                ctx.pending_requests.remove(key);
            }
            ctx.tracker.emit(&root, ev, registry, broadcaster);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_command_execution_request() {
        let mut state = CodexState::default();
        state.register_thread("th-1", "th-1");

        let req_id = json!(42);
        let params = json!({
            "threadId": "th-1",
            "command": "rm -rf /tmp/test",
            "kind": "command"
        });
        let res = translate_request(
            req_id,
            "item/commandExecution/requestApproval",
            &params,
            &state,
        );
        let (root, ev, pending) = res.expect("translated request");
        assert_eq!(root, "th-1");
        assert_eq!(pending, PendingCodexRequest::Approval { options_len: 3 });
        match ev {
            ObservedEvent::Attention {
                key,
                kind,
                prompt,
                options,
                actionable,
            } => {
                assert_eq!(key, "obs:codex:th-1:42");
                assert_eq!(kind, AttentionKind::Approval);
                assert_eq!(prompt, "Run: rm -rf /tmp/test");
                assert_eq!(
                    options,
                    vec![
                        "Allow once".to_string(),
                        "Deny".to_string(),
                        "Allow for session".to_string()
                    ]
                );
                assert!(actionable);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_translate_request_user_input_single_question() {
        let mut state = CodexState::default();
        state.register_thread("th-1", "th-1");

        let req_id = json!("req-99");
        let params = json!({
            "threadId": "th-1",
            "questions": [{
                "id": "q1",
                "question": "Choose flavor",
                "options": [{ "label": "Vanilla" }, { "label": "Chocolate" }]
            }]
        });
        let res = translate_request(req_id, "item/tool/requestUserInput", &params, &state).unwrap();
        assert_eq!(
            res.2,
            PendingCodexRequest::Ask {
                qid: "q1".into(),
                options: vec!["Vanilla".into(), "Chocolate".into()]
            }
        );
        let ev = res.1;
        match ev {
            ObservedEvent::Attention {
                kind,
                prompt,
                options,
                actionable,
                ..
            } => {
                assert_eq!(prompt, "Choose flavor");
                assert_eq!(options, vec!["Vanilla", "Chocolate"]);
                assert_eq!(
                    kind,
                    AttentionKind::Ask {
                        multi: false,
                        initial: 0
                    }
                );
                assert!(actionable);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_translate_notifications_lifecycle() {
        let mut state = CodexState::default();
        state.register_thread("th-1", "th-1");

        let start_evs =
            translate_notification("turn/started", &json!({ "threadId": "th-1" }), &mut state);
        assert_eq!(start_evs.len(), 1);
        assert_eq!(start_evs[0].1, ObservedEvent::TurnStarted);

        let item_msg = translate_notification(
            "item/completed",
            &json!({
                "threadId": "th-1",
                "item": { "type": "agentMessage", "text": "Task finished successfully" }
            }),
            &mut state,
        );
        assert!(item_msg.is_empty());

        let complete_evs = translate_notification(
            "turn/completed",
            &json!({
                "threadId": "th-1",
                "turn": { "status": "completed" }
            }),
            &mut state,
        );
        assert_eq!(complete_evs.len(), 1);
        assert_eq!(
            complete_evs[0].1,
            ObservedEvent::TurnCompleted {
                summary: "Task finished successfully".into()
            }
        );
    }

    #[test]
    fn test_close_out_from_turn_variants() {
        let mut state = CodexState::default();
        state.active_turn.insert("r1".into(), true);
        let completed = json!({
            "status": "completed",
            "items": [
                { "type": "userMessage", "content": [] },
                { "type": "agentMessage", "text": "Final answer" }
            ]
        });
        assert_eq!(
            close_out_from_turn(&completed, &mut state, "r1"),
            Some(ObservedEvent::TurnCompleted {
                summary: "Final answer".into()
            })
        );
        assert_eq!(state.active_turn.get("r1"), Some(&false));

        state.active_turn.insert("r1".into(), true);
        let failed = json!({
            "status": "failed",
            "error": { "message": "network error" }
        });
        assert_eq!(
            close_out_from_turn(&failed, &mut state, "r1"),
            Some(ObservedEvent::TurnFailed {
                error: "network error".into()
            })
        );
        assert_eq!(state.active_turn.get("r1"), Some(&false));

        state.active_turn.insert("r1".into(), true);
        let interrupted = json!({ "status": "interrupted" });
        assert_eq!(
            close_out_from_turn(&interrupted, &mut state, "r1"),
            Some(ObservedEvent::TurnInterrupted)
        );
        assert_eq!(state.active_turn.get("r1"), Some(&false));
    }

    #[test]
    fn test_build_initialize_request_toggles_human_approval() {
        let with_flag = build_initialize_request(1, true);
        assert_eq!(
            with_flag["params"]["capabilities"]["requiredHumanApproval"],
            json!(true)
        );
        let without_flag = build_initialize_request(2, false);
        assert!(without_flag["params"]["capabilities"]
            .get("requiredHumanApproval")
            .is_none());
    }
}
