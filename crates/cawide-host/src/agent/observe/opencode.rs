use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cawide_protocol::types::AgentChoice;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch};

use super::opencode_db::OpenCodeDbPoller;
use super::{
    uses_private_server, verified_id, Candidate, ObservedEvent, ObserverCommand, RootTracker,
    OBSERVER_KEY_PREFIX,
};
use crate::agent::map::AttentionKind;
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::registry::SessionRegistry;

const SSE_SILENCE_TIMEOUT: Duration = Duration::from_secs(45);
const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
const TRANSPORT_DOWN_THRESHOLD: Duration = Duration::from_secs(10);
const PREPARE_EXPIRY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceInfo {
    pub id: String,
    pub version: String,
    pub url: String,
    pub pid: u64,
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum FormReplySpec {
    Options {
        field_key: String,
        values: Vec<Value>,
        allow_custom: bool,
    },
    Text {
        field_key: String,
    },
    Unsupported,
}

#[derive(Debug, Default)]
pub struct OcState {
    pub parent_by_sid: HashMap<String, Option<String>>,
    pub tool_names: HashMap<String, String>,
    pub active_turn: HashMap<String, bool>,
    pub last_text: HashMap<String, String>,
    pub form_specs: HashMap<String, FormReplySpec>,
}

impl OcState {
    pub fn cache_parent(&mut self, sid: &str, parent_id: Option<&str>) {
        let parent = parent_id.filter(|s| !s.is_empty()).map(str::to_string);
        self.parent_by_sid.insert(sid.to_string(), parent);
    }

    pub fn resolve_root(&self, sid: &str) -> String {
        let mut cur = sid;
        let mut seen = 0usize;
        while let Some(Some(parent)) = self.parent_by_sid.get(cur) {
            if parent == cur || seen >= 16 {
                break;
            }
            cur = parent.as_str();
            seen += 1;
        }
        cur.to_string()
    }

    pub fn children_of(&self, root_id: &str) -> Vec<String> {
        self.parent_by_sid
            .keys()
            .filter(|sid| sid.as_str() != root_id && self.resolve_root(sid) == root_id)
            .cloned()
            .collect()
    }
}

pub fn make_perm_key(sid: &str, req_id: &str) -> String {
    format!("{OBSERVER_KEY_PREFIX}opencode:perm:{sid}:{req_id}")
}

pub fn make_form_key(sid: &str, form_id: &str) -> String {
    format!("{OBSERVER_KEY_PREFIX}opencode:form:{sid}:{form_id}")
}

fn translate_permission_asked(data: &Value, state: &OcState) -> Option<(String, ObservedEvent)> {
    let sid = data.get("sessionID").and_then(|v| v.as_str())?;
    let id = data.get("id").and_then(|v| v.as_str())?;
    let root = state.resolve_root(sid);
    let key = make_perm_key(sid, id);

    let message = data
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let action = data
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("permission");
    let prompt = if let Some(msg) = message {
        msg.to_string()
    } else {
        let resources: Vec<&str> = data
            .get("resources")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|r| r.as_str()).collect())
            .unwrap_or_default();
        if resources.is_empty() {
            action.to_string()
        } else {
            format!("{action}: {}", resources.join(", "))
        }
    };

    Some((
        root,
        ObservedEvent::Attention {
            key,
            kind: AttentionKind::Approval,
            prompt,
            options: vec!["Allow once".into(), "Deny".into(), "Always allow".into()],
            actionable: true,
        },
    ))
}

fn translate_form_object(form: &Value, state: &mut OcState) -> Option<(String, ObservedEvent)> {
    let sid = form.get("sessionID").and_then(|v| v.as_str())?;
    let form_id = form.get("id").and_then(|v| v.as_str())?;
    let root = state.resolve_root(sid);
    let key = make_form_key(sid, form_id);
    let form_title = form
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Input required");

    let visible_fields: Vec<&Value> = form
        .get("fields")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| !f.get("hidden").and_then(|v| v.as_bool()).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();

    if visible_fields.len() == 1 {
        let field = visible_fields[0];
        let field_type = field.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let field_key = field
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let prompt = field
            .get("title")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(form_title)
            .to_string();

        match field_type {
            "string" => {
                let opts = field
                    .get("options")
                    .and_then(|v| v.as_array())
                    .filter(|a| !a.is_empty());
                if let Some(opts) = opts {
                    let mut labels = Vec::new();
                    let mut values = Vec::new();
                    for opt in opts.iter().take(8) {
                        let label = opt
                            .get("label")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let val = opt
                            .get("value")
                            .cloned()
                            .unwrap_or_else(|| Value::String(label.clone()));
                        labels.push(label);
                        values.push(val);
                    }
                    let allow_custom = field
                        .get("custom")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    state.form_specs.insert(
                        key.clone(),
                        FormReplySpec::Options {
                            field_key,
                            values,
                            allow_custom,
                        },
                    );
                    return Some((
                        root,
                        ObservedEvent::Attention {
                            key,
                            kind: AttentionKind::Ask {
                                multi: false,
                                initial: 0,
                            },
                            prompt,
                            options: labels,
                            actionable: true,
                        },
                    ));
                }
                state
                    .form_specs
                    .insert(key.clone(), FormReplySpec::Text { field_key });
                return Some((
                    root,
                    ObservedEvent::Attention {
                        key,
                        kind: AttentionKind::TextQuestion,
                        prompt,
                        options: Vec::new(),
                        actionable: true,
                    },
                ));
            }
            "boolean" => {
                state.form_specs.insert(
                    key.clone(),
                    FormReplySpec::Options {
                        field_key,
                        values: vec![Value::Bool(true), Value::Bool(false)],
                        allow_custom: false,
                    },
                );
                return Some((
                    root,
                    ObservedEvent::Attention {
                        key,
                        kind: AttentionKind::Ask {
                            multi: false,
                            initial: 0,
                        },
                        prompt,
                        options: vec!["Yes".into(), "No".into()],
                        actionable: true,
                    },
                ));
            }
            _ => {}
        }
    }

    state
        .form_specs
        .insert(key.clone(), FormReplySpec::Unsupported);
    Some((
        root,
        ObservedEvent::Attention {
            key,
            kind: AttentionKind::TextQuestion,
            prompt: form_title.to_string(),
            options: Vec::new(),
            actionable: false,
        },
    ))
}

pub fn translate_event(val: &Value, state: &mut OcState) -> Vec<(String, ObservedEvent)> {
    let mut out = Vec::new();
    let Some(ev_type) = val.get("type").and_then(|v| v.as_str()) else {
        return out;
    };
    let data = val.get("data").unwrap_or(&Value::Null);

    match ev_type {
        "session.created" => {
            let info = data.get("info");
            let sid = data
                .get("sessionID")
                .or_else(|| info.and_then(|i| i.get("id")))
                .and_then(|v| v.as_str());
            let parent_id = data
                .get("parentID")
                .or_else(|| info.and_then(|i| i.get("parentID")))
                .and_then(|v| v.as_str());
            if let Some(sid) = sid {
                state.cache_parent(sid, parent_id);
            }
        }
        "session.execution.started" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    state.active_turn.insert(root.clone(), true);
                    state.last_text.entry(root.clone()).or_default().clear();
                    out.push((root, ObservedEvent::TurnStarted));
                }
            }
        }
        "session.inbox.enqueued" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    if let Some(item) = data.get("item") {
                        if item.get("type").and_then(|v| v.as_str()) == Some("user") {
                            if let Some(text) = item
                                .get("payload")
                                .and_then(|p| p.get("text"))
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                            {
                                out.push((
                                    root,
                                    ObservedEvent::Activity {
                                        desc: text.to_string(),
                                    },
                                ));
                            }
                        }
                    }
                }
            }
        }
        "session.tool.input.started" => {
            if let (Some(id), Some(name)) = (
                data.get("id").and_then(|v| v.as_str()),
                data.get("name").and_then(|v| v.as_str()),
            ) {
                state.tool_names.insert(id.to_string(), name.to_string());
            }
        }
        "session.tool.called" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let name = state
                        .tool_names
                        .get(id)
                        .map(String::as_str)
                        .or_else(|| data.get("name").and_then(|v| v.as_str()))
                        .unwrap_or("tool");
                    let input = data.get("input");
                    let target = input.and_then(|inp| {
                        ["command", "filePath", "path", "pattern", "url"]
                            .iter()
                            .find_map(|k| {
                                inp.get(*k)
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                            })
                    });
                    let desc = match target {
                        Some(t) => format!("{name}: {t}"),
                        None => name.to_string(),
                    };
                    out.push((root, ObservedEvent::Activity { desc }));
                }
            }
        }
        "session.retry.scheduled" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                let attempt = data.get("attempt").and_then(|v| v.as_u64()).unwrap_or(1);
                let msg = data
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("error");
                out.push((
                    root,
                    ObservedEvent::Activity {
                        desc: format!("Retrying (attempt {attempt}): {msg}"),
                    },
                ));
            }
        }
        "session.compaction.started" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                out.push((
                    root,
                    ObservedEvent::Activity {
                        desc: "Compacting context…".into(),
                    },
                ));
            }
        }
        "session.text.ended" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    if let Some(text) = data.get("text").and_then(|v| v.as_str()) {
                        state.last_text.insert(root, text.to_string());
                    }
                }
            }
        }
        "session.execution.succeeded" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    state.active_turn.insert(root.clone(), false);
                    let summary = state.last_text.get(&root).cloned().unwrap_or_default();
                    out.push((root, ObservedEvent::TurnCompleted { summary }));
                }
            }
        }
        "session.execution.failed" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    state.active_turn.insert(root.clone(), false);
                    let error = data
                        .get("error")
                        .and_then(|e| e.get("message"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("OpenCode run failed")
                        .to_string();
                    out.push((root, ObservedEvent::TurnFailed { error }));
                }
            }
        }
        "session.execution.interrupted" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    state.active_turn.insert(root.clone(), false);
                    out.push((root, ObservedEvent::TurnInterrupted));
                }
            }
        }
        "permission.asked" => {
            if let Some(item) = translate_permission_asked(data, state) {
                out.push(item);
            }
        }
        "form.created" => {
            if let Some(form) = data.get("form") {
                if let Some(item) = translate_form_object(form, state) {
                    out.push(item);
                }
            }
        }
        "permission.replied" => {
            if let (Some(sid), Some(req_id)) = (
                data.get("sessionID").and_then(|v| v.as_str()),
                data.get("requestID").and_then(|v| v.as_str()),
            ) {
                let root = state.resolve_root(sid);
                let key = make_perm_key(sid, req_id);
                out.push((root, ObservedEvent::AttentionResolved { key }));
            }
        }
        "form.replied" | "form.cancelled" => {
            if let (Some(sid), Some(form_id)) = (
                data.get("sessionID").and_then(|v| v.as_str()),
                data.get("id").and_then(|v| v.as_str()),
            ) {
                let root = state.resolve_root(sid);
                let key = make_form_key(sid, form_id);
                state.form_specs.remove(&key);
                out.push((root, ObservedEvent::AttentionResolved { key }));
            }
        }
        "session.deleted" => {
            if let Some(sid) = data.get("sessionID").and_then(|v| v.as_str()) {
                let root = state.resolve_root(sid);
                if sid == root {
                    state.active_turn.remove(&root);
                    out.push((root, ObservedEvent::Detached));
                }
            }
        }
        _ => {}
    }

    out
}

pub fn build_permission_reply_payload(choice: &AgentChoice) -> Result<Value, String> {
    match choice {
        AgentChoice::Option { index } => match *index {
            0 => Ok(json!({ "decision": "once" })),
            1 => Ok(json!({ "decision": "reject" })),
            2 => Ok(json!({ "decision": "always" })),
            _ => Err("unsupported choice".into()),
        },
        AgentChoice::Text { text } => {
            let sanitized = crate::agent::respond::sanitize_reply_text(text)?;
            Ok(json!({ "decision": "reject", "message": sanitized }))
        }
    }
}

pub fn build_form_reply_payload(
    choice: &AgentChoice,
    spec: &FormReplySpec,
) -> Result<Value, String> {
    match spec {
        FormReplySpec::Options {
            field_key,
            values,
            allow_custom,
        } => match choice {
            AgentChoice::Option { index } => {
                let val = values
                    .get(*index as usize)
                    .ok_or_else(|| "unsupported choice".to_string())?;
                Ok(json!({ "answer": { field_key: val } }))
            }
            AgentChoice::Text { text } => {
                if !*allow_custom {
                    return Err("unsupported choice".into());
                }
                let sanitized = crate::agent::respond::sanitize_reply_text(text)?;
                Ok(json!({ "answer": { field_key: sanitized } }))
            }
        },
        FormReplySpec::Text { field_key } => match choice {
            AgentChoice::Option { .. } => Err("unsupported choice".into()),
            AgentChoice::Text { text } => {
                let sanitized = crate::agent::respond::sanitize_reply_text(text)?;
                Ok(json!({ "answer": { field_key: sanitized } }))
            }
        },
        FormReplySpec::Unsupported => Err("unsupported choice".into()),
    }
}

enum ReplyTarget<'a> {
    Permission { sid: &'a str, rid: &'a str },
    Form { sid: &'a str, fid: &'a str },
}

fn parse_opencode_key(key: &str) -> Option<ReplyTarget<'_>> {
    let rest = key.strip_prefix("obs:opencode:")?;
    if let Some(perm_rest) = rest.strip_prefix("perm:") {
        let (sid, rid) = perm_rest.split_once(':')?;
        if !sid.is_empty() && !rid.is_empty() {
            return Some(ReplyTarget::Permission { sid, rid });
        }
    } else if let Some(form_rest) = rest.strip_prefix("form:") {
        let (sid, fid) = form_rest.split_once(':')?;
        if !sid.is_empty() && !fid.is_empty() {
            return Some(ReplyTarget::Form { sid, fid });
        }
    }
    None
}

fn read_service_json(opencode_state: &Path) -> Option<ServiceInfo> {
    let path = opencode_state.join("service.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let info: ServiceInfo = serde_json::from_str(&raw).ok()?;
    if info.url.is_empty() {
        return None;
    }
    Some(info)
}

async fn check_service_liveness(client: &Client, info: &ServiceInfo) -> bool {
    let url = format!("{}/api/info", info.url.trim_end_matches('/'));
    let Ok(resp) = client
        .get(&url)
        .basic_auth("opencode", Some(&info.password))
        .timeout(Duration::from_secs(3))
        .send()
        .await
    else {
        return false;
    };
    if resp.status() != StatusCode::OK {
        return false;
    }
    let Ok(val) = resp.json::<Value>().await else {
        return false;
    };
    val.get("pid").and_then(|v| v.as_u64()) == Some(info.pid)
}

async fn connect_sse(
    client: &Client,
    opencode_state: &Path,
) -> Option<(ServiceInfo, reqwest::Response)> {
    let mut info = read_service_json(opencode_state)?;
    if !check_service_liveness(client, &info).await {
        return None;
    }
    let url = format!("{}/api/event", info.url.trim_end_matches('/'));
    let mut resp = client
        .get(&url)
        .basic_auth("opencode", Some(&info.password))
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .ok()?;
    if resp.status() == StatusCode::UNAUTHORIZED {
        info = read_service_json(opencode_state)?;
        let retry_url = format!("{}/api/event", info.url.trim_end_matches('/'));
        resp = client
            .get(&retry_url)
            .basic_auth("opencode", Some(&info.password))
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await
            .ok()?;
    }
    if resp.status() != StatusCode::OK {
        return None;
    }
    Some((info, resp))
}

struct SseParser {
    line_buf: Vec<u8>,
    data_lines: Vec<String>,
}

impl SseParser {
    fn new() -> Self {
        Self {
            line_buf: Vec::new(),
            data_lines: Vec::new(),
        }
    }

    fn push_chunk(&mut self, chunk: &[u8]) -> Vec<Value> {
        let mut events = Vec::new();
        for &b in chunk {
            if b == b'\n' {
                let line = String::from_utf8_lossy(&self.line_buf)
                    .trim_end_matches('\r')
                    .to_string();
                self.line_buf.clear();
                if line.is_empty() {
                    if !self.data_lines.is_empty() {
                        let joined = self.data_lines.join("\n");
                        self.data_lines.clear();
                        if let Ok(val) = serde_json::from_str::<Value>(&joined) {
                            events.push(val);
                        }
                    }
                } else if line.starts_with(':') {
                    // Heartbeat / comment line
                } else if let Some(rest) = line.strip_prefix("data:") {
                    let payload = rest.strip_prefix(' ').unwrap_or(rest);
                    self.data_lines.push(payload.to_string());
                }
            } else {
                self.line_buf.push(b);
            }
        }
        events
    }
}

pub fn spawn_opencode_adapter(
    registry: Arc<SessionRegistry>,
    broadcaster: Arc<HostEventBroadcaster>,
    opencode_state: PathBuf,
    opencode_data: PathBuf,
    candidates_rx: watch::Receiver<Vec<Candidate>>,
    commands_rx: mpsc::Receiver<ObserverCommand>,
    has_prepared: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_opencode_adapter(
        registry,
        broadcaster,
        opencode_state,
        opencode_data,
        candidates_rx,
        commands_rx,
        has_prepared,
    ))
}

struct OcAdapterCtx {
    state: OcState,
    tracker: RootTracker,
    verified_roots: HashSet<String>,
    db_only_roots: HashSet<String>,
    prepared_map: HashMap<String, Instant>,
    synced_roots: HashSet<String>,
}

impl OcAdapterCtx {
    fn new() -> Self {
        Self {
            state: OcState::default(),
            tracker: RootTracker::new("opencode"),
            verified_roots: HashSet::new(),
            db_only_roots: HashSet::new(),
            prepared_map: HashMap::new(),
            synced_roots: HashSet::new(),
        }
    }

    fn wanted_service_roots(&self) -> HashSet<String> {
        let mut wanted: HashSet<String> = self
            .verified_roots
            .iter()
            .filter(|r| !self.db_only_roots.contains(*r))
            .cloned()
            .collect();
        for id in self.prepared_map.keys() {
            wanted.insert(id.clone());
        }
        wanted
    }

    fn update_candidates(&mut self, candidates: &[Candidate]) {
        let mut by_root: HashMap<String, Vec<&Candidate>> = HashMap::new();
        for c in candidates {
            if let Some(root_id) = verified_id("opencode", &c.argv) {
                by_root.entry(root_id).or_default().push(c);
            }
        }
        self.verified_roots = by_root.keys().cloned().collect();
        self.db_only_roots = by_root
            .into_iter()
            .filter_map(|(root_id, cands)| {
                cands
                    .iter()
                    .all(|c| uses_private_server("opencode", &c.argv))
                    .then_some(root_id)
            })
            .collect();
    }
}

async fn fetch_json_with_auth_retry(
    client: &Client,
    opencode_state: &Path,
    service: &mut Option<ServiceInfo>,
    path: &str,
) -> Option<Value> {
    let info = service.as_ref()?.clone();
    let url = format!("{}{path}", info.url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .basic_auth("opencode", Some(&info.password))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if resp.status() == StatusCode::UNAUTHORIZED {
        let refreshed = read_service_json(opencode_state)?;
        *service = Some(refreshed.clone());
        let retry_url = format!("{}{path}", refreshed.url.trim_end_matches('/'));
        let retry_resp = client
            .get(&retry_url)
            .basic_auth("opencode", Some(&refreshed.password))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if retry_resp.status() != StatusCode::OK {
            return None;
        }
        return retry_resp.json::<Value>().await.ok();
    }
    if resp.status() != StatusCode::OK {
        return None;
    }
    resp.json::<Value>().await.ok()
}

struct OcHttp<'a> {
    client: &'a Client,
    opencode_state: &'a Path,
    service: &'a mut Option<ServiceInfo>,
}

async fn sync_root_snapshot(
    http: &mut OcHttp<'_>,
    root_id: &str,
    active_map: Option<&serde_json::Map<String, Value>>,
    ctx: &mut OcAdapterCtx,
    registry: &SessionRegistry,
    broadcaster: &HostEventBroadcaster,
) {
    let session_path = format!("/api/session/{root_id}");
    let session_val = fetch_json_with_auth_retry(
        http.client,
        http.opencode_state,
        http.service,
        &session_path,
    )
    .await;
    let session_data = session_val.as_ref().and_then(|v| v.get("data"));
    if let Some(data) = session_data {
        let parent_id = data.get("parentID").and_then(|v| v.as_str());
        ctx.state.cache_parent(root_id, parent_id);
    }

    let is_active = active_map.is_some_and(|m| m.contains_key(root_id));
    let was_active = ctx.state.active_turn.get(root_id).copied().unwrap_or(false);
    ctx.state.active_turn.insert(root_id.to_string(), is_active);

    if is_active {
        ctx.tracker
            .emit(root_id, ObservedEvent::TurnStarted, registry, broadcaster);
    } else if was_active {
        let outcome = session_data
            .and_then(|d| d.get("outcome"))
            .and_then(|v| v.as_str());
        let ev = match outcome {
            Some("succeeded") => ObservedEvent::TurnCompleted {
                summary: ctx
                    .state
                    .last_text
                    .get(root_id)
                    .cloned()
                    .unwrap_or_default(),
            },
            Some("failed") => ObservedEvent::TurnFailed {
                error: "OpenCode run failed".into(),
            },
            Some("interrupted") => ObservedEvent::TurnInterrupted,
            _ => ObservedEvent::TurnCompleted {
                summary: ctx
                    .state
                    .last_text
                    .get(root_id)
                    .cloned()
                    .unwrap_or_default(),
            },
        };
        ctx.tracker.emit(root_id, ev, registry, broadcaster);
    }

    let mut sids_to_check = vec![root_id.to_string()];
    sids_to_check.extend(ctx.state.children_of(root_id));

    for sid in sids_to_check {
        let perm_path = format!("/api/session/{sid}/permission");
        if let Some(val) =
            fetch_json_with_auth_retry(http.client, http.opencode_state, http.service, &perm_path)
                .await
        {
            if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some((r, ev)) = translate_permission_asked(item, &ctx.state) {
                        ctx.tracker.emit(&r, ev, registry, broadcaster);
                    }
                }
            }
        }

        let form_path = format!("/api/session/{sid}/form");
        if let Some(val) =
            fetch_json_with_auth_retry(http.client, http.opencode_state, http.service, &form_path)
                .await
        {
            if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some((r, ev)) = translate_form_object(item, &mut ctx.state) {
                        ctx.tracker.emit(&r, ev, registry, broadcaster);
                    }
                }
            }
        }
    }
}

async fn sync_all_wanted_roots(
    client: &Client,
    opencode_state: &Path,
    service: &mut Option<ServiceInfo>,
    ctx: &mut OcAdapterCtx,
    registry: &SessionRegistry,
    broadcaster: &HostEventBroadcaster,
) {
    let active_val =
        fetch_json_with_auth_retry(client, opencode_state, service, "/api/session/active").await;
    let active_map = active_val
        .as_ref()
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object());

    let wanted: Vec<String> = ctx.wanted_service_roots().into_iter().collect();
    let mut http = OcHttp {
        client,
        opencode_state,
        service,
    };
    for root_id in wanted {
        sync_root_snapshot(&mut http, &root_id, active_map, ctx, registry, broadcaster).await;
        ctx.synced_roots.insert(root_id);
    }
}

async fn post_prepare_session(
    client: &Client,
    opencode_state: &Path,
    service: &mut Option<ServiceInfo>,
    cwd: &Path,
) -> Result<String, String> {
    let Some(info) = service.clone() else {
        return Err("agent server unavailable".into());
    };
    let body = json!({ "location": { "directory": cwd.display().to_string() } });
    let url = format!("{}/api/session", info.url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .basic_auth("opencode", Some(&info.password))
        .json(&body)
        .timeout(Duration::from_secs(4))
        .send()
        .await
        .map_err(|_| "agent server unavailable".to_string())?;

    let resp = if resp.status() == StatusCode::UNAUTHORIZED {
        let refreshed = read_service_json(opencode_state)
            .ok_or_else(|| "agent server unavailable".to_string())?;
        *service = Some(refreshed.clone());
        let retry_url = format!("{}/api/session", refreshed.url.trim_end_matches('/'));
        client
            .post(&retry_url)
            .basic_auth("opencode", Some(&refreshed.password))
            .json(&body)
            .timeout(Duration::from_secs(4))
            .send()
            .await
            .map_err(|_| "agent server unavailable".to_string())?
    } else {
        resp
    };

    if !resp.status().is_success() {
        return Err(format!("agent error {}", resp.status().as_u16()));
    }
    let val: Value = resp
        .json()
        .await
        .map_err(|_| "invalid session response".to_string())?;
    val.get("data")
        .and_then(|d| d.get("id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "invalid session response".to_string())
}

async fn post_reply_with_retry(
    client: &Client,
    opencode_state: &Path,
    service: Option<ServiceInfo>,
    path: &str,
    payload: &Value,
) -> (Result<(), String>, Option<ServiceInfo>) {
    let Some(info) = service else {
        return (Err("agent connection unavailable".into()), None);
    };
    let url = format!("{}{path}", info.url.trim_end_matches('/'));
    let resp = match client
        .post(&url)
        .basic_auth("opencode", Some(&info.password))
        .json(payload)
        .timeout(Duration::from_secs(8))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return (Err("agent connection unavailable".to_string()), None),
    };

    let mut refreshed_info = None;
    let resp = if resp.status() == StatusCode::UNAUTHORIZED {
        let Some(refreshed) = read_service_json(opencode_state) else {
            return (Err("agent connection unavailable".into()), None);
        };
        let retry_url = format!("{}{path}", refreshed.url.trim_end_matches('/'));
        let retry_resp = match client
            .post(&retry_url)
            .basic_auth("opencode", Some(&refreshed.password))
            .json(payload)
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => {
                return (
                    Err("agent connection unavailable".to_string()),
                    Some(refreshed),
                )
            }
        };
        refreshed_info = Some(refreshed);
        retry_resp
    } else {
        resp
    };

    let res = match resp.status() {
        StatusCode::OK | StatusCode::NO_CONTENT => Ok(()),
        StatusCode::BAD_REQUEST => Err("unsupported choice".into()),
        StatusCode::UNAUTHORIZED => Err("agent connection unavailable".into()),
        StatusCode::NOT_FOUND | StatusCode::CONFLICT => Err("prompt no longer open".into()),
        other => Err(format!("agent error {}", other.as_u16())),
    };
    (res, refreshed_info)
}

struct RespondDone {
    key: String,
    root_id: String,
    result: Result<(), String>,
    refreshed_service: Option<ServiceInfo>,
    reply: oneshot::Sender<Result<(), String>>,
}

async fn run_opencode_adapter(
    registry: Arc<SessionRegistry>,
    broadcaster: Arc<HostEventBroadcaster>,
    opencode_state: PathBuf,
    opencode_data: PathBuf,
    mut candidates_rx: watch::Receiver<Vec<Candidate>>,
    mut commands_rx: mpsc::Receiver<ObserverCommand>,
    has_prepared: Arc<AtomicBool>,
) {
    let client = Client::builder()
        .no_proxy()
        .build()
        .unwrap_or_else(|_| Client::new());
    let mut ctx = OcAdapterCtx::new();
    let opencode_data_backup = opencode_data.clone();
    let mut db_poller = OpenCodeDbPoller::new(opencode_data);
    let mut service: Option<ServiceInfo> = None;
    let mut sse_resp: Option<reqwest::Response> = None;
    let mut sse_parser = SseParser::new();
    let mut last_sse_activity = Instant::now();
    let mut next_connect_attempt = Instant::now();
    let mut disconnect_timer: Option<Instant> = None;
    let mut transport_reemitted = false;
    let mut queued_prepares: Vec<(PathBuf, oneshot::Sender<Result<String, String>>)> = Vec::new();
    let (respond_done_tx, mut respond_done_rx) = mpsc::channel::<RespondDone>(16);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let candidates = candidates_rx.borrow().clone();
                ctx.update_candidates(&candidates);
                ctx.tracker.reconcile_candidates(&candidates, &registry, &broadcaster);

                let now = Instant::now();
                ctx.prepared_map
                    .retain(|_, t| now.duration_since(*t) <= PREPARE_EXPIRY);
                has_prepared.store(!ctx.prepared_map.is_empty(), Ordering::Release);

                if let Some(resp) = &sse_resp {
                    let _ = resp;
                    if now.duration_since(last_sse_activity) >= SSE_SILENCE_TIMEOUT {
                        sse_resp = None;
                        service = None;
                        ctx.synced_roots.clear();
                        disconnect_timer = Some(now);
                        next_connect_attempt = now + RECONNECT_BACKOFF;
                    }
                }

                if sse_resp.is_none() && now >= next_connect_attempt {
                    if let Some((info, resp)) = connect_sse(&client, &opencode_state).await {
                        service = Some(info);
                        sse_resp = Some(resp);
                        sse_parser = SseParser::new();
                        last_sse_activity = Instant::now();
                        disconnect_timer = None;
                        transport_reemitted = false;
                        ctx.synced_roots.clear();

                        for (cwd, reply) in queued_prepares.drain(..) {
                            match post_prepare_session(&client, &opencode_state, &mut service, &cwd).await {
                                Ok(id) => {
                                    ctx.prepared_map.insert(id.clone(), Instant::now());
                                    has_prepared.store(true, Ordering::Release);
                                    let _ = reply.send(Ok(id));
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        }
                    } else {
                        next_connect_attempt = now + RECONNECT_BACKOFF;
                        if let Some(down_since) = disconnect_timer {
                            if !transport_reemitted && now.duration_since(down_since) >= TRANSPORT_DOWN_THRESHOLD {
                                ctx.tracker.emit_transport_down(&registry, &broadcaster);
                                transport_reemitted = true;
                            }
                        } else {
                            disconnect_timer = Some(now);
                        }
                    }
                }

                if sse_resp.is_some() {
                    let wanted = ctx.wanted_service_roots();
                    ctx.synced_roots.retain(|r| wanted.contains(r));
                    let unsynced: Vec<String> = wanted
                        .iter()
                        .filter(|r| !ctx.synced_roots.contains(*r))
                        .cloned()
                        .collect();
                    if !unsynced.is_empty() {
                        let active_val = fetch_json_with_auth_retry(
                            &client,
                            &opencode_state,
                            &mut service,
                            "/api/session/active",
                        )
                        .await;
                        let active_map = active_val
                            .as_ref()
                            .and_then(|v| v.get("data"))
                            .and_then(|v| v.as_object());
                        let mut http = OcHttp {
                            client: &client,
                            opencode_state: &opencode_state,
                            service: &mut service,
                        };
                        for root_id in unsynced {
                            sync_root_snapshot(
                                &mut http,
                                &root_id,
                                active_map,
                                &mut ctx,
                                &registry,
                                &broadcaster,
                            )
                            .await;
                            ctx.synced_roots.insert(root_id);
                        }
                    }
                }

                // DB polling for db-only roots, and service-source roots while service is unreachable.
                let service_connected = sse_resp.is_some();
                let db_roots: Vec<String> = ctx
                    .verified_roots
                    .iter()
                    .filter(|r| ctx.db_only_roots.contains(*r) || !service_connected)
                    .cloned()
                    .collect();
                db_poller.retain_roots(&db_roots);
                if !db_roots.is_empty() {
                    let backup_data = opencode_data_backup.clone();
                    let (polled_events, returned_poller) = tokio::task::spawn_blocking(move || {
                        let events = db_poller.poll_roots(&db_roots);
                        (events, db_poller)
                    })
                    .await
                    .unwrap_or_else(|_| (Vec::new(), OpenCodeDbPoller::new(backup_data)));
                    db_poller = returned_poller;
                    for (root_id, ev) in polled_events {
                        match &ev {
                            ObservedEvent::TurnStarted => {
                                ctx.state.active_turn.insert(root_id.clone(), true);
                            }
                            ObservedEvent::TurnCompleted { .. }
                            | ObservedEvent::TurnFailed { .. }
                            | ObservedEvent::TurnInterrupted => {
                                ctx.state.active_turn.insert(root_id.clone(), false);
                            }
                            _ => {}
                        }
                        ctx.tracker.emit(&root_id, ev, &registry, &broadcaster);
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
            chunk_res = async {
                match sse_resp.as_mut() {
                    Some(resp) => resp.chunk().await,
                    None => std::future::pending().await,
                }
            } => {
                match chunk_res {
                    Ok(Some(bytes)) => {
                        last_sse_activity = Instant::now();
                        for val in sse_parser.push_chunk(&bytes) {
                            if val.get("type").and_then(|v| v.as_str()) == Some("server.connected") {
                                sync_all_wanted_roots(
                                    &client,
                                    &opencode_state,
                                    &mut service,
                                    &mut ctx,
                                    &registry,
                                    &broadcaster,
                                )
                                .await;
                                continue;
                            }
                            let wanted = ctx.wanted_service_roots();
                            for (root, ev) in translate_event(&val, &mut ctx.state) {
                                if wanted.contains(&root) {
                                    ctx.tracker.emit(&root, ev, &registry, &broadcaster);
                                }
                            }
                        }
                    }
                    Ok(None) | Err(_) => {
                        sse_resp = None;
                        service = None;
                        ctx.synced_roots.clear();
                        let now = Instant::now();
                        disconnect_timer = Some(now);
                        next_connect_attempt = now + RECONNECT_BACKOFF;
                    }
                }
            }
            cmd = commands_rx.recv() => {
                let Some(cmd) = cmd else {
                    break;
                };
                match cmd {
                    ObserverCommand::Respond { key, choice, reply } => {
                        if sse_resp.is_none() || service.is_none() {
                            let _ = reply.send(Err("agent connection unavailable".into()));
                            continue;
                        }
                        let Some(target) = parse_opencode_key(&key) else {
                            let _ = reply.send(Err("unsupported choice".into()));
                            continue;
                        };
                        let (path, payload, root_id) = match target {
                            ReplyTarget::Permission { sid, rid } => {
                                match build_permission_reply_payload(&choice) {
                                    Ok(p) => (
                                        format!("/api/session/{sid}/permission/{rid}/reply"),
                                        p,
                                        ctx.state.resolve_root(sid),
                                    ),
                                    Err(e) => {
                                        let _ = reply.send(Err(e));
                                        continue;
                                    }
                                }
                            }
                            ReplyTarget::Form { sid, fid } => {
                                let Some(spec) = ctx.state.form_specs.get(&key) else {
                                    let _ = reply.send(Err("prompt no longer open".into()));
                                    continue;
                                };
                                match build_form_reply_payload(&choice, spec) {
                                    Ok(p) => (
                                        format!("/api/session/{sid}/form/{fid}/reply"),
                                        p,
                                        ctx.state.resolve_root(sid),
                                    ),
                                    Err(e) => {
                                        let _ = reply.send(Err(e));
                                        continue;
                                    }
                                }
                            }
                        };
                        let done_tx = respond_done_tx.clone();
                        let client_clone = client.clone();
                        let state_clone = opencode_state.clone();
                        let service_clone = service.clone();
                        tokio::spawn(async move {
                            let (res, refreshed) = post_reply_with_retry(
                                &client_clone,
                                &state_clone,
                                service_clone,
                                &path,
                                &payload,
                            )
                            .await;
                            let _ = done_tx
                                .send(RespondDone {
                                    key,
                                    root_id,
                                    result: res,
                                    refreshed_service: refreshed,
                                    reply,
                                })
                                .await;
                        });
                    }
                    ObserverCommand::Prepare { agent: _, cwd, reply } => {
                        if sse_resp.is_some() && service.is_some() {
                            match post_prepare_session(&client, &opencode_state, &mut service, &cwd).await {
                                Ok(id) => {
                                    ctx.prepared_map.insert(id.clone(), Instant::now());
                                    has_prepared.store(true, Ordering::Release);
                                    let _ = reply.send(Ok(id));
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        } else {
                            queued_prepares.push((cwd, reply));
                        }
                    }
                }
            }
            Some(done) = respond_done_rx.recv() => {
                if let Some(refreshed) = done.refreshed_service {
                    service = Some(refreshed);
                }
                match done.result {
                    Ok(()) => {
                        ctx.state.form_specs.remove(&done.key);
                        ctx.tracker.emit(
                            &done.root_id,
                            ObservedEvent::AttentionResolved { key: done.key },
                            &registry,
                            &broadcaster,
                        );
                        let _ = done.reply.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = done.reply.send(Err(e));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_event_lifecycle_and_children() {
        let mut state = OcState::default();

        // Child session created with parentID -> resolves to root.
        assert!(translate_event(
            &json!({
                "type": "session.created",
                "data": { "sessionID": "ses_child", "parentID": "ses_root" }
            }),
            &mut state
        )
        .is_empty());
        assert_eq!(state.resolve_root("ses_child"), "ses_root");

        // Execution started on root -> TurnStarted; on child -> ignored.
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.execution.started",
                    "data": { "sessionID": "ses_root" }
                }),
                &mut state
            ),
            vec![("ses_root".into(), ObservedEvent::TurnStarted)]
        );
        assert!(translate_event(
            &json!({
                "type": "session.execution.started",
                "data": { "sessionID": "ses_child" }
            }),
            &mut state
        )
        .is_empty());

        // User inbox enqueued.
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.inbox.enqueued",
                    "data": {
                        "sessionID": "ses_root",
                        "item": { "type": "user", "payload": { "text": "Run tests" } }
                    }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::Activity {
                    desc: "Run tests".into()
                }
            )]
        );

        // Tool input started + tool called.
        assert!(translate_event(
            &json!({
                "type": "session.tool.input.started",
                "data": { "sessionID": "ses_root", "id": "call_1", "name": "bash" }
            }),
            &mut state
        )
        .is_empty());
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.tool.called",
                    "data": {
                        "sessionID": "ses_root",
                        "id": "call_1",
                        "input": { "command": "cargo test" }
                    }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::Activity {
                    desc: "bash: cargo test".into()
                }
            )]
        );

        // Retry & compaction.
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.retry.scheduled",
                    "data": {
                        "sessionID": "ses_child",
                        "attempt": 2,
                        "error": { "message": "rate limit" }
                    }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::Activity {
                    desc: "Retrying (attempt 2): rate limit".into()
                }
            )]
        );
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.compaction.started",
                    "data": { "sessionID": "ses_root" }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::Activity {
                    desc: "Compacting context…".into()
                }
            )]
        );

        // Text ended + execution succeeded.
        assert!(translate_event(
            &json!({
                "type": "session.text.ended",
                "data": { "sessionID": "ses_root", "text": "All tests pass." }
            }),
            &mut state
        )
        .is_empty());
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.execution.succeeded",
                    "data": { "sessionID": "ses_root" }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::TurnCompleted {
                    summary: "All tests pass.".into()
                }
            )]
        );

        // Failed & interrupted & deleted.
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.execution.failed",
                    "data": { "sessionID": "ses_root", "error": { "message": "boom" } }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::TurnFailed {
                    error: "boom".into()
                }
            )]
        );
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.execution.interrupted",
                    "data": { "sessionID": "ses_root" }
                }),
                &mut state
            ),
            vec![("ses_root".into(), ObservedEvent::TurnInterrupted)]
        );
        assert_eq!(
            translate_event(
                &json!({
                    "type": "session.deleted",
                    "data": { "sessionID": "ses_root" }
                }),
                &mut state
            ),
            vec![("ses_root".into(), ObservedEvent::Detached)]
        );
    }

    #[test]
    fn test_translate_permissions_and_forms_and_replies() {
        let mut state = OcState::default();
        state.cache_parent("ses_child", Some("ses_root"));

        // Permission asked on child resolves to root, key uses child sid.
        let perm_evs = translate_event(
            &json!({
                "type": "permission.asked",
                "data": {
                    "id": "per_1",
                    "sessionID": "ses_child",
                    "action": "bash",
                    "resources": ["rm -rf /tmp/x"]
                }
            }),
            &mut state,
        );
        assert_eq!(
            perm_evs,
            vec![(
                "ses_root".into(),
                ObservedEvent::Attention {
                    key: "obs:opencode:perm:ses_child:per_1".into(),
                    kind: AttentionKind::Approval,
                    prompt: "bash: rm -rf /tmp/x".into(),
                    options: vec!["Allow once".into(), "Deny".into(), "Always allow".into()],
                    actionable: true,
                }
            )]
        );

        assert_eq!(
            build_permission_reply_payload(&AgentChoice::Option { index: 0 }).unwrap(),
            json!({ "decision": "once" })
        );
        assert_eq!(
            build_permission_reply_payload(&AgentChoice::Option { index: 1 }).unwrap(),
            json!({ "decision": "reject" })
        );
        assert_eq!(
            build_permission_reply_payload(&AgentChoice::Option { index: 2 }).unwrap(),
            json!({ "decision": "always" })
        );
        assert_eq!(
            build_permission_reply_payload(&AgentChoice::Text {
                text: "use ls instead".into()
            })
            .unwrap(),
            json!({ "decision": "reject", "message": "use ls instead" })
        );

        // Permission replied.
        assert_eq!(
            translate_event(
                &json!({
                    "type": "permission.replied",
                    "data": { "sessionID": "ses_child", "requestID": "per_1" }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::AttentionResolved {
                    key: "obs:opencode:perm:ses_child:per_1".into()
                }
            )]
        );

        // Form with 1 hidden + 1 string option field (custom: false).
        let form_evs = translate_event(
            &json!({
                "type": "form.created",
                "data": {
                    "form": {
                        "id": "frm_1",
                        "sessionID": "ses_root",
                        "title": "Pick mode",
                        "fields": [
                            { "key": "secret", "type": "string", "hidden": true },
                            {
                                "key": "mode",
                                "type": "string",
                                "title": "Which mode?",
                                "custom": false,
                                "options": [
                                    { "value": "fast", "label": "Fast" },
                                    { "value": "safe", "label": "Safe" }
                                ]
                            }
                        ]
                    }
                }
            }),
            &mut state,
        );
        assert_eq!(
            form_evs,
            vec![(
                "ses_root".into(),
                ObservedEvent::Attention {
                    key: "obs:opencode:form:ses_root:frm_1".into(),
                    kind: AttentionKind::Ask {
                        multi: false,
                        initial: 0
                    },
                    prompt: "Which mode?".into(),
                    options: vec!["Fast".into(), "Safe".into()],
                    actionable: true,
                }
            )]
        );
        let spec1 = state
            .form_specs
            .get("obs:opencode:form:ses_root:frm_1")
            .unwrap();
        assert_eq!(
            build_form_reply_payload(&AgentChoice::Option { index: 1 }, spec1).unwrap(),
            json!({ "answer": { "mode": "safe" } })
        );
        assert_eq!(
            build_form_reply_payload(
                &AgentChoice::Text {
                    text: "custom".into()
                },
                spec1
            ),
            Err("unsupported choice".into())
        );

        // Form with boolean field.
        let bool_evs = translate_event(
            &json!({
                "type": "form.created",
                "data": {
                    "form": {
                        "id": "frm_2",
                        "sessionID": "ses_root",
                        "title": "Confirm",
                        "fields": [
                            { "key": "ok", "type": "boolean", "title": "Proceed?" }
                        ]
                    }
                }
            }),
            &mut state,
        );
        assert_eq!(
            bool_evs,
            vec![(
                "ses_root".into(),
                ObservedEvent::Attention {
                    key: "obs:opencode:form:ses_root:frm_2".into(),
                    kind: AttentionKind::Ask {
                        multi: false,
                        initial: 0
                    },
                    prompt: "Proceed?".into(),
                    options: vec!["Yes".into(), "No".into()],
                    actionable: true,
                }
            )]
        );
        let spec2 = state
            .form_specs
            .get("obs:opencode:form:ses_root:frm_2")
            .unwrap();
        assert_eq!(
            build_form_reply_payload(&AgentChoice::Option { index: 0 }, spec2).unwrap(),
            json!({ "answer": { "ok": true } })
        );
        assert_eq!(
            build_form_reply_payload(&AgentChoice::Option { index: 1 }, spec2).unwrap(),
            json!({ "answer": { "ok": false } })
        );

        // Form with free-text string field.
        let text_evs = translate_event(
            &json!({
                "type": "form.created",
                "data": {
                    "form": {
                        "id": "frm_3",
                        "sessionID": "ses_root",
                        "title": "Name",
                        "fields": [
                            { "key": "name", "type": "string", "title": "Enter name" }
                        ]
                    }
                }
            }),
            &mut state,
        );
        assert_eq!(
            text_evs,
            vec![(
                "ses_root".into(),
                ObservedEvent::Attention {
                    key: "obs:opencode:form:ses_root:frm_3".into(),
                    kind: AttentionKind::TextQuestion,
                    prompt: "Enter name".into(),
                    options: vec![],
                    actionable: true,
                }
            )]
        );
        let spec3 = state
            .form_specs
            .get("obs:opencode:form:ses_root:frm_3")
            .unwrap();
        assert_eq!(
            build_form_reply_payload(
                &AgentChoice::Text {
                    text: "Alice".into()
                },
                spec3
            )
            .unwrap(),
            json!({ "answer": { "name": "Alice" } })
        );

        // Multi-field form -> non-actionable.
        let multi_evs = translate_event(
            &json!({
                "type": "form.created",
                "data": {
                    "form": {
                        "id": "frm_4",
                        "sessionID": "ses_root",
                        "title": "Multi",
                        "fields": [
                            { "key": "a", "type": "string" },
                            { "key": "b", "type": "boolean" }
                        ]
                    }
                }
            }),
            &mut state,
        );
        assert_eq!(
            multi_evs,
            vec![(
                "ses_root".into(),
                ObservedEvent::Attention {
                    key: "obs:opencode:form:ses_root:frm_4".into(),
                    kind: AttentionKind::TextQuestion,
                    prompt: "Multi".into(),
                    options: vec![],
                    actionable: false,
                }
            )]
        );

        // Form cancelled resolves attention.
        assert_eq!(
            translate_event(
                &json!({
                    "type": "form.cancelled",
                    "data": { "sessionID": "ses_root", "id": "frm_1" }
                }),
                &mut state
            ),
            vec![(
                "ses_root".into(),
                ObservedEvent::AttentionResolved {
                    key: "obs:opencode:form:ses_root:frm_1".into()
                }
            )]
        );
    }

    #[test]
    fn test_sse_parser_handles_heartbeats_and_multiline_data() {
        let mut parser = SseParser::new();
        let chunk1 = b": heartbeat\n\ndata: {\"type\":\"server.connected\",";
        assert!(parser.push_chunk(chunk1).is_empty());
        let chunk2 = b"\ndata: \"data\":{}}\n\n";
        let evs = parser.push_chunk(chunk2);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["type"], "server.connected");
    }
}
