//! Pure Claude engine: hook parsing, event extraction, attention specs,
//! decisions, state machine, transcript line classification, and screen anchors (W2).

use std::collections::{BTreeMap, HashSet, VecDeque};

use cawide_protocol::types::AgentStatus;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent::map::{
    extract_target, truncate_chars, AgentSignal, AttentionKind, AttentionSpec, SignalResolution,
    TurnOutcome,
};
use crate::net::ipc::{ClaudeEventKind, ClaudeHookEvent, ClaudeHookFrame, ClaudeReply};

/// Inbound JSON payload from Claude Code hooks (`$in` via stdin).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClaudeHookInput {
    pub session_id: String,
    pub transcript_path: Option<String>,
    pub cwd: Option<String>,
    pub prompt_id: Option<String>,
    pub hook_event_name: String,
    pub permission_mode: Option<String>,
    pub source: Option<String>,
    pub model: Option<String>,
    pub prompt: Option<String>,
    #[serde(alias = "toolName")]
    pub tool_name: Option<String>,
    pub tool_use_id: Option<String>,
    #[serde(alias = "toolInput")]
    pub tool_input: Option<serde_json::Value>,
    pub tool_response: Option<serde_json::Value>,
    pub error: Option<String>,
    pub error_details: Option<serde_json::Value>,
    pub message: Option<String>,
    pub notification_type: Option<String>,
    #[serde(alias = "last-assistant-message")]
    pub last_assistant_message: Option<String>,
    pub background_tasks: Vec<serde_json::Value>,
    pub session_crons: Vec<serde_json::Value>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub agent_transcript_path: Option<String>,
    pub trigger: Option<String>,
    pub compact_summary: Option<String>,
    pub custom_instructions: Option<serde_json::Value>,
    pub reason: Option<String>,
    pub mcp_server_name: Option<String>,
    pub mode: Option<String>,
    pub requested_schema: Option<serde_json::Value>,
    pub permission_suggestions: Vec<serde_json::Value>,
}

/// Recursively canonicalize a JSON value by sorting object keys with BTreeMap.
fn canonicalize_json(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize_json(v));
            }
            serde_json::to_value(sorted).unwrap_or(serde_json::Value::Null)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_json).collect())
        }
        other => other.clone(),
    }
}

/// Computes a canonical SHA-256 hash (first 8 bytes, big-endian `u64`) of a JSON input.
pub fn canonical_input_hash(val: Option<&serde_json::Value>) -> Option<u64> {
    let v = val?;
    let canonical = canonicalize_json(v);
    let bytes = serde_json::to_vec(&canonical).ok()?;
    let digest = Sha256::digest(&bytes);
    if digest.len() < 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&digest[..8]);
    Some(u64::from_be_bytes(arr))
}

/// Formats an internal MCP tool name `mcp__<server>__<tool>` into `<server>/<tool>`.
pub fn format_tool_name(tool_name: &str) -> String {
    if let Some(rest) = tool_name.strip_prefix("mcp__") {
        if let Some((server, tool)) = rest.split_once("__") {
            return format!("{server}/{tool}");
        }
    }
    tool_name.to_string()
}

/// Summarizes the first non-empty lines of a plan or summary string into ≤280 chars.
fn summarize_head(head: &str) -> String {
    let mut out = String::new();
    for line in head.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(trimmed);
        if out.chars().count() >= 280 {
            break;
        }
    }
    truncate_chars(&out, 280)
}

/// Extracts a typed `ClaudeHookEvent` from raw `ClaudeHookInput`.
pub fn extract_claude_event(input: &ClaudeHookInput) -> Option<ClaudeHookEvent> {
    let kind = match input.hook_event_name.as_str() {
        "SessionStart" => ClaudeEventKind::SessionStart,
        "UserPromptSubmit" => ClaudeEventKind::UserPromptSubmit,
        "PreToolUse" => ClaudeEventKind::PreToolUse,
        "PermissionRequest" => ClaudeEventKind::PermissionRequest,
        "PermissionDenied" => ClaudeEventKind::PermissionDenied,
        "PostToolUse" => ClaudeEventKind::PostToolUse,
        "PostToolUseFailure" => ClaudeEventKind::PostToolUseFailure,
        "Notification" => ClaudeEventKind::Notification,
        "SubagentStart" => ClaudeEventKind::SubagentStart,
        "SubagentStop" => ClaudeEventKind::SubagentStop,
        "PreCompact" => ClaudeEventKind::PreCompact,
        "PostCompact" => ClaudeEventKind::PostCompact,
        "Stop" => ClaudeEventKind::Stop,
        "StopFailure" => ClaudeEventKind::StopFailure,
        "SessionEnd" => ClaudeEventKind::SessionEnd,
        _ => return None,
    };

    let background_count = (input.background_tasks.len() + input.session_crons.len()) as u32;

    let input_hash = match kind {
        ClaudeEventKind::PreToolUse
        | ClaudeEventKind::PermissionRequest
        | ClaudeEventKind::PostToolUse
        | ClaudeEventKind::PostToolUseFailure
        | ClaudeEventKind::PermissionDenied => canonical_input_hash(input.tool_input.as_ref()),
        _ => None,
    };

    let text = match kind {
        ClaudeEventKind::UserPromptSubmit => {
            input.prompt.as_deref().map(|p| truncate_chars(p, 280))
        }
        ClaudeEventKind::PreToolUse => {
            let tool = input.tool_name.as_deref().unwrap_or("");
            let display_tool = format_tool_name(tool);
            let target = extract_target(input.tool_input.as_ref());
            let desc = if target.is_empty() {
                format!("Using {display_tool}")
            } else {
                format!("{display_tool}: {target}")
            };
            Some(truncate_chars(&desc, 280))
        }
        ClaudeEventKind::PermissionRequest => {
            let tool = input.tool_name.as_deref().unwrap_or("");
            let display_tool = format_tool_name(tool);
            let target = extract_target(input.tool_input.as_ref());
            let desc = if target.is_empty() {
                format!("Approve {display_tool}")
            } else {
                format!("Approve {display_tool}: {target}")
            };
            Some(truncate_chars(&desc, 280))
        }
        ClaudeEventKind::PostToolUseFailure => {
            input.error.as_deref().map(|e| truncate_chars(e, 500))
        }
        ClaudeEventKind::Notification => input.message.as_deref().map(|m| truncate_chars(m, 280)),
        ClaudeEventKind::Stop => input
            .last_assistant_message
            .as_deref()
            .map(|m| truncate_chars(m, 4000)),
        ClaudeEventKind::StopFailure => input
            .error
            .as_deref()
            .or(input.last_assistant_message.as_deref())
            .map(|e| truncate_chars(e, 500)),
        _ => None,
    };

    Some(ClaudeHookEvent {
        session_id: String::new(),
        claude_session_id: input.session_id.clone(),
        kind,
        agent_id: input.agent_id.clone(),
        tool_use_id: input.tool_use_id.clone(),
        tool_name: input.tool_name.clone(),
        input_hash,
        text,
        source: input.source.clone(),
        notification_type: input.notification_type.clone(),
        background_count,
    })
}

/// Builds an `AttentionSpec` (`key: None`) for a `PermissionRequest`.
pub fn build_attention_spec(input: &ClaudeHookInput) -> AttentionSpec {
    let tool_name = input.tool_name.as_deref().unwrap_or("");
    if tool_name == "AskUserQuestion" {
        let questions_arr = input
            .tool_input
            .as_ref()
            .and_then(|ti| ti.get("questions"))
            .and_then(|q| q.as_array());

        if let Some(arr) = questions_arr {
            if arr.len() == 1 {
                let q = &arr[0];
                let multi = q
                    .get("multiSelect")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let question_text = q.get("question").and_then(|v| v.as_str()).unwrap_or("");
                if !multi {
                    let options: Vec<String> = q
                        .get("options")
                        .and_then(|v| v.as_array())
                        .map(|o_arr| {
                            o_arr
                                .iter()
                                .take(8)
                                .map(|val| {
                                    let s = val
                                        .get("label")
                                        .and_then(|l| l.as_str())
                                        .or_else(|| val.as_str())
                                        .unwrap_or("");
                                    truncate_chars(s, 80)
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    return AttentionSpec {
                        key: None,
                        kind: AttentionKind::Ask {
                            multi: false,
                            initial: 0,
                        },
                        prompt: truncate_chars(question_text, 280),
                        options,
                        actionable: true,
                    };
                }
                return AttentionSpec {
                    key: None,
                    kind: AttentionKind::Ask {
                        multi: true,
                        initial: 0,
                    },
                    prompt: truncate_chars(question_text, 280),
                    options: Vec::new(),
                    actionable: false,
                };
            }
        }

        return AttentionSpec {
            key: None,
            kind: AttentionKind::Ask {
                multi: true,
                initial: 0,
            },
            prompt: "Answer Claude's question".to_string(),
            options: Vec::new(),
            actionable: false,
        };
    }

    if tool_name == "ExitPlanMode" {
        let plan_str = input
            .tool_input
            .as_ref()
            .and_then(|ti| ti.get("plan"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let prompt_raw = if plan_str.is_empty() {
            "Approve Claude's plan?".to_string()
        } else {
            format!("Approve Claude's plan?\n{}", summarize_head(plan_str))
        };
        return AttentionSpec {
            key: None,
            kind: AttentionKind::Plan {
                review_id: String::new(),
                option_ids: vec!["approve".into(), "approve_accept_edits".into()],
            },
            prompt: truncate_chars(&prompt_raw, 280),
            options: vec!["Approve".into(), "Approve & accept edits".into()],
            actionable: true,
        };
    }

    let display_tool = format_tool_name(tool_name);
    let target = extract_target(input.tool_input.as_ref());
    let prompt_raw = if target.is_empty() {
        format!("Allow {display_tool}?")
    } else {
        format!("Allow {display_tool}: {target}?")
    };

    AttentionSpec {
        key: None,
        kind: AttentionKind::Approval,
        prompt: truncate_chars(&prompt_raw, 280),
        options: vec!["Allow".into(), "Deny".into()],
        actionable: true,
    }
}

/// Translates a `ClaudeReply` into exact Claude Code stdout JSON decision output.
pub fn decision_for(input: &ClaudeHookInput, reply: ClaudeReply) -> Option<serde_json::Value> {
    let tool_name = input.tool_name.as_deref().unwrap_or("");
    if tool_name == "AskUserQuestion" {
        let ClaudeReply::Answer { option_index, text } = reply else {
            return None;
        };
        let q_obj = input
            .tool_input
            .as_ref()
            .and_then(|ti| ti.get("questions"))
            .and_then(|q| q.as_array())
            .and_then(|arr| arr.first())?;

        let question_text = q_obj.get("question").and_then(|v| v.as_str())?;
        let options_arr = q_obj.get("options").and_then(|v| v.as_array());

        let answer_str = if let Some(idx) = option_index {
            let opts = options_arr?;
            let opt_val = opts.get(idx as usize)?;
            opt_val
                .get("label")
                .and_then(|l| l.as_str())
                .or_else(|| opt_val.as_str())?
                .to_string()
        } else {
            text?
        };

        let mut updated = input.tool_input.clone().unwrap_or_default();
        if let Some(obj) = updated.as_object_mut() {
            let mut answers = serde_json::Map::new();
            answers.insert(
                question_text.to_string(),
                serde_json::Value::String(answer_str),
            );
            obj.insert("answers".to_string(), serde_json::Value::Object(answers));
        }

        return Some(serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "allow",
                    "updatedInput": updated
                }
            }
        }));
    }

    if tool_name == "ExitPlanMode" {
        match reply {
            ClaudeReply::ApprovePlan {
                accept_edits: false,
            } => {
                let updated = input.tool_input.clone().unwrap_or_default();
                Some(serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "allow",
                            "updatedInput": updated
                        }
                    }
                }))
            }
            ClaudeReply::ApprovePlan { accept_edits: true } => {
                let updated = input.tool_input.clone().unwrap_or_default();
                Some(serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "allow",
                            "updatedInput": updated,
                            "updatedPermissions": [
                                {
                                    "type": "setMode",
                                    "mode": "acceptEdits",
                                    "destination": "session"
                                }
                            ]
                        }
                    }
                }))
            }
            ClaudeReply::Deny { message } => {
                let msg = message.unwrap_or_else(|| "Denied from Cawide".to_string());
                Some(serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "deny",
                            "message": msg
                        }
                    }
                }))
            }
            ClaudeReply::Allow | ClaudeReply::Answer { .. } => None,
        }
    } else {
        match reply {
            ClaudeReply::Allow => Some(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {
                        "behavior": "allow"
                    }
                }
            })),
            ClaudeReply::Deny { message } => {
                let msg = message.unwrap_or_else(|| "Denied from Cawide".to_string());
                Some(serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "deny",
                            "message": msg
                        }
                    }
                }))
            }
            ClaudeReply::Answer { .. } | ClaudeReply::ApprovePlan { .. } => None,
        }
    }
}

/// A pending permission card tracked by `ClaudeSessionState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPerm {
    pub key: String,
    pub tool_use_id: Option<String>,
    pub input_hash: Option<u64>,
    pub tool_name: String,
    pub agent_id: Option<String>,
}

/// An unmatched `PreToolUse` waiting for a matching `PermissionRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmatchedPreTool {
    pub tool_use_id: Option<String>,
    pub tool_name: Option<String>,
    pub input_hash: Option<u64>,
    pub agent_id: Option<String>,
}
/// State machine tracking Claude Code sessions and pending permissions.
#[derive(Debug, Default)]
pub struct ClaudeSessionState {
    pub owner_claude_session_id: Option<String>,
    pub unmatched_pre_tool_use: VecDeque<UnmatchedPreTool>,
    pub open_perms: Vec<OpenPerm>,
    pub open_notifs: Vec<String>,
    pub subagents: HashSet<String>,
    pub perm_seq: u64,
    pub notif_seq: u64,
    pub last_stop_had_bg: bool,
    pub last_bg_stop_summary: String,
    pub currently_thinking_base: Option<String>,
}

/// Effects produced by processing a `ClaudeHookEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClaudeEffects {
    pub signal: Option<AgentSignal>,
    pub dismiss: Vec<String>,
    pub registered_tool_use_id: Option<String>,
    pub request_key: Option<String>,
}

impl ClaudeSessionState {
    fn format_thinking_desc(&self, base: &str) -> String {
        let count = self.subagents.len();
        if count > 0 {
            let s = format!("{base} · {count} agent{}", if count > 1 { "s" } else { "" });
            truncate_chars(&s, 280)
        } else {
            truncate_chars(base, 280)
        }
    }

    fn format_current_thinking_desc(&self) -> String {
        let base = self
            .currently_thinking_base
            .as_deref()
            .unwrap_or("Thinking…");
        self.format_thinking_desc(base)
    }

    /// Applies a hook event to update the state machine and returns resulting effects.
    pub fn apply(
        &mut self,
        ev: ClaudeHookEvent,
        attention_spec: Option<AttentionSpec>,
    ) -> ClaudeEffects {
        if (matches!(ev.kind, ClaudeEventKind::SessionStart)
            && matches!(ev.source.as_deref(), Some("startup" | "resume" | "clear")))
            || self.owner_claude_session_id.is_none()
        {
            self.owner_claude_session_id = Some(ev.claude_session_id.clone());
        } else if self.owner_claude_session_id.as_deref() != Some(ev.claude_session_id.as_str()) {
            return ClaudeEffects::default();
        }

        let mut effects = ClaudeEffects::default();

        match ev.kind {
            ClaudeEventKind::SessionStart => {
                let mut dismissed = Vec::new();
                for p in self.open_perms.drain(..) {
                    dismissed.push(p.key);
                }
                dismissed.append(&mut self.open_notifs);
                effects.dismiss = dismissed;

                self.unmatched_pre_tool_use.clear();
                self.subagents.clear();
                self.last_stop_had_bg = false;
                self.last_bg_stop_summary.clear();
                self.currently_thinking_base = None;

                if ev.source.as_deref() == Some("compact") {
                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::Thinking {
                            task_desc: "Thinking…".into(),
                        },
                        attention: None,
                        outcome: TurnOutcome::None,
                        resolution: SignalResolution::None,
                        seq: None,
                        epoch: None,
                    });
                } else {
                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::Idle,
                        attention: None,
                        outcome: TurnOutcome::None,
                        resolution: SignalResolution::ClearAll,
                        seq: None,
                        epoch: None,
                    });
                }
            }
            ClaudeEventKind::UserPromptSubmit => {
                let mut dismissed = Vec::new();
                for p in self.open_perms.drain(..) {
                    dismissed.push(p.key);
                }
                dismissed.append(&mut self.open_notifs);
                effects.dismiss = dismissed;

                self.unmatched_pre_tool_use.clear();
                self.last_stop_had_bg = false;
                self.last_bg_stop_summary.clear();

                let prompt = ev.text.unwrap_or_default();
                let prompt_trunc = truncate_chars(&prompt, 280);
                self.currently_thinking_base = Some(prompt_trunc.clone());

                effects.signal = Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: self.format_thinking_desc(&prompt_trunc),
                    },
                    attention: None,
                    outcome: TurnOutcome::Started,
                    resolution: SignalResolution::ClearAll,
                    seq: None,
                    epoch: None,
                });
            }
            ClaudeEventKind::PreToolUse => {
                if self.unmatched_pre_tool_use.len() >= 128 {
                    self.unmatched_pre_tool_use.pop_front();
                }
                let is_ask_or_plan = ev
                    .tool_name
                    .as_deref()
                    .is_some_and(|t| t == "AskUserQuestion" || t == "ExitPlanMode");

                self.unmatched_pre_tool_use.push_back(UnmatchedPreTool {
                    tool_use_id: ev.tool_use_id,
                    tool_name: ev.tool_name,
                    input_hash: ev.input_hash,
                    agent_id: ev.agent_id,
                });

                if !is_ask_or_plan {
                    if let Some(txt) = ev.text {
                        self.currently_thinking_base = Some(txt);
                    }

                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::Thinking {
                            task_desc: self.format_current_thinking_desc(),
                        },
                        attention: None,
                        outcome: TurnOutcome::None,
                        resolution: SignalResolution::None,
                        seq: None,
                        epoch: None,
                    });
                }
            }
            ClaudeEventKind::PermissionRequest => {
                let mut matched_tool_use_id = ev.tool_use_id;
                let req_tool_name = ev.tool_name.unwrap_or_default();
                let req_agent_id = ev.agent_id;

                if matched_tool_use_id.is_none() {
                    let matched_idx = self
                        .unmatched_pre_tool_use
                        .iter()
                        .rposition(|u| {
                            u.tool_name.as_deref() == Some(req_tool_name.as_str())
                                && u.agent_id == req_agent_id
                                && ev.input_hash.is_some()
                                && u.input_hash == ev.input_hash
                        })
                        .or_else(|| {
                            if ev.input_hash.is_none() {
                                self.unmatched_pre_tool_use.iter().rposition(|u| {
                                    u.tool_name.as_deref() == Some(req_tool_name.as_str())
                                        && u.agent_id == req_agent_id
                                })
                            } else {
                                None
                            }
                        });

                    if let Some(idx) = matched_idx {
                        if let Some(removed) = self.unmatched_pre_tool_use.remove(idx) {
                            matched_tool_use_id = removed.tool_use_id;
                        }
                    }
                }

                self.perm_seq += 1;
                let key = format!("perm-{}", self.perm_seq);

                self.open_perms.push(OpenPerm {
                    key: key.clone(),
                    tool_use_id: matched_tool_use_id.clone(),
                    input_hash: ev.input_hash,
                    tool_name: req_tool_name,
                    agent_id: req_agent_id,
                });

                let mut att = attention_spec.unwrap_or(AttentionSpec {
                    key: None,
                    kind: AttentionKind::Approval,
                    prompt: "Approve action?".to_string(),
                    options: vec!["Allow".into(), "Deny".into()],
                    actionable: true,
                });
                att.key = Some(key.clone());
                if let AttentionKind::Plan { review_id, .. } = &mut att.kind {
                    *review_id = key.clone();
                }

                let dismissed = std::mem::take(&mut self.open_notifs);
                effects.dismiss = dismissed.clone();
                effects.request_key = Some(key);
                effects.registered_tool_use_id = matched_tool_use_id;
                effects.signal = Some(AgentSignal {
                    status: AgentStatus::WaitingForInput {
                        prompt: att.prompt.clone(),
                        options: att.options.clone(),
                    },
                    attention: Some(att),
                    outcome: TurnOutcome::None,
                    resolution: if dismissed.is_empty() {
                        SignalResolution::None
                    } else {
                        SignalResolution::ByKeys(dismissed)
                    },
                    seq: None,
                    epoch: None,
                });
            }
            ClaudeEventKind::Notification => match ev.notification_type.as_deref() {
                Some("permission_prompt") => {
                    if self.open_perms.is_empty() {
                        self.notif_seq += 1;
                        let notif_key = format!("notif-{}", self.notif_seq);
                        self.open_notifs.push(notif_key.clone());
                        effects.request_key = Some(notif_key.clone());

                        let prompt = ev
                            .text
                            .unwrap_or_else(|| "Claude needs approval".to_string());
                        effects.signal = Some(AgentSignal {
                            status: AgentStatus::WaitingForInput {
                                prompt: prompt.clone(),
                                options: Vec::new(),
                            },
                            attention: Some(AttentionSpec {
                                key: Some(notif_key),
                                kind: AttentionKind::Approval,
                                prompt,
                                options: Vec::new(),
                                actionable: false,
                            }),
                            outcome: TurnOutcome::None,
                            resolution: SignalResolution::None,
                            seq: None,
                            epoch: None,
                        });
                    }
                }
                Some("elicitation_dialog" | "elicitation_url_dialog") => {
                    self.notif_seq += 1;
                    let notif_key = format!("notif-{}", self.notif_seq);
                    self.open_notifs.push(notif_key.clone());
                    effects.request_key = Some(notif_key.clone());

                    let prompt = ev
                        .text
                        .unwrap_or_else(|| "Claude Code needs your input".to_string());
                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::WaitingForInput {
                            prompt: prompt.clone(),
                            options: Vec::new(),
                        },
                        attention: Some(AttentionSpec {
                            key: Some(notif_key),
                            kind: AttentionKind::Ask {
                                multi: false,
                                initial: 0,
                            },
                            prompt,
                            options: Vec::new(),
                            actionable: false,
                        }),
                        outcome: TurnOutcome::None,
                        resolution: SignalResolution::None,
                        seq: None,
                        epoch: None,
                    });
                }
                Some("idle_prompt") => {
                    let mut dismissed = Vec::new();
                    for p in self.open_perms.drain(..) {
                        dismissed.push(p.key);
                    }
                    dismissed.append(&mut self.open_notifs);
                    effects.dismiss = dismissed;

                    if self.currently_thinking_base.is_some() {
                        if self.last_stop_had_bg {
                            self.currently_thinking_base = None;
                            effects.signal = Some(AgentSignal {
                                status: AgentStatus::Completed {
                                    summary: self.last_bg_stop_summary.clone(),
                                },
                                attention: None,
                                outcome: TurnOutcome::Done,
                                resolution: SignalResolution::ClearAll,
                                seq: None,
                                epoch: None,
                            });
                        } else {
                            self.currently_thinking_base = None;
                            effects.signal = Some(AgentSignal {
                                status: AgentStatus::Idle,
                                attention: None,
                                outcome: TurnOutcome::Aborted,
                                resolution: SignalResolution::ClearAll,
                                seq: None,
                                epoch: None,
                            });
                        }
                    } else {
                        effects.signal = Some(AgentSignal {
                            status: AgentStatus::Idle,
                            attention: None,
                            outcome: TurnOutcome::None,
                            resolution: SignalResolution::ClearAll,
                            seq: None,
                            epoch: None,
                        });
                    }
                }
                _ => {}
            },
            ClaudeEventKind::PostToolUse
            | ClaudeEventKind::PostToolUseFailure
            | ClaudeEventKind::PermissionDenied => {
                let matched_pos = if let Some(tuid) = &ev.tool_use_id {
                    self.open_perms
                        .iter()
                        .position(|p| p.tool_use_id.as_deref() == Some(tuid.as_str()))
                } else {
                    None
                }
                .or_else(|| {
                    if let Some(tn) = &ev.tool_name {
                        self.open_perms.iter().rposition(|p| {
                            &p.tool_name == tn
                                && p.agent_id == ev.agent_id
                                && (ev.input_hash.is_none() || p.input_hash == ev.input_hash)
                        })
                    } else {
                        None
                    }
                });

                let mut dismissed = Vec::new();
                if let Some(pos) = matched_pos {
                    let removed = self.open_perms.remove(pos);
                    dismissed.push(removed.key);
                }
                dismissed.append(&mut self.open_notifs);
                effects.dismiss = dismissed.clone();

                match ev.kind {
                    ClaudeEventKind::PostToolUse | ClaudeEventKind::PostToolUseFailure => {
                        effects.signal = Some(AgentSignal {
                            status: AgentStatus::Thinking {
                                task_desc: self.format_thinking_desc("Thinking…"),
                            },
                            attention: None,
                            outcome: TurnOutcome::None,
                            resolution: SignalResolution::ByKeys(dismissed),
                            seq: None,
                            epoch: None,
                        });
                    }
                    ClaudeEventKind::PermissionDenied => {
                        effects.signal = Some(AgentSignal {
                            status: AgentStatus::Thinking {
                                task_desc: self.format_thinking_desc("Thinking…"),
                            },
                            attention: None,
                            outcome: TurnOutcome::None,
                            resolution: SignalResolution::ByKeys(dismissed),
                            seq: None,
                            epoch: None,
                        });
                    }
                    _ => {}
                }
            }
            ClaudeEventKind::SubagentStart => {
                if let Some(aid) = ev.agent_id {
                    self.subagents.insert(aid);
                }
                effects.signal = Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: self.format_current_thinking_desc(),
                    },
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::None,
                    seq: None,
                    epoch: None,
                });
            }
            ClaudeEventKind::SubagentStop => {
                if let Some(aid) = ev.agent_id {
                    self.subagents.remove(&aid);
                }
                if self.currently_thinking_base.is_some() {
                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::Thinking {
                            task_desc: self.format_current_thinking_desc(),
                        },
                        attention: None,
                        outcome: TurnOutcome::None,
                        resolution: SignalResolution::None,
                        seq: None,
                        epoch: None,
                    });
                }
            }
            ClaudeEventKind::Stop => {
                let summary = ev.text.unwrap_or_default();
                if ev.background_count > 0 {
                    self.last_stop_had_bg = true;
                    self.last_bg_stop_summary = truncate_chars(&summary, 280);
                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::Thinking {
                            task_desc: self.format_thinking_desc(&format!(
                                "Waiting on {} background task(s)",
                                ev.background_count
                            )),
                        },
                        attention: None,
                        outcome: TurnOutcome::None,
                        resolution: SignalResolution::None,
                        seq: None,
                        epoch: None,
                    });
                } else {
                    let mut dismissed = Vec::new();
                    for p in self.open_perms.drain(..) {
                        dismissed.push(p.key);
                    }
                    dismissed.append(&mut self.open_notifs);
                    effects.dismiss = dismissed;

                    self.last_stop_had_bg = false;
                    self.currently_thinking_base = None;
                    effects.signal = Some(AgentSignal {
                        status: AgentStatus::Completed {
                            summary: truncate_chars(&summary, 280),
                        },
                        attention: None,
                        outcome: TurnOutcome::Done,
                        resolution: SignalResolution::ClearAll,
                        seq: None,
                        epoch: None,
                    });
                }
            }
            ClaudeEventKind::StopFailure => {
                let mut dismissed = Vec::new();
                for p in self.open_perms.drain(..) {
                    dismissed.push(p.key);
                }
                dismissed.append(&mut self.open_notifs);
                effects.dismiss = dismissed;

                self.last_stop_had_bg = false;
                self.currently_thinking_base = None;
                let err_msg = ev.text.unwrap_or_else(|| "API error".to_string());
                effects.signal = Some(AgentSignal {
                    status: AgentStatus::Completed {
                        summary: truncate_chars(&format!("Error: {err_msg}"), 280),
                    },
                    attention: None,
                    outcome: TurnOutcome::Failed {
                        error: truncate_chars(&err_msg, 500),
                    },
                    resolution: SignalResolution::ClearAll,
                    seq: None,
                    epoch: None,
                });
            }
            ClaudeEventKind::PreCompact => {
                effects.signal = Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: self.format_thinking_desc("Compacting context…"),
                    },
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::None,
                    seq: None,
                    epoch: None,
                });
            }
            ClaudeEventKind::PostCompact => {
                effects.signal = Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: self.format_thinking_desc("Thinking…"),
                    },
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::None,
                    seq: None,
                    epoch: None,
                });
            }
            ClaudeEventKind::SessionEnd => {
                let mut dismissed = Vec::new();
                for p in self.open_perms.drain(..) {
                    dismissed.push(p.key);
                }
                dismissed.append(&mut self.open_notifs);
                effects.dismiss = dismissed;

                self.unmatched_pre_tool_use.clear();
                self.subagents.clear();
                self.last_stop_had_bg = false;
                self.currently_thinking_base = None;

                effects.signal = Some(AgentSignal {
                    status: AgentStatus::Idle,
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::ClearAll,
                    seq: None,
                    epoch: None,
                });
            }
        }

        effects
    }
}

/// Classifies a real Claude transcript line to detect terminal interruptions or external answers.
pub fn classify_transcript_line(
    line: &str,
    registered_tool_use_id: Option<&str>,
) -> Option<ClaudeHookFrame> {
    let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
    if parsed.get("type").and_then(|v| v.as_str()) != Some("user") {
        return None;
    }

    let msg = parsed.get("message")?;
    let content = msg.get("content")?.as_array()?;

    for item in content {
        if item.get("type").and_then(|v| v.as_str()) == Some("tool_result") {
            let item_tuid = item.get("tool_use_id").and_then(|v| v.as_str());
            if let Some(reg_id) = registered_tool_use_id {
                if item_tuid == Some(reg_id) {
                    let has_user_feedback = parsed
                        .get("userFeedback")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty());
                    if has_user_feedback {
                        return Some(ClaudeHookFrame::AnsweredElsewhere);
                    }
                    if parsed.get("toolDenialKind").and_then(|v| v.as_str())
                        == Some("user-rejected")
                    {
                        return Some(ClaudeHookFrame::Interrupted);
                    }
                    return Some(ClaudeHookFrame::AnsweredElsewhere);
                }
            }
        }
    }

    if registered_tool_use_id.is_none() {
        for item in content {
            if let Some(txt) = item.get("text").and_then(|v| v.as_str()) {
                if txt.contains("[Request interrupted by user") {
                    return Some(ClaudeHookFrame::Interrupted);
                }
            }
        }
    }

    None
}

/// A substring anchor for verifying permission dialog presence on the terminal screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionAnchor {
    pub needle: String,
}

/// Returns the permission dialog anchor pattern for a tool.
pub fn permission_dialog_anchor(tool_name: &str, _prompt: &str) -> Option<PermissionAnchor> {
    let needle = match tool_name {
        "Bash" => "Do you want to proceed?",
        "Write" => "Do you want to create ",
        "Edit" => "Do you want to make this edit to ",
        "WebFetch" => "Do you want to allow Claude to fetch this content?",
        "ExitPlanMode" => "Would you like to proceed?",
        "AskUserQuestion" => "Enter to select",
        t if t.starts_with("mcp__") => "Do you want to proceed?",
        _ => return None,
    };
    Some(PermissionAnchor {
        needle: needle.to_string(),
    })
}

/// Checks whether the dialog anchor is currently rendered in the screen text.
pub fn anchor_visible_on_screen(screen_text: &str, anchor: &PermissionAnchor) -> bool {
    screen_text.contains(&anchor.needle)
}
pub fn ingest_event(
    registry: &crate::net::registry::SessionRegistry,
    broadcaster: &crate::net::broadcaster::HostEventBroadcaster,
    ev: crate::net::ipc::ClaudeHookEvent,
) -> crate::net::ipc::IpcResponse {
    let session_id = ev.session_id.clone();
    if session_id.is_empty() {
        return crate::net::ipc::IpcResponse::Error("unknown session".into());
    }

    match registry.apply_claude_event(&session_id, ev) {
        crate::net::registry::HookOutcome::Updated(summary) => {
            broadcaster.broadcast(cawide_protocol::HostEvent::SessionUpdated { summary: *summary });
            crate::net::ipc::IpcResponse::Ok
        }
        crate::net::registry::HookOutcome::Ignored => crate::net::ipc::IpcResponse::Ok,
        crate::net::registry::HookOutcome::UnknownSession => {
            crate::net::ipc::IpcResponse::Error("unknown session".into())
        }
    }
}
fn poll_transcript_once(
    path: &str,
    last_offset: &mut u64,
    tool_use_id: Option<&str>,
) -> Option<ClaudeHookFrame> {
    let meta = std::fs::metadata(path).ok()?;
    let cur_len = meta.len();
    if cur_len <= *last_offset {
        return None;
    }
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(*last_offset)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let mut start = 0;
    for (idx, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            if let Ok(line) = std::str::from_utf8(&buf[start..idx]) {
                if let Some(frame) = classify_transcript_line(line, tool_use_id) {
                    *last_offset += (idx + 1) as u64;
                    return Some(frame);
                }
            }
            start = idx + 1;
        }
    }
    *last_offset += start as u64;
    None
}

pub async fn run_claude_hook(event_flag: Option<&str>) {
    if event_flag.is_some() {
        return;
    }
    let Some(session_id) = std::env::var("CAWIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    let Some(socket_path) = std::env::var("CAWIDE_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
    else {
        return;
    };

    use std::io::IsTerminal;
    let payload_bytes = if !std::io::stdin().is_terminal() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin().take(256 * 1024);
            let mut buf = Vec::new();
            let _ = stdin.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(bytes) => bytes,
            Err(_) => return,
        }
    } else {
        return;
    };

    let input: ClaudeHookInput = match serde_json::from_slice(&payload_bytes) {
        Ok(inp) => inp,
        Err(_) => return,
    };

    let mut ev = match extract_claude_event(&input) {
        Some(e) => e,
        None => return,
    };
    ev.session_id = session_id.clone();

    if ev.kind != ClaudeEventKind::PermissionRequest {
        let req = crate::net::ipc::IpcRequest::ClaudeEvent(ev);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            crate::net::ipc::send_ipc_request(&socket_path, &req),
        )
        .await;
        return;
    }

    let transcript_path = input.transcript_path.clone();
    let initial_len = transcript_path
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);

    let att = build_attention_spec(&input);
    let req = crate::net::ipc::IpcRequest::ClaudePermission {
        event: ev,
        attention: att,
    };
    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(1),
        crate::net::ipc::connect_ipc(&socket_path),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return,
    };

    use tokio::io::AsyncWriteExt;
    if cawide_protocol::write_length_prefixed(&mut stream, &req, crate::net::MAX_IPC_FRAME_SIZE)
        .await
        .is_err()
    {
        return;
    }
    let _ = stream.flush().await;

    let reg_resp: Option<crate::net::ipc::IpcResponse> = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cawide_protocol::read_length_prefixed(&mut stream, crate::net::MAX_IPC_FRAME_SIZE),
    )
    .await
    {
        Ok(Ok(r)) => r,
        _ => return,
    };

    let Some(crate::net::ipc::IpcResponse::ClaudeRegistered {
        request_key: _,
        tool_use_id,
    }) = reg_resp
    else {
        return;
    };

    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut last_offset = initial_len;

    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

    let transcript_period = std::time::Duration::from_millis(250);
    let mut transcript_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + transcript_period,
        transcript_period,
    );
    let ppid_period = std::time::Duration::from_secs(1);
    let mut ppid_interval =
        tokio::time::interval_at(tokio::time::Instant::now() + ppid_period, ppid_period);
    #[cfg(unix)]
    // SAFETY: POSIX getppid() takes no arguments and has no preconditions or side effects.
    let initial_ppid = unsafe { libc::getppid() };

    let mut drain_on_signal = false;
    'poll: loop {
        tokio::select! {
            reply_res = cawide_protocol::read_length_prefixed::<_, crate::net::ipc::IpcResponse>(&mut reader, crate::net::MAX_IPC_FRAME_SIZE) => {
                match reply_res {
                    Ok(Some(crate::net::ipc::IpcResponse::ClaudeReply(reply))) => {
                        if let Some(dec) = decision_for(&input, reply) {
                            use std::io::Write;
                            let out_str = dec.to_string();
                            let _ = std::io::stdout().write_all(out_str.as_bytes());
                            let _ = std::io::stdout().flush();
                        }
                        break;
                    }
                    Ok(Some(crate::net::ipc::IpcResponse::ClaudeDismissed)) | Ok(None) | Err(_) => {
                        break;
                    }
                    _ => break,
                }
            }
            _ = transcript_interval.tick() => {
                if let Some(ref path) = transcript_path {
                    if let Some(frame) = poll_transcript_once(path, &mut last_offset, tool_use_id.as_deref()) {
                        let _ = cawide_protocol::write_length_prefixed(&mut writer, &frame, crate::net::MAX_IPC_FRAME_SIZE).await;
                        let _ = writer.flush().await;
                        let _ = writer.shutdown().await;
                        break 'poll;
                    }
                }
            }
            _ = ppid_interval.tick() => {
                #[cfg(unix)]
                {
                    // SAFETY: POSIX getppid() takes no arguments and has no preconditions or side effects.
                    let cur_ppid = unsafe { libc::getppid() };
                    if cur_ppid == 1 || cur_ppid != initial_ppid {
                        break;
                    }
                }
            }
            _ = async {
                #[cfg(unix)]
                {
                    if let Some(sig) = &mut sigterm {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }
                #[cfg(not(unix))]
                std::future::pending::<()>().await
            } => {
                drain_on_signal = true;
                break 'poll;
            }
            _ = async {
                #[cfg(unix)]
                {
                    if let Some(sig) = &mut sighup {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }
                #[cfg(not(unix))]
                std::future::pending::<()>().await
            } => {
                drain_on_signal = true;
                break 'poll;
            }
        }
    }

    if drain_on_signal {
        if let Some(ref path) = transcript_path {
            if std::path::Path::new(path).exists() {
                for attempt in 0..18 {
                    if let Some(frame) =
                        poll_transcript_once(path, &mut last_offset, tool_use_id.as_deref())
                    {
                        let _ = cawide_protocol::write_length_prefixed(
                            &mut writer,
                            &frame,
                            crate::net::MAX_IPC_FRAME_SIZE,
                        )
                        .await;
                        let _ = writer.flush().await;
                        let _ = writer.shutdown().await;
                        break;
                    }
                    if attempt < 17 {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/claude");

    fn read_fixture(subpath: &str) -> String {
        let p = format!("{FIXTURES_DIR}/{subpath}");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read fixture {p}: {e}"))
    }

    fn read_json_fixture(subpath: &str) -> ClaudeHookInput {
        let txt = read_fixture(subpath);
        serde_json::from_str(&txt).unwrap_or_else(|e| panic!("failed to parse {subpath}: {e}"))
    }

    #[test]
    fn test_canonical_input_hash_invariance() {
        let v1 = serde_json::json!({
            "b": 2,
            "a": 1,
            "nested": { "z": [3, 2, 1], "y": "hello" }
        });
        let v2 = serde_json::json!({
            "nested": { "y": "hello", "z": [3, 2, 1] },
            "a": 1,
            "b": 2
        });
        let h1 = canonical_input_hash(Some(&v1)).unwrap();
        let h2 = canonical_input_hash(Some(&v2)).unwrap();
        assert_eq!(h1, h2, "canonical input hash must be key-order invariant");
        assert_eq!(canonical_input_hash(None), None);
    }

    #[test]
    fn test_format_tool_name() {
        assert_eq!(format_tool_name("Bash"), "Bash");
        assert_eq!(format_tool_name("mcp__w2demo__echo_msg"), "w2demo/echo_msg");
        assert_eq!(format_tool_name("mcp__server"), "mcp__server");
    }

    #[test]
    fn test_extract_claude_event_all_hook_fixtures() {
        let cases = [
            (
                "hooks/session_start_startup.json",
                ClaudeEventKind::SessionStart,
            ),
            (
                "hooks/session_start_resume.json",
                ClaudeEventKind::SessionStart,
            ),
            (
                "hooks/session_start_clear.json",
                ClaudeEventKind::SessionStart,
            ),
            (
                "hooks/session_start_compact.json",
                ClaudeEventKind::SessionStart,
            ),
            (
                "hooks/user_prompt_submit.json",
                ClaudeEventKind::UserPromptSubmit,
            ),
            ("hooks/pre_tool_use_bash.json", ClaudeEventKind::PreToolUse),
            (
                "hooks/permission_request_bash.json",
                ClaudeEventKind::PermissionRequest,
            ),
            ("hooks/pre_tool_use_write.json", ClaudeEventKind::PreToolUse),
            (
                "hooks/permission_request_write.json",
                ClaudeEventKind::PermissionRequest,
            ),
            ("hooks/pre_tool_use_edit.json", ClaudeEventKind::PreToolUse),
            (
                "hooks/permission_request_edit.json",
                ClaudeEventKind::PermissionRequest,
            ),
            (
                "hooks/pre_tool_use_webfetch.json",
                ClaudeEventKind::PreToolUse,
            ),
            (
                "hooks/permission_request_webfetch.json",
                ClaudeEventKind::PermissionRequest,
            ),
            (
                "hooks/pre_tool_use_ask_user_question.json",
                ClaudeEventKind::PreToolUse,
            ),
            (
                "hooks/permission_request_ask_user_question.json",
                ClaudeEventKind::PermissionRequest,
            ),
            (
                "hooks/pre_tool_use_exit_plan_mode.json",
                ClaudeEventKind::PreToolUse,
            ),
            (
                "hooks/permission_request_exit_plan_mode.json",
                ClaudeEventKind::PermissionRequest,
            ),
            ("hooks/pre_tool_use_mcp.json", ClaudeEventKind::PreToolUse),
            (
                "hooks/permission_request_mcp.json",
                ClaudeEventKind::PermissionRequest,
            ),
            (
                "hooks/post_tool_use_bash.json",
                ClaudeEventKind::PostToolUse,
            ),
            (
                "hooks/post_tool_use_write.json",
                ClaudeEventKind::PostToolUse,
            ),
            (
                "hooks/post_tool_use_edit.json",
                ClaudeEventKind::PostToolUse,
            ),
            (
                "hooks/post_tool_use_webfetch.json",
                ClaudeEventKind::PostToolUse,
            ),
            (
                "hooks/post_tool_use_ask_user_question.json",
                ClaudeEventKind::PostToolUse,
            ),
            (
                "hooks/post_tool_use_exit_plan_mode.json",
                ClaudeEventKind::PostToolUse,
            ),
            ("hooks/post_tool_use_mcp.json", ClaudeEventKind::PostToolUse),
            (
                "hooks/post_tool_use_failure_bash.json",
                ClaudeEventKind::PostToolUseFailure,
            ),
            (
                "hooks/notification_permission_prompt.json",
                ClaudeEventKind::Notification,
            ),
            (
                "hooks/notification_idle_prompt.json",
                ClaudeEventKind::Notification,
            ),
            (
                "hooks/notification_elicitation_dialog.json",
                ClaudeEventKind::Notification,
            ),
            ("hooks/stop.json", ClaudeEventKind::Stop),
            (
                "hooks/stop_with_background_tasks_subagent.json",
                ClaudeEventKind::Stop,
            ),
            (
                "hooks/stop_with_background_tasks_shell.json",
                ClaudeEventKind::Stop,
            ),
            ("hooks/stop_failure.json", ClaudeEventKind::StopFailure),
            ("hooks/subagent_start.json", ClaudeEventKind::SubagentStart),
            ("hooks/subagent_stop.json", ClaudeEventKind::SubagentStop),
            ("hooks/pre_compact.json", ClaudeEventKind::PreCompact),
            ("hooks/post_compact.json", ClaudeEventKind::PostCompact),
            ("hooks/session_end_other.json", ClaudeEventKind::SessionEnd),
            ("hooks/session_end_clear.json", ClaudeEventKind::SessionEnd),
            (
                "hooks/session_end_prompt_input_exit.json",
                ClaudeEventKind::SessionEnd,
            ),
        ];

        for (fixture, expected_kind) in cases {
            let input = read_json_fixture(fixture);
            let ev = extract_claude_event(&input)
                .unwrap_or_else(|| panic!("failed to extract event for {fixture}"));
            assert_eq!(ev.kind, expected_kind, "kind mismatch for {fixture}");
        }
    }

    #[test]
    fn test_state_machine_full_turn_lifecycle() {
        let mut state = ClaudeSessionState::default();
        let sid = "test-session-turn-1";

        // 1. SessionStart
        let inp_start = read_json_fixture("hooks/session_start_startup.json");
        let mut ev_start = extract_claude_event(&inp_start).unwrap();
        ev_start.claude_session_id = sid.into();
        let eff_start = state.apply(ev_start, None);
        assert_eq!(eff_start.signal.unwrap().status, AgentStatus::Idle);

        // 2. UserPromptSubmit
        let inp_prompt = read_json_fixture("hooks/user_prompt_submit.json");
        let mut ev_prompt = extract_claude_event(&inp_prompt).unwrap();
        ev_prompt.claude_session_id = sid.into();
        let eff_prompt = state.apply(ev_prompt, None);
        let sig_prompt = eff_prompt.signal.unwrap();
        assert!(matches!(sig_prompt.status, AgentStatus::Thinking { .. }));
        assert_eq!(sig_prompt.outcome, TurnOutcome::Started);

        // 3. PreToolUse Bash
        let inp_pre_bash = read_json_fixture("hooks/pre_tool_use_bash.json");
        let mut ev_pre_bash = extract_claude_event(&inp_pre_bash).unwrap();
        ev_pre_bash.claude_session_id = sid.into();
        let eff_pre_bash = state.apply(ev_pre_bash, None);
        assert!(matches!(
            eff_pre_bash.signal.unwrap().status,
            AgentStatus::Thinking { .. }
        ));
        assert_eq!(state.unmatched_pre_tool_use.len(), 1);

        // 4. PermissionRequest Bash
        let inp_req_bash = read_json_fixture("hooks/permission_request_bash.json");
        let mut ev_req_bash = extract_claude_event(&inp_req_bash).unwrap();
        ev_req_bash.claude_session_id = sid.into();
        let att_spec = build_attention_spec(&inp_req_bash);
        let eff_req_bash = state.apply(ev_req_bash, Some(att_spec));
        assert!(eff_req_bash.request_key.is_some());
        assert_eq!(
            eff_req_bash.registered_tool_use_id,
            Some("call_1199577024592148501".into())
        );
        assert!(matches!(
            eff_req_bash.signal.unwrap().status,
            AgentStatus::WaitingForInput { .. }
        ));
        assert_eq!(state.open_perms.len(), 1);

        // 5. Notification permission_prompt while perm is already open is ignored
        let inp_notif = read_json_fixture("hooks/notification_permission_prompt.json");
        let mut ev_notif = extract_claude_event(&inp_notif).unwrap();
        ev_notif.claude_session_id = sid.into();
        let eff_notif = state.apply(ev_notif, None);
        assert!(eff_notif.signal.is_none());

        // 6. PostToolUse Bash dismisses perm
        let inp_post_bash = read_json_fixture("hooks/post_tool_use_bash.json");
        let mut ev_post_bash = extract_claude_event(&inp_post_bash).unwrap();
        ev_post_bash.claude_session_id = sid.into();
        ev_post_bash.tool_use_id = Some("call_1199577024592148501".into());
        let eff_post_bash = state.apply(ev_post_bash, None);
        assert_eq!(eff_post_bash.dismiss, vec!["perm-1"]);
        assert!(state.open_perms.is_empty());
        assert!(matches!(
            eff_post_bash.signal.unwrap().status,
            AgentStatus::Thinking { .. }
        ));

        // 7. Stop without bg tasks
        let inp_stop = read_json_fixture("hooks/stop.json");
        let mut ev_stop = extract_claude_event(&inp_stop).unwrap();
        ev_stop.claude_session_id = sid.into();
        let eff_stop = state.apply(ev_stop, None);
        let sig_stop = eff_stop.signal.unwrap();
        assert!(matches!(sig_stop.status, AgentStatus::Completed { .. }));
        assert_eq!(sig_stop.outcome, TurnOutcome::Done);
        assert_eq!(sig_stop.resolution, SignalResolution::ClearAll);
    }

    #[test]
    fn test_subagent_counting_and_orphan_stop() {
        let mut state = ClaudeSessionState::default();
        let sid = "test-session-sub-1";

        let inp_prompt = read_json_fixture("hooks/user_prompt_submit.json");
        let mut ev_prompt = extract_claude_event(&inp_prompt).unwrap();
        ev_prompt.claude_session_id = sid.into();
        state.apply(ev_prompt, None);

        // SubagentStart
        let inp_sub_start = read_json_fixture("hooks/subagent_start.json");
        let mut ev_sub_start = extract_claude_event(&inp_sub_start).unwrap();
        ev_sub_start.claude_session_id = sid.into();
        let eff_sub_start = state.apply(ev_sub_start, None);
        if let AgentStatus::Thinking { task_desc } = eff_sub_start.signal.unwrap().status {
            assert!(task_desc.contains("1 agent"), "desc was {task_desc}");
        } else {
            panic!("expected Thinking");
        }

        // SubagentStop
        let inp_sub_stop = read_json_fixture("hooks/subagent_stop.json");
        let mut ev_sub_stop = extract_claude_event(&inp_sub_stop).unwrap();
        ev_sub_stop.claude_session_id = sid.into();
        let eff_sub_stop = state.apply(ev_sub_stop.clone(), None);
        if let AgentStatus::Thinking { task_desc } = eff_sub_stop.signal.unwrap().status {
            assert!(!task_desc.contains("agent"), "desc was {task_desc}");
        } else {
            panic!("expected Thinking");
        }

        // Stray SubagentStop when no subagents active does not crash or underflow
        let eff_stray = state.apply(ev_sub_stop, None);
        assert!(
            eff_stray.signal.is_none()
                || matches!(
                    eff_stray.signal.unwrap().status,
                    AgentStatus::Thinking { .. }
                )
        );
    }

    #[test]
    fn test_stop_with_background_tasks_and_idle_prompt_recovery() {
        let mut state = ClaudeSessionState::default();
        let sid = "test-session-bg-1";

        let inp_prompt = read_json_fixture("hooks/user_prompt_submit.json");
        let mut ev_prompt = extract_claude_event(&inp_prompt).unwrap();
        ev_prompt.claude_session_id = sid.into();
        state.apply(ev_prompt, None);

        // Stop with background tasks -> status is Thinking Waiting for background tasks
        let inp_stop_bg = read_json_fixture("hooks/stop_with_background_tasks_shell.json");
        let mut ev_stop_bg = extract_claude_event(&inp_stop_bg).unwrap();
        ev_stop_bg.claude_session_id = sid.into();
        let eff_stop_bg = state.apply(ev_stop_bg, None);
        let sig_stop_bg = eff_stop_bg.signal.unwrap();
        if let AgentStatus::Thinking { task_desc } = &sig_stop_bg.status {
            assert_eq!(task_desc, "Waiting on 1 background task(s)");
        } else {
            panic!("expected Thinking");
        }
        assert_eq!(sig_stop_bg.outcome, TurnOutcome::None);
        assert_eq!(sig_stop_bg.resolution, SignalResolution::None);
        assert!(state.last_stop_had_bg);

        // idle_prompt after background task finishes -> emits Completed with Done
        let inp_idle = read_json_fixture("hooks/notification_idle_prompt.json");
        let mut ev_idle = extract_claude_event(&inp_idle).unwrap();
        ev_idle.claude_session_id = sid.into();
        let eff_idle = state.apply(ev_idle, None);
        let sig_idle = eff_idle.signal.unwrap();
        assert!(matches!(sig_idle.status, AgentStatus::Completed { .. }));
        assert_eq!(sig_idle.outcome, TurnOutcome::Done);
    }

    #[test]
    fn test_idle_prompt_aborted_when_no_bg_tasks() {
        let mut state = ClaudeSessionState::default();
        let sid = "test-session-abort-1";

        let inp_prompt = read_json_fixture("hooks/user_prompt_submit.json");
        let mut ev_prompt = extract_claude_event(&inp_prompt).unwrap();
        ev_prompt.claude_session_id = sid.into();
        state.apply(ev_prompt, None);

        // Esc during thinking -> idle_prompt fires with last_stop_had_bg: false
        let inp_idle = read_json_fixture("hooks/notification_idle_prompt.json");
        let mut ev_idle = extract_claude_event(&inp_idle).unwrap();
        ev_idle.claude_session_id = sid.into();
        let eff_idle = state.apply(ev_idle, None);
        let sig_idle = eff_idle.signal.unwrap();
        assert_eq!(sig_idle.status, AgentStatus::Idle);
        assert_eq!(sig_idle.outcome, TurnOutcome::Aborted);
    }
    #[test]
    fn test_foreign_session_id_ignored() {
        let mut state = ClaudeSessionState::default();
        let inp_start = read_json_fixture("hooks/session_start_startup.json");
        state.apply(extract_claude_event(&inp_start).unwrap(), None);

        let mut inp_foreign = read_json_fixture("hooks/user_prompt_submit.json");
        inp_foreign.session_id = "foreign-session-uuid-9999".into();
        let ev_foreign = extract_claude_event(&inp_foreign).unwrap();
        let eff_foreign = state.apply(ev_foreign, None);
        assert_eq!(eff_foreign, ClaudeEffects::default());
    }

    #[test]
    fn test_decision_for_generic_tool() {
        let input = read_json_fixture("hooks/permission_request_bash.json");

        let allow_res = decision_for(&input, ClaudeReply::Allow).unwrap();
        assert_eq!(
            allow_res["hookSpecificOutput"]["decision"]["behavior"],
            "allow"
        );

        let deny_res = decision_for(
            &input,
            ClaudeReply::Deny {
                message: Some("No way".into()),
            },
        )
        .unwrap();
        assert_eq!(
            deny_res["hookSpecificOutput"]["decision"]["behavior"],
            "deny"
        );
        assert_eq!(
            deny_res["hookSpecificOutput"]["decision"]["message"],
            "No way"
        );

        assert!(decision_for(&input, ClaudeReply::ApprovePlan { accept_edits: true }).is_none());
        assert!(decision_for(
            &input,
            ClaudeReply::Answer {
                option_index: Some(0),
                text: None
            }
        )
        .is_none());
    }

    #[test]
    fn test_decision_for_ask_user_question() {
        let input = read_json_fixture("hooks/permission_request_ask_user_question.json");

        // option_index = 2 -> "Blue"
        let ans_idx = decision_for(
            &input,
            ClaudeReply::Answer {
                option_index: Some(2),
                text: None,
            },
        )
        .unwrap();
        assert_eq!(
            ans_idx["hookSpecificOutput"]["decision"]["behavior"],
            "allow"
        );
        assert_eq!(
            ans_idx["hookSpecificOutput"]["decision"]["updatedInput"]["answers"]["Pick a color?"],
            "Blue"
        );

        // text override -> "Custom"
        let ans_txt = decision_for(
            &input,
            ClaudeReply::Answer {
                option_index: None,
                text: Some("Yellow".into()),
            },
        )
        .unwrap();
        assert_eq!(
            ans_txt["hookSpecificOutput"]["decision"]["updatedInput"]["answers"]["Pick a color?"],
            "Yellow"
        );

        // out of bounds index returns None
        assert!(decision_for(
            &input,
            ClaudeReply::Answer {
                option_index: Some(99),
                text: None
            }
        )
        .is_none());

        // Allow / Deny on AskUserQuestion return None (defensive)
        assert!(decision_for(&input, ClaudeReply::Allow).is_none());
        assert!(decision_for(&input, ClaudeReply::Deny { message: None }).is_none());
    }

    #[test]
    fn test_decision_for_exit_plan_mode() {
        let input = read_json_fixture("hooks/permission_request_exit_plan_mode.json");

        // accept_edits: false
        let dec_no_edits = decision_for(
            &input,
            ClaudeReply::ApprovePlan {
                accept_edits: false,
            },
        )
        .unwrap();
        assert_eq!(
            dec_no_edits["hookSpecificOutput"]["decision"]["behavior"],
            "allow"
        );
        assert!(dec_no_edits["hookSpecificOutput"]["decision"]
            .get("updatedPermissions")
            .is_none());

        // accept_edits: true
        let dec_edits =
            decision_for(&input, ClaudeReply::ApprovePlan { accept_edits: true }).unwrap();
        assert_eq!(
            dec_edits["hookSpecificOutput"]["decision"]["behavior"],
            "allow"
        );
        let perms = dec_edits["hookSpecificOutput"]["decision"]["updatedPermissions"]
            .as_array()
            .unwrap();
        assert_eq!(perms[0]["mode"], "acceptEdits");

        // Deny
        let dec_deny = decision_for(
            &input,
            ClaudeReply::Deny {
                message: Some("Need changes".into()),
            },
        )
        .unwrap();
        assert_eq!(
            dec_deny["hookSpecificOutput"]["decision"]["behavior"],
            "deny"
        );
        assert_eq!(
            dec_deny["hookSpecificOutput"]["decision"]["message"],
            "Need changes"
        );

        // Allow / Answer on ExitPlanMode return None
        assert!(decision_for(&input, ClaudeReply::Allow).is_none());
        assert!(decision_for(
            &input,
            ClaudeReply::Answer {
                option_index: Some(0),
                text: None
            }
        )
        .is_none());
    }

    #[test]
    fn test_classify_transcript_line() {
        let p_no = format!("{FIXTURES_DIR}/transcripts/terminal_no.jsonl");
        let lines_no: Vec<String> = std::fs::read_to_string(&p_no)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        // L2 has tool_result with tool_use_id "call_1199577024592148501" and toolDenialKind "user-rejected"
        assert_eq!(
            classify_transcript_line(&lines_no[1], Some("call_1199577024592148501")),
            Some(ClaudeHookFrame::Interrupted)
        );
        // L4 is "[Request interrupted by user for tool use]" with registered_tool_use_id = None
        assert_eq!(
            classify_transcript_line(&lines_no[3], None),
            Some(ClaudeHookFrame::Interrupted)
        );

        let p_fb = format!("{FIXTURES_DIR}/transcripts/plan_feedback.jsonl");
        let lines_fb: Vec<String> = std::fs::read_to_string(&p_fb)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        // L2 has userFeedback = "also add a newline"
        assert_eq!(
            classify_transcript_line(&lines_fb[1], Some("call_5151771725678009000")),
            Some(ClaudeHookFrame::AnsweredElsewhere)
        );

        let p_app = format!("{FIXTURES_DIR}/transcripts/approved_tool.jsonl");
        let lines_app: Vec<String> = std::fs::read_to_string(&p_app)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        // L3 has successful tool_result
        assert_eq!(
            classify_transcript_line(&lines_app[2], Some("call_13076200003776771996")),
            Some(ClaudeHookFrame::AnsweredElsewhere)
        );
    }

    #[test]
    fn test_permission_dialog_anchors() {
        let tools_and_screens = [
            ("Bash", "screens/Bash.txt"),
            ("Write", "screens/Write.txt"),
            ("Edit", "screens/Edit.txt"),
            ("WebFetch", "screens/WebFetch.txt"),
            ("AskUserQuestion", "screens/AskUserQuestion.txt"),
            ("ExitPlanMode", "screens/ExitPlanMode.txt"),
            ("mcp__w2demo__echo_msg", "screens/Mcp.txt"),
        ];

        for (tool, screen_rel) in tools_and_screens {
            let anchor = permission_dialog_anchor(tool, "").expect("expected anchor");
            let screen_txt = read_fixture(screen_rel);
            assert!(
                anchor_visible_on_screen(&screen_txt, &anchor),
                "anchor {:?} was not found in {screen_rel}",
                anchor.needle
            );
            assert!(
                !anchor_visible_on_screen(
                    "completely unrelated console output\njust a prompt",
                    &anchor
                ),
                "anchor {:?} falsely matched non-dialog screen",
                anchor.needle
            );
        }
        assert!(permission_dialog_anchor("UnknownTool", "").is_none());
    }
    #[test]
    fn test_part_a_edge_cases() {
        let mut state = ClaudeSessionState::default();
        let sid = "edge-cases-sid";

        // 1. PreToolUse for AskUserQuestion and ExitPlanMode gives effects.signal = None
        let inp_pre_ask = read_json_fixture("hooks/pre_tool_use_ask_user_question.json");
        let mut ev_pre_ask = extract_claude_event(&inp_pre_ask).unwrap();
        ev_pre_ask.claude_session_id = sid.into();
        let eff_pre_ask = state.apply(ev_pre_ask, None);
        assert!(eff_pre_ask.signal.is_none());
        assert_eq!(state.unmatched_pre_tool_use.len(), 1);

        let inp_pre_plan = read_json_fixture("hooks/pre_tool_use_exit_plan_mode.json");
        let mut ev_pre_plan = extract_claude_event(&inp_pre_plan).unwrap();
        ev_pre_plan.claude_session_id = sid.into();
        let eff_pre_plan = state.apply(ev_pre_plan, None);
        assert!(eff_pre_plan.signal.is_none());
        assert_eq!(state.unmatched_pre_tool_use.len(), 2);

        // 2. SessionStart compact, PreCompact, PostCompact
        let inp_compact_start = read_json_fixture("hooks/session_start_compact.json");
        let mut ev_compact_start = extract_claude_event(&inp_compact_start).unwrap();
        ev_compact_start.claude_session_id = sid.into();
        let eff_compact_start = state.apply(ev_compact_start, None);
        assert_eq!(
            eff_compact_start.signal.unwrap().status,
            AgentStatus::Thinking {
                task_desc: "Thinking…".into()
            }
        );

        let inp_pre_compact = read_json_fixture("hooks/pre_compact.json");
        let mut ev_pre_compact = extract_claude_event(&inp_pre_compact).unwrap();
        ev_pre_compact.claude_session_id = sid.into();
        let eff_pre_compact = state.apply(ev_pre_compact, None);
        assert_eq!(
            eff_pre_compact.signal.unwrap().status,
            AgentStatus::Thinking {
                task_desc: "Compacting context…".into()
            }
        );

        let inp_post_compact = read_json_fixture("hooks/post_compact.json");
        let mut ev_post_compact = extract_claude_event(&inp_post_compact).unwrap();
        ev_post_compact.claude_session_id = sid.into();
        let eff_post_compact = state.apply(ev_post_compact, None);
        assert_eq!(
            eff_post_compact.signal.unwrap().status,
            AgentStatus::Thinking {
                task_desc: "Thinking…".into()
            }
        );

        // 4. Notification elicitation_url_dialog
        let mut inp_url_elicit = read_json_fixture("hooks/notification_elicitation_dialog.json");
        inp_url_elicit.notification_type = Some("elicitation_url_dialog".into());
        let mut ev_url_elicit = extract_claude_event(&inp_url_elicit).unwrap();
        ev_url_elicit.claude_session_id = sid.into();
        let eff_url_elicit = state.apply(ev_url_elicit, None);
        let sig_elicit = eff_url_elicit.signal.unwrap();
        assert!(matches!(
            sig_elicit.attention.unwrap().kind,
            AttentionKind::Ask {
                multi: false,
                initial: 0
            }
        ));

        // 5. Drain open_perms on StopFailure and SessionEnd
        let inp_perm = read_json_fixture("hooks/permission_request_bash.json");
        let mut ev_perm = extract_claude_event(&inp_perm).unwrap();
        ev_perm.claude_session_id = sid.into();
        let att = build_attention_spec(&inp_perm);
        state.apply(ev_perm, Some(att));
        assert_eq!(state.open_perms.len(), 1);

        let inp_stop_fail = read_json_fixture("hooks/stop_failure.json");
        let mut ev_stop_fail = extract_claude_event(&inp_stop_fail).unwrap();
        ev_stop_fail.claude_session_id = sid.into();
        let eff_stop_fail = state.apply(ev_stop_fail, None);
        assert!(!eff_stop_fail.dismiss.is_empty());
        assert!(state.open_perms.is_empty());
        // 6. PermissionRequest drains preceding open_notifs so notif-* cannot shadow perm-*
        let inp_notif = read_json_fixture("hooks/notification_permission_prompt.json");
        let mut ev_notif = extract_claude_event(&inp_notif).unwrap();
        ev_notif.claude_session_id = sid.into();
        let eff_notif = state.apply(ev_notif, None);
        assert!(eff_notif
            .request_key
            .as_deref()
            .is_some_and(|k| k.starts_with("notif-")));
        assert_eq!(state.open_notifs.len(), 1);

        let mut ev_perm2 = extract_claude_event(&inp_perm).unwrap();
        ev_perm2.claude_session_id = sid.into();
        let att2 = build_attention_spec(&inp_perm);
        let eff_perm2 = state.apply(ev_perm2, Some(att2));
        assert!(state.open_notifs.is_empty());
        assert_eq!(eff_perm2.dismiss.len(), 1);
        assert!(eff_perm2.dismiss[0].starts_with("notif-"));
        assert_eq!(
            eff_perm2.signal.unwrap().resolution,
            SignalResolution::ByKeys(eff_perm2.dismiss)
        );
    }
}
