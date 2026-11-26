//! Agent payload event mapping (Brick 7).

use cawide_protocol::types::AgentStatus;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub enum SignalResolution {
    #[default]
    None,
    ByKey(String),
    Approval(Option<String>),
    ClearNonPlan,
    ClearAll,
    ByKeys(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentSignal {
    pub status: AgentStatus,
    pub attention: Option<AttentionSpec>,
    pub outcome: TurnOutcome,
    pub resolution: SignalResolution,
    pub seq: Option<u64>,
    pub epoch: Option<u32>,
}

impl AgentSignal {
    pub fn from_status(status: AgentStatus) -> Self {
        Self {
            status,
            attention: None,
            outcome: TurnOutcome::None,
            resolution: SignalResolution::None,
            seq: None,
            epoch: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttentionSpec {
    pub key: Option<String>,
    pub kind: AttentionKind,
    pub prompt: String,
    pub options: Vec<String>,
    pub actionable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum AttentionKind {
    Approval,
    Ask {
        multi: bool,
        initial: u32,
    },
    Plan {
        review_id: String,
        option_ids: Vec<String>,
    },
    TextQuestion,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TurnOutcome {
    None,
    Started,
    Done,
    Failed { error: String },
    Aborted,
}

pub(crate) fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 32
        && slug
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

pub fn map_signal(
    agent: &str,
    event: Option<&str>,
    payload: &serde_json::Value,
) -> Option<AgentSignal> {
    if !is_valid_slug(agent) {
        return None;
    }

    let resolved_event = event.filter(|e| !e.is_empty()).or_else(|| {
        payload
            .get("hook_event_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    });

    let mut signal = match agent {
        "omp" => map_omp_signal(resolved_event, payload)?,
        _ => return None,
    };

    signal.epoch = payload
        .get("epoch")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());
    signal.seq = payload.get("seq").and_then(|v| v.as_u64());
    Some(signal)
}

pub fn map_event(
    agent: &str,
    event: Option<&str>,
    payload: &serde_json::Value,
) -> Option<AgentStatus> {
    map_signal(agent, event, payload).map(|s| s.status)
}

pub(crate) fn extract_target(tool_input: Option<&serde_json::Value>) -> &str {
    let Some(ti) = tool_input else {
        return "";
    };
    ti.get("command")
        .or_else(|| ti.get("file_path"))
        .or_else(|| ti.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

pub(crate) fn summarize_head(head: &str) -> String {
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

fn map_omp_signal(event: Option<&str>, payload: &serde_json::Value) -> Option<AgentSignal> {
    match event? {
        "before_agent_start" => {
            let prompt = payload.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
            Some(AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: truncate_chars(prompt, 280),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: None,
                epoch: None,
            })
        }
        "agent_start" => Some(AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: "Working".into(),
            },
            attention: None,
            outcome: TurnOutcome::Started,
            resolution: SignalResolution::None,
            seq: None,
            epoch: None,
        }),
        "tool_call" => {
            let tool_name = payload
                .get("toolName")
                .or_else(|| payload.get("tool_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool_call_id = payload
                .get("toolCallId")
                .or_else(|| payload.get("tool_call_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if tool_name == "ask" {
                let question = payload
                    .get("question")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let options: Vec<String> = payload
                    .get("options")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .take(8)
                            .map(|val| {
                                let s = val
                                    .as_str()
                                    .or_else(|| val.get("label").and_then(|l| l.as_str()))
                                    .unwrap_or("");
                                truncate_chars(s, 80)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let multi = payload
                    .get("multi")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let questions_len = payload
                    .get("questionsLength")
                    .or_else(|| payload.get("questions_length"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);
                let recommended = payload
                    .get("recommended")
                    .and_then(|v| v.as_u64())
                    .and_then(|n| u32::try_from(n).ok())
                    .unwrap_or(0);
                let prompt = truncate_chars(question, 280);
                let is_multi = multi || questions_len > 1;
                let actionable = !multi && questions_len == 1;
                Some(AgentSignal {
                    status: AgentStatus::WaitingForInput {
                        prompt: prompt.clone(),
                        options: options.clone(),
                    },
                    attention: Some(AttentionSpec {
                        key: tool_call_id,
                        kind: AttentionKind::Ask {
                            multi: is_multi,
                            initial: recommended,
                        },
                        prompt,
                        options,
                        actionable,
                    }),
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::None,
                    seq: None,
                    epoch: None,
                })
            } else {
                let target = payload
                    .get("command")
                    .or_else(|| payload.get("path"))
                    .or_else(|| payload.get("file_path"))
                    .or_else(|| {
                        payload.get("input").and_then(|inp| {
                            inp.get("command")
                                .or_else(|| inp.get("path"))
                                .or_else(|| inp.get("file_path"))
                        })
                    })
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let desc = if target.is_empty() {
                    format!("Using {tool_name}")
                } else {
                    format!("{tool_name}: {target}")
                };
                Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: truncate_chars(&desc, 280),
                    },
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::None,
                    seq: None,
                    epoch: None,
                })
            }
        }
        "tool_approval_requested" => {
            let tool_call_id = payload
                .get("toolCallId")
                .or_else(|| payload.get("tool_call_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let cmd = payload
                .get("command")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let path = payload
                .get("path")
                .or_else(|| payload.get("file_path"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let tool = payload
                .get("tool")
                .or_else(|| payload.get("toolName"))
                .or_else(|| payload.get("tool_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let prompt_raw = if let Some(r) = reason {
                r.to_string()
            } else if let Some(c) = cmd {
                format!("Run `{c}`?")
            } else if let Some(p) = path {
                match tool {
                    Some(t) => format!("Approve {t}: {p}"),
                    None => format!("Approve {p}"),
                }
            } else if let Some(t) = tool {
                format!("Approve {t}")
            } else {
                "Approve tool execution?".to_string()
            };
            let prompt = truncate_chars(&prompt_raw, 280);
            let options = vec!["Allow once".into(), "Deny".into()];
            Some(AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: prompt.clone(),
                    options: options.clone(),
                },
                attention: Some(AttentionSpec {
                    key: tool_call_id,
                    kind: AttentionKind::Approval,
                    prompt,
                    options,
                    actionable: true,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: None,
                epoch: None,
            })
        }
        "plan_review_requested" => {
            let review_id = payload
                .get("reviewId")
                .or_else(|| payload.get("review_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let title = payload
                .get("title")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("Review plan");
            let mut option_labels = Vec::new();
            let mut option_ids = Vec::new();
            if let Some(arr) = payload.get("options").and_then(|v| v.as_array()) {
                for item in arr {
                    if item.get("disabled").and_then(|v| v.as_bool()) == Some(true) {
                        continue;
                    }
                    let id = item
                        .get("id")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.as_str())
                        .unwrap_or("");
                    if id.is_empty() || id == "refine" || id == "save" {
                        continue;
                    }
                    let label = item
                        .get("label")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.as_str())
                        .unwrap_or(id);
                    if label.is_empty() {
                        continue;
                    }
                    option_ids.push(id.to_string());
                    option_labels.push(truncate_chars(label, 80));
                    if option_labels.len() >= 8 {
                        break;
                    }
                }
            }
            let prompt = truncate_chars(title, 280);
            let key = (!review_id.is_empty()).then(|| review_id.clone());
            Some(AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: prompt.clone(),
                    options: option_labels.clone(),
                },
                attention: Some(AttentionSpec {
                    key,
                    kind: AttentionKind::Plan {
                        review_id,
                        option_ids,
                    },
                    prompt,
                    options: option_labels,
                    actionable: true,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: None,
                epoch: None,
            })
        }
        "plan_review_resolved" => {
            let review_id = payload
                .get("reviewId")
                .or_else(|| payload.get("review_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Some(AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "Thinking…".into(),
                },
                attention: None,
                outcome: TurnOutcome::None,
                resolution: review_id
                    .map(SignalResolution::ByKey)
                    .unwrap_or(SignalResolution::None),
                seq: None,
                epoch: None,
            })
        }
        "tool_approval_resolved" => {
            let tool_call_id = payload
                .get("toolCallId")
                .or_else(|| payload.get("tool_call_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Some(AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "Thinking…".into(),
                },
                attention: None,
                outcome: TurnOutcome::None,
                resolution: SignalResolution::Approval(tool_call_id),
                seq: None,
                epoch: None,
            })
        }
        "tool_result" => {
            let tool_call_id = payload
                .get("toolCallId")
                .or_else(|| payload.get("tool_call_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Some(AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "Thinking…".into(),
                },
                attention: None,
                outcome: TurnOutcome::None,
                resolution: tool_call_id
                    .map(SignalResolution::ByKey)
                    .unwrap_or(SignalResolution::None),
                seq: None,
                epoch: None,
            })
        }
        "agent_end" => {
            if payload.get("awaitingAsyncWork").and_then(|v| v.as_bool()) == Some(true) {
                return Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: "Waiting for background jobs".into(),
                    },
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::ClearNonPlan,
                    seq: None,
                    epoch: None,
                });
            }
            if payload.get("willContinue").and_then(|v| v.as_bool()) == Some(true) {
                return Some(AgentSignal {
                    status: AgentStatus::Thinking {
                        task_desc: "Continuing…".into(),
                    },
                    attention: None,
                    outcome: TurnOutcome::None,
                    resolution: SignalResolution::ClearNonPlan,
                    seq: None,
                    epoch: None,
                });
            }
            let stop_reason = payload
                .get("stopReason")
                .or_else(|| payload.get("stop_reason"))
                .and_then(|v| v.as_str());
            if stop_reason == Some("error") {
                let err_msg = payload
                    .get("errorMessage")
                    .or_else(|| payload.get("error_message"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Agent error");
                return Some(AgentSignal {
                    status: AgentStatus::Completed {
                        summary: truncate_chars(&format!("Error: {err_msg}"), 280),
                    },
                    attention: None,
                    outcome: TurnOutcome::Failed {
                        error: truncate_chars(err_msg, 500),
                    },
                    resolution: SignalResolution::ClearNonPlan,
                    seq: None,
                    epoch: None,
                });
            }
            if stop_reason == Some("aborted") {
                return Some(AgentSignal {
                    status: AgentStatus::Idle,
                    attention: None,
                    outcome: TurnOutcome::Aborted,
                    resolution: SignalResolution::ClearNonPlan,
                    seq: None,
                    epoch: None,
                });
            }

            let final_text_head = payload
                .get("finalTextHead")
                .or_else(|| payload.get("finalText"))
                .or_else(|| payload.get("summary"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(AgentSignal {
                status: AgentStatus::Completed {
                    summary: summarize_head(final_text_head),
                },
                attention: None,
                outcome: TurnOutcome::Done,
                resolution: SignalResolution::ClearNonPlan,
                seq: None,
                epoch: None,
            })
        }
        "session_shutdown" => Some(AgentSignal {
            status: AgentStatus::Idle,
            attention: None,
            outcome: TurnOutcome::None,
            resolution: SignalResolution::ClearAll,
            seq: None,
            epoch: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_invalid_slug() {
        assert_eq!(map_event("Claude", Some("SessionStart"), &json!({})), None);
        assert_eq!(
            map_event("claude_code", Some("SessionStart"), &json!({})),
            None
        );
        assert_eq!(map_event("", Some("SessionStart"), &json!({})), None);
        let too_long = "a".repeat(33);
        assert_eq!(map_event(&too_long, Some("SessionStart"), &json!({})), None);
    }

    #[test]
    fn test_omp_events() {
        assert_eq!(
            map_event(
                "omp",
                Some("before_agent_start"),
                &json!({ "prompt": "build feature X" })
            ),
            Some(AgentStatus::Thinking {
                task_desc: "build feature X".into()
            })
        );
        assert_eq!(
            map_event("omp", Some("agent_start"), &json!({})),
            Some(AgentStatus::Thinking {
                task_desc: "Working".into()
            })
        );
        assert_eq!(
            map_event(
                "omp",
                Some("tool_call"),
                &json!({
                    "toolName": "ask",
                    "question": "Choose an option",
                    "options": ["A", "B"]
                })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Choose an option".into(),
                options: vec!["A".into(), "B".into()]
            })
        );
        assert_eq!(
            map_event("omp", Some("tool_call"), &json!({ "toolName": "read" })),
            Some(AgentStatus::Thinking {
                task_desc: "Using read".into()
            })
        );
        assert_eq!(
            map_event(
                "omp",
                Some("tool_call"),
                &json!({ "toolName": "bash", "command": "cargo test" })
            ),
            Some(AgentStatus::Thinking {
                task_desc: "bash: cargo test".into()
            })
        );
        assert_eq!(
            map_event(
                "omp",
                Some("tool_approval_requested"),
                &json!({ "reason": "Allow running dangerous command?", "tool": "bash" })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Allow running dangerous command?".into(),
                options: vec!["Allow once".into(), "Deny".into()]
            })
        );
        assert_eq!(
            map_event("omp", Some("tool_approval_resolved"), &json!({})),
            Some(AgentStatus::Thinking {
                task_desc: "Thinking…".into()
            })
        );
        assert_eq!(
            map_event("omp", Some("tool_result"), &json!({})),
            Some(AgentStatus::Thinking {
                task_desc: "Thinking…".into()
            })
        );
        assert_eq!(
            map_event(
                "omp",
                Some("agent_end"),
                &json!({ "willContinue": true, "summary": "part 1 done" })
            ),
            Some(AgentStatus::Thinking {
                task_desc: "Continuing…".into()
            })
        );
        assert_eq!(
            map_event("omp", Some("agent_end"), &json!({})),
            Some(AgentStatus::Completed { summary: "".into() })
        );
        assert_eq!(
            map_event("omp", Some("session_shutdown"), &json!({})),
            Some(AgentStatus::Idle)
        );
    }

    #[test]
    fn test_truncation() {
        let long_prompt = "x".repeat(350);
        let res = map_event(
            "omp",
            Some("before_agent_start"),
            &json!({ "prompt": long_prompt }),
        );
        match res {
            Some(AgentStatus::Thinking { task_desc }) => {
                assert_eq!(task_desc.chars().count(), 280);
            }
            other => panic!("expected Thinking, got {other:?}"),
        }

        let long_opt = "y".repeat(120);
        let options: Vec<String> = (0..12).map(|_| long_opt.clone()).collect();
        let res = map_event(
            "omp",
            Some("tool_call"),
            &json!({
                "toolName": "ask",
                "question": "q",
                "options": options
            }),
        );
        match res {
            Some(AgentStatus::WaitingForInput { options, .. }) => {
                assert_eq!(options.len(), 8);
                for opt in options {
                    assert_eq!(opt.chars().count(), 80);
                }
            }
            other => panic!("expected WaitingForInput, got {other:?}"),
        }
    }

    #[test]
    fn test_omp_map_signal_full() {
        let sig = map_signal(
            "omp",
            Some("before_agent_start"),
            &json!({ "prompt": "fix bug", "epoch": 7, "seq": 1 }),
        )
        .unwrap();
        assert_eq!(sig.outcome, TurnOutcome::Started);
        assert_eq!(sig.epoch, Some(7));
        assert_eq!(sig.seq, Some(1));

        let ask_single = map_signal(
            "omp",
            Some("tool_call"),
            &json!({
                "toolName": "ask",
                "toolCallId": "tc-1",
                "question": "Pick one",
                "options": ["A", "B"],
                "questionsLength": 1,
                "multi": false,
                "recommended": 1
            }),
        )
        .unwrap();
        assert_eq!(
            ask_single.attention,
            Some(AttentionSpec {
                key: Some("tc-1".into()),
                kind: AttentionKind::Ask {
                    multi: false,
                    initial: 1
                },
                prompt: "Pick one".into(),
                options: vec!["A".into(), "B".into()],
                actionable: true,
            })
        );

        let ask_multi = map_signal(
            "omp",
            Some("tool_call"),
            &json!({
                "toolName": "ask",
                "toolCallId": "tc-2",
                "question": "Pick many",
                "options": ["A", "B"],
                "questionsLength": 2,
                "multi": false
            }),
        )
        .unwrap();
        assert!(!ask_multi.attention.as_ref().unwrap().actionable);
        assert_eq!(
            ask_multi.attention.as_ref().unwrap().kind,
            AttentionKind::Ask {
                multi: true,
                initial: 0
            }
        );

        let approval = map_signal(
            "omp",
            Some("tool_approval_requested"),
            &json!({ "toolName": "bash", "toolCallId": "tc-3", "command": "rm -rf /tmp/x" }),
        )
        .unwrap();
        assert_eq!(
            approval.attention,
            Some(AttentionSpec {
                key: Some("tc-3".into()),
                kind: AttentionKind::Approval,
                prompt: "Run `rm -rf /tmp/x`?".into(),
                options: vec!["Allow once".into(), "Deny".into()],
                actionable: true,
            })
        );

        let plan = map_signal(
            "omp",
            Some("plan_review_requested"),
            &json!({
                "reviewId": "rev-1",
                "title": "Approve plan?",
                "options": [
                    { "id": "execute", "label": "Execute" },
                    { "id": "refine", "label": "Refine" },
                    { "id": "save", "label": "Save" },
                    { "id": "keep", "label": "Keep", "disabled": false },
                    { "id": "other", "label": "Disabled", "disabled": true }
                ]
            }),
        )
        .unwrap();
        assert_eq!(
            plan.attention,
            Some(AttentionSpec {
                key: Some("rev-1".into()),
                kind: AttentionKind::Plan {
                    review_id: "rev-1".into(),
                    option_ids: vec!["execute".into(), "keep".into()],
                },
                prompt: "Approve plan?".into(),
                options: vec!["Execute".into(), "Keep".into()],
                actionable: true,
            })
        );

        let plan_res = map_signal(
            "omp",
            Some("plan_review_resolved"),
            &json!({ "reviewId": "rev-1", "choice": "execute" }),
        )
        .unwrap();
        assert_eq!(plan_res.resolution, SignalResolution::ByKey("rev-1".into()));

        let app_res = map_signal(
            "omp",
            Some("tool_approval_resolved"),
            &json!({ "approved": true }),
        )
        .unwrap();
        assert_eq!(app_res.resolution, SignalResolution::Approval(None));

        let async_end = map_signal(
            "omp",
            Some("agent_end"),
            &json!({ "awaitingAsyncWork": true, "willContinue": true }),
        )
        .unwrap();
        assert_eq!(
            async_end.status,
            AgentStatus::Thinking {
                task_desc: "Waiting for background jobs".into()
            }
        );

        let err_end = map_signal(
            "omp",
            Some("agent_end"),
            &json!({ "stopReason": "error", "errorMessage": "rate limit" }),
        )
        .unwrap();
        assert_eq!(
            err_end.status,
            AgentStatus::Completed {
                summary: "Error: rate limit".into()
            }
        );
        assert_eq!(
            err_end.outcome,
            TurnOutcome::Failed {
                error: "rate limit".into()
            }
        );

        let abort_end = map_signal(
            "omp",
            Some("agent_end"),
            &json!({ "stopReason": "aborted" }),
        )
        .unwrap();
        assert_eq!(abort_end.status, AgentStatus::Idle);
        assert_eq!(abort_end.outcome, TurnOutcome::Aborted);

        let done_end = map_signal(
            "omp",
            Some("agent_end"),
            &json!({
                "finalTextHead": "\nFirst line.\nSecond line.\n",
                "finalTextTail": "All done."
            }),
        )
        .unwrap();
        assert_eq!(
            done_end.status,
            AgentStatus::Completed {
                summary: "First line. Second line.".into()
            }
        );
        assert_eq!(done_end.outcome, TurnOutcome::Done);

        let shutdown = map_signal("omp", Some("session_shutdown"), &json!({})).unwrap();
        assert_eq!(shutdown.status, AgentStatus::Idle);
        assert_eq!(shutdown.resolution, SignalResolution::ClearAll);
    }

    #[test]
    fn test_omp_agent_end_never_infers_text_question() {
        let cases = [
            "Should I proceed?",
            "Proceed (y/n)",
            "Continue [Y/n]",
            "Options:\n- Fast\n- Safe\n- Minimal\n\nWhich mode should I use?",
        ];
        for text in cases {
            let sig = map_signal(
                "omp",
                Some("agent_end"),
                &json!({
                    "finalTextHead": text,
                    "finalTextTail": text,
                }),
            )
            .unwrap();
            assert!(
                !matches!(sig.status, AgentStatus::WaitingForInput { .. }),
                "agent_end must never infer WaitingForInput for {text:?}"
            );
            assert!(
                matches!(sig.status, AgentStatus::Completed { .. }),
                "expected Completed for {text:?}, got {:?}",
                sig.status
            );
            assert_eq!(sig.attention, None);
            assert_eq!(sig.outcome, TurnOutcome::Done);
            assert_eq!(sig.resolution, SignalResolution::ClearNonPlan);
        }
    }
}
