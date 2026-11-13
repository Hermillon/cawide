//! Agent payload event mapping (Brick 7).

use cawide_protocol::types::AgentStatus;

fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 32
        && slug
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

pub fn map_event(
    agent: &str,
    event: Option<&str>,
    payload: &serde_json::Value,
) -> Option<AgentStatus> {
    if !is_valid_slug(agent) {
        return None;
    }

    let resolved_event = event.filter(|e| !e.is_empty()).or_else(|| {
        payload
            .get("hook_event_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    });

    match agent {
        "claude" => map_claude(resolved_event, payload),
        "codex" => map_codex(resolved_event, payload),
        "omp" => map_omp(resolved_event, payload),
        "opencode" => map_opencode(resolved_event, payload),
        _ => None,
    }
}

fn extract_target(tool_input: Option<&serde_json::Value>) -> &str {
    let Some(ti) = tool_input else {
        return "";
    };
    ti.get("command")
        .or_else(|| ti.get("file_path"))
        .or_else(|| ti.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn map_claude(event: Option<&str>, payload: &serde_json::Value) -> Option<AgentStatus> {
    match event? {
        "SessionStart" | "SessionEnd" => Some(AgentStatus::Idle),
        "UserPromptSubmit" => {
            let prompt = payload.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
            Some(AgentStatus::Thinking {
                task_desc: truncate_chars(prompt, 280),
            })
        }
        "PermissionRequest" => {
            let tool_name = payload
                .get("tool_name")
                .or_else(|| payload.get("toolName"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool_input = payload
                .get("tool_input")
                .or_else(|| payload.get("toolInput"));
            let target = extract_target(tool_input);
            let prompt = if target.is_empty() {
                format!("Approve {tool_name}")
            } else {
                format!("Approve {tool_name}: {target}")
            };
            Some(AgentStatus::WaitingForInput {
                prompt: truncate_chars(&prompt, 280),
                options: vec!["Allow".into(), "Deny".into()],
            })
        }
        "PreToolUse" => {
            let tool_name = payload
                .get("tool_name")
                .or_else(|| payload.get("toolName"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if tool_name == "AskUserQuestion" {
                let q_obj = payload
                    .get("tool_input")
                    .or_else(|| payload.get("toolInput"))
                    .and_then(|ti| ti.get("questions"))
                    .or_else(|| payload.get("questions"))
                    .and_then(|q| q.get(0));
                let question = q_obj
                    .and_then(|q| q.get("question"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let options = q_obj
                    .and_then(|q| q.get("options"))
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
                Some(AgentStatus::WaitingForInput {
                    prompt: truncate_chars(question, 280),
                    options,
                })
            } else if tool_name == "ExitPlanMode" {
                Some(AgentStatus::WaitingForInput {
                    prompt: "Approve plan implementation?".into(),
                    options: vec!["Approve".into(), "Revise".into()],
                })
            } else {
                let tool_input = payload
                    .get("tool_input")
                    .or_else(|| payload.get("toolInput"));
                let target = extract_target(tool_input);
                let desc = if target.is_empty() {
                    format!("Using {tool_name}")
                } else {
                    format!("{tool_name}: {target}")
                };
                Some(AgentStatus::Thinking {
                    task_desc: truncate_chars(&desc, 280),
                })
            }
        }
        "PostToolUse" => Some(AgentStatus::Thinking {
            task_desc: "Thinking…".into(),
        }),
        "Notification" => match payload.get("notification_type").and_then(|v| v.as_str()) {
            Some("permission_prompt" | "elicitation_dialog") => {
                let msg = payload
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                Some(AgentStatus::WaitingForInput {
                    prompt: truncate_chars(msg, 280),
                    options: Vec::new(),
                })
            }
            _ => None,
        },
        "Stop" => {
            let summary = payload
                .get("last_assistant_message")
                .or_else(|| payload.get("last-assistant-message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(AgentStatus::Completed {
                summary: truncate_chars(summary, 280),
            })
        }
        _ => None,
    }
}

fn map_codex(event: Option<&str>, payload: &serde_json::Value) -> Option<AgentStatus> {
    if event.is_none()
        && payload.get("type").and_then(|v| v.as_str()) == Some("agent-turn-complete")
    {
        let summary = payload
            .get("last-assistant-message")
            .or_else(|| payload.get("last_assistant_message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        return Some(AgentStatus::Completed {
            summary: truncate_chars(summary, 280),
        });
    }

    match event? {
        "SessionStart" | "SessionEnd" => Some(AgentStatus::Idle),
        "UserPromptSubmit" => {
            let prompt = payload.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
            Some(AgentStatus::Thinking {
                task_desc: truncate_chars(prompt, 280),
            })
        }
        "PermissionRequest" => {
            let tool_name = payload
                .get("tool_name")
                .or_else(|| payload.get("toolName"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool_input = payload
                .get("tool_input")
                .or_else(|| payload.get("toolInput"));
            let target = extract_target(tool_input);
            let prompt = if target.is_empty() {
                format!("Approve {tool_name}")
            } else {
                format!("Approve {tool_name}: {target}")
            };
            Some(AgentStatus::WaitingForInput {
                prompt: truncate_chars(&prompt, 280),
                options: vec!["Allow".into(), "Deny".into()],
            })
        }
        "PreToolUse" => {
            let tool_name = payload
                .get("tool_name")
                .or_else(|| payload.get("toolName"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool_input = payload
                .get("tool_input")
                .or_else(|| payload.get("toolInput"));
            let target = extract_target(tool_input);
            let desc = if target.is_empty() {
                format!("Using {tool_name}")
            } else {
                format!("{tool_name}: {target}")
            };
            Some(AgentStatus::Thinking {
                task_desc: truncate_chars(&desc, 280),
            })
        }
        "PostToolUse" => Some(AgentStatus::Thinking {
            task_desc: "Thinking…".into(),
        }),
        "Stop" => {
            let summary = payload
                .get("last_assistant_message")
                .or_else(|| payload.get("last-assistant-message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(AgentStatus::Completed {
                summary: truncate_chars(summary, 280),
            })
        }
        _ => None,
    }
}

fn map_omp(event: Option<&str>, payload: &serde_json::Value) -> Option<AgentStatus> {
    match event? {
        "before_agent_start" => {
            let prompt = payload.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
            Some(AgentStatus::Thinking {
                task_desc: truncate_chars(prompt, 280),
            })
        }
        "agent_start" => Some(AgentStatus::Thinking {
            task_desc: "Working".into(),
        }),
        "tool_call" => {
            let tool_name = payload
                .get("toolName")
                .or_else(|| payload.get("tool_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if tool_name == "ask" {
                let question = payload
                    .get("question")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let options = payload
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
                Some(AgentStatus::WaitingForInput {
                    prompt: truncate_chars(question, 280),
                    options,
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
                Some(AgentStatus::Thinking {
                    task_desc: truncate_chars(&desc, 280),
                })
            }
        }
        "tool_approval_requested" => {
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    let tool = payload
                        .get("tool")
                        .or_else(|| payload.get("toolName"))
                        .or_else(|| payload.get("tool_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if tool.is_empty() {
                        "Approve tool execution?".into()
                    } else {
                        format!("Approve {tool}")
                    }
                });
            Some(AgentStatus::WaitingForInput {
                prompt: truncate_chars(&reason, 280),
                options: vec!["Allow".into(), "Deny".into()],
            })
        }
        "tool_approval_resolved" | "tool_result" => Some(AgentStatus::Thinking {
            task_desc: "Thinking…".into(),
        }),
        "agent_end" => {
            if payload.get("willContinue") == Some(&serde_json::Value::Bool(true)) {
                return None;
            }
            let summary = payload
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(AgentStatus::Completed {
                summary: truncate_chars(summary, 280),
            })
        }
        "session_shutdown" => Some(AgentStatus::Idle),
        _ => None,
    }
}

fn map_opencode(event: Option<&str>, payload: &serde_json::Value) -> Option<AgentStatus> {
    match event? {
        "session.status" => {
            if payload
                .get("status")
                .and_then(|s| s.get("type"))
                .and_then(|v| v.as_str())
                == Some("busy")
            {
                Some(AgentStatus::Thinking {
                    task_desc: "Working".into(),
                })
            } else {
                None
            }
        }
        "permission.asked" => {
            let action = payload
                .get("action")
                .or_else(|| payload.get("permission"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let resources = payload
                .get("resources")
                .or_else(|| payload.get("patterns"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let prompt = if action.is_empty() && resources.is_empty() {
                "Approve permission request".to_string()
            } else if resources.is_empty() {
                format!("Approve {action}")
            } else if action.is_empty() {
                format!("Approve {resources}")
            } else {
                format!("Approve {action}: {resources}")
            };
            Some(AgentStatus::WaitingForInput {
                prompt: truncate_chars(&prompt, 280),
                options: vec!["Allow once".into(), "Always allow".into(), "Deny".into()],
            })
        }
        "session.reasoning.started" | "session.reasoning.delta" => {
            let delta = payload
                .get("text")
                .or_else(|| payload.get("delta"))
                .or_else(|| payload.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("Thinking…");
            Some(AgentStatus::Thinking {
                task_desc: truncate_chars(delta, 280),
            })
        }
        "session.tool.called" => {
            let tool = payload
                .get("tool")
                .or_else(|| payload.get("toolName"))
                .or_else(|| payload.get("tool_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cmd = payload
                .get("command")
                .or_else(|| payload.get("cmd"))
                .or_else(|| payload.get("input").and_then(|i| i.get("command")))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let desc = if cmd.is_empty() {
                format!("Using {tool}")
            } else if tool.is_empty() {
                cmd.to_string()
            } else {
                format!("{tool}: {cmd}")
            };
            Some(AgentStatus::Thinking {
                task_desc: truncate_chars(&desc, 280),
            })
        }
        "session.tool.success" | "session.tool.failed" => Some(AgentStatus::Thinking {
            task_desc: "Thinking…".into(),
        }),
        "form.created" => {
            let title = payload
                .get("title")
                .or_else(|| payload.get("prompt"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut options = Vec::new();
            if let Some(arr) = payload.get("options").and_then(|v| v.as_array()) {
                for item in arr.iter().take(8) {
                    if let Some(s) = item.as_str() {
                        options.push(truncate_chars(s, 80));
                    } else if let Some(s) = item
                        .get("label")
                        .or_else(|| item.get("value"))
                        .and_then(|v| v.as_str())
                    {
                        options.push(truncate_chars(s, 80));
                    }
                }
            } else if let Some(fields) = payload.get("fields").and_then(|v| v.as_array()) {
                for field in fields.iter().take(8) {
                    if let Some(field_opts) = field.get("options").and_then(|v| v.as_array()) {
                        for item in field_opts.iter().take(8 - options.len()) {
                            if let Some(s) = item.as_str() {
                                options.push(truncate_chars(s, 80));
                            } else if let Some(s) = item
                                .get("label")
                                .or_else(|| item.get("value"))
                                .and_then(|v| v.as_str())
                            {
                                options.push(truncate_chars(s, 80));
                            }
                        }
                    }
                }
            }
            Some(AgentStatus::WaitingForInput {
                prompt: truncate_chars(title, 280),
                options,
            })
        }
        "session.idle" => Some(AgentStatus::Completed {
            summary: String::new(),
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
    fn test_claude_and_codex_lifecycle() {
        for agent in &["claude", "codex"] {
            assert_eq!(
                map_event(agent, Some("SessionStart"), &json!({})),
                Some(AgentStatus::Idle)
            );
            assert_eq!(
                map_event(agent, Some("SessionEnd"), &json!({})),
                Some(AgentStatus::Idle)
            );
            assert_eq!(
                map_event(
                    agent,
                    Some("UserPromptSubmit"),
                    &json!({ "prompt": "build features" })
                ),
                Some(AgentStatus::Thinking {
                    task_desc: "build features".into()
                })
            );
            assert_eq!(
                map_event(agent, Some("PreToolUse"), &json!({ "tool_name": "grep" })),
                Some(AgentStatus::Thinking {
                    task_desc: "Using grep".into()
                })
            );
            assert_eq!(
                map_event(
                    agent,
                    Some("Stop"),
                    &json!({ "last_assistant_message": "All done!" })
                ),
                Some(AgentStatus::Completed {
                    summary: "All done!".into()
                })
            );
        }
    }

    #[test]
    fn test_claude_notifications() {
        assert_eq!(
            map_event(
                "claude",
                Some("Notification"),
                &json!({
                    "notification_type": "permission_prompt",
                    "message": "Allow bash execution?"
                })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Allow bash execution?".into(),
                options: vec![]
            })
        );
        assert_eq!(
            map_event(
                "claude",
                Some("Notification"),
                &json!({
                    "notification_type": "elicitation_dialog",
                    "message": "Which file do you mean?"
                })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Which file do you mean?".into(),
                options: vec![]
            })
        );
        assert_eq!(
            map_event(
                "claude",
                Some("Notification"),
                &json!({
                    "notification_type": "idle_prompt",
                    "message": "Still there?"
                })
            ),
            None
        );
    }

    #[test]
    fn test_codex_legacy_notify() {
        assert_eq!(
            map_event(
                "codex",
                None,
                &json!({
                    "type": "agent-turn-complete",
                    "last-assistant-message": "Fixed build"
                })
            ),
            Some(AgentStatus::Completed {
                summary: "Fixed build".into()
            })
        );
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
                options: vec!["Allow".into(), "Deny".into()]
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
            None
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
    fn test_opencode_events() {
        assert_eq!(
            map_event(
                "opencode",
                Some("session.status"),
                &json!({ "sessionID": "s", "status": { "type": "busy" } })
            ),
            Some(AgentStatus::Thinking {
                task_desc: "Working".into()
            })
        );
        assert_eq!(
            map_event(
                "opencode",
                Some("permission.asked"),
                &json!({
                    "action": "bash",
                    "resources": ["cargo build", "cargo test"]
                })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Approve bash: cargo build, cargo test".into(),
                options: vec!["Allow once".into(), "Always allow".into(), "Deny".into()]
            })
        );
        assert_eq!(
            map_event(
                "opencode",
                Some("session.reasoning.delta"),
                &json!({ "text": "Formulating architecture plan" })
            ),
            Some(AgentStatus::Thinking {
                task_desc: "Formulating architecture plan".into()
            })
        );
        assert_eq!(
            map_event(
                "opencode",
                Some("session.tool.called"),
                &json!({ "tool": "bash", "command": "cargo build" })
            ),
            Some(AgentStatus::Thinking {
                task_desc: "bash: cargo build".into()
            })
        );
        assert_eq!(
            map_event("opencode", Some("session.tool.success"), &json!({})),
            Some(AgentStatus::Thinking {
                task_desc: "Thinking…".into()
            })
        );
        assert_eq!(
            map_event(
                "opencode",
                Some("form.created"),
                &json!({ "title": "Select target platform", "options": ["macOS", "Linux"] })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Select target platform".into(),
                options: vec!["macOS".into(), "Linux".into()]
            })
        );
        assert_eq!(
            map_event("opencode", Some("session.idle"), &json!({})),
            Some(AgentStatus::Completed { summary: "".into() })
        );
    }

    #[test]
    fn test_claude_and_codex_extended() {
        for agent in &["claude", "codex"] {
            assert_eq!(
                map_event(
                    agent,
                    Some("PermissionRequest"),
                    &json!({
                        "tool_name": "Bash",
                        "tool_input": { "command": "rm -rf /tmp/foo" }
                    })
                ),
                Some(AgentStatus::WaitingForInput {
                    prompt: "Approve Bash: rm -rf /tmp/foo".into(),
                    options: vec!["Allow".into(), "Deny".into()]
                })
            );
            assert_eq!(
                map_event(
                    agent,
                    Some("PreToolUse"),
                    &json!({
                        "tool_name": "FileEdit",
                        "tool_input": { "file_path": "src/main.rs" }
                    })
                ),
                Some(AgentStatus::Thinking {
                    task_desc: "FileEdit: src/main.rs".into()
                })
            );
            assert_eq!(
                map_event(agent, Some("PostToolUse"), &json!({})),
                Some(AgentStatus::Thinking {
                    task_desc: "Thinking…".into()
                })
            );
        }

        assert_eq!(
            map_event(
                "claude",
                Some("PreToolUse"),
                &json!({
                    "tool_name": "AskUserQuestion",
                    "tool_input": {
                        "questions": [
                            {
                                "question": "Should we proceed?",
                                "options": ["Yes", "No"]
                            }
                        ]
                    }
                })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Should we proceed?".into(),
                options: vec!["Yes".into(), "No".into()]
            })
        );

        assert_eq!(
            map_event(
                "claude",
                Some("PreToolUse"),
                &json!({ "tool_name": "ExitPlanMode" })
            ),
            Some(AgentStatus::WaitingForInput {
                prompt: "Approve plan implementation?".into(),
                options: vec!["Approve".into(), "Revise".into()]
            })
        );
    }

    #[test]
    fn test_truncation() {
        let long_prompt = "x".repeat(350);
        let res = map_event(
            "claude",
            Some("UserPromptSubmit"),
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
}
