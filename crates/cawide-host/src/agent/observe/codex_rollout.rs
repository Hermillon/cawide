use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{ExtState, ObservedEvent};

const DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct RolloutEntry {
    path: Option<PathBuf>,
    offset: u64,
    partial: String,
    last_search: Option<Instant>,
    state: ExtState,
}

#[derive(Debug, Default)]
pub struct RolloutTailer {
    codex_home: PathBuf,
    entries: HashMap<String, RolloutEntry>,
}

impl RolloutTailer {
    pub fn new(codex_home: PathBuf) -> Self {
        Self {
            codex_home,
            entries: HashMap::new(),
        }
    }

    pub fn retain_roots(&mut self, active_roots: &[String]) {
        self.entries
            .retain(|id, _| active_roots.iter().any(|r| r == id));
    }

    pub fn poll_root(&mut self, root_id: &str) -> Vec<ObservedEvent> {
        let now = Instant::now();
        let entry = self
            .entries
            .entry(root_id.to_string())
            .or_insert_with(|| RolloutEntry {
                path: None,
                offset: 0,
                partial: String::new(),
                last_search: None,
                state: ExtState::default(),
            });

        if entry.path.is_none() {
            let should_search = entry
                .last_search
                .is_none_or(|t| now.duration_since(t) >= DISCOVERY_RETRY_INTERVAL);
            if !should_search {
                return Vec::new();
            }
            entry.last_search = Some(now);
            if let Some(found) = find_rollout_file(&self.codex_home, root_id) {
                if let Ok(mut file) = File::open(&found) {
                    if let Ok(end) = file.seek(SeekFrom::End(0)) {
                        entry.offset = end;
                    }
                }
                entry.path = Some(found);
            } else {
                return Vec::new();
            }
        }

        let Some(path) = entry.path.as_ref() else {
            return Vec::new();
        };

        let Ok(mut file) = File::open(path) else {
            return Vec::new();
        };
        let Ok(len) = file.metadata().map(|m| m.len()) else {
            return Vec::new();
        };
        if len < entry.offset {
            entry.offset = 0;
            entry.partial.clear();
        }
        if len == entry.offset {
            return Vec::new();
        }
        if file.seek(SeekFrom::Start(entry.offset)).is_err() {
            return Vec::new();
        }

        let mut reader = BufReader::new(file);
        let mut events = Vec::new();
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    entry.offset += n as u64;
                    if buf.ends_with('\n') {
                        let line = if entry.partial.is_empty() {
                            buf.trim_end_matches(['\r', '\n']).to_string()
                        } else {
                            let mut combined = std::mem::take(&mut entry.partial);
                            combined.push_str(buf.trim_end_matches(['\r', '\n']));
                            combined
                        };
                        if !line.is_empty() {
                            if let Ok(val) = serde_json::from_str::<Value>(&line) {
                                if let Some(ev) = translate_rollout_line(&val, &mut entry.state) {
                                    events.push(ev);
                                }
                            }
                        }
                    } else {
                        entry.partial.push_str(&buf);
                    }
                }
                Err(_) => break,
            }
        }
        events
    }
}

pub fn find_rollout_file(codex_home: &Path, root_id: &str) -> Option<PathBuf> {
    let sessions_dir = codex_home.join("sessions");
    let suffix = format!("-{root_id}.jsonl");
    let years = std::fs::read_dir(&sessions_dir).ok()?;
    for year in years.flatten() {
        let year_path = year.path();
        if !year_path.is_dir() {
            continue;
        }
        let Ok(months) = std::fs::read_dir(&year_path) else {
            continue;
        };
        for month in months.flatten() {
            let month_path = month.path();
            if !month_path.is_dir() {
                continue;
            }
            let Ok(days) = std::fs::read_dir(&month_path) else {
                continue;
            };
            for day in days.flatten() {
                let day_path = day.path();
                if !day_path.is_dir() {
                    continue;
                }
                let Ok(files) = std::fs::read_dir(&day_path) else {
                    continue;
                };
                for file in files.flatten() {
                    let file_path = file.path();
                    if let Some(name) = file_path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("rollout-") && name.ends_with(&suffix) {
                            return Some(file_path);
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn translate_rollout_line(val: &Value, state: &mut ExtState) -> Option<ObservedEvent> {
    let line_type = val.get("type").and_then(|v| v.as_str())?;
    let payload = val.get("payload")?;

    match line_type {
        "event_msg" => {
            let payload_type = payload.get("type").and_then(|v| v.as_str())?;
            match payload_type {
                "task_started" => {
                    state.active_turn = true;
                    state.last_text.clear();
                    Some(ObservedEvent::TurnStarted)
                }
                "item_completed" => {
                    let item = payload.get("item")?;
                    if item.get("type").and_then(|v| v.as_str()) == Some("UserMessage") {
                        let text =
                            item.get("content")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| {
                                    arr.iter().find_map(|part| {
                                        part.get("text")
                                            .and_then(|t| t.as_str())
                                            .filter(|s| !s.is_empty())
                                    })
                                })?;
                        Some(ObservedEvent::Activity {
                            desc: text.to_string(),
                        })
                    } else {
                        None
                    }
                }
                "task_complete" => {
                    state.active_turn = false;
                    let summary = payload
                        .get("last_agent_message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    state.last_text = summary.clone();
                    Some(ObservedEvent::TurnCompleted { summary })
                }
                "turn_aborted" => {
                    state.active_turn = false;
                    Some(ObservedEvent::TurnInterrupted)
                }
                _ => None,
            }
        }
        "response_item" => {
            let payload_type = payload.get("type").and_then(|v| v.as_str())?;
            if payload_type == "function_call" {
                let name = payload.get("name").and_then(|v| v.as_str())?;
                let desc = if name == "exec_command" {
                    payload
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .and_then(|args| serde_json::from_str::<Value>(args).ok())
                        .and_then(|v| {
                            v.get("cmd")
                                .and_then(|c| c.as_str())
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                        })
                        .unwrap_or_else(|| "exec_command".to_string())
                } else {
                    name.to_string()
                };
                Some(ObservedEvent::Activity { desc })
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn test_translate_rollout_line_events() {
        let mut state = ExtState::default();

        let started = json!({
            "type": "event_msg",
            "payload": { "type": "task_started" }
        });
        assert_eq!(
            translate_rollout_line(&started, &mut state),
            Some(ObservedEvent::TurnStarted)
        );
        assert!(state.active_turn);

        let user_msg = json!({
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "item": {
                    "type": "UserMessage",
                    "content": [{ "type": "text", "text": "Fix the bug" }]
                }
            }
        });
        assert_eq!(
            translate_rollout_line(&user_msg, &mut state),
            Some(ObservedEvent::Activity {
                desc: "Fix the bug".into()
            })
        );

        let exec_call = json!({
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "exec_command",
                "arguments": "{\"cmd\":\"cargo test\"}"
            }
        });
        assert_eq!(
            translate_rollout_line(&exec_call, &mut state),
            Some(ObservedEvent::Activity {
                desc: "cargo test".into()
            })
        );

        let exec_fallback = json!({
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "exec_command",
                "arguments": "not-json"
            }
        });
        assert_eq!(
            translate_rollout_line(&exec_fallback, &mut state),
            Some(ObservedEvent::Activity {
                desc: "exec_command".into()
            })
        );

        let other_call = json!({
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "apply_patch",
                "arguments": "{}"
            }
        });
        assert_eq!(
            translate_rollout_line(&other_call, &mut state),
            Some(ObservedEvent::Activity {
                desc: "apply_patch".into()
            })
        );

        let complete = json!({
            "type": "event_msg",
            "payload": {
                "type": "task_complete",
                "last_agent_message": "All done"
            }
        });
        assert_eq!(
            translate_rollout_line(&complete, &mut state),
            Some(ObservedEvent::TurnCompleted {
                summary: "All done".into()
            })
        );
        assert!(!state.active_turn);

        let complete_null = json!({
            "type": "event_msg",
            "payload": {
                "type": "task_complete",
                "last_agent_message": null
            }
        });
        assert_eq!(
            translate_rollout_line(&complete_null, &mut state),
            Some(ObservedEvent::TurnCompleted {
                summary: String::new()
            })
        );

        let aborted = json!({
            "type": "event_msg",
            "payload": { "type": "turn_aborted" }
        });
        assert_eq!(
            translate_rollout_line(&aborted, &mut state),
            Some(ObservedEvent::TurnInterrupted)
        );

        let unrelated = json!({
            "type": "session_meta",
            "payload": { "id": "abc" }
        });
        assert_eq!(translate_rollout_line(&unrelated, &mut state), None);
    }

    #[test]
    fn test_rollout_tailer_seeks_end_and_tails_complete_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let root_id = "01a211ba-6ad0-7230-8009-0401d46a4787";
        let day_dir = tmp.path().join("sessions/2026/11/26");
        std::fs::create_dir_all(&day_dir).unwrap();
        let rollout_path = day_dir.join(format!("rollout-2026-11-26T00-00-00-{root_id}.jsonl"));

        // Pre-existing line before discovery must be skipped (SeekFrom::End(0)).
        {
            let mut f = File::create(&rollout_path).unwrap();
            writeln!(
                f,
                "{}",
                json!({"type":"event_msg","payload":{"type":"task_started"}})
            )
            .unwrap();
        }

        let mut tailer = RolloutTailer::new(tmp.path().to_path_buf());
        assert!(tailer.poll_root(root_id).is_empty());

        // Write partial line without newline -> must not emit yet.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&rollout_path)
                .unwrap();
            write!(f, "{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_").unwrap();
        }
        assert!(tailer.poll_root(root_id).is_empty());

        // Finish the line + add malformed line + add task_complete.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&rollout_path)
                .unwrap();
            writeln!(f, "started\"}}}}").unwrap();
            writeln!(f, "{{not valid json").unwrap();
            writeln!(
                f,
                "{}",
                json!({"type":"event_msg","payload":{"type":"task_complete","last_agent_message":"Done"}})
            )
            .unwrap();
        }

        let evs = tailer.poll_root(root_id);
        assert_eq!(
            evs,
            vec![
                ObservedEvent::TurnStarted,
                ObservedEvent::TurnCompleted {
                    summary: "Done".into()
                }
            ]
        );

        // Subsequent poll with no new bytes emits nothing.
        assert!(tailer.poll_root(root_id).is_empty());
    }
}
