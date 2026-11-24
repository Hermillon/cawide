use std::sync::Arc;
use std::time::Duration;

use cawide_protocol::types::{AgentChoice, AgentStatus};

use crate::agent::map::AttentionKind;
use crate::agent::tracker::Attention;
use crate::net::registry::SessionRegistry;
use crate::pty::PtySession;

const MAX_REPLY_BYTES: usize = 4096;
const OMP_APPROVAL_SETTLE_MS: u64 = 700;
const OMP_ASK_OTHER_DELAY_MS: u64 = 250;

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn sanitize_reply_text(raw: &str) -> Result<String, String> {
    if raw.len() > MAX_REPLY_BYTES || raw.contains('\0') {
        return Err("unsupported choice".into());
    }
    let cleaned: String = raw
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\x1b'))
        .collect();
    if cleaned.trim().is_empty() {
        return Err("unsupported choice".into());
    }
    Ok(cleaned)
}

fn bracketed_paste_enter(sanitized: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(sanitized.len() + 13);
    out.extend_from_slice(b"\x1b[200~");
    out.extend_from_slice(sanitized.as_bytes());
    out.extend_from_slice(b"\x1b[201~\r");
    out
}

fn legacy_resolve_option(options: &[String], index: usize) -> Vec<u8> {
    if let Some(label) = options.get(index) {
        let trimmed = label.trim();
        let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return format!("{digits}\r").into_bytes();
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("once") || lower.contains("always") {
            return format!("{}\r", index + 1).into_bytes();
        }
        if lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|w| w == "deny" || w == "no" || w == "reject")
        {
            return b"n\r".to_vec();
        }
        if lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|w| w == "allow" || w == "yes")
        {
            return b"y\r".to_vec();
        }
    } else if index == 0 {
        return b"y\r".to_vec();
    } else if index == 1 {
        return b"n\r".to_vec();
    }
    format!("{}\r", index + 1).into_bytes()
}

enum ActionPlan {
    OmpApprovalAllow {
        opened_at_ms: u64,
    },
    OmpApprovalDeny,
    OmpAskOption {
        rows: usize,
        index: usize,
    },
    OmpAskText {
        rows: usize,
        options_len: usize,
        sanitized: String,
    },
    OmpPlan {
        review_id: String,
        option_id: String,
    },
    BracketedPaste {
        sanitized: String,
    },
    RawBytes(Vec<u8>),
}

struct ValidatedTarget {
    expected_id: u64,
    expected_prompt: String,
    plan: ActionPlan,
}

fn validate_target(
    registry: &SessionRegistry,
    session_id: &str,
    prompt_id: u64,
    prompt: &str,
    choice: &AgentChoice,
) -> Result<ValidatedTarget, String> {
    let snap = registry
        .respond_snapshot(session_id)
        .ok_or_else(|| "prompt no longer open".to_string())?;
    let Some(state) = snap.agent_state else {
        return Err("prompt no longer open".into());
    };

    match &state.status {
        AgentStatus::Thinking { .. } => Err("prompt no longer open".into()),
        AgentStatus::WaitingForInput {
            prompt: wire_prompt,
            options: wire_options,
        } => {
            let head = snap.head_attention.unwrap_or_else(|| Attention {
                id: 0,
                key: None,
                kind: AttentionKind::Approval,
                opened_at_ms: 0,
                prompt: wire_prompt.clone(),
                options: wire_options.clone(),
                actionable: true,
            });

            if prompt_id != 0 {
                if head.id != prompt_id {
                    return Err("prompt no longer open".into());
                }
            } else if head.prompt != prompt {
                return Err("prompt no longer open".into());
            }

            let expected_id = if prompt_id != 0 { prompt_id } else { head.id };
            let expected_prompt = head.prompt.clone();
            let is_omp = state.agent == "omp";

            let plan = match &head.kind {
                AttentionKind::Approval => match choice {
                    AgentChoice::Option { index } => {
                        let idx = *index as usize;
                        if is_omp {
                            match idx {
                                0 => ActionPlan::OmpApprovalAllow {
                                    opened_at_ms: head.opened_at_ms,
                                },
                                1 => ActionPlan::OmpApprovalDeny,
                                _ => return Err("unsupported choice".into()),
                            }
                        } else {
                            let max_opts = if head.options.is_empty() {
                                2
                            } else {
                                head.options.len()
                            };
                            if idx >= max_opts {
                                return Err("unsupported choice".into());
                            }
                            ActionPlan::RawBytes(legacy_resolve_option(&head.options, idx))
                        }
                    }
                    AgentChoice::Text { text } => {
                        if is_omp {
                            return Err("unsupported choice".into());
                        }
                        ActionPlan::BracketedPaste {
                            sanitized: sanitize_reply_text(text)?,
                        }
                    }
                },
                AttentionKind::Ask { multi, .. } => {
                    if *multi || !head.actionable {
                        return Err("unsupported choice".into());
                    }
                    let rows = head.options.len() + 1;
                    match choice {
                        AgentChoice::Option { index } => {
                            let idx = *index as usize;
                            if idx >= head.options.len() {
                                return Err("unsupported choice".into());
                            }
                            ActionPlan::OmpAskOption { rows, index: idx }
                        }
                        AgentChoice::Text { text } => ActionPlan::OmpAskText {
                            rows,
                            options_len: head.options.len(),
                            sanitized: sanitize_reply_text(text)?,
                        },
                    }
                }
                AttentionKind::Plan {
                    review_id,
                    option_ids,
                } => match choice {
                    AgentChoice::Option { index } => {
                        let idx = *index as usize;
                        let Some(option_id) = option_ids.get(idx) else {
                            return Err("unsupported choice".into());
                        };
                        if review_id.is_empty() {
                            return Err("unsupported choice".into());
                        }
                        ActionPlan::OmpPlan {
                            review_id: review_id.clone(),
                            option_id: option_id.clone(),
                        }
                    }
                    AgentChoice::Text { .. } => return Err("unsupported choice".into()),
                },
                AttentionKind::TextQuestion => match choice {
                    AgentChoice::Option { index } => {
                        let idx = *index as usize;
                        let Some(opt) = head.options.get(idx) else {
                            return Err("unsupported choice".into());
                        };
                        ActionPlan::BracketedPaste {
                            sanitized: sanitize_reply_text(opt)?,
                        }
                    }
                    AgentChoice::Text { text } => ActionPlan::BracketedPaste {
                        sanitized: sanitize_reply_text(text)?,
                    },
                },
            };

            Ok(ValidatedTarget {
                expected_id,
                expected_prompt,
                plan,
            })
        }
        AgentStatus::Completed { summary } => {
            let head_id = snap.head_attention.as_ref().map_or(0, |h| h.id);
            let head_prompt = snap
                .head_attention
                .as_ref()
                .map_or(summary.as_str(), |h| h.prompt.as_str());
            if prompt_id != 0 {
                if head_id != prompt_id {
                    return Err("prompt no longer open".into());
                }
            } else if prompt.is_empty() || head_prompt != prompt {
                return Err("prompt no longer open".into());
            }
            let expected_id = if prompt_id != 0 { prompt_id } else { head_id };
            let expected_prompt = head_prompt.to_string();
            match choice {
                AgentChoice::Option { .. } => Err("unsupported choice".into()),
                AgentChoice::Text { text } => Ok(ValidatedTarget {
                    expected_id,
                    expected_prompt,
                    plan: ActionPlan::BracketedPaste {
                        sanitized: sanitize_reply_text(text)?,
                    },
                }),
            }
        }
        AgentStatus::Idle => Err("prompt no longer open".into()),
    }
}

fn ensure_still_valid(
    registry: &SessionRegistry,
    session_id: &str,
    expected_id: u64,
    expected_prompt: &str,
) -> Result<Arc<PtySession>, String> {
    let snap = registry
        .respond_snapshot(session_id)
        .ok_or_else(|| "prompt no longer open".to_string())?;
    let Some(state) = snap.agent_state else {
        return Err("prompt no longer open".into());
    };
    if matches!(state.status, AgentStatus::Thinking { .. }) {
        return Err("prompt no longer open".into());
    }
    if expected_id != 0 {
        let matches_id = snap
            .head_attention
            .as_ref()
            .is_some_and(|h| h.id == expected_id);
        if !matches_id {
            return Err("prompt no longer open".into());
        }
    } else {
        let cur_prompt = snap
            .head_attention
            .as_ref()
            .map(|h| h.prompt.as_str())
            .unwrap_or_else(|| match &state.status {
                AgentStatus::WaitingForInput { prompt, .. } => prompt.as_str(),
                AgentStatus::Completed { summary } => summary.as_str(),
                AgentStatus::Idle | AgentStatus::Thinking { .. } => "",
            });
        if cur_prompt != expected_prompt {
            return Err("prompt no longer open".into());
        }
    }
    Ok(snap.session)
}

async fn write_pty_step(
    registry: &SessionRegistry,
    session_id: &str,
    expected_id: u64,
    expected_prompt: &str,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let session = ensure_still_valid(registry, session_id, expected_id, expected_prompt)?;
    session
        .send_input_async(bytes::Bytes::from(bytes))
        .await
        .map_err(|e| e.to_string())?;
    registry.touch(session_id);
    registry.mark_input();
    Ok(())
}

pub async fn respond_to_session(
    registry: &SessionRegistry,
    session_id: &str,
    prompt_id: u64,
    prompt: &str,
    choice: AgentChoice,
) -> Result<(), String> {
    if let AgentChoice::Text { text } = &choice {
        let _ = sanitize_reply_text(text)?;
    }

    let lock = registry
        .respond_lock(session_id)
        .ok_or_else(|| "prompt no longer open".to_string())?;
    let _guard = lock.lock().await;

    let target = validate_target(registry, session_id, prompt_id, prompt, &choice)?;
    let expected_id = target.expected_id;
    let expected_prompt = target.expected_prompt;

    match target.plan {
        ActionPlan::OmpApprovalAllow { opened_at_ms } => {
            let target_ms = opened_at_ms.saturating_add(OMP_APPROVAL_SETTLE_MS);
            let cur_ms = now_millis();
            if target_ms > cur_ms {
                let _ = ensure_still_valid(registry, session_id, expected_id, &expected_prompt)?;
                let wait_ms = (target_ms - cur_ms).min(OMP_APPROVAL_SETTLE_MS);
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            }
            write_pty_step(
                registry,
                session_id,
                expected_id,
                &expected_prompt,
                b"\x11".to_vec(),
            )
            .await
        }
        ActionPlan::OmpApprovalDeny => {
            write_pty_step(
                registry,
                session_id,
                expected_id,
                &expected_prompt,
                b"\x1b".to_vec(),
            )
            .await
        }
        ActionPlan::OmpAskOption { rows, index } => {
            let mut seq = Vec::with_capacity((rows + 1 + index) * 3 + 1);
            for _ in 0..=rows {
                seq.extend_from_slice(b"\x1b[A");
            }
            for _ in 0..index {
                seq.extend_from_slice(b"\x1b[B");
            }
            seq.push(b'\r');
            write_pty_step(registry, session_id, expected_id, &expected_prompt, seq).await
        }
        ActionPlan::OmpAskText {
            rows,
            options_len,
            sanitized,
        } => {
            let mut nav = Vec::with_capacity((rows + 1 + options_len) * 3 + 1);
            for _ in 0..=rows {
                nav.extend_from_slice(b"\x1b[A");
            }
            for _ in 0..options_len {
                nav.extend_from_slice(b"\x1b[B");
            }
            nav.push(b'\r');
            write_pty_step(registry, session_id, expected_id, &expected_prompt, nav).await?;

            let _ = ensure_still_valid(registry, session_id, expected_id, &expected_prompt)?;
            tokio::time::sleep(Duration::from_millis(OMP_ASK_OTHER_DELAY_MS)).await;

            write_pty_step(
                registry,
                session_id,
                expected_id,
                &expected_prompt,
                bracketed_paste_enter(&sanitized),
            )
            .await
        }
        ActionPlan::OmpPlan {
            review_id,
            option_id,
        } => {
            let _ = ensure_still_valid(registry, session_id, expected_id, &expected_prompt)?;
            registry.send_plan_review_resolution(session_id, &review_id, &option_id)?;
            registry.touch(session_id);
            registry.mark_input();
            Ok(())
        }
        ActionPlan::BracketedPaste { sanitized } => {
            write_pty_step(
                registry,
                session_id,
                expected_id,
                &expected_prompt,
                bracketed_paste_enter(&sanitized),
            )
            .await
        }
        ActionPlan::RawBytes(bytes) => {
            write_pty_step(registry, session_id, expected_id, &expected_prompt, bytes).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_reply_text() {
        assert_eq!(
            sanitize_reply_text("hello\n\tworld").unwrap(),
            "hello\n\tworld"
        );
        assert_eq!(
            sanitize_reply_text("\x1b[201~rm -rf /\x1b[200~").unwrap(),
            "[201~rm -rf /[200~"
        );
        assert_eq!(
            sanitize_reply_text("a\r\nb\x07c\u{009b}d").unwrap(),
            "a\nbcd"
        );
        assert_eq!(
            sanitize_reply_text("a\x00b").unwrap_err(),
            "unsupported choice"
        );
        assert_eq!(
            sanitize_reply_text("\x1b\x07   \n\t").unwrap_err(),
            "unsupported choice"
        );
        assert_eq!(
            sanitize_reply_text(&"x".repeat(4097)).unwrap_err(),
            "unsupported choice"
        );
        assert!(sanitize_reply_text(&"x".repeat(4096)).is_ok());
    }

    #[test]
    fn test_legacy_resolve_option() {
        let opts = vec![
            "Allow once".to_string(),
            "Always allow".to_string(),
            "Deny".to_string(),
        ];
        assert_eq!(legacy_resolve_option(&opts, 0), b"1\r");
        assert_eq!(legacy_resolve_option(&opts, 1), b"2\r");
        assert_eq!(legacy_resolve_option(&opts, 2), b"n\r");

        let yn = vec!["Allow".to_string(), "Deny".to_string()];
        assert_eq!(legacy_resolve_option(&yn, 0), b"y\r");
        assert_eq!(legacy_resolve_option(&yn, 1), b"n\r");

        let numbered = vec!["1. Yes".to_string(), "2. No".to_string()];
        assert_eq!(legacy_resolve_option(&numbered, 0), b"1\r");
        assert_eq!(legacy_resolve_option(&numbered, 1), b"2\r");

        assert_eq!(legacy_resolve_option(&[], 0), b"y\r");
        assert_eq!(legacy_resolve_option(&[], 1), b"n\r");
    }
}
