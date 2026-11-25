use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use cawide_protocol::types::{AgentState, AgentStatus};

use crate::agent::detect::Foreground;
use crate::agent::map::{AgentSignal, AttentionKind, AttentionSpec, SignalResolution, TurnOutcome};
use crate::pty::output::{OscStatusKind, TerminalSignals};
use crate::push::{
    alert_for_tracker_transition, ActivityEventKind, ActivityPhase, AgentAlertKind, AlertDetail,
};

static NEXT_ATTENTION_ID: LazyLock<AtomicU64> = LazyLock::new(|| {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);
    let seed = ((ms << 20) ^ (rand::random::<u64>() & ((1 << 20) - 1))).max(1);
    AtomicU64::new(seed)
});

fn next_attention_id() -> u64 {
    NEXT_ATTENTION_ID.fetch_add(1, Ordering::Relaxed).max(1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attention {
    pub id: u64,
    pub key: Option<String>,
    pub kind: AttentionKind,
    pub opened_at_ms: u64,
    pub prompt: String,
    pub options: Vec<String>,
    pub actionable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerAlert {
    pub agent: String,
    pub kind: AgentAlertKind,
    pub attention_id: u64,
    pub detail: AlertDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerActivity {
    pub agent: String,
    pub phase: ActivityPhase,
    pub event: ActivityEventKind,
    pub started_at: u64,
    pub prompt_id: Option<u64>,
    pub is_tool_step: bool,
    pub dismiss_immediately: bool,
    pub detail: AlertDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrackerResult {
    pub changed: bool,
    pub alert: Option<TrackerAlert>,
    pub activity: Option<TrackerActivity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    state: AgentState,
    detected: bool,
    pub has_hook_updates: bool,
    attention_queue: VecDeque<Attention>,
    turn_started_at: Option<u64>,
    shell_since: Option<u64>,
    last_epoch: Option<u32>,
    last_seq: Option<u64>,
    last_hook_osc_seq: u64,
    last_osc_seq: u64,
    pending_outcome: TurnOutcome,
    completed_attention: Option<Attention>,
}

#[derive(Debug, Default)]
pub struct AgentTracker {
    tracked: Option<Tracked>,
    last_foreground: Option<Foreground>,
    progress_was_active: bool,
}

impl AgentTracker {
    pub fn current(&self) -> Option<AgentState> {
        self.tracked.as_ref().map(|t| t.state.clone())
    }

    pub fn head_attention(&self) -> Option<&Attention> {
        self.tracked
            .as_ref()
            .and_then(|t| t.attention_queue.front().or(t.completed_attention.as_ref()))
    }

    pub fn turn_started_at(&self) -> Option<u64> {
        self.tracked.as_ref().and_then(|t| t.turn_started_at)
    }

    pub fn on_probe(&mut self, fg: Option<Foreground>, progress_active: bool, now: u64) -> bool {
        let signals = TerminalSignals {
            title: None,
            progress_active,
            run_status: None,
        };
        self.on_probe_signals(fg, &signals, now, now.saturating_mul(1000))
            .changed
    }

    pub fn on_probe_signals(
        &mut self,
        fg: Option<Foreground>,
        signals: &TerminalSignals,
        now_secs: u64,
        now_ms: u64,
    ) -> TrackerResult {
        let old_state = self.current();
        let old_head_id = self
            .tracked
            .as_ref()
            .and_then(|t| t.attention_queue.front().map(|a| a.id));
        let old_turn_started_at = self.tracked.as_ref().and_then(|t| t.turn_started_at);
        let mut outcome_for_alert = TurnOutcome::None;

        if let Some(f) = fg {
            match f {
                Foreground::Shell => {
                    if let Some(t) = &mut self.tracked {
                        if t.has_hook_updates
                            && matches!(
                                t.state.status,
                                AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. }
                            )
                        {
                            let since = *t.shell_since.get_or_insert(now_secs);
                            if now_secs.saturating_sub(since) >= 3 {
                                self.tracked = None;
                            }
                        } else {
                            self.tracked = None;
                        }
                    }
                }
                Foreground::Agent(slug) => {
                    if self.tracked.as_ref().map(|t| t.state.agent.as_str()) == Some(slug) {
                        if let Some(t) = self.tracked.as_mut() {
                            t.detected = true;
                            t.shell_since = None;
                        }
                    } else {
                        let status = if signals.progress_active {
                            AgentStatus::Thinking {
                                task_desc: String::new(),
                            }
                        } else {
                            AgentStatus::Idle
                        };
                        let turn_started_at = if signals.progress_active {
                            Some(now_secs)
                        } else {
                            None
                        };
                        self.tracked = Some(Tracked {
                            state: AgentState {
                                agent: slug.to_string(),
                                status,
                                updated_ts: now_secs,
                            },
                            detected: true,
                            has_hook_updates: false,
                            attention_queue: VecDeque::new(),
                            turn_started_at,
                            shell_since: None,
                            last_epoch: None,
                            last_seq: None,
                            last_hook_osc_seq: 0,
                            last_osc_seq: 0,
                            pending_outcome: TurnOutcome::None,
                            completed_attention: None,
                        });
                    }
                }
                Foreground::Other => {
                    if let Some(t) = self.tracked.as_mut() {
                        t.detected = false;
                        t.shell_since = None;
                    }
                }
            }
            self.last_foreground = Some(f);
        }

        if let Some(t) = &mut self.tracked {
            if !t.has_hook_updates {
                if let Some(rs) = &signals.run_status {
                    if rs.seq > t.last_osc_seq {
                        t.last_osc_seq = rs.seq;
                        outcome_for_alert = apply_osc_status(t, rs, now_secs, now_ms, false);
                    }
                } else if signals.progress_active && !self.progress_was_active {
                    if !matches!(t.state.status, AgentStatus::Thinking { .. }) {
                        t.attention_queue.clear();
                        t.completed_attention = None;
                        t.turn_started_at.get_or_insert(now_secs);
                        t.state.status = AgentStatus::Thinking {
                            task_desc: String::new(),
                        };
                        t.state.updated_ts = now_secs;
                    }
                } else if !signals.progress_active
                    && self.progress_was_active
                    && matches!(t.state.status, AgentStatus::Thinking { .. })
                {
                    t.completed_attention = Some(Attention {
                        id: next_attention_id(),
                        key: None,
                        kind: AttentionKind::TextQuestion,
                        opened_at_ms: now_ms,
                        prompt: String::new(),
                        options: Vec::new(),
                        actionable: true,
                    });
                    t.state.status = AgentStatus::Completed {
                        summary: String::new(),
                    };
                    t.state.updated_ts = now_secs;
                    t.pending_outcome = TurnOutcome::Done;
                    outcome_for_alert = TurnOutcome::Done;
                    t.turn_started_at = None;
                }
            } else if matches!(t.state.status, AgentStatus::Thinking { .. }) {
                if let Some(rs) = &signals.run_status {
                    if rs.seq > t.last_hook_osc_seq && rs.seq > t.last_osc_seq {
                        t.last_osc_seq = rs.seq;
                        outcome_for_alert = apply_osc_status(t, rs, now_secs, now_ms, true);
                    }
                }
            }
        }

        self.progress_was_active = signals.progress_active;
        self.finish_transition(
            old_state,
            old_head_id,
            old_turn_started_at,
            &outcome_for_alert,
            now_secs,
        )
    }

    pub fn on_hook(&mut self, agent: &str, status: AgentStatus, now: u64) -> bool {
        let attention = match &status {
            AgentStatus::WaitingForInput { prompt, options } => Some(AttentionSpec {
                key: None,
                kind: AttentionKind::Approval,
                prompt: prompt.clone(),
                options: options.clone(),
                actionable: true,
            }),
            _ => None,
        };
        let (outcome, resolution) = match &status {
            AgentStatus::Completed { .. } => (TurnOutcome::Done, SignalResolution::ClearNonPlan),
            AgentStatus::Thinking { .. } => (TurnOutcome::Started, SignalResolution::ClearNonPlan),
            AgentStatus::Idle => (TurnOutcome::None, SignalResolution::ClearAll),
            AgentStatus::WaitingForInput { .. } => (TurnOutcome::None, SignalResolution::None),
        };
        let signal = AgentSignal {
            status,
            attention,
            outcome,
            resolution,
            seq: None,
            epoch: None,
        };
        self.on_hook_signal(agent, signal, now, now.saturating_mul(1000), 0)
            .changed
    }

    pub fn on_hook_signal(
        &mut self,
        agent: &str,
        signal: AgentSignal,
        now_secs: u64,
        now_ms: u64,
        osc_seq: u64,
    ) -> TrackerResult {
        if let Some(slug) = to_static_agent(agent) {
            self.last_foreground = Some(Foreground::Agent(slug));
        }

        let old_state = self.current();
        let old_head_id = self
            .tracked
            .as_ref()
            .and_then(|t| t.attention_queue.front().map(|a| a.id));
        let old_turn_started_at = self.tracked.as_ref().and_then(|t| t.turn_started_at);

        if let Some(t) = &mut self.tracked {
            if t.state.agent != agent {
                t.state.agent = agent.to_string();
                t.attention_queue.clear();
                t.completed_attention = None;
                t.turn_started_at = None;
                t.last_epoch = None;
                t.last_seq = None;
                t.pending_outcome = TurnOutcome::None;
                t.shell_since = None;
            }
            if let Some(epoch) = signal.epoch {
                if t.last_epoch != Some(epoch) {
                    t.last_epoch = Some(epoch);
                    t.last_seq = signal.seq;
                } else {
                    if let (Some(seq), Some(last_seq)) = (signal.seq, t.last_seq) {
                        if seq <= last_seq {
                            return TrackerResult::default();
                        }
                    }
                    if signal.seq.is_some() {
                        t.last_seq = signal.seq;
                    }
                }
            } else if signal.seq.is_some() {
                t.last_seq = signal.seq;
            }
            t.has_hook_updates = true;
            t.shell_since = None;
            t.last_hook_osc_seq = osc_seq;
        } else {
            self.tracked = Some(Tracked {
                state: AgentState {
                    agent: agent.to_string(),
                    status: AgentStatus::Idle,
                    updated_ts: now_secs,
                },
                detected: false,
                has_hook_updates: true,
                attention_queue: VecDeque::new(),
                turn_started_at: None,
                shell_since: None,
                last_epoch: signal.epoch,
                last_seq: signal.seq,
                last_hook_osc_seq: osc_seq,
                last_osc_seq: 0,
                pending_outcome: TurnOutcome::None,
                completed_attention: None,
            });
        }

        let Some(t) = &mut self.tracked else {
            return TrackerResult::default();
        };

        match &signal.resolution {
            SignalResolution::None => {}
            SignalResolution::ByKey(k) => {
                t.attention_queue
                    .retain(|a| a.key.as_deref() != Some(k.as_str()));
            }
            SignalResolution::Approval(opt_k) => {
                if let Some(k) = opt_k {
                    t.attention_queue
                        .retain(|a| a.key.as_deref() != Some(k.as_str()));
                } else if let Some(pos) = t
                    .attention_queue
                    .iter()
                    .position(|a| matches!(a.kind, AttentionKind::Approval))
                {
                    t.attention_queue.remove(pos);
                }
            }
            SignalResolution::ClearNonPlan => {
                t.attention_queue
                    .retain(|a| matches!(a.kind, AttentionKind::Plan { .. }));
            }
            SignalResolution::ClearAll => {
                t.attention_queue.clear();
            }
        }

        if let Some(spec) = signal.attention {
            let existing_pos = if let Some(k) = spec.key.as_ref() {
                t.attention_queue
                    .iter()
                    .position(|a| a.key.as_deref() == Some(k.as_str()))
            } else {
                t.attention_queue.iter().position(|a| {
                    a.key.is_none()
                        && a.kind == spec.kind
                        && a.prompt == spec.prompt
                        && a.options == spec.options
                        && a.actionable == spec.actionable
                })
            };
            if let Some(pos) = existing_pos {
                let existing = &mut t.attention_queue[pos];
                if existing.kind != spec.kind
                    || existing.prompt != spec.prompt
                    || existing.options != spec.options
                    || existing.actionable != spec.actionable
                {
                    existing.id = next_attention_id();
                    existing.kind = spec.kind;
                    existing.opened_at_ms = now_ms;
                    existing.prompt = spec.prompt;
                    existing.options = spec.options;
                    existing.actionable = spec.actionable;
                }
            } else {
                t.attention_queue.push_back(Attention {
                    id: next_attention_id(),
                    key: spec.key,
                    kind: spec.kind,
                    opened_at_ms: now_ms,
                    prompt: spec.prompt,
                    options: spec.options,
                    actionable: spec.actionable,
                });
            }
        }

        match &signal.outcome {
            TurnOutcome::Started => {
                t.attention_queue
                    .retain(|a| matches!(a.kind, AttentionKind::Plan { .. }));
                t.turn_started_at.get_or_insert(now_secs);
                t.pending_outcome = TurnOutcome::Started;
            }
            TurnOutcome::Done | TurnOutcome::Failed { .. } | TurnOutcome::Aborted => {
                t.pending_outcome = signal.outcome.clone();
            }
            TurnOutcome::None => {}
        }

        if let Some(head) = t.attention_queue.front() {
            let next_status = AgentStatus::WaitingForInput {
                prompt: head.prompt.clone(),
                options: head.options.clone(),
            };
            if t.state.status != next_status || old_state.is_none() {
                t.state.status = next_status;
                t.state.updated_ts = now_secs;
            }
            t.completed_attention = None;
            if matches!(
                signal.outcome,
                TurnOutcome::Done | TurnOutcome::Failed { .. } | TurnOutcome::Aborted
            ) {
                t.turn_started_at = None;
            }
        } else {
            let status_changed = t.state.status != signal.status || old_state.is_none();
            if status_changed {
                t.state.status = signal.status.clone();
                t.state.updated_ts = now_secs;
            }
            match &t.state.status {
                AgentStatus::Completed { summary } => {
                    if status_changed || t.completed_attention.is_none() {
                        t.completed_attention = Some(Attention {
                            id: next_attention_id(),
                            key: None,
                            kind: AttentionKind::TextQuestion,
                            opened_at_ms: now_ms,
                            prompt: summary.clone(),
                            options: Vec::new(),
                            actionable: true,
                        });
                    }
                    t.turn_started_at = None;
                }
                AgentStatus::Thinking { .. } => {
                    t.completed_attention = None;
                    t.turn_started_at.get_or_insert(now_secs);
                }
                AgentStatus::Idle => {
                    t.completed_attention = None;
                    t.turn_started_at = None;
                }
                AgentStatus::WaitingForInput { .. } => {
                    t.completed_attention = None;
                }
            }
        }

        self.finish_transition(
            old_state,
            old_head_id,
            old_turn_started_at,
            &signal.outcome,
            now_secs,
        )
    }

    fn finish_transition(
        &self,
        old_state: Option<AgentState>,
        old_head_id: Option<u64>,
        old_turn_started_at: Option<u64>,
        outcome: &TurnOutcome,
        now_secs: u64,
    ) -> TrackerResult {
        let new_state = self.current();
        let new_queue_head = self
            .tracked
            .as_ref()
            .and_then(|t| t.attention_queue.front());
        let new_head_id = new_queue_head.map(|a| a.id);
        let changed =
            new_state != old_state || (new_head_id.is_some() && new_head_id != old_head_id);

        let alert_kind = alert_for_tracker_transition(
            old_state.as_ref(),
            new_state.as_ref(),
            old_head_id,
            new_queue_head,
            outcome,
            old_turn_started_at,
            now_secs,
        );

        let alert = alert_kind.map(|kind| {
            let agent = new_state
                .as_ref()
                .or(old_state.as_ref())
                .map(|s| s.agent.clone())
                .unwrap_or_default();
            let duration_secs = old_turn_started_at.map(|s| now_secs.saturating_sub(s));
            match kind {
                AgentAlertKind::NeedsApproval
                | AgentAlertKind::NeedsInput
                | AgentAlertKind::NeedsReview => {
                    if let Some(head) = new_queue_head {
                        TrackerAlert {
                            agent,
                            kind,
                            attention_id: head.id,
                            detail: AlertDetail {
                                actionable: head.actionable,
                                prompt: Some(head.prompt.clone()),
                                options: head.options.clone(),
                                ..Default::default()
                            },
                        }
                    } else {
                        let (prompt, options) = match new_state.as_ref().map(|s| &s.status) {
                            Some(AgentStatus::WaitingForInput { prompt, options }) => {
                                (Some(prompt.clone()), options.clone())
                            }
                            _ => (None, Vec::new()),
                        };
                        TrackerAlert {
                            agent,
                            kind,
                            attention_id: 0,
                            detail: AlertDetail {
                                actionable: true,
                                prompt,
                                options,
                                ..Default::default()
                            },
                        }
                    }
                }
                AgentAlertKind::Finished => {
                    let summary = match new_state.as_ref().map(|s| &s.status) {
                        Some(AgentStatus::Completed { summary }) => Some(summary.clone()),
                        _ => None,
                    };
                    let attention_id = self
                        .tracked
                        .as_ref()
                        .and_then(|t| t.completed_attention.as_ref())
                        .map_or(0, |a| a.id);
                    TrackerAlert {
                        agent,
                        kind,
                        attention_id,
                        detail: AlertDetail {
                            actionable: attention_id > 0,
                            summary,
                            duration_secs,
                            ..Default::default()
                        },
                    }
                }
                AgentAlertKind::Failed => {
                    let summary = match new_state.as_ref().map(|s| &s.status) {
                        Some(AgentStatus::Completed { summary }) => Some(summary.clone()),
                        _ => None,
                    };
                    let error = match outcome {
                        TurnOutcome::Failed { error } => Some(error.clone()),
                        _ => summary.clone(),
                    };
                    let attention_id = self
                        .tracked
                        .as_ref()
                        .and_then(|t| t.completed_attention.as_ref())
                        .map_or(0, |a| a.id);
                    TrackerAlert {
                        agent,
                        kind,
                        attention_id,
                        detail: AlertDetail {
                            actionable: attention_id > 0,
                            summary,
                            error,
                            duration_secs,
                            ..Default::default()
                        },
                    }
                }
            }
        });

        let new_turn_started_at = self.tracked.as_ref().and_then(|t| t.turn_started_at);
        let duration_secs = old_turn_started_at.map(|s| now_secs.saturating_sub(s));
        let activity = match new_state.as_ref() {
            Some(new_s) => match &new_s.status {
                AgentStatus::Thinking { task_desc } => {
                    let same_thinking = old_state.as_ref().is_some_and(|old_s| {
                        old_s.agent == new_s.agent
                            && matches!(
                                &old_s.status,
                                AgentStatus::Thinking { task_desc: old_desc } if old_desc == task_desc
                            )
                    });
                    if same_thinking {
                        None
                    } else {
                        let is_tool_step = old_state.as_ref().is_some_and(|old_s| {
                            old_s.agent == new_s.agent
                                && matches!(old_s.status, AgentStatus::Thinking { .. })
                        });
                        Some(TrackerActivity {
                            agent: new_s.agent.clone(),
                            phase: ActivityPhase::Working,
                            event: ActivityEventKind::Update,
                            started_at: new_turn_started_at.unwrap_or(now_secs),
                            prompt_id: None,
                            is_tool_step,
                            dismiss_immediately: false,
                            detail: AlertDetail {
                                prompt: (!task_desc.is_empty()).then(|| task_desc.clone()),
                                ..Default::default()
                            },
                        })
                    }
                }
                AgentStatus::WaitingForInput { prompt, options } => {
                    let same_waiting = old_state.as_ref().is_some_and(|old_s| {
                        old_s.agent == new_s.agent
                            && old_s.status == new_s.status
                            && old_head_id == new_head_id
                    });
                    if same_waiting {
                        None
                    } else if let Some(head) = new_queue_head {
                        Some(TrackerActivity {
                            agent: new_s.agent.clone(),
                            phase: ActivityPhase::Waiting,
                            event: ActivityEventKind::Update,
                            started_at: new_turn_started_at
                                .or(old_turn_started_at)
                                .unwrap_or(now_secs),
                            prompt_id: Some(head.id),
                            is_tool_step: false,
                            dismiss_immediately: false,
                            detail: AlertDetail {
                                actionable: head.actionable,
                                prompt: Some(head.prompt.clone()),
                                options: head.options.clone(),
                                ..Default::default()
                            },
                        })
                    } else {
                        Some(TrackerActivity {
                            agent: new_s.agent.clone(),
                            phase: ActivityPhase::Waiting,
                            event: ActivityEventKind::Update,
                            started_at: new_turn_started_at
                                .or(old_turn_started_at)
                                .unwrap_or(now_secs),
                            prompt_id: None,
                            is_tool_step: false,
                            dismiss_immediately: false,
                            detail: AlertDetail {
                                actionable: true,
                                prompt: Some(prompt.clone()),
                                options: options.clone(),
                                ..Default::default()
                            },
                        })
                    }
                }
                AgentStatus::Completed { summary } => {
                    let same_completed = old_state.as_ref().is_some_and(|old_s| {
                        old_s.agent == new_s.agent && old_s.status == new_s.status
                    });
                    if same_completed {
                        None
                    } else {
                        let failed_err = match outcome {
                            TurnOutcome::Failed { error } => Some(error.clone()),
                            _ => match self.tracked.as_ref().map(|t| &t.pending_outcome) {
                                Some(TurnOutcome::Failed { error }) => Some(error.clone()),
                                _ => None,
                            },
                        };
                        let phase = if failed_err.is_some() {
                            ActivityPhase::Failed
                        } else {
                            ActivityPhase::Done
                        };
                        let prompt_id = self
                            .tracked
                            .as_ref()
                            .and_then(|t| t.completed_attention.as_ref())
                            .map(|a| a.id);
                        Some(TrackerActivity {
                            agent: new_s.agent.clone(),
                            phase,
                            event: ActivityEventKind::End,
                            started_at: old_turn_started_at.unwrap_or(now_secs),
                            prompt_id,
                            is_tool_step: false,
                            dismiss_immediately: false,
                            detail: AlertDetail {
                                actionable: prompt_id.is_some_and(|id| id > 0),
                                summary: (!summary.is_empty()).then(|| summary.clone()),
                                error: failed_err,
                                duration_secs,
                                ..Default::default()
                            },
                        })
                    }
                }
                AgentStatus::Idle => {
                    let was_idle = old_state
                        .as_ref()
                        .is_some_and(|old_s| matches!(old_s.status, AgentStatus::Idle));
                    if old_state.is_some() && !was_idle {
                        let failed_err = match outcome {
                            TurnOutcome::Failed { error } => Some(error.clone()),
                            _ => None,
                        };
                        let phase = if failed_err.is_some() {
                            ActivityPhase::Failed
                        } else {
                            ActivityPhase::Done
                        };
                        Some(TrackerActivity {
                            agent: new_s.agent.clone(),
                            phase,
                            event: ActivityEventKind::End,
                            started_at: old_turn_started_at.unwrap_or(now_secs),
                            prompt_id: None,
                            is_tool_step: false,
                            dismiss_immediately: failed_err.is_none(),
                            detail: AlertDetail {
                                error: failed_err,
                                duration_secs,
                                ..Default::default()
                            },
                        })
                    } else {
                        None
                    }
                }
            },
            None => old_state.as_ref().and_then(|old_s| match old_s.status {
                AgentStatus::Thinking { .. } | AgentStatus::WaitingForInput { .. } => {
                    Some(TrackerActivity {
                        agent: old_s.agent.clone(),
                        phase: ActivityPhase::Failed,
                        event: ActivityEventKind::End,
                        started_at: old_turn_started_at.unwrap_or(now_secs),
                        prompt_id: None,
                        is_tool_step: false,
                        dismiss_immediately: false,
                        detail: AlertDetail {
                            duration_secs,
                            ..Default::default()
                        },
                    })
                }
                AgentStatus::Completed { .. } => Some(TrackerActivity {
                    agent: old_s.agent.clone(),
                    phase: ActivityPhase::Done,
                    event: ActivityEventKind::End,
                    started_at: old_turn_started_at.unwrap_or(now_secs),
                    prompt_id: None,
                    is_tool_step: false,
                    dismiss_immediately: true,
                    detail: AlertDetail {
                        duration_secs,
                        ..Default::default()
                    },
                }),
                AgentStatus::Idle => None,
            }),
        };

        TrackerResult {
            changed,
            alert,
            activity,
        }
    }
}

fn apply_osc_status(
    t: &mut Tracked,
    rs: &crate::pty::output::OscRunStatus,
    now_secs: u64,
    now_ms: u64,
    terminal_only: bool,
) -> TurnOutcome {
    match &rs.kind {
        OscStatusKind::Working if !terminal_only => {
            t.attention_queue.clear();
            t.completed_attention = None;
            t.turn_started_at.get_or_insert(now_secs);
            t.state.status = AgentStatus::Thinking {
                task_desc: rs.message.clone().unwrap_or_default(),
            };
            t.state.updated_ts = now_secs;
            TurnOutcome::Started
        }
        OscStatusKind::Blocked { kind } if !terminal_only => {
            let att_kind = if matches!(kind.as_deref(), Some("approval" | "permission")) {
                AttentionKind::Approval
            } else {
                AttentionKind::TextQuestion
            };
            let prompt = rs
                .message
                .clone()
                .unwrap_or_else(|| "Waiting for input".into());
            let options = if matches!(att_kind, AttentionKind::Approval) {
                vec!["Allow".into(), "Deny".into()]
            } else {
                Vec::new()
            };
            t.attention_queue.clear();
            t.attention_queue.push_back(Attention {
                id: next_attention_id(),
                key: None,
                kind: att_kind,
                opened_at_ms: now_ms,
                prompt: prompt.clone(),
                options: options.clone(),
                actionable: true,
            });
            t.completed_attention = None;
            t.state.status = AgentStatus::WaitingForInput { prompt, options };
            t.state.updated_ts = now_secs;
            TurnOutcome::None
        }
        OscStatusKind::Done => {
            t.attention_queue.clear();
            let summary = rs.message.clone().unwrap_or_default();
            t.completed_attention = Some(Attention {
                id: next_attention_id(),
                key: None,
                kind: AttentionKind::TextQuestion,
                opened_at_ms: now_ms,
                prompt: summary.clone(),
                options: Vec::new(),
                actionable: true,
            });
            t.state.status = AgentStatus::Completed { summary };
            t.state.updated_ts = now_secs;
            t.pending_outcome = TurnOutcome::Done;
            t.turn_started_at = None;
            TurnOutcome::Done
        }
        OscStatusKind::Error => {
            t.attention_queue.clear();
            let err = rs.message.clone().unwrap_or_else(|| "Agent error".into());
            let summary = format!("Error: {err}");
            t.completed_attention = Some(Attention {
                id: next_attention_id(),
                key: None,
                kind: AttentionKind::TextQuestion,
                opened_at_ms: now_ms,
                prompt: summary.clone(),
                options: Vec::new(),
                actionable: true,
            });
            t.state.status = AgentStatus::Completed { summary };
            t.state.updated_ts = now_secs;
            let outcome = TurnOutcome::Failed { error: err };
            t.pending_outcome = outcome.clone();
            t.turn_started_at = None;
            outcome
        }
        OscStatusKind::Idle => {
            t.attention_queue.clear();
            t.completed_attention = None;
            t.state.status = AgentStatus::Idle;
            t.state.updated_ts = now_secs;
            t.pending_outcome = TurnOutcome::None;
            t.turn_started_at = None;
            TurnOutcome::None
        }
        _ => TurnOutcome::None,
    }
}

fn to_static_agent(agent: &str) -> Option<&'static str> {
    match agent {
        "claude" => Some("claude"),
        "codex" => Some("codex"),
        "omp" => Some("omp"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_agent_without_progress_idle() {
        let mut tracker = AgentTracker::default();
        let changed = tracker.on_probe(Some(Foreground::Agent("claude")), false, 100);
        assert!(changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 100,
            })
        );
    }

    #[test]
    fn test_new_agent_with_progress_thinking() {
        let mut tracker = AgentTracker::default();
        let changed = tracker.on_probe(Some(Foreground::Agent("claude")), true, 100);
        assert!(changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Thinking {
                    task_desc: String::new()
                },
                updated_ts: 100,
            })
        );
    }

    #[test]
    fn test_rising_edge_to_thinking() {
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Agent("claude")), false, 100);
        let changed = tracker.on_probe(None, true, 200);
        assert!(changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Thinking {
                    task_desc: String::new()
                },
                updated_ts: 200,
            })
        );
    }

    #[test]
    fn test_falling_edge_to_completed() {
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Agent("claude")), true, 100);
        let changed = tracker.on_probe(None, false, 200);
        assert!(changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Completed {
                    summary: String::new()
                },
                updated_ts: 200,
            })
        );
    }

    #[test]
    fn test_falling_edge_keeps_waiting_for_input() {
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Agent("claude")), true, 100);
        tracker.on_hook(
            "claude",
            AgentStatus::WaitingForInput {
                prompt: "yes/no?".to_string(),
                options: vec!["yes".to_string(), "no".to_string()],
            },
            150,
        );
        let changed = tracker.on_probe(None, false, 200);
        assert!(!changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::WaitingForInput {
                    prompt: "yes/no?".to_string(),
                    options: vec!["yes".to_string(), "no".to_string()],
                },
                updated_ts: 150,
            })
        );
    }

    #[test]
    fn test_hook_thinking_not_overwritten_by_rising_edge() {
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Agent("claude")), false, 100);
        tracker.on_hook(
            "claude",
            AgentStatus::Thinking {
                task_desc: "Using bash".to_string(),
            },
            150,
        );
        let changed = tracker.on_probe(None, true, 200);
        assert!(!changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Thinking {
                    task_desc: "Using bash".to_string(),
                },
                updated_ts: 150,
            })
        );
    }

    #[test]
    fn test_shell_clears() {
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Agent("claude")), false, 100);
        let changed = tracker.on_probe(Some(Foreground::Shell), false, 200);
        assert!(changed);
        assert_eq!(tracker.current(), None);
    }

    #[test]
    fn test_other_clears_detected_but_keeps_hook_only() {
        // Detected agent retained on Other (detected set to false)
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Agent("claude")), false, 100);
        let changed = tracker.on_probe(Some(Foreground::Other), false, 200);
        assert!(!changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 100,
            })
        );

        // Hook-only agent kept on Other
        let mut tracker2 = AgentTracker::default();
        tracker2.on_hook("claude", AgentStatus::Idle, 100);
        let changed2 = tracker2.on_probe(Some(Foreground::Other), false, 200);
        assert!(!changed2);
        assert_eq!(
            tracker2.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 100,
            })
        );
    }

    #[test]
    fn test_agent_replaces_hook_only() {
        let mut tracker = AgentTracker::default();
        tracker.on_hook("codex", AgentStatus::Idle, 100);
        let changed = tracker.on_probe(Some(Foreground::Agent("omp")), false, 200);
        assert!(changed);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "omp".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 200,
            })
        );
    }

    #[test]
    fn test_hook_accepted_after_shell_probe() {
        let mut tracker = AgentTracker::default();
        tracker.on_probe(Some(Foreground::Shell), false, 100);
        let accepted = tracker.on_hook("claude", AgentStatus::Idle, 200);
        assert!(accepted);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 200,
            })
        );
    }

    #[test]
    fn test_falling_edge_respects_has_hook_updates() {
        // Prober-driven session: falling edge transitions to Completed
        let mut tracker1 = AgentTracker::default();
        tracker1.on_probe(Some(Foreground::Agent("claude")), true, 100);
        assert!(matches!(
            tracker1.current().unwrap().status,
            AgentStatus::Thinking { .. }
        ));
        tracker1.on_probe(None, false, 200);
        assert!(matches!(
            tracker1.current().unwrap().status,
            AgentStatus::Completed { .. }
        ));

        // Hook-driven session: falling edge does NOT transition to Completed
        let mut tracker2 = AgentTracker::default();
        tracker2.on_probe(Some(Foreground::Agent("claude")), true, 100);
        tracker2.on_hook(
            "claude",
            AgentStatus::Thinking {
                task_desc: "planning".into(),
            },
            150,
        );
        tracker2.on_probe(None, false, 200);
        assert!(matches!(
            tracker2.current().unwrap().status,
            AgentStatus::Thinking { task_desc } if task_desc == "planning"
        ));
    }

    #[test]
    fn test_hook_before_any_probe_accepted() {
        let mut tracker = AgentTracker::default();
        let accepted = tracker.on_hook("claude", AgentStatus::Idle, 100);
        assert!(accepted);
        assert_eq!(
            tracker.current(),
            Some(AgentState {
                agent: "claude".to_string(),
                status: AgentStatus::Idle,
                updated_ts: 100,
            })
        );
    }

    #[test]
    fn test_on_probe_no_change_returns_false() {
        let mut tracker = AgentTracker::default();
        assert!(!tracker.on_probe(Some(Foreground::Shell), false, 100));

        tracker.on_probe(Some(Foreground::Agent("claude")), false, 100);
        // Repeated identical probe
        assert!(!tracker.on_probe(Some(Foreground::Agent("claude")), false, 200));
    }

    #[test]
    fn test_epoch_seq_ordering_and_reset() {
        let mut tracker = AgentTracker::default();
        let s1 = AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: "step 1".into(),
            },
            attention: None,
            outcome: TurnOutcome::Started,
            resolution: SignalResolution::None,
            seq: Some(2),
            epoch: Some(10),
        };
        assert!(tracker.on_hook_signal("omp", s1, 100, 100_000, 0).changed);

        // Out-of-order / duplicate seq in same epoch dropped
        let s_old = AgentSignal {
            status: AgentStatus::Completed {
                summary: "stale".into(),
            },
            attention: None,
            outcome: TurnOutcome::Done,
            resolution: SignalResolution::ClearNonPlan,
            seq: Some(1),
            epoch: Some(10),
        };
        assert!(
            !tracker
                .on_hook_signal("omp", s_old, 101, 101_000, 0)
                .changed
        );
        assert!(matches!(
            tracker.current().unwrap().status,
            AgentStatus::Thinking { .. }
        ));

        // New epoch resets seq
        let s_new_epoch = AgentSignal {
            status: AgentStatus::Completed {
                summary: "done".into(),
            },
            attention: None,
            outcome: TurnOutcome::Done,
            resolution: SignalResolution::ClearNonPlan,
            seq: Some(1),
            epoch: Some(11),
        };
        let res = tracker.on_hook_signal("omp", s_new_epoch, 102, 102_000, 0);
        assert!(res.changed);
        assert_eq!(res.alert.unwrap().kind, AgentAlertKind::Finished);
    }

    #[test]
    fn test_overlapping_prompts_and_plan_survives_aborted_agent_end() {
        let mut tracker = AgentTracker::default();
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "plan".into(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
            100,
            100_000,
            0,
        );

        // Plan review opens
        let r1 = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: "Approve plan?".into(),
                    options: vec!["Execute".into(), "Keep".into()],
                },
                attention: Some(AttentionSpec {
                    key: Some("rev-1".into()),
                    kind: AttentionKind::Plan {
                        review_id: "rev-1".into(),
                        option_ids: vec!["execute".into(), "keep".into()],
                    },
                    prompt: "Approve plan?".into(),
                    options: vec!["Execute".into(), "Keep".into()],
                    actionable: true,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: Some(2),
                epoch: Some(1),
            },
            101,
            101_000,
            0,
        );
        assert_eq!(r1.alert.as_ref().unwrap().kind, AgentAlertKind::NeedsReview);
        let plan_id = r1.alert.unwrap().attention_id;

        // Aborted agent_end arrives after plan_review_requested -> Plan MUST stay visible!
        let r2 = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Idle,
                attention: None,
                outcome: TurnOutcome::Aborted,
                resolution: SignalResolution::ClearNonPlan,
                seq: Some(3),
                epoch: Some(1),
            },
            102,
            102_000,
            0,
        );
        assert!(!r2.changed);
        assert!(r2.alert.is_none());
        assert_eq!(tracker.head_attention().unwrap().id, plan_id);
        assert!(matches!(
            tracker.current().unwrap().status,
            AgentStatus::WaitingForInput { .. }
        ));

        // Second prompt queued behind Plan; resolving Plan promotes second prompt and emits alert
        let r3 = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: "Run ls?".into(),
                    options: vec!["Allow once".into(), "Deny".into()],
                },
                attention: Some(AttentionSpec {
                    key: Some("tc-1".into()),
                    kind: AttentionKind::Approval,
                    prompt: "Run ls?".into(),
                    options: vec!["Allow once".into(), "Deny".into()],
                    actionable: true,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: Some(4),
                epoch: Some(1),
            },
            103,
            103_000,
            0,
        );
        assert!(!r3.changed);
        assert!(r3.alert.is_none());

        let r4 = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "Thinking…".into(),
                },
                attention: None,
                outcome: TurnOutcome::None,
                resolution: SignalResolution::ByKey("rev-1".into()),
                seq: Some(5),
                epoch: Some(1),
            },
            104,
            104_000,
            0,
        );
        assert!(r4.changed);
        assert_eq!(r4.alert.unwrap().kind, AgentAlertKind::NeedsApproval);
    }

    #[test]
    fn test_shell_grace_and_osc_7501_fallback() {
        let mut tracker = AgentTracker::default();
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "working".into(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
            100,
            100_000,
            1,
        );

        let empty_sig = TerminalSignals {
            title: None,
            progress_active: false,
            run_status: None,
        };
        // Shell probe at t=101 and t=102 keeps Thinking during 3s grace
        let p1 = tracker.on_probe_signals(Some(Foreground::Shell), &empty_sig, 101, 101_000);
        assert!(!p1.changed);
        assert!(p1.alert.is_none());
        let p2 = tracker.on_probe_signals(Some(Foreground::Shell), &empty_sig, 103, 103_000);
        assert!(!p2.changed);
        // At t=104 (104 - 101 >= 3), clears and emits Failed
        let p3 = tracker.on_probe_signals(Some(Foreground::Shell), &empty_sig, 104, 104_000);
        assert!(p3.changed);
        assert_eq!(p3.alert.unwrap().kind, AgentAlertKind::Failed);
        assert_eq!(tracker.current(), None);

        // OSC 7501 fallback when has_hook_updates && Thinking
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "Continuing…".into(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(2),
                epoch: Some(1),
            },
            200,
            200_000,
            5,
        );
        // Stale OSC seq <= 5 ignored
        let stale_osc = TerminalSignals {
            title: None,
            progress_active: false,
            run_status: Some(crate::pty::output::OscRunStatus {
                kind: OscStatusKind::Done,
                message: Some("old".into()),
                seq: 5,
            }),
        };
        assert!(
            !tracker
                .on_probe_signals(Some(Foreground::Agent("omp")), &stale_osc, 201, 201_000)
                .changed
        );

        // Newer OSC seq > 5 applies Done + Finished alert
        let fresh_osc = TerminalSignals {
            title: None,
            progress_active: false,
            run_status: Some(crate::pty::output::OscRunStatus {
                kind: OscStatusKind::Done,
                message: Some("finished via osc".into()),
                seq: 6,
            }),
        };
        let res =
            tracker.on_probe_signals(Some(Foreground::Agent("omp")), &fresh_osc, 202, 202_000);
        assert!(res.changed);
        assert_eq!(res.alert.unwrap().kind, AgentAlertKind::Finished);
        assert_eq!(
            tracker.current().unwrap().status,
            AgentStatus::Completed {
                summary: "finished via osc".into()
            }
        );
    }

    #[test]
    fn test_text_question_cleared_on_turn_started() {
        let mut tracker = AgentTracker::default();
        let q_sig = AgentSignal {
            status: AgentStatus::WaitingForInput {
                prompt: "Proceed?".into(),
                options: vec!["Yes".into(), "No".into()],
            },
            attention: Some(AttentionSpec {
                key: None,
                kind: AttentionKind::TextQuestion,
                prompt: "Proceed?".into(),
                options: vec!["Yes".into(), "No".into()],
                actionable: true,
            }),
            outcome: TurnOutcome::None,
            resolution: SignalResolution::ClearNonPlan,
            seq: Some(1),
            epoch: Some(1),
        };
        assert!(
            tracker
                .on_hook_signal("omp", q_sig, 100, 100_000, 0)
                .changed
        );
        assert!(matches!(
            tracker.current().unwrap().status,
            AgentStatus::WaitingForInput { .. }
        ));

        let start_sig = AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: "Yes".into(),
            },
            attention: None,
            outcome: TurnOutcome::Started,
            resolution: SignalResolution::None,
            seq: Some(2),
            epoch: Some(1),
        };
        let res = tracker.on_hook_signal("omp", start_sig, 101, 101_000, 0);
        assert!(res.changed);
        assert!(res.alert.is_none());
        assert_eq!(
            tracker.current().unwrap().status,
            AgentStatus::Thinking {
                task_desc: "Yes".into()
            }
        );
        assert!(tracker.head_attention().is_none());
    }

    #[test]
    fn test_legacy_approval_cleared_by_post_tool_use() {
        let mut tracker = AgentTracker::default();
        let perm = crate::agent::map::map_signal(
            "claude",
            Some("PermissionRequest"),
            &serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": "ls" } }),
        )
        .unwrap();
        let r1 = tracker.on_hook_signal("claude", perm, 100, 100_000, 0);
        assert!(r1.changed);
        assert!(matches!(
            tracker.current().unwrap().status,
            AgentStatus::WaitingForInput { .. }
        ));

        let post =
            crate::agent::map::map_signal("claude", Some("PostToolUse"), &serde_json::json!({}))
                .unwrap();
        let r2 = tracker.on_hook_signal("claude", post, 101, 101_000, 0);
        assert!(r2.changed);
        assert!(matches!(
            tracker.current().unwrap().status,
            AgentStatus::Thinking { .. }
        ));
        assert!(tracker.head_attention().is_none());
    }

    #[test]
    fn test_idle_dismiss_immediately_transitions() {
        let mut tracker = AgentTracker::default();

        // None -> Idle emits no activity
        let r0 = tracker.on_hook_signal(
            "omp",
            AgentSignal::from_status(AgentStatus::Idle),
            100,
            100_000,
            0,
        );
        assert!(r0.activity.is_none());

        // Idle -> Idle (same agent) emits no activity
        let r_same = tracker.on_hook_signal(
            "omp",
            AgentSignal::from_status(AgentStatus::Idle),
            101,
            101_000,
            0,
        );
        assert!(r_same.activity.is_none());

        // Thinking -> Completed emits End with dismiss_immediately: false
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "working".into(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(1),
                epoch: Some(1),
            },
            102,
            102_000,
            0,
        );
        let r_done = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Completed {
                    summary: "done".into(),
                },
                attention: None,
                outcome: TurnOutcome::Done,
                resolution: SignalResolution::ClearNonPlan,
                seq: Some(2),
                epoch: Some(1),
            },
            105,
            105_000,
            0,
        );
        let act_done = r_done.activity.expect("completed activity");
        assert_eq!(act_done.event, ActivityEventKind::End);
        assert_eq!(act_done.phase, ActivityPhase::Done);
        assert!(!act_done.dismiss_immediately);

        // Completed -> Idle emits End with dismiss_immediately: true
        let r_idle = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Idle,
                attention: None,
                outcome: TurnOutcome::None,
                resolution: SignalResolution::ClearAll,
                seq: Some(3),
                epoch: Some(1),
            },
            110,
            110_000,
            0,
        );
        let act_idle = r_idle.activity.expect("idle after completed activity");
        assert_eq!(act_idle.event, ActivityEventKind::End);
        assert_eq!(act_idle.phase, ActivityPhase::Done);
        assert!(act_idle.dismiss_immediately);

        // Thinking -> Idle emits End with dismiss_immediately: true
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "step".into(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(4),
                epoch: Some(1),
            },
            120,
            120_000,
            0,
        );
        let r_abort = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Idle,
                attention: None,
                outcome: TurnOutcome::Aborted,
                resolution: SignalResolution::ClearAll,
                seq: Some(5),
                epoch: Some(1),
            },
            125,
            125_000,
            0,
        );
        let act_abort = r_abort.activity.expect("idle after thinking activity");
        assert_eq!(act_abort.event, ActivityEventKind::End);
        assert!(act_abort.dismiss_immediately);

        // WaitingForInput -> Idle emits End with dismiss_immediately: true
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::WaitingForInput {
                    prompt: "Allow?".into(),
                    options: vec!["Allow".into()],
                },
                attention: Some(AttentionSpec {
                    key: Some("k1".into()),
                    kind: AttentionKind::Approval,
                    prompt: "Allow?".into(),
                    options: vec!["Allow".into()],
                    actionable: true,
                }),
                outcome: TurnOutcome::None,
                resolution: SignalResolution::None,
                seq: Some(6),
                epoch: Some(1),
            },
            130,
            130_000,
            0,
        );
        let r_wait_idle = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Idle,
                attention: None,
                outcome: TurnOutcome::None,
                resolution: SignalResolution::ClearAll,
                seq: Some(7),
                epoch: Some(1),
            },
            135,
            135_000,
            0,
        );
        let act_wait_idle = r_wait_idle.activity.expect("idle after waiting activity");
        assert_eq!(act_wait_idle.event, ActivityEventKind::End);
        assert!(act_wait_idle.dismiss_immediately);

        // Idle -> Idle across different agents emits no activity
        let r_cross_idle = tracker.on_hook_signal(
            "claude",
            AgentSignal::from_status(AgentStatus::Idle),
            136,
            136_000,
            0,
        );
        assert!(r_cross_idle.activity.is_none());

        // Thinking -> Idle with TurnOutcome::Failed keeps dismiss_immediately: false
        tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Thinking {
                    task_desc: "failing".into(),
                },
                attention: None,
                outcome: TurnOutcome::Started,
                resolution: SignalResolution::None,
                seq: Some(8),
                epoch: Some(1),
            },
            140,
            140_000,
            0,
        );
        let r_fail_idle = tracker.on_hook_signal(
            "omp",
            AgentSignal {
                status: AgentStatus::Idle,
                attention: None,
                outcome: TurnOutcome::Failed {
                    error: "boom".into(),
                },
                resolution: SignalResolution::ClearAll,
                seq: Some(9),
                epoch: Some(1),
            },
            145,
            145_000,
            0,
        );
        let act_fail_idle = r_fail_idle.activity.expect("failed idle activity");
        assert_eq!(act_fail_idle.event, ActivityEventKind::End);
        assert_eq!(act_fail_idle.phase, ActivityPhase::Failed);
        assert!(!act_fail_idle.dismiss_immediately);

        // Thinking -> None (agent disappeared in probe) emits Failed End with dismiss_immediately: false
        let mut probe_tracker = AgentTracker::default();
        probe_tracker.on_probe(Some(Foreground::Agent("claude")), true, 200);
        let r_gone = probe_tracker.on_probe_signals(
            Some(Foreground::Shell),
            &TerminalSignals {
                title: None,
                progress_active: false,
                run_status: None,
            },
            205,
            205_000,
        );
        let act_gone = r_gone.activity.expect("disappeared activity");
        assert_eq!(act_gone.event, ActivityEventKind::End);
        assert_eq!(act_gone.phase, ActivityPhase::Failed);
        assert!(!act_gone.dismiss_immediately);

        // Completed -> None (agent exited back to shell in probe) emits Done End with dismiss_immediately: true
        let mut completed_probe_tracker = AgentTracker::default();
        completed_probe_tracker.on_probe(Some(Foreground::Agent("claude")), true, 300);
        completed_probe_tracker.on_probe(Some(Foreground::Agent("claude")), false, 302);
        let r_shell_after_done = completed_probe_tracker.on_probe_signals(
            Some(Foreground::Shell),
            &TerminalSignals {
                title: None,
                progress_active: false,
                run_status: None,
            },
            305,
            305_000,
        );
        let act_shell_done = r_shell_after_done
            .activity
            .expect("completed cleared by shell activity");
        assert_eq!(act_shell_done.event, ActivityEventKind::End);
        assert_eq!(act_shell_done.phase, ActivityPhase::Done);
        assert!(act_shell_done.dismiss_immediately);
    }

    #[test]
    fn test_stale_ask_cleared_on_turn_started_and_osc_permission_maps_to_approval() {
        let mut tracker = AgentTracker::default();
        let ask_sig = AgentSignal {
            status: AgentStatus::WaitingForInput {
                prompt: "Pick one".into(),
                options: vec!["A".into(), "B".into()],
            },
            attention: Some(AttentionSpec {
                key: Some("tc-ask".into()),
                kind: AttentionKind::Ask {
                    multi: false,
                    initial: 0,
                },
                prompt: "Pick one".into(),
                options: vec!["A".into(), "B".into()],
                actionable: true,
            }),
            outcome: TurnOutcome::None,
            resolution: SignalResolution::None,
            seq: Some(1),
            epoch: Some(1),
        };
        assert!(
            tracker
                .on_hook_signal("omp", ask_sig, 100, 100_000, 0)
                .changed
        );
        assert!(matches!(
            tracker.head_attention().map(|a| &a.kind),
            Some(AttentionKind::Ask { .. })
        ));

        let start_sig = AgentSignal {
            status: AgentStatus::Thinking {
                task_desc: "next turn".into(),
            },
            attention: None,
            outcome: TurnOutcome::Started,
            resolution: SignalResolution::None,
            seq: Some(2),
            epoch: Some(1),
        };
        let res = tracker.on_hook_signal("omp", start_sig, 101, 101_000, 0);
        assert!(res.changed);
        assert!(tracker.head_attention().is_none());
        assert_eq!(
            tracker.current().unwrap().status,
            AgentStatus::Thinking {
                task_desc: "next turn".into()
            }
        );

        let mut osc_tracker = AgentTracker::default();
        let perm_sig = TerminalSignals {
            title: None,
            progress_active: false,
            run_status: Some(crate::pty::output::OscRunStatus {
                kind: OscStatusKind::Blocked {
                    kind: Some("permission".into()),
                },
                message: Some("Allow bash?".into()),
                seq: 1,
            }),
        };
        let osc_res =
            osc_tracker.on_probe_signals(Some(Foreground::Agent("omp")), &perm_sig, 200, 200_000);
        assert!(osc_res.changed);
        assert_eq!(osc_res.alert.unwrap().kind, AgentAlertKind::NeedsApproval);
        let head = osc_tracker.head_attention().unwrap();
        assert_eq!(head.kind, AttentionKind::Approval);
        assert_eq!(head.options, vec!["Allow".to_string(), "Deny".to_string()]);
    }
}
