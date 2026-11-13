use cawide_protocol::types::{AgentState, AgentStatus};

use crate::agent::detect::Foreground;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    state: AgentState,
    detected: bool,
    pub has_hook_updates: bool,
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

    pub fn on_probe(&mut self, fg: Option<Foreground>, progress_active: bool, now: u64) -> bool {
        let old_state = self.current();

        if let Some(f) = fg {
            match f {
                Foreground::Shell => {
                    self.tracked = None;
                }
                Foreground::Agent(slug) => {
                    if self.tracked.as_ref().map(|t| t.state.agent.as_str()) == Some(slug) {
                        if let Some(t) = self.tracked.as_mut() {
                            t.detected = true;
                        }
                    } else {
                        let status = if progress_active {
                            AgentStatus::Thinking {
                                task_desc: String::new(),
                            }
                        } else {
                            AgentStatus::Idle
                        };
                        self.tracked = Some(Tracked {
                            state: AgentState {
                                agent: slug.to_string(),
                                status,
                                updated_ts: now,
                            },
                            detected: true,
                            has_hook_updates: false,
                        });
                    }
                }
                Foreground::Other => {
                    if let Some(t) = self.tracked.as_mut() {
                        t.detected = false;
                    }
                }
            }
            self.last_foreground = Some(f);
        }

        if let Some(t) = &mut self.tracked {
            if progress_active && !self.progress_was_active {
                if !matches!(t.state.status, AgentStatus::Thinking { .. }) {
                    t.state.status = AgentStatus::Thinking {
                        task_desc: String::new(),
                    };
                    t.state.updated_ts = now;
                }
            } else if !progress_active
                && self.progress_was_active
                && matches!(t.state.status, AgentStatus::Thinking { .. })
                && !t.has_hook_updates
            {
                t.state.status = AgentStatus::Completed {
                    summary: String::new(),
                };
                t.state.updated_ts = now;
            }
        }

        self.progress_was_active = progress_active;
        self.current() != old_state
    }

    pub fn on_hook(&mut self, agent: &str, status: AgentStatus, now: u64) -> bool {
        if let Some(slug) = to_static_agent(agent) {
            self.last_foreground = Some(Foreground::Agent(slug));
        }

        if let Some(t) = &mut self.tracked {
            t.state.agent = agent.to_string();
            t.state.status = status;
            t.state.updated_ts = now;
            t.has_hook_updates = true;
        } else {
            self.tracked = Some(Tracked {
                state: AgentState {
                    agent: agent.to_string(),
                    status,
                    updated_ts: now,
                },
                detected: false,
                has_hook_updates: true,
            });
        }
        true
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
}
