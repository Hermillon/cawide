use std::sync::Arc;
use std::time::Duration;

use cawide_protocol::types::HostEvent;

use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::registry::SessionRegistry;
use crate::pty::process::ProcScratch;
use crate::watch::RootWatchers;

pub const PROBE_INTERVAL: Duration = Duration::from_secs(1);

pub struct SessionProbe {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SessionProbe {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SessionProbe {
    pub fn spawn(
        registry: Arc<SessionRegistry>,
        broadcaster: Arc<HostEventBroadcaster>,
        mut watchers: Option<RootWatchers>,
    ) -> Self {
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROBE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut scratch = ProcScratch::default();

            loop {
                interval.tick().await;
                let reg = Arc::clone(&registry);
                let Ok((outcome, returned_scratch)) = tokio::task::spawn_blocking(move || {
                    let out = reg.probe(&mut scratch);
                    (out, scratch)
                })
                .await
                else {
                    break;
                };
                scratch = returned_scratch;

                for summary in outcome.changed {
                    broadcaster.broadcast(HostEvent::SessionUpdated { summary });
                }

                for (session_id, url) in outcome.detected_urls {
                    broadcaster.broadcast(HostEvent::WebUrlDetected { session_id, url });
                }

                if let Some(w) = watchers.as_mut() {
                    w.sync(&outcome.roots);
                }
            }
        });

        Self { task }
    }
}
