//! Background watcher for host listening port changes.

use std::sync::Arc;
use std::time::Duration;

use cawide_protocol::types::{HostEvent, ListeningPort};

use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::connections::ConnectionTracker;
use crate::net::registry::SessionRegistry;

pub const PORT_WATCH_INTERVAL: Duration = Duration::from_secs(2);

pub struct PortWatcher {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PortWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PortWatcher {
    pub fn spawn(
        registry: Arc<SessionRegistry>,
        broadcaster: Arc<HostEventBroadcaster>,
        connections: Arc<ConnectionTracker>,
    ) -> Self {
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(PORT_WATCH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut last_ports: Option<Vec<ListeningPort>> = None;
            let mut last_error: Option<String> = None;

            loop {
                interval.tick().await;

                if !connections.has_connections() {
                    last_ports = None;
                    continue;
                }

                let reg = Arc::clone(&registry);
                let roots = reg.root_pids();
                let my_pid = std::process::id();

                let scan_res =
                    tokio::task::spawn_blocking(move || crate::ports::scan(Some(my_pid), &roots))
                        .await;

                match scan_res {
                    Ok(Ok(ports)) => {
                        last_error = None;
                        if last_ports.as_ref() != Some(&ports) {
                            broadcaster.broadcast(HostEvent::PortsChanged {
                                ports: ports.clone(),
                            });
                            last_ports = Some(ports);
                        }
                    }
                    Ok(Err(e)) => {
                        if last_error.as_deref() != Some(&e) {
                            tracing::warn!(error = %e, "listening port scan failed");
                            last_error = Some(e);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "port scan task cancelled or panicked");
                        break;
                    }
                }
            }
        });

        Self { task }
    }
}
