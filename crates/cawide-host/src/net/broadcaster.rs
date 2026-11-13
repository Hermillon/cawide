//! Fan-out of host events to every open Control stream.

use cawide_protocol::types::HostEvent;
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
pub struct HostEventBroadcaster {
    sender: broadcast::Sender<HostEvent>,
}

impl HostEventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Delivers `event` to current subscribers; with none, it is intentionally dropped.
    pub fn broadcast(&self, event: HostEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HostEvent> {
        self.sender.subscribe()
    }
}
