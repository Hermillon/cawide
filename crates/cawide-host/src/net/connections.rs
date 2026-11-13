//! Connection tracking across active QUIC connections (Brick 9).

use iroh::endpoint::VarInt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

type ConnMap = HashMap<[u8; 32], Vec<(usize, iroh::endpoint::Connection)>>;

pub struct ConnectionTracker {
    conns: parking_lot::Mutex<ConnMap>,
    next_id: AtomicUsize,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            conns: parking_lot::Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(1),
        }
    }

    pub fn register(&self, node: [u8; 32], conn: iroh::endpoint::Connection) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut conns = self.conns.lock();
        conns.entry(node).or_default().push((id, conn));
        id
    }

    pub fn unregister(&self, node: [u8; 32], id: usize) {
        let mut conns = self.conns.lock();
        if let Some(list) = conns.get_mut(&node) {
            list.retain(|(conn_id, _)| *conn_id != id);
            if list.is_empty() {
                conns.remove(&node);
            }
        }
    }

    pub fn close_all(&self, node: [u8; 32], code: u32, reason: &[u8]) -> usize {
        let list = {
            let mut conns = self.conns.lock();
            conns.remove(&node).unwrap_or_default()
        };
        let count = list.len();
        let code = VarInt::from_u32(code);
        for (_, conn) in list {
            conn.close(code, reason);
        }
        count
    }

    pub fn has_connections(&self) -> bool {
        !self.conns.lock().is_empty()
    }
}

impl std::fmt::Debug for ConnectionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionTracker")
            .field("tracked_nodes", &self.conns.lock().len())
            .finish()
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}
