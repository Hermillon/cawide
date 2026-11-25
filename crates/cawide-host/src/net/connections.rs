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

    pub fn close_all_connections(&self, code: u32, reason: &[u8]) -> usize {
        let all_conns: Vec<iroh::endpoint::Connection> = {
            let mut conns = self.conns.lock();
            let mut list = Vec::new();
            for (_, pairs) in conns.drain() {
                for (_, conn) in pairs {
                    list.push(conn);
                }
            }
            list
        };
        let count = all_conns.len();
        let code = VarInt::from_u32(code);
        for conn in all_conns {
            conn.close(code, reason);
        }
        count
    }

    pub fn close_all_except(&self, except_conn_id: usize, code: u32, reason: &[u8]) -> usize {
        let to_close: Vec<iroh::endpoint::Connection> = {
            let mut conns = self.conns.lock();
            let mut close_list = Vec::new();
            conns.retain(|_, pairs| {
                pairs.retain(|(id, conn)| {
                    if *id == except_conn_id {
                        true
                    } else {
                        close_list.push(conn.clone());
                        false
                    }
                });
                !pairs.is_empty()
            });
            close_list
        };
        let count = to_close.len();
        let code = VarInt::from_u32(code);
        for conn in to_close {
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
