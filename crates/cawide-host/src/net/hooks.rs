//! Transport gate: rejects unauthorized peers before any stream is accepted.

use std::sync::Arc;

use crate::auth::{AuthorizedKeysStore, PairingManager};
use cawide_protocol::{
    ALPN_CAWIDE, ALPN_CAWIDE_LEGACY, ALPN_CAWIDE_PAIR, CLOSE_PAIRING_DISABLED, CLOSE_UNAUTHORIZED,
    CLOSE_UNSUPPORTED_ALPN,
};

#[derive(Debug, Clone)]
pub struct CawideEndpointHooks {
    auth_store: Arc<AuthorizedKeysStore>,
    pairing_manager: Arc<PairingManager>,
}

impl CawideEndpointHooks {
    pub fn new(auth_store: Arc<AuthorizedKeysStore>, pairing_manager: Arc<PairingManager>) -> Self {
        Self {
            auth_store,
            pairing_manager,
        }
    }
}

impl iroh::endpoint::EndpointHooks for CawideEndpointHooks {
    async fn after_handshake<'a>(
        &'a self,
        conn: &'a iroh::endpoint::Connection,
    ) -> iroh::endpoint::AfterHandshakeOutcome {
        if conn.side() == iroh::endpoint::Side::Client {
            return iroh::endpoint::AfterHandshakeOutcome::Accept;
        }
        let remote = conn.remote_id();
        let alpn = conn.alpn();
        match alpn {
            a if a == ALPN_CAWIDE => {
                if self.auth_store.is_authorized(remote.as_bytes()) {
                    tracing::debug!(remote = %remote.fmt_short(), "accepted authorized connection");
                    iroh::endpoint::AfterHandshakeOutcome::Accept
                } else {
                    tracing::warn!(remote = %remote.fmt_short(), alpn = ?String::from_utf8_lossy(alpn), "rejected unauthorized connection");
                    reject(CLOSE_UNAUTHORIZED, b"unauthorized node id")
                }
            }
            a if a == ALPN_CAWIDE_PAIR => {
                if self.pairing_manager.active_ticket().is_some() {
                    tracing::debug!(remote = %remote.fmt_short(), "accepted pairing connection");
                    iroh::endpoint::AfterHandshakeOutcome::Accept
                } else {
                    tracing::warn!(remote = %remote.fmt_short(), alpn = ?String::from_utf8_lossy(alpn), "rejected pairing disabled");
                    reject(CLOSE_PAIRING_DISABLED, b"pairing disabled")
                }
            }
            a if ALPN_CAWIDE_LEGACY.contains(&a) => {
                tracing::debug!(remote = %remote.fmt_short(), "accepted legacy connection for termination");
                iroh::endpoint::AfterHandshakeOutcome::Accept
            }
            _ => {
                tracing::warn!(remote = %remote.fmt_short(), alpn = ?String::from_utf8_lossy(alpn), "rejected unsupported alpn");
                reject(CLOSE_UNSUPPORTED_ALPN, b"unsupported alpn")
            }
        }
    }
}

fn reject(code: u32, reason: &[u8]) -> iroh::endpoint::AfterHandshakeOutcome {
    iroh::endpoint::AfterHandshakeOutcome::Reject {
        error_code: iroh::endpoint::VarInt::from_u32(code),
        reason: reason.to_vec(),
    }
}
