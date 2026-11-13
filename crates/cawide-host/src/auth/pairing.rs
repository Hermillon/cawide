use parking_lot::Mutex;
use rand::RngCore;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use crate::auth::error::AuthError;
use cawide_protocol::PairingUri;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct PairingTicket {
    pub host_node_id: [u8; 32],
    pub pairing_secret: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
    pub expires_at: Instant,
}

impl PairingTicket {
    pub fn to_uri(&self) -> String {
        PairingUri {
            host_node_id: self.host_node_id,
            pairing_secret: self.pairing_secret,
            relay_url: self.relay_url.clone(),
            direct_addrs: self.direct_addrs.clone(),
        }
        .to_uri()
    }

    pub fn render_terminal_qr(&self) -> Result<String, AuthError> {
        let uri = self.to_uri();
        let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::L)?;
        let raw = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(false)
            .build();
        let lines: Vec<&str> = raw.lines().collect();
        let width = lines.first().map(|l| l.chars().count()).unwrap_or(0);
        let margin_len = width + 2;
        let mut result = Vec::with_capacity(lines.len() + 2);
        result.push(" ".repeat(margin_len));
        for line in lines {
            result.push(format!(" {line} "));
        }
        result.push(" ".repeat(margin_len));
        Ok(result.join("\n"))
    }
}

pub struct PairingManager {
    active_ticket: Mutex<Option<PairingTicket>>,
    ttl: Duration,
}

impl PairingManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            active_ticket: Mutex::new(None),
            ttl,
        }
    }

    pub fn start_pairing(
        &self,
        host_node_id: [u8; 32],
        relay_url: Option<String>,
        direct_addrs: Vec<SocketAddr>,
    ) -> Result<PairingTicket, AuthError> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let ticket = PairingTicket {
            host_node_id,
            pairing_secret: secret,
            relay_url,
            direct_addrs,
            expires_at: Instant::now() + self.ttl,
        };
        *self.active_ticket.lock() = Some(ticket.clone());
        Ok(ticket)
    }

    pub fn active_ticket(&self) -> Option<PairingTicket> {
        let lock = self.active_ticket.lock();
        match &*lock {
            Some(t) if Instant::now() <= t.expires_at => Some(t.clone()),
            _ => None,
        }
    }

    pub fn render_terminal_qr(&self) -> Result<String, AuthError> {
        let ticket = self.active_ticket().ok_or(AuthError::PairingExpired)?;
        ticket.render_terminal_qr()
    }

    pub fn verify_and_consume(&self, received_secret: &[u8; 32]) -> Result<(), AuthError> {
        let mut lock = self.active_ticket.lock();
        let ticket = lock.as_ref().ok_or(AuthError::PairingExpired)?;
        if Instant::now() > ticket.expires_at {
            *lock = None;
            return Err(AuthError::PairingExpired);
        }
        if ticket.pairing_secret.ct_eq(received_secret).into() {
            *lock = None;
            Ok(())
        } else {
            Err(AuthError::InvalidPairingSecret)
        }
    }
}

impl Default for PairingManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

impl std::fmt::Debug for PairingManager {
    // Deliberately omits the active ticket: it contains the pairing secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingManager")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}
