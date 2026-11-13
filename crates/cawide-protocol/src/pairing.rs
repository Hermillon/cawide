//! Pairing URI representation, parsing, and percent-encoding.

use std::net::SocketAddr;

use crate::error::ProtocolError;

/// Maximum number of direct address hints in a pairing URI.
pub const MAX_PAIRING_ADDRS: usize = 8;

/// Structured pairing URI payload exchanged out-of-band (e.g. via QR code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub host_node_id: [u8; 32],
    pub pairing_secret: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
}

pub fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len().saturating_mul(3));
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(encoded, "%{:02X}", byte);
            }
        }
    }
    encoded
}

pub fn percent_decode(input: &str) -> Result<String, ProtocolError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next().ok_or_else(|| {
                ProtocolError::InvalidPairingUri("truncated percent escape".into())
            })?;
            let h2 = chars.next().ok_or_else(|| {
                ProtocolError::InvalidPairingUri("truncated percent escape".into())
            })?;
            let hex_str = [h1, h2];
            let s = std::str::from_utf8(&hex_str).map_err(|_| {
                ProtocolError::InvalidPairingUri("invalid hex in percent escape".into())
            })?;
            let val = u8::from_str_radix(s, 16).map_err(|_| {
                ProtocolError::InvalidPairingUri("invalid hex in percent escape".into())
            })?;
            bytes.push(val);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).map_err(|_| {
        ProtocolError::InvalidPairingUri("invalid utf-8 after percent decoding".into())
    })
}

impl PairingUri {
    pub fn to_uri(&self) -> String {
        let mut uri = format!(
            "cawide://pair?node={}&secret={}",
            hex::encode(self.host_node_id),
            hex::encode(self.pairing_secret)
        );
        if let Some(relay) = &self.relay_url {
            uri.push_str("&relay=");
            uri.push_str(&percent_encode(relay));
        }
        for addr in &self.direct_addrs {
            uri.push_str("&addr=");
            uri.push_str(&percent_encode(&addr.to_string()));
        }
        uri
    }

    pub fn parse(uri: &str) -> Result<Self, ProtocolError> {
        if !uri.starts_with("cawide://") {
            return Err(ProtocolError::InvalidPairingUri(
                "scheme must be cawide://".into(),
            ));
        }
        let after_scheme = &uri["cawide://".len()..];
        let query_idx = after_scheme.find('?').ok_or_else(|| {
            ProtocolError::InvalidPairingUri("missing query delimiter '?'".into())
        })?;
        let host_part = &after_scheme[..query_idx];
        if host_part != "pair" {
            return Err(ProtocolError::InvalidPairingUri(format!(
                "invalid host '{host_part}', expected 'pair'"
            )));
        }

        let query = &after_scheme[query_idx + 1..];
        if query.is_empty() {
            return Err(ProtocolError::InvalidPairingUri(
                "query parameters are empty".into(),
            ));
        }

        let mut seen_node: Option<[u8; 32]> = None;
        let mut seen_secret: Option<[u8; 32]> = None;
        let mut seen_relay: Option<String> = None;
        let mut direct_addrs: Vec<SocketAddr> = Vec::new();

        for param in query.split('&') {
            if param.is_empty() {
                return Err(ProtocolError::InvalidPairingUri(
                    "empty query parameter".into(),
                ));
            }
            let (key, val) = param.split_once('=').ok_or_else(|| {
                ProtocolError::InvalidPairingUri("missing '=' in parameter".into())
            })?;

            match key {
                "node" => {
                    if seen_node.is_some() {
                        return Err(ProtocolError::InvalidPairingUri(
                            "duplicate node parameter".into(),
                        ));
                    }
                    if val.len() != 64 {
                        return Err(ProtocolError::InvalidPairingUri(
                            "node must be 64 hex characters".into(),
                        ));
                    }
                    let mut node = [0u8; 32];
                    hex::decode_to_slice(val, &mut node).map_err(|e| {
                        ProtocolError::InvalidPairingUri(format!("invalid hex node: {e}"))
                    })?;
                    seen_node = Some(node);
                }
                "secret" => {
                    if seen_secret.is_some() {
                        return Err(ProtocolError::InvalidPairingUri(
                            "duplicate secret parameter".into(),
                        ));
                    }
                    if val.len() != 64 {
                        return Err(ProtocolError::InvalidPairingUri(
                            "secret must be 64 hex characters".into(),
                        ));
                    }
                    let mut secret = [0u8; 32];
                    hex::decode_to_slice(val, &mut secret).map_err(|e| {
                        ProtocolError::InvalidPairingUri(format!("invalid hex secret: {e}"))
                    })?;
                    seen_secret = Some(secret);
                }
                "relay" => {
                    if seen_relay.is_some() {
                        return Err(ProtocolError::InvalidPairingUri(
                            "duplicate relay parameter".into(),
                        ));
                    }
                    let decoded = percent_decode(val)?;
                    seen_relay = Some(decoded);
                }
                "addr" => {
                    let decoded = percent_decode(val)?;
                    let addr: SocketAddr = decoded.parse().map_err(|e| {
                        ProtocolError::InvalidPairingUri(format!("invalid socket address: {e}"))
                    })?;
                    direct_addrs.push(addr);
                    if direct_addrs.len() > MAX_PAIRING_ADDRS {
                        return Err(ProtocolError::InvalidPairingUri(
                            "more than 8 addr parameters".into(),
                        ));
                    }
                }
                unknown => {
                    return Err(ProtocolError::InvalidPairingUri(format!(
                        "unknown query key '{unknown}'"
                    )));
                }
            }
        }

        let host_node_id = seen_node
            .ok_or_else(|| ProtocolError::InvalidPairingUri("missing node parameter".into()))?;
        let pairing_secret = seen_secret
            .ok_or_else(|| ProtocolError::InvalidPairingUri("missing secret parameter".into()))?;

        Ok(PairingUri {
            host_node_id,
            pairing_secret,
            relay_url: seen_relay,
            direct_addrs,
        })
    }
}
