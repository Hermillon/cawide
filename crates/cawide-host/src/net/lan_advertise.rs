//! LAN advertisement via mDNS Service Discovery (RFC 6763).

use std::net::SocketAddr;
use std::sync::Arc;

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub(crate) fn build_service_info(
    node_id: &[u8; 32],
    addrs: &[SocketAddr],
    display_name: &str,
) -> Result<mdns_sd::ServiceInfo, mdns_sd::Error> {
    if addrs.is_empty() {
        return Err(mdns_sd::Error::Msg(
            "at least one direct address is required".into(),
        ));
    }

    let node_id_hex = hex::encode(node_id);
    let instance_name = format!("cawide-{}", &node_id_hex[..16]);
    let hostname = format!("{instance_name}.local.");
    let port = addrs[0].port();

    let ips: Vec<std::net::IpAddr> = addrs.iter().map(|a| a.ip()).collect();
    let addrs_str = addrs
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let truncated_name = truncate_utf8(display_name, 63);

    let txt_properties: [(&str, &str); 4] = [
        ("v", "1"),
        ("node_id", node_id_hex.as_str()),
        ("name", truncated_name),
        ("addrs", addrs_str.as_str()),
    ];

    mdns_sd::ServiceInfo::new(
        "_cawide._udp.local.",
        &instance_name,
        &hostname,
        ips.as_slice(),
        port,
        &txt_properties[..],
    )
}

pub struct LanAdvertiser {
    daemon: mdns_sd::ServiceDaemon,
    fullname: Arc<parking_lot::Mutex<Option<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl LanAdvertiser {
    pub fn start(endpoint: iroh::Endpoint, display_name: String) -> Option<Self> {
        if std::env::var("CAWIDE_LAN_DISCOVERY").as_deref() == Ok("0") {
            return None;
        }

        let daemon = match mdns_sd::ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("lan advertise disabled: {e}");
                return None;
            }
        };

        let fullname: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let daemon_clone = daemon.clone();
        let fullname_clone = Arc::clone(&fullname);

        let task = tokio::spawn(async move {
            use iroh::Watcher;
            let mut watcher = endpoint.watch_addr();
            let mut last_addrs: Vec<SocketAddr> = Vec::new();
            let mut initial = Some(watcher.get());

            loop {
                let addr = if let Some(first) = initial.take() {
                    first
                } else {
                    match watcher.updated().await {
                        Ok(val) => val,
                        Err(_) => break,
                    }
                };

                let direct_addrs = crate::net::ipc::filter_direct_addrs(addr.ip_addrs().copied());

                if direct_addrs.is_empty() {
                    if !last_addrs.is_empty() {
                        if let Some(fn_str) = fullname_clone.lock().take() {
                            if let Err(e) = daemon_clone.unregister(&fn_str) {
                                tracing::warn!("failed to unregister LAN advertisement: {e}");
                            }
                        }
                        last_addrs.clear();
                    }
                } else if direct_addrs != last_addrs {
                    match build_service_info(addr.id.as_bytes(), &direct_addrs, &display_name) {
                        Ok(info) => {
                            let fn_str = info.get_fullname().to_string();
                            match daemon_clone.register(info) {
                                Ok(_) => {
                                    *fullname_clone.lock() = Some(fn_str);
                                    last_addrs = direct_addrs;
                                }
                                Err(e) => {
                                    tracing::warn!("failed to register LAN advertisement: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "failed to build service info for LAN advertisement: {e}"
                            );
                        }
                    }
                }
            }
        });

        Some(Self {
            daemon,
            fullname,
            task,
        })
    }
}

impl Drop for LanAdvertiser {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(fn_str) = self.fullname.lock().take() {
            let _ = self.daemon.unregister(&fn_str);
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_name_format_and_length() {
        let node_id = [0xabu8; 32];
        let addr = "192.168.1.50:4242".parse::<SocketAddr>().unwrap();
        let info = build_service_info(&node_id, &[addr], "my-host").unwrap();
        let hex_id = hex::encode(node_id);
        let expected_instance = format!("cawide-{}", &hex_id[..16]);
        assert_eq!(expected_instance.len(), 23);
        assert!(expected_instance.len() <= 63);
        assert!(info.get_fullname().starts_with(&expected_instance));
    }

    #[test]
    fn test_txt_node_id_is_64_hex() {
        let node_id = [0x34u8; 32];
        let addr = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let info = build_service_info(&node_id, &[addr], "host").unwrap();
        let val = info.get_property_val_str("node_id").expect("node_id TXT");
        assert_eq!(val.len(), 64);
        assert_eq!(val, hex::encode(node_id));
        assert!(val
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_addrs_round_trip_and_length() {
        let node_id = [0x11u8; 32];
        let addrs = [
            "[2001:db8::1]:12345".parse::<SocketAddr>().unwrap(),
            "[2001:db8::2]:12346".parse::<SocketAddr>().unwrap(),
            "[2001:db8::3]:12347".parse::<SocketAddr>().unwrap(),
            "[2001:db8::4]:12348".parse::<SocketAddr>().unwrap(),
        ];
        let info = build_service_info(&node_id, &addrs, "host").unwrap();
        let addrs_val = info.get_property_val_str("addrs").expect("addrs TXT");
        assert!(addrs_val.len() <= 255);
        let parsed: Vec<SocketAddr> = addrs_val.split(',').map(|s| s.parse().unwrap()).collect();
        assert_eq!(parsed, addrs);
    }

    #[test]
    fn test_name_truncated_utf8() {
        let node_id = [0x22u8; 32];
        let addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
        let display_name = "é".repeat(40); // 80 bytes
        let info = build_service_info(&node_id, &[addr], &display_name).unwrap();
        let name_val = info.get_property_val_str("name").expect("name TXT");
        assert!(name_val.len() <= 63);
        assert_eq!(name_val, &"é".repeat(31)); // 62 bytes
        assert_eq!(name_val.len(), 62);
    }

    #[test]
    fn test_empty_addrs_returns_err() {
        let node_id = [0x55u8; 32];
        let res = build_service_info(&node_id, &[], "host");
        assert!(res.is_err());
    }
}
