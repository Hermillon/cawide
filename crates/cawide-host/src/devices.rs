//! Device authorization and revocation CLI & IPC handlers (Brick 9).

use std::path::Path;

use cawide_protocol::CLOSE_UNAUTHORIZED;

use crate::auth::AuthorizedKeysStore;
use crate::net::connections::ConnectionTracker;
use crate::net::ipc::{DeviceInfo, IpcResponse};

pub fn list(store: &AuthorizedKeysStore) -> IpcResponse {
    let mut devices: Vec<DeviceInfo> = store
        .list_keys()
        .into_iter()
        .map(|entry| DeviceInfo {
            node_id: hex::encode(entry.public_key),
            device_name: entry.device_name,
            added_at_ts: entry.added_at_ts,
        })
        .collect();
    devices.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    IpcResponse::Devices(devices)
}

pub fn revoke(
    store: &AuthorizedKeysStore,
    conns: &ConnectionTracker,
    selector: &str,
) -> IpcResponse {
    let selector = selector.trim();
    if selector.is_empty() {
        return IpcResponse::Error("selector cannot be empty".into());
    }

    let all_keys = store.list_keys();

    // 1. Exact 64-char hex match
    if selector.len() == 64 && selector.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(selector) {
            if bytes.len() == 32 {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&bytes);
                if let Some(target) = all_keys.iter().find(|e| e.public_key == pk) {
                    return execute_revoke(store, conns, target);
                }
            }
        }
    }

    // 2. Device name match
    let name_matches: Vec<_> = all_keys
        .iter()
        .filter(|e| e.device_name == selector)
        .collect();
    if name_matches.len() == 1 {
        return execute_revoke(store, conns, name_matches[0]);
    } else if name_matches.len() > 1 {
        return IpcResponse::Error(format!(
            "ambiguous device name: selector '{}' matches {} devices",
            selector,
            name_matches.len()
        ));
    }

    // 3. Hex prefix match (prefix length >= 8)
    let is_hex = selector.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex && selector.len() >= 8 {
        let selector_lower = selector.to_ascii_lowercase();
        let matches: Vec<_> = all_keys
            .iter()
            .filter(|e| hex::encode(e.public_key).starts_with(&selector_lower))
            .collect();
        if matches.len() == 1 {
            return execute_revoke(store, conns, matches[0]);
        } else if matches.len() > 1 {
            return IpcResponse::Error(format!(
                "ambiguous prefix: selector '{}' matches {} devices",
                selector,
                matches.len()
            ));
        }
    }

    IpcResponse::Error(format!("device not found: '{selector}'"))
}

fn execute_revoke(
    store: &AuthorizedKeysStore,
    conns: &ConnectionTracker,
    entry: &crate::auth::store::AuthorizedEntry,
) -> IpcResponse {
    match store.remove_key(&entry.public_key) {
        Ok(true) => {
            conns.close_all(entry.public_key, CLOSE_UNAUTHORIZED, b"device revoked");
            IpcResponse::Revoked {
                node_id: hex::encode(entry.public_key),
                device_name: entry.device_name.clone(),
            }
        }
        Ok(false) => IpcResponse::Error("device not found in store".into()),
        Err(e) => IpcResponse::Error(format!("failed to remove key: {e}")),
    }
}

pub async fn cli_devices(config_dir: &Path) -> anyhow::Result<()> {
    let socket = config_dir.join("cawide.sock");
    let resp = match crate::net::send_ipc_request(&socket, &crate::net::IpcRequest::ListDevices)
        .await
    {
        Ok(r) => r,
        Err(crate::net::NetError::DaemonNotRunning(_)) => {
            let store = AuthorizedKeysStore::open_or_create(config_dir.join("authorized_keys"))?;
            list(&store)
        }
        Err(e) => anyhow::bail!("failed to query daemon: {e}"),
    };

    match resp {
        IpcResponse::Devices(devices) => {
            if devices.is_empty() {
                println!("No authorized devices.");
            } else {
                for d in devices {
                    println!("{}  {}", d.node_id, d.device_name);
                }
            }
            Ok(())
        }
        IpcResponse::Error(e) => anyhow::bail!(e),
        _ => anyhow::bail!("unexpected response"),
    }
}

pub async fn cli_revoke(config_dir: &Path, selector: &str) -> anyhow::Result<()> {
    let socket = config_dir.join("cawide.sock");
    let resp = match crate::net::send_ipc_request(
        &socket,
        &crate::net::IpcRequest::RevokeDevice {
            selector: selector.to_string(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(crate::net::NetError::DaemonNotRunning(_)) => {
            let store = AuthorizedKeysStore::open_or_create(config_dir.join("authorized_keys"))?;
            let conns = ConnectionTracker::new();
            revoke(&store, &conns, selector)
        }
        Err(e) => anyhow::bail!("failed to query daemon: {e}"),
    };

    match resp {
        IpcResponse::Revoked {
            node_id,
            device_name,
        } => {
            println!("revoked {device_name} ({node_id})");
            Ok(())
        }
        IpcResponse::Error(e) => anyhow::bail!(e),
        _ => anyhow::bail!("unexpected response"),
    }
}
