//! Local daemon IPC over a Unix domain socket (u32-BE length-prefixed postcard frames).

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::auth::{AuthorizedKeysStore, PairingManager};
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::connections::ConnectionTracker;
use crate::net::error::NetError;
use crate::net::registry::SessionRegistry;
use crate::net::{HANDSHAKE_STEP_TIMEOUT, MAX_IPC_FRAME_SIZE};
use cawide_protocol::types::AgentStatus;
use cawide_protocol::{read_length_prefixed, write_length_prefixed};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum IpcRequest {
    Pair,
    Status,
    Stop,
    AgentEvent {
        session_id: Option<String>,
        workdir: Option<String>,
        agent: String,
        status: AgentStatus,
    },
    ListDevices,
    RevokeDevice {
        selector: String,
    },
    OpenUrl {
        url: String,
        session_id: Option<String>,
    },
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum IpcResponse {
    PairTicket {
        uri: String,
        qr_text: String,
        expires_in_secs: u64,
    },
    Status {
        node_id: String,
        active_sessions: usize,
        active_connections: bool,
        authorized_keys: usize,
        pairing_active: bool,
        last_input_unix: u64,
    },
    Ok,
    Error(String),
    Devices(Vec<DeviceInfo>),
    Revoked {
        node_id: String,
        device_name: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub node_id: String,
    pub device_name: String,
    pub added_at_ts: u64,
}
pub struct IpcContext {
    pub node_id: [u8; 32],
    pub endpoint: iroh::Endpoint,
    pub pairing_manager: Arc<PairingManager>,
    pub auth_store: Arc<AuthorizedKeysStore>,
    pub registry: Arc<SessionRegistry>,
    pub broadcaster: Arc<HostEventBroadcaster>,
    pub connections: Arc<ConnectionTracker>,
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
}

/// Computes the platform-default IPC socket / named pipe path for a given `config_dir`.
pub fn default_ipc_path(config_dir: &Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        use sha2::{Digest, Sha256};
        let s = config_dir
            .to_string_lossy()
            .to_ascii_lowercase()
            .replace('/', "\\");
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let hash = hex::encode(hasher.finalize());
        std::path::PathBuf::from(format!(r"\\.\pipe\cawide-{}", &hash[..16]))
    }
    #[cfg(not(windows))]
    {
        config_dir.join("cawide.sock")
    }
}

/// Returns the cawide configuration directory.
pub fn config_dir() -> std::io::Result<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("CAWIDE_CONFIG_DIR") {
        if !d.is_empty() {
            return Ok(std::path::PathBuf::from(d));
        }
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Ok(std::path::PathBuf::from(appdata).join("cawide"));
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME not found"))?;
    Ok(std::path::PathBuf::from(home)
        .join(".config")
        .join("cawide"))
}
#[cfg(unix)]
pub struct IpcListener {
    inner: UnixListener,
}

#[cfg(unix)]
pub struct IpcStream {
    inner: UnixStream,
}

#[cfg(windows)]
pub struct IpcListener {
    pipe_name: String,
    current_server: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
pub struct IpcStream {
    inner: tokio::net::windows::named_pipe::NamedPipeServer,
}

impl tokio::io::AsyncRead for IpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for IpcStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl IpcListener {
    pub async fn accept(&mut self) -> std::io::Result<IpcStream> {
        #[cfg(unix)]
        {
            let (stream, _) = self.inner.accept().await?;
            Ok(IpcStream { inner: stream })
        }
        #[cfg(windows)]
        {
            self.current_server.connect().await?;
            let next_server = create_named_pipe_server(&self.pipe_name, false)?;
            let connected_server = std::mem::replace(&mut self.current_server, next_server);
            Ok(IpcStream {
                inner: connected_server,
            })
        }
    }
}

#[cfg(windows)]
fn create_named_pipe_server(
    pipe_name: &str,
    first: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first);

    let sddl: Vec<u16> = "D:(A;;GA;;;OW)\0".encode_utf16().collect();
    let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW parses SDDL string.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut p_sd,
            std::ptr::null_mut(),
        )
    };

    if ok != 0 && !p_sd.is_null() {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: p_sd,
            bInheritHandle: 0,
        };
        // SAFETY: sa is a valid SECURITY_ATTRIBUTES pointing to p_sd.
        let res = unsafe {
            opts.create_with_security_attributes_raw(pipe_name, &mut sa as *mut _ as *mut _)
        };
        unsafe {
            LocalFree(p_sd as _);
        }
        res
    } else {
        opts.create(pipe_name)
    }
}

/// Binds the IPC listener, recovering from a stale socket file.
///
/// Must be called from within a tokio runtime.
pub fn bind_ipc_listener(socket_path: &Path) -> Result<IpcListener, NetError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(parent)?;
            }
        }

        if socket_path.exists() {
            match std::os::unix::net::UnixStream::connect(socket_path) {
                Ok(_) => {
                    return Err(NetError::DaemonAlreadyRunning(
                        socket_path.display().to_string(),
                    ))
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    std::fs::remove_file(socket_path)?;
                }
                Err(e) => return Err(NetError::Io(e)),
            }
        }

        let listener = UnixListener::bind(socket_path)?;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(IpcListener { inner: listener })
    }
    #[cfg(windows)]
    {
        let pipe_name = socket_path.to_string_lossy().to_string();

        // Check if another daemon is already running on this named pipe
        if let Ok(_client) = tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe_name)
        {
            return Err(NetError::DaemonAlreadyRunning(pipe_name));
        }

        let server = match create_named_pipe_server(&pipe_name, true) {
            Ok(s) => s,
            Err(e)
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(5)
                    || e.raw_os_error() == Some(231) =>
            {
                return Err(NetError::DaemonAlreadyRunning(pipe_name));
            }
            Err(e) => return Err(NetError::Io(e)),
        };

        Ok(IpcListener {
            pipe_name,
            current_server: server,
        })
    }
}

pub async fn serve_ipc(
    mut listener: IpcListener,
    ctx: Arc<IpcContext>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = async { let _ = stop.wait_for(|v| *v).await; } => break,
            accepted = listener.accept() => match accepted {
                Ok(stream) => {
                    let ctx = Arc::clone(&ctx);
                    tokio::spawn(async move {
                        if let Err(e) = handle_ipc_conn(stream, ctx).await {
                            tracing::debug!(error = %e, "ipc connection failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ipc accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

async fn handle_ipc_conn(mut stream: IpcStream, ctx: Arc<IpcContext>) -> Result<(), NetError> {
    let req: Option<IpcRequest> = tokio::time::timeout(
        HANDSHAKE_STEP_TIMEOUT,
        read_length_prefixed(&mut stream, MAX_IPC_FRAME_SIZE),
    )
    .await
    .map_err(|_| NetError::Timeout("ipc request"))??;
    let Some(req) = req else {
        return Ok(());
    };

    let (resp, stop) = match req {
        IpcRequest::Pair => (pair_response(&ctx), false),
        IpcRequest::Status => (
            IpcResponse::Status {
                node_id: hex::encode(ctx.node_id),
                active_sessions: ctx.registry.len(),
                active_connections: ctx.connections.has_connections(),
                authorized_keys: ctx.auth_store.list_keys().len(),
                pairing_active: ctx.pairing_manager.active_ticket().is_some(),
                last_input_unix: ctx.registry.last_input_unix(),
            },
            false,
        ),
        IpcRequest::Stop => (IpcResponse::Ok, true),
        IpcRequest::AgentEvent {
            session_id,
            workdir,
            agent,
            status,
        } => (
            crate::agent::ingest(
                &ctx.registry,
                &ctx.broadcaster,
                session_id.as_deref(),
                workdir.as_deref(),
                &agent,
                status,
            ),
            false,
        ),
        IpcRequest::ListDevices => (crate::devices::list(&ctx.auth_store), false),
        IpcRequest::RevokeDevice { selector } => (
            crate::devices::revoke(&ctx.auth_store, &ctx.connections, &selector),
            false,
        ),
        IpcRequest::OpenUrl { url, session_id } => (
            crate::web::open_url(&ctx.broadcaster, &ctx.connections, &url, session_id),
            false,
        ),
    };

    write_length_prefixed(&mut stream, &resp, MAX_IPC_FRAME_SIZE).await?;
    stream.shutdown().await?;
    if stop {
        // Signal only after the reply is flushed so the CLI always sees the acknowledgement.
        ctx.shutdown_tx.send_replace(true);
    }
    Ok(())
}

/// Filter out loopback, unspecified, and non-routable IPv6 addresses,
/// prioritize RFC 1918 private IPv4 addresses then reachable global IPv6, and take at most 4.
pub fn filter_direct_addrs(
    addrs: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    fn is_rfc1918(addr: &std::net::SocketAddr) -> bool {
        match addr.ip() {
            std::net::IpAddr::V4(v4) => v4.is_private(),
            std::net::IpAddr::V6(_) => false,
        }
    }

    fn is_reachable_ipv6(addr: &std::net::SocketAddr) -> bool {
        match addr.ip() {
            std::net::IpAddr::V4(_) => false,
            std::net::IpAddr::V6(v6) => {
                let seg = v6.segments();
                (seg[0] & 0xffc0) != 0xfe80 && (seg[0] & 0xfe00) != 0xfc00
            }
        }
    }

    fn address_priority(addr: &std::net::SocketAddr) -> u8 {
        if is_rfc1918(addr) {
            0
        } else if addr.is_ipv4() {
            1
        } else if is_reachable_ipv6(addr) {
            2
        } else {
            3
        }
    }

    let mut list: Vec<std::net::SocketAddr> = addrs
        .into_iter()
        .filter(|addr| {
            let ip = addr.ip();
            if ip.is_loopback() || ip.is_unspecified() {
                return false;
            }
            if let std::net::IpAddr::V6(v6) = ip {
                let seg = v6.segments();
                if (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
            }
            true
        })
        .collect();

    list.sort_by_key(|addr| (address_priority(addr), *addr));
    list.dedup();
    list.truncate(4);
    list
}

fn pair_response(ctx: &IpcContext) -> IpcResponse {
    let relay = ctx
        .endpoint
        .addr()
        .relay_urls()
        .next()
        .map(|u| u.to_string());
    let direct_addrs = filter_direct_addrs(ctx.endpoint.addr().ip_addrs().copied());
    let ticket = match ctx
        .pairing_manager
        .start_pairing(ctx.node_id, relay, direct_addrs)
    {
        Ok(t) => t,
        Err(e) => return IpcResponse::Error(e.to_string()),
    };
    match ticket.render_terminal_qr() {
        Ok(qr_text) => IpcResponse::PairTicket {
            uri: ticket.to_uri(),
            qr_text,
            expires_in_secs: ticket
                .expires_at
                .saturating_duration_since(Instant::now())
                .as_secs(),
        },
        Err(e) => IpcResponse::Error(e.to_string()),
    }
}

pub async fn send_ipc_request(
    socket_path: &Path,
    req: &IpcRequest,
) -> Result<IpcResponse, NetError> {
    #[cfg(unix)]
    let mut stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(NetError::DaemonNotRunning(
                socket_path.display().to_string(),
            ))
        }
        Err(e) => return Err(NetError::Io(e)),
    };

    #[cfg(windows)]
    let mut stream = {
        let pipe_name = socket_path.to_string_lossy().into_owned();
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe_name) {
            Ok(client) => client,
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::NotFound)
                    || e.raw_os_error() == Some(2) =>
            {
                return Err(NetError::DaemonNotRunning(pipe_name.to_string()));
            }
            Err(e) => return Err(NetError::Io(e)),
        }
    };
    write_length_prefixed(&mut stream, req, MAX_IPC_FRAME_SIZE).await?;
    let resp: Option<IpcResponse> = tokio::time::timeout(
        HANDSHAKE_STEP_TIMEOUT,
        read_length_prefixed(&mut stream, MAX_IPC_FRAME_SIZE),
    )
    .await
    .map_err(|_| NetError::Timeout("ipc response"))??;
    resp.ok_or_else(|| NetError::UnexpectedIpcResponse("daemon closed connection".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_filter_direct_addrs() {
        let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        let link_local_v6 =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 8080);
        let ula_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), 8080);
        let public_v6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let public_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 8080);
        let lan_192 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 8080);
        let lan_10 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let lan_172 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 8080);

        let input = vec![
            loopback_v4,
            public_v4,
            lan_192,
            loopback_v6,
            link_local_v6,
            ula_v6,
            public_v6,
            lan_10,
            lan_172,
        ];

        let filtered = filter_direct_addrs(input);
        assert_eq!(filtered.len(), 4);
        // Should prioritize RFC1918 first (3 of them), then public IPv4, and cap at 4
        assert!(!filtered.contains(&loopback_v4));
        assert!(!filtered.contains(&loopback_v6));
        assert!(!filtered.contains(&link_local_v6));
        assert!(!filtered.contains(&ula_v6));
        assert!(filtered.contains(&lan_10));
        assert!(filtered.contains(&lan_172));
        assert!(filtered.contains(&lan_192));
        assert!(filtered.contains(&public_v4));
        assert!(!filtered.contains(&public_v6)); // truncated by capacity 4
    }
}
