//! Local daemon IPC over a Unix domain socket (u32-BE length-prefixed postcard frames).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::auth::{AuthorizedKeysStore, PairingManager};
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::connections::ConnectionTracker;
use crate::net::error::NetError;
use crate::net::registry::SessionRegistry;
use crate::net::{HANDSHAKE_STEP_TIMEOUT, MAX_IPC_FRAME_SIZE};
use cawide_protocol::{read_length_prefixed, write_length_prefixed};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum IpcRequest {
    Pair,
    Status,
    Stop,
    AgentEvent {
        session_id: String,
        agent: String,
        signal: crate::agent::map::AgentSignal,
    },
    ListDevices,
    RevokeDevice {
        selector: String,
    },
    OpenUrl {
        url: String,
        session_id: Option<String>,
    },
    AccountStatus,
    AccountUnlink,
    ListDevicesWithSource,
    AgentStream {
        session_id: String,
        agent: String,
    },
    ClaudeEvent(ClaudeHookEvent),
    ClaudePermission {
        event: ClaudeHookEvent,
        attention: crate::agent::map::AttentionSpec,
    },
    PrepareAgentSession {
        agent: String,
        cwd: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum IpcStreamIn {
    Signal(crate::agent::map::AgentSignal),
    Close,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum IpcStreamOut {
    ResolvePlanReview { review_id: String, choice: String },
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
    AccountStatus {
        account_id: Option<String>,
        claims_disabled: bool,
    },
    Unlinked {
        was_linked: bool,
    },
    DevicesWithSource(Vec<DeviceInfoWithSource>),
    ClaudeRegistered {
        request_key: String,
        tool_use_id: Option<String>,
    },
    ClaudeReply(ClaudeReply),
    ClaudeDismissed,
    AgentPrepared {
        id: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeEventKind {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PermissionRequest,
    PermissionDenied,
    PostToolUse,
    PostToolUseFailure,
    Notification,
    SubagentStart,
    SubagentStop,
    PreCompact,
    PostCompact,
    Stop,
    StopFailure,
    SessionEnd,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClaudeHookEvent {
    pub session_id: String,
    pub claude_session_id: String,
    pub kind: ClaudeEventKind,
    pub agent_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub tool_name: Option<String>,
    pub input_hash: Option<u64>,
    pub text: Option<String>,
    pub source: Option<String>,
    pub notification_type: Option<String>,
    pub background_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClaudeReply {
    Allow,
    Deny {
        message: Option<String>,
    },
    Answer {
        option_index: Option<u32>,
        text: Option<String>,
    },
    ApprovePlan {
        accept_edits: bool,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClaudeHookFrame {
    AnsweredElsewhere,
    Interrupted,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub node_id: String,
    pub device_name: String,
    pub added_at_ts: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfoWithSource {
    pub node_id: String,
    pub device_name: String,
    pub added_at_ts: u64,
    pub source: String,
}
pub struct IpcContext {
    pub node_id: [u8; 32],
    pub endpoint: iroh::Endpoint,
    pub pairing_manager: Arc<PairingManager>,
    pub auth_store: Arc<AuthorizedKeysStore>,
    pub registry: Arc<SessionRegistry>,
    pub broadcaster: Arc<HostEventBroadcaster>,
    pub connections: Arc<ConnectionTracker>,
    pub trust: Option<Arc<crate::cloud::trust_sync::TrustSync>>,
    pub push: Arc<crate::push::PushService>,
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

/// Returns the user's home directory.
pub fn home_dir() -> std::io::Result<std::path::PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        if !h.is_empty() {
            return Ok(std::path::PathBuf::from(h));
        }
    }
    #[cfg(windows)]
    {
        if let Some(userprofile) = std::env::var_os("USERPROFILE") {
            if !userprofile.is_empty() {
                return Ok(std::path::PathBuf::from(userprofile));
            }
        }
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let combined = format!("{}{}", drive.to_string_lossy(), path.to_string_lossy());
            if !combined.is_empty() {
                return Ok(std::path::PathBuf::from(combined));
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "HOME is not set; set CAWIDE_CONFIG_DIR",
    ))
}

/// Returns the default cawide configuration directory (ignoring `CAWIDE_CONFIG_DIR`).
pub fn default_config_dir() -> std::io::Result<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let legacy = home_dir()?.join(r".config\cawide");
        if legacy.exists() {
            return Ok(legacy);
        }
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            if !local_app_data.is_empty() {
                return Ok(std::path::PathBuf::from(local_app_data).join("cawide"));
            }
        }
    }
    Ok(home_dir()?.join(".config").join("cawide"))
}

/// Returns the cawide configuration directory.
pub fn config_dir() -> std::io::Result<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("CAWIDE_CONFIG_DIR") {
        if !d.is_empty() {
            return Ok(std::path::PathBuf::from(d));
        }
    }
    default_config_dir()
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

#[cfg(unix)]
pub struct IpcClientStream {
    inner: UnixStream,
}

#[cfg(windows)]
pub struct IpcClientStream {
    inner: tokio::net::windows::named_pipe::NamedPipeClient,
}

impl tokio::io::AsyncRead for IpcClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for IpcClientStream {
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
            agent,
            signal,
        } => (
            crate::agent::ingest(&ctx.registry, &ctx.broadcaster, &session_id, &agent, signal),
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
        IpcRequest::AccountStatus => (
            IpcResponse::AccountStatus {
                account_id: ctx.auth_store.account_link().map(|l| l.account_id),
                claims_disabled: ctx.auth_store.claims_disabled(),
            },
            false,
        ),
        IpcRequest::AccountUnlink => {
            let resp = if let Some(trust) = &ctx.trust {
                match trust.unlink().await {
                    Ok(was_linked) => IpcResponse::Unlinked { was_linked },
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            } else {
                let was_managed = ctx.auth_store.is_managed();
                let store = Arc::clone(&ctx.auth_store);
                match tokio::task::spawn_blocking(move || store.mark_unlinked_local(true)).await {
                    Ok(Ok((was_linked, removed))) => {
                        if was_managed {
                            // Managed revocation: every transport stream must end, not just removed keys.
                            ctx.connections.close_all_connections(
                                cawide_protocol::CLOSE_UNAUTHORIZED,
                                b"account unlinked",
                            );
                            ctx.auth_store.revoke_lease();
                        }
                        for pk in removed {
                            ctx.connections.close_all(
                                pk,
                                cawide_protocol::CLOSE_UNAUTHORIZED,
                                b"account unlinked",
                            );
                        }
                        ctx.push.prune_channels().await;
                        IpcResponse::Unlinked { was_linked }
                    }
                    Ok(Err(e)) => {
                        if was_managed {
                            ctx.connections.close_all_connections(
                                cawide_protocol::CLOSE_UNAUTHORIZED,
                                b"account unlinked",
                            );
                            ctx.auth_store.revoke_lease();
                            ctx.push.prune_channels().await;
                        }
                        IpcResponse::Error(e.to_string())
                    }
                    Err(e) => IpcResponse::Error(format!("unlink task failed: {e}")),
                }
            };
            (resp, false)
        }
        IpcRequest::ListDevicesWithSource => {
            (crate::devices::list_with_source(&ctx.auth_store), false)
        }
        IpcRequest::AgentStream { session_id, agent } => {
            if !crate::agent::map::is_valid_slug(&agent) {
                tracing::debug!(session = %session_id, agent = %agent, "rejecting agent stream with invalid agent slug");
                return Ok(());
            }
            let (tx, mut rx) = tokio::sync::mpsc::channel::<IpcStreamOut>(16);
            let Some(stream_id) = ctx.registry.register_agent_stream(&session_id, tx) else {
                tracing::debug!(session = %session_id, "rejecting agent stream for unknown or dead session");
                return Ok(());
            };
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut shutdown_rx = ctx.shutdown_tx.subscribe();
            let mut writer_shutdown = shutdown_rx.clone();
            let mut writer_task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        out_opt = rx.recv() => {
                            match out_opt {
                                Some(out_msg) => {
                                    let res = tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, async {
                                        write_length_prefixed(&mut writer, &out_msg, MAX_IPC_FRAME_SIZE).await?;
                                        writer.flush().await.map_err(cawide_protocol::ProtocolError::Io)
                                    })
                                    .await;
                                    if !matches!(res, Ok(Ok(()))) {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        res = writer_shutdown.changed() => {
                            if res.is_err() || *writer_shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
            loop {
                tokio::select! {
                    in_res = read_length_prefixed::<_, IpcStreamIn>(&mut reader, MAX_IPC_FRAME_SIZE) => {
                        match in_res {
                            Ok(Some(IpcStreamIn::Signal(signal))) => {
                                let _ = crate::agent::ingest(
                                    &ctx.registry,
                                    &ctx.broadcaster,
                                    &session_id,
                                    &agent,
                                    signal,
                                );
                            }
                            Ok(Some(IpcStreamIn::Close)) | Ok(None) | Err(_) => break,
                        }
                    }
                    _ = &mut writer_task => break,
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
            writer_task.abort();
            ctx.registry.unregister_agent_stream(&session_id, stream_id);
            return Ok(());
        }
        IpcRequest::PrepareAgentSession { agent, cwd } => {
            let agent_static = match agent.as_str() {
                "codex" => "codex",
                "opencode" => "opencode",
                _ => {
                    let resp = IpcResponse::Error("unsupported agent".into());
                    write_length_prefixed(&mut stream, &resp, MAX_IPC_FRAME_SIZE).await?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            };
            let resp = match ctx.registry.observer_prepare(agent_static, cwd).await {
                Ok(id) => IpcResponse::AgentPrepared { id },
                Err(e) => IpcResponse::Error(e),
            };
            (resp, false)
        }
        IpcRequest::ClaudeEvent(ev) => {
            let resp = crate::agent::claude::ingest_event(&ctx.registry, &ctx.broadcaster, ev);
            (resp, false)
        }
        IpcRequest::ClaudePermission { event, attention } => {
            let session_id = event.session_id.clone();
            if session_id.is_empty() {
                write_length_prefixed(
                    &mut stream,
                    &IpcResponse::Error("unknown session".into()),
                    MAX_IPC_FRAME_SIZE,
                )
                .await?;
                stream.shutdown().await?;
                return Ok(());
            }

            let mut shutdown_rx = ctx.shutdown_tx.subscribe();
            if *shutdown_rx.borrow() {
                let _ = write_length_prefixed(
                    &mut stream,
                    &IpcResponse::ClaudeDismissed,
                    MAX_IPC_FRAME_SIZE,
                )
                .await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                return Ok(());
            }

            let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
            let reg_info = match ctx.registry.register_claude_permission(
                &session_id,
                event,
                attention,
                reply_tx,
            ) {
                Ok(info) => info,
                Err(err) => {
                    write_length_prefixed(
                        &mut stream,
                        &IpcResponse::Error(err),
                        MAX_IPC_FRAME_SIZE,
                    )
                    .await?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            };

            let reg_resp = IpcResponse::ClaudeRegistered {
                request_key: reg_info.request_key.clone(),
                tool_use_id: reg_info.tool_use_id,
            };
            if let Err(e) = write_length_prefixed(&mut stream, &reg_resp, MAX_IPC_FRAME_SIZE).await
            {
                ctx.registry
                    .resolve_claude_hook_frame(&session_id, &reg_info.request_key, None);
                return Err(NetError::Protocol(e));
            }
            if let Err(e) = stream.flush().await {
                ctx.registry
                    .resolve_claude_hook_frame(&session_id, &reg_info.request_key, None);
                return Err(NetError::Io(e));
            }

            let (mut reader, mut writer) = tokio::io::split(stream);
            let request_key = reg_info.request_key;
            let reply_opt = tokio::select! {
                frame_res = read_length_prefixed::<_, ClaudeHookFrame>(&mut reader, MAX_IPC_FRAME_SIZE) => {
                    match frame_res {
                        Ok(Some(frame)) => {
                            ctx.registry.resolve_claude_hook_frame(&session_id, &request_key, Some(frame));
                            None
                        }
                        Ok(None) | Err(_) => {
                            ctx.registry.resolve_claude_hook_frame(&session_id, &request_key, None);
                            None
                        }
                    }
                }
                reply_res = &mut reply_rx => {
                    reply_res.ok()
                }
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        ctx.registry.resolve_claude_hook_frame(&session_id, &request_key, None);
                    }
                    None
                }
            };

            let final_resp = match reply_opt {
                Some(reply) => IpcResponse::ClaudeReply(reply),
                None => IpcResponse::ClaudeDismissed,
            };

            let _ = tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, async {
                write_length_prefixed(&mut writer, &final_resp, MAX_IPC_FRAME_SIZE).await?;
                writer
                    .flush()
                    .await
                    .map_err(cawide_protocol::ProtocolError::Io)
            })
            .await;

            return Ok(());
        }
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

pub async fn connect_ipc(socket_path: &Path) -> Result<IpcClientStream, NetError> {
    #[cfg(unix)]
    let inner = match UnixStream::connect(socket_path).await {
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
    let inner = {
        let pipe_name = socket_path.to_string_lossy().into_owned();
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe_name) {
            Ok(client) => client,
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::NotFound)
                    || e.raw_os_error() == Some(2) =>
            {
                return Err(NetError::DaemonNotRunning(pipe_name));
            }
            Err(e) => return Err(NetError::Io(e)),
        }
    };

    Ok(IpcClientStream { inner })
}

pub async fn send_ipc_request(
    socket_path: &Path,
    req: &IpcRequest,
) -> Result<IpcResponse, NetError> {
    send_ipc_request_with_timeout(socket_path, req, HANDSHAKE_STEP_TIMEOUT).await
}

pub async fn send_ipc_request_with_timeout(
    socket_path: &Path,
    req: &IpcRequest,
    timeout: std::time::Duration,
) -> Result<IpcResponse, NetError> {
    let mut stream = connect_ipc(socket_path).await?;
    write_length_prefixed(&mut stream, req, MAX_IPC_FRAME_SIZE).await?;
    let resp: Option<IpcResponse> = tokio::time::timeout(
        timeout,
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

    #[cfg(windows)]
    #[test]
    fn test_windows_default_config_dir_uses_localappdata() {
        let prev = std::env::var_os("LOCALAPPDATA");
        std::env::set_var("LOCALAPPDATA", r"C:\Users\Test\AppData\Local");
        let dir = default_config_dir().expect("default_config_dir");
        assert!(dir.ends_with("cawide"));
        assert!(dir.starts_with(r"C:\Users\Test\AppData\Local"));
        match prev {
            Some(v) => std::env::set_var("LOCALAPPDATA", v),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
    }
}
