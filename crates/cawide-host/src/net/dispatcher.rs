//! ALPN protocol handlers: pairing enrollment and session stream multiplexing.

use std::collections::HashSet;
use std::sync::Arc;

use cawide_protocol::{
    encode_rpc_response_frame, read_control_message, read_pty_attach_header,
    read_rpc_request_with_caps, read_stream_purpose, write_control_message,
    write_pty_attach_ack_chunked, write_rpc_response_with_caps, ControlMessage, HostEvent,
    HostInfo, ProtocolError, PtyAttachAck, PtyChunkEncoder, RpcRequest, RpcResponse, StreamPurpose,
    STREAM_ERR_INVALID_SESSION, STREAM_ERR_PROTOCOL, STREAM_ERR_RESYNC, STREAM_ERR_SESSION_GONE,
    STREAM_ERR_SESSION_OCCUPIED, STREAM_ERR_SESSION_TAKEN, STREAM_ERR_SPAWN_FAILED,
    STREAM_ERR_UNKNOWN_PURPOSE,
};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};

use crate::auth::{validate_device_name, AuthError, AuthorizedKeysStore, PairingManager};
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::connections::ConnectionTracker;
use crate::net::error::NetError;
use crate::net::registry::{validate_session_id, ClaimResult, SessionRegistry};
use crate::net::{DEFAULT_COLS, DEFAULT_ROWS, HANDSHAKE_STEP_TIMEOUT};
use crate::pty::{AttachStart, PtySession};
use crate::rpc::{resolve_root, FsEngine, GitEngine};

/// Control replies queued while the writer is busy pushing host events.
const CONTROL_REPLY_QUEUE: usize = 64;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn reset_stream(send: &mut SendStream, recv: &mut RecvStream, code: u32) {
    let code = VarInt::from_u32(code);
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

async fn step<T>(
    what: &'static str,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, AcceptError> {
    tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, fut)
        .await
        .map_err(|_| AcceptError::from_err(NetError::Timeout(what)))
}

#[derive(Debug, Clone, Copy)]
pub struct LegacyAlpnHandler;

impl ProtocolHandler for LegacyAlpnHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        conn.close(
            VarInt::from_u32(cawide_protocol::CLOSE_UNSUPPORTED_ALPN),
            b"unsupported alpn",
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pairing (`cawide/pair/1`)
// ---------------------------------------------------------------------------

pub fn host_display_name() -> String {
    let candidate = whoami::devicename()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            whoami::hostname()
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "Computer".to_string());

    candidate.chars().take(64).collect()
}

#[derive(Debug, Clone)]
pub struct CawidePairingHandler {
    pub pairing_manager: Arc<PairingManager>,
    pub auth_store: Arc<AuthorizedKeysStore>,
    pub host_name: Arc<str>,
}

impl CawidePairingHandler {
    fn evaluate(&self, conn: &Connection, msg: Option<ControlMessage>) -> Result<(), String> {
        let Some(ControlMessage::PairRequest {
            pairing_secret,
            client_node_id,
            device_name,
        }) = msg
        else {
            return Err("expected PairRequest".into());
        };
        if client_node_id != *conn.remote_id().as_bytes() {
            return Err("client_node_id does not match TLS identity".into());
        }
        validate_device_name(&device_name).map_err(|e| e.to_string())?;
        self.pairing_manager
            .verify_and_consume(&pairing_secret)
            .map_err(|_| "invalid or expired pairing secret".to_string())?;
        match self.auth_store.add_key(client_node_id, device_name) {
            Ok(()) | Err(AuthError::KeyAlreadyAuthorized(_)) => {
                tracing::info!(remote = %conn.remote_id().fmt_short(), "device paired");
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

impl ProtocolHandler for CawidePairingHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = step("pairing", conn.accept_bi())
            .await?
            .map_err(AcceptError::from)?;

        let purpose = step("pairing", read_stream_purpose(&mut recv))
            .await?
            .map_err(|e| AcceptError::from_err(NetError::Protocol(e)))?;
        if purpose != Some(StreamPurpose::Control) {
            reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
            return Ok(());
        }

        let msg = step("pairing", read_control_message(&mut recv))
            .await?
            .map_err(|e| AcceptError::from_err(NetError::Protocol(e)))?;

        let response = match self.evaluate(&conn, msg) {
            Ok(()) => ControlMessage::PairResponse {
                success: true,
                error: None,
                host_name: Some(self.host_name.to_string()),
            },
            Err(reason) => {
                tracing::warn!(remote = %conn.remote_id().fmt_short(), %reason, "pairing refused");
                ControlMessage::PairResponse {
                    success: false,
                    error: Some(reason),
                    host_name: None,
                }
            }
        };
        step("pairing", write_control_message(&mut send, &response))
            .await?
            .map_err(|e| AcceptError::from_err(NetError::Protocol(e)))?;

        let _ = send.finish();
        // The client closes after reading the response; never close before it is delivered.
        let _ = tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, conn.closed()).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sessions (`cawide/2`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CawideProtocolHandler {
    pub registry: Arc<SessionRegistry>,
    pub fs_engine: Arc<FsEngine>,
    pub broadcaster: Arc<HostEventBroadcaster>,
    pub connections: Arc<ConnectionTracker>,
    pub forge_service: Arc<crate::forge::ForgeService>,
    pub git_host_env: Arc<crate::rpc::git::env::GitHostEnv>,
    pub push: Arc<crate::push::PushService>,
}

/// Per-connection state shared by that connection's stream tasks.
struct ConnState {
    attached: parking_lot::Mutex<HashSet<String>>,
    size: parking_lot::Mutex<Option<(u16, u16)>>,
}

fn resize_session_locked(size: Option<(u16, u16)>, session: &PtySession, id: &str) {
    if let Some((cols, rows)) = size {
        if let Err(e) = session.resize(cols, rows) {
            tracing::warn!(session = %id, error = %e, "resize failed");
        }
    }
}

impl ProtocolHandler for CawideProtocolHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let node_id = *conn.remote_id().as_bytes();
        let conn_id = self.connections.register(node_id, conn.clone());
        let state = Arc::new(ConnState {
            attached: parking_lot::Mutex::new(HashSet::new()),
            size: parking_lot::Mutex::new(None),
        });
        let mut tasks = tokio::task::JoinSet::new();
        while let Ok((send, recv)) = conn.accept_bi().await {
            tasks.spawn(handle_stream(
                self.clone(),
                node_id,
                Arc::clone(&state),
                send,
                recv,
            ));
        }
        // Connection gone: stop stream tasks; PTY sessions stay alive in the registry.
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.connections.unregister(node_id, conn_id);
        Ok(())
    }
}

async fn handle_stream(
    handler: CawideProtocolHandler,
    node_id: [u8; 32],
    state: Arc<ConnState>,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let purpose =
        match tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, read_stream_purpose(&mut recv)).await {
            Ok(Ok(Some(p))) => p,
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(ProtocolError::InvalidStreamPurpose(b))) => {
                tracing::warn!(purpose = b, "unknown stream purpose");
                reset_stream(&mut send, &mut recv, STREAM_ERR_UNKNOWN_PURPOSE);
                return;
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "failed reading stream purpose");
                return;
            }
        };

    match purpose {
        StreamPurpose::Pty => handle_pty_stream(node_id, handler.registry, state, send, recv).await,
        StreamPurpose::Control => {
            handle_control_stream(handler.registry, state, &handler.broadcaster, send, recv).await
        }
        StreamPurpose::Rpc => {
            handle_rpc_stream(
                node_id,
                &handler.registry,
                &handler.fs_engine,
                &handler.broadcaster,
                &handler.forge_service,
                &handler.git_host_env,
                &handler.push,
                &state,
                send,
                recv,
            )
            .await;
        }
        StreamPurpose::Tunnel => {
            let _ = send.set_priority(0);
            crate::net::tunnel::handle_tunnel_stream(send, recv).await
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("client fell behind the PTY ring buffer")]
struct FellBehind;

async fn write_pty_bytes(
    send: &mut iroh::endpoint::SendStream,
    encoder: Option<&mut cawide_protocol::PtyChunkEncoder>,
    data: &[u8],
) -> std::io::Result<()> {
    match encoder {
        None => send
            .write_all(data)
            .await
            .map_err(|e| std::io::Error::other(e.to_string())),
        Some(enc) => {
            for chunk in data.chunks(cawide_protocol::MAX_PTY_CHUNK_RAW) {
                let frame = enc
                    .encode(chunk)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                send.write_all(frame)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            Ok(())
        }
    }
}

async fn flush_ring(
    session: &Arc<PtySession>,
    send: &mut SendStream,
    encoder: Option<&mut cawide_protocol::PtyChunkEncoder>,
    next: &mut u64,
) -> Result<(), BoxError> {
    let slice = session.read_slice(*next);
    if slice.underrun {
        tracing::info!(
            from = *next,
            start = slice.start_offset,
            "client fell behind ring buffer; resetting stream for resync"
        );
        return Err(Box::new(FellBehind));
    }
    if !slice.data.is_empty() {
        write_pty_bytes(send, encoder, &slice.data).await?;
    }
    *next = slice.end_offset;
    Ok(())
}

/// Splits an attach start into the ack, the ring bytes written right after it, and the next live offset.
fn attach_ack(start: AttachStart, accept_compressed: bool) -> (PtyAttachAck, Vec<u8>, u64) {
    match start {
        AttachStart::Replay(slice) => (
            PtyAttachAck::Replay {
                offset: slice.start_offset,
            },
            slice.data,
            slice.end_offset,
        ),
        AttachStart::Snapshot {
            offset,
            history,
            screen,
        } => {
            let total_len = history.len() + screen.len();
            if accept_compressed && total_len > 1024 {
                use flate2::write::GzEncoder;
                use flate2::Compression;
                use std::io::Write;

                let uncompressed_history_len = history.len() as u32;
                let mut h_encoder = GzEncoder::new(Vec::new(), Compression::fast());
                let _ = h_encoder.write_all(&history);
                let history_gz = h_encoder.finish().unwrap_or(history);

                let uncompressed_screen_len = screen.len() as u32;
                let mut s_encoder = GzEncoder::new(Vec::new(), Compression::fast());
                let _ = s_encoder.write_all(&screen);
                let screen_gz = s_encoder.finish().unwrap_or(screen);

                (
                    PtyAttachAck::SnapshotGzip {
                        offset,
                        uncompressed_history_len,
                        history: history_gz,
                        uncompressed_screen_len,
                        screen: screen_gz,
                    },
                    Vec::new(),
                    offset,
                )
            } else {
                (
                    PtyAttachAck::Snapshot {
                        offset,
                        history,
                        screen,
                    },
                    Vec::new(),
                    offset,
                )
            }
        }
    }
}

async fn emit_input_mode_if_changed(
    session: &PtySession,
    send: &mut SendStream,
    encoder: Option<&mut PtyChunkEncoder>,
    last_mode: &mut Option<u8>,
) -> Result<(), BoxError> {
    if let Some(m) = session.input_mode() {
        if Some(m) != *last_mode {
            if let Some(enc) = encoder {
                send.write_all(enc.encode_input_mode(m)).await?;
                *last_mode = Some(m);
            }
        }
    }
    Ok(())
}

async fn handle_pty_stream(
    node_id: [u8; 32],
    registry: Arc<SessionRegistry>,
    state: Arc<ConnState>,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let _ = send.set_priority(5);
    let header =
        match tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, read_pty_attach_header(&mut recv)).await
        {
            Ok(Ok(Some(h))) => h,
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "bad PTY attach header");
                reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
                return;
            }
        };
    let chunked = header.accept_chunked_output;
    let want_modes = header.accept_input_mode_frames && chunked;
    let mut last_mode: Option<u8> = None;
    let mode_check = Arc::new(tokio::sync::Notify::new());
    let mut encoder = if chunked {
        match cawide_protocol::PtyChunkEncoder::new() {
            Ok(enc) => Some(enc),
            Err(e) => {
                tracing::debug!(error = %e, "encoder init failed");
                reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
                return;
            }
        }
    } else {
        None
    };
    if !validate_session_id(&header.session_id) {
        reset_stream(&mut send, &mut recv, STREAM_ERR_INVALID_SESSION);
        return;
    }
    let id = header.session_id;

    let session = if header.resume {
        match registry.get(&id) {
            Some(s) => s,
            None => {
                tracing::debug!(session = %id, "resume requested for unknown session");
                reset_stream(&mut send, &mut recv, STREAM_ERR_SESSION_GONE);
                return;
            }
        }
    } else {
        let (cols, rows) = state.size.lock().unwrap_or((DEFAULT_COLS, DEFAULT_ROWS));
        match registry.get_or_create(&id, cols, rows) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(session = %id, error = %e, "failed to spawn session");
                reset_stream(&mut send, &mut recv, STREAM_ERR_SPAWN_FAILED);
                return;
            }
        }
    };

    if header.resume && !session.is_alive() {
        let (ack, data, _) = attach_ack(
            session.attach_start(header.last_ack_offset),
            header.accept_compressed_snapshot,
        );
        if let Err(e) = write_pty_attach_ack_chunked(&mut send, &ack, chunked).await {
            tracing::debug!(session = %id, error = %e, "PTY resume ack failed");
            return;
        }
        if !data.is_empty() {
            if let Err(e) = write_pty_bytes(&mut send, encoder.as_mut(), &data).await {
                tracing::debug!(session = %id, error = %e, "PTY resume replay failed");
                return;
            }
        }
        let _ = send.finish();
        return;
    }

    let (token, mut kick_rx) = match registry.claim_attach(&id, node_id) {
        Ok(ClaimResult::Success { token, kick_rx }) => (token, kick_rx),
        Ok(ClaimResult::Occupied) => {
            tracing::warn!(session = %id, "session occupied by another client");
            reset_stream(&mut send, &mut recv, STREAM_ERR_SESSION_OCCUPIED);
            return;
        }
        Err(e) => {
            tracing::warn!(session = %id, error = %e, "claim attach failed");
            reset_stream(&mut send, &mut recv, STREAM_ERR_SPAWN_FAILED);
            return;
        }
    };

    struct ClaimGuard {
        registry: Arc<SessionRegistry>,
        session_id: String,
        token: u64,
    }
    impl Drop for ClaimGuard {
        fn drop(&mut self) {
            self.registry.release_claim(&self.session_id, self.token);
        }
    }
    let _guard = ClaimGuard {
        registry: Arc::clone(&registry),
        session_id: id.clone(),
        token,
    };

    // Subscribe BEFORE reading the ring so no output falls between replay and live.
    let mut out_rx = session.subscribe();
    let mut eof_rx = session.subscribe_eof();

    {
        let size_guard = state.size.lock();
        resize_session_locked(*size_guard, &session, &id);
    }
    let (ack, data, start_next) = attach_ack(
        session.attach_start(header.last_ack_offset),
        header.accept_compressed_snapshot,
    );
    let mut next = start_next;

    let attach = async {
        write_pty_attach_ack_chunked(&mut send, &ack, chunked)
            .await
            .map_err(|e| Box::new(e) as BoxError)?;
        if !data.is_empty() {
            write_pty_bytes(&mut send, encoder.as_mut(), &data).await?;
        }
        if want_modes {
            emit_input_mode_if_changed(&session, &mut send, encoder.as_mut(), &mut last_mode)
                .await?;
        }
        Ok::<(), BoxError>(())
    };
    if let Err(e) = attach.await {
        tracing::debug!(session = %id, error = %e, "PTY attach failed");
        return;
    }
    state.attached.lock().insert(id.clone());

    let output_pump = async {
        const PTY_COALESCE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(16);
        let timer: Option<tokio::time::Sleep> = None;
        tokio::pin!(timer);
        let mut dirty = false;

        loop {
            tokio::select! {
                _ = mode_check.notified(), if want_modes => {
                    emit_input_mode_if_changed(&session, &mut send, encoder.as_mut(), &mut last_mode).await?;
                }
                r = out_rx.recv() => match r {
                    Ok(_) | Err(RecvError::Lagged(_)) => {
                        if timer.is_none() {
                            flush_ring(&session, &mut send, encoder.as_mut(), &mut next).await?;
                            if want_modes {
                                emit_input_mode_if_changed(&session, &mut send, encoder.as_mut(), &mut last_mode).await?;
                            }
                            timer.set(Some(tokio::time::sleep(PTY_COALESCE_INTERVAL)));
                        } else {
                            dirty = true;
                        }
                    }
                    Err(RecvError::Closed) => {
                        flush_ring(&session, &mut send, encoder.as_mut(), &mut next).await?;
                        if want_modes {
                            emit_input_mode_if_changed(&session, &mut send, encoder.as_mut(), &mut last_mode).await?;
                        }
                        break;
                    }
                },
                _ = async {
                    match timer.as_mut().as_pin_mut() {
                        Some(t) => t.await,
                        None => std::future::pending().await,
                    }
                } => {
                    if dirty {
                        dirty = false;
                        flush_ring(&session, &mut send, encoder.as_mut(), &mut next).await?;
                        if want_modes {
                            emit_input_mode_if_changed(&session, &mut send, encoder.as_mut(), &mut last_mode).await?;
                        }
                        timer.set(Some(tokio::time::sleep(PTY_COALESCE_INTERVAL)));
                    } else {
                        timer.set(None);
                    }
                }
                _ = async { let _ = eof_rx.wait_for(|v| *v).await; } => {
                    flush_ring(&session, &mut send, encoder.as_mut(), &mut next).await?;
                    if want_modes {
                        emit_input_mode_if_changed(&session, &mut send, encoder.as_mut(), &mut last_mode).await?;
                    }
                    let _ = send.finish();
                    break;
                }
            }
        }
        Ok::<(), BoxError>(())
    };

    let mode_check_in = Arc::clone(&mode_check);
    let input_pump = async {
        let mut buf = [0u8; 4096];
        while let Some(n) = recv.read(&mut buf).await? {
            let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
            session.send_input_async(chunk).await?;
            mode_check_in.notify_one();
            registry.touch(&id);
            registry.mark_input();
        }
        Ok::<(), BoxError>(())
    };

    let result = tokio::select! {
        _ = &mut kick_rx => {
            tracing::info!(session = %id, "session taken over by reconnecting client");
            reset_stream(&mut send, &mut recv, STREAM_ERR_SESSION_TAKEN);
            Ok(())
        }
        r = output_pump => r,
        r = input_pump => r,
    };
    match result {
        Err(e) if e.is::<FellBehind>() => reset_stream(&mut send, &mut recv, STREAM_ERR_RESYNC),
        Err(e) => tracing::debug!(session = %id, error = %e, "PTY stream ended"),
        Ok(()) => {}
    }
    state.attached.lock().remove(&id);
}

/// Control streams carry client requests and host-pushed events. Reading and writing
/// run as separate futures so a pending event never cancels a half-read frame.
async fn handle_control_stream(
    registry: Arc<SessionRegistry>,
    state: Arc<ConnState>,
    broadcaster: &HostEventBroadcaster,
    send: SendStream,
    recv: RecvStream,
) {
    let _ = send.set_priority(10);
    let (replies_tx, replies_rx) = mpsc::channel(CONTROL_REPLY_QUEUE);
    let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
    // Subscribe before reading anything: a client that got a reply is subscribed.
    let writer = control_writer(send, replies_rx, broadcaster.subscribe(), abort_rx);
    let reader = control_reader(registry, state, recv, replies_tx);
    tokio::pin!(writer);
    tokio::select! {
        (mut recv, protocol_error) = reader => {
            if protocol_error {
                // Stop at once: queued replies are abandoned, not drained.
                let _ = abort_tx.send(());
            }
            // The reader dropped its sender, so the writer returns after draining
            // (clean EOF) or immediately (abort).
            let mut send = writer.await;
            if protocol_error {
                reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
            } else {
                let _ = send.finish();
            }
        }
        // Write failed: the stream is unusable, dropping the reader is fine.
        _ = &mut writer => {}
    }
}

/// Handles client control messages until EOF; returns the stream and whether it
/// ended with a protocol error.
async fn control_reader(
    registry: Arc<SessionRegistry>,
    state: Arc<ConnState>,
    mut recv: RecvStream,
    replies: mpsc::Sender<ControlMessage>,
) -> (RecvStream, bool) {
    loop {
        let msg = match read_control_message(&mut recv).await {
            Ok(Some(m)) => m,
            Ok(None) => return (recv, false),
            Err(e) => {
                tracing::debug!(error = %e, "control stream protocol error");
                return (recv, true);
            }
        };
        let reply = match msg {
            ControlMessage::Resize { cols, rows } => {
                *state.size.lock() = Some((cols, rows));
                let ids: Vec<String> = state.attached.lock().iter().cloned().collect();
                for id in ids {
                    if let Some(session) = registry.get(&id) {
                        resize_session_locked(Some((cols, rows)), &session, &id);
                    }
                }
                None
            }
            ControlMessage::Ping { client_ts } => Some(ControlMessage::Pong {
                client_ts,
                host_ts: unix_millis(),
            }),

            other => {
                tracing::warn!(message = ?other, "unexpected control message");
                None
            }
        };
        if let Some(reply) = reply {
            if replies.send(reply).await.is_err() {
                return (recv, false);
            }
        }
    }
}

/// Sole writer of a control stream: interleaves replies with host events. Returns
/// the stream once all replies are written (reader gone), a write fails, or `abort`
/// fires (protocol error: the caller resets, so a half-written frame is harmless).
async fn control_writer(
    mut send: SendStream,
    mut replies: mpsc::Receiver<ControlMessage>,
    mut events: broadcast::Receiver<HostEvent>,
    mut abort: tokio::sync::oneshot::Receiver<()>,
) -> SendStream {
    let mut events_open = true;
    loop {
        let msg = tokio::select! {
            biased;
            _ = &mut abort => return send,
            reply = replies.recv() => match reply {
                Some(m) => m,
                None => return send,
            },
            event = events.recv(), if events_open => match event {
                Ok(e) => ControlMessage::HostEvent(e),
                // Events are refresh hints, so missed ones coalesce into one refresh.
                // `GitChanged` is the only event today; a new variant needs its own
                // coalescing rule here.
                Err(RecvError::Lagged(_)) => ControlMessage::HostEvent(HostEvent::Resync),
                Err(RecvError::Closed) => {
                    events_open = false;
                    continue;
                }
            },
        };
        tokio::select! {
            biased;
            _ = &mut abort => return send,
            written = write_control_message(&mut send, &msg) => if let Err(e) = written {
                tracing::debug!(error = %e, "control write failed");
                return send;
            },
        }
    }
}

/// Serves RPC requests sequentially; clients open more RPC streams for parallelism.
#[allow(clippy::too_many_arguments)]
async fn handle_rpc_stream(
    client_node_id: [u8; 32],
    registry: &SessionRegistry,
    fs_engine: &FsEngine,
    broadcaster: &HostEventBroadcaster,
    forge: &crate::forge::ForgeService,
    git_host_env: &crate::rpc::git::env::GitHostEnv,
    push: &crate::push::PushService,
    state: &ConnState,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    use cawide_protocol::types::GitReply;
    use tokio::io::AsyncWriteExt;

    let _ = send.set_priority(1);
    loop {
        let (frame, caps) = match read_rpc_request_with_caps(&mut recv).await {
            Ok(Some(f)) => f,
            Ok(None) => {
                let _ = send.finish();
                return;
            }
            Err(e) => {
                tracing::debug!(error = %e, "rpc stream protocol error");
                reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
                return;
            }
        };
        let resp = dispatch_rpc(
            client_node_id,
            registry,
            fs_engine,
            broadcaster,
            forge,
            git_host_env,
            push,
            state,
            frame.payload,
        )
        .await;

        let request_id = frame.request_id;
        let is_bulk = matches!(
            &resp,
            RpcResponse::FsRead(Ok(_))
                | RpcResponse::FsReadChunk(Ok(_))
                | RpcResponse::FsList(Ok(_))
                | RpcResponse::Git {
                    result: Ok(GitReply::Diff { .. } | GitReply::Log { .. }),
                }
        );

        if is_bulk {
            let encoded = tokio::task::spawn_blocking(move || {
                encode_rpc_response_frame(request_id, &resp, caps)
            })
            .await;
            let frame_bytes = match encoded {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "rpc encode frame error");
                    reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "rpc encoding task panicked");
                    reset_stream(&mut send, &mut recv, STREAM_ERR_PROTOCOL);
                    return;
                }
            };
            if let Err(e) = send.write_all(&frame_bytes).await {
                tracing::debug!(error = %e, "rpc reply write failed");
                return;
            }
            if let Err(e) = send.flush().await {
                tracing::debug!(error = %e, "rpc reply flush failed");
                return;
            }
        } else if let Err(e) =
            write_rpc_response_with_caps(&mut send, request_id, &resp, caps).await
        {
            tracing::debug!(error = %e, "rpc reply failed");
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_rpc(
    client_node_id: [u8; 32],
    registry: &SessionRegistry,
    fs: &FsEngine,
    broadcaster: &HostEventBroadcaster,
    forge: &crate::forge::ForgeService,
    git_host_env: &crate::rpc::git::env::GitHostEnv,
    push: &crate::push::PushService,
    state: &ConnState,
    req: RpcRequest,
) -> RpcResponse {
    macro_rules! resolve_fs_root {
        ($root:expr, $variant:ident) => {
            match resolve_root($root) {
                Ok(p) => p,
                Err(e) => return RpcResponse::$variant(Err(e)),
            }
        };
    }

    match req {
        RpcRequest::FsList {
            root,
            path,
            recursive,
        } => {
            let root_path = resolve_fs_root!(&root, FsList);
            RpcResponse::FsList(fs.list(&root_path, &path, recursive).await)
        }
        RpcRequest::FsRead {
            root,
            path,
            offset,
            length,
        } => {
            let root_path = resolve_fs_root!(&root, FsRead);
            RpcResponse::FsRead(fs.read(&root_path, &path, offset, length).await)
        }
        RpcRequest::FsReadChunk {
            root,
            path,
            offset,
            length,
        } => {
            let root_path = resolve_fs_root!(&root, FsReadChunk);
            RpcResponse::FsReadChunk(fs.read_chunk(&root_path, &path, offset, length).await)
        }
        RpcRequest::FsSearch { root, query } => {
            let root_path = resolve_fs_root!(&root, FsSearch);
            RpcResponse::FsSearch(fs.search(&root_path, &query).await)
        }
        RpcRequest::FsUpload { filename, data } => {
            RpcResponse::FsUpload(fs.upload(&filename, data).await)
        }
        RpcRequest::RemoteOpen { root, target } => {
            let root_path = resolve_fs_root!(&root, RemoteOpen);
            RpcResponse::RemoteOpen(fs.remote_open(&root_path, &target).await)
        }
        RpcRequest::Git { root, op } => {
            let root_path = match resolve_root(&root) {
                Ok(p) => p,
                Err(e) => {
                    return RpcResponse::Git {
                        result: Err(cawide_protocol::types::GitError {
                            kind: cawide_protocol::types::GitErrorKind::InvalidArgument,
                            message: e,
                            host: None,
                            port: None,
                        }),
                    };
                }
            };
            let is_mutating = op.is_mutating();
            let git = GitEngine::new(root_path.clone(), Arc::new(git_host_env.clone()));
            let result = crate::rpc::git::dispatch::handle(&git, forge, git_host_env, op).await;
            if result.is_ok() && is_mutating {
                broadcaster.broadcast(HostEvent::GitChanged {
                    root: root_path.display().to_string(),
                });
            }
            RpcResponse::Git { result }
        }
        RpcRequest::ForgeAccounts { op } => {
            let result = crate::forge::dispatch::handle_accounts(forge, op).await;
            RpcResponse::ForgeAccounts { result }
        }
        RpcRequest::Forge { root, account, op } => {
            let root_path = match resolve_root(&root) {
                Ok(p) => p,
                Err(e) => {
                    return RpcResponse::Forge {
                        result: Err(cawide_protocol::types::ForgeError {
                            kind: cawide_protocol::types::ForgeErrorKind::InvalidArgument,
                            message: e,
                            git_kind: None,
                            host: None,
                            port: None,
                        }),
                    };
                }
            };
            let git = GitEngine::new(root_path, Arc::new(git_host_env.clone()));
            let result =
                crate::forge::dispatch::handle_repo(forge, &git, account.as_deref(), op).await;
            RpcResponse::Forge { result }
        }
        RpcRequest::SessionList => RpcResponse::SessionList(Ok(registry.list())),
        RpcRequest::SessionCreate {
            session_id,
            command,
            workdir,
        } => {
            let (cols, rows) = state.size.lock().unwrap_or((DEFAULT_COLS, DEFAULT_ROWS));
            RpcResponse::SessionCreate(
                crate::net::sessions::create(
                    registry,
                    &session_id,
                    command,
                    workdir.as_deref(),
                    cols,
                    rows,
                )
                .await,
            )
        }
        RpcRequest::SessionKill { session_id } => {
            RpcResponse::SessionKill(crate::net::sessions::kill(registry, &session_id).await)
        }
        RpcRequest::HostInfo => RpcResponse::HostInfo(Ok(HostInfo {
            host_name: host_display_name(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            workdir: registry.workdir().display().to_string(),
        })),
        RpcRequest::PortList => {
            let roots = registry.root_pids();
            let res = tokio::task::spawn_blocking(move || {
                crate::ports::scan(Some(std::process::id()), &roots)
            })
            .await
            .map_err(crate::rpc::join_err)
            .and_then(|r| r);
            RpcResponse::PortList(res)
        }
        RpcRequest::VoiceCompilePrompt {
            session_id,
            transcript,
            active_file,
            language_mode,
        } => {
            let result = crate::rpc::voice::handle_voice_compile(
                registry,
                &session_id,
                &transcript,
                active_file.as_deref(),
                &language_mode,
            )
            .await;
            RpcResponse::VoiceCompilePrompt(result)
        }
        RpcRequest::SetPushChannel { channel } => {
            RpcResponse::SetPushChannel(push.set_channel(client_node_id, channel).await)
        }
    }
}
