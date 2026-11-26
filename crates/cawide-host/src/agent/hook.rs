//! Agent hook execution (Brick 7).

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use cawide_protocol::{read_length_prefixed, write_length_prefixed};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use crate::agent::map::map_signal;
use crate::net::ipc::{connect_ipc, IpcClientStream, IpcRequest, IpcStreamIn, IpcStreamOut};
use crate::net::{send_ipc_request, MAX_IPC_FRAME_SIZE};
pub async fn run_hook(agent: &str, event: Option<&str>, payload_arg: Option<&str>) {
    let Some(session_id) = std::env::var("CAWIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    let Some(socket_path) = std::env::var("CAWIDE_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
    else {
        return;
    };

    let payload: serde_json::Value = if let Some(arg) = payload_arg {
        serde_json::from_str(arg).unwrap_or(serde_json::Value::Null)
    } else if !std::io::stdin().is_terminal() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().take(256 * 1024);
            let mut buf = Vec::new();
            let _ = stdin.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            Err(_) => serde_json::Value::Null,
        }
    } else {
        serde_json::Value::Null
    };

    let signal = match map_signal(agent, event, &payload) {
        Some(s) => s,
        None => return,
    };

    let req = IpcRequest::AgentEvent {
        session_id,
        agent: agent.to_string(),
        signal,
    };
    let _ =
        tokio::time::timeout(Duration::from_secs(1), send_ipc_request(&socket_path, &req)).await;
}

#[derive(serde::Deserialize)]
struct StreamLine {
    event: Option<String>,
    epoch: Option<u32>,
    seq: Option<u64>,
    #[serde(default)]
    payload: serde_json::Value,
}

fn payload_with_meta(line: StreamLine) -> (Option<String>, serde_json::Value) {
    let mut map = match line.payload {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    if let Some(epoch) = line.epoch {
        map.entry("epoch")
            .or_insert_with(|| serde_json::json!(epoch));
    }
    if let Some(seq) = line.seq {
        map.entry("seq").or_insert_with(|| serde_json::json!(seq));
    }
    (line.event, serde_json::Value::Object(map))
}

struct StreamConn {
    writer: tokio::io::WriteHalf<IpcClientStream>,
    out_rx: tokio::sync::mpsc::Receiver<IpcStreamOut>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Drop for StreamConn {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

async fn open_agent_stream(
    socket_path: &Path,
    session_id: &str,
    agent: &str,
) -> Option<StreamConn> {
    let mut stream = tokio::time::timeout(Duration::from_secs(1), connect_ipc(socket_path))
        .await
        .ok()?
        .ok()?;
    let req = IpcRequest::AgentStream {
        session_id: session_id.to_string(),
        agent: agent.to_string(),
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        write_length_prefixed(&mut stream, &req, MAX_IPC_FRAME_SIZE),
    )
    .await
    .ok()?
    .ok()?;
    let (mut reader, writer) = tokio::io::split(stream);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<IpcStreamOut>(16);
    let reader_task = tokio::spawn(async move {
        while let Ok(Some(msg)) =
            read_length_prefixed::<_, IpcStreamOut>(&mut reader, MAX_IPC_FRAME_SIZE).await
        {
            if out_tx.send(msg).await.is_err() {
                break;
            }
        }
    });
    Some(StreamConn {
        writer,
        out_rx,
        reader_task,
    })
}

async fn send_stream_signal(conn: &mut StreamConn, msg: &IpcStreamIn) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            write_length_prefixed(&mut conn.writer, msg, MAX_IPC_FRAME_SIZE),
        )
        .await,
        Ok(Ok(()))
    )
}

async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(s) = &mut sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn run_hook_stream(agent: &str) {
    let Some(session_id) = std::env::var("CAWIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    let Some(socket_path) = std::env::var("CAWIDE_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
    else {
        return;
    };

    let mut conn = open_agent_stream(&socket_path, &session_id, agent).await;
    let mut stdin_lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            line_res = stdin_lines.next_line() => {
                match line_res {
                    Ok(Some(line)) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let Ok(parsed) = serde_json::from_str::<StreamLine>(trimmed) else {
                            continue;
                        };
                        let is_shutdown = parsed.event.as_deref() == Some("session_shutdown");
                        let (ev, payload) = payload_with_meta(parsed);
                        if let Some(signal) = map_signal(agent, ev.as_deref(), &payload) {
                            let msg = IpcStreamIn::Signal(signal);
                            let mut sent = false;
                            if let Some(c) = conn.as_mut() {
                                sent = send_stream_signal(c, &msg).await;
                                if !sent {
                                    conn = None;
                                }
                            }
                            if !sent {
                                conn = open_agent_stream(&socket_path, &session_id, agent).await;
                                if let Some(c) = conn.as_mut() {
                                    if !send_stream_signal(c, &msg).await {
                                        conn = None;
                                    }
                                }
                            }
                        }
                        if is_shutdown {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            out_opt = async {
                match conn.as_mut() {
                    Some(c) => c.out_rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match out_opt {
                    Some(IpcStreamOut::ResolvePlanReview { review_id, choice }) => {
                        let line = serde_json::json!({
                            "type": "resolve_plan_review",
                            "reviewId": review_id,
                            "choice": choice,
                        });
                        if let Ok(s) = serde_json::to_string(&line) {
                            let _ = stdout.write_all(s.as_bytes()).await;
                            let _ = stdout.write_all(b"\n").await;
                            let _ = stdout.flush().await;
                        }
                    }
                    None => {
                        conn = None;
                    }
                }
            }
            _ = wait_shutdown_signal() => {
                break;
            }
        }
    }

    if let Some(mut c) = conn {
        let _ = tokio::time::timeout(Duration::from_millis(1200), async {
            let _ =
                write_length_prefixed(&mut c.writer, &IpcStreamIn::Close, MAX_IPC_FRAME_SIZE).await;
            let _ = c.writer.flush().await;
            let _ = c.writer.shutdown().await;
        })
        .await;
    }
}
