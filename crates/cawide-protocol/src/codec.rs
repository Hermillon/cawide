//! Length-prefixed framing and async message serialization codecs

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
pub use crate::types::MAX_TUNNEL_HEADER_SIZE;
use crate::types::{
    ControlMessage, PtyAttachAck, PtyAttachHeader, RpcFrame, RpcRequest, RpcResponse, TunnelAck,
    TunnelOpen,
};

/// Maximum allowed length for PTY attach header (2 KB).
pub const MAX_PTY_ATTACH_HEADER_SIZE: usize = 2048;

/// Maximum allowed length for Control stream messages (64 KB).
pub const MAX_CONTROL_FRAME_SIZE: usize = 65_536;

/// Maximum allowed length for RPC stream payloads (16 MB).
pub const MAX_RPC_FRAME_SIZE: usize = 16_777_216;

/// Maximum allowed length for PTY attach acknowledgement (8 MB).
pub const MAX_PTY_ATTACH_ACK_SIZE: usize = 8 * 1024 * 1024;
/// Maximum uncompressed size of each snapshot part (`history`, `screen`) in a `PtyAttachAck` (4 MiB).
pub const MAX_SNAPSHOT_PART_BYTES: usize = 4 * 1024 * 1024;

/// Capability bit advertised by client: client supports receiving zstd-compressed RPC responses.
pub const RPC_CAP_ZSTD: u8 = 0x01;

/// Flag bit set on RPC response length prefix indicating the response is compressed with zstd.
pub const RPC_FLAG_COMPRESSED: u32 = 0x8000_0000;
pub const PTY_ACK_FLAG_CHUNKED: u32 = 0x8000_0000; // bit 31 of the PtyAttachAck u32 length prefix
pub const PTY_CHUNK_FLAG_COMPRESSED: u32 = 0x8000_0000; // bit 31 of each chunk's u32 length prefix
pub const PTY_CHUNK_FLAG_INPUT_MODE: u32 = 0x4000_0000; // bit 30: 1-byte input-mode frame
pub const PTY_INPUT_MODE_ECHO: u8 = 0x01;
pub const PTY_INPUT_MODE_CANONICAL: u8 = 0x02;

/// Decoded frame from a chunked PTY stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyFrame {
    Output(Vec<u8>),
    InputMode(u8),
}
pub const MIN_PTY_COMPRESS_SIZE: usize = 1024;
pub const MAX_PTY_CHUNK_RAW: usize = 64 * 1024;

/// Minimum serialized uncompressed response size (in bytes) to consider zstd compression.
pub const MIN_RPC_COMPRESS_SIZE: usize = 1024;
/// Reads an exact number of bytes into a newly allocated buffer, with memory
/// amplification protection for payloads up to `max_len`.
async fn read_bounded_payload<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload_len: usize,
    max_len: usize,
) -> Result<Vec<u8>, ProtocolError> {
    if payload_len > max_len {
        return Err(ProtocolError::FrameTooLarge {
            size: payload_len,
            max: max_len,
        });
    }

    if payload_len == 0 {
        return Ok(Vec::new());
    }

    // For payloads <= 64KB, allocate exact buffer upfront.
    if payload_len <= 65_536 {
        let mut buf = vec![0u8; payload_len];
        reader.read_exact(&mut buf).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProtocolError::UnexpectedEof
            } else {
                ProtocolError::Io(e)
            }
        })?;
        Ok(buf)
    } else {
        // For larger payloads (> 64KB up to 16MB), grow buffer incrementally
        // to prevent immediate allocation amplification if stream stalls or closes.
        let mut buf = Vec::with_capacity(65_536);
        let read_bytes = reader
            .take(payload_len as u64)
            .read_to_end(&mut buf)
            .await
            .map_err(ProtocolError::Io)?;

        if read_bytes < payload_len {
            return Err(ProtocolError::UnexpectedEof);
        }

        Ok(buf)
    }
}

async fn write_u16_length_prefixed<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
    max_len: usize,
) -> Result<(), ProtocolError> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&[0u8; 2]);
    buf = postcard::to_extend(value, buf)?;
    let payload_len = buf.len() - 2;
    let effective_max = max_len.min(u16::MAX as usize);
    if payload_len > effective_max {
        return Err(ProtocolError::FrameTooLarge {
            size: payload_len,
            max: effective_max,
        });
    }
    let len_bytes = (payload_len as u16).to_be_bytes();
    buf[..2].copy_from_slice(&len_bytes);
    writer.write_all(&buf).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

async fn read_u16_length_prefixed<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
    max_len: usize,
) -> Result<Option<T>, ProtocolError> {
    let mut len_bytes = [0u8; 2];
    let n = match reader.read(&mut len_bytes).await {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) => return Err(ProtocolError::Io(e)),
    };
    if n < 2 {
        reader.read_exact(&mut len_bytes[n..]).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProtocolError::UnexpectedEof
            } else {
                ProtocolError::Io(e)
            }
        })?;
    }
    let payload_len = u16::from_be_bytes(len_bytes) as usize;
    let payload = read_bounded_payload(reader, payload_len, max_len).await?;
    let val: T = postcard::from_bytes(&payload)?;
    Ok(Some(val))
}

// ---------------------------------------------------------------------------
// PTY Attach Header (2-byte length prefix)
// ---------------------------------------------------------------------------

/// Serializes and writes a `PtyAttachHeader` onto an async stream with a 2-byte big-endian prefix.
pub async fn write_pty_attach_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &PtyAttachHeader,
) -> Result<(), ProtocolError> {
    write_u16_length_prefixed(writer, header, MAX_PTY_ATTACH_HEADER_SIZE).await
}

/// Reads a `PtyAttachHeader` from an async stream.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_pty_attach_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<PtyAttachHeader>, ProtocolError> {
    let mut len_bytes = [0u8; 2];
    let n = match reader.read(&mut len_bytes).await {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) => return Err(ProtocolError::Io(e)),
    };
    if n < 2 {
        reader.read_exact(&mut len_bytes[n..]).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProtocolError::UnexpectedEof
            } else {
                ProtocolError::Io(e)
            }
        })?;
    }
    let payload_len = u16::from_be_bytes(len_bytes) as usize;
    let payload = read_bounded_payload(reader, payload_len, MAX_PTY_ATTACH_HEADER_SIZE).await?;
    match postcard::from_bytes::<PtyAttachHeader>(&payload) {
        Ok(header) => Ok(Some(header)),
        Err(postcard::Error::DeserializeUnexpectedEnd) => {
            if let Ok(v5) =
                postcard::from_bytes::<crate::types::pty::LegacyPtyAttachHeaderV5>(&payload)
            {
                Ok(Some(PtyAttachHeader {
                    session_id: v5.session_id,
                    last_ack_offset: v5.last_ack_offset,
                    resume: v5.resume,
                    accept_compressed_snapshot: v5.accept_compressed_snapshot,
                    accept_chunked_output: v5.accept_chunked_output,
                    accept_input_mode_frames: false,
                }))
            } else if let Ok(v4) =
                postcard::from_bytes::<crate::types::pty::LegacyPtyAttachHeaderV4>(&payload)
            {
                Ok(Some(PtyAttachHeader {
                    session_id: v4.session_id,
                    last_ack_offset: v4.last_ack_offset,
                    resume: v4.resume,
                    accept_compressed_snapshot: v4.accept_compressed_snapshot,
                    accept_chunked_output: false,
                    accept_input_mode_frames: false,
                }))
            } else {
                let legacy =
                    postcard::from_bytes::<crate::types::pty::LegacyPtyAttachHeader>(&payload)?;
                Ok(Some(PtyAttachHeader {
                    session_id: legacy.session_id,
                    last_ack_offset: legacy.last_ack_offset,
                    resume: legacy.resume,
                    accept_compressed_snapshot: false,
                    accept_chunked_output: false,
                    accept_input_mode_frames: false,
                }))
            }
        }
        Err(e) => Err(ProtocolError::Serialization(e)),
    }
}

// ---------------------------------------------------------------------------
// Web Tunnel Headers (2-byte length prefix + postcard TunnelOpen / TunnelAck)
// ---------------------------------------------------------------------------

/// Serializes and writes a `TunnelOpen` header with a 2-byte big-endian prefix.
pub async fn write_tunnel_open<W: AsyncWrite + Unpin>(
    writer: &mut W,
    open: &TunnelOpen,
) -> Result<(), ProtocolError> {
    write_u16_length_prefixed(writer, open, MAX_TUNNEL_HEADER_SIZE).await
}

/// Reads a `TunnelOpen` header from an async stream.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_tunnel_open<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<TunnelOpen>, ProtocolError> {
    read_u16_length_prefixed(reader, MAX_TUNNEL_HEADER_SIZE).await
}

/// Serializes and writes a `TunnelAck` header with a 2-byte big-endian prefix.
pub async fn write_tunnel_ack<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ack: &TunnelAck,
) -> Result<(), ProtocolError> {
    write_u16_length_prefixed(writer, ack, MAX_TUNNEL_HEADER_SIZE).await
}

/// Reads a `TunnelAck` header from an async stream.
///
/// Returns `ProtocolError::UnexpectedEof` if the stream is closed before any bytes are read.
pub async fn read_tunnel_ack<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<TunnelAck, ProtocolError> {
    read_u16_length_prefixed(reader, MAX_TUNNEL_HEADER_SIZE)
        .await?
        .ok_or(ProtocolError::UnexpectedEof)
}

// ---------------------------------------------------------------------------
// PTY Attach Acknowledgement (4-byte length prefix + postcard PtyAttachAck)
// ---------------------------------------------------------------------------

/// Serializes and writes a `PtyAttachAck` onto an async stream with a 4-byte big-endian prefix.
/// If `chunked` is true, bit 31 of the length prefix is set to `PTY_ACK_FLAG_CHUNKED`.
pub async fn write_pty_attach_ack_chunked<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ack: &PtyAttachAck,
    chunked: bool,
) -> Result<(), ProtocolError> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&[0u8; 4]);
    buf = postcard::to_extend(ack, buf)?;
    let payload_len = buf.len() - 4;
    if payload_len > MAX_PTY_ATTACH_ACK_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: payload_len,
            max: MAX_PTY_ATTACH_ACK_SIZE,
        });
    }

    let mut prefix = payload_len as u32;
    if chunked {
        prefix |= PTY_ACK_FLAG_CHUNKED;
    }
    let len_bytes = prefix.to_be_bytes();
    buf[..4].copy_from_slice(&len_bytes);
    writer.write_all(&buf).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Reads a `PtyAttachAck` and chunked negotiation flag from an async stream.
///
/// Returns `ProtocolError::UnexpectedEof` if the stream is closed before any bytes are read.
pub async fn read_pty_attach_ack_chunked<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(PtyAttachAck, bool), ProtocolError> {
    let mut len_bytes = [0u8; 4];
    let n = match reader.read(&mut len_bytes).await {
        Ok(0) => return Err(ProtocolError::UnexpectedEof),
        Ok(n) => n,
        Err(e) => return Err(ProtocolError::Io(e)),
    };

    if n < 4 {
        reader.read_exact(&mut len_bytes[n..]).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProtocolError::UnexpectedEof
            } else {
                ProtocolError::Io(e)
            }
        })?;
    }

    let raw_prefix = u32::from_be_bytes(len_bytes);
    let chunked = (raw_prefix & PTY_ACK_FLAG_CHUNKED) != 0;
    let payload_len = (raw_prefix & !PTY_ACK_FLAG_CHUNKED) as usize;
    let payload = read_bounded_payload(reader, payload_len, MAX_PTY_ATTACH_ACK_SIZE).await?;
    let ack: PtyAttachAck = postcard::from_bytes(&payload)?;
    Ok((ack, chunked))
}

/// Serializes and writes a `PtyAttachAck` onto an async stream with a 4-byte big-endian prefix.
pub async fn write_pty_attach_ack<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ack: &PtyAttachAck,
) -> Result<(), ProtocolError> {
    write_pty_attach_ack_chunked(writer, ack, false).await
}

/// Reads a `PtyAttachAck` from an async stream.
///
/// Returns `ProtocolError::UnexpectedEof` if the stream is closed before any bytes are read.
pub async fn read_pty_attach_ack<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<PtyAttachAck, ProtocolError> {
    let (ack, _) = read_pty_attach_ack_chunked(reader).await?;
    Ok(ack)
}

// ---------------------------------------------------------------------------
// Generic Length-Prefixed Framing (4-byte big-endian length prefix)
// ---------------------------------------------------------------------------

/// Serializes `value` with postcard and writes it onto `writer` with a 4-byte
/// big-endian length prefix. Rejects payloads larger than `max_len`.
pub async fn write_length_prefixed<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
    max_len: usize,
) -> Result<(), ProtocolError> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&[0u8; 4]);
    buf = postcard::to_extend(value, buf)?;
    let payload_len = buf.len() - 4;
    if payload_len > max_len {
        return Err(ProtocolError::FrameTooLarge {
            size: payload_len,
            max: max_len,
        });
    }

    let len_bytes = (payload_len as u32).to_be_bytes();
    buf[..4].copy_from_slice(&len_bytes);
    writer.write_all(&buf).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Reads a 4-byte big-endian length-prefixed postcard value from `reader`.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read. Rejects frames
/// larger than `max_len`.
pub async fn read_length_prefixed<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
    max_len: usize,
) -> Result<Option<T>, ProtocolError> {
    let mut len_bytes = [0u8; 4];
    let n = match reader.read(&mut len_bytes).await {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) => return Err(ProtocolError::Io(e)),
    };

    if n < 4 {
        reader.read_exact(&mut len_bytes[n..]).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProtocolError::UnexpectedEof
            } else {
                ProtocolError::Io(e)
            }
        })?;
    }

    let payload_len = u32::from_be_bytes(len_bytes) as usize;
    let payload = read_bounded_payload(reader, payload_len, max_len).await?;
    let value: T = postcard::from_bytes(&payload)?;
    Ok(Some(value))
}

// ---------------------------------------------------------------------------
// Control Message (4-byte length prefix)
// ---------------------------------------------------------------------------

/// Serializes and writes a `ControlMessage` onto an async stream with a 4-byte big-endian prefix.
pub async fn write_control_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &ControlMessage,
) -> Result<(), ProtocolError> {
    write_length_prefixed(writer, msg, MAX_CONTROL_FRAME_SIZE).await
}

/// Reads a `ControlMessage` from an async stream.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_control_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<ControlMessage>, ProtocolError> {
    read_length_prefixed(reader, MAX_CONTROL_FRAME_SIZE).await
}

// ---------------------------------------------------------------------------
// RPC Request & Response (8-byte header: request_id: u32 BE + payload_length: u32 BE)
// ---------------------------------------------------------------------------

/// Encodes an `RpcResponse` into an RPC wire frame.
///
/// If `caps` includes `RPC_CAP_ZSTD` and the serialized response is at least
/// `MIN_RPC_COMPRESS_SIZE` (1024 bytes), compression with zstd is attempted.
/// If the compressed payload is strictly smaller than the uncompressed payload,
/// a compressed frame is produced with `RPC_FLAG_COMPRESSED` set on the length prefix.
/// Otherwise, an uncompressed frame is produced.
pub fn encode_rpc_response_frame(
    request_id: u32,
    resp: &RpcResponse,
    caps: u8,
) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(&[0u8; 4]);
    buf = postcard::to_extend(resp, buf)?;
    let uncompressed_len = buf.len() - 8;

    if (caps & RPC_CAP_ZSTD) != 0 && uncompressed_len >= MIN_RPC_COMPRESS_SIZE {
        let compressed = zstd::bulk::compress(&buf[8..], 3)
            .map_err(|e| ProtocolError::Decompress(e.to_string()))?;
        if compressed.len() + 4 < uncompressed_len {
            let wire_len = 4 + compressed.len();
            if wire_len > MAX_RPC_FRAME_SIZE {
                return Err(ProtocolError::FrameTooLarge {
                    size: wire_len,
                    max: MAX_RPC_FRAME_SIZE,
                });
            }
            let masked_len = (wire_len as u32) | RPC_FLAG_COMPRESSED;
            let mut out = Vec::with_capacity(8 + 4 + compressed.len());
            out.extend_from_slice(&request_id.to_be_bytes());
            out.extend_from_slice(&masked_len.to_be_bytes());
            out.extend_from_slice(&(uncompressed_len as u32).to_be_bytes());
            out.extend_from_slice(&compressed);
            return Ok(out);
        }
    }

    if uncompressed_len > MAX_RPC_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: uncompressed_len,
            max: MAX_RPC_FRAME_SIZE,
        });
    }

    let len_bytes = (uncompressed_len as u32).to_be_bytes();
    buf[4..8].copy_from_slice(&len_bytes);
    Ok(buf)
}

/// Serializes and writes an `RpcResponse` with capability-based compression onto an async stream.
pub async fn write_rpc_response_with_caps<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u32,
    resp: &RpcResponse,
    caps: u8,
) -> Result<(), ProtocolError> {
    let buf = encode_rpc_response_frame(request_id, resp, caps)?;
    writer.write_all(&buf).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Serializes and writes an uncompressed `RpcResponse` with its `request_id` onto an async stream.
pub async fn write_rpc_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u32,
    resp: &RpcResponse,
) -> Result<(), ProtocolError> {
    write_rpc_response_with_caps(writer, request_id, resp, 0).await
}

/// Serializes and writes an `RpcRequest` with optional capability advertising onto an async stream.
///
/// When `caps != 0`, a trailing capability byte is included within the frame length.
/// When `caps == 0`, no trailing byte is written, producing a byte-identical legacy frame.
pub async fn write_rpc_request_with_caps<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u32,
    req: &RpcRequest,
    caps: u8,
) -> Result<(), ProtocolError> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(&[0u8; 4]);
    buf = postcard::to_extend(req, buf)?;
    if caps != 0 {
        buf.push(caps);
    }
    let payload_len = buf.len() - 8;
    if payload_len > MAX_RPC_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: payload_len,
            max: MAX_RPC_FRAME_SIZE,
        });
    }
    let len_bytes = (payload_len as u32).to_be_bytes();
    buf[4..8].copy_from_slice(&len_bytes);
    writer.write_all(&buf).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Serializes and writes an `RpcRequest` with its `request_id` onto an async stream without capabilities.
pub async fn write_rpc_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u32,
    req: &RpcRequest,
) -> Result<(), ProtocolError> {
    write_rpc_request_with_caps(writer, request_id, req, 0).await
}

/// Reads an `RpcFrame<RpcRequest>` along with advertised capability flags from an async stream.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_rpc_request_with_caps<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(RpcFrame<RpcRequest>, u8)>, ProtocolError> {
    let mut header_bytes = [0u8; 8];
    let n = match reader.read(&mut header_bytes).await {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) => return Err(ProtocolError::Io(e)),
    };
    if n < 8 {
        reader
            .read_exact(&mut header_bytes[n..])
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ProtocolError::UnexpectedEof
                } else {
                    ProtocolError::Io(e)
                }
            })?;
    }
    let request_id = u32::from_be_bytes([
        header_bytes[0],
        header_bytes[1],
        header_bytes[2],
        header_bytes[3],
    ]);
    let payload_len = u32::from_be_bytes([
        header_bytes[4],
        header_bytes[5],
        header_bytes[6],
        header_bytes[7],
    ]) as usize;
    let payload = read_bounded_payload(reader, payload_len, MAX_RPC_FRAME_SIZE).await?;
    let (req, remainder): (RpcRequest, &[u8]) = postcard::take_from_bytes(&payload)?;
    let caps = match remainder.len() {
        0 => 0,
        1 => remainder[0],
        _ => {
            return Err(ProtocolError::Decompress(
                "unexpected trailing capability bytes".into(),
            ));
        }
    };
    Ok(Some((
        RpcFrame {
            request_id,
            payload: req,
        },
        caps,
    )))
}

/// Reads an `RpcFrame<RpcRequest>` from an async stream, ignoring any capability flags.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_rpc_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<RpcFrame<RpcRequest>>, ProtocolError> {
    match read_rpc_request_with_caps(reader).await? {
        Some((frame, _caps)) => Ok(Some(frame)),
        None => Ok(None),
    }
}

/// Reads an `RpcFrame<RpcResponse>` from an async stream, supporting optional zstd decompression.
///
/// If `RPC_FLAG_COMPRESSED` is set on the length prefix, masks off the flag, validates length bounds,
/// reads uncompressed length, decompresses via zstd, and deserializes the payload.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_rpc_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<RpcFrame<RpcResponse>>, ProtocolError> {
    let mut header_bytes = [0u8; 8];
    let n = match reader.read(&mut header_bytes).await {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) => return Err(ProtocolError::Io(e)),
    };
    if n < 8 {
        reader
            .read_exact(&mut header_bytes[n..])
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ProtocolError::UnexpectedEof
                } else {
                    ProtocolError::Io(e)
                }
            })?;
    }
    let request_id = u32::from_be_bytes([
        header_bytes[0],
        header_bytes[1],
        header_bytes[2],
        header_bytes[3],
    ]);
    let raw_len = u32::from_be_bytes([
        header_bytes[4],
        header_bytes[5],
        header_bytes[6],
        header_bytes[7],
    ]);

    if (raw_len & RPC_FLAG_COMPRESSED) != 0 {
        let masked_len = (raw_len & !RPC_FLAG_COMPRESSED) as usize;
        if masked_len > MAX_RPC_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge {
                size: masked_len,
                max: MAX_RPC_FRAME_SIZE,
            });
        }
        if masked_len < 4 {
            return Err(ProtocolError::Decompress(format!(
                "compressed frame length {masked_len} is less than 4"
            )));
        }
        let body = read_bounded_payload(reader, masked_len, MAX_RPC_FRAME_SIZE).await?;
        let uncompressed_len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
        if uncompressed_len > MAX_RPC_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge {
                size: uncompressed_len,
                max: MAX_RPC_FRAME_SIZE,
            });
        }
        let mut decompressor = zstd::bulk::Decompressor::new()
            .map_err(|e| ProtocolError::Decompress(e.to_string()))?;
        let decompressed = decompressor
            .decompress(&body[4..], uncompressed_len)
            .map_err(|e| ProtocolError::Decompress(e.to_string()))?;
        if decompressed.len() != uncompressed_len {
            return Err(ProtocolError::Decompress(format!(
                "decompressed length {} does not match declared {uncompressed_len}",
                decompressed.len()
            )));
        }
        let resp: RpcResponse = postcard::from_bytes(&decompressed)?;
        Ok(Some(RpcFrame {
            request_id,
            payload: resp,
        }))
    } else {
        let payload_len = raw_len as usize;
        let payload = read_bounded_payload(reader, payload_len, MAX_RPC_FRAME_SIZE).await?;
        let resp: RpcResponse = postcard::from_bytes(&payload)?;
        Ok(Some(RpcFrame {
            request_id,
            payload: resp,
        }))
    }
}

// ---------------------------------------------------------------------------
// PTY Chunk Encoder & Decoder (Streaming PTY output with chunked compression)
// ---------------------------------------------------------------------------

/// Reusable PTY chunk encoder with steady-state zero allocation.
pub struct PtyChunkEncoder {
    compressor: zstd::bulk::Compressor<'static>,
    scratch: Vec<u8>,
    out: Vec<u8>,
}

impl PtyChunkEncoder {
    pub fn new() -> Result<Self, ProtocolError> {
        let compressor =
            zstd::bulk::Compressor::new(1).map_err(|e| ProtocolError::Decompress(e.to_string()))?;
        Ok(Self {
            compressor,
            scratch: Vec::new(),
            out: Vec::new(),
        })
    }

    /// Requires raw.len() <= MAX_PTY_CHUNK_RAW; returns the whole frame (prefix included) from the reused `out`.
    pub fn encode(&mut self, raw: &[u8]) -> Result<&[u8], ProtocolError> {
        if raw.len() > MAX_PTY_CHUNK_RAW {
            return Err(ProtocolError::FrameTooLarge {
                size: raw.len(),
                max: MAX_PTY_CHUNK_RAW,
            });
        }

        if raw.len() >= MIN_PTY_COMPRESS_SIZE {
            self.scratch.clear();
            let bound = zstd::compress_bound(raw.len());
            if self.scratch.capacity() < bound {
                self.scratch.reserve(bound - self.scratch.capacity());
            }
            self.compressor
                .compress_to_buffer(raw, &mut self.scratch)
                .map_err(|e| ProtocolError::Decompress(e.to_string()))?;

            let zlen = self.scratch.len();
            if zlen + 4 < raw.len() {
                let masked = (4 + zlen as u32) | PTY_CHUNK_FLAG_COMPRESSED;
                let raw_len = raw.len() as u32;
                self.out.clear();
                self.out.reserve(8 + zlen);
                self.out.extend_from_slice(&masked.to_be_bytes());
                self.out.extend_from_slice(&raw_len.to_be_bytes());
                self.out.extend_from_slice(&self.scratch);
                return Ok(&self.out);
            }
        }

        // Raw uncompressed frame
        let len = raw.len() as u32;
        self.out.clear();
        self.out.reserve(4 + raw.len());
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(raw);
        Ok(&self.out)
    }

    pub fn encode_input_mode(&mut self, mode: u8) -> &[u8] {
        debug_assert_eq!(mode & !(PTY_INPUT_MODE_ECHO | PTY_INPUT_MODE_CANONICAL), 0);
        let prefix = 1u32 | PTY_CHUNK_FLAG_INPUT_MODE;
        self.out.clear();
        self.out.reserve(5);
        self.out.extend_from_slice(&prefix.to_be_bytes());
        self.out.push(mode);
        &self.out
    }
}

/// Reusable PTY chunk decoder.
pub struct PtyChunkDecoder {
    decompressor: zstd::bulk::Decompressor<'static>,
}

impl PtyChunkDecoder {
    pub fn new() -> Result<Self, ProtocolError> {
        let decompressor = zstd::bulk::Decompressor::new()
            .map_err(|e| ProtocolError::Decompress(e.to_string()))?;
        Ok(Self { decompressor })
    }

    /// Ok(None) = clean EOF before any prefix byte; EOF inside a frame = the existing ProtocolError::UnexpectedEof.
    pub async fn read_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<PtyFrame>, ProtocolError> {
        let mut prefix_bytes = [0u8; 4];
        let n = match reader.read(&mut prefix_bytes).await {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(e) => return Err(ProtocolError::Io(e)),
        };

        if n < 4 {
            reader
                .read_exact(&mut prefix_bytes[n..])
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        ProtocolError::UnexpectedEof
                    } else {
                        ProtocolError::Io(e)
                    }
                })?;
        }

        let raw_prefix = u32::from_be_bytes(prefix_bytes);
        if (raw_prefix & PTY_CHUNK_FLAG_INPUT_MODE) != 0 {
            if (raw_prefix & PTY_CHUNK_FLAG_COMPRESSED) != 0 {
                return Err(ProtocolError::Decompress(
                    "input-mode frame cannot be compressed".into(),
                ));
            }
            let size = (raw_prefix & !PTY_CHUNK_FLAG_INPUT_MODE) as usize;
            if size != 1 {
                return Err(ProtocolError::FrameTooLarge { size, max: 1 });
            }
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ProtocolError::UnexpectedEof
                } else {
                    ProtocolError::Io(e)
                }
            })?;
            let b = byte[0];
            if (b & !(PTY_INPUT_MODE_ECHO | PTY_INPUT_MODE_CANONICAL)) != 0 {
                return Err(ProtocolError::Decompress("unknown input-mode bits".into()));
            }
            Ok(Some(PtyFrame::InputMode(b)))
        } else if (raw_prefix & PTY_CHUNK_FLAG_COMPRESSED) != 0 {
            let masked = (raw_prefix & !PTY_CHUNK_FLAG_COMPRESSED) as usize;
            if masked < 4 {
                return Err(ProtocolError::Decompress(format!(
                    "compressed chunk wire length {masked} is smaller than 4-byte header"
                )));
            }
            if masked > MAX_PTY_CHUNK_RAW + 4 {
                return Err(ProtocolError::FrameTooLarge {
                    size: masked,
                    max: MAX_PTY_CHUNK_RAW + 4,
                });
            }

            let mut raw_len_bytes = [0u8; 4];
            reader.read_exact(&mut raw_len_bytes).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ProtocolError::UnexpectedEof
                } else {
                    ProtocolError::Io(e)
                }
            })?;
            let raw_len = u32::from_be_bytes(raw_len_bytes) as usize;
            if raw_len > MAX_PTY_CHUNK_RAW {
                return Err(ProtocolError::FrameTooLarge {
                    size: raw_len,
                    max: MAX_PTY_CHUNK_RAW,
                });
            }

            let compressed_len = masked - 4;
            let mut body = vec![0u8; compressed_len];
            reader.read_exact(&mut body).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ProtocolError::UnexpectedEof
                } else {
                    ProtocolError::Io(e)
                }
            })?;

            let decompressed = self
                .decompressor
                .decompress(&body, raw_len)
                .map_err(|e| ProtocolError::Decompress(e.to_string()))?;

            if decompressed.len() != raw_len {
                return Err(ProtocolError::Decompress(format!(
                    "decompressed size {} does not match declared raw_len {}",
                    decompressed.len(),
                    raw_len
                )));
            }

            Ok(Some(PtyFrame::Output(decompressed)))
        } else {
            let len = raw_prefix as usize;
            if len > MAX_PTY_CHUNK_RAW {
                return Err(ProtocolError::FrameTooLarge {
                    size: len,
                    max: MAX_PTY_CHUNK_RAW,
                });
            }

            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ProtocolError::UnexpectedEof
                } else {
                    ProtocolError::Io(e)
                }
            })?;
            Ok(Some(PtyFrame::Output(buf)))
        }
    }
}
