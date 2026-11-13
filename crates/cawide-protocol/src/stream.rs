//! Stream purpose discriminators and async I/O

use crate::error::ProtocolError;

/// Stream purpose constant for the PTY stream (0x04): framed attach ack, then raw bytes.
pub const STREAM_PURPOSE_PTY: u8 = 0x04;

/// Stream purpose constant for framed Control messages (0x02).
pub const STREAM_PURPOSE_CONTROL: u8 = 0x02;

/// Stream purpose constant for framed RPC requests/responses (0x03).
pub const STREAM_PURPOSE_RPC: u8 = 0x03;
/// Stream purpose constant for framed Web Tunnel streams (0x05).
pub const STREAM_PURPOSE_TUNNEL: u8 = 0x05;

/// RFC 9000 QUIC bidirectional stream purpose header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamPurpose {
    Pty = STREAM_PURPOSE_PTY,
    Control = STREAM_PURPOSE_CONTROL,
    Rpc = STREAM_PURPOSE_RPC,
    Tunnel = STREAM_PURPOSE_TUNNEL,
}

impl TryFrom<u8> for StreamPurpose {
    type Error = ProtocolError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            STREAM_PURPOSE_PTY => Ok(Self::Pty),
            STREAM_PURPOSE_CONTROL => Ok(Self::Control),
            STREAM_PURPOSE_RPC => Ok(Self::Rpc),
            STREAM_PURPOSE_TUNNEL => Ok(Self::Tunnel),
            other => Err(ProtocolError::InvalidStreamPurpose(other)),
        }
    }
}

/// Writes the 1-byte stream purpose discriminator onto an async stream and flushes it immediately.
pub async fn write_stream_purpose<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    purpose: StreamPurpose,
) -> Result<(), ProtocolError> {
    use tokio::io::AsyncWriteExt;
    writer
        .write_u8(purpose as u8)
        .await
        .map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Reads the 1-byte stream purpose discriminator from an async stream.
///
/// Returns `Ok(None)` if the peer cleanly closed the stream without sending any bytes.
pub async fn read_stream_purpose<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<StreamPurpose>, ProtocolError> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1];
    match reader.read(&mut buf).await {
        Ok(0) => Ok(None),
        Ok(1) => StreamPurpose::try_from(buf[0]).map(Some),
        Ok(_) => unreachable!(),
        Err(e) => Err(ProtocolError::Io(e)),
    }
}
