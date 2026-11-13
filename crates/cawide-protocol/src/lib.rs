//! Cawide Wire Protocol & Stream Framing Crate
//!
//! Provides RFC 9000 QUIC stream purpose headers, zero-copy `postcard` binary
//! serialization types, and length-delimited async framing codecs.

pub mod codec;
pub mod codes;
pub mod error;
pub mod pairing;
pub mod stream;
pub mod types;

pub use codec::{
    encode_rpc_response_frame, read_control_message, read_length_prefixed, read_pty_attach_ack,
    read_pty_attach_ack_chunked, read_pty_attach_header, read_rpc_request,
    read_rpc_request_with_caps, read_rpc_response, read_tunnel_ack, read_tunnel_open,
    write_control_message, write_length_prefixed, write_pty_attach_ack,
    write_pty_attach_ack_chunked, write_pty_attach_header, write_rpc_request,
    write_rpc_request_with_caps, write_rpc_response, write_rpc_response_with_caps,
    write_tunnel_ack, write_tunnel_open, PtyChunkDecoder, PtyChunkEncoder, PtyFrame,
    MAX_CONTROL_FRAME_SIZE, MAX_PTY_ATTACH_ACK_SIZE, MAX_PTY_ATTACH_HEADER_SIZE, MAX_PTY_CHUNK_RAW,
    MAX_RPC_FRAME_SIZE, MAX_SNAPSHOT_PART_BYTES, MAX_TUNNEL_HEADER_SIZE, MIN_PTY_COMPRESS_SIZE,
    MIN_RPC_COMPRESS_SIZE, PTY_ACK_FLAG_CHUNKED, PTY_CHUNK_FLAG_COMPRESSED,
    PTY_CHUNK_FLAG_INPUT_MODE, PTY_INPUT_MODE_CANONICAL, PTY_INPUT_MODE_ECHO, RPC_CAP_ZSTD,
    RPC_FLAG_COMPRESSED,
};
pub use codes::*;
pub use error::ProtocolError;
pub use pairing::*;
pub use stream::{
    read_stream_purpose, write_stream_purpose, StreamPurpose, STREAM_PURPOSE_CONTROL,
    STREAM_PURPOSE_PTY, STREAM_PURPOSE_RPC, STREAM_PURPOSE_TUNNEL,
};
pub use types::*;
