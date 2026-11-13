//! Protocol error definitions

/// Structured domain error enum for protocol operations.
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("Frame length {size} exceeds maximum allowed {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("Invalid stream purpose byte: {0:#04x}")]
    InvalidStreamPurpose(u8),

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("Invalid pairing URI: {0}")]
    InvalidPairingUri(String),

    #[error("Decompression error: {0}")]
    Decompress(String),
}
