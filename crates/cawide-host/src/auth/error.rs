use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cryptographic signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("QR code generation error: {0}")]
    Qr(#[from] qrcode::types::QrError),
    #[error("Invalid public key length or format: {0}")]
    InvalidPublicKey(String),
    #[error("Key already authorized: {0}")]
    KeyAlreadyAuthorized(String),
    #[error("Malformed authorized_keys entry: {0}")]
    CorruptStore(String),
    #[error("Invalid device name: {0}")]
    InvalidDeviceName(String),
    #[error("Pairing secret has expired or does not exist")]
    PairingExpired,
    #[error("Invalid pairing secret")]
    InvalidPairingSecret,
}
