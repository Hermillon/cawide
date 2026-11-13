//! Network layer errors.

#[derive(thiserror::Error, Debug)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] cawide_protocol::ProtocolError),
    #[error("Auth error: {0}")]
    Auth(#[from] crate::auth::AuthError),
    #[error("PTY error: {0}")]
    Pty(#[from] crate::pty::PtyError),
    #[error("Failed to bind iroh endpoint: {0}")]
    Bind(String),
    #[error("Invalid host identity key file: {0}")]
    HostKey(String),
    #[error("Another cawide daemon is already running on {0}")]
    DaemonAlreadyRunning(String),
    #[error("No cawide daemon is running on {0}")]
    DaemonNotRunning(String),
    #[error("Unexpected IPC response: {0}")]
    UnexpectedIpcResponse(String),
    #[error("Timed out waiting for peer: {0}")]
    Timeout(&'static str),
    #[error("Invalid workspace directory {0}: {1}")]
    Workdir(String, std::io::Error),
    #[error("Cannot determine upload directory: HOME is not set")]
    UploadDirUnavailable,
    #[error("Workspace watcher error: {0}")]
    Watcher(String),
    #[error("Failed to setup shims: {0}")]
    Shims(String),
}
