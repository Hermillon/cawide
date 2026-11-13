//! PTY and ring buffer domain errors.

#[derive(thiserror::Error, Debug)]
pub enum PtyError {
    #[error("Failed to open PTY system: {0}")]
    OpenPty(String),

    #[error("Failed to spawn process in PTY: {0}")]
    SpawnProcess(String),

    #[error("Failed to resize PTY: {0}")]
    Resize(String),

    #[error("Failed to control child process: {0}")]
    Process(String),

    #[error("I/O error on PTY: {0}")]
    Io(#[from] std::io::Error),

    #[error("PTY session terminated")]
    Terminated,

    #[error("Invalid terminal dimensions: cols={0}, rows={1}")]
    InvalidDimensions(u16, u16),

    #[error("Maximum sessions limit reached ({0})")]
    MaxSessions(usize),
}
