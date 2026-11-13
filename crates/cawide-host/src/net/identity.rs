//! Persistent host identity key.

use std::io::Write;
use std::path::Path;

use crate::net::error::NetError;

fn read_key(path: &Path) -> Result<iroh::SecretKey, NetError> {
    let raw = std::fs::read_to_string(path)?;
    let bytes =
        hex::decode(raw.trim()).map_err(|e| NetError::HostKey(format!("invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NetError::HostKey("expected 32-byte hex key".into()))?;
    Ok(iroh::SecretKey::from_bytes(&arr))
}

/// Loads the host identity from `path`, creating it (mode 0600) when missing.
///
/// The file holds 64 lowercase hex chars followed by a newline.
pub fn load_or_create_host_key(path: &Path) -> Result<iroh::SecretKey, NetError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(parent)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(parent)?;
        }
    }

    if path.exists() {
        return read_key(path);
    }

    let key = iroh::SecretKey::generate();

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    match opts.open(path) {
        Ok(mut file) => {
            writeln!(file, "{}", hex::encode(key.to_bytes()))?;
            file.sync_all()?;
            Ok(key)
        }
        // Concurrent first start: another process won the race, use its key.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_key(path),
        Err(e) => Err(NetError::Io(e)),
    }
}
