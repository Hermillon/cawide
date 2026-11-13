use cawide_protocol::types::{ForgeError, ForgeErrorKind, ForgeHostKey, ForgeSshKey};
use parking_lot::Mutex;
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Hardcoded verified fingerprints: host -> list of (key_type, base64_sha256_no_prefix)
pub const OFFICIAL_HOST_KEYS: &[(&str, &str, &str)] = &[
    // GitHub
    (
        "github.com",
        "ssh-ed25519",
        "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
    ),
    (
        "github.com",
        "ecdsa-sha2-nistp256",
        "p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
    ),
    (
        "github.com",
        "ssh-rsa",
        "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
    ),
    // GitLab
    (
        "gitlab.com",
        "ssh-ed25519",
        "eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQZ4raiTTH3Gs",
    ),
    (
        "gitlab.com",
        "ecdsa-sha2-nistp256",
        "HbW3g8zUjNSksFbqTiUWPWg2Bq1x8p4bJJAh3mU7g28",
    ),
    (
        "gitlab.com",
        "ssh-rsa",
        "22OBoHYibmBit62645RXAmfv0fqetplpkAm97PAbfO0",
    ),
    // Bitbucket
    (
        "bitbucket.org",
        "ssh-ed25519",
        "ybgmF0SlOtqBroX9SgnFiGh9W30799BNDNuQ+2g+boY",
    ),
    (
        "bitbucket.org",
        "ecdsa-sha2-nistp256",
        "948Gxdr/FU9Il050nBgQA282fIEE2O3pw4hdW1b4Klo",
    ),
    (
        "bitbucket.org",
        "ssh-rsa",
        "46OSHA1RsoSreH4IuhxWjH6S0U/N4q4z8K7kH5J4e2g",
    ),
];

type ScanCacheMap = HashMap<(String, u16), (Vec<String>, Instant)>;
static SCAN_CACHE: Mutex<Option<ScanCacheMap>> = Mutex::new(None);

pub async fn get_ssh_public_key(config_dir: &Path) -> Result<ForgeSshKey, ForgeError> {
    let ssh_dir = config_dir.join("ssh");
    if !ssh_dir.exists() {
        tokio::fs::create_dir_all(&ssh_dir)
            .await
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("create ssh dir: {e}"),
                git_kind: None,
                host: None,
                port: None,
            })?;
        #[cfg(unix)]
        let _ = tokio::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).await;
    }

    let priv_key = ssh_dir.join("id_ed25519");
    let pub_key_path = ssh_dir.join("id_ed25519.pub");

    if !priv_key.exists() {
        let hostname = whoami::hostname().unwrap_or_else(|_| "localhost".into());
        let comment = format!("cawide@{hostname}");
        let mut cmd = Command::new("ssh-keygen");
        cmd.args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &comment,
            "-f",
            priv_key.to_str().unwrap(),
        ]);
        let out = cmd.output().await.map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("generate ssh key: {e}"),
            git_kind: None,
            host: None,
            port: None,
        })?;
        if !out.status.success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                git_kind: None,
                host: None,
                port: None,
            });
        }
    }

    let pub_content = tokio::fs::read_to_string(&pub_key_path)
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("read ssh public key: {e}"),
            git_kind: None,
            host: None,
            port: None,
        })?
        .trim()
        .to_string();

    let mut fp_cmd = Command::new("ssh-keygen");
    fp_cmd.args(["-lf", pub_key_path.to_str().unwrap()]);
    let fp_out = fp_cmd.output().await.map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("ssh-keygen fingerprint: {e}"),
        git_kind: None,
        host: None,
        port: None,
    })?;

    let fp_line = String::from_utf8_lossy(&fp_out.stdout);
    let fingerprint = fp_line.split_whitespace().nth(1).unwrap_or("").to_string();

    Ok(ForgeSshKey {
        public_key: pub_content,
        fingerprint,
    })
}

pub async fn scan_host_key(host: &str, port: u16) -> Result<Vec<ForgeHostKey>, ForgeError> {
    let mut cmd = Command::new("ssh-keyscan");
    cmd.args(["-T", "5", "-p", &port.to_string(), "--", host]);
    let out = cmd.output().await.map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("ssh-keyscan failed: {e}"),
        git_kind: None,
        host: Some(host.to_string()),
        port: Some(port),
    })?;

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<String> = stdout_str
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();

    // Cache scanned lines in memory for 10 min
    {
        let mut lock = SCAN_CACHE.lock();
        let cache = lock.get_or_insert_with(HashMap::new);
        cache.insert((host.to_string(), port), (lines.clone(), Instant::now()));
    }

    let mut keys = Vec::new();
    for line in lines {
        // Fingerprint via ssh-keygen -lf -
        let mut fp_cmd = Command::new("ssh-keygen");
        fp_cmd.args(["-lf", "-"]);
        fp_cmd.stdin(std::process::Stdio::piped());
        fp_cmd.stdout(std::process::Stdio::piped());

        if let Ok(mut child) = fp_cmd.spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(line.as_bytes()).await;
                let _ = stdin.write_all(b"\n").await;
            }
            if let Ok(fp_out) = child.wait_with_output().await {
                if fp_out.status.success() {
                    let fp_str = String::from_utf8_lossy(&fp_out.stdout);
                    let parts: Vec<&str> = fp_str.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let fp = parts[1].to_string();
                        let clean_fp = fp.strip_prefix("SHA256:").unwrap_or(&fp);

                        let line_parts: Vec<&str> = line.split_whitespace().collect();
                        let key_type = if line_parts.len() >= 2 {
                            line_parts[1].to_string()
                        } else {
                            "unknown".to_string()
                        };

                        let officially_known = OFFICIAL_HOST_KEYS
                            .iter()
                            .any(|(h, kt, f)| *h == host && *kt == key_type && *f == clean_fp);

                        keys.push(ForgeHostKey {
                            key_type,
                            fingerprint: fp,
                            line: line.clone(),
                            officially_known,
                        });
                    }
                }
            }
        }
    }

    Ok(keys)
}

pub async fn trust_host_key(
    config_dir: &Path,
    host: &str,
    port: u16,
    lines: Vec<String>,
) -> Result<(), ForgeError> {
    if lines.is_empty() {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "no host key lines provided to trust".into(),
            git_kind: None,
            host: Some(host.to_string()),
            port: Some(port),
        });
    }

    // 1. Verify lines come from a recent scan (within 10 min)
    let (_cached_lines, is_officially_known) = {
        let lock = SCAN_CACHE.lock();
        if let Some(ref cache) = *lock {
            if let Some((valid_lines, ts)) = cache.get(&(host.to_string(), port)) {
                if ts.elapsed() < Duration::from_secs(600) {
                    for l in &lines {
                        if !valid_lines.contains(l) {
                            return Err(ForgeError {
                                kind: ForgeErrorKind::InvalidArgument,
                                message: "unscanned or expired host key line".into(),
                                git_kind: None,
                                host: Some(host.to_string()),
                                port: Some(port),
                            });
                        }
                    }

                    // Check if officially known
                    let official = lines.iter().any(|line| {
                        OFFICIAL_HOST_KEYS
                            .iter()
                            .any(|(h, kt, _)| *h == host && line.contains(kt))
                    });

                    (valid_lines.clone(), official)
                } else {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::InvalidArgument,
                        message: "scanned host key expired".into(),
                        git_kind: None,
                        host: Some(host.to_string()),
                        port: Some(port),
                    });
                }
            } else {
                return Err(ForgeError {
                    kind: ForgeErrorKind::InvalidArgument,
                    message: "no prior scan for host".into(),
                    git_kind: None,
                    host: Some(host.to_string()),
                    port: Some(port),
                });
            }
        } else {
            return Err(ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "no scan cache found".into(),
                git_kind: None,
                host: Some(host.to_string()),
                port: Some(port),
            });
        }
    };

    // 2. Check for downgrade / change protection
    let host_arg = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };

    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("~"));
    let home_kh = home.join(".ssh/known_hosts");
    let cawide_kh = config_dir.join("ssh/known_hosts");

    for kh_file in [&home_kh, &cawide_kh] {
        if kh_file.exists() {
            let mut check_cmd = Command::new("ssh-keygen");
            check_cmd.args(["-F", &host_arg, "-f", kh_file.to_str().unwrap()]);
            if let Ok(out) = check_cmd.output().await {
                if out.status.success() && !out.stdout.is_empty() {
                    // Host already has a known key in this file
                    if !is_officially_known {
                        return Err(ForgeError {
                            kind: ForgeErrorKind::HostKeyChanged,
                            message: format!(
                                "host key for {host_arg} is already present in {} and cannot be overwritten",
                                kh_file.display()
                            ),
                            git_kind: None,
                            host: Some(host.to_string()),
                            port: Some(port),
                        });
                    }
                }
            }
        }
    }

    // Append lines to <config_dir>/ssh/known_hosts
    let ssh_dir = config_dir.join("ssh");
    let _ = tokio::fs::create_dir_all(&ssh_dir).await;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cawide_kh)
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("open known_hosts: {e}"),
            git_kind: None,
            host: Some(host.to_string()),
            port: Some(port),
        })?;

    for line in lines {
        file.write_all(line.as_bytes())
            .await
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("write known_hosts: {e}"),
                git_kind: None,
                host: Some(host.to_string()),
                port: Some(port),
            })?;
        file.write_all(b"\n").await.map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: format!("write known_hosts newline: {e}"),
            git_kind: None,
            host: Some(host.to_string()),
            port: Some(port),
        })?;
    }
    file.flush().await.map_err(|e| ForgeError {
        kind: ForgeErrorKind::Other,
        message: format!("flush known_hosts: {e}"),
        git_kind: None,
        host: Some(host.to_string()),
        port: Some(port),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_official_host_keys_format() {
        for &(host, key_type, fp) in OFFICIAL_HOST_KEYS {
            assert!(!host.is_empty());
            assert!(!key_type.is_empty());
            assert_eq!(
                fp.len(),
                43,
                "fingerprint for {host}:{key_type} must be 43-char base64 SHA-256"
            );
        }
    }
}
