//! Automatic update checking and version comparison for Cawide.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const NPM_REGISTRY_LATEST_URL: &str = "https://registry.npmjs.org/cawide/latest";
pub const UPDATE_CHECK_INTERVAL_SECS: u64 = 86_400; // 24 hours

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateCache {
    pub last_checked_ts: u64,
    pub latest_version: String,
}

/// Parses a semver version string into (major, minor, patch).
pub fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches('v');
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// Returns true if `latest` is strictly newer than `current`.
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Queries the npm registry for the latest published version of cawide.
pub async fn fetch_latest_version(timeout: Duration) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(format!("cawide/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let resp = client.get(NPM_REGISTRY_LATEST_URL).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP status {}", resp.status());
    }

    let text = resp.text().await?;
    let val: serde_json::Value = serde_json::from_str(&text)?;
    let ver = val
        .get("version")
        .and_then(|v| v.as_str())
        .context("Missing 'version' field in npm response")?;

    Ok(ver.to_string())
}

/// Checks if an update is available based on local cache.
/// If cache is stale or missing, spawns a background tokio task to refresh it.
pub fn check_for_update_cached(config_dir: &Path) -> Option<String> {
    let cache_file = config_dir.join("update_check.json");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut cache_opt: Option<UpdateCache> = None;
    if cache_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&cache_file) {
            if let Ok(c) = serde_json::from_str::<UpdateCache>(&content) {
                cache_opt = Some(c);
            }
        }
    }

    let should_fetch = match &cache_opt {
        Some(c) => now.saturating_sub(c.last_checked_ts) >= UPDATE_CHECK_INTERVAL_SECS,
        None => true,
    };

    if should_fetch {
        let cache_file_clone = cache_file.clone();
        tokio::spawn(async move {
            if let Ok(latest) = fetch_latest_version(Duration::from_secs(2)).await {
                let cache = UpdateCache {
                    last_checked_ts: now,
                    latest_version: latest,
                };
                if let Ok(data) = serde_json::to_string_pretty(&cache) {
                    if let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&cache_file_clone)
                    {
                        let _ = f.write_all(data.as_bytes());
                    }
                }
            }
        });
    }

    if let Some(c) = cache_opt {
        let current = env!("CARGO_PKG_VERSION");
        if is_newer_version(current, &c.latest_version) {
            return Some(c.latest_version);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver() {
        assert_eq!(parse_semver("0.9.0"), Some((0, 9, 0)));
        assert_eq!(parse_semver("v0.10.1"), Some((0, 10, 1)));
        assert_eq!(parse_semver("1.0.0"), Some((1, 0, 0)));
        assert_eq!(parse_semver("invalid"), None);
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.9.0", "0.9.1"));
        assert!(is_newer_version("0.9.0", "0.10.0"));
        assert!(is_newer_version("0.9.0", "1.0.0"));
        assert!(!is_newer_version("0.9.0", "0.9.0"));
        assert!(!is_newer_version("0.9.1", "0.9.0"));
        assert!(!is_newer_version("1.0.0", "0.9.0"));
    }
}
