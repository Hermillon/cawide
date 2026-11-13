use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use reqwest::header::HeaderValue;
use sha2::{Digest, Sha256};

use crate::cloud::account::{self, authed};
use crate::cloud::client::{CloudClient, CloudConfig};

use super::apply::{apply_profile, TargetOs};
use super::collect::collect_profile;
#[allow(unused_imports)]
use super::credentials::{MacKeychain, NoSecretStore};
use super::spec::SourceEnv;

pub async fn run_push(
    config_dir: &Path,
    dry_run: bool,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let env = SourceEnv::from_process_env()?;
    let exe = std::env::current_exe().context("failed to get current executable path")?;

    let collected = tokio::task::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        {
            let store = MacKeychain;
            collect_profile(&env, &store, &exe)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let store = NoSecretStore;
            collect_profile(&env, &store, &exe)
        }
    })
    .await
    .context("profile collection task panicked")??;

    for s in &collected.summary {
        let kib = s.bytes as f64 / 1024.0;
        println!("{}: {} files, {:.1} KiB", s.agent, s.files, kib);
    }

    if !collected.credentials.is_empty() {
        println!("Credentials included:");
        for c in &collected.credentials {
            println!("  - {c}");
        }
    }

    for n in &collected.manifest.notices {
        println!("note: {n}");
    }

    if !collected.logins_to_redo.is_empty() {
        println!(
            "Logins not copied (each cloud machine signs in on its own so providers don't sign you out or flag your account):"
        );
        for entry in &collected.logins_to_redo {
            println!("  - {entry}");
        }
    }

    if let Some(ref out_path) = output {
        fs::write(out_path, &collected.archive)
            .with_context(|| format!("failed to write archive to {}", out_path.display()))?;
        #[cfg(unix)]
        let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(0o600));
    }

    if dry_run {
        println!("Dry run: nothing uploaded.");
        return Ok(());
    }

    let mut account = account::load(config_dir)?
        .ok_or_else(|| anyhow::anyhow!("Not logged in. Run `cawide login` first."))?;

    let cfg = CloudConfig::from_env()?;
    let client = CloudClient::new(&cfg)?;

    let sha = format!("{:x}", Sha256::digest(&collected.archive));
    let sha_header = HeaderValue::from_str(&sha).context("invalid sha header")?;
    let agents_str = collected.manifest.agents.join(",");
    let agents_header = HeaderValue::from_str(&agents_str).context("invalid agents header")?;
    let clean_source: String = collected
        .manifest
        .source_host
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '_'
            }
        })
        .collect();
    let source_header =
        HeaderValue::from_str(&clean_source).context("invalid source host header")?;
    let content_type = HeaderValue::from_static("application/octet-stream");

    let headers = [
        ("x-cawide-profile-sha256", sha_header),
        ("x-cawide-profile-agents", agents_header),
        ("x-cawide-profile-source", source_header),
        ("content-type", content_type),
        (
            "x-cawide-profile-policy",
            HeaderValue::from_static("api-keys-only"),
        ),
    ];

    let archive_bytes = collected.archive;
    let resp = authed(&client, config_dir, &mut account, |token| {
        let c = &client;
        let h = headers.clone();
        let bytes = archive_bytes.clone();
        async move {
            c.put_bytes("/api/v1/profile", bytes, &h, Some(&token))
                .await
        }
    })
    .await?;

    if resp.status != 200 {
        anyhow::bail!("{}", resp.error_message());
    }

    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).context("failed to parse profile upload response")?;

    let revision = val.get("revision").and_then(|v| v.as_i64()).unwrap_or(1);
    let size_bytes = val.get("size_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let unchanged = val
        .get("unchanged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let delivered = val
        .get("delivered")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let kib = size_bytes as f64 / 1024.0;
    println!(
        "Uploaded agent profile revision {revision} ({:.1} KiB; agents: {})",
        kib, agents_str
    );

    if unchanged && delivered {
        println!("Unchanged since the last upload.");
        println!("Applied to your running cloud machine.");
    } else if unchanged {
        println!("Unchanged since the last upload.");
    } else if delivered {
        println!("Applied to your running cloud machine.");
    } else {
        println!("It will be applied the next time your cloud machine starts.");
    }

    Ok(())
}

pub async fn run_status(config_dir: &Path) -> anyhow::Result<()> {
    let mut account = account::load(config_dir)?
        .ok_or_else(|| anyhow::anyhow!("Not logged in. Run `cawide login` first."))?;

    let cfg = CloudConfig::from_env()?;
    let client = CloudClient::new(&cfg)?;

    let resp = authed(&client, config_dir, &mut account, |token| {
        let c = &client;
        async move { c.get("/api/v1/profile", Some(&token)).await }
    })
    .await?;

    if resp.status == 404 {
        println!("No agent profile uploaded yet.");
        return Ok(());
    }

    if resp.status != 200 {
        anyhow::bail!("{}", resp.error_message());
    }

    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).context("failed to parse profile response")?;

    let revision = val.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
    let source_host = val
        .get("source_host")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let updated_at = val.get("updated_at").and_then(|v| v.as_i64()).unwrap_or(0);
    let size_bytes = val.get("size_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let agents: Vec<String> = val
        .get("agents")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let kib = size_bytes as f64 / 1024.0;
    println!(
        "Revision {revision} from {source_host}, uploaded at unix time {updated_at}; agents: {}; {:.1} KiB",
        agents.join(","),
        kib
    );

    Ok(())
}

pub async fn run_delete(config_dir: &Path) -> anyhow::Result<()> {
    let mut account = account::load(config_dir)?
        .ok_or_else(|| anyhow::anyhow!("Not logged in. Run `cawide login` first."))?;

    let cfg = CloudConfig::from_env()?;
    let client = CloudClient::new(&cfg)?;

    let resp = authed(&client, config_dir, &mut account, |token| {
        let c = &client;
        async move { c.delete("/api/v1/profile", Some(&token)).await }
    })
    .await?;

    if resp.status == 204 {
        println!(
            "Deleted the agent profile from Cawide Cloud. Cloud machines keep files that were already applied."
        );
        return Ok(());
    }

    if resp.status == 404 {
        println!("No agent profile uploaded yet.");
        return Ok(());
    }

    anyhow::bail!("{}", resp.error_message());
}

pub fn run_apply(home: &Path, config_dir: &Path, file: Option<PathBuf>) -> anyhow::Result<()> {
    let default_pending = config_dir.join("profile-pending.tar.gz");
    let (target_file, is_default) = match file {
        Some(f) => (f, false),
        None => {
            if !default_pending.is_file() {
                println!("No pending agent profile.");
                return Ok(());
            }
            (default_pending.clone(), true)
        }
    };

    let bytes = fs::read(&target_file)
        .with_context(|| format!("failed to read profile archive {}", target_file.display()))?;

    let exe = std::env::current_exe().context("failed to get current executable path")?;
    let report = apply_profile(home, config_dir, &bytes, TargetOs::current(), &exe)?;

    println!(
        "Applied agent profile from {}: {} files ({})",
        report.source_host,
        report.written,
        report.agents.join(",")
    );

    for n in &report.notices {
        println!("note: {n}");
    }

    if is_default {
        let _ = fs::remove_file(&default_pending);
    }

    Ok(())
}
