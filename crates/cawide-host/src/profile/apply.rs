use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::Context;

use super::archive::{
    read_archive, ArchiveContents, ALLOWED_PREFIXES, CLAUDE_FRAGMENT_PATH, OMP_DB_PATH,
    OPENCODE_DB_PATH,
};
use super::login_policy::{
    filter_secret_file, is_login_store, reconcile_with_existing, redact_claude_oauth_tokens,
    ExistingLoginVerdict, SecretFileVerdict, CLAUDE_SETTINGS_PATH, OMP_AGENT_ENV_PATH,
    OMP_ROOT_ENV_PATH,
};
use super::portability::{rewrite_home, rewrite_homebrew, strip_macos_only_mcp};
use super::sqlite_snapshot::{merge_omp_credentials, merge_opencode_credentials};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    Macos,
    Linux,
}

impl TargetOs {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            TargetOs::Macos
        } else {
            TargetOs::Linux
        }
    }
}

pub struct ApplyReport {
    pub written: usize,
    pub agents: Vec<String>,
    pub source_host: String,
    pub notices: Vec<String>,
}

fn has_symlink_ancestor(home: &Path, file_path: &Path) -> Option<PathBuf> {
    let mut current = file_path.parent();
    while let Some(dir) = current {
        if dir == home {
            break;
        }
        if let Ok(meta) = fs::symlink_metadata(dir) {
            if meta.file_type().is_symlink() {
                return Some(dir.to_path_buf());
            }
        }
        current = dir.parent();
    }
    None
}

fn write_file_atomic(
    path: &Path,
    bytes: &[u8],
    #[allow(unused_variables)] mode: u32,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no parent for {}", path.display()))?;
    fs::create_dir_all(parent)?;

    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp file in {}", parent.display()))?;

    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    #[cfg(unix)]
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
    temp.persist(path)
        .with_context(|| format!("failed to persist to {}", path.display()))?;

    Ok(())
}

pub fn apply_profile(
    home: &Path,
    config_dir: &Path,
    bytes: &[u8],
    target_os: TargetOs,
    cawide_exe: &Path,
) -> anyhow::Result<ApplyReport> {
    // 1. Read & validate archive completely
    let ArchiveContents { manifest, files } = read_archive(bytes)?;

    let cross = manifest.source_os == "macos" && target_os == TargetOs::Linux;
    let target_home = home.to_string_lossy().trim_end_matches('/').to_string();
    let mut notices = manifest.notices.clone();
    let mut written_files = Vec::new();

    let mut fragment_file = None;
    let mut omp_db_file = None;
    let mut opencode_db_file = None;

    // 3. For each file except __cawide__/*
    for file in &files {
        if file.path.starts_with("__cawide__/") {
            if file.path == CLAUDE_FRAGMENT_PATH {
                fragment_file = Some(file);
            } else if file.path == OMP_DB_PATH {
                omp_db_file = Some(file);
            } else if file.path == OPENCODE_DB_PATH {
                opencode_db_file = Some(file);
            }
            continue;
        }

        // 1. filter_secret_file
        let mut data = match filter_secret_file(&file.path, &file.data) {
            SecretFileVerdict::Dropped => {
                notices.push(format!(
                    "skipped {}: sign-in tokens are never installed from a synced profile",
                    file.path
                ));
                continue;
            }
            SecretFileVerdict::Rewritten(bytes) => {
                if file.path == CLAUDE_SETTINGS_PATH
                    || file.path == OMP_AGENT_ENV_PATH
                    || file.path == OMP_ROOT_ENV_PATH
                {
                    notices.push(format!(
                        "removed sign-in token variables from {}",
                        file.path
                    ));
                }
                bytes
            }
            SecretFileVerdict::Unchanged => file.data.clone(),
        };

        // 2. redact_claude_oauth_tokens
        if let Ok(text) = std::str::from_utf8(&data) {
            if !text.contains('\0') {
                if let Some((new_text, _)) = redact_claude_oauth_tokens(text) {
                    data = new_text.into_bytes();
                    notices.push(format!(
                        "removed Claude sign-in token(s) from {}; sign in on the cloud machine instead",
                        file.path
                    ));
                }
            }
        }

        let full_path = home.join(&file.path);

        // 3. Existing ancestor-symlink guard
        if let Some(ancestor) = has_symlink_ancestor(home, &full_path) {
            notices.push(format!(
                "skipped {}: refusing to write through symlink {}",
                file.path,
                ancestor.display()
            ));
            continue;
        }

        // 4. If login_policy::is_login_store(&file.path)
        if is_login_store(&file.path) {
            let existing = fs::read(&full_path).ok();
            match reconcile_with_existing(&file.path, data, existing.as_deref()) {
                ExistingLoginVerdict::KeepExisting => {
                    notices.push(format!(
                        "kept the sign-in already on this machine in {}",
                        file.path
                    ));
                    written_files.push(file.path.clone());
                    continue;
                }
                ExistingLoginVerdict::Write(bytes) => {
                    data = bytes;
                }
            }
        }

        // 5. Existing symlink removal, home/Homebrew/MCP transforms, and write_file_atomic
        if let Ok(meta) = fs::symlink_metadata(&full_path) {
            if meta.file_type().is_symlink() {
                let _ = fs::remove_file(&full_path);
            }
        }

        // Data transformations
        if let Ok(text) = std::str::from_utf8(&data) {
            if !text.contains('\0') {
                let mut transformed = rewrite_home(text, &manifest.source_home, &target_home);

                let ext = Path::new(&file.path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                if cross && matches!(ext, "json" | "jsonc" | "toml" | "yml" | "yaml") {
                    transformed = rewrite_homebrew(&transformed);
                }

                if cross {
                    if let Some(res) = strip_macos_only_mcp(&file.path, &transformed) {
                        match res {
                            Ok((new_text, removed)) => {
                                transformed = new_text;
                                for name in removed {
                                    notices.push(format!(
                                        "disabled macOS-only MCP server '{name}' ({})",
                                        file.path
                                    ));
                                }
                            }
                            Err(err) => {
                                notices.push(err);
                            }
                        }
                    }
                }
                data = transformed.into_bytes();
            }
        }

        let mode = if is_login_store(&file.path) {
            0o600
        } else {
            file.mode
        };
        write_file_atomic(&full_path, &data, mode)?;
        written_files.push(file.path.clone());
    }

    // 4. Claude fragment, if present
    if let Some(frag_file) = fragment_file {
        let claude_json_target = home.join(".claude.json");
        let mut skip_fragment = false;

        if let Some(ancestor) = has_symlink_ancestor(home, &claude_json_target) {
            notices.push(format!(
                "skipped .claude.json: refusing to write through symlink {}",
                ancestor.display()
            ));
            skip_fragment = true;
        }

        if !skip_fragment {
            let mut frag_text = match std::str::from_utf8(&frag_file.data) {
                Ok(s) => rewrite_home(s, &manifest.source_home, &target_home),
                Err(_) => String::new(),
            };

            if let Some((new_text, _)) = redact_claude_oauth_tokens(&frag_text) {
                frag_text = new_text;
                notices.push(
                    "removed Claude sign-in token(s) from .claude.json; sign in on the cloud machine instead"
                        .to_string(),
                );
            }

            if cross {
                frag_text = rewrite_homebrew(&frag_text);
                if let Some(res) = strip_macos_only_mcp(CLAUDE_FRAGMENT_PATH, &frag_text) {
                    match res {
                        Ok((new_text, removed)) => {
                            frag_text = new_text;
                            for name in removed {
                                notices.push(format!(
                                    "disabled macOS-only MCP server '{name}' (.claude.json)"
                                ));
                            }
                        }
                        Err(err) => notices.push(err),
                    }
                }
            }

            let fragment_val: serde_json::Value =
                serde_json::from_str(&frag_text).unwrap_or(serde_json::json!({}));

            let mut target_val = if claude_json_target.is_file() {
                match fs::read_to_string(&claude_json_target) {
                    Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(v) => v,
                        Err(_) => {
                            let bak = home.join(".claude.json.cawide-bak");
                            let _ = fs::copy(&claude_json_target, &bak);
                            serde_json::json!({})
                        }
                    },
                    Err(_) => serde_json::json!({}),
                }
            } else {
                serde_json::json!({})
            };

            if !target_val.is_object() {
                target_val = serde_json::json!({});
            }

            if let Some(target_map) = target_val.as_object_mut() {
                if let Some(frag_map) = fragment_val.as_object() {
                    for key in &["mcpServers", "theme", "hasCompletedOnboarding"] {
                        if let Some(val) = frag_map.get(*key) {
                            target_map.insert((*key).to_string(), val.clone());
                        }
                    }
                }

                if !target_map.contains_key("theme") {
                    target_map.insert("theme".to_string(), serde_json::json!("dark"));
                }
            }

            let new_claude_json = serde_json::to_vec_pretty(&target_val)?;
            write_file_atomic(&claude_json_target, &new_claude_json, 0o600)?;
        }
    }

    // 5. DB merges
    if let Some(db_file) = omp_db_file {
        let omp_target = home.join(".omp/agent/agent.db");
        if let Some(ancestor) = has_symlink_ancestor(home, &omp_target) {
            notices.push(format!(
                "skipped .omp/agent/agent.db: refusing to write through symlink {}",
                ancestor.display()
            ));
        } else {
            let mut temp = tempfile::NamedTempFile::new()?;
            temp.write_all(&db_file.data)?;
            temp.flush()?;
            match merge_omp_credentials(temp.path(), &omp_target) {
                Ok(_) => {}
                Err(e) => {
                    notices.push(format!("could not merge OMP credentials: {e}"));
                }
            }
        }
    }

    if let Some(db_file) = opencode_db_file {
        let opencode_target = home.join(".local/share/opencode/opencode.db");
        if let Some(ancestor) = has_symlink_ancestor(home, &opencode_target) {
            notices.push(format!(
                "skipped .local/share/opencode/opencode.db: refusing to write through symlink {}",
                ancestor.display()
            ));
        } else {
            let mut temp = tempfile::NamedTempFile::new()?;
            temp.write_all(&db_file.data)?;
            temp.flush()?;
            match merge_opencode_credentials(temp.path(), &opencode_target) {
                Ok(_) => {}
                Err(e) => {
                    notices.push(format!("could not merge OpenCode credentials: {e}"));
                }
            }
        }
    }

    // 6. Stale cleanup
    let profile_applied_path = config_dir.join("profile-applied.json");
    let previously_applied = if profile_applied_path.is_file() {
        fs::read_to_string(&profile_applied_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("files").and_then(|f| f.as_array().cloned()))
            .map(|arr| {
                arr.into_iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let new_file_set: std::collections::HashSet<&str> =
        files.iter().map(|f| f.path.as_str()).collect();

    for old_file in previously_applied {
        if is_login_store(&old_file) {
            continue;
        }

        if !ALLOWED_PREFIXES
            .iter()
            .any(|p| *p != "__cawide__/" && old_file.starts_with(p))
        {
            continue;
        }

        let p = Path::new(&old_file);
        let normal_only = p.components().all(|c| matches!(c, Component::Normal(_)));
        if !normal_only {
            continue;
        }

        let abs_old = home.join(&old_file);
        if has_symlink_ancestor(home, &abs_old).is_some() {
            continue;
        }

        if !new_file_set.contains(old_file.as_str()) {
            let _ = fs::remove_file(&abs_old);
        }
    }

    written_files.sort();
    let applied_json = serde_json::json!({
        "files": written_files,
    });
    let applied_bytes = serde_json::to_vec_pretty(&applied_json)?;
    write_file_atomic(&profile_applied_path, &applied_bytes, 0o600)?;

    // 7. Re-install Cawide hooks
    for agent in &manifest.agents {
        let targets: &[&str] = match agent.as_str() {
            "claude" => &[".claude/settings.json"],
            "codex" => &[".codex/config.toml", ".codex/hooks.json"],
            "omp" => &[".omp/agent/extensions/cawide.js"],
            "opencode" => &[".config/opencode/plugins/cawide.js"],
            _ => &[],
        };

        let mut guarded_ancestor = None;
        for t in targets {
            let full_target = home.join(t);
            if let Some(anc) = has_symlink_ancestor(home, &full_target) {
                guarded_ancestor = Some(anc);
                break;
            }
        }

        if let Some(ancestor) = guarded_ancestor {
            notices.push(format!(
                "skipped Cawide hooks for {agent}: refusing to write through symlink {}",
                ancestor.display()
            ));
            continue;
        }

        match crate::agent::setup::run_setup(home, cawide_exe, agent, false) {
            Ok(_) => {}
            Err(e) => {
                notices.push(format!("could not install Cawide hooks for {agent}: {e}"));
            }
        }
    }

    Ok(ApplyReport {
        written: written_files.len(),
        agents: manifest.agents,
        source_host: manifest.source_host,
        notices,
    })
}
