use std::collections::HashSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}
use std::path::{Path, PathBuf};

use super::archive::{
    write_archive, Manifest, CLAUDE_FRAGMENT_PATH, OMP_DB_PATH, OPENCODE_DB_PATH,
};
use super::credentials::{collect_credentials, SecretStore};
use super::login_policy::{
    opencode_legacy_oauth_ids, redact_claude_oauth_tokens, sanitize_opencode_legacy_auth,
    strip_oauth_env, CredentialDb, CLAUDE_SETTINGS_PATH, OMP_AGENT_ENV_PATH, OMP_ROOT_ENV_PATH,
};
#[cfg(target_os = "macos")]
use super::portability::find_macos_only_mcp;
use super::spec::SourceEnv;
use super::sqlite_snapshot::{omp_keep, opencode_keep, snapshot_db};

#[derive(Debug, Clone)]
pub struct AgentSummary {
    pub agent: String,
    pub files: usize,
    pub bytes: u64,
}

pub struct CollectedProfile {
    pub archive: Vec<u8>,
    pub manifest: Manifest,
    pub summary: Vec<AgentSummary>,
    pub credentials: Vec<String>,
    pub logins_to_redo: Vec<String>,
}

struct WalkContext {
    ancestor_stack: Vec<PathBuf>,
    notices: Vec<String>,
    secret: bool,
}

fn copy_staged_file(
    src: &Path,
    dst: &Path,
    secret: bool,
    notices: &mut Vec<String>,
) -> anyhow::Result<bool> {
    let metadata = match fs::metadata(src) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };

    if metadata.len() > 4 * 1024 * 1024 {
        notices.push(format!("skipped {} (larger than 4 MiB)", src.display()));
        return Ok(false);
    }

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(src, dst)?;

    #[cfg(unix)]
    let is_exec = metadata.permissions().mode() & 0o111 != 0;
    #[cfg(not(unix))]
    let is_exec = false;

    let mode = if secret {
        0o600
    } else if is_exec {
        0o755
    } else {
        0o644
    };

    set_mode(dst, mode)?;
    Ok(true)
}

fn walk_dir(
    current_src: &Path,
    current_dst: &Path,
    ctx: &mut WalkContext,
    skip_child: Option<&str>,
) -> anyhow::Result<()> {
    let canon_current = match fs::canonicalize(current_src) {
        Ok(c) => c,
        Err(_) => {
            ctx.notices
                .push(format!("skipped broken symlink {}", current_src.display()));
            return Ok(());
        }
    };

    if ctx.ancestor_stack.contains(&canon_current) {
        // Cycle detected on current path
        return Ok(());
    }

    ctx.ancestor_stack.push(canon_current);

    let read_res = fs::read_dir(current_src);
    let entries = match read_res {
        Ok(rd) => {
            let mut items: Vec<_> = rd.filter_map(|e| e.ok()).collect();
            items.sort_by_key(|e| e.file_name());
            items
        }
        Err(_) => {
            ctx.ancestor_stack.pop();
            return Ok(());
        }
    };

    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if name_str == ".DS_Store"
            || name_str == "node_modules"
            || name_str == ".git"
            || name_str == "__pycache__"
            || name_str.ends_with(".pyc")
            || name_str.ends_with(".cawide-bak")
        {
            continue;
        }

        if let Some(skip) = skip_child {
            if name_str == skip {
                continue;
            }
        }

        let is_sym = match fs::symlink_metadata(&path) {
            Ok(meta) => meta.file_type().is_symlink(),
            Err(_) => false,
        };

        if is_sym {
            let canon_target = match fs::canonicalize(&path) {
                Ok(c) => c,
                Err(_) => {
                    ctx.notices
                        .push(format!("skipped broken symlink {}", path.display()));
                    continue;
                }
            };

            if canon_target.is_file() {
                let dst_file = current_dst.join(&file_name);
                let _ = copy_staged_file(&path, &dst_file, ctx.secret, &mut ctx.notices);
            } else if canon_target.is_dir() {
                if ctx.ancestor_stack.contains(&canon_target) {
                    ctx.notices.push(format!(
                        "skipped recursive symlink {} pointing to {}",
                        path.display(),
                        canon_target.display()
                    ));
                    continue;
                }
                let dst_dir = current_dst.join(&file_name);
                walk_dir(&path, &dst_dir, ctx, skip_child)?;
            }
            continue;
        }

        if path.is_file() {
            let dst_file = current_dst.join(&file_name);
            let _ = copy_staged_file(&path, &dst_file, ctx.secret, &mut ctx.notices);
        } else if path.is_dir() {
            let dst_dir = current_dst.join(&file_name);
            walk_dir(&path, &dst_dir, ctx, skip_child)?;
        }
    }

    ctx.ancestor_stack.pop();
    Ok(())
}

pub fn collect_profile(
    env: &SourceEnv,
    store: &dyn SecretStore,
    cawide_exe: &Path,
) -> anyhow::Result<CollectedProfile> {
    let staging_dir = tempfile::tempdir()?;
    let staging_home = staging_dir.path();

    let claude_root = env
        .claude_config_dir
        .clone()
        .unwrap_or_else(|| env.home.join(".claude"));

    let codex_root = env
        .codex_home
        .clone()
        .unwrap_or_else(|| env.home.join(".codex"));

    let omp_root = env
        .omp_agent_dir
        .clone()
        .unwrap_or_else(|| env.home.join(".omp/agent"));

    let opencode_config_root = env
        .xdg_config_home
        .clone()
        .unwrap_or_else(|| env.home.join(".config"))
        .join("opencode");

    let opencode_data_root = env
        .xdg_data_home
        .clone()
        .unwrap_or_else(|| env.home.join(".local/share"))
        .join("opencode");

    let mut notices = Vec::new();
    let mut credentials = Vec::new();
    let mut ctx = WalkContext {
        ancestor_stack: Vec::new(),
        notices: Vec::new(),
        secret: false,
    };

    let mut omp_dropped_logins = Vec::new();
    let mut opencode_dropped_logins = Vec::new();
    let mut opencode_mcp_logins = false;

    // 1. Walk directory trees for each agent

    // --- Claude collection ---
    let claude_staged = staging_home.join(".claude");
    for file in &["settings.json", "CLAUDE.md", "keybindings.json"] {
        let src = claude_root.join(file);
        if src.is_file() {
            let dst = claude_staged.join(file);
            let _ = copy_staged_file(&src, &dst, false, &mut ctx.notices);
        }
    }
    for dir in &[
        "commands",
        "agents",
        "skills",
        "rules",
        "output-styles",
        "hooks",
        "themes",
        "workflows",
        "agent-memory",
    ] {
        let src = claude_root.join(dir);
        if src.is_dir() {
            let dst = claude_staged.join(dir);
            ctx.secret = false;
            let _ = walk_dir(&src, &dst, &mut ctx, None);
        }
    }

    // --- Codex collection ---
    let codex_staged = staging_home.join(".codex");
    for file in &[
        "config.toml",
        "AGENTS.md",
        "AGENTS.override.md",
        "hooks.json",
    ] {
        let src = codex_root.join(file);
        if src.is_file() {
            let dst = codex_staged.join(file);
            let _ = copy_staged_file(&src, &dst, false, &mut ctx.notices);
        }
    }
    if codex_root.is_dir() {
        if let Ok(rd) = fs::read_dir(&codex_root) {
            for entry in rd.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if s.ends_with(".config.toml") && entry.path().is_file() {
                    let dst = codex_staged.join(&name);
                    let _ = copy_staged_file(&entry.path(), &dst, false, &mut ctx.notices);
                }
            }
        }
    }
    for dir in &["prompts", "rules"] {
        let src = codex_root.join(dir);
        if src.is_dir() {
            let dst = codex_staged.join(dir);
            ctx.secret = false;
            let _ = walk_dir(&src, &dst, &mut ctx, None);
        }
    }
    let codex_skills = codex_root.join("skills");
    if codex_skills.is_dir() {
        let dst = codex_staged.join("skills");
        ctx.secret = false;
        let _ = walk_dir(&codex_skills, &dst, &mut ctx, Some(".system"));
    }

    // --- OMP collection ---
    let omp_staged = staging_home.join(".omp/agent");
    for file in &[
        "config.yml",
        "config.yaml",
        "AGENTS.md",
        "SYSTEM.md",
        "RULES.md",
        "TITLE_SYSTEM.md",
    ] {
        let src = omp_root.join(file);
        if src.is_file() {
            let dst = omp_staged.join(file);
            let _ = copy_staged_file(&src, &dst, false, &mut ctx.notices);
        }
    }
    for secret_file in &[
        "models.yml",
        "models.yaml",
        "mcp.json",
        ".env",
        "secrets.yml",
        "secret-placeholder.key",
    ] {
        let src = omp_root.join(secret_file);
        if src.is_file() {
            let dst = omp_staged.join(secret_file);
            let _ = copy_staged_file(&src, &dst, true, &mut ctx.notices);
        }
    }
    for dir in &[
        "rules",
        "agents",
        "commands",
        "prompts",
        "instructions",
        "tools",
        "extensions",
        "hooks",
        "skills",
        "managed-skills",
        "modules",
    ] {
        let src = omp_root.join(dir);
        if src.is_dir() {
            let dst = omp_staged.join(dir);
            ctx.secret = false;
            let _ = walk_dir(&src, &dst, &mut ctx, None);
        }
    }

    // OMP extra: home/.omp/.env
    let omp_extra_env = env.home.join(".omp/.env");
    if omp_extra_env.is_file() {
        let dst = staging_home.join(".omp/.env");
        let _ = copy_staged_file(&omp_extra_env, &dst, true, &mut ctx.notices);
    }

    // OMP extra: home/.agents/.skill-lock.json and skills
    let agents_dir = env.home.join(".agents");
    let skill_lock = agents_dir.join(".skill-lock.json");
    if skill_lock.is_file() {
        let dst = staging_home.join(".agents/.skill-lock.json");
        let _ = copy_staged_file(&skill_lock, &dst, false, &mut ctx.notices);
    }
    let agents_skills = agents_dir.join("skills");
    if agents_skills.is_dir() {
        let dst = staging_home.join(".agents/skills");
        ctx.secret = false;
        let _ = walk_dir(&agents_skills, &dst, &mut ctx, None);
    }

    // --- OpenCode collection ---
    let opencode_cfg_staged = staging_home.join(".config/opencode");
    for file in &[
        "opencode.json",
        "opencode.jsonc",
        "config.json",
        "AGENTS.md",
    ] {
        let src = opencode_config_root.join(file);
        if src.is_file() {
            let dst = opencode_cfg_staged.join(file);
            let _ = copy_staged_file(&src, &dst, false, &mut ctx.notices);
        }
    }
    for dir in &[
        "agent", "agents", "command", "commands", "mode", "modes", "plugin", "plugins", "skills",
        "themes", "tool", "tools",
    ] {
        let src = opencode_config_root.join(dir);
        if src.is_dir() {
            let dst = opencode_cfg_staged.join(dir);
            ctx.secret = false;
            let _ = walk_dir(&src, &dst, &mut ctx, None);
        }
    }

    let opencode_data_staged = staging_home.join(".local/share/opencode");
    let opencode_auth_src = opencode_data_root.join("auth.json");
    if opencode_auth_src.is_file() {
        if let Ok(content) = fs::read_to_string(&opencode_auth_src) {
            if let Some(sanitized) = sanitize_opencode_legacy_auth(&content) {
                let dst = opencode_data_staged.join("auth.json");
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&dst, sanitized.as_bytes())?;
                set_mode(&dst, 0o600)?;
                credentials.push("OpenCode API keys (auth.json)".to_string());
            }
            opencode_dropped_logins.extend(opencode_legacy_oauth_ids(&content));
        }
    }
    let opencode_mcp_auth_src = opencode_data_root.join("mcp-auth.json");
    if opencode_mcp_auth_src.is_file() {
        opencode_mcp_logins = true;
    }

    // Add directory walk notices
    notices.extend(ctx.notices);

    // 2. Claude JSON fragment
    let claude_json_path = env
        .claude_config_dir
        .as_ref()
        .map(|p| p.join(".claude.json"))
        .unwrap_or_else(|| env.home.join(".claude.json"));

    let mut fragment_staged = false;
    if claude_json_path.is_file() {
        if let Ok(content) = fs::read_to_string(&claude_json_path) {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(val) => {
                    let mut frag = serde_json::Map::new();
                    if let Some(mcp) = val.get("mcpServers") {
                        frag.insert("mcpServers".to_string(), mcp.clone());
                    }
                    if let Some(th) = val.get("theme") {
                        frag.insert("theme".to_string(), th.clone());
                    }
                    if let Some(onb) = val.get("hasCompletedOnboarding") {
                        frag.insert("hasCompletedOnboarding".to_string(), onb.clone());
                    }

                    let frag_bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(frag))?;
                    let dst = staging_home.join(CLAUDE_FRAGMENT_PATH);
                    if let Some(parent) = dst.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&dst, frag_bytes)?;
                    set_mode(&dst, 0o600)?;
                    fragment_staged = true;
                }
                Err(_) => {
                    notices.push(
                        "could not parse .claude.json; Claude Code MCP servers were not synced"
                            .to_string(),
                    );
                }
            }
        }
    }

    // 3. Credentials & SQLite snapshots
    let creds = collect_credentials(store, &codex_root);
    notices.extend(creds.notices);
    credentials.extend(creds.credential_entries);

    if let Some(codex_cred) = creds.codex_auth {
        let dst = codex_staged.join("auth.json");
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dst, codex_cred.as_bytes())?;
        set_mode(&dst, 0o600)?;
    }

    // Add extra credential labels for secret files
    if (omp_staged.join(".env").is_file() || staging_home.join(".omp/.env").is_file())
        && !credentials.contains(&".omp/agent/.env".to_string())
    {
        credentials.push(".omp/agent/.env".to_string());
    }
    if omp_staged.join("models.yml").is_file() || omp_staged.join("models.yaml").is_file() {
        credentials.push(".omp/agent/models.yml".to_string());
    }
    if omp_staged.join("mcp.json").is_file() {
        credentials.push(".omp/agent/mcp.json".to_string());
    }
    if omp_staged.join("secrets.yml").is_file() {
        credentials.push(".omp/agent/secrets.yml".to_string());
    }

    // Snapshots:
    let omp_db_src = omp_root.join("agent.db");
    let omp_db_dst = staging_home.join(OMP_DB_PATH);
    match snapshot_db(&omp_db_src, &omp_db_dst, omp_keep, CredentialDb::Omp) {
        Ok(outcome) => {
            if outcome.created {
                set_mode(&omp_db_dst, 0o600)?;
                credentials.push("OMP credential database".to_string());
            }
            omp_dropped_logins.extend(outcome.dropped_logins);
        }
        Err(e) => {
            notices.push(format!("could not snapshot {}: {e}", omp_db_src.display()));
        }
    }

    let opencode_db_src = opencode_data_root.join("opencode.db");
    let opencode_db_dst = staging_home.join(OPENCODE_DB_PATH);
    match snapshot_db(
        &opencode_db_src,
        &opencode_db_dst,
        opencode_keep,
        CredentialDb::OpenCode,
    ) {
        Ok(outcome) => {
            if outcome.created {
                set_mode(&opencode_db_dst, 0o600)?;
                credentials.push("OpenCode credential database".to_string());
            }
            opencode_dropped_logins.extend(outcome.dropped_logins);
        }
        Err(e) => {
            notices.push(format!(
                "could not snapshot {}: {e}",
                opencode_db_src.display()
            ));
        }
    }

    // 4. Strip Cawide's own hooks from staging
    let hook_targets = [
        ("claude", claude_staged.join("settings.json")),
        ("codex", codex_staged.join("config.toml")),
        ("codex", codex_staged.join("hooks.json")),
        ("omp", omp_staged.join("extensions/cawide.js")),
        ("opencode", opencode_cfg_staged.join("plugins/cawide.js")),
    ];

    let mut stripped_agents = HashSet::new();
    for (agent, target) in hook_targets {
        if target.exists() && !stripped_agents.contains(agent) {
            match crate::agent::setup::run_setup(staging_home, cawide_exe, agent, true) {
                Ok(_) => {
                    stripped_agents.insert(agent);
                }
                Err(e) => {
                    notices.push(format!("could not remove Cawide hooks for {agent}: {e}"));
                }
            }
        }
    }

    // Delete *.cawide-bak in staging
    delete_bak_files(staging_home);

    // Env tokens pass
    let mut token_variables = Vec::new();
    for rel_path in &[CLAUDE_SETTINGS_PATH, OMP_AGENT_ENV_PATH, OMP_ROOT_ENV_PATH] {
        let staged_file = staging_home.join(rel_path);
        if staged_file.is_file() {
            if let Ok(content) = fs::read_to_string(&staged_file) {
                if let Some((rewritten, removed)) = strip_oauth_env(rel_path, &content) {
                    #[cfg(unix)]
                    let mode = fs::metadata(&staged_file)
                        .map(|m| m.permissions().mode())
                        .unwrap_or(0o600);
                    #[cfg(not(unix))]
                    let mode = 0o600;
                    if fs::write(&staged_file, rewritten.as_bytes()).is_ok() {
                        let _ = set_mode(&staged_file, mode);
                    }
                    token_variables.extend(removed);
                }
            }
        }
    }

    // Token redaction pass: walk every staged regular file except those under __cawide__/db/
    let mut staged_files_to_check = Vec::new();
    let mut stack = vec![staging_home.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    staged_files_to_check.push(p);
                } else if p.is_dir() {
                    stack.push(p);
                }
            }
        }
    }
    staged_files_to_check.sort();
    for file_path in staged_files_to_check {
        let rel = match file_path.strip_prefix(staging_home) {
            Ok(r) => r.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        if rel.starts_with("__cawide__/db/") {
            continue;
        }
        if let Ok(data) = fs::read(&file_path) {
            if let Ok(text) = std::str::from_utf8(&data) {
                if !text.contains('\0') {
                    if let Some((redacted, _)) = redact_claude_oauth_tokens(text) {
                        #[cfg(unix)]
                        let mode = fs::metadata(&file_path)
                            .map(|m| m.permissions().mode())
                            .unwrap_or(0o644);
                        #[cfg(not(unix))]
                        let mode = 0o644;
                        if fs::write(&file_path, redacted.as_bytes()).is_ok() {
                            let _ = set_mode(&file_path, mode);
                        }
                        notices.push(format!(
                            "removed Claude sign-in token(s) from {rel}; sign in on the cloud machine instead"
                        ));
                    }
                }
            }
        }
    }

    // 5. If .codex/config.toml or .codex/auth.json is staged, set cli_auth_credentials_store = "file"
    let config_toml_path = codex_staged.join("config.toml");
    let staged_codex_auth = codex_staged.join("auth.json");
    if config_toml_path.is_file() || staged_codex_auth.is_file() {
        if let Some(parent) = config_toml_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = if config_toml_path.is_file() {
            fs::read_to_string(&config_toml_path).unwrap_or_default()
        } else {
            String::new()
        };

        let mut doc: toml_edit::DocumentMut = content.parse().unwrap_or_default();
        doc["cli_auth_credentials_store"] = toml_edit::value("file");
        fs::write(&config_toml_path, doc.to_string())?;
    }

    // 6. Build notices
    #[cfg(target_os = "macos")]
    {
        let mcp_check_files = [
            (
                "__cawide__/claude-json.json",
                staging_home.join(CLAUDE_FRAGMENT_PATH),
            ),
            (".omp/agent/mcp.json", omp_staged.join("mcp.json")),
            (".codex/config.toml", codex_staged.join("config.toml")),
            (
                ".config/opencode/opencode.json",
                opencode_cfg_staged.join("opencode.json"),
            ),
            (
                ".config/opencode/opencode.jsonc",
                opencode_cfg_staged.join("opencode.jsonc"),
            ),
            (
                ".config/opencode/config.json",
                opencode_cfg_staged.join("config.json"),
            ),
        ];

        for (archive_path, disk_path) in mcp_check_files {
            if disk_path.is_file() {
                if let Ok(content) = fs::read_to_string(&disk_path) {
                    if let Some(res) = find_macos_only_mcp(archive_path, &content) {
                        match res {
                            Ok(servers) => {
                                for server in servers {
                                    notices.push(format!(
                                        "macOS-only MCP server '{server}' ({archive_path}) will be disabled on Linux"
                                    ));
                                }
                            }
                            Err(e) => notices.push(e),
                        }
                    }
                }
            }
        }
    }

    // 7. Included agents
    let mut included_agents = Vec::new();
    let has_claude = claude_staged.exists() || fragment_staged;
    let has_codex = codex_staged.exists();
    let has_omp = omp_staged.exists()
        || staging_home.join(".omp").exists()
        || staging_home.join(".agents").exists()
        || omp_db_dst.exists();
    let has_opencode =
        opencode_cfg_staged.exists() || opencode_data_staged.exists() || opencode_db_dst.exists();

    if has_claude {
        included_agents.push("claude".to_string());
    }
    if has_codex {
        included_agents.push("codex".to_string());
    }
    if has_omp {
        included_agents.push("omp".to_string());
    }
    if has_opencode {
        included_agents.push("opencode".to_string());
    }

    if included_agents.is_empty() {
        anyhow::bail!("No supported agent setup found (Claude Code, Codex, OMP, OpenCode).");
    }

    let mut logins_to_redo = Vec::new();
    if included_agents.iter().any(|a| a == "claude") {
        logins_to_redo
            .push("Claude Code: run `claude`, then /login (or set ANTHROPIC_API_KEY)".to_string());
    }
    if included_agents.iter().any(|a| a == "codex") && !codex_staged.join("auth.json").is_file() {
        logins_to_redo.push(
            "Codex: run `codex login --device-auth` (turn on device code sign-in in ChatGPT Settings → Security first)".to_string(),
        );
    }
    omp_dropped_logins.sort();
    omp_dropped_logins.dedup();
    if !omp_dropped_logins.is_empty() {
        logins_to_redo.push(format!(
            "OMP ({}): run `omp`, then /login",
            omp_dropped_logins.join(", ")
        ));
    }
    opencode_dropped_logins.sort();
    opencode_dropped_logins.dedup();
    if !opencode_dropped_logins.is_empty() {
        logins_to_redo.push(format!(
            "OpenCode ({}): run `opencode auth login`, or sign in again when OpenCode asks",
            opencode_dropped_logins.join(", ")
        ));
    }
    if opencode_mcp_logins {
        logins_to_redo.push("OpenCode MCP servers: sign in again when OpenCode asks".to_string());
    }
    token_variables.sort();
    token_variables.dedup();
    if !token_variables.is_empty() {
        logins_to_redo.push(format!(
            "Sign-in token variables not copied ({}): sign in on the cloud machine instead",
            token_variables.join(", ")
        ));
    }

    let source_os = env.source_os.clone().unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else {
            "linux".to_string()
        }
    });
    let source_home = env.home.to_string_lossy().trim_end_matches('/').to_string();
    let source_host = crate::net::dispatcher::host_display_name();

    let manifest = Manifest {
        format_version: 1,
        source_os,
        source_home,
        source_host,
        agents: included_agents.clone(),
        notices: notices.clone(),
    };

    // Calculate per-agent summary
    let mut summary = Vec::new();
    for agent in &included_agents {
        let (files, bytes) = compute_agent_size(staging_home, agent, fragment_staged);
        summary.push(AgentSummary {
            agent: agent.clone(),
            files,
            bytes,
        });
    }

    let archive = write_archive(staging_home, &manifest)?;
    if archive.len() > 16 * 1024 * 1024 {
        let top5 = get_top_5_largest_files(staging_home);
        anyhow::bail!(
            "agent profile is {:.1} MiB after compression; the limit is 16 MiB\nLargest files:\n{}",
            archive.len() as f64 / (1024.0 * 1024.0),
            top5.join("\n")
        );
    }

    Ok(CollectedProfile {
        archive,
        manifest,
        summary,
        credentials,
        logins_to_redo,
    })
}

fn compute_agent_size(staging: &Path, agent: &str, fragment_staged: bool) -> (usize, u64) {
    let mut count = 0;
    let mut bytes = 0;

    let prefixes: Vec<PathBuf> = match agent {
        "claude" => {
            let mut p = vec![staging.join(".claude")];
            if fragment_staged {
                p.push(staging.join(CLAUDE_FRAGMENT_PATH));
            }
            p
        }
        "codex" => vec![staging.join(".codex")],
        "omp" => vec![
            staging.join(".omp"),
            staging.join(".agents"),
            staging.join(OMP_DB_PATH),
        ],
        "opencode" => vec![
            staging.join(".config/opencode"),
            staging.join(".local/share/opencode"),
            staging.join(OPENCODE_DB_PATH),
        ],
        _ => Vec::new(),
    };

    for prefix in prefixes {
        if prefix.is_file() {
            count += 1;
            bytes += fs::metadata(&prefix).map(|m| m.len()).unwrap_or(0);
        } else if prefix.is_dir() {
            let mut stack = vec![prefix];
            while let Some(dir) = stack.pop() {
                if let Ok(rd) = fs::read_dir(dir) {
                    for entry in rd.filter_map(|e| e.ok()) {
                        let p = entry.path();
                        if p.is_file() {
                            count += 1;
                            bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                        } else if p.is_dir() {
                            stack.push(p);
                        }
                    }
                }
            }
        }
    }

    (count, bytes)
}

fn delete_bak_files(dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(rd) = fs::read_dir(current) {
            for entry in rd.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() && p.extension().is_some_and(|ext| ext == "cawide-bak") {
                    let _ = fs::remove_file(&p);
                } else if p.is_dir() {
                    stack.push(p);
                }
            }
        }
    }
}

fn get_top_5_largest_files(staging: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut stack = vec![staging.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    let rel = p
                        .strip_prefix(staging)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string();
                    files.push((len, rel));
                } else if p.is_dir() {
                    stack.push(p);
                }
            }
        }
    }
    files.sort_by_key(|a| std::cmp::Reverse(a.0));
    files
        .into_iter()
        .take(5)
        .map(|(len, path)| format!("  - {path}: {:.2} MiB", len as f64 / (1024.0 * 1024.0)))
        .collect()
}
