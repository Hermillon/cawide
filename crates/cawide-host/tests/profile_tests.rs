use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn set_perm(path: &Path, mode: u32) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_perm(_path: &Path, _mode: u32) {}
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::Connection;

use cawide_host::cloud::account::{self, Account};
use cawide_host::profile::apply::{apply_profile, TargetOs};
use cawide_host::profile::archive::{read_archive, write_archive, Manifest, MANIFEST_PATH};
use cawide_host::profile::collect::collect_profile;
use cawide_host::profile::credentials::{codex_keychain_account, NoSecretStore, SecretStore};
use cawide_host::profile::login_policy::{sanitize_codex_auth, sanitize_opencode_legacy_auth};
use cawide_host::profile::portability::{is_macos_only_command, rewrite_home};
use cawide_host::profile::spec::SourceEnv;

fn fixture_home(dir: &Path) -> SourceEnv {
    let home = dir.to_path_buf();
    let home_str = home.to_string_lossy().to_string();

    // 1. Claude
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    let settings_json = serde_json::json!({
        "env": {
            "CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-fixture",
            "FOO": "bar"
        },
        "hooks": {
            "Stop": [
                {
                    "hooks": [
                        { "type": "command", "command": "/x/cawide hook claude --event Stop" }
                    ]
                }
            ],
            "PreToolUse": [
                {
                    "hooks": [
                        { "type": "command", "command": format!("{home_str}/.claude/hooks/guard.sh") }
                    ]
                }
            ]
        }
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_vec_pretty(&settings_json).unwrap(),
    )
    .unwrap();

    let cred_file = claude_dir.join(".credentials.json");
    fs::write(&cred_file, "{\"claudeAiOauth\":{\"refreshToken\":\"r\"}}").unwrap();
    set_perm(&cred_file, 0o600);

    let commands_dir = claude_dir.join("commands");
    fs::create_dir_all(&commands_dir).unwrap();
    fs::write(commands_dir.join("review.md"), "# Review command").unwrap();

    let hooks_dir = claude_dir.join("hooks");
    fs::create_dir_all(&hooks_dir).unwrap();
    let guard_sh = hooks_dir.join("guard.sh");
    fs::write(&guard_sh, "#!/bin/sh\nexit 0\n").unwrap();
    set_perm(&guard_sh, 0o755);

    // Symlinked skill
    let shared_skill_dir = home.join(".agents/skills/linked");
    fs::create_dir_all(&shared_skill_dir).unwrap();
    fs::write(shared_skill_dir.join("SKILL.md"), "# Shared skill").unwrap();
    // Cycle symlink
    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink("..", shared_skill_dir.join("loop"));

    let claude_skills_dir = claude_dir.join("skills");
    fs::create_dir_all(&claude_skills_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&shared_skill_dir, claude_skills_dir.join("linked")).unwrap();

    // Excluded directory in Claude
    let projects_dir = claude_dir.join("projects/p");
    fs::create_dir_all(&projects_dir).unwrap();
    fs::write(projects_dir.join("s.jsonl"), "{\"history\":true}").unwrap();

    // .claude.json in home
    let claude_json = serde_json::json!({
        "numStartups": 9,
        "theme": "light",
        "mcpServers": {
            "xcode": {
                "command": "xcrun",
                "args": ["mcpbridge"]
            },
            "ctx": {
                "command": "/opt/homebrew/bin/npx",
                "args": [format!("{home_str}/tools")]
            }
        }
    });
    fs::write(
        home.join(".claude.json"),
        serde_json::to_vec_pretty(&claude_json).unwrap(),
    )
    .unwrap();

    // 2. Codex
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    let codex_toml = format!(
        "model = \"gpt-x\"\nnotify = [\"/x/cawide\", \"hook\", \"codex\"]\n\n[projects.\"{home_str}/repo\"]\ntrust_level = \"trusted\"\n"
    );
    fs::write(codex_dir.join("config.toml"), codex_toml).unwrap();

    let codex_auth_json = serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": "sk-minted",
        "tokens": {
            "access_token": "a",
            "refresh_token": "r",
            "id_token": "i",
            "account_id": "x"
        },
        "last_refresh": "2026-11-01T00:00:00Z"
    });
    fs::write(
        codex_dir.join("auth.json"),
        serde_json::to_vec_pretty(&codex_auth_json).unwrap(),
    )
    .unwrap();
    set_perm(&codex_dir.join("auth.json"), 0o600);

    let codex_secrets_dir = codex_dir.join("secrets");
    fs::create_dir_all(&codex_secrets_dir).unwrap();
    fs::write(codex_secrets_dir.join("codex_auth.age"), "age-bytes").unwrap();

    let codex_sessions = codex_dir.join("sessions/2026");
    fs::create_dir_all(&codex_sessions).unwrap();
    fs::write(codex_sessions.join("a.jsonl"), "{\"sess\":1}").unwrap();

    // 3. OMP
    let omp_agent_dir = home.join(".omp/agent");
    fs::create_dir_all(&omp_agent_dir).unwrap();
    fs::write(omp_agent_dir.join("config.yml"), "telemetry: true\n").unwrap();
    fs::write(
        omp_agent_dir.join(".env"),
        "ANTHROPIC_API_KEY=sk-test\nexport ANTHROPIC_OAUTH_TOKEN=sk-ant-oat01-y\n",
    )
    .unwrap();
    set_perm(&omp_agent_dir.join(".env"), 0o600);

    let ext_dir = omp_agent_dir.join("extensions");
    fs::create_dir_all(&ext_dir).unwrap();
    fs::write(
        ext_dir.join("cawide.js"),
        "// cawide-telemetry v1\nmodule.exports = {};\n",
    )
    .unwrap();

    let omp_skills_dir = omp_agent_dir.join("skills");
    fs::create_dir_all(&omp_skills_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&shared_skill_dir, omp_skills_dir.join("linked")).unwrap();

    // OMP agent.db
    let db_path = omp_agent_dir.join("agent.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE auth_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            data TEXT NOT NULL,
            disabled_cause TEXT,
            identity_key TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        INSERT INTO auth_credentials (provider, credential_type, data, disabled_cause, created_at, updated_at)
        VALUES ('anthropic', 'api_key', '{"key":"sk-1"}', NULL, 1000, 1000),
               ('openai', 'api_key', '{"key":"sk-2"}', NULL, 1000, 1000),
               ('openai-codex', 'oauth', '{"access":"a","refresh":"r"}', NULL, 1000, 1000),
               ('anthropic', 'oauth', '{"refresh":"r2"}', NULL, 1000, 1000),
               ('google-gemini-cli', 'oauth', '{"refresh":"r3"}', 'invalid_grant', 1000, 1000),
               ('minimax', 'api_key', '{"key":"sk-ant-oat01-db"}', NULL, 1000, 1000);
        CREATE TABLE model_usage (
            id INTEGER PRIMARY KEY,
            tokens INTEGER NOT NULL
        );
        INSERT INTO model_usage VALUES (1, 500);
        "#,
    )
    .unwrap();
    drop(conn);

    fs::write(omp_agent_dir.join("history.db"), "fake history db").unwrap();

    // 4. OpenCode
    let opencode_cfg_dir = home.join(".config/opencode");
    fs::create_dir_all(&opencode_cfg_dir).unwrap();
    let opencode_json = serde_json::json!({
        "provider": {
            "anthropic": {
                "options": {
                    "apiKey": "sk-ant-oat01-pasted"
                }
            }
        },
        "mcp": {
            "osa": {
                "type": "local",
                "command": ["osascript", "x"]
            }
        }
    });
    fs::write(
        opencode_cfg_dir.join("opencode.json"),
        serde_json::to_vec_pretty(&opencode_json).unwrap(),
    )
    .unwrap();

    let nm = opencode_cfg_dir.join("node_modules");
    fs::create_dir_all(&nm).unwrap();
    fs::write(nm.join("a.js"), "console.log(1);").unwrap();

    let opencode_data_dir = home.join(".local/share/opencode");
    fs::create_dir_all(&opencode_data_dir).unwrap();

    let legacy_auth = serde_json::json!({
        "groq": {"type": "api", "key": "g"},
        "github-copilot": {"type": "oauth", "refresh": "r", "access": "a", "expires": 0}
    });
    fs::write(
        opencode_data_dir.join("auth.json"),
        serde_json::to_vec_pretty(&legacy_auth).unwrap(),
    )
    .unwrap();

    let mcp_auth = serde_json::json!({
        "srv": {"tokens": {}}
    });
    fs::write(
        opencode_data_dir.join("mcp-auth.json"),
        serde_json::to_vec_pretty(&mcp_auth).unwrap(),
    )
    .unwrap();

    let opencode_db_path = opencode_data_dir.join("opencode.db");
    let opencode_conn = Connection::open(&opencode_db_path).unwrap();
    opencode_conn
        .execute_batch(
            r#"
        CREATE TABLE credential (
            id TEXT PRIMARY KEY,
            integration_id TEXT,
            label TEXT NOT NULL,
            value TEXT NOT NULL,
            connector_id TEXT,
            method_id TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            time_created INTEGER NOT NULL,
            time_updated INTEGER NOT NULL
        );
        INSERT INTO credential (id, integration_id, label, value, connector_id, method_id, active, time_created, time_updated)
        VALUES ('A', 'anthropic', 'Anthropic API', '{"type":"key","key":"sk-ant-1"}', NULL, NULL, 1, 1000, 1000),
               ('O', 'openai', 'OpenAI OAuth', '{"type":"oauth","methodID":"chatgpt-token-sharing","access":"a","refresh":"r","expires":1}', NULL, NULL, 1, 1000, 1000),
               ('X', 'claude-agent', 'Claude External', '{"type":"external","methodID":"claude-login"}', NULL, NULL, 1, 1000, 1000),
               ('K', 'anthropic-sub', 'Sub Key', '{"type":"key","key":"sk-ant-oat01-db"}', NULL, NULL, 1, 1000, 1000);

        CREATE TABLE __drizzle_migrations (
            id INTEGER PRIMARY KEY,
            hash TEXT NOT NULL
        );
        INSERT INTO __drizzle_migrations VALUES (1, 'm1');

        CREATE TABLE session (
            id TEXT PRIMARY KEY,
            title TEXT
        );
        INSERT INTO session VALUES ('sess1', 'Chat 1');
        "#,
        )
        .unwrap();
    drop(opencode_conn);

    SourceEnv {
        home,
        claude_config_dir: None,
        codex_home: None,
        omp_agent_dir: None,
        xdg_config_home: None,
        xdg_data_home: None,
        source_os: Some("macos".to_string()),
    }
}

fn fixture_exe(tmp: &Path) -> PathBuf {
    let bin_dir = tmp.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let exe = bin_dir.join("cawide");
    fs::write(&exe, "#!/bin/sh\nexit 0\n").unwrap();
    set_perm(&exe, 0o755);
    exe
}

#[test]
fn test_1_collect_inventory() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp.path());
    let exe = fixture_exe(tmp.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();
    assert_eq!(
        collected.manifest.agents,
        vec!["claude", "codex", "omp", "opencode"]
    );

    let parsed = read_archive(&collected.archive).unwrap();
    let paths: Vec<&str> = parsed.files.iter().map(|f| f.path.as_str()).collect();

    assert!(paths.contains(&".claude/settings.json"));
    assert!(paths.contains(&".claude/commands/review.md"));
    assert!(paths.contains(&".claude/skills/linked/SKILL.md"));
    assert!(paths.contains(&".codex/config.toml"));
    assert!(!paths.contains(&".codex/auth.json"));
    assert!(!paths.contains(&".claude/.credentials.json"));
    assert!(!paths.iter().any(|p| p.starts_with(".codex/secrets/")));
    assert!(!paths.contains(&".local/share/opencode/mcp-auth.json"));
    assert!(paths.contains(&".local/share/opencode/auth.json"));
    assert!(paths.contains(&".omp/agent/skills/linked/SKILL.md"));
    assert!(paths.contains(&".agents/skills/linked/SKILL.md"));
    assert!(paths.contains(&"__cawide__/claude-json.json"));
    assert!(paths.contains(&"__cawide__/db/omp-agent.db"));
    assert!(paths.contains(&"__cawide__/db/opencode.db"));

    // Excluded patterns
    for p in &paths {
        assert!(!p.contains("projects/"), "contained projects: {p}");
        assert!(!p.contains("sessions/"), "contained sessions: {p}");
        assert!(!p.contains("node_modules"), "contained node_modules: {p}");
        assert!(!p.ends_with("history.db"), "contained history.db: {p}");
        assert!(!p.ends_with("cawide.js"), "contained cawide.js: {p}");
    }

    // .local/share/opencode/auth.json is a JSON object with exactly the key groq
    let oc_auth_file = parsed
        .files
        .iter()
        .find(|f| f.path == ".local/share/opencode/auth.json")
        .unwrap();
    let oc_auth_val: serde_json::Value = serde_json::from_slice(&oc_auth_file.data).unwrap();
    let oc_auth_obj = oc_auth_val.as_object().unwrap();
    let mut oc_keys: Vec<String> = oc_auth_obj.keys().cloned().collect();
    oc_keys.sort();
    assert_eq!(oc_keys, vec!["groq"]);

    // Stripped settings.json has no " hook claude", user hook remains, env is {"FOO":"bar"}
    let settings_file = parsed
        .files
        .iter()
        .find(|f| f.path == ".claude/settings.json")
        .unwrap();
    let settings_val: serde_json::Value = serde_json::from_slice(&settings_file.data).unwrap();
    assert_eq!(settings_val["env"], serde_json::json!({"FOO": "bar"}));
    let settings_str = std::str::from_utf8(&settings_file.data).unwrap();
    assert!(!settings_str.contains(" hook claude"));
    assert!(settings_str.contains("guard.sh"));

    // Archived .omp/agent/.env is exactly ANTHROPIC_API_KEY=sk-test\n
    let omp_env_file = parsed
        .files
        .iter()
        .find(|f| f.path == ".omp/agent/.env")
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&omp_env_file.data).unwrap(),
        "ANTHROPIC_API_KEY=sk-test\n"
    );

    // Archived .config/opencode/opencode.json does not contain sk-ant-o and notice present
    let oc_json_file = parsed
        .files
        .iter()
        .find(|f| f.path == ".config/opencode/opencode.json")
        .unwrap();
    let oc_json_str = std::str::from_utf8(&oc_json_file.data).unwrap();
    assert!(!oc_json_str.contains("sk-ant-o"));
    assert!(collected.manifest.notices.contains(
        &"removed Claude sign-in token(s) from .config/opencode/opencode.json; sign in on the cloud machine instead".to_string()
    ));

    // Codex config has no notify, has cli_auth_credentials_store = "file"
    let codex_file = parsed
        .files
        .iter()
        .find(|f| f.path == ".codex/config.toml")
        .unwrap();
    let codex_str = std::str::from_utf8(&codex_file.data).unwrap();
    assert!(!codex_str.contains("notify ="));
    assert!(codex_str.contains("cli_auth_credentials_store = \"file\""));

    // Fragment has only mcpServers and theme
    let frag_file = parsed
        .files
        .iter()
        .find(|f| f.path == "__cawide__/claude-json.json")
        .unwrap();
    let frag_json: serde_json::Value = serde_json::from_slice(&frag_file.data).unwrap();
    let frag_map = frag_json.as_object().unwrap();
    assert!(frag_map.contains_key("mcpServers"));
    assert!(frag_map.contains_key("theme"));
    assert!(!frag_map.contains_key("numStartups"));

    // collected.logins_to_redo
    assert_eq!(
        collected.logins_to_redo,
        vec![
            "Claude Code: run `claude`, then /login (or set ANTHROPIC_API_KEY)".to_string(),
            "Codex: run `codex login --device-auth` (turn on device code sign-in in ChatGPT Settings → Security first)".to_string(),
            "OMP (minimax, openai-codex): run `omp`, then /login".to_string(),
            "OpenCode (anthropic-sub, claude-agent, github-copilot, openai): run `opencode auth login`, or sign in again when OpenCode asks".to_string(),
            "OpenCode MCP servers: sign in again when OpenCode asks".to_string(),
            "Sign-in token variables not copied (ANTHROPIC_OAUTH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN): sign in on the cloud machine instead".to_string(),
        ]
    );
}

#[test]
fn test_2_deterministic_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp.path());
    let exe = fixture_exe(tmp.path());

    let c1 = collect_profile(&env, &NoSecretStore, &exe).unwrap();
    let c2 = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    assert_eq!(c1.archive, c2.archive);
}

#[test]
fn test_3_secret_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp.path());
    let exe = fixture_exe(tmp.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();
    let parsed = read_archive(&collected.archive).unwrap();

    let file_mode = |p: &str| -> u32 {
        parsed
            .files
            .iter()
            .find(|f| f.path == p)
            .map(|f| f.mode)
            .unwrap_or(0)
    };

    assert_eq!(file_mode(".local/share/opencode/auth.json"), 0o600);
    assert_eq!(file_mode(".omp/agent/.env"), 0o600);
    assert_eq!(file_mode("__cawide__/claude-json.json"), 0o600);
    assert_eq!(file_mode("__cawide__/db/omp-agent.db"), 0o600);
    assert_eq!(file_mode("__cawide__/db/opencode.db"), 0o600);
    assert_eq!(file_mode(".claude/hooks/guard.sh"), 0o755);
}

#[test]
fn test_4_db_snapshot_filtering() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp.path());
    let exe = fixture_exe(tmp.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();
    let parsed = read_archive(&collected.archive).unwrap();

    // OMP DB
    let omp_file = parsed
        .files
        .iter()
        .find(|f| f.path == "__cawide__/db/omp-agent.db")
        .unwrap();
    let tmp_omp = tmp.path().join("omp-snap.db");
    fs::write(&tmp_omp, &omp_file.data).unwrap();
    let omp_conn = Connection::open(&tmp_omp).unwrap();

    let auth_count: i64 = omp_conn
        .query_row("SELECT COUNT(*) FROM auth_credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(auth_count, 2);

    let model_usage_count: i64 = omp_conn
        .query_row("SELECT COUNT(*) FROM model_usage", [], |r| r.get(0))
        .unwrap_or(0);
    assert_eq!(model_usage_count, 0);
    drop(omp_conn);

    // OpenCode DB
    let opencode_file = parsed
        .files
        .iter()
        .find(|f| f.path == "__cawide__/db/opencode.db")
        .unwrap();
    let tmp_opencode = tmp.path().join("opencode-snap.db");
    fs::write(&tmp_opencode, &opencode_file.data).unwrap();
    let opencode_conn = Connection::open(&tmp_opencode).unwrap();

    let cred_count: i64 = opencode_conn
        .query_row("SELECT COUNT(*) FROM credential", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cred_count, 1);

    let id: String = opencode_conn
        .query_row("SELECT id FROM credential", [], |r| r.get(0))
        .unwrap();
    assert_eq!(id, "A");

    let migration_count: i64 = opencode_conn
        .query_row("SELECT COUNT(*) FROM __drizzle_migrations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(migration_count, 1);

    let session_count: i64 = opencode_conn
        .query_row("SELECT COUNT(*) FROM session", [], |r| r.get(0))
        .unwrap_or(0);
    assert_eq!(session_count, 0);
}

#[test]
fn test_5_apply_roundtrip_linux_target() {
    let tmp_bin = tempfile::tempdir().unwrap();
    let exe = fixture_exe(tmp_bin.path());
    let tmp_src = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp_src.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");
    let pre_claude_json = serde_json::json!({
        "numStartups": 3,
        "userID": "u123",
    });
    fs::write(
        target_home.join(".claude.json"),
        serde_json::to_vec_pretty(&pre_claude_json).unwrap(),
    )
    .unwrap();

    let report =
        apply_profile(target_home, &cfg, &collected.archive, TargetOs::Linux, &exe).unwrap();

    let src_home_str = tmp_src.path().to_string_lossy();
    let dst_home_str = target_home.to_string_lossy();

    // Codex config: home rewritten
    let codex_conf = fs::read_to_string(target_home.join(".codex/config.toml")).unwrap();
    assert!(!codex_conf.contains(src_home_str.as_ref()));
    assert!(codex_conf.contains(&format!("[projects.\"{dst_home_str}/repo\"]")));

    // .claude.json
    let new_claude_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(target_home.join(".claude.json")).unwrap())
            .unwrap();
    assert_eq!(new_claude_json["numStartups"], 3);
    assert_eq!(new_claude_json["userID"], "u123");
    assert_eq!(new_claude_json["theme"], "light");
    assert!(new_claude_json.get("hasCompletedOnboarding").is_none());

    let mcps = new_claude_json["mcpServers"].as_object().unwrap();
    assert!(
        !mcps.contains_key("xcode"),
        "xcode server must be stripped on Linux"
    );
    assert_eq!(mcps["ctx"]["command"], "npx");
    assert_eq!(
        mcps["ctx"]["args"],
        serde_json::json!([format!("{dst_home_str}/tools")])
    );

    // OpenCode: osa stripped
    let opencode_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(target_home.join(".config/opencode/opencode.json")).unwrap(),
    )
    .unwrap();
    assert!(
        opencode_json["mcp"].get("osa").is_none(),
        "osa must be removed on Linux"
    );

    // Cawide hooks re-installed
    let settings_str = fs::read_to_string(target_home.join(".claude/settings.json")).unwrap();
    assert!(settings_str.contains(" hook claude"));
    assert!(target_home
        .join(".omp/agent/extensions/cawide.js")
        .is_file());

    assert!(report.notices.iter().any(|n| n.contains("xcode")));
}

#[test]
fn test_6_claude_login_never_synced() {
    let tmp_src = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp_src.path());
    let exe = fixture_exe(tmp_src.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");

    apply_profile(target_home, &cfg, &collected.archive, TargetOs::Linux, &exe).unwrap();

    assert!(!target_home.join(".claude/.credentials.json").exists());

    let new_claude_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(target_home.join(".claude.json")).unwrap())
            .unwrap();
    assert!(new_claude_json.get("hasCompletedOnboarding").is_none());

    let target_settings: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(target_home.join(".claude/settings.json")).unwrap(),
    )
    .unwrap();
    if let Some(env_obj) = target_settings.get("env").and_then(|e| e.as_object()) {
        assert!(!env_obj.contains_key("CLAUDE_CODE_OAUTH_TOKEN"));
    }
}

#[test]
fn test_7_apply_macos_target() {
    let tmp_src = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp_src.path());
    let exe = fixture_exe(tmp_src.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");

    apply_profile(target_home, &cfg, &collected.archive, TargetOs::Macos, &exe).unwrap();

    let new_claude_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(target_home.join(".claude.json")).unwrap())
            .unwrap();
    let mcps = new_claude_json["mcpServers"].as_object().unwrap();
    assert!(mcps.contains_key("xcode"), "xcode kept on macOS");
    assert_eq!(mcps["ctx"]["command"], "/opt/homebrew/bin/npx");
}

#[test]
fn test_8_db_merge_into_existing_target() {
    let tmp_src = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp_src.path());
    let exe = fixture_exe(tmp_src.path());

    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");

    // Pre-create target agent.db with anthropic (old data), xai, and anthropic oauth container
    let target_omp_dir = target_home.join(".omp/agent");
    fs::create_dir_all(&target_omp_dir).unwrap();
    let target_omp_db = target_omp_dir.join("agent.db");
    let conn = Connection::open(&target_omp_db).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE auth_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            data TEXT NOT NULL,
            disabled_cause TEXT,
            identity_key TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        INSERT INTO auth_credentials (provider, credential_type, data, created_at, updated_at)
        VALUES ('anthropic', 'api_key', '{"key":"old-anthropic"}', 500, 500),
               ('xai', 'api_key', '{"key":"xai-val"}', 500, 500),
               ('anthropic', 'oauth', '{"refresh":"container"}', 500, 500);
        "#,
    )
    .unwrap();
    drop(conn);

    // Pre-create target opencode.db with B (anthropic old), C (anthropic oauth container), and Z (github)
    let target_opencode_dir = target_home.join(".local/share/opencode");
    fs::create_dir_all(&target_opencode_dir).unwrap();
    let target_opencode_db = target_opencode_dir.join("opencode.db");
    let oconn = Connection::open(&target_opencode_db).unwrap();
    oconn
        .execute_batch(
            r#"
        CREATE TABLE credential (
            id TEXT PRIMARY KEY,
            integration_id TEXT,
            label TEXT NOT NULL,
            value TEXT NOT NULL,
            connector_id TEXT,
            method_id TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            time_created INTEGER NOT NULL,
            time_updated INTEGER NOT NULL
        );
        INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated)
        VALUES ('B', 'anthropic', 'Old', '{"type":"key","key":"old"}', 0, 500, 500),
               ('C', 'anthropic', 'Container', '{"type":"oauth","access":"a","refresh":"container","expires":1}', 1, 500, 500),
               ('Z', 'github', 'GH', '{"type":"key","key":"gh"}', 1, 500, 500);
        "#,
        )
        .unwrap();
    drop(oconn);

    apply_profile(target_home, &cfg, &collected.archive, TargetOs::Linux, &exe).unwrap();

    // Verify OMP DB: anthropic has snapshot data, openai added, xai kept, container oauth row survives
    let omp_conn = Connection::open(&target_omp_db).unwrap();
    let anthropic_data: String = omp_conn
        .query_row(
            "SELECT data FROM auth_credentials WHERE provider = 'anthropic' AND credential_type = 'api_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(anthropic_data, "{\"key\":\"sk-1\"}");

    let providers: Vec<String> = omp_conn
        .prepare("SELECT provider FROM auth_credentials ORDER BY provider")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(providers, vec!["anthropic", "anthropic", "openai", "xai"]);

    let container_oauth: i64 = omp_conn
        .query_row(
            "SELECT COUNT(*) FROM auth_credentials WHERE provider = 'anthropic' AND credential_type = 'oauth' AND data = '{\"refresh\":\"container\"}'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(container_oauth, 1);
    drop(omp_conn);

    // Verify OpenCode DB: B gone, A exists with active = 0, C exists with active = 1, Z is kept
    let opencode_conn = Connection::open(&target_opencode_db).unwrap();
    let rows: Vec<(String, i64)> = opencode_conn
        .prepare("SELECT id, active FROM credential ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        rows,
        vec![
            ("A".to_string(), 0),
            ("C".to_string(), 1),
            ("Z".to_string(), 1)
        ]
    );
}

#[test]
fn test_9_unsafe_archives() {
    let tmp = tempfile::tempdir().unwrap();
    let target_home = tmp.path();
    let cfg = target_home.join(".config/cawide");
    let exe = fixture_exe(tmp.path());

    let make_archive = |bad_name: &str, is_symlink: bool, format_ver: u32| -> Vec<u8> {
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(enc);

        let manifest = Manifest {
            format_version: format_ver,
            source_os: "macos".to_string(),
            source_home: "/Users/test".to_string(),
            source_host: "host".to_string(),
            agents: vec!["claude".to_string()],
            notices: Vec::new(),
        };
        let m_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let mut m_hdr = tar::Header::new_gnu();
        m_hdr.set_size(m_bytes.len() as u64);
        m_hdr.set_mode(0o600);
        m_hdr.set_entry_type(tar::EntryType::Regular);
        m_hdr.set_cksum();
        builder
            .append_data(&mut m_hdr, MANIFEST_PATH, m_bytes.as_slice())
            .unwrap();

        if !bad_name.is_empty() {
            let mut bad_hdr = tar::Header::new_gnu();
            bad_hdr.set_size(5);
            bad_hdr.set_mode(0o644);
            if is_symlink {
                bad_hdr.set_entry_type(tar::EntryType::Symlink);
            } else {
                bad_hdr.set_entry_type(tar::EntryType::Regular);
            }

            // Write raw bytes directly into header to bypass set_path validation
            let name_bytes = bad_name.as_bytes();
            bad_hdr.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
            bad_hdr.set_cksum();

            builder.append(&bad_hdr, b"hello".as_slice()).unwrap();
        }

        builder.into_inner().unwrap().finish().unwrap()
    };

    // 1. ../evil
    let a1 = make_archive("../evil", false, 1);
    assert!(apply_profile(target_home, &cfg, &a1, TargetOs::Linux, &exe).is_err());

    // 2. /abs
    let a2 = make_archive("/abs", false, 1);
    assert!(apply_profile(target_home, &cfg, &a2, TargetOs::Linux, &exe).is_err());

    // 3. .config/cawide/authorized_keys
    let a3 = make_archive(".config/cawide/authorized_keys", false, 1);
    assert!(apply_profile(target_home, &cfg, &a3, TargetOs::Linux, &exe).is_err());

    // 4. symlink entry
    let a4 = make_archive(".claude/link", true, 1);
    assert!(apply_profile(target_home, &cfg, &a4, TargetOs::Linux, &exe).is_err());

    // 5. format_version: 2
    let a5 = make_archive("", false, 2);
    assert!(apply_profile(target_home, &cfg, &a5, TargetOs::Linux, &exe).is_err());
}

#[test]
fn test_10_symlinked_ancestor() {
    let tmp = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let target_home = tmp.path();
    let cfg = target_home.join(".config/cawide");
    let exe = fixture_exe(tmp.path());

    // Symlink .claude to outside_dir
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside_dir.path(), target_home.join(".claude")).unwrap();

    let tmp_src = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp_src.path());
    let collected = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    let report =
        apply_profile(target_home, &cfg, &collected.archive, TargetOs::Linux, &exe).unwrap();

    // Outside dir must stay empty
    let entries_count = fs::read_dir(outside_dir.path()).unwrap().count();
    assert_eq!(entries_count, 0, "outside dir must remain empty");

    assert!(report
        .notices
        .iter()
        .any(|n| n.contains("refusing to write through symlink")));
    assert!(report
        .notices
        .iter()
        .any(|n| n.contains("skipped Cawide hooks for claude")));
}

#[test]
fn test_11_stale_cleanup() {
    let tmp_src = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp_src.path());
    let exe = fixture_exe(tmp_src.path());

    // Archive A: has old.md
    fs::write(env.home.join(".claude/commands/old.md"), "old").unwrap();
    let collected_a = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    // Archive B: without old.md
    fs::remove_file(env.home.join(".claude/commands/old.md")).unwrap();
    let collected_b = collect_profile(&env, &NoSecretStore, &exe).unwrap();

    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");

    // Apply A
    apply_profile(
        target_home,
        &cfg,
        &collected_a.archive,
        TargetOs::Linux,
        &exe,
    )
    .unwrap();
    assert!(target_home.join(".claude/commands/old.md").is_file());

    // Create user file mine.md (never in archive)
    fs::write(target_home.join(".claude/commands/mine.md"), "mine").unwrap();

    // Apply B
    apply_profile(
        target_home,
        &cfg,
        &collected_b.archive,
        TargetOs::Linux,
        &exe,
    )
    .unwrap();
    assert!(
        !target_home.join(".claude/commands/old.md").exists(),
        "old.md must be deleted"
    );
    assert!(
        target_home.join(".claude/commands/mine.md").is_file(),
        "mine.md must be kept"
    );
}

#[test]
fn test_12_portability_unit_cases() {
    assert_eq!(
        rewrite_home("/Users/al/path", "/Users/al", "/home/dev"),
        "/home/dev/path"
    );
    assert_eq!(
        rewrite_home("\"/Users/al\"", "/Users/al", "/home/dev"),
        "\"/home/dev\""
    );
    assert_eq!(
        rewrite_home("/Users/alice/path", "/Users/al", "/home/dev"),
        "/Users/alice/path"
    );

    assert!(is_macos_only_command("/usr/bin/xcrun mcpbridge"));
    assert!(!is_macos_only_command("npx"));
}

#[test]
fn test_13_keychain_naming() {
    let codex_account = codex_keychain_account(Path::new("/tmp/codex"));
    assert!(codex_account.starts_with("cli|"));
    assert_eq!(codex_account.len(), 4 + 16);
}

struct StubSecretStore;
impl SecretStore for StubSecretStore {
    fn read_generic_password(
        &self,
        service: &str,
        _account: &str,
    ) -> anyhow::Result<Option<String>> {
        if service == "Codex Auth" {
            Ok(Some(
                "{\"auth_mode\":\"apikey\",\"OPENAI_API_KEY\":\"sk-k\",\"tokens\":null}"
                    .to_string(),
            ))
        } else if service == "Claude Code-credentials" {
            Ok(Some("{\"claudeAiOauth\":{}}".to_string()))
        } else {
            Ok(None)
        }
    }
}

#[test]
fn test_14_keychain_lookup_codex_api_key_only() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fixture_home(tmp.path());
    let exe = fixture_exe(tmp.path());

    fs::remove_file(env.home.join(".codex/auth.json")).unwrap();

    let collected = collect_profile(&env, &StubSecretStore, &exe).unwrap();
    let parsed = read_archive(&collected.archive).unwrap();

    let codex_file = parsed
        .files
        .iter()
        .find(|f| f.path == ".codex/auth.json")
        .unwrap();
    assert_eq!(codex_file.mode, 0o600);
    let codex_val: serde_json::Value = serde_json::from_slice(&codex_file.data).unwrap();
    assert_eq!(
        codex_val,
        serde_json::json!({
            "auth_mode": "apikey",
            "OPENAI_API_KEY": "sk-k"
        })
    );

    assert!(collected
        .credentials
        .contains(&"Codex API key (macOS Keychain)".to_string()));

    assert!(!parsed
        .files
        .iter()
        .any(|f| f.path == ".claude/.credentials.json"));

    assert!(!collected
        .logins_to_redo
        .iter()
        .any(|l| l.starts_with("Codex:")));
}

#[test]
fn test_15_account_file() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path();

    let acc = Account {
        user_id: "u1".to_string(),
        email: "u1@example.com".to_string(),
        access_token: "tok-acc".to_string(),
        refresh_token: "tok-ref".to_string(),
    };

    account::save(cfg, &acc).unwrap();
    let loaded = account::load(cfg).unwrap().unwrap();
    assert_eq!(acc, loaded);

    let _p = account::account_path(cfg);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&_p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn test_16_apply_ignores_tokens_in_old_archive() {
    let tmp_src = tempfile::tempdir().unwrap();
    let staging = tmp_src.path().join("staging");
    fs::create_dir_all(&staging).unwrap();

    let claude_dir = staging.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join(".credentials.json"),
        "{\"claudeAiOauth\":{}}",
    )
    .unwrap();

    let codex_dir = staging.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    let codex_auth_json = serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": "sk-minted",
        "tokens": {
            "access_token": "a",
            "refresh_token": "r",
            "id_token": "i",
            "account_id": "x"
        },
        "last_refresh": "2026-11-01T00:00:00Z"
    });
    fs::write(
        codex_dir.join("auth.json"),
        serde_json::to_string(&codex_auth_json).unwrap(),
    )
    .unwrap();

    let codex_secrets = codex_dir.join("secrets");
    fs::create_dir_all(&codex_secrets).unwrap();
    fs::write(codex_secrets.join("codex_auth.age"), "age-bytes").unwrap();

    let opencode_data = staging.join(".local/share/opencode");
    fs::create_dir_all(&opencode_data).unwrap();
    fs::write(opencode_data.join("mcp-auth.json"), "{\"srv\":{}}").unwrap();

    let omp_agent = staging.join(".omp/agent");
    fs::create_dir_all(&omp_agent).unwrap();
    fs::write(
        omp_agent.join(".env"),
        "DEEPSEEK_API_KEY=k\nANTHROPIC_OAUTH_TOKEN=sk-ant-oat01-old\n",
    )
    .unwrap();

    let opencode_cfg = staging.join(".config/opencode");
    fs::create_dir_all(&opencode_cfg).unwrap();
    fs::write(
        opencode_cfg.join("opencode.json"),
        "{\"provider\":{\"anthropic\":{\"options\":{\"apiKey\":\"sk-ant-oat01-old\"}}}}",
    )
    .unwrap();

    let db_dir = staging.join("__cawide__/db");
    fs::create_dir_all(&db_dir).unwrap();
    let omp_snap = db_dir.join("omp-agent.db");
    let conn = Connection::open(&omp_snap).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE auth_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            data TEXT NOT NULL,
            disabled_cause TEXT,
            identity_key TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        INSERT INTO auth_credentials (provider, credential_type, data, created_at, updated_at)
        VALUES ('deepseek', 'api_key', '{"key":"k"}', 1000, 1000),
               ('minimax', 'api_key', '{"key":"sk-ant-oat01-OLD"}', 1000, 1000),
               ('oauth-prov', 'oauth', '{"refresh":"OLD-RT"}', 1000, 1000);
        "#,
    )
    .unwrap();
    drop(conn);

    let manifest = Manifest {
        format_version: 1,
        source_os: "linux".to_string(),
        source_home: "/home/test".to_string(),
        source_host: "test-host".to_string(),
        agents: vec![
            "claude".to_string(),
            "codex".to_string(),
            "omp".to_string(),
            "opencode".to_string(),
        ],
        notices: Vec::new(),
    };

    let archive = write_archive(&staging, &manifest).unwrap();

    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");
    let exe = fixture_exe(tmp_dst.path());

    let report = apply_profile(target_home, &cfg, &archive, TargetOs::Linux, &exe).unwrap();

    assert!(!target_home.join(".claude/.credentials.json").exists());
    assert!(!target_home.join(".codex/auth.json").exists());
    assert!(!target_home.join(".codex/secrets/codex_auth.age").exists());
    assert!(!target_home
        .join(".local/share/opencode/mcp-auth.json")
        .exists());

    let notices_with_tokens = report
        .notices
        .iter()
        .filter(|n| n.contains("sign-in tokens are never installed"))
        .count();
    assert_eq!(notices_with_tokens, 4);

    assert!(report
        .notices
        .iter()
        .any(|n| n == "removed sign-in token variables from .omp/agent/.env"));

    assert!(report
        .notices
        .iter()
        .any(|n| n == "removed Claude sign-in token(s) from .config/opencode/opencode.json; sign in on the cloud machine instead"));

    let omp_env = fs::read_to_string(target_home.join(".omp/agent/.env")).unwrap();
    assert_eq!(omp_env, "DEEPSEEK_API_KEY=k\n");

    let oc_json = fs::read_to_string(target_home.join(".config/opencode/opencode.json")).unwrap();
    assert!(!oc_json.contains("sk-ant-o"));

    let target_omp_db = target_home.join(".omp/agent/agent.db");
    let conn = Connection::open(&target_omp_db).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM auth_credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let prov: String = conn
        .query_row("SELECT provider FROM auth_credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(prov, "deepseek");
    drop(conn);

    let raw_bytes = fs::read(&target_omp_db).unwrap();
    assert!(!raw_bytes.windows(6).any(|w| w == b"OLD-RT"));
    assert!(!raw_bytes.windows(15).any(|w| w == b"sk-ant-oat01-OLD"));
}

#[test]
fn test_17_login_policy_units() {
    assert_eq!(sanitize_codex_auth(r#"{"OPENAI_API_KEY":"  "}"#), None);
    assert_eq!(
        sanitize_codex_auth(
            r#"{"auth_mode":"chatgpt","OPENAI_API_KEY":"sk","tokens":{"refresh_token":"r"}}"#
        ),
        None
    );
    assert_eq!(
        sanitize_codex_auth(r#"{"OPENAI_API_KEY":"sk","tokens":{"refresh_token":"r"}}"#),
        None
    );

    let res = sanitize_codex_auth(r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk"}"#);
    assert!(res.is_some());
    let parsed: serde_json::Value = serde_json::from_str(&res.unwrap()).unwrap();
    assert_eq!(
        parsed,
        serde_json::json!({
            "auth_mode": "apikey",
            "OPENAI_API_KEY": "sk"
        })
    );

    assert_eq!(sanitize_codex_auth("not json"), None);

    let legacy_mixed = r#"{
        "gh": {"type": "oauth", "refresh": "r"},
        "wk": {"type": "wellknown", "token": "t"},
        "k": {"type": "api", "key": "k"}
    }"#;
    let res = sanitize_opencode_legacy_auth(legacy_mixed);
    assert!(res.is_some());
    let parsed: serde_json::Value = serde_json::from_str(&res.unwrap()).unwrap();
    let obj = parsed.as_object().unwrap();
    assert!(obj.contains_key("wk"));
    assert!(obj.contains_key("k"));
    assert!(!obj.contains_key("gh"));

    let legacy_oauth_only = r#"{"gh": {"type": "oauth", "refresh": "r"}}"#;
    assert_eq!(sanitize_opencode_legacy_auth(legacy_oauth_only), None);
}

#[test]
fn test_18_apply_keeps_container_logins() {
    let tmp_dst = tempfile::tempdir().unwrap();
    let target_home = tmp_dst.path();
    let cfg = target_home.join(".config/cawide");
    let exe = fixture_exe(tmp_dst.path());

    // 1. Codex
    let codex_dir = target_home.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    let chatgpt_json = serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": "sk-minted",
        "tokens": {
            "access_token": "a",
            "refresh_token": "r",
            "id_token": "i",
            "account_id": "x"
        },
        "last_refresh": "2026-11-01T00:00:00Z"
    });
    let chatgpt_bytes = serde_json::to_vec_pretty(&chatgpt_json).unwrap();
    fs::write(codex_dir.join("auth.json"), &chatgpt_bytes).unwrap();

    let tmp_src = tempfile::tempdir().unwrap();
    let staging = tmp_src.path().join("staging");
    fs::create_dir_all(staging.join(".codex")).unwrap();
    let apikey_json = serde_json::json!({
        "auth_mode": "apikey",
        "OPENAI_API_KEY": "sk-k"
    });
    fs::write(
        staging.join(".codex/auth.json"),
        serde_json::to_vec_pretty(&apikey_json).unwrap(),
    )
    .unwrap();

    let manifest = Manifest {
        format_version: 1,
        source_os: "linux".to_string(),
        source_home: "/home/test".to_string(),
        source_host: "test-host".to_string(),
        agents: vec!["codex".to_string()],
        notices: Vec::new(),
    };
    let archive = write_archive(&staging, &manifest).unwrap();

    let report = apply_profile(target_home, &cfg, &archive, TargetOs::Linux, &exe).unwrap();
    assert_eq!(
        fs::read(codex_dir.join("auth.json")).unwrap(),
        chatgpt_bytes
    );
    assert!(report
        .notices
        .iter()
        .any(|n| n == "kept the sign-in already on this machine in .codex/auth.json"));

    // 2. OpenCode legacy
    let opencode_dir = target_home.join(".local/share/opencode");
    fs::create_dir_all(&opencode_dir).unwrap();
    let oc_target_json = serde_json::json!({
        "github-copilot": {"type": "oauth", "refresh": "r", "access": "a", "expires": 0},
        "groq": {"type": "api", "key": "old"}
    });
    fs::write(
        opencode_dir.join("auth.json"),
        serde_json::to_vec_pretty(&oc_target_json).unwrap(),
    )
    .unwrap();

    let tmp_src2 = tempfile::tempdir().unwrap();
    let staging2 = tmp_src2.path().join("staging2");
    fs::create_dir_all(staging2.join(".local/share/opencode")).unwrap();
    let oc_archive_json = serde_json::json!({
        "groq": {"type": "api", "key": "g"},
        "github-copilot": {"type": "api", "key": "gh-key"}
    });
    fs::write(
        staging2.join(".local/share/opencode/auth.json"),
        serde_json::to_vec_pretty(&oc_archive_json).unwrap(),
    )
    .unwrap();

    let manifest2 = Manifest {
        format_version: 1,
        source_os: "linux".to_string(),
        source_home: "/home/test".to_string(),
        source_host: "test-host".to_string(),
        agents: vec!["opencode".to_string()],
        notices: Vec::new(),
    };
    let archive2 = write_archive(&staging2, &manifest2).unwrap();
    apply_profile(target_home, &cfg, &archive2, TargetOs::Linux, &exe).unwrap();

    let merged_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(opencode_dir.join("auth.json")).unwrap()).unwrap();
    let merged_obj = merged_val.as_object().unwrap();
    let mut keys: Vec<String> = merged_obj.keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, vec!["github-copilot", "groq"]);
    assert_eq!(merged_obj["groq"]["key"], "g");
    assert_eq!(merged_obj["github-copilot"]["type"], "oauth");

    // 3. Stale cleanup
    let tmp_dst3 = tempfile::tempdir().unwrap();
    let target_home3 = tmp_dst3.path();
    let cfg3 = target_home3.join(".config/cawide");

    // Apply archive A with apikey auth.json
    apply_profile(target_home3, &cfg3, &archive, TargetOs::Linux, &exe).unwrap();
    assert!(target_home3.join(".codex/auth.json").is_file());

    // Overwrite with ChatGPT fixture JSON
    fs::write(target_home3.join(".codex/auth.json"), &chatgpt_bytes).unwrap();

    // Apply archive B without .codex/auth.json
    let tmp_src3 = tempfile::tempdir().unwrap();
    let staging3 = tmp_src3.path().join("staging3");
    fs::create_dir_all(staging3.join(".codex")).unwrap();
    fs::write(staging3.join(".codex/config.toml"), "model = \"gpt-4\"").unwrap();
    let manifest3 = Manifest {
        format_version: 1,
        source_os: "linux".to_string(),
        source_home: "/home/test".to_string(),
        source_host: "test-host".to_string(),
        agents: vec!["codex".to_string()],
        notices: Vec::new(),
    };
    let archive3 = write_archive(&staging3, &manifest3).unwrap();
    apply_profile(target_home3, &cfg3, &archive3, TargetOs::Linux, &exe).unwrap();

    assert!(target_home3.join(".codex/auth.json").is_file());
    assert_eq!(
        fs::read(target_home3.join(".codex/auth.json")).unwrap(),
        chatgpt_bytes
    );
}
