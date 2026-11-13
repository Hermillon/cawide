use std::sync::LazyLock;

use regex::Regex;

pub const CLAUDE_CREDENTIALS_PATH: &str = ".claude/.credentials.json";
pub const CLAUDE_SETTINGS_PATH: &str = ".claude/settings.json";
pub const CODEX_AUTH_PATH: &str = ".codex/auth.json";
pub const CODEX_SECRETS_PREFIX: &str = ".codex/secrets/";
pub const OMP_AGENT_ENV_PATH: &str = ".omp/agent/.env";
pub const OMP_ROOT_ENV_PATH: &str = ".omp/.env";
pub const OPENCODE_LEGACY_AUTH_PATH: &str = ".local/share/opencode/auth.json";
pub const OPENCODE_MCP_AUTH_PATH: &str = ".local/share/opencode/mcp-auth.json";
pub const OAUTH_ENV_NAMES: [&str; 4] = [
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_SCOPES",
    "ANTHROPIC_OAUTH_TOKEN",
];
const CLAUDE_OAUTH_TOKEN_PREFIX: &str = "sk-ant-oat";
const CLAUDE_OAUTH_REFRESH_PREFIX: &str = "sk-ant-ort";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFileVerdict {
    Unchanged,
    Rewritten(Vec<u8>),
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExistingLoginVerdict {
    Write(Vec<u8>),
    KeepExisting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialDb {
    Omp,
    OpenCode,
}

impl CredentialDb {
    pub fn table(self) -> &'static str {
        match self {
            CredentialDb::Omp => "auth_credentials",
            CredentialDb::OpenCode => "credential",
        }
    }
}

pub struct RetainReport {
    pub kept: i64,
    pub dropped_logins: Vec<String>,
}

pub fn filter_secret_file(archive_path: &str, data: &[u8]) -> SecretFileVerdict {
    if archive_path == CLAUDE_CREDENTIALS_PATH
        || archive_path == OPENCODE_MCP_AUTH_PATH
        || archive_path.starts_with(CODEX_SECRETS_PREFIX)
    {
        return SecretFileVerdict::Dropped;
    }

    if archive_path == CODEX_AUTH_PATH {
        if let Ok(s) = std::str::from_utf8(data) {
            if let Some(sanitized) = sanitize_codex_auth(s) {
                return SecretFileVerdict::Rewritten(sanitized.into_bytes());
            }
        }
        return SecretFileVerdict::Dropped;
    }

    if archive_path == OPENCODE_LEGACY_AUTH_PATH {
        if let Ok(s) = std::str::from_utf8(data) {
            if let Some(sanitized) = sanitize_opencode_legacy_auth(s) {
                return SecretFileVerdict::Rewritten(sanitized.into_bytes());
            }
        }
        return SecretFileVerdict::Dropped;
    }

    if archive_path == CLAUDE_SETTINGS_PATH
        || archive_path == OMP_AGENT_ENV_PATH
        || archive_path == OMP_ROOT_ENV_PATH
    {
        if let Ok(s) = std::str::from_utf8(data) {
            if let Some((rewritten, _)) = strip_oauth_env(archive_path, s) {
                return SecretFileVerdict::Rewritten(rewritten.into_bytes());
            }
        }
        return SecretFileVerdict::Unchanged;
    }

    SecretFileVerdict::Unchanged
}

pub fn sanitize_codex_auth(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = val.as_object()?;
    let key_val = obj.get("OPENAI_API_KEY")?.as_str()?;
    if key_val.trim().is_empty() {
        return None;
    }
    match obj.get("auth_mode") {
        None => {}
        Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(s)) if s == "apikey" => {}
        _ => return None,
    }
    for field in &["tokens", "agent_identity", "personal_access_token"] {
        match obj.get(*field) {
            None | Some(serde_json::Value::Null) => {}
            _ => return None,
        }
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "auth_mode": "apikey",
        "OPENAI_API_KEY": key_val,
    }))
    .ok()
}

pub fn sanitize_opencode_legacy_auth(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = val.as_object()?;
    let mut kept = serde_json::Map::new();
    for (k, v) in obj {
        if let Some(entry_obj) = v.as_object() {
            if let Some(t) = entry_obj.get("type").and_then(|t| t.as_str()) {
                if t == "api" || t == "wellknown" {
                    kept.insert(k.clone(), v.clone());
                }
            }
        }
    }
    if kept.is_empty() {
        None
    } else {
        serde_json::to_string_pretty(&serde_json::Value::Object(kept)).ok()
    }
}

pub fn opencode_legacy_oauth_ids(json: &str) -> Vec<String> {
    let val: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let obj = match val.as_object() {
        Some(o) => o,
        None => return Vec::new(),
    };
    let mut dropped = Vec::new();
    for (k, v) in obj {
        let is_kept = if let Some(entry_obj) = v.as_object() {
            if let Some(t) = entry_obj.get("type").and_then(|t| t.as_str()) {
                t == "api" || t == "wellknown"
            } else {
                false
            }
        } else {
            false
        };
        if !is_kept {
            dropped.push(k.clone());
        }
    }
    dropped.sort();
    dropped
}

fn is_oauth_var(name: &str, raw_val: &str) -> bool {
    if OAUTH_ENV_NAMES.contains(&name) {
        return true;
    }
    let trimmed = raw_val.trim();
    let unquoted = if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    unquoted.starts_with(CLAUDE_OAUTH_TOKEN_PREFIX)
        || unquoted.starts_with(CLAUDE_OAUTH_REFRESH_PREFIX)
}

pub fn strip_oauth_env(archive_path: &str, text: &str) -> Option<(String, Vec<String>)> {
    if archive_path == CLAUDE_SETTINGS_PATH {
        let mut val: serde_json::Value = serde_json::from_str(text).ok()?;
        let obj = val.as_object_mut()?;
        let env_val = obj.get_mut("env")?;
        let env_obj = env_val.as_object_mut()?;
        let mut removed = Vec::new();
        let keys: Vec<String> = env_obj.keys().cloned().collect();
        for k in keys {
            let should_remove = match env_obj.get(&k) {
                Some(serde_json::Value::String(s)) => is_oauth_var(&k, s),
                Some(_) => OAUTH_ENV_NAMES.contains(&k.as_str()),
                None => false,
            };
            if should_remove {
                env_obj.remove(&k);
                removed.push(k);
            }
        }
        if removed.is_empty() {
            return None;
        }
        removed.sort();
        removed.dedup();
        let res = serde_json::to_string_pretty(&val).ok()?;
        Some((res, removed))
    } else if archive_path == OMP_AGENT_ENV_PATH || archive_path == OMP_ROOT_ENV_PATH {
        let has_trailing_newline = text.ends_with('\n');
        let trimmed_text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        let lines: Vec<&str> = if trimmed_text.is_empty() {
            Vec::new()
        } else {
            trimmed_text.split('\n').collect()
        };
        let mut kept_lines = Vec::new();
        let mut removed = Vec::new();
        for line in lines {
            if line.trim_start().starts_with('#') || !line.contains('=') {
                kept_lines.push(line);
            } else if let Some((raw_key, val_part)) = line.split_once('=') {
                let trimmed_start = raw_key.trim_start();
                let key = trimmed_start
                    .strip_prefix("export ")
                    .unwrap_or(trimmed_start)
                    .trim();
                if is_oauth_var(key, val_part) {
                    removed.push(key.to_string());
                } else {
                    kept_lines.push(line);
                }
            } else {
                kept_lines.push(line);
            }
        }
        if removed.is_empty() {
            return None;
        }
        removed.sort();
        removed.dedup();
        let mut res = kept_lines.join("\n");
        if has_trailing_newline && (!kept_lines.is_empty() || text == "\n" || text == "\r\n") {
            res.push('\n');
        }
        Some((res, removed))
    } else {
        None
    }
}

pub fn reconcile_with_existing(
    archive_path: &str,
    synced: Vec<u8>,
    existing: Option<&[u8]>,
) -> ExistingLoginVerdict {
    if archive_path == CODEX_AUTH_PATH {
        if let Some(bytes) = existing {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(bytes) {
                if let Some(obj) = val.as_object() {
                    let has_tokens = obj.get("tokens").is_some_and(|v| !v.is_null());
                    let has_identity = obj.get("agent_identity").is_some_and(|v| !v.is_null());
                    let has_pat = obj
                        .get("personal_access_token")
                        .is_some_and(|v| !v.is_null());
                    let other_mode = match obj.get("auth_mode") {
                        Some(serde_json::Value::String(s)) => s != "apikey",
                        _ => false,
                    };
                    if has_tokens || has_identity || has_pat || other_mode {
                        return ExistingLoginVerdict::KeepExisting;
                    }
                }
            }
        }
        ExistingLoginVerdict::Write(synced)
    } else if archive_path == OPENCODE_LEGACY_AUTH_PATH {
        match existing {
            None => ExistingLoginVerdict::Write(synced),
            Some(bytes) => {
                if let Ok(serde_json::Value::Object(mut existing_map)) =
                    serde_json::from_slice::<serde_json::Value>(bytes)
                {
                    if let Ok(serde_json::Value::Object(synced_map)) =
                        serde_json::from_slice::<serde_json::Value>(&synced)
                    {
                        for (k, v) in synced_map {
                            let keep_existing = match existing_map.get(&k) {
                                Some(serde_json::Value::Object(obj)) => {
                                    match obj.get("type").and_then(|t| t.as_str()) {
                                        Some("api" | "wellknown") => false,
                                        Some(_) => true,
                                        None => false,
                                    }
                                }
                                _ => false,
                            };
                            if !keep_existing {
                                existing_map.insert(k, v);
                            }
                        }
                        if let Ok(s) =
                            serde_json::to_string_pretty(&serde_json::Value::Object(existing_map))
                        {
                            return ExistingLoginVerdict::Write(s.into_bytes());
                        }
                    }
                    ExistingLoginVerdict::Write(synced)
                } else {
                    ExistingLoginVerdict::KeepExisting
                }
            }
        }
    } else {
        ExistingLoginVerdict::Write(synced)
    }
}

pub fn is_login_store(archive_path: &str) -> bool {
    archive_path == CODEX_AUTH_PATH || archive_path == OPENCODE_LEGACY_AUTH_PATH
}

static CLAUDE_OAUTH_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    // SAFETY: statically verified regular expression pattern.
    match Regex::new(r"sk-ant-o[ar]t[A-Za-z0-9_-]*") {
        Ok(re) => re,
        Err(_) => unreachable!("statically verified regular expression pattern"),
    }
});

pub fn redact_claude_oauth_tokens(text: &str) -> Option<(String, usize)> {
    let count = CLAUDE_OAUTH_TOKEN_RE.find_iter(text).count();
    if count == 0 {
        None
    } else {
        let replaced = CLAUDE_OAUTH_TOKEN_RE.replace_all(text, "").into_owned();
        Some((replaced, count))
    }
}

pub fn retain_api_key_rows(
    conn: &rusqlite::Connection,
    db: CredentialDb,
) -> anyhow::Result<RetainReport> {
    match db {
        CredentialDb::Omp => {
            let query_dropped = r#"
                SELECT DISTINCT provider FROM auth_credentials o
                WHERE o.disabled_cause IS NULL
                  AND NOT (o.credential_type = 'api_key' AND o.disabled_cause IS NULL AND instr(o.data, 'sk-ant-oat') = 0 AND instr(o.data, 'sk-ant-ort') = 0)
                  AND NOT EXISTS (
                    SELECT 1 FROM auth_credentials k
                    WHERE k.provider = o.provider
                      AND k.credential_type = 'api_key' AND k.disabled_cause IS NULL AND instr(k.data, 'sk-ant-oat') = 0 AND instr(k.data, 'sk-ant-ort') = 0
                  )
                ORDER BY provider
            "#;
            let mut stmt = conn.prepare(query_dropped)?;
            let dropped_logins: Vec<String> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<String>, _>>()?;

            conn.execute(
                r#"
                DELETE FROM auth_credentials
                WHERE NOT (credential_type = 'api_key' AND disabled_cause IS NULL AND instr(data, 'sk-ant-oat') = 0 AND instr(data, 'sk-ant-ort') = 0)
                "#,
                [],
            )?;

            let kept: i64 = conn.query_row("SELECT COUNT(*) FROM auth_credentials", [], |row| {
                row.get(0)
            })?;

            Ok(RetainReport {
                kept,
                dropped_logins,
            })
        }
        CredentialDb::OpenCode => {
            let drop_predicate = "CASE WHEN json_valid(value) THEN COALESCE(json_extract(value, '$.type'), '') != 'key' OR instr(value, 'sk-ant-oat') > 0 OR instr(value, 'sk-ant-ort') > 0 ELSE 1 END";
            let query_dropped = format!(
                "SELECT DISTINCT integration_id FROM credential WHERE integration_id IS NOT NULL AND ({drop_predicate}) ORDER BY integration_id"
            );
            let mut stmt = conn.prepare(&query_dropped)?;
            let dropped_logins: Vec<String> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<String>, _>>()?;

            let delete_sql = format!("DELETE FROM credential WHERE {drop_predicate}");
            conn.execute(&delete_sql, [])?;

            let kept: i64 =
                conn.query_row("SELECT COUNT(*) FROM credential", [], |row| row.get(0))?;

            Ok(RetainReport {
                kept,
                dropped_logins,
            })
        }
    }
}
