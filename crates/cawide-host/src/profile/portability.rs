use std::path::Path;

pub fn rewrite_home(text: &str, source_home: &str, target_home: &str) -> String {
    if source_home.is_empty() || source_home == target_home {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(pos) = rest.find(source_home) {
        let after_idx = pos + source_home.len();
        let next_char = rest[after_idx..].chars().next();

        let is_boundary = match next_char {
            None => true,
            Some(c) => !c.is_alphanumeric() && c != '.' && c != '_' && c != '-',
        };

        if is_boundary {
            result.push_str(&rest[..pos]);
            result.push_str(target_home);
            rest = &rest[after_idx..];
        } else {
            // Include source_home as-is and continue searching past it
            result.push_str(&rest[..after_idx]);
            rest = &rest[after_idx..];
        }
    }

    result.push_str(rest);
    result
}

pub fn rewrite_homebrew(text: &str) -> String {
    text.replace("/opt/homebrew/bin/", "")
}

pub fn is_macos_only_command(cmd: &str) -> bool {
    let first_token = cmd.split_whitespace().next().unwrap_or("");
    if first_token.starts_with("/Applications/")
        || first_token.starts_with("/System/")
        || first_token.starts_with("/Library/")
    {
        return true;
    }

    let basename = Path::new(first_token)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(first_token);

    matches!(basename, "xcrun" | "osascript")
}

pub fn strip_macos_only_mcp(
    path: &str,
    content: &str,
) -> Option<Result<(String, Vec<String>), String>> {
    let filename = Path::new(path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");

    // 1. Claude fragment or OMP mcp.json
    if path == "__cawide__/claude-json.json" || path == ".omp/agent/mcp.json" {
        let mut val: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => {
                return Some(Err(format!(
                "could not parse {path}; its MCP servers were not checked for macOS-only commands"
            )))
            }
        };

        let mut removed = Vec::new();
        if let Some(servers) = val.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
            let names_to_remove: Vec<String> = servers
                .iter()
                .filter_map(|(name, server_val)| {
                    let cmd = server_val.get("command").and_then(|c| c.as_str())?;
                    if is_macos_only_command(cmd) {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for name in names_to_remove {
                servers.remove(&name);
                removed.push(name);
            }
        }

        if removed.is_empty() {
            return Some(Ok((content.to_string(), Vec::new())));
        }

        let new_content = match serde_json::to_string_pretty(&val) {
            Ok(s) => s,
            Err(_) => return Some(Ok((content.to_string(), Vec::new()))),
        };
        return Some(Ok((new_content, removed)));
    }

    // 2. Codex config.toml and *.config.toml
    if path == ".codex/config.toml"
        || (path.starts_with(".codex/") && filename.ends_with(".config.toml"))
    {
        let mut doc: toml_edit::DocumentMut = match content.parse() {
            Ok(d) => d,
            Err(_) => {
                return Some(Err(format!(
                "could not parse {path}; its MCP servers were not checked for macOS-only commands"
            )))
            }
        };

        let mut removed = Vec::new();
        if let Some(table) = doc
            .get_mut("mcp_servers")
            .and_then(|t| t.as_table_like_mut())
        {
            let names_to_remove: Vec<String> = table
                .iter()
                .filter_map(|(name, item)| {
                    let cmd = item.get("command").and_then(|c| c.as_str())?;
                    if is_macos_only_command(cmd) {
                        Some(name.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            for name in names_to_remove {
                table.remove(&name);
                removed.push(name);
            }
        }

        if removed.is_empty() {
            return Some(Ok((content.to_string(), Vec::new())));
        }

        return Some(Ok((doc.to_string(), removed)));
    }

    // 3. OpenCode config
    if path == ".config/opencode/opencode.json"
        || path == ".config/opencode/opencode.jsonc"
        || path == ".config/opencode/config.json"
    {
        let mut val: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => {
                return Some(Err(format!(
                "could not parse {path}; its MCP servers were not checked for macOS-only commands"
            )))
            }
        };

        let mut removed = Vec::new();
        if let Some(mcp) = val.get_mut("mcp").and_then(|s| s.as_object_mut()) {
            let names_to_remove: Vec<String> = mcp
                .iter()
                .filter_map(|(name, server_val)| {
                    let cmd = server_val
                        .get("command")
                        .and_then(|c| c.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|c| c.as_str())?;
                    if is_macos_only_command(cmd) {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for name in names_to_remove {
                mcp.remove(&name);
                removed.push(name);
            }
        }

        if removed.is_empty() {
            return Some(Ok((content.to_string(), Vec::new())));
        }

        let new_content = match serde_json::to_string_pretty(&val) {
            Ok(s) => s,
            Err(_) => return Some(Ok((content.to_string(), Vec::new()))),
        };
        return Some(Ok((new_content, removed)));
    }

    None
}

pub fn find_macos_only_mcp(path: &str, content: &str) -> Option<Result<Vec<String>, String>> {
    strip_macos_only_mcp(path, content).map(|res| res.map(|(_, names)| names))
}
