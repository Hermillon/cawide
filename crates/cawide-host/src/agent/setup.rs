//! Agent integration setup (Brick 7).

use std::path::{Path, PathBuf};

use anyhow::Context;
use toml_edit::{value, Array, DocumentMut, Item, Table};

const CLAUDE_EVENTS: &[&str] = &[
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "Notification",
    "Stop",
    "SessionEnd",
];

const CODEX_EVENTS: &[&str] = &[
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "Stop",
];

const TELEMETRY_MARKER: &str = "// cawide-telemetry";
const TELEMETRY_MARKER_V2: &str = "// cawide-telemetry v2";
fn backup_file_if_exists(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        let bak = PathBuf::from(format!("{}.cawide-bak", path.display()));
        if !bak.exists() {
            std::fs::copy(path, &bak)
                .with_context(|| format!("creating backup {}", bak.display()))?;
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let target = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    };

    #[cfg(unix)]
    let mode = match std::fs::metadata(&target) {
        Ok(m) => m.permissions().mode() & 0o7777,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0o644,
        Err(e) => {
            return Err(e).with_context(|| format!("reading permissions of {}", target.display()))
        }
    };

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating tempfile in {}", parent.display()))?;
    tmp.write_all(content)
        .with_context(|| format!("writing tempfile for {}", target.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("syncing tempfile for {}", target.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", target.display()))?;
    tmp.persist(&target)
        .map_err(|e| e.error)
        .with_context(|| format!("persisting to {}", target.display()))?;
    Ok(())
}
fn is_our_hook_group(group: &serde_json::Value, agent: &str) -> bool {
    let needle = format!(" hook {agent}");
    if let Some(hooks_arr) = group.get("hooks").and_then(|v| v.as_array()) {
        for hook in hooks_arr {
            if let Some(cmd) = hook.get("command").and_then(|v| v.as_str()) {
                if cmd.contains(&needle) {
                    return true;
                }
            }
        }
    }
    false
}

fn update_json_hooks(
    path: &Path,
    abs_exe: &Path,
    agent: &str,
    events: &[&str],
    remove: bool,
) -> anyhow::Result<()> {
    let mut root: serde_json::Value = if path.exists() {
        backup_file_if_exists(path)?;
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("parsing {}: invalid JSON", path.display()))?;
        if !parsed.is_object() {
            anyhow::bail!("{}: top-level value must be a JSON object", path.display());
        }
        parsed
    } else {
        if remove {
            return Ok(());
        }
        serde_json::json!({})
    };

    if remove {
        let Some(hooks_obj) = root.get_mut("hooks").and_then(|v| v.as_object_mut()) else {
            return Ok(());
        };
        let mut modified = false;
        for event in events {
            if let Some(groups) = hooks_obj.get_mut(*event).and_then(|v| v.as_array_mut()) {
                let orig_len = groups.len();
                groups.retain(|g| !is_our_hook_group(g, agent));
                if groups.len() != orig_len {
                    modified = true;
                }
            }
            if hooks_obj
                .get(*event)
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.is_empty())
            {
                hooks_obj.remove(*event);
                modified = true;
            }
        }
        if hooks_obj.is_empty() {
            if let Some(map) = root.as_object_mut() {
                map.remove("hooks");
                modified = true;
            }
        }
        if !modified {
            return Ok(());
        }
    } else {
        match root.get("hooks") {
            None => {
                if let Some(map) = root.as_object_mut() {
                    map.insert("hooks".into(), serde_json::json!({}));
                }
            }
            Some(v) if v.is_object() => {}
            Some(_) => {
                anyhow::bail!("{}: 'hooks' exists but is not an object", path.display());
            }
        }
        let hooks_obj = root
            .get_mut("hooks")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| anyhow::anyhow!("{}: 'hooks' is not an object", path.display()))?;
        for event in events {
            let cmd = if cfg!(windows) {
                let exe_str = abs_exe.to_string_lossy().replace('"', "\\\"");
                format!("\"{exe_str}\" hook {agent} --event {event}")
            } else {
                let escaped_exe = abs_exe.display().to_string().replace('\'', "'\\''");
                format!("'{escaped_exe}' hook {agent} --event {event}")
            };
            let our_group = serde_json::json!({
                "hooks": [
                    { "type": "command", "command": cmd }
                ]
            });

            match hooks_obj.get(*event) {
                None => {
                    hooks_obj.insert((*event).into(), serde_json::json!([]));
                }
                Some(v) if v.is_array() => {}
                Some(_) => {
                    anyhow::bail!(
                        "{}: 'hooks.{}' exists but is not an array",
                        path.display(),
                        event
                    );
                }
            }
            let groups = hooks_obj
                .get_mut(*event)
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| {
                    anyhow::anyhow!("{}: 'hooks.{}' is not an array", path.display(), event)
                })?;
            let existing_idx = groups.iter().position(|g| is_our_hook_group(g, agent));
            if let Some(idx) = existing_idx {
                groups[idx] = our_group;
            } else {
                groups.push(our_group);
            }
        }
    }

    let mut formatted = serde_json::to_string_pretty(&root)?;
    formatted.push('\n');
    atomic_write(path, formatted.as_bytes())?;
    Ok(())
}

fn setup_claude(home: &Path, abs_exe: &Path, remove: bool) -> anyhow::Result<String> {
    let settings_path = home.join(".claude/settings.json");
    update_json_hooks(&settings_path, abs_exe, "claude", CLAUDE_EVENTS, remove)?;
    if remove {
        Ok("Claude Code hooks removed from settings.json".into())
    } else {
        Ok("Claude Code hooks configured in settings.json".into())
    }
}

fn is_our_codex_notify(item: &Item) -> bool {
    if let Some(arr) = item.as_array() {
        if arr.len() >= 3 {
            let p1 = arr.get(1).and_then(|v| v.as_str());
            let p2 = arr.get(2).and_then(|v| v.as_str());
            return p1 == Some("hook") && p2 == Some("codex");
        }
    }
    false
}

fn setup_codex(home: &Path, abs_exe: &Path, remove: bool) -> anyhow::Result<String> {
    let codex_dir = home.join(".codex");
    let config_path = codex_dir.join("config.toml");
    let hooks_path = codex_dir.join("hooks.json");

    let mut summary = String::new();

    if remove {
        if config_path.exists() {
            backup_file_if_exists(&config_path)?;
            let content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?;
            let mut doc = content.parse::<DocumentMut>()?;
            if doc.get("notify").is_some_and(is_our_codex_notify) {
                doc.as_table_mut().remove("notify");
                summary.push_str("Removed cawide notify from config.toml. ");
                atomic_write(&config_path, doc.to_string().as_bytes())?;
            }
        }
    } else {
        let mut doc = if config_path.exists() {
            backup_file_if_exists(&config_path)?;
            let content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?;
            content.parse::<DocumentMut>()?
        } else {
            DocumentMut::new()
        };

        let features = doc.entry("features").or_insert(Item::Table(Table::new()));
        let tbl = features.as_table_like_mut().ok_or_else(|| {
            anyhow::anyhow!("{}: [features] is not a table", config_path.display())
        })?;
        tbl.insert("hooks", value(true));

        if let Some(item) = doc.get("notify") {
            if is_our_codex_notify(item) {
                let mut arr = Array::new();
                arr.push(abs_exe.display().to_string());
                arr.push("hook");
                arr.push("codex");
                doc["notify"] = Item::Value(toml_edit::Value::Array(arr));
                summary.push_str("Updated cawide notify in config.toml. ");
            } else {
                summary.push_str(&format!(
                    "Keeping existing foreign notify ({item}) in config.toml. "
                ));
            }
        } else {
            let mut arr = Array::new();
            arr.push(abs_exe.display().to_string());
            arr.push("hook");
            arr.push("codex");
            doc["notify"] = Item::Value(toml_edit::Value::Array(arr));
            summary.push_str("Set cawide notify in config.toml. ");
        }

        atomic_write(&config_path, doc.to_string().as_bytes())?;
    }

    update_json_hooks(&hooks_path, abs_exe, "codex", CODEX_EVENTS, remove)?;
    if remove {
        summary.push_str("Codex hooks removed from hooks.json.");
    } else {
        summary.push_str("Codex hooks configured in hooks.json. Codex ignores new or changed hooks until you approve them: run /hooks inside Codex once.");
    }
    Ok(summary)
}

fn setup_marker_file(
    path: &Path,
    content: &str,
    remove: bool,
    agent_name: &str,
) -> anyhow::Result<String> {
    if path.exists() {
        let existing = std::fs::read_to_string(path)?;
        if !existing.starts_with(TELEMETRY_MARKER) {
            anyhow::bail!(
                "refusing to overwrite existing file without '{}' marker: {}",
                TELEMETRY_MARKER,
                path.display()
            );
        }
        if remove {
            std::fs::remove_file(path)?;
            return Ok(format!("{agent_name} telemetry plugin removed"));
        }
        backup_file_if_exists(path)?;
    } else if remove {
        return Ok(format!("{agent_name} telemetry plugin was not present"));
    }

    atomic_write(path, content.as_bytes())?;
    Ok(format!("{agent_name} telemetry plugin installed"))
}
fn setup_omp(home: &Path, abs_exe: &Path, remove: bool) -> anyhow::Result<String> {
    let path = home.join(".omp/agent/extensions/cawide.js");
    let exe_js = serde_json::to_string(&abs_exe.display().to_string())?;
    let content = format!(
        "{TELEMETRY_MARKER_V2}\n\
export default function (pi) {{\n  \
const isMain = (ctx) => {{\n    \
if (ctx?.agent?.kind === \"sub\") return false;\n    \
const id = ctx?.agent?.id || ctx?.session?.id || \"root\";\n    \
if (!globalThis.__cawideOmpOwnership) {{\n      \
globalThis.__cawideOmpOwnership = id;\n    \
}}\n    \
return globalThis.__cawideOmpOwnership === id;\n  \
}};\n  \
const send = (event, payload) => {{\n    \
try {{\n      \
const data = {{ ...(payload ?? {{}}), cwd: process.cwd() }};\n      \
const body = JSON.stringify(data);\n      \
if (globalThis.Bun?.spawn) {{\n        \
globalThis.Bun.spawn([{exe_js}, \"hook\", \"omp\", \"--event\", event, body], {{ stdout: \"ignore\", stderr: \"ignore\" }});\n      \
}} else {{\n        \
import(\"node:child_process\").then(({{ spawn }}) => {{\n          \
const child = spawn({exe_js}, [\"hook\", \"omp\", \"--event\", event, body], {{ stdio: \"ignore\", detached: true }});\n          \
child.unref();\n        \
}}).catch(() => {{}});\n      \
}}\n    \
}} catch {{}}\n  \
}};\n  \
pi.on(\"before_agent_start\", (e, ctx) => {{\n    \
if (isMain(ctx)) send(\"before_agent_start\", {{ prompt: e?.prompt }});\n  \
}});\n  \
pi.on(\"agent_start\", (_e, ctx) => {{\n    \
if (isMain(ctx)) send(\"agent_start\");\n  \
}});\n  \
pi.on(\"tool_call\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
const q = e.toolName === \"ask\" ? (e.input?.questions?.[0] ?? {{}}) : {{}};\n    \
send(\"tool_call\", {{\n      \
toolName: e.toolName,\n      \
question: q.question,\n      \
options: (q.options ?? []).map(o => o.label || o),\n      \
command: e.input?.command || e.input?.cmd,\n      \
path: e.input?.path || e.input?.file_path,\n    \
}});\n  \
}});\n  \
pi.on(\"tool_approval_requested\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
send(\"tool_approval_requested\", {{ reason: e?.reason, tool: e?.toolName || e?.tool }});\n  \
}});\n  \
pi.on(\"tool_approval_resolved\", (_e, ctx) => {{\n    \
if (isMain(ctx)) send(\"tool_approval_resolved\");\n  \
}});\n  \
pi.on(\"tool_result\", (_e, ctx) => {{\n    \
if (isMain(ctx)) send(\"tool_result\");\n  \
}});\n  \
pi.on(\"agent_end\", (e, ctx) => {{\n    \
if (isMain(ctx)) {{\n      \
send(\"agent_end\", {{ willContinue: e?.willContinue, summary: e?.summary }});\n      \
if (!e?.willContinue) {{\n        \
globalThis.__cawideOmpOwnership = null;\n      \
}}\n    \
}}\n  \
}});\n  \
pi.on(\"session_shutdown\", (_e, ctx) => {{\n    \
if (isMain(ctx)) {{\n      \
send(\"session_shutdown\");\n      \
globalThis.__cawideOmpOwnership = null;\n    \
}}\n  \
}});\n\
}}\n"
    );

    setup_marker_file(&path, &content, remove, "OMP")
}

fn setup_opencode(home: &Path, abs_exe: &Path, remove: bool) -> anyhow::Result<String> {
    let path = home.join(".config/opencode/plugins/cawide.js");
    let exe_js = serde_json::to_string(&abs_exe.display().to_string())?;
    let content = format!(
        "{TELEMETRY_MARKER_V2}\n\
export default {{\n  \
id: \"cawide\",\n  \
async setup(context) {{\n    \
if (!context?.event?.subscribe) return;\n    \
let spawn = globalThis.Bun?.spawn;\n    \
if (!spawn) {{\n      \
try {{\n        \
const cp = await import(\"node:child_process\");\n        \
spawn = (args, _opts) => {{\n          \
const child = cp.spawn(args[0], args.slice(1), {{ stdio: \"ignore\", detached: true }});\n          \
child.unref();\n          \
return child;\n        \
}};\n      \
}} catch {{}}\n    \
}}\n    \
if (!spawn) return;\n    \
try {{\n      \
const sub = await context.event.subscribe();\n      \
for await (const event of sub) {{\n        \
if (!event || !event.type) continue;\n        \
const directory = event.location?.directory || process.cwd();\n        \
const payload = {{\n          \
...(event.data ?? event.properties ?? {{}}),\n          \
directory,\n        \
}};\n        \
try {{\n          \
spawn([{exe_js}, \"hook\", \"opencode\", \"--event\", event.type, JSON.stringify(payload)], {{ stdout: \"ignore\", stderr: \"ignore\" }});\n        \
}} catch {{}}\n      \
}}\n    \
}} catch {{}}\n  \
}}\n\
}};\n"
    );

    setup_marker_file(&path, &content, remove, "OpenCode")
}

pub fn run_setup(home: &Path, exe: &Path, agent: &str, remove: bool) -> anyhow::Result<String> {
    let abs_exe = if exe.is_absolute() {
        exe.to_path_buf()
    } else {
        std::env::current_dir()?.join(exe)
    };

    match agent {
        "claude" => setup_claude(home, &abs_exe, remove),
        "codex" => setup_codex(home, &abs_exe, remove),
        "omp" => setup_omp(home, &abs_exe, remove),
        "opencode" => setup_opencode(home, &abs_exe, remove),
        other => anyhow::bail!(
            "unsupported agent: '{other}'; supported agents: claude, codex, omp, opencode"
        ),
    }
}

pub fn auto_setup_all(home: &Path, exe: &Path) -> std::io::Result<()> {
    if home.join(".claude").exists() {
        if let Err(e) = run_setup(home, exe, "claude", false) {
            tracing::warn!("Auto-setup for claude failed: {e}");
        }
    }
    if home.join(".codex").exists() {
        if let Err(e) = run_setup(home, exe, "codex", false) {
            tracing::warn!("Auto-setup for codex failed: {e}");
        }
    }
    if home.join(".omp/agent").exists() {
        if let Err(e) = run_setup(home, exe, "omp", false) {
            tracing::warn!("Auto-setup for omp failed: {e}");
        }
    }
    if home.join(".config/opencode").exists() {
        if let Err(e) = run_setup(home, exe, "opencode", false) {
            tracing::warn!("Auto-setup for opencode failed: {e}");
        }
    }
    Ok(())
}
