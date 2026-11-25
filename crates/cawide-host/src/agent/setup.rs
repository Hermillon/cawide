//! Agent integration setup (Brick 7).

use std::path::{Path, PathBuf};

use anyhow::Context;
use toml_edit::{value, Array, DocumentMut, Item, Table};

const CODEX_EVENTS: &[&str] = &[
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "Stop",
];

const TELEMETRY_MARKER: &str = "// cawide-telemetry";
const TELEMETRY_MARKER_V3: &str = "// cawide-telemetry v3";
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

fn is_legacy_claude_hook_group(group: &serde_json::Value) -> bool {
    let Some(hooks_arr) = group.get("hooks").and_then(|v| v.as_array()) else {
        return false;
    };
    hooks_arr.iter().any(|hook| {
        hook.get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|cmd| cmd.contains(" hook claude --event "))
    })
}

/// Removes legacy `" hook claude --event "` hook groups from `~/.claude/settings.json`
/// without creating a `.cawide-bak` backup. Returns `Ok(true)` only if the file was modified.
pub fn remove_legacy_claude_hooks(settings_path: &Path) -> anyhow::Result<bool> {
    if !settings_path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(settings_path)
        .with_context(|| format!("reading {}", settings_path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("parsing {}: invalid JSON", settings_path.display()))?;
    let Some(root_obj) = root.as_object_mut() else {
        return Ok(false);
    };
    let Some(hooks_obj) = root_obj.get_mut("hooks").and_then(|v| v.as_object_mut()) else {
        return Ok(false);
    };

    let mut modified = false;
    let mut empty_events = Vec::new();
    for (event, val) in hooks_obj.iter_mut() {
        let Some(groups) = val.as_array_mut() else {
            continue;
        };
        let orig_len = groups.len();
        groups.retain(|g| !is_legacy_claude_hook_group(g));
        if groups.len() != orig_len {
            modified = true;
            if groups.is_empty() {
                empty_events.push(event.clone());
            }
        }
    }
    for event in empty_events {
        hooks_obj.remove(&event);
    }
    if modified && hooks_obj.is_empty() {
        root_obj.remove("hooks");
    }
    if !modified {
        return Ok(false);
    }

    let mut formatted = serde_json::to_string_pretty(&root)?;
    formatted.push('\n');
    atomic_write(settings_path, formatted.as_bytes())?;
    Ok(true)
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
        "{TELEMETRY_MARKER_V3}\n\
export default function (pi) {{\n  \
if (!process.env.CAWIDE_SESSION_ID || !process.env.CAWIDE_SOCKET) return;\n  \
const binName = process.platform === \"win32\" ? \"cawide.exe\" : \"cawide\";\n  \
const bin = process.env.CAWIDE_BIN_DIR ? `${{process.env.CAWIDE_BIN_DIR}}/${{binName}}` : {exe_js};\n  \
const clip = (s, n) => {{\n    \
if (typeof s !== \"string\") return undefined;\n    \
const clean = typeof s.toWellFormed === \"function\" ? s.toWellFormed() : s;\n    \
if (clean.length <= n) return clean;\n    \
let end = n;\n    \
const code = clean.charCodeAt(end - 1);\n    \
if (code >= 0xd800 && code <= 0xdbff) end -= 1;\n    \
return clean.slice(0, end);\n  \
}};\n  \
const clipTail = (s, n) => {{\n    \
if (typeof s !== \"string\") return \"\";\n    \
const clean = typeof s.toWellFormed === \"function\" ? s.toWellFormed() : s;\n    \
if (clean.length <= n) return clean;\n    \
let start = clean.length - n;\n    \
const code = clean.charCodeAt(start);\n    \
if (code >= 0xdc00 && code <= 0xdfff) start += 1;\n    \
return clean.slice(start);\n  \
}};\n  \
const pendingTools = new Map();\n  \
let lastCtx = null;\n  \
let currentProc = null;\n  \
let shuttingDown = false;\n  \
let queue = Promise.resolve();\n  \
const readStdout = async (proc, stream) => {{\n    \
if (!stream) return;\n    \
const decoder = new TextDecoder();\n    \
let buf = \"\";\n    \
const handleLine = (line) => {{\n      \
const trimmed = line.trim();\n      \
if (!trimmed) return;\n      \
try {{\n        \
const msg = JSON.parse(trimmed);\n        \
if (msg?.type === \"resolve_plan_review\" && typeof msg.reviewId === \"string\" && typeof msg.choice === \"string\") {{\n          \
lastCtx?.resolvePlanReview?.(msg.reviewId, msg.choice);\n        \
}}\n      \
}} catch {{}}\n    \
}};\n    \
try {{\n      \
if (typeof stream.getReader === \"function\") {{\n        \
const reader = stream.getReader();\n        \
while (true) {{\n          \
const {{ value, done }} = await reader.read();\n          \
if (done) break;\n          \
buf += decoder.decode(value, {{ stream: true }});\n          \
let idx;\n          \
while ((idx = buf.indexOf(\"\\n\")) !== -1) {{\n            \
handleLine(buf.slice(0, idx));\n            \
buf = buf.slice(idx + 1);\n          \
}}\n        \
}}\n      \
}} else {{\n        \
for await (const chunk of stream) {{\n          \
buf += typeof chunk === \"string\" ? chunk : decoder.decode(chunk, {{ stream: true }});\n          \
let idx;\n          \
while ((idx = buf.indexOf(\"\\n\")) !== -1) {{\n            \
handleLine(buf.slice(0, idx));\n            \
buf = buf.slice(idx + 1);\n          \
}}\n        \
}}\n      \
}}\n      \
buf += decoder.decode();\n      \
if (buf) handleLine(buf);\n    \
}} catch {{}}\n  \
}};\n  \
const spawnHook = async () => {{\n    \
const epoch = ((Math.random() * 0xffffffff) >>> 0) ^ (process.pid >>> 0);\n    \
let proc = null;\n    \
if (globalThis.Bun?.spawn) {{\n      \
const child = globalThis.Bun.spawn([bin, \"hook\", \"omp\", \"--stream\"], {{\n        \
stdin: \"pipe\",\n        \
stdout: \"pipe\",\n        \
stderr: \"ignore\",\n      }});\n      \
let exited = false;\n      \
const exitedPromise = child.exited.then(() => {{ exited = true; }}, () => {{ exited = true; }});\n      \
proc = {{\n        \
epoch,\n        \
seq: 0,\n        \
isExited: () => exited,\n        \
exited: exitedPromise,\n        \
writeLine: async (line) => {{\n          \
await child.stdin.write(line);\n          \
await child.stdin.flush?.();\n        \
}},\n        \
endStdin: async () => {{ await child.stdin.end(); }},\n        \
kill: () => {{ try {{ child.kill(); }} catch {{}} }},\n      }};\n      \
readStdout(proc, child.stdout);\n    \
}} else {{\n      \
const {{ spawn }} = await import(\"node:child_process\");\n      \
const child = spawn(bin, [\"hook\", \"omp\", \"--stream\"], {{ stdio: [\"pipe\", \"pipe\", \"ignore\"] }});\n      \
let exited = false;\n      \
const exitedPromise = new Promise((resolve) => {{\n        \
const done = () => {{ exited = true; resolve(); }};\n        \
child.once(\"exit\", done);\n        \
child.once(\"error\", done);\n      }});\n      \
proc = {{\n        \
epoch,\n        \
seq: 0,\n        \
isExited: () => exited,\n        \
exited: exitedPromise,\n        \
writeLine: (line) => new Promise((resolve, reject) => {{\n          \
child.stdin.write(line, (err) => (err ? reject(err) : resolve()));\n        }}),\n        \
endStdin: () => new Promise((resolve) => {{ child.stdin.end(resolve); }}),\n        \
kill: () => {{ try {{ child.kill(); }} catch {{}} }},\n      }};\n      \
readStdout(proc, child.stdout);\n    \
}}\n    \
proc.exited.then(() => {{ if (currentProc === proc) currentProc = null; }});\n    \
return proc;\n  \
}};\n  \
  const enqueue = (event, payload, force = false) => {{\n    \
if (shuttingDown && !force) return;\n    \
queue = queue.then(async () => {{\n      \
try {{\n        \
if (!currentProc || currentProc.isExited()) {{\n          \
currentProc = await spawnHook();\n        \
}}\n        \
const p = currentProc;\n        \
p.seq += 1;\n        \
const line = JSON.stringify({{\n          \
event,\n          \
epoch: p.epoch,\n          \
seq: p.seq,\n          \
ts: Math.floor(Date.now() / 1000),\n          \
payload: payload ?? {{}},\n        }}) + \"\\n\";\n        \
await p.writeLine(line);\n      \
}} catch {{\n        \
if (currentProc) {{\n          \
currentProc.kill();\n          \
currentProc = null;\n        \
}}\n      \
}}\n    \
}});\n  \
}};\n  \
const isMain = (ctx) => {{\n    \
if (ctx?.agent?.kind === \"sub\") return false;\n    \
if (ctx?.hasUI === false) return false;\n    \
lastCtx = ctx;\n    \
return true;\n  \
}};\n  \
pi.on(\"before_agent_start\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
    const prompt = clip(e?.prompt, 2000) ?? \"\";\n    \
enqueue(\"before_agent_start\", {{ prompt }});\n  \
}});\n  \
pi.on(\"agent_start\", (_e, ctx) => {{\n    \
if (isMain(ctx)) enqueue(\"agent_start\", {{}});\n  \
}});\n  \
pi.on(\"tool_call\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
const toolName = e?.toolName;\n    \
const toolCallId = e?.toolCallId;\n    \
const cmd = e?.input?.command || e?.input?.cmd;\n    \
const path = e?.input?.path || e?.input?.file_path;\n    \
    const shortCmd = clip(cmd, 200);\n    \
const shortPath = clip(path, 200);\n    \
if (toolCallId) {{\n      \
if (pendingTools.size >= 128) {{\n        \
const firstKey = pendingTools.keys().next().value;\n        \
if (firstKey !== undefined) pendingTools.delete(firstKey);\n      \
}}\n      \
pendingTools.set(toolCallId, {{ command: shortCmd, path: shortPath }});\n    \
}}\n    \
if (toolName === \"ask\") {{\n      \
const questions = Array.isArray(e?.input?.questions) ? e.input.questions : null;\n      \
const q = questions?.[0] ?? e?.input ?? {{}};\n      \
const questionsLength = questions ? questions.length : (q.question ? 1 : 0);\n      \
enqueue(\"tool_call\", {{\n        \
toolName,\n        \
toolCallId,\n        \
questionsLength,\n        \
question: q.question,\n        \
options: (q.options ?? []).map((o) => (typeof o === \"string\" ? o : (o?.label ?? \"\"))),\n        \
multi: Boolean(q.multi),\n        \
recommended: typeof q.recommended === \"number\" ? q.recommended : undefined,\n      }});\n    \
}} else {{\n      \
enqueue(\"tool_call\", {{\n        \
toolName,\n        \
toolCallId,\n        \
command: shortCmd,\n        \
path: shortPath,\n      }});\n    \
}}\n  \
}});\n  \
pi.on(\"tool_approval_requested\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
const toolCallId = e?.toolCallId;\n    \
const cached = toolCallId ? pendingTools.get(toolCallId) : undefined;\n    \
const cmd = e?.command || e?.input?.command || cached?.command;\n    \
const path = e?.path || e?.input?.path || e?.input?.file_path || cached?.path;\n    \
enqueue(\"tool_approval_requested\", {{\n      \
toolName: e?.toolName || e?.tool,\n      \
toolCallId,\n      \
reason: e?.reason,\n      \
command: clip(cmd, 200),\n      \
path: clip(path, 200),\n    \
}});\n  \
}});\n  \
pi.on(\"tool_approval_resolved\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
enqueue(\"tool_approval_resolved\", {{ approved: e?.approved, toolCallId: e?.toolCallId }});\n  \
}});\n  \
pi.on(\"tool_result\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
if (e?.toolCallId) pendingTools.delete(e.toolCallId);\n    \
enqueue(\"tool_result\", {{\n      \
toolName: e?.toolName,\n      \
toolCallId: e?.toolCallId,\n      \
isError: Boolean(e?.isError),\n    }});\n  \
}});\n  \
pi.on(\"tool_execution_end\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
const toolCallId = e?.toolCallId;\n    \
if (toolCallId && pendingTools.has(toolCallId)) {{\n      \
pendingTools.delete(toolCallId);\n      \
enqueue(\"tool_result\", {{\n        \
toolName: e?.toolName,\n        \
toolCallId,\n        \
isError: Boolean(e?.isError),\n      }});\n    \
}}\n  \
}});\n  \
pi.on(\"plan_review_requested\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
const options = (e?.options ?? [])\n      \
.filter((o) => o && !o.disabled && o.id !== \"refine\" && o.id !== \"save\")\n      \
.map((o) => ({{ id: o.id, label: o.label }}));\n    \
enqueue(\"plan_review_requested\", {{\n      \
reviewId: e?.reviewId,\n      \
title: e?.title,\n      \
options,\n    }});\n  \
}});\n  \
pi.on(\"plan_review_resolved\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
enqueue(\"plan_review_resolved\", {{ reviewId: e?.reviewId, choice: e?.choice }});\n  \
}});\n  \
pi.on(\"agent_end\", (e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
const msgs = Array.isArray(e?.messages) ? e.messages : [];\n    \
let lastAsst = null;\n    \
for (let i = msgs.length - 1; i >= 0; i--) {{\n      \
if (msgs[i]?.role === \"assistant\") {{ lastAsst = msgs[i]; break; }}\n    \
}}\n    \
const stopReason = lastAsst?.stopReason ?? e?.stopReason;\n    \
const errorMessage = lastAsst?.errorMessage ?? e?.errorMessage;\n    \
let fullText = \"\";\n    \
if (typeof lastAsst?.content === \"string\") {{\n      \
fullText = lastAsst.content;\n    \
}} else if (Array.isArray(lastAsst?.content)) {{\n      \
fullText = lastAsst.content\n        \
.filter((b) => b?.type === \"text\" && typeof b.text === \"string\")\n        \
.map((b) => b.text)\n        \
.join(\"\\n\");\n    \
}} else if (typeof e?.summary === \"string\") {{\n      \
fullText = e.summary;\n    \
}}\n    \
    const finalTextHead = clip(fullText, 500) ?? \"\";\n    \
const finalTextTail = clipTail(fullText, 4000);\n    \
enqueue(\"agent_end\", {{\n      \
awaitingAsyncWork: Boolean(e?.awaitingAsyncWork),\n      \
willContinue: Boolean(e?.willContinue),\n      \
stopReason,\n      \
errorMessage,\n      \
finalTextHead,\n      \
finalTextTail,\n    }});\n  \
}});\n  \
  pi.on(\"session_shutdown\", async (_e, ctx) => {{\n    \
if (!isMain(ctx)) return;\n    \
shuttingDown = true;\n    \
enqueue(\"session_shutdown\", {{}}, true);\n    \
await queue.catch(() => {{}});\n    \
const p = currentProc;\n    \
if (!p) return;\n    \
try {{ await p.endStdin(); }} catch {{}}\n    \
await Promise.race([\n      \
p.exited,\n      \
new Promise((resolve) => setTimeout(resolve, 1500)),\n    \
]);\n    \
if (!p.isExited()) p.kill();\n    \
if (currentProc === p) currentProc = null;\n  \
}});\n\
}}\n"
    );

    setup_marker_file(&path, &content, remove, "OMP")
}

fn setup_opencode(home: &Path, abs_exe: &Path, remove: bool) -> anyhow::Result<String> {
    let path = home.join(".config/opencode/plugins/cawide.js");
    let exe_js = serde_json::to_string(&abs_exe.display().to_string())?;
    let content = format!(
        "{TELEMETRY_MARKER_V3}\n\
export default {{\n  \
id: \"cawide\",\n  \
async setup(context) {{\n    \
if (!process.env.CAWIDE_SESSION_ID || !process.env.CAWIDE_SOCKET) return;\n    \
if (!context?.event?.subscribe) return;\n    \
    const binName = process.platform === \"win32\" ? \"cawide.exe\" : \"cawide\";\n    \
const bin = process.env.CAWIDE_BIN_DIR ? `${{process.env.CAWIDE_BIN_DIR}}/${{binName}}` : {exe_js};\n    \
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
directory,\n        }};\n        \
try {{\n          \
spawn([bin, \"hook\", \"opencode\", \"--event\", event.type, JSON.stringify(payload)], {{ stdout: \"ignore\", stderr: \"ignore\" }});\n        \
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
        "claude" => {
            let settings_path = home.join(".claude/settings.json");
            let cleaned = remove_legacy_claude_hooks(&settings_path).unwrap_or(false);
            if cleaned {
                Ok("Claude Code requires no global setup (managed via Cawide launcher). Cleaned legacy hooks from settings.json.".into())
            } else {
                Ok("Claude Code requires no global setup (managed via Cawide launcher).".into())
            }
        }
        "codex" => setup_codex(home, &abs_exe, remove),
        "omp" => setup_omp(home, &abs_exe, remove),
        "opencode" => setup_opencode(home, &abs_exe, remove),
        other => anyhow::bail!(
            "unsupported agent: '{other}'; supported agents: claude, codex, omp, opencode"
        ),
    }
}

pub fn auto_setup_all(home: &Path, exe: &Path) -> std::io::Result<()> {
    let claude_settings = home.join(".claude/settings.json");
    if claude_settings.exists() {
        if let Err(e) = remove_legacy_claude_hooks(&claude_settings) {
            tracing::warn!("Failed to clean legacy claude hooks: {e}");
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

#[cfg(test)]
mod tests {
    use super::remove_legacy_claude_hooks;

    #[test]
    fn remove_legacy_claude_hooks_cleans_legacy_and_preserves_user_hooks() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let settings = tmp.path().join("settings.json");
        let initial = serde_json::json!({
            "theme": "dark",
            "hooks": {
                "SessionStart": [
                    { "hooks": [{ "type": "command", "command": "/usr/local/bin/cawide hook claude --event SessionStart" }] },
                    { "hooks": [{ "type": "command", "command": "echo user-start" }] }
                ],
                "Stop": [
                    { "hooks": [{ "type": "command", "command": "'/opt/cawide' hook claude --event Stop" }] }
                ]
            }
        });
        std::fs::write(&settings, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

        let changed = remove_legacy_claude_hooks(&settings).expect("remove_legacy_claude_hooks");
        assert!(changed);
        assert!(!tmp.path().join("settings.json.cawide-bak").exists());

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings).unwrap()).unwrap();
        assert_eq!(parsed["theme"], "dark");
        let start = parsed["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(start.len(), 1);
        assert_eq!(start[0]["hooks"][0]["command"], "echo user-start");
        assert!(parsed["hooks"].get("Stop").is_none());

        // Removing the remaining legacy-only file drops the empty "hooks" object too.
        let only_legacy = serde_json::json!({
            "theme": "dark",
            "hooks": {
                "PreToolUse": [
                    { "hooks": [{ "type": "command", "command": "cawide hook claude --event PreToolUse" }] }
                ]
            }
        });
        std::fs::write(
            &settings,
            serde_json::to_string_pretty(&only_legacy).unwrap(),
        )
        .unwrap();
        assert!(remove_legacy_claude_hooks(&settings).unwrap());
        let parsed2: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings).unwrap()).unwrap();
        assert_eq!(parsed2, serde_json::json!({ "theme": "dark" }));
    }

    #[test]
    fn remove_legacy_claude_hooks_does_not_rewrite_unchanged_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let settings = tmp.path().join("settings.json");
        let initial = serde_json::json!({
            "theme": "dark",
            "hooks": {
                "SessionStart": [
                    { "hooks": [{ "type": "command", "command": "echo custom" }] }
                ]
            }
        });
        let raw = serde_json::to_string_pretty(&initial).unwrap();
        std::fs::write(&settings, &raw).unwrap();

        #[cfg(unix)]
        let before_ino = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&settings).unwrap().ino()
        };

        let changed = remove_legacy_claude_hooks(&settings).expect("remove_legacy_claude_hooks");
        assert!(!changed);
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), raw);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let after_ino = std::fs::metadata(&settings).unwrap().ino();
            assert_eq!(
                before_ino, after_ino,
                "unchanged file must not be rewritten"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn remove_legacy_claude_hooks_cleans_through_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("dotfiles-claude-settings.json");
        let link = tmp.path().join("settings.json");
        let initial = serde_json::json!({
            "model": "sonnet",
            "hooks": {
                "Stop": [
                    { "hooks": [{ "type": "command", "command": "/usr/bin/cawide hook claude --event Stop" }] }
                ]
            }
        });
        std::fs::write(&target, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let changed = remove_legacy_claude_hooks(&link).expect("remove_legacy_claude_hooks");
        assert!(changed);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "settings.json must remain a symlink"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(parsed, serde_json::json!({ "model": "sonnet" }));
    }
}
