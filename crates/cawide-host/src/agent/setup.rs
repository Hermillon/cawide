//! Agent integration setup (Brick 7).

use std::path::{Path, PathBuf};

use anyhow::Context;
use toml_edit::{DocumentMut, Item};

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

/// Best-effort cleanup of legacy Cawide hooks, notify entries, OpenCode plugins,
/// and `.cawide-bak` backups for Codex and OpenCode. Never fails; logs warnings.
pub fn remove_legacy_codex_opencode(home: &Path) -> Vec<String> {
    let mut actions = Vec::new();

    // 1. Clean ~/.codex/hooks.json
    let hooks_path = home.join(".codex/hooks.json");
    let mut removed_cawide_hooks = false;
    let mut user_hooks_remain = false;

    if hooks_path.exists() {
        match std::fs::read_to_string(&hooks_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(mut root) => {
                    if let Some(root_obj) = root.as_object_mut() {
                        if let Some(hooks_obj) =
                            root_obj.get_mut("hooks").and_then(|v| v.as_object_mut())
                        {
                            let mut empty_events = Vec::new();
                            for (event, val) in hooks_obj.iter_mut() {
                                let Some(groups) = val.as_array_mut() else {
                                    user_hooks_remain = true;
                                    continue;
                                };
                                let orig_len = groups.len();
                                groups.retain(|g| !is_our_hook_group(g, "codex"));
                                if groups.len() != orig_len {
                                    removed_cawide_hooks = true;
                                }
                                if groups.is_empty() {
                                    empty_events.push(event.clone());
                                } else {
                                    user_hooks_remain = true;
                                }
                            }
                            for event in empty_events {
                                hooks_obj.remove(&event);
                            }
                            if hooks_obj.is_empty() {
                                root_obj.remove("hooks");
                            }
                        }
                        if removed_cawide_hooks {
                            if root_obj.is_empty() {
                                match std::fs::remove_file(&hooks_path) {
                                    Ok(()) => actions
                                        .push(format!("Removed legacy {}", hooks_path.display())),
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(e) => tracing::warn!(
                                        "Failed to remove {}: {e}",
                                        hooks_path.display()
                                    ),
                                }
                            } else {
                                match serde_json::to_string_pretty(&root) {
                                    Ok(mut formatted) => {
                                        formatted.push('\n');
                                        match atomic_write(&hooks_path, formatted.as_bytes()) {
                                            Ok(()) => actions.push(format!(
                                                "Cleaned legacy cawide hooks from {}",
                                                hooks_path.display()
                                            )),
                                            Err(e) => tracing::warn!(
                                                "Failed to write {}: {e}",
                                                hooks_path.display()
                                            ),
                                        }
                                    }
                                    Err(e) => tracing::warn!(
                                        "Failed to serialize {}: {e}",
                                        hooks_path.display()
                                    ),
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Skipping invalid JSON in {}: {e}", hooks_path.display());
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Failed to read {}: {e}", hooks_path.display()),
        }
    }

    // 2. Clean ~/.codex/config.toml
    let config_path = home.join(".codex/config.toml");
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match content.parse::<DocumentMut>() {
                Ok(mut doc) => {
                    let mut removed_notify = false;
                    let mut changed = false;
                    if doc.get("notify").is_some_and(is_our_codex_notify) {
                        doc.as_table_mut().remove("notify");
                        removed_notify = true;
                        changed = true;
                    }
                    let should_remove_features_hooks =
                        removed_notify || (removed_cawide_hooks && !user_hooks_remain);
                    if should_remove_features_hooks {
                        let hooks_is_true = doc
                            .get("features")
                            .and_then(|f| f.as_table_like())
                            .and_then(|t| t.get("hooks"))
                            .and_then(|v| v.as_bool())
                            == Some(true);
                        if hooks_is_true {
                            let mut features_empty = false;
                            if let Some(tbl) =
                                doc.get_mut("features").and_then(|f| f.as_table_like_mut())
                            {
                                tbl.remove("hooks");
                                features_empty = tbl.is_empty();
                                changed = true;
                            }
                            if features_empty {
                                doc.as_table_mut().remove("features");
                            }
                        }
                    }
                    if changed {
                        match atomic_write(&config_path, doc.to_string().as_bytes()) {
                            Ok(()) => actions.push(format!(
                                "Cleaned legacy cawide entries from {}",
                                config_path.display()
                            )),
                            Err(e) => {
                                tracing::warn!("Failed to write {}: {e}", config_path.display())
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Skipping invalid TOML in {}: {e}", config_path.display());
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Failed to read {}: {e}", config_path.display()),
        }
    }

    // 3. Delete ~/.config/opencode/{plugins,plugin}/cawide.js only if marker matches
    for rel in [
        ".config/opencode/plugins/cawide.js",
        ".config/opencode/plugin/cawide.js",
    ] {
        let path = home.join(rel);
        match std::fs::read_to_string(&path) {
            Ok(content) if content.starts_with(TELEMETRY_MARKER) => {
                match std::fs::remove_file(&path) {
                    Ok(()) => actions.push(format!("Removed legacy {}", path.display())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!("Failed to remove {}: {e}", path.display()),
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Failed to read {}: {e}", path.display()),
        }
    }

    // 4. Delete legacy .cawide-bak files if present
    for rel in [
        ".codex/config.toml.cawide-bak",
        ".codex/hooks.json.cawide-bak",
        ".config/opencode/plugins/cawide.js.cawide-bak",
        ".config/opencode/plugin/cawide.js.cawide-bak",
    ] {
        let path = home.join(rel);
        if std::fs::symlink_metadata(&path).is_ok() {
            match std::fs::remove_file(&path) {
                Ok(()) => actions.push(format!("Removed legacy backup {}", path.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!("Failed to remove {}: {e}", path.display()),
            }
        }
    }

    actions
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
        "codex" | "opencode" => {
            anyhow::bail!("{agent} needs no setup: cawide observes it through its own server")
        }
        "omp" => setup_omp(home, &abs_exe, remove),
        other => anyhow::bail!("unsupported agent: '{other}'; supported agents: claude, omp"),
    }
}

pub fn auto_setup_all(home: &Path, exe: &Path) -> std::io::Result<()> {
    let claude_settings = home.join(".claude/settings.json");
    if claude_settings.exists() {
        if let Err(e) = remove_legacy_claude_hooks(&claude_settings) {
            tracing::warn!("Failed to clean legacy claude hooks: {e}");
        }
    }
    if home.join(".omp/agent").exists() {
        if let Err(e) = run_setup(home, exe, "omp", false) {
            tracing::warn!("Auto-setup for omp failed: {e}");
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

    #[test]
    fn remove_legacy_codex_opencode_cleans_notify_and_hooks_preserving_comments() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let codex_dir = home.join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        let toml = "# user comment\nmodel = \"gpt-5\"\nnotify = [\"/usr/bin/cawide\", \"hook\", \"codex\"]\n\n[features]\nhooks = true\n";
        std::fs::write(codex_dir.join("config.toml"), toml).unwrap();

        let actions = super::remove_legacy_codex_opencode(home);
        assert_eq!(actions.len(), 1);
        let updated = std::fs::read_to_string(codex_dir.join("config.toml")).unwrap();
        assert_eq!(updated, "# user comment\nmodel = \"gpt-5\"\n");
        assert!(super::remove_legacy_codex_opencode(home).is_empty());
    }

    #[test]
    fn remove_legacy_codex_opencode_foreign_notify_and_hooks_json_variants() {
        // (b) foreign notify + cawide-only hooks.json -> features.hooks removed, notify kept, hooks.json deleted
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let codex_dir = home.join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        std::fs::write(
            codex_dir.join("config.toml"),
            "notify = [\"custom\", \"script\"]\n\n[features]\nhooks = true\n",
        )
        .unwrap();
        std::fs::write(
            codex_dir.join("hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "Stop": [{ "hooks": [{ "type": "command", "command": "/tmp/ck-x/bin/cawide hook codex --event Stop" }] }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let actions = super::remove_legacy_codex_opencode(home);
        assert_eq!(actions.len(), 2);
        assert!(!codex_dir.join("hooks.json").exists());
        let toml = std::fs::read_to_string(codex_dir.join("config.toml")).unwrap();
        assert!(toml.contains("custom"));
        assert!(!toml.contains("hooks"));

        // (b2) foreign notify + user hook group -> features.hooks and user group kept
        let tmp2 = tempfile::tempdir().unwrap();
        let home2 = tmp2.path();
        let codex_dir2 = home2.join(".codex");
        std::fs::create_dir_all(&codex_dir2).unwrap();
        std::fs::write(
            codex_dir2.join("config.toml"),
            "notify = [\"custom\"]\n\n[features]\nhooks = true\n",
        )
        .unwrap();
        std::fs::write(
            codex_dir2.join("hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "Stop": [
                        { "hooks": [{ "type": "command", "command": "/tmp/ck-x/bin/cawide hook codex --event Stop" }] },
                        { "hooks": [{ "type": "command", "command": "echo user" }] }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let actions2 = super::remove_legacy_codex_opencode(home2);
        assert_eq!(actions2.len(), 1);
        let hooks2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_dir2.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(hooks2["hooks"]["Stop"].as_array().unwrap().len(), 1);
        assert_eq!(
            hooks2["hooks"]["Stop"][0]["hooks"][0]["command"],
            "echo user"
        );
        let toml2 = std::fs::read_to_string(codex_dir2.join("config.toml")).unwrap();
        assert!(toml2.contains("hooks = true"));
        assert!(super::remove_legacy_codex_opencode(home2).is_empty());
    }

    #[test]
    fn remove_legacy_codex_opencode_plugins_backups_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let plugins_dir = home.join(".config/opencode/plugins");
        let plugin_dir = home.join(".config/opencode/plugin");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();

        // Marker plugin deleted; non-marker stub kept
        std::fs::write(plugins_dir.join("cawide.js"), "// cawide-telemetry v3\n").unwrap();
        std::fs::write(plugin_dir.join("cawide.js"), "export default () => {};\n").unwrap();
        std::fs::write(home.join(".codex/config.toml.cawide-bak"), "bak").unwrap();
        std::fs::write(home.join(".codex/hooks.json.cawide-bak"), "bak").unwrap();
        std::fs::write(plugins_dir.join("cawide.js.cawide-bak"), "bak").unwrap();

        let actions = super::remove_legacy_codex_opencode(home);
        assert_eq!(actions.len(), 4);
        assert!(!plugins_dir.join("cawide.js").exists());
        assert!(plugin_dir.join("cawide.js").exists());
        assert!(!home.join(".codex/config.toml.cawide-bak").exists());
        assert!(!home.join(".codex/hooks.json.cawide-bak").exists());
        assert!(!plugins_dir.join("cawide.js.cawide-bak").exists());
        assert!(super::remove_legacy_codex_opencode(home).is_empty());

        // (e) symlinked .config dir -> marker plugin still deleted
        #[cfg(unix)]
        {
            let tmp_sym = tempfile::tempdir().unwrap();
            let real_cfg = tmp_sym.path().join("dotfiles-config");
            std::fs::create_dir_all(real_cfg.join("opencode/plugins")).unwrap();
            std::fs::write(
                real_cfg.join("opencode/plugins/cawide.js"),
                "// cawide-telemetry v2\n",
            )
            .unwrap();
            let sym_home = tmp_sym.path().join("home");
            std::fs::create_dir_all(&sym_home).unwrap();
            std::os::unix::fs::symlink(&real_cfg, sym_home.join(".config")).unwrap();

            let sym_actions = super::remove_legacy_codex_opencode(&sym_home);
            assert_eq!(sym_actions.len(), 1);
            assert!(!real_cfg.join("opencode/plugins/cawide.js").exists());
        }
    }
}
