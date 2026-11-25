//! Host launcher shims and bin directory management.

use std::path::{Path, PathBuf};

pub const CAWIDE_OPEN_SCRIPT: &str = r#"#!/bin/sh
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x "$BIN_DIR/cawide" ]; then
    exec "$BIN_DIR/cawide" open "$@"
fi
exec cawide open "$@"
"#;

pub const OPEN_SCRIPT: &str = r#"#!/bin/sh
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CAWIDE_BIN="$BIN_DIR/cawide"
[ -x "$CAWIDE_BIN" ] || CAWIDE_BIN="cawide"

is_url() {
    case "$1" in
        http://*|https://*|localhost:*|127.0.0.1:*|0.0.0.0:*|:*) return 0 ;;
        *) return 1 ;;
    esac
}

is_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *)
            if [ ! -e "$1" ] && [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null; then
                return 0
            fi
            return 1
            ;;
    esac
}

has_macos_flag=0
target_url=""
url_count=0
skip_next=0

for arg in "$@"; do
    if [ $skip_next -eq 1 ]; then
        skip_next=0
        continue
    fi
    case "$arg" in
        -a|-b)
            has_macos_flag=1
            skip_next=1
            ;;
        -e|-t|-R|-f|-F)
            has_macos_flag=1
            ;;
        *)
            if is_url "$arg" || is_port "$arg"; then
                target_url="$arg"
                url_count=$((url_count + 1))
            fi
            ;;
    esac
done

# Intercept pure URL launches without macOS app-targeting flags (or on non-Darwin where macOS flags are invalid for xdg-open)
if { [ $has_macos_flag -eq 0 ] || [ "$(uname -s)" != "Darwin" ]; } && [ $url_count -eq 1 ] && [ -n "$target_url" ]; then
    if "$CAWIDE_BIN" open "$target_url"; then
        exit 0
    fi
fi

# Fallback only on Darwin to native /usr/bin/open
if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/open ]; then
    exec /usr/bin/open "$@"
fi

# On non-Darwin (Linux), delegate fallback to real system xdg-open (never openvt)
REAL_XDG_OPEN=""
IFS=':'
for p in $PATH; do
    if [ "$p" != "$BIN_DIR" ] && [ -x "$p/xdg-open" ] && [ ! "$p/xdg-open" -ef "$BIN_DIR/xdg-open" ]; then
        REAL_XDG_OPEN="$p/xdg-open"
        break
    fi
done
unset IFS

if [ -n "$REAL_XDG_OPEN" ]; then
    exec "$REAL_XDG_OPEN" "$@"
fi

echo "cawide open: unable to open target" >&2
exit 1
"#;

pub const XDG_OPEN_SCRIPT: &str = r#"#!/bin/sh
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CAWIDE_BIN="$BIN_DIR/cawide"
[ -x "$CAWIDE_BIN" ] || CAWIDE_BIN="cawide"

is_url() {
    case "$1" in
        http://*|https://*|localhost:*|127.0.0.1:*|0.0.0.0:*|:*) return 0 ;;
        *) return 1 ;;
    esac
}

is_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *)
            if [ ! -e "$1" ] && [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null; then
                return 0
            fi
            return 1
            ;;
    esac
}

target_url=""
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        *)
            if is_url "$arg" || is_port "$arg"; then
                target_url="$arg"
                break
            fi
            ;;
    esac
done

if [ -n "$target_url" ]; then
    if "$CAWIDE_BIN" open "$target_url"; then
        exit 0
    fi
fi

REAL_XDG_OPEN=""
IFS=':'
for p in $PATH; do
    if [ "$p" != "$BIN_DIR" ] && [ -x "$p/xdg-open" ] && [ ! "$p/xdg-open" -ef "$BIN_DIR/xdg-open" ]; then
        REAL_XDG_OPEN="$p/xdg-open"
        break
    fi
done
unset IFS

if [ -n "$REAL_XDG_OPEN" ]; then
    exec "$REAL_XDG_OPEN" "$@"
fi

if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/open ]; then
    exec /usr/bin/open "$@"
fi

echo "cawide xdg-open: unable to open target" >&2
exit 1
"#;

pub const CODEX_SCRIPT: &str = r#"#!/bin/sh
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REAL_BIN=""
IFS=':'
for p in $PATH; do
    if [ "$p" != "$BIN_DIR" ] && [ -x "$p/codex" ] && [ ! "$p/codex" -ef "$BIN_DIR/codex" ]; then
        REAL_BIN="$p/codex"
        break
    fi
done
unset IFS

if [ -z "$REAL_BIN" ]; then
    echo "cawide shim: codex not found in PATH" >&2
    exit 127
fi

exec "$REAL_BIN" --enable hooks --dangerously-bypass-hook-trust "$@"
"#;

const CLAUDE_HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PermissionDenied",
    "PostToolUse",
    "PostToolUseFailure",
    "Notification",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "Stop",
    "StopFailure",
    "SessionEnd",
];

pub fn claude_settings_path(config_dir: &Path) -> PathBuf {
    config_dir.join("agents").join("claude-settings.json")
}

fn posix_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn claude_script(config_dir: &Path) -> String {
    let settings_path = claude_settings_path(config_dir);
    let quoted_settings = posix_single_quote(&settings_path.to_string_lossy());
    format!(
        r#"#!/bin/sh
if [ "${{CAWIDE_CLAUDE_SHIM_PID:-}}" = "$$" ]; then
    printf '%s\n' 'cawide: `claude` resolves back to Cawide'\''s launcher through another wrapper on PATH; install Claude Code (npm i -g @anthropic-ai/claude-code)' >&2
    exit 127
fi
export CAWIDE_CLAUDE_SHIM_PID="$$"

_self_dir="${{0%/*}}"
[ "$_self_dir" = "$0" ] && _self_dir="."
[ -z "$_self_dir" ] && _self_dir="/"
BIN_DIR="$(CDPATH= cd -- "$_self_dir" && pwd)"
REAL_BIN=""
IFS=':'
for p in $PATH; do
    if [ -n "$p" ] && [ "$p" != "$BIN_DIR" ] && [ -x "$p/claude" ] && [ ! "$p/claude" -ef "$BIN_DIR/claude" ]; then
        REAL_BIN="$p/claude"
        break
    fi
done
unset IFS

if [ -z "$REAL_BIN" ]; then
    echo "cawide shim: claude not found in PATH" >&2
    exit 127
fi

PASSTHROUGH=0
if [ -n "${{CAWIDE_CLAUDE_OWNER:-}}" ]; then
    PASSTHROUGH=1
else
    case "${{1:-}}" in
        -p|--print|-v|--version|-h|--help|update|upgrade|install|mcp|config|doctor|setup-token|plugin|migrate-installer)
            PASSTHROUGH=1
            ;;
    esac
    if [ "$PASSTHROUGH" -eq 0 ]; then
        for arg in "$@"; do
            case "$arg" in
                -p|--print|--settings|--settings=*)
                    PASSTHROUGH=1
                    break
                    ;;
            esac
        done
    fi
fi

if [ "$PASSTHROUGH" -eq 1 ]; then
    exec "$REAL_BIN" "$@"
fi

export CAWIDE_CLAUDE_OWNER=1
exec "$REAL_BIN" --settings {quoted_settings} "$@"
"#
    )
}

fn write_private_atomic(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    temp.write_all(content)?;
    temp.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temp.persist(path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {}", path.display(), e.error))?;
    Ok(())
}

fn write_claude_settings(config_dir: &Path) -> anyhow::Result<PathBuf> {
    let mut hooks = serde_json::Map::new();
    for &event in CLAUDE_HOOK_EVENTS {
        let timeout = if event == "PermissionRequest" {
            86_400
        } else {
            600
        };
        hooks.insert(
            event.to_string(),
            serde_json::json!([{
                "hooks": [{
                    "type": "command",
                    "command": "\"$CAWIDE_BIN_DIR/cawide\" hook claude",
                    "timeout": timeout
                }]
            }]),
        );
    }
    let payload = serde_json::json!({ "hooks": hooks });
    let bytes = serde_json::to_vec_pretty(&payload)?;
    let path = claude_settings_path(config_dir);
    write_private_atomic(&path, &bytes)?;
    Ok(path)
}

pub const OMP_SCRIPT: &str = r#"#!/bin/sh
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x "$BIN_DIR/cawide" ]; then
    "$BIN_DIR/cawide" setup omp >/dev/null 2>&1 || true
elif command -v cawide >/dev/null 2>&1; then
    cawide setup omp >/dev/null 2>&1 || true
fi

REAL_BIN=""
IFS=':'
for p in $PATH; do
    if [ "$p" != "$BIN_DIR" ] && [ -x "$p/omp" ] && [ ! "$p/omp" -ef "$BIN_DIR/omp" ]; then
        REAL_BIN="$p/omp"
        break
    fi
done
unset IFS

if [ -z "$REAL_BIN" ]; then
    echo "cawide shim: omp not found in PATH" >&2
    exit 127
fi

exec "$REAL_BIN" "$@"
"#;

pub const OPENCODE_SCRIPT: &str = r#"#!/bin/sh
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x "$BIN_DIR/cawide" ]; then
    "$BIN_DIR/cawide" setup opencode >/dev/null 2>&1 || true
elif command -v cawide >/dev/null 2>&1; then
    cawide setup opencode >/dev/null 2>&1 || true
fi

REAL_BIN=""
IFS=':'
for p in $PATH; do
    if [ "$p" != "$BIN_DIR" ] && [ -x "$p/opencode" ] && [ ! "$p/opencode" -ef "$BIN_DIR/opencode" ]; then
        REAL_BIN="$p/opencode"
        break
    fi
done
unset IFS

if [ -z "$REAL_BIN" ]; then
    echo "cawide shim: opencode not found in PATH" >&2
    exit 127
fi

exec "$REAL_BIN" "$@"
"#;

fn write_executable(path: &Path, content: &str) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Creates `<config_dir>/bin` with 0o755 permissions and populates launcher shims.
pub fn ensure_shims(config_dir: &Path) -> anyhow::Result<PathBuf> {
    let bin_dir = config_dir.join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755))?;
    }

    let current_exe = std::env::current_exe()?;
    let is_cawide_bin = current_exe
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.starts_with("cawide") && !s.contains('-'))
        .unwrap_or(false);

    let target_bin = if is_cawide_bin {
        current_exe
    } else if let Some(parent) = current_exe.parent() {
        let sibling = parent.join("cawide");
        if sibling.exists() {
            sibling.canonicalize().unwrap_or(sibling)
        } else {
            current_exe
        }
    } else {
        current_exe
    };

    let link_path = bin_dir.join("cawide");
    let target_bin_canonical = target_bin
        .canonicalize()
        .unwrap_or_else(|_| target_bin.clone());
    let link_canonical = link_path.canonicalize().ok();
    if link_canonical.as_ref() != Some(&target_bin_canonical) {
        if std::fs::symlink_metadata(&link_path).is_ok() {
            let _ = std::fs::remove_file(&link_path);
        }

        let symlinked = {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target_bin, &link_path).is_ok()
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::symlink_file(&target_bin, &link_path).is_ok()
            }
            #[cfg(not(any(unix, windows)))]
            {
                false
            }
        };

        if !symlinked {
            std::fs::copy(&target_bin, &link_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&link_path, std::fs::Permissions::from_mode(0o755));
            }
        }
    }

    write_executable(&bin_dir.join("cawide-open"), CAWIDE_OPEN_SCRIPT)?;
    write_executable(&bin_dir.join("open"), OPEN_SCRIPT)?;
    write_executable(&bin_dir.join("xdg-open"), XDG_OPEN_SCRIPT)?;
    write_executable(&bin_dir.join("codex"), CODEX_SCRIPT)?;
    write_claude_settings(config_dir)?;
    write_executable(&bin_dir.join("claude"), &claude_script(config_dir))?;
    write_executable(&bin_dir.join("omp"), OMP_SCRIPT)?;
    write_executable(&bin_dir.join("opencode"), OPENCODE_SCRIPT)?;

    ensure_shell_integration(config_dir)?;

    Ok(bin_dir)
}

pub fn ensure_shell_integration(config_dir: &Path) -> anyhow::Result<PathBuf> {
    let zsh_dir = config_dir.join("shell").join("zsh");
    std::fs::create_dir_all(&zsh_dir)?;

    let zshenv = r#"_cawide_zd="$ZDOTDIR"
if [ -n "$CAWIDE_ORIG_ZDOTDIR" ]; then
    export ZDOTDIR="$CAWIDE_ORIG_ZDOTDIR"
else
    unset ZDOTDIR
fi
[ -f "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zshenv" ] && . "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zshenv"
if [ -n "$ZDOTDIR" ]; then
    export CAWIDE_ORIG_ZDOTDIR="$ZDOTDIR"
else
    unset CAWIDE_ORIG_ZDOTDIR
fi
if [[ -o interactive || -o login ]] 2>/dev/null; then
    export ZDOTDIR="$_cawide_zd"
else
    unset CAWIDE_ORIG_ZDOTDIR
fi
unset _cawide_zd
"#;
    let zprofile = r#"_cawide_zd="$ZDOTDIR"
if [ -n "$CAWIDE_ORIG_ZDOTDIR" ]; then
    export ZDOTDIR="$CAWIDE_ORIG_ZDOTDIR"
else
    unset ZDOTDIR
fi
[ -f "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zprofile" ] && . "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zprofile"
if [ -n "$ZDOTDIR" ]; then
    export CAWIDE_ORIG_ZDOTDIR="$ZDOTDIR"
else
    unset CAWIDE_ORIG_ZDOTDIR
fi
export ZDOTDIR="$_cawide_zd"
unset _cawide_zd
"#;
    let zshrc = r#"_cawide_zd="$ZDOTDIR"
if [ "$HISTFILE" = "$_cawide_zd/.zsh_history" ]; then
    HISTFILE="${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zsh_history"
fi
if [ -n "$CAWIDE_ORIG_ZDOTDIR" ]; then
    export ZDOTDIR="$CAWIDE_ORIG_ZDOTDIR"
else
    unset ZDOTDIR
fi
[ -f "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zshrc" ] && . "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zshrc"
if [ -n "$ZDOTDIR" ]; then
    export CAWIDE_ORIG_ZDOTDIR="$ZDOTDIR"
else
    unset CAWIDE_ORIG_ZDOTDIR
fi

if ! [[ -o login ]] 2>/dev/null; then
    if [ -n "$CAWIDE_BIN_DIR" ]; then
        PATH="$CAWIDE_BIN_DIR:$PATH"
        export PATH
    fi
    if [ -n "$CAWIDE_ORIG_ZDOTDIR" ]; then
        export ZDOTDIR="$CAWIDE_ORIG_ZDOTDIR"
    else
        unset ZDOTDIR
    fi
    unset CAWIDE_ORIG_ZDOTDIR
else
    export ZDOTDIR="$_cawide_zd"
fi
unset _cawide_zd
"#;
    let zlogin = r#"_cawide_zd="$ZDOTDIR"
if [ -n "$CAWIDE_ORIG_ZDOTDIR" ]; then
    export ZDOTDIR="$CAWIDE_ORIG_ZDOTDIR"
else
    unset ZDOTDIR
fi
[ -f "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zlogin" ] && . "${CAWIDE_ORIG_ZDOTDIR:-$HOME}/.zlogin"
if [ -n "$ZDOTDIR" ]; then
    export CAWIDE_ORIG_ZDOTDIR="$ZDOTDIR"
else
    unset CAWIDE_ORIG_ZDOTDIR
fi

if [ -n "$CAWIDE_BIN_DIR" ]; then
    PATH="$CAWIDE_BIN_DIR:$PATH"
    export PATH
fi
if [ -n "$CAWIDE_ORIG_ZDOTDIR" ]; then
    export ZDOTDIR="$CAWIDE_ORIG_ZDOTDIR"
else
    unset ZDOTDIR
fi
unset CAWIDE_ORIG_ZDOTDIR _cawide_zd
"#;

    std::fs::write(zsh_dir.join(".zshenv"), zshenv)?;
    std::fs::write(zsh_dir.join(".zprofile"), zprofile)?;
    std::fs::write(zsh_dir.join(".zshrc"), zshrc)?;
    std::fs::write(zsh_dir.join(".zlogin"), zlogin)?;

    Ok(zsh_dir)
}
