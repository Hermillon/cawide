use crate::pty::process::ProcInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Foreground {
    Shell,
    Agent(&'static str),
    Other,
}

const SHELLS: &[&str] = &[
    "bash",
    "zsh",
    "fish",
    "sh",
    "dash",
    "ksh",
    "tcsh",
    "csh",
    "nu",
    "xonsh",
    "elvish",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "cmd",
    "cmd.exe",
];

const INTERPRETERS: &[&str] = &["node", "bun", "deno", "python", "python3"];

const AGENT_BINARIES: &[(&str, &str)] = &[
    ("claude", "claude"),
    ("codex", "codex"),
    ("omp", "omp"),
    ("opencode", "opencode"),
    ("gemini", "gemini"),
    ("cursor-agent", "cursor"),
    ("cline", "cline"),
    ("copilot", "copilot"),
    ("goose", "goose"),
];

const PACKAGE_MARKERS: &[(&str, &str)] = &[
    ("/@anthropic-ai/claude-code/", "claude"),
    ("/@openai/codex/", "codex"),
    ("/@oh-my-pi/", "omp"),
    ("/opencode-ai/", "opencode"),
    ("/@google/gemini-cli/", "gemini"),
    ("/@github/copilot/", "copilot"),
];

fn strip_exe_ext(name: &str) -> &str {
    for ext in &[".exe", ".cmd", ".bat"] {
        if let Some(stripped) = name.strip_suffix(ext) {
            return stripped;
        }
        if name.len() >= ext.len() {
            let (stem, suffix) = name.split_at(name.len() - ext.len());
            if suffix.eq_ignore_ascii_case(ext) {
                return stem;
            }
        }
    }
    name
}

fn program_name(s: &str) -> &str {
    let without_path = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let trimmed = without_path.trim_start_matches('-');
    strip_exe_ext(trimmed)
}

fn strip_script_ext(name: &str) -> &str {
    for ext in &[".js", ".mjs", ".cjs", ".ts", ".py", ".exe", ".cmd", ".bat"] {
        if let Some(stripped) = name.strip_suffix(ext) {
            return stripped;
        }
        if name.len() >= ext.len() {
            let (stem, suffix) = name.split_at(name.len() - ext.len());
            if suffix.eq_ignore_ascii_case(ext) {
                return stem;
            }
        }
    }
    name
}

pub fn classify(info: &ProcInfo) -> Foreground {
    let name0_str = info
        .argv
        .first()
        .map(|s| program_name(s.as_str()))
        .or_else(|| {
            info.exe
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|f| f.to_str())
                .map(program_name)
        });

    let name0 = match name0_str {
        Some(n) => n,
        None => return Foreground::Other,
    };

    let exe_name = info
        .exe
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|f| f.to_str())
        .map(program_name);

    // 1. If name0 or exe_name matches an entry in AGENT_BINARIES, return Foreground::Agent(slug).
    for &(bin, slug) in AGENT_BINARIES {
        if name0.eq_ignore_ascii_case(bin) || exe_name.is_some_and(|e| e.eq_ignore_ascii_case(bin))
        {
            return Foreground::Agent(slug);
        }
    }

    // 2. If SHELLS or INTERPRETERS contains name0:
    let is_shell = SHELLS.iter().any(|s| name0.eq_ignore_ascii_case(s));
    let is_interpreter = INTERPRETERS.iter().any(|i| name0.eq_ignore_ascii_case(i));
    if (is_shell || is_interpreter) && info.argv.len() > 1 && !info.argv[1].starts_with('-') {
        let raw_script = &info.argv[1];
        let normalized_script = raw_script.replace('\\', "/");
        for &(marker, slug) in PACKAGE_MARKERS {
            if normalized_script.contains(marker) {
                return Foreground::Agent(slug);
            }
        }
        let script_filename = raw_script.rsplit(['/', '\\']).next().unwrap_or(raw_script);
        let script_stem = strip_script_ext(script_filename);
        for &(bin, slug) in AGENT_BINARIES {
            if script_stem.eq_ignore_ascii_case(bin) {
                return Foreground::Agent(slug);
            }
        }
        return Foreground::Other;
    }

    // 3. If SHELLS contains name0:
    if is_shell {
        let args_after = info.argv.get(1..).unwrap_or(&[]);
        let is_cmd = name0.eq_ignore_ascii_case("cmd") || name0.eq_ignore_ascii_case("cmd.exe");
        let is_ps = name0.eq_ignore_ascii_case("powershell")
            || name0.eq_ignore_ascii_case("powershell.exe")
            || name0.eq_ignore_ascii_case("pwsh")
            || name0.eq_ignore_ascii_case("pwsh.exe");

        if is_cmd {
            let has_c = args_after.iter().any(|arg| {
                let lower = arg.to_ascii_lowercase();
                lower == "/c" || lower == "-c"
            });
            if !has_c {
                return Foreground::Shell;
            }
            return Foreground::Other;
        }

        if is_ps {
            let has_c = args_after.iter().any(|arg| {
                let lower = arg.to_ascii_lowercase();
                lower == "-c" || lower == "-command" || lower == "/c" || lower == "/command"
            });
            if !has_c {
                return Foreground::Shell;
            }
            return Foreground::Other;
        }

        let all_options = args_after.iter().all(|arg| arg.starts_with('-'));
        let has_command_mode = args_after
            .iter()
            .any(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c'));

        if all_options && !has_command_mode {
            return Foreground::Shell;
        }
        return Foreground::Other;
    }

    // 4. Otherwise return Foreground::Other.
    Foreground::Other
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_classify_shells() {
        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["-zsh".to_string()],
                exe: None,
            }),
            Foreground::Shell
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["/bin/zsh".to_string(), "-l".to_string()],
                exe: None,
            }),
            Foreground::Shell
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["bash".to_string(), "--login".to_string()],
                exe: None,
            }),
            Foreground::Shell
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["/bin/sh".to_string()],
                exe: None,
            }),
            Foreground::Shell
        );
    }

    #[test]
    fn test_classify_shell_command_or_script() {
        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["sh".to_string(), "-c".to_string(), "exec omp".to_string(),],
                exe: None,
            }),
            Foreground::Other
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["zsh".to_string(), "-lc".to_string(), "omp".to_string()],
                exe: None,
            }),
            Foreground::Other
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![
                    "bash".to_string(),
                    "-l".to_string(),
                    "-c".to_string(),
                    "x".to_string(),
                ],
                exe: None,
            }),
            Foreground::Other
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["bash".to_string(), "deploy.sh".to_string()],
                exe: None,
            }),
            Foreground::Other
        );
    }

    #[test]
    fn test_classify_agents() {
        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["/bin/sh".to_string(), "/tmp/bin/omp".to_string()],
                exe: None,
            }),
            Foreground::Agent("omp")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["claude".to_string()],
                exe: Some(PathBuf::from("/x/claude/versions/2.0.30")),
            }),
            Foreground::Agent("claude")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![
                    "node".to_string(),
                    "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js".to_string(),
                ],
                exe: None,
            }),
            Foreground::Agent("claude")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![
                    "node".to_string(),
                    "/x/@openai/codex/bin/codex.js".to_string(),
                ],
                exe: None,
            }),
            Foreground::Agent("codex")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["omp".to_string()],
                exe: None,
            }),
            Foreground::Agent("omp")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![],
                exe: Some(PathBuf::from("/Users/u/.bun/bin/omp")),
            }),
            Foreground::Agent("omp")
        );
    }

    #[test]
    fn test_classify_other_and_empty() {
        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["nvim".to_string(), "a.rs".to_string()],
                exe: None,
            }),
            Foreground::Other
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![],
                exe: None,
            }),
            Foreground::Other
        );
    }

    #[test]
    fn test_classify_windows_paths_and_shells() {
        assert_eq!(
            classify(&ProcInfo {
                argv: vec![
                    r"C:\Program Files\nodejs\node.exe".to_string(),
                    r"C:\Users\User\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js".to_string(),
                ],
                exe: Some(PathBuf::from(r"C:\Program Files\nodejs\node.exe")),
            }),
            Foreground::Agent("claude")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![
                    r"C:\Users\User\AppData\Local\Programs\Python\Python311\python.exe".to_string(),
                    r"C:\Users\User\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js"
                        .to_string(),
                ],
                exe: None,
            }),
            Foreground::Agent("codex")
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![r"C:\Windows\System32\cmd.exe".to_string()],
                exe: Some(PathBuf::from(r"C:\Windows\System32\cmd.exe")),
            }),
            Foreground::Shell
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["pwsh.exe".to_string(), "-NoLogo".to_string()],
                exe: None,
            }),
            Foreground::Shell
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec!["cmd.exe".to_string(), "/c".to_string(), "dir".to_string()],
                exe: None,
            }),
            Foreground::Other
        );

        assert_eq!(
            classify(&ProcInfo {
                argv: vec![
                    "powershell.exe".to_string(),
                    "-Command".to_string(),
                    "Get-Process".to_string()
                ],
                exe: None,
            }),
            Foreground::Other
        );
    }
}
