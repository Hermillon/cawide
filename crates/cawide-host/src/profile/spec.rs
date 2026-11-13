use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentId {
    Claude,
    Codex,
    Omp,
    OpenCode,
}

impl AgentId {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentId::Claude => "claude",
            AgentId::Codex => "codex",
            AgentId::Omp => "omp",
            AgentId::OpenCode => "opencode",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceEnv {
    pub home: PathBuf,
    pub claude_config_dir: Option<PathBuf>,
    pub codex_home: Option<PathBuf>,
    pub omp_agent_dir: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub source_os: Option<String>,
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).and_then(|val| {
        let s = val.to_string_lossy();
        if s.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(val))
        }
    })
}

impl SourceEnv {
    pub fn from_process_env() -> anyhow::Result<Self> {
        let home = env_path("HOME")
            .ok_or_else(|| anyhow::anyhow!("HOME environment variable is not set"))?;

        let claude_config_dir = env_path("CLAUDE_CONFIG_DIR");
        let codex_home = env_path("CODEX_HOME");
        let omp_agent_dir = env_path("PI_CODING_AGENT_DIR");
        let xdg_config_home = env_path("XDG_CONFIG_HOME");
        let xdg_data_home = env_path("XDG_DATA_HOME");

        Ok(Self {
            home,
            claude_config_dir,
            codex_home,
            omp_agent_dir,
            xdg_config_home,
            xdg_data_home,
            source_os: None,
        })
    }
}
