use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ForgeHostConfig {
    pub client_ids: HashMap<String, String>,
    pub helper_exe: Option<PathBuf>,
    pub endpoint_overrides: HashMap<String, String>,
    pub cli_search_path: Option<String>,
}
