#[derive(Debug, Clone, Default)]
pub struct GitHostEnv {
    pub extra_env: Vec<(String, String)>,
    pub user_ssh_command: Option<String>,
}

impl GitHostEnv {
    pub fn new(extra_env: Vec<(String, String)>) -> Self {
        Self {
            extra_env,
            user_ssh_command: std::env::var("GIT_SSH_COMMAND")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}
