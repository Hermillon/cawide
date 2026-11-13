#[derive(Debug, Clone, Default)]
pub struct GitAuthInjection {
    pub config_args: Vec<String>,
    pub env: Vec<(String, String)>,
}

pub trait ForgeCredentialSource: Send + Sync {
    fn auth_for(&self, remote_url: &str, account: Option<&str>) -> GitAuthInjection;
    fn https_injection(
        &self,
        _scheme: &str,
        _authority: &str,
        _account: Option<&str>,
    ) -> Option<GitAuthInjection> {
        None
    }
    fn ssh_command(&self, _host: &str, _port: Option<u16>) -> Option<String> {
        None
    }
}

#[derive(Debug, Default)]
pub struct NoForgeCredentials;

impl ForgeCredentialSource for NoForgeCredentials {
    fn auth_for(&self, _remote_url: &str, _account: Option<&str>) -> GitAuthInjection {
        GitAuthInjection::default()
    }
}
