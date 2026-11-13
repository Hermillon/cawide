//! Remote URL parser and HTTPS equivalence converter.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRemoteUrl {
    pub raw: String,
    pub scheme: String,
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

impl ParsedRemoteUrl {
    /// Returns the HTTPS equivalent URL, or `None` if local/unsupported.
    pub fn https_equivalent(&self) -> Option<String> {
        if self.scheme == "file" || self.host.is_empty() {
            return None;
        }

        // Special handling for Azure DevOps v3
        // e.g. git@ssh.dev.azure.com:v3/org/project/repo -> https://dev.azure.com/org/project/_git/repo
        if (self.host == "ssh.dev.azure.com" || self.host == "dev.azure.com")
            && (self.scheme == "ssh" || !self.path.contains("/_git/"))
        {
            let p = self.path.strip_prefix("v3/").unwrap_or(&self.path);
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() >= 3 {
                let org = parts[0];
                let project = parts[1];
                let repo = parts[2..].join("/");
                let repo = repo.strip_suffix(".git").unwrap_or(&repo);
                return Some(format!("https://dev.azure.com/{org}/{project}/_git/{repo}"));
            }
        }

        let clean_path = self.path.strip_suffix(".git").unwrap_or(&self.path);
        let clean_path = clean_path.trim_start_matches('/');

        let host_formatted = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        if self.scheme == "https" && self.port.is_some() {
            Some(format!(
                "https://{}:{}/{}",
                host_formatted,
                self.port.unwrap_or(443),
                clean_path
            ))
        } else {
            Some(format!("https://{}/{}", host_formatted, clean_path))
        }
    }
}

/// Parses a Git remote URL into structured fields.
pub fn parse_remote_url(raw: &str) -> Option<ParsedRemoteUrl> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // Local file paths
    if raw.starts_with('/') || raw.starts_with('.') || raw.starts_with('~') {
        let clean_path = raw.strip_suffix(".git").unwrap_or(raw);
        return Some(ParsedRemoteUrl {
            raw: raw.to_string(),
            scheme: "file".into(),
            user: None,
            host: String::new(),
            port: None,
            path: clean_path.to_string(),
        });
    }

    if let Some(rest) = raw.strip_prefix("file://") {
        let clean_path = rest.strip_suffix(".git").unwrap_or(rest);
        return Some(ParsedRemoteUrl {
            raw: raw.to_string(),
            scheme: "file".into(),
            user: None,
            host: String::new(),
            port: None,
            path: clean_path.to_string(),
        });
    }

    // URLs with explicit scheme, e.g. ssh://, https://, http://, git://
    if let Some((scheme, rest)) = raw.split_once("://") {
        let scheme = scheme.to_lowercase();
        let (authority, path) = match rest.split_once('/') {
            Some((auth, p)) => (auth, p),
            None => (rest, ""),
        };

        let (user, host_port) = match authority.split_once('@') {
            Some((u, hp)) => (Some(u.to_string()), hp),
            None => (None, authority),
        };

        let (host, port) = if host_port.starts_with('[') {
            // IPv6 [::1]:port
            if let Some(end_bracket) = host_port.find(']') {
                let h = &host_port[1..end_bracket];
                let after = &host_port[end_bracket + 1..];
                let p = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
                (h.to_string(), p)
            } else {
                (host_port.to_string(), None)
            }
        } else {
            match host_port.split_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
                None => (host_port.to_string(), None),
            }
        };

        let clean_path = path.strip_suffix(".git").unwrap_or(path);
        let clean_path = clean_path.trim_start_matches('/');

        return Some(ParsedRemoteUrl {
            raw: raw.to_string(),
            scheme,
            user,
            host,
            port,
            path: clean_path.to_string(),
        });
    }

    // SCP-like SSH syntax: [user@]host:path
    if let Some((auth, path)) = raw.split_once(':') {
        let (user, host) = match auth.split_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, auth),
        };

        let clean_path = path.strip_suffix(".git").unwrap_or(path);
        let clean_path = clean_path.trim_start_matches('/');

        return Some(ParsedRemoteUrl {
            raw: raw.to_string(),
            scheme: "ssh".into(),
            user,
            host: host.to_string(),
            port: None,
            path: clean_path.to_string(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_ssh_and_https() {
        let ssh = parse_remote_url("git@github.com:owner/repo.git").unwrap();
        assert_eq!(ssh.scheme, "ssh");
        assert_eq!(ssh.user.as_deref(), Some("git"));
        assert_eq!(ssh.host, "github.com");
        assert_eq!(ssh.path, "owner/repo");
        assert_eq!(
            ssh.https_equivalent().as_deref(),
            Some("https://github.com/owner/repo")
        );

        let https = parse_remote_url("https://github.com/owner/repo.git").unwrap();
        assert_eq!(https.scheme, "https");
        assert_eq!(https.host, "github.com");
        assert_eq!(https.path, "owner/repo");
        assert_eq!(
            https.https_equivalent().as_deref(),
            Some("https://github.com/owner/repo")
        );
    }

    #[test]
    fn test_parse_azure_v3() {
        let azure_ssh =
            parse_remote_url("git@ssh.dev.azure.com:v3/myorg/myproject/myrepo").unwrap();
        assert_eq!(azure_ssh.scheme, "ssh");
        assert_eq!(azure_ssh.host, "ssh.dev.azure.com");
        assert_eq!(azure_ssh.path, "v3/myorg/myproject/myrepo");
        assert_eq!(
            azure_ssh.https_equivalent().as_deref(),
            Some("https://dev.azure.com/myorg/myproject/_git/myrepo")
        );
    }

    #[test]
    fn test_parse_gitlab_subgroups() {
        let gl = parse_remote_url("git@gitlab.com:group/sub1/sub2/repo.git").unwrap();
        assert_eq!(gl.scheme, "ssh");
        assert_eq!(gl.host, "gitlab.com");
        assert_eq!(gl.path, "group/sub1/sub2/repo");
        assert_eq!(
            gl.https_equivalent().as_deref(),
            Some("https://gitlab.com/group/sub1/sub2/repo")
        );
    }

    #[test]
    fn test_parse_custom_port() {
        let p = parse_remote_url("ssh://git@example.com:2222/org/repo.git").unwrap();
        assert_eq!(p.scheme, "ssh");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, Some(2222));
        assert_eq!(p.path, "org/repo");
        assert_eq!(
            p.https_equivalent().as_deref(),
            Some("https://example.com/org/repo")
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let ipv6 = parse_remote_url("ssh://git@[::1]:2222/org/repo.git").unwrap();
        assert_eq!(ipv6.scheme, "ssh");
        assert_eq!(ipv6.host, "::1");
        assert_eq!(ipv6.port, Some(2222));
        assert_eq!(ipv6.path, "org/repo");
        assert_eq!(
            ipv6.https_equivalent().as_deref(),
            Some("https://[::1]/org/repo")
        );
    }

    #[test]
    fn test_parse_file() {
        let f = parse_remote_url("/var/git/repo.git").unwrap();
        assert_eq!(f.scheme, "file");
        assert_eq!(f.https_equivalent(), None);

        let f2 = parse_remote_url("file:///var/git/repo.git").unwrap();
        assert_eq!(f2.scheme, "file");
        assert_eq!(f2.https_equivalent(), None);
    }
}
