use cawide_protocol::types::{GitError, GitErrorKind, MAX_PATHS_PER_OP};

fn invalid_arg(msg: impl Into<String>) -> GitError {
    GitError {
        kind: GitErrorKind::InvalidArgument,
        message: msg.into(),
        host: None,
        port: None,
    }
}

pub fn validate_ref_name(s: &str) -> Result<(), GitError> {
    if s.is_empty() {
        return Err(invalid_arg("ref name cannot be empty"));
    }
    if s.len() > 255 {
        return Err(invalid_arg("ref name exceeds 255 bytes"));
    }
    if s.starts_with('-') || s.starts_with('/') || s.ends_with('/') || s.ends_with(".lock") {
        return Err(invalid_arg(format!("invalid ref name: {s}")));
    }
    if s.contains("..")
        || s.contains("@{")
        || s.contains('~')
        || s.contains('^')
        || s.contains(':')
        || s.contains('?')
        || s.contains('*')
        || s.contains('[')
        || s.contains('\\')
    {
        return Err(invalid_arg(format!("invalid ref name: {s}")));
    }
    for c in s.chars() {
        if c.is_ascii_whitespace() || c.is_ascii_control() {
            return Err(invalid_arg(format!(
                "ref name contains invalid character: {s}"
            )));
        }
    }
    for part in s.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with('.') {
            return Err(invalid_arg(format!("invalid ref component in: {s}")));
        }
    }
    Ok(())
}

pub fn validate_revision(s: &str) -> Result<(), GitError> {
    if s.is_empty() {
        return Err(invalid_arg("revision cannot be empty"));
    }
    if s.len() > 255 {
        return Err(invalid_arg("revision exceeds 255 bytes"));
    }
    if s.starts_with('-') {
        return Err(invalid_arg("revision cannot start with '-'"));
    }
    for c in s.chars() {
        if c.is_ascii_whitespace() || c.is_ascii_control() {
            return Err(invalid_arg("revision contains invalid characters"));
        }
    }
    Ok(())
}

pub fn validate_oid(s: &str) -> Result<(), GitError> {
    if s.len() < 4 || s.len() > 64 {
        return Err(invalid_arg(format!("invalid OID length: {}", s.len())));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid_arg(format!("invalid OID format: {s}")));
    }
    Ok(())
}

pub fn validate_remote_name(s: &str) -> Result<(), GitError> {
    if s.is_empty() || s.len() > 64 {
        return Err(invalid_arg("remote name must be 1-64 characters"));
    }
    let first = s.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() && first != '.' && first != '_' {
        return Err(invalid_arg(
            "remote name must start with alphanumeric, dot, or underscore",
        ));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(invalid_arg("remote name contains invalid characters"));
    }
    Ok(())
}

pub fn validate_remote_url(s: &str) -> Result<(), GitError> {
    if s.is_empty() {
        return Err(invalid_arg("remote URL cannot be empty"));
    }
    if s.starts_with('-') {
        return Err(invalid_arg("remote URL cannot start with '-'"));
    }
    if s.contains(char::is_whitespace) {
        return Err(invalid_arg("remote URL cannot contain whitespace"));
    }
    if let Some(pos) = s.find("::") {
        if let Some(slash_pos) = s.find('/') {
            if pos < slash_pos {
                return Err(invalid_arg("remote URL protocol ext:: is disallowed"));
            }
        } else {
            return Err(invalid_arg("remote URL protocol ext:: is disallowed"));
        }
    }

    let is_standard = s.starts_with("https://")
        || s.starts_with("http://")
        || s.starts_with("ssh://")
        || s.starts_with("git://")
        || s.starts_with("file://")
        || s.starts_with('/');
    if let Some(rest) = s.strip_prefix("ssh://") {
        let host_part = rest.split('/').next().unwrap_or("");
        let host = host_part.split('@').next_back().unwrap_or(host_part);
        if host.starts_with('-') {
            return Err(invalid_arg("remote SSH host cannot start with '-'"));
        }
    }

    let is_scp = if !is_standard && s.contains('@') && s.contains(':') {
        let (user_host, path) = s.split_once(':').unwrap();
        let host = user_host.split('@').next_back().unwrap_or(user_host);
        user_host.contains('@')
            && !path.is_empty()
            && !user_host.starts_with('-')
            && !host.starts_with('-')
    } else {
        false
    };

    if !is_standard && !is_scp {
        return Err(invalid_arg("unsupported remote URL scheme"));
    }
    Ok(())
}

pub fn validate_paths(paths: &[String]) -> Result<(), GitError> {
    if paths.len() > MAX_PATHS_PER_OP {
        return Err(invalid_arg(format!(
            "path count {} exceeds maximum allowed ({})",
            paths.len(),
            MAX_PATHS_PER_OP
        )));
    }
    for p in paths {
        if p.contains('\n') {
            return Err(invalid_arg("file name contains a newline — use Terminal"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ref_name() {
        assert!(validate_ref_name("main").is_ok());
        assert!(validate_ref_name("feature/add-login").is_ok());
        assert!(validate_ref_name("").is_err());
        assert!(validate_ref_name("-bad").is_err());
        assert!(validate_ref_name("has space").is_err());
        assert!(validate_ref_name("has..dotdot").is_err());
        assert!(validate_ref_name("has~tilde").is_err());
        assert!(validate_ref_name("has^caret").is_err());
        assert!(validate_ref_name("has:colon").is_err());
        assert!(validate_ref_name("has?question").is_err());
        assert!(validate_ref_name("has*star").is_err());
        assert!(validate_ref_name("has[bracket").is_err());
        assert!(validate_ref_name("has@{atbrace").is_err());
        assert!(validate_ref_name("has\\backslash").is_err());
        assert!(validate_ref_name("/leading-slash").is_err());
        assert!(validate_ref_name("trailing-slash/").is_err());
        assert!(validate_ref_name("ends-with.lock").is_err());
    }

    #[test]
    fn test_validate_oid() {
        assert!(validate_oid("1234").is_ok());
        assert!(validate_oid("0123456789abcdef0123456789abcdef01234567").is_ok());
        assert!(validate_oid("123").is_err()); // too short
        assert!(validate_oid("").is_err());
        assert!(validate_oid("xyz123").is_err());
    }

    #[test]
    fn test_validate_remote_name() {
        assert!(validate_remote_name("origin").is_ok());
        assert!(validate_remote_name("upstream-1").is_ok());
        assert!(validate_remote_name("").is_err());
        assert!(validate_remote_name("-leading-dash").is_err());
        assert!(validate_remote_name("has space").is_err());
    }

    #[test]
    fn test_validate_remote_url() {
        assert!(validate_remote_url("https://github.com/org/repo.git").is_ok());
        assert!(validate_remote_url("http://example.com/repo.git").is_ok());
        assert!(validate_remote_url("ssh://git@github.com/org/repo.git").is_ok());
        assert!(validate_remote_url("git://github.com/org/repo.git").is_ok());
        assert!(validate_remote_url("git@github.com:org/repo.git").is_ok());
        assert!(validate_remote_url("-leading-dash").is_err());
        assert!(validate_remote_url("ext::sh -c evil").is_err());
        assert!(validate_remote_url("https://bad url.git").is_err());
    }
}
