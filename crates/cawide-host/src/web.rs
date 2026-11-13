//! Web utilities for URL normalization and browser target handling.

use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::connections::ConnectionTracker;
use crate::net::ipc::IpcResponse;
use cawide_protocol::types::HostEvent;

fn rewrite_zero_host(url: &mut url::Url) {
    if let Some(host) = url.host_str() {
        if host == "0.0.0.0" || host == "[::]" || host == "::" {
            let _ = url.set_host(Some("localhost"));
        }
    }
}

pub fn normalize_open_target(input: &str) -> Result<String, String> {
    // 1. Trim input whitespace and surrounding matching single/double quotes. Empty -> Err("missing URL or port").
    let mut trimmed = input.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
    {
        trimmed = &trimmed[1..trimmed.len() - 1];
    }
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return Err("missing URL or port".to_string());
    }

    // 2. Digits only, or `:` followed by digits -> port 1..=65535 -> format!("http://localhost:{p}/"). Out of range -> Err("port must be 1-65535").
    let is_digits_only = trimmed.bytes().all(|b| b.is_ascii_digit());
    let is_colon_digits = trimmed.starts_with(':')
        && trimmed.len() > 1
        && trimmed[1..].bytes().all(|b| b.is_ascii_digit());

    if is_digits_only || is_colon_digits {
        let digits = if is_colon_digits {
            &trimmed[1..]
        } else {
            trimmed
        };
        let port = digits.parse::<u32>().ok();
        return match port {
            Some(p @ 1..=65535) => Ok(format!("http://localhost:{p}/")),
            _ => Err("port must be 1-65535".to_string()),
        };
    }

    // 3. Contains :// -> parse with url::Url::parse. Scheme must be http or https, else Err("only http and https URLs can be opened").
    if trimmed.contains("://") {
        let mut url = url::Url::parse(trimmed).map_err(|e| e.to_string())?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err("only http and https URLs can be opened".to_string());
        }
        rewrite_zero_host(&mut url);
        return Ok(url.to_string());
    }

    // 4. Otherwise pick scheme and parse "{scheme}://{input}".
    let candidate = format!("http://{trimmed}");
    let test_url = url::Url::parse(&candidate).map_err(|e| e.to_string())?;
    let host_str = match test_url.host_str() {
        Some(h) if !h.is_empty() => h,
        _ => return Err("missing host in URL".to_string()),
    };

    let is_ip = matches!(
        test_url.host(),
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))
    );
    let has_explicit_port_other_than_443 = test_url.port().is_some_and(|p| p != 443);
    let is_localhost = host_str == "localhost" || host_str.ends_with(".localhost");
    let is_single_label = !is_ip && !host_str.contains('.');
    let is_local_tld = host_str.ends_with(".local")
        || host_str.ends_with(".internal")
        || host_str.ends_with(".lan")
        || host_str.ends_with(".home.arpa");

    let scheme = if has_explicit_port_other_than_443
        || is_ip
        || is_localhost
        || is_single_label
        || is_local_tld
    {
        "http"
    } else {
        "https"
    };

    let mut url = if scheme == "http" {
        test_url
    } else {
        url::Url::parse(&format!("https://{trimmed}")).map_err(|e| e.to_string())?
    };

    rewrite_zero_host(&mut url);
    Ok(url.to_string())
}

/// Resolves the target URL or port from CLI arguments, prioritizing URLs and ports over flags.
pub fn resolve_open_target<S: AsRef<str>>(args: &[S]) -> Result<String, String> {
    let is_explicit_target = |s: &str| {
        let mut trimmed = s.trim();
        if (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
            || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        {
            trimmed = &trimmed[1..trimmed.len() - 1];
        }
        let trimmed = trimmed.trim();
        !trimmed.starts_with('-')
            && (trimmed.contains("://")
                || trimmed.starts_with(':')
                || (!trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()))
                || trimmed.starts_with("localhost:")
                || trimmed.starts_with("127.0.0.1:")
                || trimmed.starts_with("0.0.0.0:"))
    };
    args.iter()
        .map(|s| s.as_ref())
        .find(|a| is_explicit_target(a))
        .or_else(|| {
            args.iter()
                .map(|s| s.as_ref())
                .find(|a| !a.starts_with('-') && !a.is_empty())
        })
        .map(|s| s.to_string())
        .ok_or_else(|| "missing URL or port".to_string())
}

pub fn open_url(
    broadcaster: &HostEventBroadcaster,
    connections: &ConnectionTracker,
    target: &str,
    session_id: Option<String>,
) -> IpcResponse {
    let url = match normalize_open_target(target) {
        Ok(u) => u,
        Err(msg) => return IpcResponse::Error(msg),
    };

    if !connections.has_connections() {
        return IpcResponse::Error(
            "No phone is connected. Open Cawide on your phone, then run this again.".to_string(),
        );
    }

    broadcaster.broadcast(HostEvent::OpenUrl { url, session_id });
    IpcResponse::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_open_target_table() {
        assert_eq!(
            normalize_open_target("3000").as_deref(),
            Ok("http://localhost:3000/")
        );
        assert_eq!(
            normalize_open_target(":3000").as_deref(),
            Ok("http://localhost:3000/")
        );
        assert_eq!(
            normalize_open_target("localhost:5173/app").as_deref(),
            Ok("http://localhost:5173/app")
        );
        assert_eq!(
            normalize_open_target("0.0.0.0:8080").as_deref(),
            Ok("http://localhost:8080/")
        );
        assert_eq!(
            normalize_open_target("192.168.1.5:8080").as_deref(),
            Ok("http://192.168.1.5:8080/")
        );
        assert_eq!(
            normalize_open_target("jenkins:8080").as_deref(),
            Ok("http://jenkins:8080/")
        );
        assert_eq!(
            normalize_open_target("example.com").as_deref(),
            Ok("https://example.com/")
        );
        assert_eq!(
            normalize_open_target("ftp://x"),
            Err("only http and https URLs can be opened".to_string())
        );
        assert_eq!(
            normalize_open_target("70000"),
            Err("port must be 1-65535".to_string())
        );
        assert_eq!(
            normalize_open_target(""),
            Err("missing URL or port".to_string())
        );
        assert_eq!(
            normalize_open_target("'5173'").as_deref(),
            Ok("http://localhost:5173/")
        );
        assert_eq!(
            normalize_open_target("\"3000\"").as_deref(),
            Ok("http://localhost:3000/")
        );
        assert_eq!(
            normalize_open_target("'https://www.npmjs.com/login?next=/login/cli/12345'").as_deref(),
            Ok("https://www.npmjs.com/login?next=/login/cli/12345")
        );
        assert_eq!(
            normalize_open_target("https://www.npmjs.com/login?next=/login/cli/12345").as_deref(),
            Ok("https://www.npmjs.com/login?next=/login/cli/12345")
        );
        assert_eq!(
            normalize_open_target("''"),
            Err("missing URL or port".to_string())
        );
        assert_eq!(
            normalize_open_target("\"\""),
            Err("missing URL or port".to_string())
        );
    }

    #[test]
    fn test_resolve_open_target() {
        let args = vec!["--new-window".to_string(), "5173".to_string()];
        assert_eq!(resolve_open_target(&args).as_deref(), Ok("5173"));

        let args2 = vec![
            "-a".to_string(),
            "Safari".to_string(),
            "http://localhost:3000".to_string(),
        ];
        assert_eq!(
            resolve_open_target(&args2).as_deref(),
            Ok("http://localhost:3000")
        );

        let empty_args: Vec<String> = vec![];
        assert_eq!(
            resolve_open_target(&empty_args),
            Err("missing URL or port".to_string())
        );
    }
}
