//! Terminal PTY output URL scanner for detecting local web server URLs.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use regex::Regex;
use std::sync::LazyLock;

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // SAFETY: statically verified regular expression pattern.
    match Regex::new(
        r"(?i)\bhttps?://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|[a-z0-9-]+\.localhost)(?::\d{1,5})?(?:/[^\s\x22'<>`)\]]*)?",
    ) {
        Ok(re) => re,
        Err(_) => unreachable!("statically verified regular expression pattern"),
    }
});

const MAX_LINE_LEN: usize = 4096;
const MAX_PENDING: usize = 8;
const DEDUP_WINDOW: Duration = Duration::from_secs(60);
fn contains_http_scheme(buf: &[u8]) -> bool {
    buf.windows(7).any(|w| w.eq_ignore_ascii_case(b"http://"))
        || (buf.len() >= 8 && buf.windows(8).any(|w| w.eq_ignore_ascii_case(b"https://")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeState {
    Normal,
    Esc,
    Csi,
    Osc,
    OscEsc,
}

pub struct UrlScanner {
    state: EscapeState,
    line_buf: Vec<u8>,
    pending: Vec<String>,
    seen: HashMap<String, Instant>,
}

impl Default for UrlScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl UrlScanner {
    pub fn new() -> Self {
        Self {
            state: EscapeState::Normal,
            line_buf: Vec::with_capacity(512),
            pending: Vec::new(),
            seen: HashMap::new(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match self.state {
                EscapeState::Normal => {
                    if b == 0x1B {
                        self.state = EscapeState::Esc;
                    } else if b == b'\n' || b == b'\r' {
                        self.process_line();
                    } else if self.line_buf.len() < MAX_LINE_LEN {
                        self.line_buf.push(b);
                    }
                }
                EscapeState::Esc => match b {
                    b'[' => self.state = EscapeState::Csi,
                    b']' => self.state = EscapeState::Osc,
                    b'\n' | b'\r' => {
                        self.process_line();
                        self.state = EscapeState::Normal;
                    }
                    _ => self.state = EscapeState::Normal,
                },
                EscapeState::Csi => {
                    if (0x40..=0x7E).contains(&b) {
                        self.state = EscapeState::Normal;
                    } else if b == b'\n' || b == b'\r' {
                        self.process_line();
                        self.state = EscapeState::Normal;
                    }
                }
                EscapeState::Osc => {
                    if b == 0x07 {
                        self.state = EscapeState::Normal;
                    } else if b == 0x1B {
                        self.state = EscapeState::OscEsc;
                    } else if b == b'\n' || b == b'\r' {
                        self.process_line();
                        self.state = EscapeState::Normal;
                    }
                }
                EscapeState::OscEsc => {
                    if b == b'\\' {
                        self.state = EscapeState::Normal;
                    } else if b == b'\n' || b == b'\r' {
                        self.process_line();
                        self.state = EscapeState::Normal;
                    } else {
                        self.state = EscapeState::Osc;
                    }
                }
            }
        }
    }

    fn process_line(&mut self) {
        if self.line_buf.len() < 7 || !contains_http_scheme(&self.line_buf) {
            self.line_buf.clear();
            return;
        }

        let line = String::from_utf8_lossy(&self.line_buf);
        let now = Instant::now();

        // Prune entries older than 60s
        if !self.seen.is_empty() {
            self.seen
                .retain(|_, ts| now.duration_since(*ts) < DEDUP_WINDOW);
        }
        for m in URL_REGEX.find_iter(&line) {
            let matched_str = m.as_str().trim_end_matches(['.', ',', ';', ':']);
            if let Ok(mut url) = url::Url::parse(matched_str) {
                if url.scheme() != "http" && url.scheme() != "https" {
                    continue;
                }

                // Rewrite 0.0.0.0 and [::] / :: to localhost
                if let Some(host) = url.host_str() {
                    if host == "0.0.0.0" || host == "[::]" || host == "::" {
                        let _ = url.set_host(Some("localhost"));
                    }
                }

                let port = url.port_or_known_default().unwrap_or(0);
                if !(1..=65535).contains(&port) {
                    continue;
                }

                let normalized = url.to_string();
                if self.seen.contains_key(&normalized) {
                    continue;
                }

                self.seen.insert(normalized.clone(), now);
                if self.pending.len() >= MAX_PENDING {
                    self.pending.remove(0);
                }
                self.pending.push(normalized);
            }
        }

        self.line_buf.clear();
    }

    pub fn take(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vite_banner_detection() {
        let mut scanner = UrlScanner::new();
        let bytes =
            b"  \xe2\x9e\x9c  Local:   \x1b[36mhttp://localhost:\x1b[1m5173\x1b[22m/\x1b[39m\r\n";
        scanner.feed(bytes);
        assert_eq!(scanner.take(), vec!["http://localhost:5173/"]);
    }

    #[test]
    fn test_zero_host_rewritten_to_localhost() {
        let mut scanner = UrlScanner::new();
        scanner.feed(b"Listening on http://0.0.0.0:8000/\n");
        assert_eq!(scanner.take(), vec!["http://localhost:8000/"]);
    }

    #[test]
    fn test_dedup_within_60_seconds() {
        let mut scanner = UrlScanner::new();
        scanner.feed(b"Server at http://localhost:3000/\n");
        assert_eq!(scanner.take(), vec!["http://localhost:3000/"]);

        // Second line with same URL should be deduplicated
        scanner.feed(b"Server ready: http://localhost:3000/\n");
        assert_eq!(scanner.take(), Vec::<String>::new());
    }

    #[test]
    fn test_ws_not_detected() {
        let mut scanner = UrlScanner::new();
        scanner.feed(b"Debugger listening on ws://127.0.0.1:9229/123\n");
        assert_eq!(scanner.take(), Vec::<String>::new());
    }

    #[test]
    fn test_large_line_no_panic() {
        let mut scanner = UrlScanner::new();
        let large = vec![b'a'; 5000];
        scanner.feed(&large);
        scanner.feed(b"\n");
        assert_eq!(scanner.take(), Vec::<String>::new());
    }
}
