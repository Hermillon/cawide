use bytes::Bytes;
use cawide_protocol::types::{ForgeError, ForgeErrorKind};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, ETAG, IF_NONE_MATCH};
use reqwest::{Client, Method, Request, RequestBuilder, StatusCode};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

pub const FORGE_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub const ETAG_MAX_ENTRIES: usize = 512;
pub const ETAG_MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
pub const ETAG_MAX_ENTRY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct EtagEntry {
    pub etag: HeaderValue,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Default)]
pub struct EtagCache {
    entries: HashMap<String, EtagEntry>,
    order: VecDeque<String>,
    total_bytes: usize,
}

impl std::fmt::Debug for EtagCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtagCache")
            .field("entries", &self.entries.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl EtagCache {
    pub fn get(&self, key: &str) -> Option<&EtagEntry> {
        self.entries.get(key)
    }

    pub fn put(&mut self, key: String, entry: EtagEntry) {
        if entry.body.len() > ETAG_MAX_ENTRY_BYTES {
            self.remove(&key);
            return;
        }

        self.remove(&key);
        self.total_bytes += entry.body.len();
        self.order.push_back(key.clone());
        self.entries.insert(key, entry);

        while self.entries.len() > ETAG_MAX_ENTRIES || self.total_bytes > ETAG_MAX_TOTAL_BYTES {
            if let Some(old_key) = self.order.pop_front() {
                if let Some(old_entry) = self.entries.remove(&old_key) {
                    self.total_bytes = self.total_bytes.saturating_sub(old_entry.body.len());
                }
            } else {
                break;
            }
        }
    }

    pub fn remove(&mut self, key: &str) {
        if let Some(old_entry) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(old_entry.body.len());
            self.order.retain(|k| k != key);
        }
    }
}

pub fn etag_key(req: &Request) -> Option<String> {
    if req.method() != Method::GET {
        return None;
    }
    let url = req.url().as_str();
    let accept = req
        .headers()
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .map(|v| v.as_bytes())
        .unwrap_or(b"");
    let mut hasher = Sha256::new();
    hasher.update(auth);
    let auth_sha256 = hex::encode(hasher.finalize());
    Some(format!("{url}\n{accept}\n{auth_sha256}"))
}

#[derive(Debug, Clone)]
pub struct ForgeHttp {
    client: Client,
    endpoint_overrides: HashMap<String, String>,
    pub etags: Arc<parking_lot::Mutex<EtagCache>>,
}
pub fn url_encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

pub fn form_encode<'a, I, K, V>(pairs: I) -> String
where
    I: IntoIterator<Item = &'a (K, V)>,
    K: AsRef<str> + 'a,
    V: AsRef<str> + 'a,
{
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k.as_ref(), v.as_ref());
    }
    s.finish()
}

impl ForgeHttp {
    pub fn new(endpoint_overrides: HashMap<String, String>) -> Self {
        let version = env!("CARGO_PKG_VERSION");
        let client = Client::builder()
            .timeout(FORGE_HTTP_TIMEOUT)
            .user_agent(format!("cawide/{version}"))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            endpoint_overrides,
            etags: Arc::new(parking_lot::Mutex::new(EtagCache::default())),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn url(&self, canonical_host: &str, default_scheme: &str, path: &str) -> String {
        let clean_path = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };

        if let Some(override_base) = self.endpoint_overrides.get(canonical_host) {
            let base = override_base.trim_end_matches('/');
            format!("{base}{clean_path}")
        } else {
            format!("{default_scheme}://{canonical_host}{clean_path}")
        }
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client.request(method, url)
    }

    pub async fn execute(
        &self,
        rb: RequestBuilder,
        is_merge: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes), ForgeError> {
        let req = rb.build().map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: e.to_string(),
            git_kind: None,
            host: None,
            port: None,
        })?;

        self.send(req, is_merge).await
    }

    pub async fn send(
        &self,
        mut req: Request,
        is_merge: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes), ForgeError> {
        let url_host = req.url().host_str().map(str::to_string);
        let url_port = req.url().port();

        let cache_key = etag_key(&req);
        let mut cached_entry = None;
        if let Some(key) = &cache_key {
            if !req.headers().contains_key(IF_NONE_MATCH) {
                if let Some(entry) = self.etags.lock().get(key).cloned() {
                    req.headers_mut().insert(IF_NONE_MATCH, entry.etag.clone());
                    cached_entry = Some(entry);
                }
            }
        }

        let resp = match self.client.execute(req).await {
            Ok(r) => r,
            Err(e) => {
                let kind = if e.is_timeout() {
                    ForgeErrorKind::Timeout
                } else if e.is_connect() {
                    ForgeErrorKind::Network
                } else {
                    ForgeErrorKind::Other
                };
                return Err(ForgeError {
                    kind,
                    message: e.to_string(),
                    git_kind: None,
                    host: url_host,
                    port: url_port,
                });
            }
        };

        let status = resp.status();
        if status == StatusCode::NOT_MODIFIED {
            if let Some(entry) = cached_entry.or_else(|| {
                cache_key
                    .as_deref()
                    .and_then(|k| self.etags.lock().get(k).cloned())
            }) {
                return Ok((StatusCode::OK, entry.headers, entry.body));
            } else {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: "received 304 Not Modified but cached entry is missing".into(),
                    git_kind: None,
                    host: url_host,
                    port: url_port,
                });
            }
        }

        let headers = resp.headers().clone();

        let body_bytes = match resp.bytes().await {
            Ok(b) => {
                if b.len() > MAX_RESPONSE_BYTES {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::Other,
                        message: "response exceeded maximum size".into(),
                        git_kind: None,
                        host: url_host,
                        port: url_port,
                    });
                }
                b
            }
            Err(e) => {
                return Err(ForgeError {
                    kind: if e.is_timeout() {
                        ForgeErrorKind::Timeout
                    } else {
                        ForgeErrorKind::Network
                    },
                    message: e.to_string(),
                    git_kind: None,
                    host: url_host,
                    port: url_port,
                });
            }
        };

        if status.is_success() {
            if let Some(key) = cache_key {
                if let Some(etag) = headers.get(ETAG) {
                    self.etags.lock().put(
                        key,
                        EtagEntry {
                            etag: etag.clone(),
                            headers: headers.clone(),
                            body: body_bytes.clone(),
                        },
                    );
                } else {
                    self.etags.lock().remove(&key);
                }
            }
            return Ok((status, headers, body_bytes));
        }

        // Map errors
        let body_str = String::from_utf8_lossy(&body_bytes);
        let lower_body = body_str.to_ascii_lowercase();

        let kind = match status.as_u16() {
            401 => ForgeErrorKind::NotAuthenticated,
            403 => {
                let remaining_is_zero = headers
                    .get("x-ratelimit-remaining")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.trim() == "0")
                    .unwrap_or(false);
                let has_retry_after = headers.contains_key("retry-after");
                let has_rate_limit_body = lower_body.contains("rate limit");
                if remaining_is_zero || has_retry_after || has_rate_limit_body {
                    ForgeErrorKind::RateLimited
                } else {
                    ForgeErrorKind::PermissionDenied
                }
            }
            404 => ForgeErrorKind::NotFound,
            429 => ForgeErrorKind::RateLimited,
            405 | 406 if is_merge => ForgeErrorKind::MergeBlocked,
            409 if is_merge => ForgeErrorKind::MergeBlocked,
            409 | 422 if lower_body.contains("already exist") => ForgeErrorKind::AlreadyExists,
            _ => ForgeErrorKind::Other,
        };

        let message = extract_error_message(&body_str, status);

        Err(ForgeError {
            kind,
            message,
            git_kind: None,
            host: url_host,
            port: url_port,
        })
    }
}

fn extract_error_message(body: &str, status: StatusCode) -> String {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(msg) = json.get("message").and_then(|m| m.as_str()) {
            return msg.to_string();
        }
        if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
            return err.to_string();
        }
        if let Some(errs) = json.get("errors").and_then(|e| e.as_array()) {
            let parts: Vec<String> = errs
                .iter()
                .filter_map(|e| {
                    if let Some(s) = e.as_str() {
                        Some(s.to_string())
                    } else {
                        e.get("message")
                            .and_then(|m| m.as_str())
                            .map(|m| m.to_string())
                    }
                })
                .collect();
            if !parts.is_empty() {
                return parts.join(", ");
            }
        }
    }

    if !body.trim().is_empty() {
        return body.trim().to_string();
    }

    status
        .canonical_reason()
        .unwrap_or("HTTP error")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn test_etag_cache_basic_put_get_remove() {
        let mut cache = EtagCache::default();
        let entry = EtagEntry {
            etag: HeaderValue::from_static("\"12345\""),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"hello world"),
        };

        cache.put("key1".to_string(), entry.clone());
        assert_eq!(cache.get("key1").map(|e| &e.body), Some(&entry.body));
        assert_eq!(cache.total_bytes, 11);

        cache.remove("key1");
        assert!(cache.get("key1").is_none());
        assert_eq!(cache.total_bytes, 0);
    }

    #[test]
    fn test_etag_cache_reject_oversized_entry() {
        let mut cache = EtagCache::default();
        let oversized = vec![0u8; ETAG_MAX_ENTRY_BYTES + 1];
        let entry = EtagEntry {
            etag: HeaderValue::from_static("\"huge\""),
            headers: HeaderMap::new(),
            body: Bytes::from(oversized),
        };

        cache.put("huge_key".to_string(), entry);
        assert!(cache.get("huge_key").is_none());
        assert_eq!(cache.total_bytes, 0);
    }

    #[test]
    fn test_etag_cache_eviction_when_exceeding_count() {
        let mut cache = EtagCache::default();
        // Insert ETAG_MAX_ENTRIES + 1 small entries
        for i in 0..=ETAG_MAX_ENTRIES {
            cache.put(
                format!("key_{i}"),
                EtagEntry {
                    etag: HeaderValue::from_static("\"etag\""),
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(b"x"),
                },
            );
        }

        assert_eq!(cache.entries.len(), ETAG_MAX_ENTRIES);
        // Oldest entry (key_0) must have been evicted
        assert!(cache.get("key_0").is_none());
        assert!(cache.get("key_1").is_some());
        assert!(cache.get(&format!("key_{ETAG_MAX_ENTRIES}")).is_some());
    }

    #[test]
    fn test_etag_cache_debug_format() {
        let mut cache = EtagCache::default();
        cache.put(
            "k1".to_string(),
            EtagEntry {
                etag: HeaderValue::from_static("\"etag\""),
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"abcd"),
            },
        );

        let debug_str = format!("{cache:?}");
        assert!(debug_str.contains("EtagCache"));
        assert!(debug_str.contains("entries: 1"));
        assert!(debug_str.contains("total_bytes: 4"));
    }

    #[test]
    fn test_etag_key_generation() {
        let client = Client::new();

        let get_req = client
            .get("https://api.github.com/repos/org/repo")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, "Bearer secret_token")
            .build()
            .unwrap();
        let key1 = etag_key(&get_req);
        assert!(key1.is_some());

        // POST requests yield None
        let post_req = client
            .post("https://api.github.com/repos/org/repo")
            .build()
            .unwrap();
        assert!(etag_key(&post_req).is_none());

        // Different token produces different key
        let get_req2 = client
            .get("https://api.github.com/repos/org/repo")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, "Bearer different_token")
            .build()
            .unwrap();
        let key2 = etag_key(&get_req2);
        assert_ne!(key1, key2);
    }
}
