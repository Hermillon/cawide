use std::time::Duration;

use anyhow::Context;
use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE};

pub const DEFAULT_CLOUD_URL: &str = "https://api.cawide.dev";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudConfig {
    pub base_url: String,
}

impl CloudConfig {
    pub fn resolve(override_url: Option<String>) -> Self {
        let base_url = match override_url {
            Some(mut url) => {
                while url.ends_with('/') {
                    url.pop();
                }
                url
            }
            None => DEFAULT_CLOUD_URL.trim_end_matches('/').to_string(),
        };
        Self { base_url }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self::resolve(
            std::env::var("CAWIDE_CLOUD_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        ))
    }
}

pub struct CloudClient {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl ApiResponse {
    pub fn error_message(&self) -> String {
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&self.body) {
            if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
                return err.to_string();
            }
        }
        format!("HTTP {}", self.status)
    }
}

impl CloudClient {
    pub fn new(cfg: &CloudConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(format!("cawide/{}", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .build()
            .context("failed to build reqwest client")?;

        Ok(Self {
            http,
            base_url: cfg.base_url.clone(),
        })
    }

    pub async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> anyhow::Result<ApiResponse> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.post(&url);

        let body_bytes = serde_json::to_vec(body).context("failed to serialize JSON body")?;
        req = req
            .header(CONTENT_TYPE, "application/json")
            .body(body_bytes);

        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await.map_err(|err| {
            anyhow::Error::new(err)
                .context(format!("could not reach Cawide Cloud at {}", self.base_url))
        })?;

        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|err| {
                anyhow::Error::new(err)
                    .context(format!("failed to read response from {}", self.base_url))
            })?
            .to_vec();

        Ok(ApiResponse {
            status,
            body: bytes,
        })
    }

    pub async fn put_bytes(
        &self,
        path: &str,
        bytes: Vec<u8>,
        headers: &[(&'static str, HeaderValue)],
        bearer: Option<&str>,
    ) -> anyhow::Result<ApiResponse> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.put(&url).body(bytes);

        for (name, val) in headers {
            let header_name = HeaderName::from_static(name);
            req = req.header(header_name, val.clone());
        }

        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await.map_err(|err| {
            anyhow::Error::new(err)
                .context(format!("could not reach Cawide Cloud at {}", self.base_url))
        })?;

        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|err| {
                anyhow::Error::new(err)
                    .context(format!("failed to read response from {}", self.base_url))
            })?
            .to_vec();

        Ok(ApiResponse { status, body })
    }

    pub async fn get(&self, path: &str, bearer: Option<&str>) -> anyhow::Result<ApiResponse> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.get(&url);

        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await.map_err(|err| {
            anyhow::Error::new(err)
                .context(format!("could not reach Cawide Cloud at {}", self.base_url))
        })?;

        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|err| {
                anyhow::Error::new(err)
                    .context(format!("failed to read response from {}", self.base_url))
            })?
            .to_vec();

        Ok(ApiResponse { status, body })
    }

    pub async fn delete(&self, path: &str, bearer: Option<&str>) -> anyhow::Result<ApiResponse> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.delete(&url);

        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await.map_err(|err| {
            anyhow::Error::new(err)
                .context(format!("could not reach Cawide Cloud at {}", self.base_url))
        })?;

        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|err| {
                anyhow::Error::new(err)
                    .context(format!("failed to read response from {}", self.base_url))
            })?
            .to_vec();

        Ok(ApiResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_config_resolve() {
        assert_eq!(
            CloudConfig::resolve(None).base_url,
            "https://api.cawide.dev"
        );
        assert_eq!(
            CloudConfig::resolve(Some("https://staging.example/".into())).base_url,
            "https://staging.example"
        );
    }
}
