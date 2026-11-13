use bytes::Bytes;
use parking_lot::Mutex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: Method,
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

type MockResponse = (StatusCode, HeaderMap, Bytes);
type RouteMap = HashMap<(Method, String), MockResponse>;
type MockHandler = Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync>;

#[derive(Clone)]
pub struct MockServer {
    addr: SocketAddr,
    routes: Arc<Mutex<RouteMap>>,
    dynamic_routes: Arc<Mutex<Vec<(Method, String, MockHandler)>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    _shutdown: Arc<tokio::sync::broadcast::Sender<()>>,
}

impl MockServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let dynamic_routes = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let shutdown = Arc::new(shutdown_tx);

        let server_routes = Arc::clone(&routes);
        let server_dynamic = Arc::clone(&dynamic_routes);
        let server_requests = Arc::clone(&requests);
        let mut shutdown_rx = shutdown.subscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok((stream, _)) = listener.accept() => {
                        let r = Arc::clone(&server_routes);
                        let d = Arc::clone(&server_dynamic);
                        let reqs = Arc::clone(&server_requests);
                        tokio::spawn(async move {
                            let _ = handle_connection(stream, r, d, reqs).await;
                        });
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Self {
            addr,
            routes,
            dynamic_routes,
            requests,
            _shutdown: shutdown,
        }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn url(&self, path: &str) -> String {
        let path = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };
        format!("http://127.0.0.1:{}{path}", self.port())
    }

    pub fn on(
        &self,
        method: Method,
        path_and_query: impl Into<String>,
        status: StatusCode,
        headers: HeaderMap,
        body: impl Into<Bytes>,
    ) {
        let key = (method, path_and_query.into());
        self.routes
            .lock()
            .insert(key, (status, headers, body.into()));
    }

    pub fn on_json(
        &self,
        method: Method,
        path_and_query: impl Into<String>,
        status: StatusCode,
        json_body: impl Into<String>,
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = Bytes::from(json_body.into());
        self.on(method, path_and_query, status, headers, body);
    }

    pub fn on_dynamic(
        &self,
        method: Method,
        path_prefix: impl Into<String>,
        handler: impl Fn(&RecordedRequest) -> (StatusCode, HeaderMap, Bytes) + Send + Sync + 'static,
    ) {
        self.dynamic_routes
            .lock()
            .push((method, path_prefix.into(), Arc::new(handler)));
    }

    pub fn recorded_requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().clone()
    }

    pub fn clear_recorded(&self) {
        self.requests.lock().clear();
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    routes: Arc<Mutex<RouteMap>>,
    dynamic_routes: Arc<Mutex<Vec<(Method, String, MockHandler)>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk_buf = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk_buf).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk_buf[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = std::str::from_utf8(&buf[..pos])?;
            let mut lines = header_str.lines();

            let request_line = lines.next().unwrap_or("");
            let mut parts = request_line.split_whitespace();
            let method_str = parts.next().unwrap_or("GET");
            let method = Method::from_bytes(method_str.as_bytes())?;
            let path_and_query = parts.next().unwrap_or("/").to_string();

            let mut header_map = HeaderMap::new();
            let mut content_length = 0usize;

            for line in lines {
                if let Some((name, val)) = line.split_once(':') {
                    let name_trimmed = name.trim();
                    let val_trimmed = val.trim();
                    if let Ok(hname) = HeaderName::from_bytes(name_trimmed.as_bytes()) {
                        if let Ok(hval) = HeaderValue::from_str(val_trimmed) {
                            if hname == CONTENT_LENGTH {
                                content_length = val_trimmed.parse().unwrap_or(0);
                            }
                            header_map.append(hname, hval);
                        }
                    }
                }
            }

            // Read body if needed
            let body_start = pos + 4;
            let mut body_bytes = buf[body_start..].to_vec();
            while body_bytes.len() < content_length {
                let mut chunk = vec![0u8; content_length - body_bytes.len()];
                let read_n = stream.read(&mut chunk).await?;
                if read_n == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&chunk[..read_n]);
            }

            let recorded = RecordedRequest {
                method: method.clone(),
                path_and_query: path_and_query.clone(),
                headers: header_map,
                body: Bytes::from(body_bytes),
            };

            requests.lock().push(recorded.clone());

            // Lookup route
            let (status, resp_headers, resp_body) = {
                let lock = routes.lock();
                if let Some(resp) = lock.get(&(method.clone(), path_and_query.clone())) {
                    resp.clone()
                } else {
                    drop(lock);
                    let dyn_lock = dynamic_routes.lock();
                    let mut found = None;
                    for (m, prefix, handler) in dyn_lock.iter() {
                        if *m == method && path_and_query.starts_with(prefix) {
                            found = Some(handler(&recorded));
                            break;
                        }
                    }
                    found.unwrap_or_else(|| {
                        (
                            StatusCode::NOT_FOUND,
                            HeaderMap::new(),
                            Bytes::from_static(b"{\"message\":\"mock not found\"}"),
                        )
                    })
                }
            };

            let reason = status.canonical_reason().unwrap_or("OK");
            let mut resp_text = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);
            for (k, v) in resp_headers.iter() {
                resp_text.push_str(k.as_str());
                resp_text.push_str(": ");
                resp_text.push_str(v.to_str().unwrap_or(""));
                resp_text.push_str("\r\n");
            }
            resp_text.push_str(&format!("Content-Length: {}\r\n", resp_body.len()));
            resp_text.push_str("Connection: close\r\n\r\n");

            stream.write_all(resp_text.as_bytes()).await?;
            stream.write_all(&resp_body).await?;
            stream.flush().await?;
            break;
        }
    }

    Ok(())
}
