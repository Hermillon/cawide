//! Integration tests for Forge HTTP client: ETag cache and error classification.

mod common;

use bytes::Bytes;
use cawide_host::forge::http::ForgeHttp;
use cawide_protocol::types::ForgeErrorKind;
use common::MockServer;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, ETAG, IF_NONE_MATCH};
use reqwest::{Method, StatusCode};
use std::collections::HashMap;

#[tokio::test(flavor = "multi_thread")]
async fn test_etag_cache_304_served_as_200_with_cached_body() {
    let mock = MockServer::start().await;
    let path = "/test/etag/resource";
    let url = mock.url(path);

    mock.on_dynamic(Method::GET, path, |req| {
        if let Some(inm) = req.headers.get(IF_NONE_MATCH) {
            if inm == "\"etag-12345\"" {
                return (StatusCode::NOT_MODIFIED, HeaderMap::new(), Bytes::new());
            }
        }
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"etag-12345\""));
        (
            StatusCode::OK,
            headers,
            Bytes::from_static(b"cached payload data"),
        )
    });

    let http = ForgeHttp::new(HashMap::new());

    // First request: gets 200 and caches entry with etag
    let rb = http.client().get(&url);
    let (status, _, body) = http.execute(rb, false).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"cached payload data");

    // Second request: client sends If-None-Match, server replies 304, client returns 200 with cached body
    let rb = http.client().get(&url);
    let (status, _, body) = http.execute(rb, false).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"cached payload data");

    let requests = mock.recorded_requests();
    assert_eq!(requests.len(), 2);
    assert!(!requests[0].headers.contains_key(IF_NONE_MATCH));
    assert_eq!(
        requests[1].headers.get(IF_NONE_MATCH).unwrap(),
        "\"etag-12345\""
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_etag_token_isolation() {
    let mock = MockServer::start().await;
    let path = "/test/etag/auth-isolated";
    let url = mock.url(path);

    mock.on_dynamic(Method::GET, path, |_req| {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"etag-token-abc\""));
        (
            StatusCode::OK,
            headers,
            Bytes::from_static(b"user private data"),
        )
    });

    let http = ForgeHttp::new(HashMap::new());

    // First request with token 1
    let rb = http
        .client()
        .get(&url)
        .header(AUTHORIZATION, "Bearer token_1");
    let (status, _, _) = http.execute(rb, false).await.unwrap();
    assert_eq!(status, StatusCode::OK);

    // Second request with token 2 (must not use cached etag from token 1)
    let rb = http
        .client()
        .get(&url)
        .header(AUTHORIZATION, "Bearer token_2");
    let (status, _, _) = http.execute(rb, false).await.unwrap();
    assert_eq!(status, StatusCode::OK);

    let requests = mock.recorded_requests();
    assert_eq!(requests.len(), 2);
    assert!(
        !requests[1].headers.contains_key(IF_NONE_MATCH),
        "different authorization token must not reuse etag from previous token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_etag_post_untouched() {
    let mock = MockServer::start().await;
    let path = "/test/etag/post-endpoint";
    let url = mock.url(path);

    mock.on_dynamic(Method::POST, path, |_req| {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"etag-post\""));
        (
            StatusCode::OK,
            headers,
            Bytes::from_static(b"post response"),
        )
    });

    let http = ForgeHttp::new(HashMap::new());

    // First POST
    let rb = http.client().post(&url).body("data");
    let (status, _, _) = http.execute(rb, false).await.unwrap();
    assert_eq!(status, StatusCode::OK);

    // Cache should remain empty for POST
    assert_eq!(http.etags.lock().get(&url).map(|e| &e.body), None);

    // Second POST
    let rb = http.client().post(&url).body("data2");
    let (status, _, _) = http.execute(rb, false).await.unwrap();
    assert_eq!(status, StatusCode::OK);

    let requests = mock.recorded_requests();
    assert_eq!(requests.len(), 2);
    assert!(!requests[1].headers.contains_key(IF_NONE_MATCH));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_403_rate_limit_classification() {
    let mock = MockServer::start().await;
    let http = ForgeHttp::new(HashMap::new());

    // 1. 403 with x-ratelimit-remaining == "0"
    let p1 = "/rate-limit/remaining-zero";
    let mut h1 = HeaderMap::new();
    h1.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
    mock.on(
        Method::GET,
        p1,
        StatusCode::FORBIDDEN,
        h1,
        "API rate limit exceeded",
    );

    let err1 = http
        .execute(http.client().get(mock.url(p1)), false)
        .await
        .unwrap_err();
    assert_eq!(err1.kind, ForgeErrorKind::RateLimited);

    // 2. 403 with retry-after header
    let p2 = "/rate-limit/retry-after";
    let mut h2 = HeaderMap::new();
    h2.insert("retry-after", HeaderValue::from_static("60"));
    mock.on(
        Method::GET,
        p2,
        StatusCode::FORBIDDEN,
        h2,
        "Please slow down",
    );

    let err2 = http
        .execute(http.client().get(mock.url(p2)), false)
        .await
        .unwrap_err();
    assert_eq!(err2.kind, ForgeErrorKind::RateLimited);

    // 3. 403 with secondary rate limit message in body
    let p3 = "/rate-limit/body-message";
    mock.on(
        Method::GET,
        p3,
        StatusCode::FORBIDDEN,
        HeaderMap::new(),
        "You have triggered an abuse detection mechanism / secondary rate limit.",
    );

    let err3 = http
        .execute(http.client().get(mock.url(p3)), false)
        .await
        .unwrap_err();
    assert_eq!(err3.kind, ForgeErrorKind::RateLimited);

    // 4. 403 standard permission denied (no rate limit indicators)
    let p4 = "/rate-limit/permission-denied";
    mock.on(
        Method::GET,
        p4,
        StatusCode::FORBIDDEN,
        HeaderMap::new(),
        "You do not have permission to view this resource.",
    );

    let err4 = http
        .execute(http.client().get(mock.url(p4)), false)
        .await
        .unwrap_err();
    assert_eq!(err4.kind, ForgeErrorKind::PermissionDenied);
}
