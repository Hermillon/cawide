//! Integration tests for Forge RPC engine (C0 - C8) using MockServer HTTP fixture.

mod common;

use cawide_protocol::types::{
    ForgeAccountOp, ForgeAccountReply, ForgeCheckBucket, ForgeErrorKind, ForgeKind, ForgePrFilter,
    ForgePrStateChange, ForgeRepoOp, ForgeRepoReply, ForgeScheme,
};
use common::{Env, MockServer};
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn test_forge_accounts_and_detect_host() {
    let mock = MockServer::start().await;
    let mock_host = format!("127.0.0.1:{}", mock.port());

    // Setup GitLab probe endpoint: GET /api/v4/version
    mock.on_json(
        reqwest::Method::GET,
        "/api/v4/version",
        StatusCode::OK,
        json!({ "version": "16.1.0" }).to_string(),
    );

    let mut env = Env::start().await;

    // DetectHost: mock returns gitlab version -> ForgeKind::GitLab
    let reply = env
        .forge_accounts_op(ForgeAccountOp::DetectHost {
            host: mock_host.clone(),
            scheme: ForgeScheme::Http,
        })
        .await
        .unwrap();

    let ForgeAccountReply::HostKind { kind } = reply else {
        panic!("expected HostKind, got {:?}", reply);
    };
    assert_eq!(kind, ForgeKind::GitLab);

    // Builtin detection: github.com -> ForgeKind::GitHub
    let reply = env
        .forge_accounts_op(ForgeAccountOp::DetectHost {
            host: "github.com".into(),
            scheme: ForgeScheme::Https,
        })
        .await
        .unwrap();

    let ForgeAccountReply::HostKind { kind } = reply else {
        panic!("expected HostKind");
    };
    assert_eq!(kind, ForgeKind::GitHub);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_forge_accounts_add_token_and_list() {
    let mock = MockServer::start().await;
    let mock_host = format!("127.0.0.1:{}", mock.port());

    // Mock verify token for GitLab: GET /api/v4/user
    mock.on_json(
        reqwest::Method::GET,
        "/api/v4/user",
        StatusCode::OK,
        json!({
            "id": 1234,
            "username": "alice",
            "name": "Alice Developer"
        })
        .to_string(),
    );

    let mut env = Env::start().await;

    // AddToken
    let reply = env
        .forge_accounts_op(ForgeAccountOp::AddToken {
            kind: ForgeKind::GitLab,
            scheme: ForgeScheme::Http,
            host: mock_host.clone(),
            login: Some("alice".into()),
            token: "glpat-secret123".into(), // gitleaks:allow
            azure_org: None,
            verify_url: None,
        })
        .await
        .unwrap();

    let ForgeAccountReply::Account { account } = reply else {
        panic!("expected Account, got {:?}", reply);
    };
    assert_eq!(account.login, "alice");
    assert_eq!(account.host, mock_host);
    assert!(account.is_default);

    // List accounts
    let reply = env.forge_accounts_op(ForgeAccountOp::List).await.unwrap();
    let ForgeAccountReply::Accounts { state } = reply else {
        panic!("expected Accounts");
    };
    assert_eq!(state.accounts.len(), 1);
    assert_eq!(state.accounts[0].login, "alice");

    // Remove account
    let acct_id = account.id.clone();
    let reply = env
        .forge_accounts_op(ForgeAccountOp::Remove {
            account_id: acct_id,
        })
        .await
        .unwrap();
    assert_eq!(reply, ForgeAccountReply::Done);

    // List should now be empty
    let reply = env.forge_accounts_op(ForgeAccountOp::List).await.unwrap();
    let ForgeAccountReply::Accounts { state } = reply else {
        panic!("expected Accounts");
    };
    assert!(state.accounts.is_empty());

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_forge_repo_operations_mocked() {
    let mock = MockServer::start().await;
    let mock_host = format!("127.0.0.1:{}", mock.port());

    let mut env = Env::start().await;
    env.init_repo();

    // Add git remote pointing to mock server
    let remote_url = format!("http://{mock_host}/myorg/myrepo.git");
    env.git(&["remote", "add", "origin", &remote_url]);

    // Mock verify endpoint for Gitea token
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/user",
        StatusCode::OK,
        json!({
            "id": 42,
            "username": "gitea-user",
            "full_name": "Gitea User"
        })
        .to_string(),
    );

    // Add token for mock host
    env.forge_accounts_op(ForgeAccountOp::AddToken {
        kind: ForgeKind::Gitea,
        scheme: ForgeScheme::Http,
        host: mock_host.clone(),
        login: Some("gitea-user".into()),
        token: "gtea-token".into(),
        azure_org: None,
        verify_url: None,
    })
    .await
    .unwrap();

    // Mock Gitea endpoints:
    // 1. GET /api/v1/repos/myorg/myrepo
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo",
        StatusCode::OK,
        json!({
            "id": 1,
            "name": "myrepo",
            "html_url": format!("http://{mock_host}/myorg/myrepo"),
            "default_branch": "main",
            "permissions": { "push": true, "admin": true }
        })
        .to_string(),
    );

    // 2. GET /api/v1/repos/myorg/myrepo/pulls?state=open&limit=30
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls?state=open&sort=recentupdate&limit=50",
        StatusCode::OK,
        json!([
            {
                "number": 1,
                "title": "Add feature X",
                "state": "open",
                "draft": false,
                "user": { "username": "alice" },
                "head": { "ref": "feat-x" },
                "base": { "ref": "main" },
                "updated_at": "2026-03-30T10:00:00Z",
                "html_url": format!("http://{mock_host}/myorg/myrepo/pulls/1")
            }
        ])
        .to_string(),
    );

    // 3. GET /api/v1/repos/myorg/myrepo/pulls/1
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls/1",
        StatusCode::OK,
        json!({
            "number": 1,
            "title": "Add feature X",
            "body": "PR description here",
            "state": "open",
            "draft": false,
            "user": { "username": "alice" },
            "head": { "ref": "feat-x", "sha": "0123456789abcdef" },
            "base": { "ref": "main" },
            "updated_at": "2026-03-30T10:00:00Z",
            "created_at": "2026-03-30T09:00:00Z",
            "html_url": format!("http://{mock_host}/myorg/myrepo/pulls/1"),
            "mergeable": true
        })
        .to_string(),
    );

    // 4. GET /api/v1/repos/myorg/myrepo/pulls/1/commits
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls/1/commits",
        StatusCode::OK,
        json!([]).to_string(),
    );

    // 5. GET /api/v1/repos/myorg/myrepo/pulls/1/reviews
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls/1/reviews",
        StatusCode::OK,
        json!([]).to_string(),
    );

    // 6. GET /api/v1/repos/myorg/myrepo/issues/1/comments
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/issues/1/comments",
        StatusCode::OK,
        json!([]).to_string(),
    );

    // Test Repository operation
    let reply = env.forge_op(None, ForgeRepoOp::Repository).await.unwrap();

    let ForgeRepoReply::Repository { repository } = reply else {
        panic!("expected Repository, got {:?}", reply);
    };
    assert_eq!(repository.name, "myrepo");
    assert_eq!(repository.default_branch, "main");
    assert_eq!(repository.kind, ForgeKind::Gitea);

    // Test ListPullRequests
    let reply = env
        .forge_op(
            None,
            ForgeRepoOp::ListPullRequests {
                filter: ForgePrFilter::Open,
                limit: 30,
            },
        )
        .await
        .unwrap();

    let ForgeRepoReply::PullRequests { pull_requests } = reply else {
        panic!("expected PullRequests, got {:?}", reply);
    };
    assert_eq!(pull_requests.len(), 1);
    assert_eq!(pull_requests[0].number, 1);
    assert_eq!(pull_requests[0].title, "Add feature X");

    // Test PullRequest detail
    let reply = env
        .forge_op(None, ForgeRepoOp::PullRequest { number: 1 })
        .await
        .unwrap();

    let ForgeRepoReply::PullRequest { detail } = reply else {
        panic!("expected PullRequest, got {:?}", reply);
    };
    assert_eq!(detail.summary.number, 1);
    assert_eq!(detail.body, "PR description here");

    // Test SetState (Close PR)
    mock.on_json(
        reqwest::Method::PATCH,
        "/api/v1/repos/myorg/myrepo/pulls/1",
        StatusCode::OK,
        json!({ "state": "closed" }).to_string(),
    );

    let reply = env
        .forge_op(
            None,
            ForgeRepoOp::SetState {
                number: 1,
                change: ForgePrStateChange::Close,
            },
        )
        .await
        .unwrap();
    assert_eq!(reply, ForgeRepoReply::Done);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ssh_key_generation_and_storage() {
    let mut env = Env::start().await;

    // SshPublicKey creates key if missing
    let reply = env
        .forge_accounts_op(ForgeAccountOp::SshPublicKey)
        .await
        .unwrap();

    let ForgeAccountReply::SshKey { key } = reply else {
        panic!("expected SshKey");
    };
    assert!(key.public_key.starts_with("ssh-ed25519 "));
    assert!(!key.fingerprint.is_empty());

    // Calling it again returns identical key
    let reply2 = env
        .forge_accounts_op(ForgeAccountOp::SshPublicKey)
        .await
        .unwrap();
    let ForgeAccountReply::SshKey { key: key2 } = reply2 else {
        panic!("expected SshKey");
    };
    assert_eq!(key.public_key, key2.public_key);
    assert_eq!(key.fingerprint, key2.fingerprint);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_forge_fallback_to_imported_account_when_selector_none() {
    let mock = MockServer::start().await;
    let mock_host = format!("127.0.0.1:{}", mock.port());

    // Create fake gh binary
    let tmp = tempfile::tempdir().unwrap();
    let gh_path = tmp.path().join("gh");
    let script = r#"#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
    cat <<'EOF'
{
  "hosts": {
    "github.com": [
      {
        "login": "gh-fallback-user",
        "state": "success",
        "active": true
      }
    ]
  }
}
EOF
elif [ "$1" = "auth" ] && [ "$2" = "token" ]; then
    echo "ghp-mock-fallback-token"
fi
"#;
    std::fs::write(&gh_path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut endpoint_overrides = std::collections::HashMap::new();
    endpoint_overrides.insert("github.com".to_string(), format!("http://{mock_host}"));
    endpoint_overrides.insert("api.github.com".to_string(), format!("http://{mock_host}"));
    let forge_config = cawide_host::forge::ForgeHostConfig {
        client_ids: std::collections::HashMap::new(),
        helper_exe: None,
        endpoint_overrides,
        cli_search_path: Some(tmp.path().display().to_string()),
    };
    let mut env = Env::start_with_forge(forge_config).await;
    env.init_repo();

    // Add git remote for github.com
    env.git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/myorg/myrepo.git",
    ]);

    // Mock GitHub endpoints
    mock.on_json(
        reqwest::Method::GET,
        "/repos/myorg/myrepo",
        StatusCode::OK,
        json!({
            "id": 100,
            "name": "myrepo",
            "html_url": "https://github.com/myorg/myrepo",
            "default_branch": "main",
            "permissions": { "push": true, "admin": true }
        })
        .to_string(),
    );

    mock.on_json(
        reqwest::Method::POST,
        "/graphql",
        StatusCode::OK,
        json!({
            "data": {
                "search": {
                    "nodes": []
                }
            }
        })
        .to_string(),
    );
    // Call ListPullRequests with account: None (no store account added)
    let reply = env
        .forge_op(
            None,
            ForgeRepoOp::ListPullRequests {
                filter: ForgePrFilter::Open,
                limit: 30,
            },
        )
        .await
        .unwrap();

    let ForgeRepoReply::PullRequests { pull_requests } = reply else {
        panic!("expected PullRequests, got {:?}", reply);
    };
    assert!(pull_requests.is_empty());

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_forge_pull_request_with_checks_gitea() {
    let mock = MockServer::start().await;
    let mock_host = format!("127.0.0.1:{}", mock.port());

    let mut env = Env::start().await;
    env.init_repo();

    let remote_url = format!("http://{mock_host}/myorg/myrepo.git");
    env.git(&["remote", "add", "origin", &remote_url]);

    // Mock verify endpoint for Gitea token
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/user",
        StatusCode::OK,
        json!({
            "id": 42,
            "username": "gitea-user",
            "full_name": "Gitea User"
        })
        .to_string(),
    );

    // Add token for mock host
    env.forge_accounts_op(ForgeAccountOp::AddToken {
        kind: ForgeKind::Gitea,
        scheme: ForgeScheme::Http,
        host: mock_host.clone(),
        login: Some("gitea-user".into()),
        token: "gtea-token".into(),
        azure_org: None,
        verify_url: None,
    })
    .await
    .unwrap();

    // Mock Gitea repo endpoints:
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo",
        StatusCode::OK,
        json!({
            "id": 1,
            "name": "myrepo",
            "html_url": format!("http://{mock_host}/myorg/myrepo"),
            "default_branch": "main",
            "permissions": { "push": true, "admin": true }
        })
        .to_string(),
    );

    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls/1",
        StatusCode::OK,
        json!({
            "number": 1,
            "title": "Add feature X",
            "body": "PR description here",
            "state": "open",
            "draft": false,
            "user": { "username": "alice" },
            "head": { "ref": "feat-x", "sha": "0123456789abcdef" },
            "base": { "ref": "main" },
            "updated_at": "2026-03-30T10:00:00Z",
            "created_at": "2026-03-30T09:00:00Z",
            "html_url": format!("http://{mock_host}/myorg/myrepo/pulls/1"),
            "mergeable": true
        })
        .to_string(),
    );

    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls/1/commits",
        StatusCode::OK,
        json!([]).to_string(),
    );

    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/pulls/1/reviews",
        StatusCode::OK,
        json!([]).to_string(),
    );

    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/issues/1/comments",
        StatusCode::OK,
        json!([]).to_string(),
    );

    let success_status_body = json!({
        "state": "success",
        "statuses": [
            {
                "context": "ci/test",
                "status": "success",
                "target_url": "http://ci.example/1",
                "description": "all tests passed",
                "created_at": "2026-03-30T09:05:00Z"
            }
        ]
    })
    .to_string();

    // 1. Mock combined status success -> PullRequestWithChecks returns detail and 1 check.
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/commits/0123456789abcdef/status",
        StatusCode::OK,
        success_status_body.clone(),
    );

    let reply = env
        .forge_op(None, ForgeRepoOp::PullRequestWithChecks { number: 1 })
        .await
        .unwrap();
    let ForgeRepoReply::PullRequestWithChecks { detail, checks } = reply else {
        panic!("expected PullRequestWithChecks, got {:?}", reply);
    };
    assert_eq!(detail.summary.number, 1);
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].name, "ci/test");
    assert_eq!(checks[0].bucket, ForgeCheckBucket::Pass);

    // 2. Mock 403 Forbidden -> reply OK, checks empty, detail present.
    mock.on(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/commits/0123456789abcdef/status",
        StatusCode::FORBIDDEN,
        HeaderMap::new(),
        "forbidden",
    );

    let reply = env
        .forge_op(None, ForgeRepoOp::PullRequestWithChecks { number: 1 })
        .await
        .unwrap();
    let ForgeRepoReply::PullRequestWithChecks { detail, checks } = reply else {
        panic!("expected PullRequestWithChecks, got {:?}", reply);
    };
    assert_eq!(detail.summary.number, 1);
    assert!(checks.is_empty(), "expected empty checks on soft failure");

    // 3. Mock 429 Too Many Requests -> env.forge_op returns Err with kind RateLimited.
    mock.on(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/commits/0123456789abcdef/status",
        StatusCode::TOO_MANY_REQUESTS,
        HeaderMap::new(),
        "rate limited",
    );

    let err = env
        .forge_op(None, ForgeRepoOp::PullRequestWithChecks { number: 1 })
        .await
        .unwrap_err();
    assert_eq!(err.kind, ForgeErrorKind::RateLimited);

    // 4. Re-register success mock, legacy op Checks { number: 1 } returns 1 check.
    mock.on_json(
        reqwest::Method::GET,
        "/api/v1/repos/myorg/myrepo/commits/0123456789abcdef/status",
        StatusCode::OK,
        success_status_body,
    );

    let reply = env
        .forge_op(None, ForgeRepoOp::Checks { number: 1 })
        .await
        .unwrap();
    let ForgeRepoReply::Checks { checks } = reply else {
        panic!("expected Checks, got {:?}", reply);
    };
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].name, "ci/test");

    env.shutdown().await;
}
