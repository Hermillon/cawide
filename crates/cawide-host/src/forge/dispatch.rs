use super::adapters::{
    azure::AzureAdapter, bitbucket::BitbucketAdapter, gitea::GiteaAdapter, github::GitHubAdapter,
    gitlab::GitLabAdapter, Adapter,
};
use super::checkout::run_checkout;
use super::create::{create_defaults, get_head_spec};
use super::repo::{detect_kind, resolve_repo};
use super::store::{with_locked_store, StoreAccount};
use super::ForgeService;
use crate::rpc::git::GitEngine;
use cawide_protocol::types::{
    ForgeAccountOp, ForgeAccountReply, ForgeError, ForgeErrorKind, ForgeKind, ForgeRepoOp,
    ForgeRepoReply, ForgeReviewEvent, ForgeReviewSubmission,
};
use std::path::Path;

pub async fn handle_accounts(
    service: &ForgeService,
    op: ForgeAccountOp,
) -> Result<ForgeAccountReply, ForgeError> {
    match op {
        ForgeAccountOp::List => {
            let state = super::accounts::list(
                service.config_dir(),
                &service.config.client_ids,
                service.config.cli_search_path.as_deref(),
            )
            .await?;
            Ok(ForgeAccountReply::Accounts { state })
        }
        ForgeAccountOp::DetectHost { host, scheme } => {
            super::accounts::validate_host(&host)?;
            let kind = detect_kind(service.http(), &host, scheme, &[]).await;
            Ok(ForgeAccountReply::HostKind { kind })
        }
        ForgeAccountOp::SignInStart { kind, host } => {
            super::accounts::validate_host(&host)?;
            let challenge = super::oauth::start_sign_in(
                service.http(),
                &service.config.client_ids,
                kind,
                &host,
            )
            .await?;
            Ok(ForgeAccountReply::Challenge { challenge })
        }
        ForgeAccountOp::SignInPoll { session_id } => {
            let state = super::oauth::poll_sign_in(
                service.http(),
                &service.config.client_ids,
                service.config_dir(),
                &session_id,
            )
            .await?;
            Ok(ForgeAccountReply::SignInState { state })
        }
        ForgeAccountOp::SignInCancel { session_id } => {
            super::oauth::cancel_sign_in(&session_id)?;
            Ok(ForgeAccountReply::Done)
        }
        ForgeAccountOp::AddToken {
            kind,
            scheme,
            host,
            login,
            token,
            azure_org,
            verify_url,
        } => {
            let account = super::accounts::add_token(
                service.http(),
                service.config_dir(),
                kind,
                scheme,
                &host,
                login,
                &token,
                azure_org,
                verify_url,
            )
            .await?;
            Ok(ForgeAccountReply::Account { account })
        }
        ForgeAccountOp::Remove { account_id } => {
            super::accounts::remove(service.config_dir(), &account_id)?;
            Ok(ForgeAccountReply::Done)
        }
        ForgeAccountOp::SetDefault { account_id } => {
            super::accounts::set_default(service.config_dir(), &account_id)?;
            Ok(ForgeAccountReply::Done)
        }
        ForgeAccountOp::SetTerminalHelper { host, enabled } => {
            super::accounts::validate_host(&host)?;
            super::accounts::set_terminal_helper(service.config_dir(), &host, enabled)?;
            Ok(ForgeAccountReply::Done)
        }
        ForgeAccountOp::SshPublicKey => {
            let key = super::ssh::get_ssh_public_key(service.config_dir()).await?;
            Ok(ForgeAccountReply::SshKey { key })
        }
        ForgeAccountOp::UploadSshKey { account_id, title } => {
            upload_ssh_key(service, &account_id, &title).await?;
            Ok(ForgeAccountReply::Done)
        }
        ForgeAccountOp::ScanHostKey { host, port } => {
            super::accounts::validate_host(&host)?;
            let keys = super::ssh::scan_host_key(&host, port).await?;
            Ok(ForgeAccountReply::HostKeys { keys })
        }
        ForgeAccountOp::TrustHostKey { host, port, lines } => {
            super::accounts::validate_host(&host)?;
            super::ssh::trust_host_key(service.config_dir(), &host, port, lines).await?;
            Ok(ForgeAccountReply::Done)
        }
    }
}

pub async fn handle_repo(
    service: &ForgeService,
    engine: &GitEngine,
    account_selector: Option<&str>,
    op: ForgeRepoOp,
) -> Result<ForgeRepoReply, ForgeError> {
    // 1. Get known accounts for remote candidate detection
    let known_accounts = with_locked_store(service.config_dir(), |store| {
        let mut list = Vec::new();
        for a in &store.accounts {
            let k = match a.kind.as_str() {
                "github" => ForgeKind::GitHub,
                "gitlab" => ForgeKind::GitLab,
                "gitea" => ForgeKind::Gitea,
                "bitbucket" => ForgeKind::Bitbucket,
                "azuredevops" | "azure" => ForgeKind::AzureDevOps,
                _ => ForgeKind::Generic,
            };
            list.push((a.host.clone(), k));
        }
        Ok(list)
    })
    .unwrap_or_default();

    // 2. Resolve repo
    let resolved = resolve_repo(engine, service.http(), &known_accounts).await?;

    // 3. Resolve account token
    let acct = resolve_account(
        service.config_dir(),
        &resolved.host,
        account_selector,
        service.config.cli_search_path.as_deref(),
    )
    .await?;
    // 4. Build adapter
    let adapter = match resolved.kind {
        ForgeKind::GitHub => Adapter::GitHub(GitHubAdapter {
            http: service.http(),
            scheme: &acct.scheme,
            host: &resolved.host,
            namespace: &resolved.namespace,
            name: &resolved.name,
            token: &acct.token,
            remote_name: &resolved.remote_name,
        }),
        ForgeKind::GitLab => Adapter::GitLab(GitLabAdapter {
            http: service.http(),
            scheme: &acct.scheme,
            host: &resolved.host,
            namespace: &resolved.namespace,
            name: &resolved.name,
            token: &acct.token,
            remote_name: &resolved.remote_name,
        }),
        ForgeKind::Gitea => Adapter::Gitea(GiteaAdapter {
            http: service.http(),
            scheme: &acct.scheme,
            host: &resolved.host,
            namespace: &resolved.namespace,
            name: &resolved.name,
            token: &acct.token,
            remote_name: &resolved.remote_name,
        }),
        ForgeKind::Bitbucket => Adapter::Bitbucket(BitbucketAdapter {
            http: service.http(),
            host: &resolved.host,
            namespace: &resolved.namespace,
            name: &resolved.name,
            login: &acct.login,
            token: &acct.token,
            remote_name: &resolved.remote_name,
        }),
        ForgeKind::AzureDevOps => Adapter::Azure(AzureAdapter {
            http: service.http(),
            scheme: &acct.scheme,
            host: &resolved.host,
            namespace: &resolved.namespace,
            name: &resolved.name,
            token: &acct.token,
            account_user_id: acct.user_id.as_deref(),
            account_azure_org: acct.azure_org.as_deref(),
            remote_name: &resolved.remote_name,
            engine,
        }),
        ForgeKind::Generic => {
            return Err(ForgeError {
                kind: ForgeErrorKind::NoForgeRemote,
                message: "plain git remote has no forge PR/MR support".into(),
                git_kind: None,
                host: Some(resolved.host),
                port: None,
            });
        }
    };

    // 5. Check capability
    let caps = super::capabilities::default_capabilities(resolved.kind.clone());
    match &op {
        ForgeRepoOp::SubmitReview { review } => {
            validate_review_submission(review, &caps)?;
            if review.event == ForgeReviewEvent::RequestChanges && !caps.request_changes {
                return Err(unsupported("request changes"));
            }
        }
        ForgeRepoOp::ReplyToThread { .. } if !caps.reply_to_threads => {
            return Err(unsupported("reply to threads"));
        }
        ForgeRepoOp::ResolveThread { .. } if !caps.resolve_threads => {
            return Err(unsupported("resolve threads"));
        }
        ForgeRepoOp::Checks { .. } if !caps.checks => {
            return Err(unsupported("checks"));
        }
        _ => {}
    }

    match op {
        ForgeRepoOp::Repository => {
            let repository = adapter.repository().await?;
            Ok(ForgeRepoReply::Repository { repository })
        }
        ForgeRepoOp::CurrentPullRequest { branch } => {
            let pull_request = adapter.current_pull_request(&branch).await?;
            Ok(ForgeRepoReply::CurrentPullRequest { pull_request })
        }
        ForgeRepoOp::ListPullRequests { filter, limit } => {
            let pull_requests = adapter.list(filter, limit).await?;
            Ok(ForgeRepoReply::PullRequests { pull_requests })
        }
        ForgeRepoOp::PullRequest { number } => {
            let detail = adapter.detail(number).await?;
            Ok(ForgeRepoReply::PullRequest { detail })
        }
        ForgeRepoOp::Checks { number } => {
            let checks = adapter.checks(number).await?;
            Ok(ForgeRepoReply::Checks { checks })
        }
        ForgeRepoOp::PullRequestWithChecks { number } => {
            let (detail, checks) = adapter.detail_with_checks(number, caps.checks).await?;
            Ok(ForgeRepoReply::PullRequestWithChecks { detail, checks })
        }
        ForgeRepoOp::Files { number, head_oid } => {
            let files = adapter.files(number, &head_oid).await?;
            Ok(ForgeRepoReply::Files { files })
        }
        ForgeRepoOp::FileDiff {
            number,
            path,
            head_oid,
        } => {
            let diff = adapter.file_diff(number, &path, &head_oid).await?;
            Ok(ForgeRepoReply::FileDiff { diff })
        }
        ForgeRepoOp::ReviewThreads { number } => {
            let threads = adapter.threads(number).await?;
            Ok(ForgeRepoReply::ReviewThreads { threads })
        }
        ForgeRepoOp::SubmitReview { review } => {
            adapter.submit_review(&review).await?;
            Ok(ForgeRepoReply::Done)
        }
        ForgeRepoOp::ReplyToThread {
            number,
            thread_id,
            body,
        } => {
            adapter.reply(number, &thread_id, &body).await?;
            Ok(ForgeRepoReply::Done)
        }
        ForgeRepoOp::ResolveThread {
            number,
            thread_id,
            resolved,
        } => {
            adapter.resolve(number, &thread_id, resolved).await?;
            Ok(ForgeRepoReply::Done)
        }
        ForgeRepoOp::Comment { number, body } => {
            adapter.comment(number, &body).await?;
            Ok(ForgeRepoReply::Done)
        }
        ForgeRepoOp::Merge { request } => {
            adapter.merge(&request).await?;
            Ok(ForgeRepoReply::Done)
        }
        ForgeRepoOp::CreateDefaults { head_branch, base } => {
            let defaults =
                create_defaults(engine, &resolved, &head_branch, base.as_deref()).await?;
            Ok(ForgeRepoReply::CreateDefaults { defaults })
        }
        ForgeRepoOp::Create { request } => {
            let head_spec = get_head_spec(engine, &resolved, &request.head_branch).await?;
            let (number, url) = adapter.create(&request, &head_spec).await?;
            Ok(ForgeRepoReply::Created { number, url })
        }
        ForgeRepoOp::Checkout {
            number,
            reset_existing,
        } => {
            let source = adapter.checkout_source(number).await?;
            let local_branch = run_checkout(engine, &source, reset_existing).await?;
            Ok(ForgeRepoReply::CheckedOut { local_branch })
        }
        ForgeRepoOp::SetState { number, change } => {
            adapter.set_state(number, change).await?;
            Ok(ForgeRepoReply::Done)
        }
    }
}

fn unsupported(action: &str) -> ForgeError {
    ForgeError {
        kind: ForgeErrorKind::Unsupported,
        message: format!("{action} is not supported by this provider"),
        git_kind: None,
        host: None,
        port: None,
    }
}

fn validate_review_submission(
    review: &ForgeReviewSubmission,
    caps: &cawide_protocol::types::ForgeCapabilities,
) -> Result<(), ForgeError> {
    if review.event == ForgeReviewEvent::RequestChanges && review.body.trim().is_empty() {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "body is required when requesting changes".into(),
            git_kind: None,
            host: None,
            port: None,
        });
    }

    if review.event == ForgeReviewEvent::Comment
        && review.body.trim().is_empty()
        && review.threads.is_empty()
    {
        return Err(ForgeError {
            kind: ForgeErrorKind::InvalidArgument,
            message: "comment review requires a body or at least one thread comment".into(),
            git_kind: None,
            host: None,
            port: None,
        });
    }

    for t in &review.threads {
        if t.start.is_some() && !caps.multiline_comments {
            return Err(ForgeError {
                kind: ForgeErrorKind::InvalidArgument,
                message: "multiline comments are not supported by this provider".into(),
                git_kind: None,
                host: None,
                port: None,
            });
        }

        match t.side {
            cawide_protocol::types::ForgeDiffSide::Right => {
                if t.end.new_line.is_none() {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::InvalidArgument,
                        message: "right-side comments require new_line".into(),
                        git_kind: None,
                        host: None,
                        port: None,
                    });
                }
            }
            cawide_protocol::types::ForgeDiffSide::Left => {
                if t.end.old_line.is_none() {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::InvalidArgument,
                        message: "left-side comments require old_line".into(),
                        git_kind: None,
                        host: None,
                        port: None,
                    });
                }
            }
        }
    }

    Ok(())
}

async fn resolve_account(
    config_dir: &Path,
    host: &str,
    account_selector: Option<&str>,
    custom_path: Option<&str>,
) -> Result<StoreAccount, ForgeError> {
    // 1. Try Cawide store accounts
    let store_res = with_locked_store(config_dir, |store| {
        if let Some(sel) = account_selector {
            if let Some(acct) = store.accounts.iter().find(|a| a.id == sel) {
                if acct.host != host {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::InvalidArgument,
                        message: format!(
                            "account '{}' belongs to '{}', not '{}'",
                            sel, acct.host, host
                        ),
                        git_kind: None,
                        host: Some(host.to_string()),
                        port: None,
                    });
                }
                return Ok(Some(acct.clone()));
            }
        } else if let Some(acct) = store
            .accounts
            .iter()
            .find(|a| a.host == host && a.is_default)
        {
            return Ok(Some(acct.clone()));
        } else if let Some(acct) = store.accounts.iter().find(|a| a.host == host) {
            return Ok(Some(acct.clone()));
        }
        Ok(None)
    })?;

    if let Some(a) = store_res {
        return Ok(a);
    }

    // 2. Try imported account
    let store_accounts = with_locked_store(config_dir, |store| Ok(store.accounts.clone()))?;
    let has_cawide_default = |h: &str| store_accounts.iter().any(|a| a.host == h && a.is_default);
    let imported = super::import::list_imported_accounts(custom_path, &has_cawide_default).await;

    let chosen = if let Some(sel) = account_selector {
        if sel.starts_with("gh:") || sel.starts_with("glab:") || sel.starts_with("env:") {
            imported.iter().find(|a| a.id == sel && a.host == host)
        } else {
            None
        }
    } else {
        // Fallback when account_selector is None: look up imported accounts
        imported
            .iter()
            .find(|a| a.host == host && a.healthy && a.is_default)
            .or_else(|| imported.iter().find(|a| a.host == host && a.healthy))
            .or_else(|| imported.iter().find(|a| a.host == host && a.is_default))
            .or_else(|| imported.iter().find(|a| a.host == host))
    };

    if let Some(imp) = chosen {
        let token =
            super::import::fetch_imported_token(&imp.id, &imp.host, &imp.login, custom_path)
                .await?;
        let kind = match imp.kind {
            cawide_protocol::types::ForgeKind::GitLab => "gitlab",
            cawide_protocol::types::ForgeKind::Gitea => "gitea",
            _ => "github",
        };
        return Ok(StoreAccount {
            id: imp.id.clone(),
            kind: kind.to_string(),
            scheme: match imp.scheme {
                cawide_protocol::types::ForgeScheme::Http => "http".into(),
                cawide_protocol::types::ForgeScheme::Https => "https".into(),
            },
            host: host.to_string(),
            login: imp.login.clone(),
            token,
            refresh_token: None,
            expires_at: None,
            user_id: None,
            azure_org: None,
            is_default: imp.is_default,
            terminal_helper: imp.terminal_helper,
        });
    }

    if let Some(sel) = account_selector {
        if sel.starts_with("gh:") || sel.starts_with("glab:") || sel.starts_with("env:") {
            if let Some((prefix, rest)) = sel.split_once(':') {
                if let Some((imp_host, imp_login)) = rest.split_once(':') {
                    if imp_host == host {
                        let token = super::import::fetch_imported_token(
                            sel,
                            imp_host,
                            imp_login,
                            custom_path,
                        )
                        .await?;
                        let kind =
                            if prefix == "glab" || (prefix == "env" && host.contains("gitlab")) {
                                "gitlab"
                            } else {
                                "github"
                            };
                        return Ok(StoreAccount {
                            id: sel.to_string(),
                            kind: kind.to_string(),
                            scheme: "https".into(),
                            host: host.to_string(),
                            login: imp_login.to_string(),
                            token,
                            refresh_token: None,
                            expires_at: None,
                            user_id: None,
                            azure_org: None,
                            is_default: false,
                            terminal_helper: false,
                        });
                    }
                }
            }
        }
    }

    Err(ForgeError {
        kind: ForgeErrorKind::NotAuthenticated,
        message: format!("no account configured for host {host}"),
        git_kind: None,
        host: Some(host.to_string()),
        port: None,
    })
}

async fn upload_ssh_key(
    service: &ForgeService,
    account_id: &str,
    title: &str,
) -> Result<(), ForgeError> {
    let key = super::ssh::get_ssh_public_key(service.config_dir()).await?;
    let acct = with_locked_store(service.config_dir(), |store| {
        store
            .accounts
            .iter()
            .find(|a| a.id == account_id)
            .cloned()
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: format!("account {account_id} not found"),
                git_kind: None,
                host: None,
                port: None,
            })
    })?;

    match acct.kind.as_str() {
        "github" => {
            let url = service.http.url(&acct.host, "https", "/user/keys");
            let payload = serde_json::json!({
                "title": title,
                "key": key.public_key,
            });
            let rb = service
                .http
                .client()
                .post(&url)
                .header(reqwest::header::USER_AGENT, "cawide")
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", acct.token),
                )
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .json(&payload);
            let (status, _, _) = service.http.execute(rb, false).await?;
            if !status.is_success() {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: format!("failed to upload SSH key to GitHub: {status}"),
                    git_kind: None,
                    host: Some(acct.host),
                    port: None,
                });
            }
        }
        "gitlab" => {
            let url = service.http.url(&acct.host, "https", "/api/v4/user/keys");
            let payload = serde_json::json!({
                "title": title,
                "key": key.public_key,
            });
            let rb = service
                .http
                .client()
                .post(&url)
                .header(reqwest::header::USER_AGENT, "cawide")
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", acct.token),
                )
                .json(&payload);
            let (status, _, _) = service.http.execute(rb, false).await?;
            if !status.is_success() {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: format!("failed to upload SSH key to GitLab: {status}"),
                    git_kind: None,
                    host: Some(acct.host),
                    port: None,
                });
            }
        }
        "gitea" => {
            let url = service.http.url(&acct.host, "https", "/api/v1/user/keys");
            let payload = serde_json::json!({
                "title": title,
                "key": key.public_key,
            });
            let rb = service
                .http
                .client()
                .post(&url)
                .header(reqwest::header::USER_AGENT, "cawide")
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("token {}", acct.token),
                )
                .json(&payload);
            let (status, _, _) = service.http.execute(rb, false).await?;
            if !status.is_success() {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: format!("failed to upload SSH key to Gitea: {status}"),
                    git_kind: None,
                    host: Some(acct.host),
                    port: None,
                });
            }
        }
        "bitbucket" => {
            let uid = acct.user_id.unwrap_or(acct.login.clone());
            let url = service.http.url(
                "api.bitbucket.org",
                "https",
                &format!("/2.0/users/{uid}/ssh-keys"),
            );
            let payload = serde_json::json!({
                "label": title,
                "key": key.public_key,
            });
            let rb = service
                .http
                .client()
                .post(&url)
                .header(reqwest::header::USER_AGENT, "cawide")
                .basic_auth(&acct.login, Some(&acct.token))
                .json(&payload);
            let (status, _, _) = service.http.execute(rb, false).await?;
            if !status.is_success() {
                return Err(ForgeError {
                    kind: ForgeErrorKind::Other,
                    message: format!("failed to upload SSH key to Bitbucket: {status}"),
                    git_kind: None,
                    host: Some(acct.host),
                    port: None,
                });
            }
        }
        _ => {
            return Err(ForgeError {
                kind: ForgeErrorKind::Unsupported,
                message: "SSH key upload not supported for this provider".into(),
                git_kind: None,
                host: Some(acct.host),
                port: None,
            });
        }
    }

    Ok(())
}
