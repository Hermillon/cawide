pub mod azure;
pub mod bitbucket;
pub mod gitea;
pub mod github;
pub mod gitlab;

use cawide_protocol::types::{
    ForgeCheck, ForgeCreateRequest, ForgeError, ForgeErrorKind, ForgeMergeRequest, ForgePrDetail,
    ForgePrFile, ForgePrFilter, ForgePrStateChange, ForgePrSummary, ForgeRepository,
    ForgeReviewSubmission, ForgeReviewThread, GitFileDiff,
};

pub struct CheckoutSource {
    pub fetch_from: String,
    pub refspec: String,
    pub local_branch: String,
}

pub enum Adapter<'a> {
    GitHub(github::GitHubAdapter<'a>),
    GitLab(gitlab::GitLabAdapter<'a>),
    Gitea(gitea::GiteaAdapter<'a>),
    Bitbucket(bitbucket::BitbucketAdapter<'a>),
    Azure(azure::AzureAdapter<'a>),
}

impl<'a> Adapter<'a> {
    pub async fn repository(&self) -> Result<ForgeRepository, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.repository().await,
            Adapter::GitLab(a) => a.repository().await,
            Adapter::Gitea(a) => a.repository().await,
            Adapter::Bitbucket(a) => a.repository().await,
            Adapter::Azure(a) => a.repository().await,
        }
    }

    pub async fn current_pull_request(
        &self,
        branch: &str,
    ) -> Result<Option<ForgePrSummary>, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.current_pull_request(branch).await,
            Adapter::GitLab(a) => a.current_pull_request(branch).await,
            Adapter::Gitea(a) => a.current_pull_request(branch).await,
            Adapter::Bitbucket(a) => a.current_pull_request(branch).await,
            Adapter::Azure(a) => a.current_pull_request(branch).await,
        }
    }

    pub async fn list(
        &self,
        filter: ForgePrFilter,
        limit: u32,
    ) -> Result<Vec<ForgePrSummary>, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.list(filter, limit).await,
            Adapter::GitLab(a) => a.list(filter, limit).await,
            Adapter::Gitea(a) => a.list(filter, limit).await,
            Adapter::Bitbucket(a) => a.list(filter, limit).await,
            Adapter::Azure(a) => a.list(filter, limit).await,
        }
    }

    pub async fn detail(&self, number: u64) -> Result<ForgePrDetail, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.detail_with_checks(number).await.map(|(d, _)| d),
            Adapter::GitLab(a) => a.detail(number).await,
            Adapter::Gitea(a) => a.detail(number).await,
            Adapter::Bitbucket(a) => a.detail(number).await,
            Adapter::Azure(a) => a.detail(number).await,
        }
    }

    pub async fn checks(&self, number: u64) -> Result<Vec<ForgeCheck>, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.detail_with_checks(number).await.map(|(_, c)| c),
            Adapter::GitLab(a) => a.checks(number).await,
            Adapter::Gitea(a) => a.checks(number).await,
            Adapter::Bitbucket(a) => a.checks(number).await,
            Adapter::Azure(a) => a.checks(number).await,
        }
    }

    pub async fn detail_with_checks(
        &self,
        number: u64,
        include_checks: bool,
    ) -> Result<(ForgePrDetail, Vec<ForgeCheck>), ForgeError> {
        match self {
            Adapter::GitHub(a) => {
                let (d, c) = a.detail_with_checks(number).await?;
                let c = if include_checks { c } else { Vec::new() };
                Ok((d, c))
            }
            Adapter::Gitea(a) => {
                let d = a.detail(number).await?;
                let c = if include_checks {
                    soft_checks(a.statuses_for_head(&d.head_oid).await)?
                } else {
                    Vec::new()
                };
                Ok((d, c))
            }
            Adapter::GitLab(a) => {
                if !include_checks {
                    return Ok((a.detail(number).await?, Vec::new()));
                }
                let (d, c) = tokio::join!(a.detail(number), a.checks(number));
                Ok((d?, soft_checks(c)?))
            }
            Adapter::Bitbucket(a) => {
                if !include_checks {
                    return Ok((a.detail(number).await?, Vec::new()));
                }
                let (d, c) = tokio::join!(a.detail(number), a.checks(number));
                Ok((d?, soft_checks(c)?))
            }
            Adapter::Azure(a) => {
                if !include_checks {
                    return Ok((a.detail(number).await?, Vec::new()));
                }
                let (d, c) = tokio::join!(a.detail(number), a.checks(number));
                Ok((d?, soft_checks(c)?))
            }
        }
    }

    pub async fn files(&self, number: u64, head_oid: &str) -> Result<Vec<ForgePrFile>, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.files(number, head_oid).await,
            Adapter::GitLab(a) => a.files(number, head_oid).await,
            Adapter::Gitea(a) => a.files(number, head_oid).await,
            Adapter::Bitbucket(a) => a.files(number, head_oid).await,
            Adapter::Azure(a) => a.files(number, head_oid).await,
        }
    }

    pub async fn file_diff(
        &self,
        number: u64,
        path: &str,
        head_oid: &str,
    ) -> Result<GitFileDiff, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.file_diff(number, path, head_oid).await,
            Adapter::GitLab(a) => a.file_diff(number, path, head_oid).await,
            Adapter::Gitea(a) => a.file_diff(number, path, head_oid).await,
            Adapter::Bitbucket(a) => a.file_diff(number, path, head_oid).await,
            Adapter::Azure(a) => a.file_diff(number, path, head_oid).await,
        }
    }

    pub async fn threads(&self, number: u64) -> Result<Vec<ForgeReviewThread>, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.threads(number).await,
            Adapter::GitLab(a) => a.threads(number).await,
            Adapter::Gitea(a) => a.threads(number).await,
            Adapter::Bitbucket(a) => a.threads(number).await,
            Adapter::Azure(a) => a.threads(number).await,
        }
    }

    pub async fn submit_review(&self, review: &ForgeReviewSubmission) -> Result<(), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.submit_review(review).await,
            Adapter::GitLab(a) => a.submit_review(review).await,
            Adapter::Gitea(a) => a.submit_review(review).await,
            Adapter::Bitbucket(a) => a.submit_review(review).await,
            Adapter::Azure(a) => a.submit_review(review).await,
        }
    }

    pub async fn reply(&self, number: u64, thread_id: &str, body: &str) -> Result<(), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.reply(number, thread_id, body).await,
            Adapter::GitLab(a) => a.reply(number, thread_id, body).await,
            Adapter::Gitea(a) => a.reply(number, thread_id, body).await,
            Adapter::Bitbucket(a) => a.reply(number, thread_id, body).await,
            Adapter::Azure(a) => a.reply(number, thread_id, body).await,
        }
    }

    pub async fn resolve(
        &self,
        number: u64,
        thread_id: &str,
        resolved: bool,
    ) -> Result<(), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.resolve(number, thread_id, resolved).await,
            Adapter::GitLab(a) => a.resolve(number, thread_id, resolved).await,
            Adapter::Gitea(a) => a.resolve(number, thread_id, resolved).await,
            Adapter::Bitbucket(a) => a.resolve(number, thread_id, resolved).await,
            Adapter::Azure(a) => a.resolve(number, thread_id, resolved).await,
        }
    }

    pub async fn comment(&self, number: u64, body: &str) -> Result<(), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.comment(number, body).await,
            Adapter::GitLab(a) => a.comment(number, body).await,
            Adapter::Gitea(a) => a.comment(number, body).await,
            Adapter::Bitbucket(a) => a.comment(number, body).await,
            Adapter::Azure(a) => a.comment(number, body).await,
        }
    }

    pub async fn merge(&self, request: &ForgeMergeRequest) -> Result<(), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.merge(request).await,
            Adapter::GitLab(a) => a.merge(request).await,
            Adapter::Gitea(a) => a.merge(request).await,
            Adapter::Bitbucket(a) => a.merge(request).await,
            Adapter::Azure(a) => a.merge(request).await,
        }
    }

    pub async fn create(
        &self,
        request: &ForgeCreateRequest,
        head_spec: &str,
    ) -> Result<(u64, String), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.create(request, head_spec).await,
            Adapter::GitLab(a) => a.create(request, head_spec).await,
            Adapter::Gitea(a) => a.create(request, head_spec).await,
            Adapter::Bitbucket(a) => a.create(request, head_spec).await,
            Adapter::Azure(a) => a.create(request, head_spec).await,
        }
    }

    pub async fn set_state(
        &self,
        number: u64,
        change: ForgePrStateChange,
    ) -> Result<(), ForgeError> {
        match self {
            Adapter::GitHub(a) => a.set_state(number, change).await,
            Adapter::GitLab(a) => a.set_state(number, change).await,
            Adapter::Gitea(a) => a.set_state(number, change).await,
            Adapter::Bitbucket(a) => a.set_state(number, change).await,
            Adapter::Azure(a) => a.set_state(number, change).await,
        }
    }

    pub async fn checkout_source(&self, number: u64) -> Result<CheckoutSource, ForgeError> {
        match self {
            Adapter::GitHub(a) => a.checkout_source(number).await,
            Adapter::GitLab(a) => a.checkout_source(number).await,
            Adapter::Gitea(a) => a.checkout_source(number).await,
            Adapter::Bitbucket(a) => a.checkout_source(number).await,
            Adapter::Azure(a) => a.checkout_source(number).await,
        }
    }
}
fn soft_checks(r: Result<Vec<ForgeCheck>, ForgeError>) -> Result<Vec<ForgeCheck>, ForgeError> {
    match r {
        Ok(v) => Ok(v),
        Err(e)
            if e.kind == ForgeErrorKind::RateLimited
                || e.kind == ForgeErrorKind::NotAuthenticated =>
        {
            Err(e)
        }
        Err(e) => {
            tracing::warn!(
                kind = ?e.kind,
                message = %e.message,
                "forge checks unavailable; returning detail without checks"
            );
            Ok(Vec::new())
        }
    }
}
