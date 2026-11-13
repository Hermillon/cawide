use super::CheckoutSource;
use crate::forge::capabilities::default_capabilities;
use crate::forge::http::ForgeHttp;
use crate::forge::text::{cap_comment_body, cap_description, initial_reply_budget};
use cawide_protocol::types::{
    ForgeCheck, ForgeCheckBucket, ForgeChecksRollup, ForgeComment, ForgeCreateRequest,
    ForgeDiffSide, ForgeError, ForgeErrorKind, ForgeKind, ForgeMergeMethod, ForgeMergeRequest,
    ForgeMergeState, ForgeMergeable, ForgePrCommit, ForgePrDetail, ForgePrFile, ForgePrFilter,
    ForgePrState, ForgePrStateChange, ForgePrSummary, ForgeRepository, ForgeReview,
    ForgeReviewDecision, ForgeReviewEvent, ForgeReviewState, ForgeReviewSubmission,
    ForgeReviewThread, ForgeThreadComment, GitChange, GitFileDiff, MAX_FORGE_DIFF_BYTES,
    MAX_PR_FILES,
};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::StatusCode;
use serde_json::{json, Value};

pub struct GitHubAdapter<'a> {
    pub http: &'a ForgeHttp,
    pub scheme: &'a str,
    pub host: &'a str,
    pub namespace: &'a str,
    pub name: &'a str,
    pub token: &'a str,
    pub remote_name: &'a str,
}

impl<'a> GitHubAdapter<'a> {
    fn is_enterprise(&self) -> bool {
        self.host != "github.com"
    }

    fn rest_url(&self, path: &str) -> String {
        let clean = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };
        if self.is_enterprise() {
            self.http
                .url(self.host, self.scheme, &format!("/api/v3{clean}"))
        } else {
            self.http.url("api.github.com", "https", clean)
        }
    }

    fn graphql_url(&self) -> String {
        if self.is_enterprise() {
            self.http.url(self.host, self.scheme, "/api/graphql")
        } else {
            self.http.url("api.github.com", "https", "/graphql")
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static("cawide"));
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            h.insert(AUTHORIZATION, v);
        }
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        h.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        h
    }

    async fn graphql_raw(
        &self,
        query: &str,
        variables: Value,
    ) -> Result<(Value, Vec<Value>), ForgeError> {
        let url = self.graphql_url();
        let body = json!({
            "query": query,
            "variables": variables,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .json(&body);
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("GitHub GraphQL HTTP error: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let mut json: Value = serde_json::from_slice(&bytes).map_err(|e| ForgeError {
            kind: ForgeErrorKind::Other,
            message: e.to_string(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        let data = json.get_mut("data").map(Value::take).unwrap_or(Value::Null);
        let errors = json
            .get_mut("errors")
            .and_then(|e| e.as_array_mut().map(std::mem::take))
            .unwrap_or_default();

        Ok((data, errors))
    }

    async fn graphql(&self, query: &str, variables: Value) -> Result<Value, ForgeError> {
        let (data, errors) = self.graphql_raw(query, variables).await?;
        if !errors.is_empty() {
            let first = &errors[0];
            let err_type = first.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let msg = first
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("GraphQL error");
            let kind = graphql_error_kind(err_type);
            return Err(ForgeError {
                kind,
                message: msg.to_string(),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        Ok(data)
    }

    pub async fn repository(&self) -> Result<ForgeRepository, ForgeError> {
        let url = self.rest_url(&format!("/repos/{}/{}", self.namespace, self.name));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to fetch repository: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        let default_branch = json
            .get("default_branch")
            .and_then(|v| v.as_str())
            .unwrap_or("main")
            .to_string();
        let web_url = json
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let permissions = json.get("permissions");
        let viewer_can_merge = permissions.is_none_or(|p| {
            p.get("admin").and_then(|v| v.as_bool()).unwrap_or(false)
                || p.get("maintain").and_then(|v| v.as_bool()).unwrap_or(false)
                || p.get("push").and_then(|v| v.as_bool()).unwrap_or(false)
        });

        let mut merge_methods = Vec::new();
        if json
            .get("allow_merge_commit")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            merge_methods.push(ForgeMergeMethod::Merge);
        }
        if json
            .get("allow_squash_merge")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            merge_methods.push(ForgeMergeMethod::Squash);
        }
        if json
            .get("allow_rebase_merge")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            merge_methods.push(ForgeMergeMethod::Rebase);
        }

        let delete_branch_on_merge = json
            .get("delete_branch_on_merge")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let allow_auto_merge = json
            .get("allow_auto_merge")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut capabilities = default_capabilities(ForgeKind::GitHub);
        if !allow_auto_merge {
            capabilities.auto_merge = false;
        }

        Ok(ForgeRepository {
            kind: ForgeKind::GitHub,
            host: self.host.to_string(),
            namespace: self.namespace.to_string(),
            name: self.name.to_string(),
            web_url,
            default_branch,
            remote_name: self.remote_name.to_string(),
            viewer_can_merge,
            merge_methods,
            delete_branch_on_merge,
            capabilities,
        })
    }

    pub async fn current_pull_request(
        &self,
        branch: &str,
    ) -> Result<Option<ForgePrSummary>, ForgeError> {
        let q = format!(
            "repo:{}/{} is:pr is:open head:{}",
            self.namespace, self.name, branch
        );
        let list = self.search_prs(&q, 10).await?;
        Ok(list.into_iter().next())
    }

    pub async fn list(
        &self,
        filter: ForgePrFilter,
        limit: u32,
    ) -> Result<Vec<ForgePrSummary>, ForgeError> {
        let filter_q = match filter {
            ForgePrFilter::NeedsMyReview => "is:open review-requested:@me",
            ForgePrFilter::Mine => "is:open author:@me",
            ForgePrFilter::Open => "is:open",
            ForgePrFilter::Merged => "is:merged",
            ForgePrFilter::Closed => "is:closed is:unmerged",
        };

        let q = format!(
            "repo:{}/{} is:pr sort:updated-desc {}",
            self.namespace, self.name, filter_q
        );
        self.search_prs(&q, limit).await
    }

    async fn search_prs(&self, q: &str, limit: u32) -> Result<Vec<ForgePrSummary>, ForgeError> {
        let query = r#"
            query($q: String!, $n: Int!) {
                search(query: $q, type: ISSUE, first: $n) {
                    nodes {
                        ... on PullRequest {
                            number
                            title
                            author { login }
                            state
                            isDraft
                            headRefName
                            baseRefName
                            updatedAt
                            reviewDecision
                            url
                            headRepositoryOwner { login }
                            commits(last: 1) {
                                nodes {
                                    commit {
                                        statusCheckRollup {
                                            state
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let data = self.graphql(query, json!({ "q": q, "n": limit })).await?;
        let nodes = data
            .get("search")
            .and_then(|s| s.get("nodes"))
            .and_then(|n| n.as_array());

        let mut summaries = Vec::new();
        if let Some(nodes) = nodes {
            for node in nodes {
                if let Some(pr) = parse_pr_summary(node) {
                    summaries.push(pr);
                }
            }
        }

        Ok(summaries)
    }

    pub async fn detail_with_checks(
        &self,
        number: u64,
    ) -> Result<(ForgePrDetail, Vec<ForgeCheck>), ForgeError> {
        let query = r#"
            query($owner: String!, $name: String!, $number: Int!) {
                repository(owner: $owner, name: $name) {
                    pullRequest(number: $number) {
                        id
                        number
                        title
                        body
                        state
                        isDraft
                        author { login }
                        url
                        createdAt
                        updatedAt
                        additions
                        deletions
                        changedFiles
                        mergeable
                        mergeStateStatus
                        reviewDecision
                        headRefName
                        headRefOid
                        baseRefName
                        isCrossRepository
                        headRepositoryOwner { login }
                        autoMergeRequest { enabledAt }
                        commits(last: 100) {
                            nodes {
                                commit {
                                    oid
                                    messageHeadline
                                    authoredDate
                                    author { name user { login } }
                                }
                            }
                        }
                        reviews(last: 50) {
                            nodes {
                                author { login }
                                state
                                body
                                submittedAt
                            }
                        }
                        comments(last: 100) {
                            nodes {
                                author { login }
                                body
                                createdAt
                            }
                        }
                        statusRollup: commits(last: 1) {
                            nodes {
                                commit {
                                    statusCheckRollup {
                                        state
                                        contexts(first: 100) {
                                            nodes {
                                                __typename
                                                ... on CheckRun {
                                                    name
                                                    status
                                                    conclusion
                                                    detailsUrl
                                                    startedAt
                                                    completedAt
                                                    checkSuite {
                                                        workflowRun {
                                                            workflow { name }
                                                        }
                                                    }
                                                }
                                                ... on StatusContext {
                                                    context
                                                    state
                                                    targetUrl
                                                    description
                                                    createdAt
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let (data, errors) = self
            .graphql_raw(
                query,
                json!({
                    "owner": self.namespace,
                    "name": self.name,
                    "number": number,
                }),
            )
            .await?;

        if !errors.is_empty() {
            if accept_partial(&data, &errors) {
                tracing::warn!(
                    errors = ?errors,
                    "GitHub GraphQL returned partial errors in statusRollup; accepting partial response"
                );
            } else {
                let first = &errors[0];
                let err_type = first.get("type").and_then(|t| t.as_str()).unwrap_or("");
                let msg = first
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("GraphQL error");
                let kind = graphql_error_kind(err_type);
                return Err(ForgeError {
                    kind,
                    message: msg.to_string(),
                    git_kind: None,
                    host: Some(self.host.to_string()),
                    port: None,
                });
            }
        }

        let pr_val = data
            .get("repository")
            .and_then(|r| r.get("pullRequest"))
            .filter(|v| !v.is_null())
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: format!("pull request #{number} not found"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            })?;

        let mut budget = initial_reply_budget();

        let mut summary = parse_pr_summary(pr_val).ok_or_else(|| ForgeError {
            kind: ForgeErrorKind::Other,
            message: "failed to parse pull request summary".into(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        let mut raw_body = pr_val
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let body_truncated = cap_description(&mut raw_body, &mut budget);

        let head_oid = pr_val
            .get("headRefOid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let head_owner = pr_val
            .get("headRepositoryOwner")
            .and_then(|o| o.get("login"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let is_cross_repository = pr_val
            .get("isCrossRepository")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let additions = pr_val
            .get("additions")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let deletions = pr_val
            .get("deletions")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let changed_files = pr_val
            .get("changedFiles")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);

        let mergeable = match pr_val.get("mergeable").and_then(|v| v.as_str()) {
            Some("MERGEABLE") => ForgeMergeable::Mergeable,
            Some("CONFLICTING") => ForgeMergeable::Conflicting,
            _ => ForgeMergeable::Unknown,
        };

        let contexts = pr_val
            .get("statusRollup")
            .and_then(|c| c.get("nodes"))
            .and_then(|n| n.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("commit"))
            .and_then(|c| c.get("statusCheckRollup"))
            .and_then(|s| s.get("contexts"))
            .and_then(|c| c.get("nodes"))
            .and_then(|n| n.as_array());

        let checks = contexts
            .map(|c| parse_check_contexts(c))
            .unwrap_or_default();

        if !checks.is_empty() {
            summary.checks = compute_checks_rollup(&checks);
        }

        let rollup_state = pr_val
            .get("statusRollup")
            .and_then(|c| c.get("nodes"))
            .and_then(|n| n.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("commit"))
            .and_then(|c| c.get("statusCheckRollup"))
            .and_then(|s| s.get("state"))
            .and_then(|v| v.as_str());
        let merge_state_status = pr_val
            .get("mergeStateStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let merge_state = match merge_state_status {
            "CLEAN" | "HAS_HOOKS" => ForgeMergeState::Clean,
            "BLOCKED" => {
                if summary.checks == ForgeChecksRollup::Pending
                    || rollup_state == Some("PENDING")
                    || rollup_state == Some("EXPECTED")
                {
                    ForgeMergeState::ChecksPending
                } else if summary.checks == ForgeChecksRollup::Failing {
                    ForgeMergeState::ChecksFailing
                } else {
                    ForgeMergeState::Blocked
                }
            }
            "BEHIND" => ForgeMergeState::Behind,
            "DIRTY" => ForgeMergeState::Conflicts,
            "UNSTABLE" => {
                if summary.checks == ForgeChecksRollup::Passing {
                    ForgeMergeState::Clean
                } else {
                    ForgeMergeState::ChecksFailing
                }
            }
            "DRAFT" => ForgeMergeState::Draft,
            _ => ForgeMergeState::Unknown,
        };

        let auto_merge_enabled = pr_val.get("autoMergeRequest").is_some_and(|v| !v.is_null());
        let created_at = pr_val
            .get("createdAt")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut commits = Vec::new();
        if let Some(nodes) = pr_val
            .get("commits")
            .and_then(|c| c.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                if let Some(commit) = node.get("commit") {
                    let oid = commit
                        .get("oid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let headline = commit
                        .get("messageHeadline")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let authored_at = commit
                        .get("authoredDate")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let author = commit
                        .get("author")
                        .and_then(|a| {
                            a.get("user")
                                .and_then(|u| u.get("login"))
                                .or_else(|| a.get("name"))
                        })
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    commits.push(ForgePrCommit {
                        oid,
                        headline,
                        author,
                        authored_at,
                    });
                }
            }
        }

        let mut reviews = Vec::new();
        if let Some(nodes) = pr_val
            .get("reviews")
            .and_then(|r| r.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                let author = node
                    .get("author")
                    .and_then(|a| a.get("login"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let state_str = node.get("state").and_then(|v| v.as_str()).unwrap_or("");
                let state = match state_str {
                    "APPROVED" => ForgeReviewState::Approved,
                    "CHANGES_REQUESTED" => ForgeReviewState::ChangesRequested,
                    "COMMENTED" => ForgeReviewState::Commented,
                    "DISMISSED" => ForgeReviewState::Dismissed,
                    _ => ForgeReviewState::Pending,
                };
                let mut body = node
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let truncated = cap_comment_body(&mut body, &mut budget);
                let submitted_at = node
                    .get("submittedAt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                reviews.push(ForgeReview {
                    author,
                    state,
                    body,
                    truncated,
                    submitted_at,
                });
            }
        }

        let mut comments = Vec::new();
        if let Some(nodes) = pr_val
            .get("comments")
            .and_then(|c| c.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                let author = node
                    .get("author")
                    .and_then(|a| a.get("login"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut body = node
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let truncated = cap_comment_body(&mut body, &mut budget);
                let c_at = node
                    .get("createdAt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                comments.push(ForgeComment {
                    author,
                    body,
                    truncated,
                    created_at: c_at,
                });
            }
        }

        let detail = ForgePrDetail {
            summary,
            body: raw_body,
            body_truncated,
            head_oid,
            head_owner,
            is_cross_repository,
            additions,
            deletions,
            changed_files,
            mergeable,
            merge_state,
            auto_merge_enabled,
            created_at,
            commits,
            reviews,
            comments,
        };

        Ok((detail, checks))
    }

    pub async fn detail(&self, number: u64) -> Result<ForgePrDetail, ForgeError> {
        self.detail_with_checks(number).await.map(|(d, _)| d)
    }

    pub async fn checks(&self, number: u64) -> Result<Vec<ForgeCheck>, ForgeError> {
        self.detail_with_checks(number).await.map(|(_, c)| c)
    }

    pub async fn files(
        &self,
        number: u64,
        _head_oid: &str,
    ) -> Result<Vec<ForgePrFile>, ForgeError> {
        let mut all_files = Vec::new();
        let mut page = 1;

        loop {
            let url = self.rest_url(&format!(
                "/repos/{}/{}/pulls/{number}/files?per_page=100&page={page}",
                self.namespace, self.name
            ));
            let rb = self.http.client().get(&url).headers(self.headers());
            let (status, _, bytes) = self.http.execute(rb, false).await?;

            if !status.is_success() {
                break;
            }

            let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
            if arr.is_empty() {
                break;
            }

            let len = arr.len();
            for item in arr {
                let path = item
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let previous_path = item
                    .get("previous_filename")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let status_str = item
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("modified");
                let additions = item.get("additions").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let deletions = item.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

                let change = match status_str {
                    "added" => GitChange::Added,
                    "removed" => GitChange::Deleted,
                    "renamed" => GitChange::Renamed,
                    "copied" => GitChange::Copied,
                    "changed" => GitChange::TypeChanged,
                    _ => GitChange::Modified,
                };

                all_files.push(ForgePrFile {
                    path,
                    previous_path,
                    change,
                    additions,
                    deletions,
                });

                if all_files.len() >= MAX_PR_FILES {
                    return Ok(all_files);
                }
            }

            if len < 100 {
                break;
            }
            page += 1;
        }

        Ok(all_files)
    }

    pub async fn file_diff(
        &self,
        number: u64,
        path: &str,
        _head_oid: &str,
    ) -> Result<GitFileDiff, ForgeError> {
        let mut page = 1;

        loop {
            let url = self.rest_url(&format!(
                "/repos/{}/{}/pulls/{number}/files?per_page=100&page={page}",
                self.namespace, self.name
            ));
            let rb = self.http.client().get(&url).headers(self.headers());
            let (status, _, bytes) = self.http.execute(rb, false).await?;

            if !status.is_success() {
                break;
            }

            let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
            if arr.is_empty() {
                break;
            }

            let len = arr.len();
            for item in arr {
                let filename = item.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                if filename == path {
                    let old_path = item
                        .get("previous_filename")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let additions = item.get("additions").and_then(|v| v.as_u64()).unwrap_or(0);
                    let deletions = item.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0);

                    if let Some(patch) = item.get("patch").and_then(|v| v.as_str()) {
                        let total_bytes = patch.len() as u64;
                        let too_large = patch.len() > MAX_FORGE_DIFF_BYTES;
                        let hunks = if too_large {
                            Vec::new()
                        } else {
                            crate::rpc::git::diff::parse_unified_diff(patch)
                        };

                        return Ok(GitFileDiff {
                            path: path.to_string(),
                            old_path,
                            binary: false,
                            too_large,
                            lfs: false,
                            total_bytes,
                            hunks,
                        });
                    } else {
                        let binary = additions + deletions == 0;
                        return Ok(GitFileDiff {
                            path: path.to_string(),
                            old_path,
                            binary,
                            too_large: false,
                            lfs: false,
                            total_bytes: 0,
                            hunks: Vec::new(),
                        });
                    }
                }
            }

            if len < 100 {
                break;
            }
            page += 1;
        }

        Err(ForgeError {
            kind: ForgeErrorKind::NotFound,
            message: format!("file {path} not found in pull request #{number}"),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })
    }

    pub async fn threads(&self, number: u64) -> Result<Vec<ForgeReviewThread>, ForgeError> {
        let query = r#"
            query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
                repository(owner: $owner, name: $name) {
                    pullRequest(number: $number) {
                        reviewThreads(first: 100, after: $cursor) {
                            pageInfo { hasNextPage endCursor }
                            nodes {
                                id
                                path
                                line
                                startLine
                                diffSide
                                isResolved
                                isOutdated
                                viewerCanReply
                                viewerCanResolve
                                viewerCanUnresolve
                                comments(first: 50) {
                                    nodes {
                                        id
                                        body
                                        createdAt
                                        author { login }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let mut all_threads = Vec::new();
        let mut cursor: Option<String> = None;
        let mut budget = initial_reply_budget();

        for _ in 0..5 {
            let data = self
                .graphql(
                    query,
                    json!({
                        "owner": self.namespace,
                        "name": self.name,
                        "number": number,
                        "cursor": cursor,
                    }),
                )
                .await?;

            let threads_val = data
                .get("repository")
                .and_then(|r| r.get("pullRequest"))
                .and_then(|pr| pr.get("reviewThreads"));

            let nodes = threads_val
                .and_then(|t| t.get("nodes"))
                .and_then(|n| n.as_array());
            if let Some(nodes) = nodes {
                for node in nodes {
                    let id = node
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let path = node
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let line = node.get("line").and_then(|v| v.as_u64()).map(|n| n as u32);
                    let start_line = node
                        .get("startLine")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u32);

                    let side = match node.get("diffSide").and_then(|v| v.as_str()) {
                        Some("LEFT") => ForgeDiffSide::Left,
                        _ => ForgeDiffSide::Right,
                    };

                    let resolved = node
                        .get("isResolved")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let outdated = node
                        .get("isOutdated")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let can_reply = node
                        .get("viewerCanReply")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let can_resolve = node
                        .get("viewerCanResolve")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || node
                            .get("viewerCanUnresolve")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                    let mut comments = Vec::new();
                    if let Some(c_nodes) = node
                        .get("comments")
                        .and_then(|c| c.get("nodes"))
                        .and_then(|n| n.as_array())
                    {
                        for c in c_nodes {
                            let cid = c
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let author = c
                                .get("author")
                                .and_then(|a| a.get("login"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let mut body = c
                                .get("body")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let truncated = cap_comment_body(&mut body, &mut budget);
                            let created_at = c
                                .get("createdAt")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            comments.push(ForgeThreadComment {
                                id: cid,
                                author,
                                body,
                                truncated,
                                created_at,
                            });
                        }
                    }

                    all_threads.push(ForgeReviewThread {
                        id,
                        path,
                        line,
                        start_line,
                        side,
                        resolved,
                        outdated,
                        can_reply,
                        can_resolve,
                        comments,
                    });
                }
            }

            let page_info = threads_val.and_then(|t| t.get("pageInfo"));
            let has_next = page_info
                .and_then(|p| p.get("hasNextPage"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !has_next {
                break;
            }
            cursor = page_info
                .and_then(|p| p.get("endCursor"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }

        Ok(all_threads)
    }

    pub async fn submit_review(&self, review: &ForgeReviewSubmission) -> Result<(), ForgeError> {
        // Fetch PR Node ID
        let query = r#"
            query($owner: String!, $name: String!, $number: Int!) {
                repository(owner: $owner, name: $name) {
                    pullRequest(number: $number) { id }
                }
            }
        "#;
        let data = self
            .graphql(
                query,
                json!({
                    "owner": self.namespace,
                    "name": self.name,
                    "number": review.number,
                }),
            )
            .await?;

        let pr_id = data
            .get("repository")
            .and_then(|r| r.get("pullRequest"))
            .and_then(|pr| pr.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: "pull request ID not found".into(),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            })?;

        let event = match review.event {
            ForgeReviewEvent::Comment => "COMMENT",
            ForgeReviewEvent::Approve => "APPROVE",
            ForgeReviewEvent::RequestChanges => "REQUEST_CHANGES",
        };

        let mut threads_input = Vec::new();
        for t in &review.threads {
            let side_str = match t.side {
                ForgeDiffSide::Left => "LEFT",
                ForgeDiffSide::Right => "RIGHT",
            };
            let line_num = match t.side {
                ForgeDiffSide::Left => t.end.old_line.unwrap_or(1),
                ForgeDiffSide::Right => t.end.new_line.unwrap_or(1),
            };

            let mut thread_obj = json!({
                "path": t.path,
                "body": t.body,
                "line": line_num,
                "side": side_str,
            });

            if let Some(ref st) = t.start {
                let start_line = match t.side {
                    ForgeDiffSide::Left => st.old_line.unwrap_or(1),
                    ForgeDiffSide::Right => st.new_line.unwrap_or(1),
                };
                if start_line != line_num {
                    thread_obj["startLine"] = json!(start_line);
                    thread_obj["startSide"] = json!(side_str);
                }
            }

            threads_input.push(thread_obj);
        }

        let mutation = r#"
            mutation($input: AddPullRequestReviewInput!) {
                addPullRequestReview(input: $input) {
                    pullRequestReview { id }
                }
            }
        "#;

        let input = json!({
            "pullRequestId": pr_id,
            "commitOID": review.head_oid,
            "event": event,
            "body": review.body,
            "threads": threads_input,
        });

        self.graphql(mutation, json!({ "input": input })).await?;
        Ok(())
    }

    pub async fn reply(&self, _number: u64, thread_id: &str, body: &str) -> Result<(), ForgeError> {
        let mutation = r#"
            mutation($input: AddPullRequestReviewThreadReplyInput!) {
                addPullRequestReviewThreadReply(input: $input) {
                    comment { id }
                }
            }
        "#;

        let input = json!({
            "pullRequestReviewThreadId": thread_id,
            "body": body,
        });

        self.graphql(mutation, json!({ "input": input })).await?;
        Ok(())
    }

    pub async fn resolve(
        &self,
        _number: u64,
        thread_id: &str,
        resolved: bool,
    ) -> Result<(), ForgeError> {
        let mutation = if resolved {
            r#"
                mutation($input: ResolveReviewThreadInput!) {
                    resolveReviewThread(input: $input) {
                        thread { isResolved }
                    }
                }
            "#
        } else {
            r#"
                mutation($input: UnresolveReviewThreadInput!) {
                    unresolveReviewThread(input: $input) {
                        thread { isResolved }
                    }
                }
            "#
        };

        let input = json!({ "threadId": thread_id });
        self.graphql(mutation, json!({ "input": input })).await?;
        Ok(())
    }

    pub async fn comment(&self, number: u64, body: &str) -> Result<(), ForgeError> {
        let url = self.rest_url(&format!(
            "/repos/{}/{}/issues/{number}/comments",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .json(&json!({ "body": body }));

        let (status, _, _) = self.http.execute(rb, false).await?;
        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to post comment: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn merge(&self, req: &ForgeMergeRequest) -> Result<(), ForgeError> {
        if req.auto {
            let query = r#"
                query($owner: String!, $name: String!, $number: Int!) {
                    repository(owner: $owner, name: $name) {
                        pullRequest(number: $number) { id }
                    }
                }
            "#;
            let data = self
                .graphql(
                    query,
                    json!({
                        "owner": self.namespace,
                        "name": self.name,
                        "number": req.number,
                    }),
                )
                .await?;

            let pr_id = data
                .get("repository")
                .and_then(|r| r.get("pullRequest"))
                .and_then(|pr| pr.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| ForgeError {
                    kind: ForgeErrorKind::NotFound,
                    message: "pull request ID not found".into(),
                    git_kind: None,
                    host: Some(self.host.to_string()),
                    port: None,
                })?;

            let method = match req.method {
                ForgeMergeMethod::Merge => "MERGE",
                ForgeMergeMethod::Squash => "SQUASH",
                ForgeMergeMethod::Rebase => "REBASE",
            };

            let mutation = r#"
                mutation($input: EnablePullRequestAutoMergeInput!) {
                    enablePullRequestAutoMerge(input: $input) {
                        pullRequest { autoMergeRequest { enabledAt } }
                    }
                }
            "#;

            let input = json!({
                "pullRequestId": pr_id,
                "mergeMethod": method,
                "commitHeadline": req.subject,
                "commitBody": req.body,
            });

            self.graphql(mutation, json!({ "input": input })).await?;
            return Ok(());
        }

        let url = self.rest_url(&format!(
            "/repos/{}/{}/pulls/{}/merge",
            self.namespace, self.name, req.number
        ));
        let method_str = match req.method {
            ForgeMergeMethod::Merge => "merge",
            ForgeMergeMethod::Squash => "squash",
            ForgeMergeMethod::Rebase => "rebase",
        };

        let mut payload = json!({
            "merge_method": method_str,
            "sha": req.head_oid,
        });

        if let Some(ref s) = req.subject {
            payload["commit_title"] = json!(s);
        }
        if let Some(ref b) = req.body {
            payload["commit_message"] = json!(b);
        }

        let rb = self
            .http
            .client()
            .put(&url)
            .headers(self.headers())
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, true).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::MergeBlocked,
                message: format!("merge failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        Ok(())
    }

    pub async fn create(
        &self,
        req: &ForgeCreateRequest,
        head_spec: &str,
    ) -> Result<(u64, String), ForgeError> {
        let url = self.rest_url(&format!("/repos/{}/{}/pulls", self.namespace, self.name));
        let payload = json!({
            "title": req.title,
            "body": req.body,
            "head": head_spec,
            "base": req.base,
            "draft": req.draft,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .json(&payload);
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: if status == StatusCode::UNPROCESSABLE_ENTITY {
                    ForgeErrorKind::AlreadyExists
                } else {
                    ForgeErrorKind::Other
                },
                message: format!("create pull request failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let number = json.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
        let pr_url = json
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if !req.reviewers.is_empty() {
            let rev_url = self.rest_url(&format!(
                "/repos/{}/{}/pulls/{number}/requested_reviewers",
                self.namespace, self.name
            ));
            let _ = self
                .http
                .client()
                .post(&rev_url)
                .headers(self.headers())
                .json(&json!({ "reviewers": req.reviewers }))
                .send()
                .await;
        }

        Ok((number, pr_url))
    }

    pub async fn set_state(
        &self,
        number: u64,
        change: ForgePrStateChange,
    ) -> Result<(), ForgeError> {
        match change {
            ForgePrStateChange::Close | ForgePrStateChange::Reopen => {
                let state_val = if change == ForgePrStateChange::Close {
                    "closed"
                } else {
                    "open"
                };
                let url = self.rest_url(&format!(
                    "/repos/{}/{}/pulls/{number}",
                    self.namespace, self.name
                ));
                let rb = self
                    .http
                    .client()
                    .patch(&url)
                    .headers(self.headers())
                    .json(&json!({ "state": state_val }));
                let (status, _, _) = self.http.execute(rb, false).await?;
                if !status.is_success() {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::Other,
                        message: format!("failed to update state: {status}"),
                        git_kind: None,
                        host: Some(self.host.to_string()),
                        port: None,
                    });
                }
            }
            ForgePrStateChange::Ready => {
                let query = r#"
                    query($owner: String!, $name: String!, $number: Int!) {
                        repository(owner: $owner, name: $name) {
                            pullRequest(number: $number) { id }
                        }
                    }
                "#;
                let data = self
                    .graphql(
                        query,
                        json!({
                            "owner": self.namespace,
                            "name": self.name,
                            "number": number,
                        }),
                    )
                    .await?;

                let pr_id = data
                    .get("repository")
                    .and_then(|r| r.get("pullRequest"))
                    .and_then(|pr| pr.get("id"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ForgeError {
                        kind: ForgeErrorKind::NotFound,
                        message: "pull request ID not found".into(),
                        git_kind: None,
                        host: Some(self.host.to_string()),
                        port: None,
                    })?;

                let mutation = r#"
                    mutation($input: MarkPullRequestReadyForReviewInput!) {
                        markPullRequestReadyForReview(input: $input) {
                            pullRequest { isDraft }
                        }
                    }
                "#;
                self.graphql(mutation, json!({ "input": { "pullRequestId": pr_id } }))
                    .await?;
            }
            ForgePrStateChange::ConvertToDraft => {
                let query = r#"
                    query($owner: String!, $name: String!, $number: Int!) {
                        repository(owner: $owner, name: $name) {
                            pullRequest(number: $number) { id }
                        }
                    }
                "#;
                let data = self
                    .graphql(
                        query,
                        json!({
                            "owner": self.namespace,
                            "name": self.name,
                            "number": number,
                        }),
                    )
                    .await?;

                let pr_id = data
                    .get("repository")
                    .and_then(|r| r.get("pullRequest"))
                    .and_then(|pr| pr.get("id"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ForgeError {
                        kind: ForgeErrorKind::NotFound,
                        message: "pull request ID not found".into(),
                        git_kind: None,
                        host: Some(self.host.to_string()),
                        port: None,
                    })?;

                let mutation = r#"
                    mutation($input: ConvertPullRequestToDraftInput!) {
                        convertPullRequestToDraft(input: $input) {
                            pullRequest { isDraft }
                        }
                    }
                "#;
                self.graphql(mutation, json!({ "input": { "pullRequestId": pr_id } }))
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn checkout_source(&self, number: u64) -> Result<CheckoutSource, ForgeError> {
        Ok(CheckoutSource {
            fetch_from: self.remote_name.to_string(),
            refspec: format!("pull/{number}/head"),
            local_branch: format!("pr/{number}"),
        })
    }
}

fn parse_pr_summary(val: &Value) -> Option<ForgePrSummary> {
    let number = val.get("number")?.as_u64()?;
    let title = val.get("title")?.as_str()?.to_string();
    let author = val
        .get("author")
        .and_then(|a| a.get("login"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let state_str = val.get("state")?.as_str()?;
    let state = match state_str {
        "OPEN" => ForgePrState::Open,
        "MERGED" => ForgePrState::Merged,
        _ => ForgePrState::Closed,
    };
    let is_draft = val
        .get("isDraft")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let head_ref = val
        .get("headRefName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let base_ref = val
        .get("baseRefName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let updated_at = val
        .get("updatedAt")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let url = val
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let review_decision = match val.get("reviewDecision").and_then(|v| v.as_str()) {
        Some("APPROVED") => Some(ForgeReviewDecision::Approved),
        Some("CHANGES_REQUESTED") => Some(ForgeReviewDecision::ChangesRequested),
        Some("REVIEW_REQUIRED") => Some(ForgeReviewDecision::ReviewRequired),
        _ => None,
    };

    let rollup_val = val.get("statusRollup").or_else(|| val.get("commits"));
    let rollup_state = rollup_val
        .and_then(|c| c.get("nodes"))
        .and_then(|n| n.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("commit"))
        .and_then(|c| c.get("statusCheckRollup"))
        .and_then(|s| s.get("state"))
        .and_then(|v| v.as_str());

    let checks = match rollup_state {
        Some("SUCCESS") => ForgeChecksRollup::Passing,
        Some("FAILURE") | Some("ERROR") => ForgeChecksRollup::Failing,
        Some("PENDING") | Some("EXPECTED") => ForgeChecksRollup::Pending,
        _ => ForgeChecksRollup::NoChecks,
    };

    Some(ForgePrSummary {
        number,
        title,
        author,
        state,
        is_draft,
        head_ref,
        base_ref,
        updated_at,
        review_decision,
        checks,
        url,
    })
}

fn parse_check_contexts(contexts: &[Value]) -> Vec<ForgeCheck> {
    let mut checks: Vec<ForgeCheck> = Vec::new();
    let mut indices: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();

    for ctx in contexts {
        let typename = ctx.get("__typename").and_then(|v| v.as_str()).unwrap_or("");
        let check_opt = if typename == "CheckRun" {
            let name = ctx
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let group = ctx
                .get("checkSuite")
                .and_then(|cs| cs.get("workflowRun"))
                .and_then(|wr| wr.get("workflow"))
                .and_then(|w| w.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let link = ctx
                .get("detailsUrl")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let started_at = ctx
                .get("startedAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let completed_at = ctx
                .get("completedAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let conclusion = ctx.get("conclusion").and_then(|v| v.as_str());
            let bucket = match conclusion {
                Some("SUCCESS") | Some("NEUTRAL") => ForgeCheckBucket::Pass,
                Some("FAILURE")
                | Some("TIMED_OUT")
                | Some("ACTION_REQUIRED")
                | Some("STARTUP_FAILURE") => ForgeCheckBucket::Fail,
                Some("CANCELLED") => ForgeCheckBucket::Cancel,
                Some("SKIPPED") | Some("STALE") => ForgeCheckBucket::Skipping,
                _ => ForgeCheckBucket::Pending,
            };

            Some(ForgeCheck {
                name,
                group,
                bucket,
                link,
                started_at,
                completed_at,
                description: String::new(),
            })
        } else if typename == "StatusContext" {
            let name = ctx
                .get("context")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let link = ctx
                .get("targetUrl")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let description = ctx
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let started_at = ctx
                .get("createdAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let state = ctx.get("state").and_then(|v| v.as_str());
            let bucket = match state {
                Some("SUCCESS") => ForgeCheckBucket::Pass,
                Some("FAILURE") | Some("ERROR") => ForgeCheckBucket::Fail,
                _ => ForgeCheckBucket::Pending,
            };

            Some(ForgeCheck {
                name,
                group: "Status".to_string(),
                bucket,
                link,
                started_at,
                completed_at: String::new(),
                description,
            })
        } else {
            None
        };

        if let Some(check) = check_opt {
            let key = (check.group.clone(), check.name.clone());
            if let Some(&idx) = indices.get(&key) {
                let existing = &checks[idx];
                let should_replace = if check.bucket == ForgeCheckBucket::Pending
                    && existing.bucket != ForgeCheckBucket::Pending
                {
                    true
                } else if !check.started_at.is_empty() && !existing.started_at.is_empty() {
                    check.started_at >= existing.started_at
                } else {
                    true
                };

                if should_replace {
                    checks[idx] = check;
                }
            } else {
                indices.insert(key, checks.len());
                checks.push(check);
            }
        }
    }

    checks
}

pub fn compute_checks_rollup(checks: &[ForgeCheck]) -> ForgeChecksRollup {
    if checks.is_empty() {
        return ForgeChecksRollup::NoChecks;
    }
    if checks.iter().any(|c| c.bucket == ForgeCheckBucket::Fail) {
        return ForgeChecksRollup::Failing;
    }
    if checks.iter().any(|c| c.bucket == ForgeCheckBucket::Pending) {
        return ForgeChecksRollup::Pending;
    }
    if checks.iter().any(|c| c.bucket == ForgeCheckBucket::Cancel) {
        return ForgeChecksRollup::Failing;
    }
    if checks.iter().any(|c| c.bucket == ForgeCheckBucket::Pass) {
        return ForgeChecksRollup::Passing;
    }
    if checks
        .iter()
        .all(|c| c.bucket == ForgeCheckBucket::Skipping)
    {
        return ForgeChecksRollup::Passing;
    }
    ForgeChecksRollup::NoChecks
}

fn graphql_error_kind(err_type: &str) -> ForgeErrorKind {
    match err_type {
        "FORBIDDEN" => ForgeErrorKind::PermissionDenied,
        "NOT_FOUND" => ForgeErrorKind::NotFound,
        "RATE_LIMITED" => ForgeErrorKind::RateLimited,
        _ => ForgeErrorKind::Other,
    }
}

fn errors_only_in_status_rollup(errors: &[Value]) -> bool {
    errors.iter().all(|err| {
        err.get("path")
            .and_then(|p| p.as_array())
            .is_some_and(|path| {
                path.len() >= 3
                    && path[0].as_str() == Some("repository")
                    && path[1].as_str() == Some("pullRequest")
                    && path[2].as_str() == Some("statusRollup")
            })
    })
}

fn accept_partial(data: &Value, errors: &[Value]) -> bool {
    !errors.is_empty()
        && data
            .pointer("/repository/pullRequest")
            .is_some_and(|v| !v.is_null())
        && errors_only_in_status_rollup(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_check_contexts() {
        let contexts = vec![
            json!({
                "__typename": "CheckRun",
                "name": "build",
                "conclusion": "SUCCESS",
                "detailsUrl": "https://ci.example/1",
                "startedAt": "2026-03-30T09:00:00Z",
                "completedAt": "2026-03-30T09:05:00Z",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CI" } } }
            }),
            json!({
                "__typename": "CheckRun",
                "name": "lint",
                "conclusion": "STALE",
                "detailsUrl": "https://ci.example/2",
                "startedAt": "2026-03-30T09:00:00Z",
                "completedAt": "2026-03-30T09:02:00Z",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CI" } } }
            }),
            json!({
                "__typename": "CheckRun",
                "name": "deploy",
                "conclusion": null,
                "detailsUrl": "https://ci.example/3",
                "startedAt": "2026-03-30T09:00:00Z",
                "completedAt": "",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CD" } } }
            }),
            json!({
                "__typename": "StatusContext",
                "context": "coverage/codecov",
                "state": "SUCCESS",
                "targetUrl": "https://codecov.example/1",
                "description": "Coverage 95%",
                "createdAt": "2026-03-30T09:03:00Z"
            }),
        ];

        let checks = parse_check_contexts(&contexts);
        assert_eq!(checks.len(), 4);
        assert_eq!(checks[0].bucket, ForgeCheckBucket::Pass);
        assert_eq!(checks[1].bucket, ForgeCheckBucket::Skipping);
        assert_eq!(checks[2].bucket, ForgeCheckBucket::Pending);
        assert_eq!(checks[3].bucket, ForgeCheckBucket::Pass);
    }
    #[test]
    fn test_parse_check_contexts_deduplicates_latest_runs() {
        let contexts = vec![
            // Run 1 of CI: failed
            json!({
                "__typename": "CheckRun",
                "name": "CI Gate",
                "conclusion": "FAILURE",
                "detailsUrl": "https://ci.example/1",
                "startedAt": "2026-03-30T09:00:00Z",
                "completedAt": "2026-03-30T09:01:00Z",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CI" } } }
            }),
            // Run 1 of macos: cancelled
            json!({
                "__typename": "CheckRun",
                "name": "macos",
                "conclusion": "CANCELLED",
                "detailsUrl": "https://ci.example/2",
                "startedAt": "2026-03-30T09:00:00Z",
                "completedAt": "2026-03-30T09:02:00Z",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CI" } } }
            }),
            // Run 2 of macos: success (supersedes run 1)
            json!({
                "__typename": "CheckRun",
                "name": "macos",
                "conclusion": "SUCCESS",
                "detailsUrl": "https://ci.example/3",
                "startedAt": "2026-03-30T09:10:00Z",
                "completedAt": "2026-03-30T09:15:00Z",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CI" } } }
            }),
            // Run 2 of CI Gate: success (supersedes run 1)
            json!({
                "__typename": "CheckRun",
                "name": "CI Gate",
                "conclusion": "SUCCESS",
                "detailsUrl": "https://ci.example/4",
                "startedAt": "2026-03-30T09:15:00Z",
                "completedAt": "2026-03-30T09:16:00Z",
                "checkSuite": { "workflowRun": { "workflow": { "name": "CI" } } }
            }),
        ];

        let checks = parse_check_contexts(&contexts);
        assert_eq!(checks.len(), 2, "must deduplicate to 2 checks");
        let macos_check = checks
            .iter()
            .find(|c| c.name == "macos")
            .expect("macos check present");
        assert_eq!(
            macos_check.bucket,
            ForgeCheckBucket::Pass,
            "latest macos run was SUCCESS"
        );
        let gate_check = checks
            .iter()
            .find(|c| c.name == "CI Gate")
            .expect("CI Gate present");
        assert_eq!(
            gate_check.bucket,
            ForgeCheckBucket::Pass,
            "latest CI Gate run was SUCCESS"
        );
    }

    #[test]
    fn test_compute_checks_rollup() {
        let passing_checks = vec![
            ForgeCheck {
                name: "test".into(),
                group: "CI".into(),
                bucket: ForgeCheckBucket::Pass,
                link: String::new(),
                started_at: String::new(),
                completed_at: String::new(),
                description: String::new(),
            },
            ForgeCheck {
                name: "lint".into(),
                group: "CI".into(),
                bucket: ForgeCheckBucket::Skipping,
                link: String::new(),
                started_at: String::new(),
                completed_at: String::new(),
                description: String::new(),
            },
        ];
        assert_eq!(
            compute_checks_rollup(&passing_checks),
            ForgeChecksRollup::Passing
        );

        let failing_checks = vec![
            ForgeCheck {
                name: "test".into(),
                group: "CI".into(),
                bucket: ForgeCheckBucket::Pass,
                link: String::new(),
                started_at: String::new(),
                completed_at: String::new(),
                description: String::new(),
            },
            ForgeCheck {
                name: "gate".into(),
                group: "CI".into(),
                bucket: ForgeCheckBucket::Fail,
                link: String::new(),
                started_at: String::new(),
                completed_at: String::new(),
                description: String::new(),
            },
        ];
        assert_eq!(
            compute_checks_rollup(&failing_checks),
            ForgeChecksRollup::Failing
        );
    }

    #[test]
    fn test_graphql_error_kind() {
        assert_eq!(
            graphql_error_kind("FORBIDDEN"),
            ForgeErrorKind::PermissionDenied
        );
        assert_eq!(graphql_error_kind("NOT_FOUND"), ForgeErrorKind::NotFound);
        assert_eq!(
            graphql_error_kind("RATE_LIMITED"),
            ForgeErrorKind::RateLimited
        );
        assert_eq!(graphql_error_kind("SOME_OTHER"), ForgeErrorKind::Other);
    }

    #[test]
    fn test_errors_only_in_status_rollup() {
        let rollup_errors = vec![
            json!({ "path": ["repository", "pullRequest", "statusRollup", "commits"] }),
            json!({ "path": ["repository", "pullRequest", "statusRollup", "contexts", 0] }),
        ];
        assert!(errors_only_in_status_rollup(&rollup_errors));

        let non_rollup_errors = vec![
            json!({ "path": ["repository", "pullRequest", "statusRollup"] }),
            json!({ "path": ["repository", "pullRequest", "body"] }),
        ];
        assert!(!errors_only_in_status_rollup(&non_rollup_errors));

        let short_path = vec![json!({ "path": ["repository"] })];
        assert!(!errors_only_in_status_rollup(&short_path));

        let no_path = vec![json!({ "message": "fail" })];
        assert!(!errors_only_in_status_rollup(&no_path));

        assert!(errors_only_in_status_rollup(&[]));
    }

    #[test]
    fn test_accept_partial() {
        let valid_data = json!({
            "repository": {
                "pullRequest": {
                    "id": "PR_1"
                }
            }
        });
        let null_pr_data = json!({
            "repository": {
                "pullRequest": null
            }
        });
        let rollup_errors =
            vec![json!({ "path": ["repository", "pullRequest", "statusRollup", "commits"] })];
        let other_errors = vec![json!({ "path": ["repository", "pullRequest", "title"] })];

        // Partial accepted: has PR data and errors only in statusRollup
        assert!(accept_partial(&valid_data, &rollup_errors));

        // Not accepted if errors is empty
        assert!(!accept_partial(&valid_data, &[]));

        // Not accepted if PR data is null/missing
        assert!(!accept_partial(&null_pr_data, &rollup_errors));

        // Not accepted if errors touch other fields
        assert!(!accept_partial(&valid_data, &other_errors));
    }
}
