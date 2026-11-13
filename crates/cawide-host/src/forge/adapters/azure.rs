use super::CheckoutSource;
use crate::forge::capabilities::default_capabilities;
use crate::forge::http::ForgeHttp;
use crate::forge::text::{cap_comment_body, cap_description, initial_reply_budget};
use crate::rpc::git::GitEngine;
use cawide_protocol::types::{
    ForgeCheck, ForgeCheckBucket, ForgeComment, ForgeCreateRequest, ForgeDiffSide, ForgeError,
    ForgeErrorKind, ForgeKind, ForgeMergeMethod, ForgeMergeRequest, ForgeMergeState,
    ForgeMergeable, ForgePrCommit, ForgePrDetail, ForgePrFile, ForgePrFilter, ForgePrState,
    ForgePrStateChange, ForgePrSummary, ForgeRepository, ForgeReview, ForgeReviewDecision,
    ForgeReviewEvent, ForgeReviewState, ForgeReviewSubmission, ForgeReviewThread,
    ForgeThreadComment, GitChange, GitFileDiff, MAX_PR_FILES,
};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;

pub struct AzureAdapter<'a> {
    pub http: &'a ForgeHttp,
    pub scheme: &'a str,
    pub host: &'a str,
    pub namespace: &'a str, // org/project
    pub name: &'a str,      // repo
    pub token: &'a str,
    pub account_user_id: Option<&'a str>,
    pub account_azure_org: Option<&'a str>,
    pub remote_name: &'a str,
    pub engine: &'a GitEngine,
}

impl<'a> AzureAdapter<'a> {
    fn org_and_project(&self) -> (&str, &str) {
        self.namespace
            .split_once('/')
            .unwrap_or((self.namespace, ""))
    }

    fn check_org(&self) -> Result<(), ForgeError> {
        let (org, _) = self.org_and_project();
        if let Some(acct_org) = self.account_azure_org {
            if !acct_org.eq_ignore_ascii_case(org) {
                return Err(ForgeError {
                    kind: ForgeErrorKind::NotAuthenticated,
                    message: format!("account azure_org '{acct_org}' does not match repository organization '{org}'"),
                    git_kind: None,
                    host: Some(self.host.to_string()),
                    port: None,
                });
            }
        }
        Ok(())
    }

    fn api_url(&self, path: &str) -> String {
        let (org, project) = self.org_and_project();
        let clean = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };
        let sep = if path.contains('?') { "&" } else { "?" };
        let full = format!(
            "/{org}/{project}/_apis/git/repositories/{}{clean}{sep}api-version=7.1",
            self.name
        );
        self.http.url(self.host, self.scheme, &full)
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static("cawide"));
        h.insert(ACCEPT, HeaderValue::from_static("application/json"));
        h
    }

    async fn get_user_id(&self) -> Result<String, ForgeError> {
        if let Some(uid) = self.account_user_id {
            if !uid.is_empty() {
                return Ok(uid.to_string());
            }
        }

        let (org, _) = self.org_and_project();
        let url = format!(
            "{}/_apis/connectionData?api-version=7.1",
            self.http.url(self.host, "https", &format!("/{org}"))
        );
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotAuthenticated,
                message: "failed to authenticate Azure DevOps PAT".into(),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let uid = json
            .get("authenticatedUser")
            .and_then(|u| u.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ForgeError {
                kind: ForgeErrorKind::Other,
                message: "missing authenticated user ID".into(),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            })?
            .to_string();

        Ok(uid)
    }

    pub async fn repository(&self) -> Result<ForgeRepository, ForgeError> {
        self.check_org()?;
        let (org, project) = self.org_and_project();
        let url = format!(
            "{}/_apis/git/repositories/{}?api-version=7.1",
            self.http
                .url(self.host, "https", &format!("/{org}/{project}")),
            self.name
        );
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to fetch Azure repository: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let default_branch = json
            .get("defaultBranch")
            .and_then(|v| v.as_str())
            .unwrap_or("refs/heads/main")
            .strip_prefix("refs/heads/")
            .unwrap_or("main")
            .to_string();

        let web_url = json
            .get("webUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let merge_methods = vec![
            ForgeMergeMethod::Merge,
            ForgeMergeMethod::Squash,
            ForgeMergeMethod::Rebase,
        ];

        let capabilities = default_capabilities(ForgeKind::AzureDevOps);

        Ok(ForgeRepository {
            kind: ForgeKind::AzureDevOps,
            host: self.host.to_string(),
            namespace: self.namespace.to_string(),
            name: self.name.to_string(),
            web_url,
            default_branch,
            remote_name: self.remote_name.to_string(),
            viewer_can_merge: true,
            merge_methods,
            delete_branch_on_merge: false,
            capabilities,
        })
    }

    pub async fn current_pull_request(
        &self,
        branch: &str,
    ) -> Result<Option<ForgePrSummary>, ForgeError> {
        self.check_org()?;
        let ref_name = format!("refs/heads/{branch}");
        let url = self.api_url(&format!(
            "/pullrequests?searchCriteria.sourceRefName={}&searchCriteria.status=active&$top=1",
            crate::forge::http::url_encode(&ref_name)
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(None);
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
            if let Some(first) = values.first() {
                return Ok(parse_azure_pr_summary(first));
            }
        }
        Ok(None)
    }

    pub async fn list(
        &self,
        filter: ForgePrFilter,
        limit: u32,
    ) -> Result<Vec<ForgePrSummary>, ForgeError> {
        self.check_org()?;
        let status_param = match filter {
            ForgePrFilter::Merged => "completed",
            ForgePrFilter::Closed => "abandoned",
            _ => "active",
        };

        let mut query = format!("/pullrequests?searchCriteria.status={status_param}&$top={limit}");

        match filter {
            ForgePrFilter::Mine => {
                if let Ok(uid) = self.get_user_id().await {
                    query.push_str(&format!("&searchCriteria.creatorId={uid}"));
                }
            }
            ForgePrFilter::NeedsMyReview => {
                if let Ok(uid) = self.get_user_id().await {
                    query.push_str(&format!("&searchCriteria.reviewerId={uid}"));
                }
            }
            _ => {}
        }

        let url = self.api_url(&query);
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to list Azure pull requests: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut list = Vec::new();

        if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
            for v in values {
                if let Some(s) = parse_azure_pr_summary(v) {
                    list.push(s);
                }
            }
        }

        Ok(list)
    }

    pub async fn detail(&self, number: u64) -> Result<ForgePrDetail, ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullrequests/{number}"));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: if status == StatusCode::NOT_FOUND {
                    ForgeErrorKind::NotFound
                } else {
                    ForgeErrorKind::Other
                },
                message: format!("pull request #{number} not found"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let pr: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let summary = parse_azure_pr_summary(&pr).ok_or_else(|| ForgeError {
            kind: ForgeErrorKind::Other,
            message: "failed to parse pull request summary".into(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        let mut budget = initial_reply_budget();
        let mut raw_body = pr
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let body_truncated = cap_description(&mut raw_body, &mut budget);

        let head_oid = pr
            .get("lastMergeSourceCommit")
            .and_then(|c| c.get("commitId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let head_owner = summary.author.clone();

        let merge_status_str = pr.get("mergeStatus").and_then(|v| v.as_str()).unwrap_or("");
        let (mergeable, merge_state) = match merge_status_str {
            "succeeded" => (ForgeMergeable::Mergeable, ForgeMergeState::Clean),
            "conflicts" => (ForgeMergeable::Conflicting, ForgeMergeState::Conflicts),
            _ => (ForgeMergeable::Unknown, ForgeMergeState::Unknown),
        };

        let auto_merge_enabled = pr.get("autoCompleteSetBy").is_some_and(|v| !v.is_null());
        let created_at = pr
            .get("creationDate")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Commits
        let mut commits = Vec::new();
        let commits_url = self.api_url(&format!("/pullRequests/{number}/commits"));
        if let Ok((c_status, _, c_bytes)) = self
            .http
            .execute(
                self.http
                    .client()
                    .get(&commits_url)
                    .headers(self.headers())
                    .basic_auth("", Some(self.token)),
                false,
            )
            .await
        {
            if c_status.is_success() {
                if let Ok(c_json) = serde_json::from_slice::<Value>(&c_bytes) {
                    if let Some(values) = c_json.get("value").and_then(|v| v.as_array()) {
                        for c in values {
                            let oid = c
                                .get("commitId")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let headline = c
                                .get("comment")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .lines()
                                .next()
                                .unwrap_or("")
                                .to_string();
                            let author = c
                                .get("author")
                                .and_then(|a| a.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let authored_at = c
                                .get("author")
                                .and_then(|a| a.get("date"))
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
            }
        }

        // Reviews (from reviewers array)
        let mut reviews = Vec::new();
        if let Some(reviewers) = pr.get("reviewers").and_then(|r| r.as_array()) {
            for r in reviewers {
                let author = r
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let vote = r.get("vote").and_then(|v| v.as_i64()).unwrap_or(0);
                let state = if vote >= 5 {
                    ForgeReviewState::Approved
                } else if vote <= -5 {
                    ForgeReviewState::ChangesRequested
                } else {
                    ForgeReviewState::Pending
                };

                reviews.push(ForgeReview {
                    author,
                    state,
                    body: String::new(),
                    truncated: false,
                    submitted_at: String::new(),
                });
            }
        }

        // Comments (threads without threadContext)
        let mut comments = Vec::new();
        let threads_url = self.api_url(&format!("/pullRequests/{number}/threads"));
        if let Ok((t_status, _, t_bytes)) = self
            .http
            .execute(
                self.http
                    .client()
                    .get(&threads_url)
                    .headers(self.headers())
                    .basic_auth("", Some(self.token)),
                false,
            )
            .await
        {
            if t_status.is_success() {
                if let Ok(t_json) = serde_json::from_slice::<Value>(&t_bytes) {
                    if let Some(values) = t_json.get("value").and_then(|v| v.as_array()) {
                        for t in values {
                            if t.get("threadContext").is_none()
                                || t.get("threadContext").is_some_and(|v| v.is_null())
                            {
                                if let Some(c_arr) = t.get("comments").and_then(|c| c.as_array()) {
                                    for c in c_arr {
                                        let author = c
                                            .get("author")
                                            .and_then(|a| a.get("displayName"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let mut body = c
                                            .get("content")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let truncated = cap_comment_body(&mut body, &mut budget);
                                        let c_at = c
                                            .get("publishedDate")
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
                            }
                        }
                    }
                }
            }
        }

        Ok(ForgePrDetail {
            summary,
            body: raw_body,
            body_truncated,
            head_oid,
            head_owner,
            is_cross_repository: false,
            additions: None,
            deletions: None,
            changed_files: None,
            mergeable,
            merge_state,
            auto_merge_enabled,
            created_at,
            commits,
            reviews,
            comments,
        })
    }

    pub async fn checks(&self, number: u64) -> Result<Vec<ForgeCheck>, ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullRequests/{number}/statuses"));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut checks = Vec::new();

        if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
            for v in values {
                let context = v.get("context");
                let genre = context
                    .and_then(|c| c.get("genre"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                let cname = context
                    .and_then(|c| c.get("name"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                let name = if genre.is_empty() {
                    cname.to_string()
                } else {
                    format!("{genre}/{cname}")
                };

                let link = v
                    .get("targetUrl")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let started_at = v
                    .get("creationDate")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = v
                    .get("description")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();

                let state_str = v.get("state").and_then(|s| s.as_str()).unwrap_or("");
                let bucket = match state_str {
                    "succeeded" => ForgeCheckBucket::Pass,
                    "failed" | "error" => ForgeCheckBucket::Fail,
                    "notApplicable" => ForgeCheckBucket::Skipping,
                    _ => ForgeCheckBucket::Pending,
                };

                checks.push(ForgeCheck {
                    name,
                    group: "Checks".into(),
                    bucket,
                    link,
                    started_at,
                    completed_at: String::new(),
                    description,
                });
            }
        }

        Ok(checks)
    }

    pub async fn files(
        &self,
        number: u64,
        _head_oid: &str,
    ) -> Result<Vec<ForgePrFile>, ForgeError> {
        self.check_org()?;
        // 1. Get iterations
        let it_url = self.api_url(&format!("/pullRequests/{number}/iterations"));
        let (i_status, _, i_bytes) = self
            .http
            .execute(
                self.http
                    .client()
                    .get(&it_url)
                    .headers(self.headers())
                    .basic_auth("", Some(self.token)),
                false,
            )
            .await?;

        if !i_status.is_success() {
            return Ok(Vec::new());
        }

        let it_json: Value = serde_json::from_slice(&i_bytes).unwrap_or(Value::Null);
        let last_it = it_json
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.last())
            .and_then(|it| it.get("id"))
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        // 2. Get changes for iteration
        let changes_url = self.api_url(&format!(
            "/pullRequests/{number}/iterations/{last_it}/changes"
        ));
        let (c_status, _, c_bytes) = self
            .http
            .execute(
                self.http
                    .client()
                    .get(&changes_url)
                    .headers(self.headers())
                    .basic_auth("", Some(self.token)),
                false,
            )
            .await?;

        if !c_status.is_success() {
            return Ok(Vec::new());
        }

        let c_json: Value = serde_json::from_slice(&c_bytes).unwrap_or(Value::Null);
        let mut files = Vec::new();

        if let Some(changes) = c_json.get("changeEntries").and_then(|v| v.as_array()) {
            for item in changes {
                let raw_path = item
                    .get("item")
                    .and_then(|i| i.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let path = raw_path.trim_start_matches('/').to_string();
                let source_path = item
                    .get("sourceServerItem")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim_start_matches('/').to_string());

                let change_type = item
                    .get("changeType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("edit");
                let change = match change_type {
                    "add" => GitChange::Added,
                    "delete" => GitChange::Deleted,
                    "rename" => GitChange::Renamed,
                    _ => GitChange::Modified,
                };

                files.push(ForgePrFile {
                    path,
                    previous_path: source_path,
                    change,
                    additions: 0,
                    deletions: 0,
                });

                if files.len() >= MAX_PR_FILES {
                    break;
                }
            }
        }

        Ok(files)
    }

    pub async fn file_diff(
        &self,
        number: u64,
        path: &str,
        _head_oid: &str,
    ) -> Result<GitFileDiff, ForgeError> {
        self.check_org()?;
        // Fetch merge ref into local git: git fetch <remote> +refs/pull/{id}/merge:refs/cawide/pr/{id}
        let ctx = self
            .engine
            .build_request_ctx()
            .await
            .map_err(|e| ForgeError {
                kind: ForgeErrorKind::GitFailed,
                message: e,
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            })?;

        let refspec = format!("+refs/pull/{number}/merge:refs/cawide/pr/{number}");
        let fetch_cmd = self
            .engine
            .git_cmd(&ctx, &["fetch", self.remote_name, &refspec]);
        let out = crate::rpc::process::run(
            fetch_cmd,
            crate::rpc::process::RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_secs(60),
            },
        )
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::GitFailed,
            message: e.to_string(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        if !out.status.success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::GitFailed,
                message: format!(
                    "fetch Azure merge ref failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        // Run git diff refs/cawide/pr/{id}^1...refs/cawide/pr/{id}^2 -- <path>
        let rev = format!("refs/cawide/pr/{number}^1...refs/cawide/pr/{number}^2");
        let diff_cmd = self.engine.git_cmd(
            &ctx,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "-M",
                &rev,
                "--",
                path,
            ],
        );

        let diff_out = crate::rpc::process::run(
            diff_cmd,
            crate::rpc::process::RunOpts {
                stdin: None,
                stdout_cap: 8 * 1024 * 1024,
                timeout: Duration::from_secs(30),
            },
        )
        .await
        .map_err(|e| ForgeError {
            kind: ForgeErrorKind::GitFailed,
            message: e.to_string(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        let diff_text = String::from_utf8_lossy(&diff_out.stdout);
        let total_bytes = diff_text.len() as u64;
        let hunks = crate::rpc::git::diff::parse_unified_diff(&diff_text);

        Ok(GitFileDiff {
            path: path.to_string(),
            old_path: None,
            binary: false,
            too_large: false,
            lfs: false,
            total_bytes,
            hunks,
        })
    }

    pub async fn threads(&self, number: u64) -> Result<Vec<ForgeReviewThread>, ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullRequests/{number}/threads"));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut threads = Vec::new();
        let mut budget = initial_reply_budget();

        if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
            for t in values {
                let is_deleted = t
                    .get("isDeleted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let thread_ctx = t.get("threadContext");
                let file_path = thread_ctx
                    .and_then(|tc| tc.get("filePath"))
                    .and_then(|v| v.as_str());

                if !is_deleted {
                    if let Some(fp) = file_path {
                        let path = fp.trim_start_matches('/').to_string();
                        let tid = t.get("id").map(|v| v.to_string()).unwrap_or_default();

                        let right_start = thread_ctx
                            .and_then(|tc| tc.get("rightFileStart"))
                            .and_then(|p| p.get("line"))
                            .and_then(|v| v.as_u64())
                            .map(|n| n as u32);
                        let right_end = thread_ctx
                            .and_then(|tc| tc.get("rightFileEnd"))
                            .and_then(|p| p.get("line"))
                            .and_then(|v| v.as_u64())
                            .map(|n| n as u32);

                        let left_start = thread_ctx
                            .and_then(|tc| tc.get("leftFileStart"))
                            .and_then(|p| p.get("line"))
                            .and_then(|v| v.as_u64())
                            .map(|n| n as u32);
                        let left_end = thread_ctx
                            .and_then(|tc| tc.get("leftFileEnd"))
                            .and_then(|p| p.get("line"))
                            .and_then(|v| v.as_u64())
                            .map(|n| n as u32);

                        let (line, start_line, side) = if let Some(end) = right_end {
                            (
                                Some(end),
                                right_start.filter(|s| *s != end),
                                ForgeDiffSide::Right,
                            )
                        } else {
                            (
                                left_end,
                                left_start.filter(|s| *s != left_end.unwrap_or(0)),
                                ForgeDiffSide::Left,
                            )
                        };

                        let status_str = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        let resolved =
                            matches!(status_str, "fixed" | "closed" | "wontFix" | "byDesign");

                        let mut comments = Vec::new();
                        if let Some(c_arr) = t.get("comments").and_then(|c| c.as_array()) {
                            for c in c_arr {
                                let cid = c.get("id").map(|v| v.to_string()).unwrap_or_default();
                                let author = c
                                    .get("author")
                                    .and_then(|a| a.get("displayName"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let mut body = c
                                    .get("content")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let truncated = cap_comment_body(&mut body, &mut budget);
                                let c_at = c
                                    .get("publishedDate")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                comments.push(ForgeThreadComment {
                                    id: cid,
                                    author,
                                    body,
                                    truncated,
                                    created_at: c_at,
                                });
                            }
                        }

                        threads.push(ForgeReviewThread {
                            id: tid,
                            path,
                            line,
                            start_line,
                            side,
                            resolved,
                            outdated: false,
                            can_reply: true,
                            can_resolve: true,
                            comments,
                        });
                    }
                }
            }
        }

        Ok(threads)
    }

    pub async fn submit_review(&self, review: &ForgeReviewSubmission) -> Result<(), ForgeError> {
        self.check_org()?;
        // 1. Submit thread comments
        for t in &review.threads {
            let file_path = if t.path.starts_with('/') {
                t.path.clone()
            } else {
                format!("/{}", t.path)
            };
            let line_num = match t.side {
                ForgeDiffSide::Right => t.end.new_line.unwrap_or(1),
                ForgeDiffSide::Left => t.end.old_line.unwrap_or(1),
            };
            let start_line_num = match t.side {
                ForgeDiffSide::Right => t
                    .start
                    .as_ref()
                    .and_then(|s| s.new_line)
                    .unwrap_or(line_num),
                ForgeDiffSide::Left => t
                    .start
                    .as_ref()
                    .and_then(|s| s.old_line)
                    .unwrap_or(line_num),
            };

            let mut thread_ctx = json!({
                "filePath": file_path,
            });

            match t.side {
                ForgeDiffSide::Right => {
                    thread_ctx["rightFileStart"] = json!({ "line": start_line_num, "offset": 1 });
                    thread_ctx["rightFileEnd"] = json!({ "line": line_num, "offset": 1 });
                }
                ForgeDiffSide::Left => {
                    thread_ctx["leftFileStart"] = json!({ "line": start_line_num, "offset": 1 });
                    thread_ctx["leftFileEnd"] = json!({ "line": line_num, "offset": 1 });
                }
            }

            let payload = json!({
                "comments": [{
                    "parentCommentId": 0,
                    "content": t.body,
                    "commentType": 1,
                }],
                "status": 1,
                "threadContext": thread_ctx,
            });

            let url = self.api_url(&format!("/pullRequests/{}/threads", review.number));
            let rb = self
                .http
                .client()
                .post(&url)
                .headers(self.headers())
                .basic_auth("", Some(self.token))
                .json(&payload);
            let _ = self.http.execute(rb, false).await;
        }

        // 2. Submit body as general thread
        if !review.body.trim().is_empty() {
            let payload = json!({
                "comments": [{
                    "parentCommentId": 0,
                    "content": review.body,
                    "commentType": 1,
                }],
                "status": 1,
            });
            let url = self.api_url(&format!("/pullRequests/{}/threads", review.number));
            let rb = self
                .http
                .client()
                .post(&url)
                .headers(self.headers())
                .basic_auth("", Some(self.token))
                .json(&payload);
            let _ = self.http.execute(rb, false).await;
        }

        // 3. Vote: Approve (10), RequestChanges (-5)
        let vote = match review.event {
            ForgeReviewEvent::Approve => Some(10),
            ForgeReviewEvent::RequestChanges => Some(-5),
            ForgeReviewEvent::Comment => None,
        };

        if let Some(v) = vote {
            if let Ok(uid) = self.get_user_id().await {
                let vote_url =
                    self.api_url(&format!("/pullRequests/{}/reviewers/{uid}", review.number));
                let rb = self
                    .http
                    .client()
                    .put(&vote_url)
                    .headers(self.headers())
                    .basic_auth("", Some(self.token))
                    .json(&json!({ "vote": v }));
                let _ = self.http.execute(rb, false).await;
            }
        }

        Ok(())
    }

    pub async fn reply(&self, number: u64, thread_id: &str, body: &str) -> Result<(), ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!(
            "/pullRequests/{number}/threads/{thread_id}/comments"
        ));
        let payload = json!({
            "parentCommentId": 1,
            "content": body,
            "commentType": 1,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token))
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("reply to comment failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn resolve(
        &self,
        number: u64,
        thread_id: &str,
        resolved: bool,
    ) -> Result<(), ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullRequests/{number}/threads/{thread_id}"));
        let status_val = if resolved { 2 } else { 1 };
        let payload = json!({ "status": status_val });

        let rb = self
            .http
            .client()
            .patch(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token))
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("resolve/reopen comment failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn comment(&self, number: u64, body: &str) -> Result<(), ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullRequests/{number}/threads"));
        let payload = json!({
            "comments": [{
                "parentCommentId": 0,
                "content": body,
                "commentType": 1,
            }],
            "status": 1,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token))
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("comment failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn merge(&self, req: &ForgeMergeRequest) -> Result<(), ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullrequests/{}", req.number));
        let strategy = match req.method {
            ForgeMergeMethod::Merge => "noFastForward",
            ForgeMergeMethod::Squash => "squash",
            ForgeMergeMethod::Rebase => "rebase",
        };

        let mut completion_options = json!({
            "mergeStrategy": strategy,
            "deleteSourceBranch": req.delete_branch,
        });

        if let Some(ref m) = req.subject {
            completion_options["mergeCommitMessage"] = json!(m);
        }

        let payload = if req.auto {
            let uid = self.get_user_id().await.unwrap_or_default();
            json!({
                "autoCompleteSetBy": { "id": uid },
                "completionOptions": completion_options,
            })
        } else {
            json!({
                "status": "completed",
                "lastMergeSourceCommit": { "commitId": req.head_oid },
                "completionOptions": completion_options,
            })
        };

        let rb = self
            .http
            .client()
            .patch(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token))
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, true).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::MergeBlocked,
                message: format!("Azure DevOps merge failed: {status}"),
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
        _head_spec: &str,
    ) -> Result<(u64, String), ForgeError> {
        self.check_org()?;
        let url = self.api_url("/pullrequests");
        let source_ref = format!("refs/heads/{}", req.head_branch);
        let target_ref = format!("refs/heads/{}", req.base);

        let payload = json!({
            "sourceRefName": source_ref,
            "targetRefName": target_ref,
            "title": req.title,
            "description": req.body,
            "isDraft": req.draft,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token))
            .json(&payload);
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: if status == StatusCode::CONFLICT {
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
        let number = json
            .get("pullRequestId")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let (org, project) = self.org_and_project();
        let pr_url = format!(
            "{}/{org}/{project}/_git/{}/pullrequest/{number}",
            self.http.url(self.host, "https", ""),
            self.name
        );

        Ok((number, pr_url))
    }

    pub async fn set_state(
        &self,
        number: u64,
        change: ForgePrStateChange,
    ) -> Result<(), ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullrequests/{number}"));
        let payload = match change {
            ForgePrStateChange::Close => json!({ "status": "abandoned" }),
            ForgePrStateChange::Reopen => json!({ "status": "active" }),
            ForgePrStateChange::Ready => json!({ "isDraft": false }),
            ForgePrStateChange::ConvertToDraft => json!({ "isDraft": true }),
        };

        let rb = self
            .http
            .client()
            .patch(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token))
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("update state failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn checkout_source(&self, number: u64) -> Result<CheckoutSource, ForgeError> {
        self.check_org()?;
        let url = self.api_url(&format!("/pullrequests/{number}"));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth("", Some(self.token));
        let (_, _, bytes) = self.http.execute(rb, false).await?;
        let pr: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        let source_ref = pr
            .get("sourceRefName")
            .and_then(|v| v.as_str())
            .unwrap_or("refs/heads/main");
        let branch = source_ref.strip_prefix("refs/heads/").unwrap_or(source_ref);

        Ok(CheckoutSource {
            fetch_from: self.remote_name.to_string(),
            refspec: format!("refs/heads/{branch}"),
            local_branch: format!("pr/{number}"),
        })
    }
}

fn parse_azure_pr_summary(val: &Value) -> Option<ForgePrSummary> {
    let number = val.get("pullRequestId")?.as_u64()?;
    let title = val.get("title")?.as_str()?.to_string();
    let author = val
        .get("createdBy")
        .and_then(|c| c.get("displayName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let status_str = val.get("status")?.as_str()?;
    let state = match status_str {
        "active" => ForgePrState::Open,
        "completed" => ForgePrState::Merged,
        _ => ForgePrState::Closed,
    };

    let is_draft = val
        .get("isDraft")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let head_ref = val
        .get("sourceRefName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .strip_prefix("refs/heads/")
        .unwrap_or("")
        .to_string();

    let base_ref = val
        .get("targetRefName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .strip_prefix("refs/heads/")
        .unwrap_or("")
        .to_string();

    let updated_at = val
        .get("creationDate")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let url = val
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut review_decision = None;
    if let Some(reviewers) = val.get("reviewers").and_then(|r| r.as_array()) {
        let mut changes_req = false;
        let mut app = false;
        for r in reviewers {
            let vote = r.get("vote").and_then(|v| v.as_i64()).unwrap_or(0);
            if vote <= -5 {
                changes_req = true;
            } else if vote >= 5 {
                app = true;
            }
        }
        if changes_req {
            review_decision = Some(ForgeReviewDecision::ChangesRequested);
        } else if app {
            review_decision = Some(ForgeReviewDecision::Approved);
        } else if !reviewers.is_empty() {
            review_decision = Some(ForgeReviewDecision::ReviewRequired);
        }
    }

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
        checks: cawide_protocol::types::ForgeChecksRollup::NoChecks,
        url,
    })
}
