use super::CheckoutSource;
use crate::forge::capabilities::default_capabilities;
use crate::forge::http::ForgeHttp;
use crate::forge::text::{cap_comment_body, cap_description, initial_reply_budget};
use cawide_protocol::types::{
    ForgeCheck, ForgeCheckBucket, ForgeComment, ForgeCreateRequest, ForgeDiffSide, ForgeError,
    ForgeErrorKind, ForgeKind, ForgeMergeMethod, ForgeMergeRequest, ForgeMergeState,
    ForgeMergeable, ForgePrCommit, ForgePrDetail, ForgePrFile, ForgePrFilter, ForgePrState,
    ForgePrStateChange, ForgePrSummary, ForgeRepository, ForgeReview, ForgeReviewEvent,
    ForgeReviewState, ForgeReviewSubmission, ForgeReviewThread, ForgeThreadComment, GitChange,
    GitFileDiff, MAX_FORGE_DIFF_BYTES, MAX_PR_FILES,
};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;

pub struct GiteaAdapter<'a> {
    pub http: &'a ForgeHttp,
    pub scheme: &'a str,
    pub host: &'a str,
    pub namespace: &'a str,
    pub name: &'a str,
    pub token: &'a str,
    pub remote_name: &'a str,
}

impl<'a> GiteaAdapter<'a> {
    fn api_url(&self, path: &str) -> String {
        let clean = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };
        self.http
            .url(self.host, self.scheme, &format!("/api/v1{clean}"))
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static("cawide"));
        if let Ok(v) = HeaderValue::from_str(&format!("token {}", self.token)) {
            h.insert(AUTHORIZATION, v);
        }
        h.insert(ACCEPT, HeaderValue::from_static("application/json"));
        h
    }

    async fn get_current_user_login(&self) -> Option<String> {
        let url = self.api_url("/user");
        let rb = self.http.client().get(&url).headers(self.headers());
        if let Ok((status, _, bytes)) = self.http.execute(rb, false).await {
            if status.is_success() {
                if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
                    return json
                        .get("login")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                }
            }
        }
        None
    }

    pub async fn repository(&self) -> Result<ForgeRepository, ForgeError> {
        let url = self.api_url(&format!("/repos/{}/{}", self.namespace, self.name));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to fetch Gitea repo: {status}"),
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
                || p.get("push").and_then(|v| v.as_bool()).unwrap_or(false)
        });

        let mut merge_methods = Vec::new();
        if json
            .get("allow_merge_commits")
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
            .get("allow_rebase")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            merge_methods.push(ForgeMergeMethod::Rebase);
        }

        let delete_branch_on_merge = json
            .get("default_delete_branch_after_merge")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let capabilities = default_capabilities(ForgeKind::Gitea);

        Ok(ForgeRepository {
            kind: ForgeKind::Gitea,
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
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls?state=open&limit=50",
            self.namespace, self.name
        ));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(None);
        }

        let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        for item in &arr {
            let head_ref = item
                .get("head")
                .and_then(|h| h.get("ref"))
                .and_then(|v| v.as_str());
            if head_ref == Some(branch) {
                return Ok(parse_gitea_pr_summary(item));
            }
        }
        Ok(None)
    }

    pub async fn list(
        &self,
        filter: ForgePrFilter,
        limit: u32,
    ) -> Result<Vec<ForgePrSummary>, ForgeError> {
        let me = self.get_current_user_login().await.unwrap_or_default();
        let state_param = match filter {
            ForgePrFilter::Merged | ForgePrFilter::Closed => "closed",
            _ => "open",
        };

        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls?state={state_param}&sort=recentupdate&limit=50",
            self.namespace, self.name
        ));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to list pull requests: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut list = Vec::new();

        for item in &arr {
            let author = item
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let merged = item
                .get("merged")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let include = match filter {
                ForgePrFilter::Mine => author == me,
                ForgePrFilter::NeedsMyReview => {
                    let req_revs = item.get("requested_reviewers").and_then(|r| r.as_array());
                    req_revs.is_some_and(|arr| {
                        arr.iter()
                            .any(|u| u.get("login").and_then(|v| v.as_str()) == Some(&me))
                    })
                }
                ForgePrFilter::Merged => merged,
                ForgePrFilter::Closed => !merged,
                ForgePrFilter::Open => true,
            };

            if include {
                if let Some(s) = parse_gitea_pr_summary(item) {
                    list.push(s);
                    if list.len() >= limit as usize {
                        break;
                    }
                }
            }
        }

        Ok(list)
    }

    pub async fn detail(&self, number: u64) -> Result<ForgePrDetail, ForgeError> {
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}",
            self.namespace, self.name
        ));
        let rb = self.http.client().get(&url).headers(self.headers());
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
        let summary = parse_gitea_pr_summary(&pr).ok_or_else(|| ForgeError {
            kind: ForgeErrorKind::Other,
            message: "failed to parse pull request summary".into(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        let mut budget = initial_reply_budget();
        let mut raw_body = pr
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let body_truncated = cap_description(&mut raw_body, &mut budget);

        let head_oid = pr
            .get("head")
            .and_then(|h| h.get("sha"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let head_owner = pr
            .get("head")
            .and_then(|h| h.get("repo"))
            .and_then(|r| r.get("owner"))
            .and_then(|o| o.get("login"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let base_owner = pr
            .get("base")
            .and_then(|b| b.get("repo"))
            .and_then(|r| r.get("owner"))
            .and_then(|o| o.get("login"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let is_cross_repository = head_owner != base_owner;

        let mergeable_bool = pr.get("mergeable").and_then(|v| v.as_bool());
        let mergeable = match mergeable_bool {
            Some(true) => ForgeMergeable::Mergeable,
            Some(false) => ForgeMergeable::Conflicting,
            None => ForgeMergeable::Unknown,
        };

        let merge_state = if mergeable_bool == Some(false) {
            ForgeMergeState::Conflicts
        } else {
            ForgeMergeState::Clean
        };

        let additions = pr
            .get("additions")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let deletions = pr
            .get("deletions")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let changed_files = pr
            .get("changed_files")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let created_at = pr
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Commits
        let mut commits = Vec::new();
        let commits_url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}/commits",
            self.namespace, self.name
        ));
        if let Ok((c_status, _, c_bytes)) = self
            .http
            .execute(
                self.http.client().get(&commits_url).headers(self.headers()),
                false,
            )
            .await
        {
            if c_status.is_success() {
                if let Ok(c_arr) = serde_json::from_slice::<Vec<Value>>(&c_bytes) {
                    for c in c_arr {
                        let oid = c
                            .get("sha")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let headline = c
                            .get("commit")
                            .and_then(|cm| cm.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_string();
                        let author = c
                            .get("commit")
                            .and_then(|cm| cm.get("author"))
                            .and_then(|a| a.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let authored_at = c
                            .get("commit")
                            .and_then(|cm| cm.get("author"))
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

        // Reviews
        let mut reviews = Vec::new();
        let reviews_url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}/reviews",
            self.namespace, self.name
        ));
        if let Ok((r_status, _, r_bytes)) = self
            .http
            .execute(
                self.http.client().get(&reviews_url).headers(self.headers()),
                false,
            )
            .await
        {
            if r_status.is_success() {
                if let Ok(r_arr) = serde_json::from_slice::<Vec<Value>>(&r_bytes) {
                    for r in r_arr {
                        let author = r
                            .get("user")
                            .and_then(|u| u.get("login"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let state_str = r.get("state").and_then(|v| v.as_str()).unwrap_or("");
                        let state = match state_str {
                            "APPROVED" => ForgeReviewState::Approved,
                            "REQUEST_CHANGES" => ForgeReviewState::ChangesRequested,
                            "COMMENT" => ForgeReviewState::Commented,
                            _ => ForgeReviewState::Pending,
                        };
                        let mut body = r
                            .get("body")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let truncated = cap_comment_body(&mut body, &mut budget);
                        let submitted_at = r
                            .get("submitted_at")
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
            }
        }

        // Comments
        let mut comments = Vec::new();
        let comments_url = self.api_url(&format!(
            "/repos/{}/{}/issues/{number}/comments",
            self.namespace, self.name
        ));
        if let Ok((co_status, _, co_bytes)) = self
            .http
            .execute(
                self.http
                    .client()
                    .get(&comments_url)
                    .headers(self.headers()),
                false,
            )
            .await
        {
            if co_status.is_success() {
                if let Ok(co_arr) = serde_json::from_slice::<Vec<Value>>(&co_bytes) {
                    for co in co_arr {
                        let author = co
                            .get("user")
                            .and_then(|u| u.get("login"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let mut body = co
                            .get("body")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let truncated = cap_comment_body(&mut body, &mut budget);
                        let c_at = co
                            .get("created_at")
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

        Ok(ForgePrDetail {
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
            auto_merge_enabled: false,
            created_at,
            commits,
            reviews,
            comments,
        })
    }

    pub async fn statuses_for_head(&self, head_sha: &str) -> Result<Vec<ForgeCheck>, ForgeError> {
        if head_sha.is_empty() {
            return Ok(Vec::new());
        }

        let status_url = self.api_url(&format!(
            "/repos/{}/{}/commits/{head_sha}/status",
            self.namespace, self.name
        ));
        let (_, _, s_bytes) = self
            .http
            .execute(
                self.http.client().get(&status_url).headers(self.headers()),
                false,
            )
            .await?;

        let obj: Value = serde_json::from_slice(&s_bytes).unwrap_or(Value::Null);
        let items = obj.get("statuses").and_then(|v| v.as_array());

        let mut checks = Vec::new();
        if let Some(items) = items {
            for item in items {
                let name = item
                    .get("context")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let link = item
                    .get("target_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = item
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let started_at = item
                    .get("created_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let state_str = item.get("status").and_then(|v| v.as_str()).unwrap_or("");
                let bucket = match state_str {
                    "success" | "warning" => ForgeCheckBucket::Pass,
                    "failure" | "error" => ForgeCheckBucket::Fail,
                    _ => ForgeCheckBucket::Pending,
                };

                checks.push(ForgeCheck {
                    name,
                    group: "Status".into(),
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

    pub async fn checks(&self, number: u64) -> Result<Vec<ForgeCheck>, ForgeError> {
        let detail = self.detail(number).await?;
        self.statuses_for_head(&detail.head_oid).await
    }

    pub async fn files(
        &self,
        number: u64,
        _head_oid: &str,
    ) -> Result<Vec<ForgePrFile>, ForgeError> {
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}/files",
            self.namespace, self.name
        ));
        let (status, _, bytes) = self
            .http
            .execute(self.http.client().get(&url).headers(self.headers()), false)
            .await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut files = Vec::new();

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

            files.push(ForgePrFile {
                path,
                previous_path,
                change,
                additions,
                deletions,
            });

            if files.len() >= MAX_PR_FILES {
                break;
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
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}.diff",
            self.namespace, self.name
        ));
        let (status, _, bytes) = self
            .http
            .execute(self.http.client().get(&url).headers(self.headers()), false)
            .await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: format!("diff for PR #{number} not found"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let full_diff = String::from_utf8_lossy(&bytes);
        let sections = full_diff.split("diff --git ");

        for sec in sections {
            if sec.trim().is_empty() {
                continue;
            }
            let reconstructed = format!("diff --git {sec}");
            let hunks = crate::rpc::git::diff::parse_unified_diff(&reconstructed);
            if hunks.iter().any(|h| h.file_path == path) {
                let total_bytes = reconstructed.len() as u64;
                let too_large = reconstructed.len() > MAX_FORGE_DIFF_BYTES;
                return Ok(GitFileDiff {
                    path: path.to_string(),
                    old_path: None,
                    binary: false,
                    too_large,
                    lfs: false,
                    total_bytes,
                    hunks: if too_large { Vec::new() } else { hunks },
                });
            }
        }

        Err(ForgeError {
            kind: ForgeErrorKind::NotFound,
            message: format!("file {path} not found in diff"),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })
    }

    pub async fn threads(&self, number: u64) -> Result<Vec<ForgeReviewThread>, ForgeError> {
        let reviews_url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}/reviews",
            self.namespace, self.name
        ));
        let (status, _, bytes) = self
            .http
            .execute(
                self.http.client().get(&reviews_url).headers(self.headers()),
                false,
            )
            .await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let r_arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut threads_map: HashMap<(String, u32, u32), Vec<ForgeThreadComment>> = HashMap::new();
        let mut resolver_map: HashMap<(String, u32, u32), bool> = HashMap::new();
        let mut budget = initial_reply_budget();

        for r in r_arr {
            let rid = r.get("id").map(|v| v.to_string()).unwrap_or_default();
            let c_url = self.api_url(&format!(
                "/repos/{}/{}/pulls/{number}/reviews/{rid}/comments",
                self.namespace, self.name
            ));
            if let Ok((cs, _, cb)) = self
                .http
                .execute(
                    self.http.client().get(&c_url).headers(self.headers()),
                    false,
                )
                .await
            {
                if cs.is_success() {
                    if let Ok(c_arr) = serde_json::from_slice::<Vec<Value>>(&cb) {
                        for c in c_arr {
                            let path = c
                                .get("path")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let pos =
                                c.get("position").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                            let orig_pos = c
                                .get("original_position")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let key = (path, pos, orig_pos);

                            let cid = c.get("id").map(|v| v.to_string()).unwrap_or_default();
                            let author = c
                                .get("user")
                                .and_then(|u| u.get("login"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let mut body = c
                                .get("body")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let truncated = cap_comment_body(&mut body, &mut budget);
                            let c_at = c
                                .get("created_at")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            let is_resolved = c.get("resolver").is_some_and(|v| !v.is_null());
                            resolver_map.insert(key.clone(), is_resolved);

                            threads_map
                                .entry(key)
                                .or_default()
                                .push(ForgeThreadComment {
                                    id: cid,
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

        let mut threads = Vec::new();
        for ((path, pos, orig_pos), comments) in threads_map {
            let (line, side) = if pos > 0 {
                (Some(pos), ForgeDiffSide::Right)
            } else {
                (Some(orig_pos), ForgeDiffSide::Left)
            };

            let resolved = resolver_map
                .get(&(path.clone(), pos, orig_pos))
                .copied()
                .unwrap_or(false);

            threads.push(ForgeReviewThread {
                id: format!("{path}:{pos}:{orig_pos}"),
                path,
                line,
                start_line: None,
                side,
                resolved,
                outdated: false,
                can_reply: false,
                can_resolve: false,
                comments,
            });
        }

        Ok(threads)
    }

    pub async fn submit_review(&self, review: &ForgeReviewSubmission) -> Result<(), ForgeError> {
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{}/reviews",
            self.namespace, self.name, review.number
        ));

        let event = match review.event {
            ForgeReviewEvent::Comment => "COMMENT",
            ForgeReviewEvent::Approve => "APPROVED",
            ForgeReviewEvent::RequestChanges => "REQUEST_CHANGES",
        };

        let mut comments = Vec::new();
        for t in &review.threads {
            let mut obj = json!({
                "path": t.path,
                "body": t.body,
            });
            match t.side {
                ForgeDiffSide::Right => {
                    obj["new_position"] = json!(t.end.new_line.unwrap_or(1));
                }
                ForgeDiffSide::Left => {
                    obj["old_position"] = json!(t.end.old_line.unwrap_or(1));
                }
            }
            comments.push(obj);
        }

        let payload = json!({
            "event": event,
            "body": review.body,
            "commit_id": review.head_oid,
            "comments": comments,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("submit review failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        Ok(())
    }

    pub async fn reply(
        &self,
        _number: u64,
        _thread_id: &str,
        _body: &str,
    ) -> Result<(), ForgeError> {
        Err(ForgeError {
            kind: ForgeErrorKind::Unsupported,
            message: "replying to review comments is not supported by Gitea API".into(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })
    }

    pub async fn resolve(
        &self,
        _number: u64,
        _thread_id: &str,
        _resolved: bool,
    ) -> Result<(), ForgeError> {
        Err(ForgeError {
            kind: ForgeErrorKind::Unsupported,
            message: "resolving review comments is not supported by Gitea API".into(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })
    }

    pub async fn comment(&self, number: u64, body: &str) -> Result<(), ForgeError> {
        let url = self.api_url(&format!(
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
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{}/merge",
            self.namespace, self.name, req.number
        ));
        let do_val = match req.method {
            ForgeMergeMethod::Merge => "merge",
            ForgeMergeMethod::Squash => "squash",
            ForgeMergeMethod::Rebase => "rebase",
        };

        let mut payload = json!({
            "Do": do_val,
            "delete_branch_after_merge": req.delete_branch,
            "merge_when_checks_succeed": req.auto,
            "head_commit_id": req.head_oid,
        });

        if let Some(ref s) = req.subject {
            payload["MergeTitleField"] = json!(s);
        }
        if let Some(ref b) = req.body {
            payload["MergeMessageField"] = json!(b);
        }

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, true).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::MergeBlocked,
                message: format!("Gitea merge failed: {status}"),
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
        let url = self.api_url(&format!("/repos/{}/{}/pulls", self.namespace, self.name));
        let title = if req.draft && !req.title.starts_with("WIP: ") {
            format!("WIP: {}", req.title)
        } else {
            req.title.clone()
        };

        let payload = json!({
            "title": title,
            "body": req.body,
            "head": req.head_branch,
            "base": req.base,
            "assignees": req.reviewers,
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
                kind: if status == StatusCode::CONFLICT
                    || status == StatusCode::UNPROCESSABLE_ENTITY
                {
                    ForgeErrorKind::AlreadyExists
                } else {
                    ForgeErrorKind::Other
                },
                message: format!("failed to create pull request: {status}"),
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

        Ok((number, pr_url))
    }

    pub async fn set_state(
        &self,
        number: u64,
        change: ForgePrStateChange,
    ) -> Result<(), ForgeError> {
        let url = self.api_url(&format!(
            "/repos/{}/{}/pulls/{number}",
            self.namespace, self.name
        ));

        match change {
            ForgePrStateChange::Close => {
                let rb = self
                    .http
                    .client()
                    .patch(&url)
                    .headers(self.headers())
                    .json(&json!({ "state": "closed" }));
                let _ = self.http.execute(rb, false).await?;
            }
            ForgePrStateChange::Reopen => {
                let rb = self
                    .http
                    .client()
                    .patch(&url)
                    .headers(self.headers())
                    .json(&json!({ "state": "open" }));
                let _ = self.http.execute(rb, false).await?;
            }
            ForgePrStateChange::Ready => {
                let (_, _, bytes) = self
                    .http
                    .execute(self.http.client().get(&url).headers(self.headers()), false)
                    .await?;
                let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                let title = json.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let clean_title = title
                    .strip_prefix("WIP: ")
                    .or_else(|| title.strip_prefix("[WIP] "))
                    .unwrap_or(title);
                let rb = self
                    .http
                    .client()
                    .patch(&url)
                    .headers(self.headers())
                    .json(&json!({ "title": clean_title }));
                let _ = self.http.execute(rb, false).await?;
            }
            ForgePrStateChange::ConvertToDraft => {
                let (_, _, bytes) = self
                    .http
                    .execute(self.http.client().get(&url).headers(self.headers()), false)
                    .await?;
                let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                let title = json.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let draft_title = format!("WIP: {title}");
                let rb = self
                    .http
                    .client()
                    .patch(&url)
                    .headers(self.headers())
                    .json(&json!({ "title": draft_title }));
                let _ = self.http.execute(rb, false).await?;
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

fn parse_gitea_pr_summary(val: &Value) -> Option<ForgePrSummary> {
    let number = val.get("number")?.as_u64()?;
    let title = val.get("title")?.as_str()?.to_string();
    let author = val
        .get("user")
        .and_then(|u| u.get("login"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let state_str = val.get("state")?.as_str()?;
    let merged = val.get("merged").and_then(|v| v.as_bool()).unwrap_or(false);
    let state = if merged {
        ForgePrState::Merged
    } else if state_str == "open" {
        ForgePrState::Open
    } else {
        ForgePrState::Closed
    };

    let is_draft = val.get("draft").and_then(|v| v.as_bool()).unwrap_or(false)
        || title.starts_with("WIP:")
        || title.starts_with("[WIP]");

    let head_ref = val
        .get("head")
        .and_then(|h| h.get("ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let base_ref = val
        .get("base")
        .and_then(|b| b.get("ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let updated_at = val
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let url = val
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(ForgePrSummary {
        number,
        title,
        author,
        state,
        is_draft,
        head_ref,
        base_ref,
        updated_at,
        review_decision: None,
        checks: cawide_protocol::types::ForgeChecksRollup::NoChecks,
        url,
    })
}
