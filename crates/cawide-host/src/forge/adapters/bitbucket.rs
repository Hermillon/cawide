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
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;

pub struct BitbucketAdapter<'a> {
    pub http: &'a ForgeHttp,
    pub host: &'a str,
    pub namespace: &'a str, // workspace
    pub name: &'a str,      // repo_slug
    pub login: &'a str,     // email or username
    pub token: &'a str,
    pub remote_name: &'a str,
}

impl<'a> BitbucketAdapter<'a> {
    fn api_url(&self, path: &str) -> String {
        let clean = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };
        self.http
            .url("api.bitbucket.org", "https", &format!("/2.0{clean}"))
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static("cawide"));
        h.insert(ACCEPT, HeaderValue::from_static("application/json"));
        h
    }

    async fn get_user_uuid(&self) -> Option<String> {
        let url = self.api_url("/user");
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        if let Ok((status, _, bytes)) = self.http.execute(rb, false).await {
            if status.is_success() {
                if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
                    return json
                        .get("uuid")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                }
            }
        }
        None
    }

    pub async fn repository(&self) -> Result<ForgeRepository, ForgeError> {
        let url = self.api_url(&format!("/repositories/{}/{}", self.namespace, self.name));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to fetch Bitbucket repo: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        let default_branch = json
            .get("mainbranch")
            .and_then(|m| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("main")
            .to_string();

        let web_url = json
            .get("links")
            .and_then(|l| l.get("html"))
            .and_then(|h| h.get("href"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Check workspace permissions
        let perm_url = self.api_url(&format!(
            "/user/workspaces/{}/permissions/repositories?q=repository.full_name=\"{}/{}\"",
            self.namespace, self.namespace, self.name
        ));
        let perm_rb = self
            .http
            .client()
            .get(&perm_url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let mut viewer_can_merge = true;
        if let Ok((p_status, _, p_bytes)) = self.http.execute(perm_rb, false).await {
            if p_status.is_success() {
                if let Ok(p_json) = serde_json::from_slice::<Value>(&p_bytes) {
                    if let Some(values) = p_json.get("values").and_then(|v| v.as_array()) {
                        if let Some(first) = values.first() {
                            let p = first
                                .get("permission")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            viewer_can_merge = p == "admin" || p == "write";
                        }
                    }
                }
            }
        }

        let merge_methods = vec![
            ForgeMergeMethod::Merge,
            ForgeMergeMethod::Squash,
            ForgeMergeMethod::Rebase,
        ];

        let capabilities = default_capabilities(ForgeKind::Bitbucket);

        Ok(ForgeRepository {
            kind: ForgeKind::Bitbucket,
            host: self.host.to_string(),
            namespace: self.namespace.to_string(),
            name: self.name.to_string(),
            web_url,
            default_branch,
            remote_name: self.remote_name.to_string(),
            viewer_can_merge,
            merge_methods,
            delete_branch_on_merge: false,
            capabilities,
        })
    }

    pub async fn current_pull_request(
        &self,
        branch: &str,
    ) -> Result<Option<ForgePrSummary>, ForgeError> {
        let q = format!("source.branch.name=\"{branch}\" AND state=\"OPEN\"");
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests?q={}&pagelen=1",
            self.namespace,
            self.name,
            crate::forge::http::url_encode(&q)
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(None);
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            if let Some(first) = values.first() {
                return Ok(parse_bb_pr_summary(first));
            }
        }
        Ok(None)
    }

    pub async fn list(
        &self,
        filter: ForgePrFilter,
        limit: u32,
    ) -> Result<Vec<ForgePrSummary>, ForgeError> {
        let state_param = match filter {
            ForgePrFilter::Merged => "MERGED",
            ForgePrFilter::Closed => "DECLINED",
            _ => "OPEN",
        };

        let mut q = format!("state=\"{state_param}\"");
        match filter {
            ForgePrFilter::NeedsMyReview => {
                if let Some(uuid) = self.get_user_uuid().await {
                    q.push_str(&format!(" AND reviewers.uuid=\"{uuid}\""));
                }
            }
            ForgePrFilter::Mine => {
                if let Some(uuid) = self.get_user_uuid().await {
                    q.push_str(&format!(" AND author.uuid=\"{uuid}\""));
                }
            }
            _ => {}
        }

        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests?q={}&pagelen={limit}&sort=-updated_on",
            self.namespace,
            self.name,
            crate::forge::http::url_encode(&q)
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
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

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut list = Vec::new();

        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            for v in values {
                if let Some(s) = parse_bb_pr_summary(v) {
                    list.push(s);
                }
            }
        }

        Ok(list)
    }

    pub async fn detail(&self, number: u64) -> Result<ForgePrDetail, ForgeError> {
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
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
        let summary = parse_bb_pr_summary(&pr).ok_or_else(|| ForgeError {
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
            .get("source")
            .and_then(|s| s.get("commit"))
            .and_then(|c| c.get("hash"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let head_owner = pr
            .get("source")
            .and_then(|s| s.get("repository"))
            .and_then(|r| r.get("full_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let is_cross_repository =
            !head_owner.is_empty() && head_owner != format!("{}/{}", self.namespace, self.name);

        let created_at = pr
            .get("created_on")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Review decision from participants

        let mut reviews = Vec::new();

        if let Some(participants) = pr.get("participants").and_then(|p| p.as_array()) {
            for p in participants {
                let user_name = p
                    .get("user")
                    .and_then(|u| u.get("display_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let state_str = p.get("state").and_then(|v| v.as_str()).unwrap_or("");
                let is_approved = p.get("approved").and_then(|v| v.as_bool()).unwrap_or(false);

                if state_str == "changes_requested" {
                    reviews.push(ForgeReview {
                        author: user_name,
                        state: ForgeReviewState::ChangesRequested,
                        body: String::new(),
                        truncated: false,
                        submitted_at: String::new(),
                    });
                } else if is_approved {
                    reviews.push(ForgeReview {
                        author: user_name,
                        state: ForgeReviewState::Approved,
                        body: String::new(),
                        truncated: false,
                        submitted_at: String::new(),
                    });
                }
            }
        }

        // Commits
        let mut commits = Vec::new();
        let commits_url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/commits",
            self.namespace, self.name
        ));
        let c_rb = self
            .http
            .client()
            .get(&commits_url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        if let Ok((c_status, _, c_bytes)) = self.http.execute(c_rb, false).await {
            if c_status.is_success() {
                if let Ok(c_json) = serde_json::from_slice::<Value>(&c_bytes) {
                    if let Some(values) = c_json.get("values").and_then(|v| v.as_array()) {
                        for c in values {
                            let oid = c
                                .get("hash")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let headline = c
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .lines()
                                .next()
                                .unwrap_or("")
                                .to_string();
                            let author = c
                                .get("author")
                                .and_then(|a| a.get("user"))
                                .and_then(|u| u.get("display_name"))
                                .or_else(|| c.get("author").and_then(|a| a.get("raw")))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let authored_at = c
                                .get("date")
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

        // Conversation comments
        let mut comments = Vec::new();
        let comments_url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/comments?pagelen=100",
            self.namespace, self.name
        ));
        let co_rb = self
            .http
            .client()
            .get(&comments_url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        if let Ok((co_status, _, co_bytes)) = self.http.execute(co_rb, false).await {
            if co_status.is_success() {
                if let Ok(co_json) = serde_json::from_slice::<Value>(&co_bytes) {
                    if let Some(values) = co_json.get("values").and_then(|v| v.as_array()) {
                        for c in values {
                            let has_inline = c.get("inline").is_some_and(|v| !v.is_null());
                            let has_parent = c.get("parent").is_some_and(|v| !v.is_null());
                            if !has_inline && !has_parent {
                                let author = c
                                    .get("user")
                                    .and_then(|u| u.get("display_name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let mut body = c
                                    .get("content")
                                    .and_then(|cnt| cnt.get("raw"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let truncated = cap_comment_body(&mut body, &mut budget);
                                let c_at = c
                                    .get("created_on")
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

        Ok(ForgePrDetail {
            summary,
            body: raw_body,
            body_truncated,
            head_oid,
            head_owner,
            is_cross_repository,
            additions: None,
            deletions: None,
            changed_files: None,
            mergeable: ForgeMergeable::Unknown,
            merge_state: ForgeMergeState::Unknown,
            auto_merge_enabled: false,
            created_at,
            commits,
            reviews,
            comments,
        })
    }

    pub async fn checks(&self, number: u64) -> Result<Vec<ForgeCheck>, ForgeError> {
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/statuses",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut checks = Vec::new();

        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            for v in values {
                let name = v
                    .get("name")
                    .or_else(|| v.get("key"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let link = v
                    .get("url")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let started_at = v
                    .get("created_on")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let completed_at = v
                    .get("updated_on")
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
                    "SUCCESSFUL" => ForgeCheckBucket::Pass,
                    "FAILED" => ForgeCheckBucket::Fail,
                    "INPROGRESS" => ForgeCheckBucket::Pending,
                    "STOPPED" => ForgeCheckBucket::Cancel,
                    _ => ForgeCheckBucket::Pending,
                };

                checks.push(ForgeCheck {
                    name,
                    group: "Status".into(),
                    bucket,
                    link,
                    started_at,
                    completed_at,
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
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/diffstat?pagelen=100",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut files = Vec::new();

        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            for item in values {
                let path = item
                    .get("new")
                    .and_then(|n| n.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let old_path = item
                    .get("old")
                    .and_then(|o| o.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let previous_path = if old_path.as_deref() != Some(&path) {
                    old_path
                } else {
                    None
                };

                let status_str = item
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("modified");
                let additions = item
                    .get("lines_added")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let deletions = item
                    .get("lines_removed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                let change = match status_str {
                    "added" => GitChange::Added,
                    "removed" => GitChange::Deleted,
                    "renamed" => GitChange::Renamed,
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
            "/repositories/{}/{}/pullrequests/{number}/diff",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::NotFound,
                message: format!("diff for Bitbucket PR #{number} not found"),
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
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/comments?pagelen=100",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut threads_map: HashMap<u64, (ForgeReviewThread, Vec<ForgeThreadComment>)> =
            HashMap::new();
        let mut replies = Vec::new();
        let mut budget = initial_reply_budget();

        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            for c in values {
                let cid = c.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let parent_id = c
                    .get("parent")
                    .and_then(|p| p.get("id"))
                    .and_then(|v| v.as_u64());

                let author = c
                    .get("user")
                    .and_then(|u| u.get("display_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut body = c
                    .get("content")
                    .and_then(|cnt| cnt.get("raw"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let truncated = cap_comment_body(&mut body, &mut budget);
                let c_at = c
                    .get("created_on")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let thread_comment = ForgeThreadComment {
                    id: cid.to_string(),
                    author,
                    body,
                    truncated,
                    created_at: c_at,
                };

                if let Some(pid) = parent_id {
                    replies.push((pid, thread_comment));
                } else if let Some(inline) = c.get("inline") {
                    let path = inline
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let to_line = inline.get("to").and_then(|v| v.as_u64()).map(|n| n as u32);
                    let from_line = inline
                        .get("from")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u32);

                    let (line, side) = if let Some(to) = to_line {
                        (Some(to), ForgeDiffSide::Right)
                    } else {
                        (from_line, ForgeDiffSide::Left)
                    };

                    let resolved = c.get("resolution").is_some_and(|v| !v.is_null());

                    let thread = ForgeReviewThread {
                        id: cid.to_string(),
                        path,
                        line,
                        start_line: None,
                        side,
                        resolved,
                        outdated: false,
                        can_reply: true,
                        can_resolve: true,
                        comments: vec![thread_comment],
                    };
                    threads_map.insert(cid, (thread, Vec::new()));
                }
            }
        }

        // Attach replies to parents
        for (pid, reply) in replies {
            if let Some((_, reply_list)) = threads_map.get_mut(&pid) {
                reply_list.push(reply);
            }
        }

        let mut threads = Vec::new();
        for (_, (mut thread, reply_list)) in threads_map {
            thread.comments.extend(reply_list);
            threads.push(thread);
        }

        Ok(threads)
    }

    pub async fn submit_review(&self, review: &ForgeReviewSubmission) -> Result<(), ForgeError> {
        let base_url = format!(
            "/repositories/{}/{}/pullrequests/{}",
            self.namespace, self.name, review.number
        );

        // Submit each thread comment
        for t in &review.threads {
            let mut inline = json!({ "path": t.path });
            match t.side {
                ForgeDiffSide::Right => {
                    inline["to"] = json!(t.end.new_line.unwrap_or(1));
                }
                ForgeDiffSide::Left => {
                    inline["from"] = json!(t.end.old_line.unwrap_or(1));
                }
            }

            let comment_payload = json!({
                "content": { "raw": t.body },
                "inline": inline,
            });

            let comments_url = self.api_url(&format!("{base_url}/comments"));
            let rb = self
                .http
                .client()
                .post(&comments_url)
                .headers(self.headers())
                .basic_auth(self.login, Some(self.token))
                .json(&comment_payload);
            let _ = self.http.execute(rb, false).await;
        }

        // Post main body if present
        if !review.body.trim().is_empty() {
            let comments_url = self.api_url(&format!("{base_url}/comments"));
            let rb = self
                .http
                .client()
                .post(&comments_url)
                .headers(self.headers())
                .basic_auth(self.login, Some(self.token))
                .json(&json!({ "content": { "raw": review.body } }));
            let _ = self.http.execute(rb, false).await;
        }

        // Approve / Request Changes
        match review.event {
            ForgeReviewEvent::Approve => {
                let approve_url = self.api_url(&format!("{base_url}/approve"));
                let rb = self
                    .http
                    .client()
                    .post(&approve_url)
                    .headers(self.headers())
                    .basic_auth(self.login, Some(self.token));
                let _ = self.http.execute(rb, false).await;
            }
            ForgeReviewEvent::RequestChanges => {
                let req_url = self.api_url(&format!("{base_url}/request-changes"));
                let rb = self
                    .http
                    .client()
                    .post(&req_url)
                    .headers(self.headers())
                    .basic_auth(self.login, Some(self.token));
                let _ = self.http.execute(rb, false).await;
            }
            ForgeReviewEvent::Comment => {}
        }

        Ok(())
    }

    pub async fn reply(&self, number: u64, thread_id: &str, body: &str) -> Result<(), ForgeError> {
        let parent_id = thread_id.parse::<u64>().unwrap_or(0);
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/comments",
            self.namespace, self.name
        ));
        let payload = json!({
            "content": { "raw": body },
            "parent": { "id": parent_id },
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token))
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
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/comments/{thread_id}/resolve",
            self.namespace, self.name
        ));

        let rb = if resolved {
            self.http
                .client()
                .post(&url)
                .headers(self.headers())
                .basic_auth(self.login, Some(self.token))
        } else {
            self.http
                .client()
                .delete(&url)
                .headers(self.headers())
                .basic_auth(self.login, Some(self.token))
        };

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
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}/comments",
            self.namespace, self.name
        ));
        let payload = json!({
            "content": { "raw": body }
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token))
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
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{}/merge",
            self.namespace, self.name, req.number
        ));
        let strategy = match req.method {
            ForgeMergeMethod::Merge => "merge_commit",
            ForgeMergeMethod::Squash => "squash",
            ForgeMergeMethod::Rebase => "fast_forward",
        };

        let mut payload = json!({
            "merge_strategy": strategy,
            "close_source_branch": req.delete_branch,
        });

        if let Some(ref m) = req.subject {
            payload["message"] = json!(m);
        }

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token))
            .json(&payload);
        let (status, _, _) = self.http.execute(rb, true).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::MergeBlocked,
                message: format!("Bitbucket merge failed: {status}"),
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
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests",
            self.namespace, self.name
        ));

        let mut source_obj = json!({
            "branch": { "name": req.head_branch }
        });

        if head_spec.contains('/') && head_spec != format!("{}/{}", self.namespace, self.name) {
            source_obj["repository"] = json!({ "full_name": head_spec });
        }

        let payload = json!({
            "title": req.title,
            "description": req.body,
            "source": source_obj,
            "destination": { "branch": { "name": req.base } },
            "close_source_branch": false,
        });

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token))
            .json(&payload);
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("create pull request failed: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let number = json.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let pr_url = json
            .get("links")
            .and_then(|l| l.get("html"))
            .and_then(|h| h.get("href"))
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
        match change {
            ForgePrStateChange::Close => {
                let url = self.api_url(&format!(
                    "/repositories/{}/{}/pullrequests/{number}/decline",
                    self.namespace, self.name
                ));
                let rb = self
                    .http
                    .client()
                    .post(&url)
                    .headers(self.headers())
                    .basic_auth(self.login, Some(self.token));
                let (status, _, _) = self.http.execute(rb, false).await?;
                if !status.is_success() {
                    return Err(ForgeError {
                        kind: ForgeErrorKind::Other,
                        message: format!("decline pull request failed: {status}"),
                        git_kind: None,
                        host: Some(self.host.to_string()),
                        port: None,
                    });
                }
                Ok(())
            }
            _ => Err(ForgeError {
                kind: ForgeErrorKind::Unsupported,
                message: "state change not supported for Bitbucket".into(),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            }),
        }
    }

    pub async fn checkout_source(&self, number: u64) -> Result<CheckoutSource, ForgeError> {
        let url = self.api_url(&format!(
            "/repositories/{}/{}/pullrequests/{number}",
            self.namespace, self.name
        ));
        let rb = self
            .http
            .client()
            .get(&url)
            .headers(self.headers())
            .basic_auth(self.login, Some(self.token));
        let (_, _, bytes) = self.http.execute(rb, false).await?;
        let pr: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        let source_branch = pr
            .get("source")
            .and_then(|s| s.get("branch"))
            .and_then(|b| b.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("main")
            .to_string();

        let source_repo = pr
            .get("source")
            .and_then(|s| s.get("repository"))
            .and_then(|r| r.get("full_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let this_repo = format!("{}/{}", self.namespace, self.name);

        let fetch_from = if !source_repo.is_empty() && source_repo != this_repo {
            format!("https://bitbucket.org/{source_repo}.git")
        } else {
            self.remote_name.to_string()
        };

        Ok(CheckoutSource {
            fetch_from,
            refspec: format!("refs/heads/{source_branch}"),
            local_branch: format!("pr/{number}"),
        })
    }
}

fn parse_bb_pr_summary(val: &Value) -> Option<ForgePrSummary> {
    let number = val.get("id")?.as_u64()?;
    let title = val.get("title")?.as_str()?.to_string();
    let author = val
        .get("author")
        .and_then(|a| a.get("display_name"))
        .or_else(|| val.get("author").and_then(|a| a.get("nickname")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let state_str = val.get("state")?.as_str()?;
    let state = match state_str {
        "OPEN" => ForgePrState::Open,
        "MERGED" => ForgePrState::Merged,
        _ => ForgePrState::Closed,
    };

    let head_ref = val
        .get("source")
        .and_then(|s| s.get("branch"))
        .and_then(|b| b.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let base_ref = val
        .get("destination")
        .and_then(|d| d.get("branch"))
        .and_then(|b| b.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let updated_at = val
        .get("updated_on")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let url = val
        .get("links")
        .and_then(|l| l.get("html"))
        .and_then(|h| h.get("href"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(ForgePrSummary {
        number,
        title,
        author,
        state,
        is_draft: false,
        head_ref,
        base_ref,
        updated_at,
        review_decision: None,
        checks: cawide_protocol::types::ForgeChecksRollup::NoChecks,
        url,
    })
}
