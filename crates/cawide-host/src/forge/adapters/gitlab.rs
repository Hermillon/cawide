use super::CheckoutSource;
use crate::forge::capabilities::default_capabilities;
use crate::forge::http::ForgeHttp;
use crate::forge::text::{cap_comment_body, cap_description, initial_reply_budget};
use cawide_protocol::types::{
    ForgeCheck, ForgeCheckBucket, ForgeChecksRollup, ForgeComment, ForgeCreateRequest,
    ForgeDiffSide, ForgeError, ForgeErrorKind, ForgeKind, ForgeMergeMethod, ForgeMergeRequest,
    ForgeMergeState, ForgeMergeable, ForgePrCommit, ForgePrDetail, ForgePrFile, ForgePrFilter,
    ForgePrState, ForgePrStateChange, ForgePrSummary, ForgeRepository, ForgeReview,
    ForgeReviewEvent, ForgeReviewState, ForgeReviewSubmission, ForgeReviewThread,
    ForgeThreadComment, GitChange, GitFileDiff, MAX_FORGE_DIFF_BYTES, MAX_PR_FILES,
};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};

pub struct GitLabAdapter<'a> {
    pub http: &'a ForgeHttp,
    pub scheme: &'a str,
    pub host: &'a str,
    pub namespace: &'a str,
    pub name: &'a str,
    pub token: &'a str,
    pub remote_name: &'a str,
}

impl<'a> GitLabAdapter<'a> {
    fn project_id(&self) -> String {
        let full = format!("{}/{}", self.namespace, self.name);
        crate::forge::http::url_encode(&full)
    }

    fn api_url(&self, path: &str) -> String {
        let clean = if path.starts_with('/') {
            path
        } else {
            &format!("/{path}")
        };
        self.http
            .url(self.host, self.scheme, &format!("/api/v4{clean}"))
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static("cawide"));
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            h.insert(AUTHORIZATION, v);
        }
        h.insert(ACCEPT, HeaderValue::from_static("application/json"));
        h
    }

    async fn get_current_user_id(&self) -> Option<u64> {
        let url = self.api_url("/user");
        let rb = self.http.client().get(&url).headers(self.headers());
        if let Ok((status, _, bytes)) = self.http.execute(rb, false).await {
            if status.is_success() {
                if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
                    return json.get("id").and_then(|v| v.as_u64());
                }
            }
        }
        None
    }

    pub async fn repository(&self) -> Result<ForgeRepository, ForgeError> {
        let pid = self.project_id();
        let url = self.api_url(&format!("/projects/{pid}"));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to fetch GitLab project: {status}"),
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
            .get("web_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let proj_access = json
            .get("permissions")
            .and_then(|p| p.get("project_access"))
            .and_then(|a| a.get("access_level"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let group_access = json
            .get("permissions")
            .and_then(|p| p.get("group_access"))
            .and_then(|a| a.get("access_level"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let viewer_can_merge = proj_access >= 30 || group_access >= 30;

        let squash_option = json
            .get("squash_option")
            .and_then(|v| v.as_str())
            .unwrap_or("default_off");
        let mut merge_methods = vec![ForgeMergeMethod::Merge];
        if squash_option != "never" {
            merge_methods.push(ForgeMergeMethod::Squash);
        }

        let delete_branch_on_merge = json
            .get("remove_source_branch_after_merge")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let capabilities = default_capabilities(ForgeKind::GitLab);

        Ok(ForgeRepository {
            kind: ForgeKind::GitLab,
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
        let pid = self.project_id();
        let url = self.api_url(&format!(
            "/projects/{pid}/merge_requests?source_branch={}&state=opened&per_page=1",
            crate::forge::http::url_encode(branch)
        ));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(None);
        }

        let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        if let Some(first) = arr.first() {
            Ok(parse_mr_summary(first))
        } else {
            Ok(None)
        }
    }

    pub async fn list(
        &self,
        filter: ForgePrFilter,
        limit: u32,
    ) -> Result<Vec<ForgePrSummary>, ForgeError> {
        let pid = self.project_id();
        let state_param = match filter {
            ForgePrFilter::Merged => "merged",
            ForgePrFilter::Closed => "closed",
            _ => "opened",
        };

        let mut query_params = format!("state={state_param}&order_by=updated_at&per_page={limit}");

        match filter {
            ForgePrFilter::NeedsMyReview => {
                if let Some(uid) = self.get_current_user_id().await {
                    query_params.push_str(&format!("&reviewer_id={uid}"));
                }
            }
            ForgePrFilter::Mine => {
                if let Some(uid) = self.get_current_user_id().await {
                    query_params.push_str(&format!("&author_id={uid}"));
                }
            }
            _ => {}
        }

        let url = self.api_url(&format!("/projects/{pid}/merge_requests?{query_params}"));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to list merge requests: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut list = Vec::new();
        for item in &arr {
            if let Some(summary) = parse_mr_summary(item) {
                list.push(summary);
            }
        }

        Ok(list)
    }

    pub async fn detail(&self, number: u64) -> Result<ForgePrDetail, ForgeError> {
        let pid = self.project_id();
        let mr_url = self.api_url(&format!("/projects/{pid}/merge_requests/{number}"));
        let rb = self.http.client().get(&mr_url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: if status == StatusCode::NOT_FOUND {
                    ForgeErrorKind::NotFound
                } else {
                    ForgeErrorKind::Other
                },
                message: format!("merge request !{number} not found"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let mr: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let summary = parse_mr_summary(&mr).ok_or_else(|| ForgeError {
            kind: ForgeErrorKind::Other,
            message: "failed to parse merge request summary".into(),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })?;

        let mut budget = initial_reply_budget();
        let mut raw_body = mr
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let body_truncated = cap_description(&mut raw_body, &mut budget);

        let head_oid = mr
            .get("sha")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let head_owner = mr
            .get("author")
            .and_then(|a| a.get("username"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let source_proj_id = mr.get("source_project_id").and_then(|v| v.as_u64());
        let target_proj_id = mr.get("target_project_id").and_then(|v| v.as_u64());
        let is_cross_repository = source_proj_id != target_proj_id;

        let (mergeable, merge_state) = gitlab_mergeability(&mr);

        let auto_merge_enabled = mr
            .get("merge_when_pipeline_succeeds")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let created_at = mr
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Commits
        let commits_url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/commits?per_page=100"
        ));
        let (c_status, _, c_bytes) = self
            .http
            .execute(
                self.http.client().get(&commits_url).headers(self.headers()),
                false,
            )
            .await
            .unwrap_or((
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                bytes::Bytes::new(),
            ));
        let mut commits = Vec::new();
        if c_status.is_success() {
            if let Ok(c_arr) = serde_json::from_slice::<Vec<Value>>(&c_bytes) {
                for c in c_arr {
                    let oid = c
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let headline = c
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let author = c
                        .get("author_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let authored_at = c
                        .get("authored_date")
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

        // Approvals (reviews)
        let mut reviews = Vec::new();
        let app_url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/approvals"
        ));
        if let Ok((a_status, _, a_bytes)) = self
            .http
            .execute(
                self.http.client().get(&app_url).headers(self.headers()),
                false,
            )
            .await
        {
            if a_status.is_success() {
                if let Ok(app_val) = serde_json::from_slice::<Value>(&a_bytes) {
                    if let Some(approved_by) = app_val.get("approved_by").and_then(|v| v.as_array())
                    {
                        for a in approved_by {
                            let user = a.get("user");
                            let author = user
                                .and_then(|u| u.get("username"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            reviews.push(ForgeReview {
                                author,
                                state: ForgeReviewState::Approved,
                                body: String::new(),
                                truncated: false,
                                submitted_at: String::new(),
                            });
                        }
                    }
                }
            }
        }

        // General comments (notes without DiffNote)
        let notes_url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/notes?sort=asc&per_page=100"
        ));
        let mut comments = Vec::new();
        if let Ok((n_status, _, n_bytes)) = self
            .http
            .execute(
                self.http.client().get(&notes_url).headers(self.headers()),
                false,
            )
            .await
        {
            if n_status.is_success() {
                if let Ok(notes_arr) = serde_json::from_slice::<Vec<Value>>(&n_bytes) {
                    for n in notes_arr {
                        let system = n.get("system").and_then(|v| v.as_bool()).unwrap_or(false);
                        let n_type = n.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if !system && n_type != "DiffNote" {
                            let author = n
                                .get("author")
                                .and_then(|a| a.get("username"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let mut body = n
                                .get("body")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let truncated = cap_comment_body(&mut body, &mut budget);
                            let c_at = n
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
        let pid = self.project_id();
        let pipe_url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/pipelines?per_page=1"
        ));
        let (p_status, _, p_bytes) = self
            .http
            .execute(
                self.http.client().get(&pipe_url).headers(self.headers()),
                false,
            )
            .await?;

        if !p_status.is_success() {
            return Ok(Vec::new());
        }

        let pipe_arr: Vec<Value> = serde_json::from_slice(&p_bytes).unwrap_or_default();
        let pipeline_id = match pipe_arr
            .first()
            .and_then(|p| p.get("id"))
            .and_then(|v| v.as_u64())
        {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        let jobs_url = self.api_url(&format!(
            "/projects/{pid}/pipelines/{pipeline_id}/jobs?per_page=100"
        ));
        let (j_status, _, j_bytes) = self
            .http
            .execute(
                self.http.client().get(&jobs_url).headers(self.headers()),
                false,
            )
            .await?;

        if !j_status.is_success() {
            return Ok(Vec::new());
        }

        let jobs_arr: Vec<Value> = serde_json::from_slice(&j_bytes).unwrap_or_default();
        let mut checks = Vec::new();

        for j in jobs_arr {
            let name = j
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let group = j
                .get("stage")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let link = j
                .get("web_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let started_at = j
                .get("started_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let completed_at = j
                .get("finished_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let status_str = j.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let bucket = gitlab_job_bucket(status_str);

            checks.push(ForgeCheck {
                name,
                group,
                bucket,
                link,
                started_at,
                completed_at,
                description: String::new(),
            });
        }

        Ok(checks)
    }

    pub async fn files(
        &self,
        number: u64,
        _head_oid: &str,
    ) -> Result<Vec<ForgePrFile>, ForgeError> {
        let pid = self.project_id();
        let mut all_files = Vec::new();
        let mut page = 1;

        loop {
            let url = self.api_url(&format!(
                "/projects/{pid}/merge_requests/{number}/diffs?per_page=100&page={page}"
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
                    .get("new_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let old_path = item
                    .get("old_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let previous_path = if old_path != path {
                    Some(old_path)
                } else {
                    None
                };

                let new_file = item
                    .get("new_file")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let deleted_file = item
                    .get("deleted_file")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let renamed_file = item
                    .get("renamed_file")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let change = if new_file {
                    GitChange::Added
                } else if deleted_file {
                    GitChange::Deleted
                } else if renamed_file {
                    GitChange::Renamed
                } else {
                    GitChange::Modified
                };

                let diff_text = item.get("diff").and_then(|v| v.as_str()).unwrap_or("");
                let mut additions = 0u32;
                let mut deletions = 0u32;
                for l in diff_text.lines() {
                    if l.starts_with('+') && !l.starts_with("+++") {
                        additions += 1;
                    } else if l.starts_with('-') && !l.starts_with("---") {
                        deletions += 1;
                    }
                }

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
        let pid = self.project_id();
        let mut page = 1;

        loop {
            let url = self.api_url(&format!(
                "/projects/{pid}/merge_requests/{number}/diffs?per_page=100&page={page}"
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
                let new_path = item.get("new_path").and_then(|v| v.as_str()).unwrap_or("");
                if new_path == path {
                    let old_path = item.get("old_path").and_then(|v| v.as_str()).unwrap_or("");
                    let previous_path = if old_path != new_path {
                        Some(old_path.to_string())
                    } else {
                        None
                    };

                    let diff_text = item.get("diff").and_then(|v| v.as_str()).unwrap_or("");
                    let total_bytes = diff_text.len() as u64;
                    let too_large = diff_text.len() > MAX_FORGE_DIFF_BYTES;

                    let hunks = if too_large {
                        Vec::new()
                    } else {
                        // GitLab returns diff without full git header, prepend diff --git header for parser
                        let full_diff = format!("diff --git a/{path} b/{path}\n--- a/{old_path}\n+++ b/{path}\n{diff_text}");
                        crate::rpc::git::diff::parse_unified_diff(&full_diff)
                    };

                    return Ok(GitFileDiff {
                        path: path.to_string(),
                        old_path: previous_path,
                        binary: false,
                        too_large,
                        lfs: false,
                        total_bytes,
                        hunks,
                    });
                }
            }

            if len < 100 {
                break;
            }
            page += 1;
        }

        Err(ForgeError {
            kind: ForgeErrorKind::NotFound,
            message: format!("file {path} not found in merge request !{number}"),
            git_kind: None,
            host: Some(self.host.to_string()),
            port: None,
        })
    }

    pub async fn threads(&self, number: u64) -> Result<Vec<ForgeReviewThread>, ForgeError> {
        let pid = self.project_id();
        let url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/discussions?per_page=100"
        ));
        let rb = self.http.client().get(&url).headers(self.headers());
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Ok(Vec::new());
        }

        let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut threads = Vec::new();
        let mut budget = initial_reply_budget();

        for disc in arr {
            let id = disc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let notes = disc.get("notes").and_then(|n| n.as_array());
            if let Some(notes) = notes {
                if let Some(first_note) = notes.first() {
                    let pos = first_note.get("position");
                    if let Some(pos) = pos {
                        if pos.get("position_type").and_then(|v| v.as_str()) == Some("text") {
                            let path = pos
                                .get("new_path")
                                .or_else(|| pos.get("old_path"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let new_line = pos
                                .get("new_line")
                                .and_then(|v| v.as_u64())
                                .map(|n| n as u32);
                            let old_line = pos
                                .get("old_line")
                                .and_then(|v| v.as_u64())
                                .map(|n| n as u32);

                            let (line, side) = if let Some(nl) = new_line {
                                (Some(nl), ForgeDiffSide::Right)
                            } else {
                                (old_line, ForgeDiffSide::Left)
                            };

                            let start_line = pos
                                .get("line_range")
                                .and_then(|lr| lr.get("start"))
                                .and_then(|s| s.get("new_line").or_else(|| s.get("old_line")))
                                .and_then(|v| v.as_u64())
                                .map(|n| n as u32);

                            let resolved = first_note
                                .get("resolved")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let can_resolve = first_note
                                .get("resolvable")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            let mut comments = Vec::new();
                            for note in notes {
                                let cid = note.get("id").map(|v| v.to_string()).unwrap_or_default();
                                let author = note
                                    .get("author")
                                    .and_then(|a| a.get("username"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let mut body = note
                                    .get("body")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let truncated = cap_comment_body(&mut body, &mut budget);
                                let created_at = note
                                    .get("created_at")
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

                            threads.push(ForgeReviewThread {
                                id,
                                path,
                                line,
                                start_line,
                                side,
                                resolved,
                                outdated: false,
                                can_reply: true,
                                can_resolve,
                                comments,
                            });
                        }
                    }
                }
            }
        }

        Ok(threads)
    }

    pub async fn submit_review(&self, review: &ForgeReviewSubmission) -> Result<(), ForgeError> {
        let pid = self.project_id();

        // Fetch MR diff_refs
        let mr_url = self.api_url(&format!("/projects/{pid}/merge_requests/{}", review.number));
        let (_, _, mr_bytes) = self
            .http
            .execute(
                self.http.client().get(&mr_url).headers(self.headers()),
                false,
            )
            .await?;
        let mr_json: Value = serde_json::from_slice(&mr_bytes).unwrap_or(Value::Null);
        let diff_refs = mr_json.get("diff_refs");

        let base_sha = diff_refs
            .and_then(|d| d.get("base_sha"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let start_sha = diff_refs
            .and_then(|d| d.get("start_sha"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let head_sha = diff_refs
            .and_then(|d| d.get("head_sha"))
            .and_then(|v| v.as_str())
            .unwrap_or(&review.head_oid);

        for t in &review.threads {
            let mut pos = json!({
                "position_type": "text",
                "base_sha": base_sha,
                "start_sha": start_sha,
                "head_sha": head_sha,
                "old_path": t.old_path.as_deref().unwrap_or(&t.path),
                "new_path": t.path,
            });

            if let Some(ol) = t.end.old_line {
                pos["old_line"] = json!(ol);
            }
            if let Some(nl) = t.end.new_line {
                pos["new_line"] = json!(nl);
            }

            if let Some(ref st) = t.start {
                let start_ol = st.old_line.unwrap_or(0);
                let start_nl = st.new_line.unwrap_or(0);
                let end_ol = t.end.old_line.unwrap_or(0);
                let end_nl = t.end.new_line.unwrap_or(0);

                let start_code = generate_line_code(&t.path, start_ol, start_nl);
                let end_code = generate_line_code(&t.path, end_ol, end_nl);

                let start_type = if st.new_line.is_some() { "new" } else { "old" };
                let end_type = if t.end.new_line.is_some() {
                    "new"
                } else {
                    "old"
                };

                pos["line_range"] = json!({
                    "start": { "line_code": start_code, "type": start_type },
                    "end": { "line_code": end_code, "type": end_type },
                });
            }

            let draft_url = self.api_url(&format!(
                "/projects/{pid}/merge_requests/{}/draft_notes",
                review.number
            ));
            let rb = self
                .http
                .client()
                .post(&draft_url)
                .headers(self.headers())
                .json(&json!({
                    "note": t.body,
                    "position": pos,
                }));
            let _ = self.http.execute(rb, false).await;
        }

        // Bulk publish draft notes
        let pub_url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{}/draft_notes/bulk_publish",
            review.number
        ));
        let _ = self
            .http
            .execute(
                self.http.client().post(&pub_url).headers(self.headers()),
                false,
            )
            .await;

        // Post body if non-empty
        if !review.body.trim().is_empty() {
            let note_url = self.api_url(&format!(
                "/projects/{pid}/merge_requests/{}/notes",
                review.number
            ));
            let rb = self
                .http
                .client()
                .post(&note_url)
                .headers(self.headers())
                .json(&json!({ "body": review.body }));
            let _ = self.http.execute(rb, false).await;
        }

        // Approve if requested
        if review.event == ForgeReviewEvent::Approve {
            let app_url = self.api_url(&format!(
                "/projects/{pid}/merge_requests/{}/approve",
                review.number
            ));
            let rb = self
                .http
                .client()
                .post(&app_url)
                .headers(self.headers())
                .json(&json!({ "sha": review.head_oid }));
            let _ = self.http.execute(rb, false).await;
        }

        Ok(())
    }

    pub async fn reply(&self, number: u64, thread_id: &str, body: &str) -> Result<(), ForgeError> {
        let pid = self.project_id();
        let url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/discussions/{thread_id}/notes"
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
                message: format!("failed to reply to discussion: {status}"),
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
        let pid = self.project_id();
        let url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{number}/discussions/{thread_id}?resolved={resolved}"
        ));
        let rb = self.http.client().put(&url).headers(self.headers());
        let (status, _, _) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: ForgeErrorKind::Other,
                message: format!("failed to resolve discussion: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn comment(&self, number: u64, body: &str) -> Result<(), ForgeError> {
        let pid = self.project_id();
        let url = self.api_url(&format!("/projects/{pid}/merge_requests/{number}/notes"));
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
                message: format!("failed to post note: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }
        Ok(())
    }

    pub async fn merge(&self, req: &ForgeMergeRequest) -> Result<(), ForgeError> {
        let pid = self.project_id();
        let url = self.api_url(&format!(
            "/projects/{pid}/merge_requests/{}/merge",
            req.number
        ));

        let mut payload = json!({
            "sha": req.head_oid,
            "squash": req.method == ForgeMergeMethod::Squash,
            "should_remove_source_branch": req.delete_branch,
            "merge_when_pipeline_succeeds": req.auto,
        });

        if let Some(ref s) = req.subject {
            if req.method == ForgeMergeMethod::Squash {
                payload["squash_commit_message"] = json!(s);
            } else {
                payload["merge_commit_message"] = json!(s);
            }
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
                message: format!("GitLab merge failed: {status}"),
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
        let pid = self.project_id();
        let url = self.api_url(&format!("/projects/{pid}/merge_requests"));

        let title = if req.draft && !req.title.starts_with("Draft: ") {
            format!("Draft: {}", req.title)
        } else {
            req.title.clone()
        };

        let mut payload = json!({
            "source_branch": req.head_branch,
            "target_branch": req.base,
            "title": title,
            "description": req.body,
        });

        if !req.reviewers.is_empty() {
            let mut reviewer_ids = Vec::new();
            for login in &req.reviewers {
                let user_url = self.api_url(&format!(
                    "/users?username={}",
                    crate::forge::http::url_encode(login)
                ));
                if let Ok((status, _, bytes)) = self
                    .http
                    .execute(
                        self.http.client().get(&user_url).headers(self.headers()),
                        false,
                    )
                    .await
                {
                    if status.is_success() {
                        if let Ok(u_arr) = serde_json::from_slice::<Vec<Value>>(&bytes) {
                            if let Some(uid) = u_arr
                                .first()
                                .and_then(|u| u.get("id"))
                                .and_then(|v| v.as_u64())
                            {
                                reviewer_ids.push(uid);
                            }
                        }
                    }
                }
            }
            if !reviewer_ids.is_empty() {
                payload["reviewer_ids"] = json!(reviewer_ids);
            }
        }

        let rb = self
            .http
            .client()
            .post(&url)
            .headers(self.headers())
            .json(&payload);
        let (status, _, bytes) = self.http.execute(rb, false).await?;

        if !status.is_success() {
            return Err(ForgeError {
                kind: if status == StatusCode::CONFLICT {
                    ForgeErrorKind::AlreadyExists
                } else {
                    ForgeErrorKind::Other
                },
                message: format!("failed to create merge request: {status}"),
                git_kind: None,
                host: Some(self.host.to_string()),
                port: None,
            });
        }

        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let iid = json.get("iid").and_then(|v| v.as_u64()).unwrap_or(0);
        let web_url = json
            .get("web_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok((iid, web_url))
    }

    pub async fn set_state(
        &self,
        number: u64,
        change: ForgePrStateChange,
    ) -> Result<(), ForgeError> {
        let pid = self.project_id();
        let url = self.api_url(&format!("/projects/{pid}/merge_requests/{number}"));

        match change {
            ForgePrStateChange::Close => {
                let rb = self
                    .http
                    .client()
                    .put(&url)
                    .headers(self.headers())
                    .json(&json!({ "state_event": "close" }));
                let _ = self.http.execute(rb, false).await?;
            }
            ForgePrStateChange::Reopen => {
                let rb = self
                    .http
                    .client()
                    .put(&url)
                    .headers(self.headers())
                    .json(&json!({ "state_event": "reopen" }));
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
                    .strip_prefix("Draft: ")
                    .or_else(|| title.strip_prefix("WIP: "))
                    .unwrap_or(title);
                let rb = self
                    .http
                    .client()
                    .put(&url)
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
                let draft_title = format!("Draft: {title}");
                let rb = self
                    .http
                    .client()
                    .put(&url)
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
            refspec: format!("merge-requests/{number}/head"),
            local_branch: format!("mr/{number}"),
        })
    }
}

pub fn generate_line_code(path: &str, old_line: u32, new_line: u32) -> String {
    let mut hasher = Sha1::new();
    hasher.update(path.as_bytes());
    let path_hash = hex::encode(hasher.finalize());
    format!("{path_hash}_{old_line}_{new_line}")
}

fn parse_mr_summary(val: &Value) -> Option<ForgePrSummary> {
    let number = val.get("iid")?.as_u64()?;
    let title = val.get("title")?.as_str()?.to_string();
    let author = val
        .get("author")
        .and_then(|a| a.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let state_str = val.get("state")?.as_str()?;
    let state = match state_str {
        "opened" => ForgePrState::Open,
        "merged" => ForgePrState::Merged,
        _ => ForgePrState::Closed,
    };

    let is_draft = val.get("draft").and_then(|v| v.as_bool()).unwrap_or(false)
        || title.starts_with("Draft:")
        || title.starts_with("[Draft]")
        || title.starts_with("WIP:");

    let head_ref = val
        .get("source_branch")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let base_ref = val
        .get("target_branch")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let updated_at = val
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let url = val
        .get("web_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let pipe_status = val
        .get("head_pipeline")
        .and_then(|p| p.get("status"))
        .and_then(|v| v.as_str());

    let checks = match pipe_status {
        Some("success") => ForgeChecksRollup::Passing,
        Some("failed") => ForgeChecksRollup::Failing,
        Some("running")
        | Some("pending")
        | Some("created")
        | Some("preparing")
        | Some("waiting_for_resource")
        | Some("scheduled") => ForgeChecksRollup::Pending,
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
        review_decision: None,
        checks,
        url,
    })
}
fn is_transient_status(status: &str) -> bool {
    matches!(
        status,
        "unchecked" | "checking" | "preparing" | "approvals_syncing" | "cannot_be_merged_recheck"
    )
}

fn gitlab_mergeability(mr: &Value) -> (ForgeMergeable, ForgeMergeState) {
    let detailed_status = mr
        .get("detailed_merge_status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let merge_status = mr
        .get("merge_status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let has_conflicts = mr
        .get("has_conflicts")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let transient = is_transient_status(detailed_status);

    let mergeable = if transient
        || matches!(
            merge_status,
            "unchecked" | "checking" | "cannot_be_merged_recheck"
        ) {
        ForgeMergeable::Unknown
    } else if has_conflicts {
        ForgeMergeable::Conflicting
    } else {
        ForgeMergeable::Mergeable
    };

    let merge_state = if detailed_status.is_empty() || transient {
        ForgeMergeState::Unknown
    } else {
        match detailed_status {
            "mergeable" => ForgeMergeState::Clean,
            "ci_still_running" => ForgeMergeState::ChecksPending,
            "ci_must_pass" => ForgeMergeState::ChecksFailing,
            "need_rebase" => ForgeMergeState::Behind,
            "draft_status" => ForgeMergeState::Draft,
            "conflict" => ForgeMergeState::Conflicts,
            "not_approved" | "blocked_status" | "discussions_not_resolved" => {
                ForgeMergeState::Blocked
            }
            _ => ForgeMergeState::Blocked,
        }
    };

    (mergeable, merge_state)
}

fn gitlab_job_bucket(status: &str) -> ForgeCheckBucket {
    match status {
        "success" => ForgeCheckBucket::Pass,
        "failed" => ForgeCheckBucket::Fail,
        "canceled" => ForgeCheckBucket::Cancel,
        "skipped" | "manual" => ForgeCheckBucket::Skipping,
        _ => ForgeCheckBucket::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitlab_line_code() {
        let code = generate_line_code("src/main.rs", 10, 12);
        assert!(code.ends_with("_10_12"));
        assert_eq!(code.len(), 40 + 1 + 2 + 1 + 2);
    }

    #[test]
    fn test_gitlab_mergeability() {
        // Transient detailed status
        for transient in &[
            "unchecked",
            "checking",
            "preparing",
            "approvals_syncing",
            "cannot_be_merged_recheck",
        ] {
            let mr = json!({
                "detailed_merge_status": transient,
                "merge_status": "can_be_merged",
                "has_conflicts": false
            });
            let (m, s) = gitlab_mergeability(&mr);
            assert_eq!(
                m,
                ForgeMergeable::Unknown,
                "transient {transient} should be Unknown mergeable"
            );
            assert_eq!(
                s,
                ForgeMergeState::Unknown,
                "transient {transient} should be Unknown merge_state"
            );
        }

        // Transient merge_status
        for transient_ms in &["unchecked", "checking", "cannot_be_merged_recheck"] {
            let mr = json!({
                "detailed_merge_status": "mergeable",
                "merge_status": transient_ms,
                "has_conflicts": false
            });
            let (m, s) = gitlab_mergeability(&mr);
            assert_eq!(m, ForgeMergeable::Unknown);
            assert_eq!(s, ForgeMergeState::Clean);
        }

        // Conflicting
        let mr_conflict = json!({
            "detailed_merge_status": "conflict",
            "merge_status": "cannot_be_merged",
            "has_conflicts": true
        });
        let (m, s) = gitlab_mergeability(&mr_conflict);
        assert_eq!(m, ForgeMergeable::Conflicting);
        assert_eq!(s, ForgeMergeState::Conflicts);

        // Clean and mergeable
        let mr_clean = json!({
            "detailed_merge_status": "mergeable",
            "merge_status": "can_be_merged",
            "has_conflicts": false
        });
        let (m, s) = gitlab_mergeability(&mr_clean);
        assert_eq!(m, ForgeMergeable::Mergeable);
        assert_eq!(s, ForgeMergeState::Clean);

        // Empty detailed status -> merge_state Unknown
        let mr_empty = json!({
            "detailed_merge_status": "",
            "merge_status": "can_be_merged",
            "has_conflicts": false
        });
        let (m, s) = gitlab_mergeability(&mr_empty);
        assert_eq!(m, ForgeMergeable::Mergeable);
        assert_eq!(s, ForgeMergeState::Unknown);

        // Unrecognized detailed status -> Blocked
        let mr_unrecognized = json!({
            "detailed_merge_status": "custom_enterprise_guard",
            "merge_status": "can_be_merged",
            "has_conflicts": false
        });
        let (m, s) = gitlab_mergeability(&mr_unrecognized);
        assert_eq!(m, ForgeMergeable::Mergeable);
        assert_eq!(s, ForgeMergeState::Blocked);
    }

    #[test]
    fn test_gitlab_job_bucket() {
        assert_eq!(gitlab_job_bucket("manual"), ForgeCheckBucket::Skipping);
        assert_eq!(gitlab_job_bucket("skipped"), ForgeCheckBucket::Skipping);
        assert_eq!(gitlab_job_bucket("success"), ForgeCheckBucket::Pass);
        assert_eq!(gitlab_job_bucket("failed"), ForgeCheckBucket::Fail);
        assert_eq!(gitlab_job_bucket("canceled"), ForgeCheckBucket::Cancel);
        assert_eq!(gitlab_job_bucket("running"), ForgeCheckBucket::Pending);
        assert_eq!(gitlab_job_bucket("created"), ForgeCheckBucket::Pending);
    }

    #[test]
    fn test_gitlab_summary_rollup() {
        for pending_status in &[
            "running",
            "pending",
            "created",
            "preparing",
            "waiting_for_resource",
            "scheduled",
        ] {
            let val = json!({
                "iid": 1,
                "title": "MR",
                "author": { "username": "bob" },
                "state": "opened",
                "source_branch": "feat",
                "target_branch": "main",
                "updated_at": "2026-03-30T10:00:00Z",
                "web_url": "https://gitlab.example/mr/1",
                "head_pipeline": { "status": pending_status }
            });
            let summary = parse_mr_summary(&val).unwrap();
            assert_eq!(
                summary.checks,
                ForgeChecksRollup::Pending,
                "pipeline status {pending_status} should map to Pending"
            );
        }

        let val_success = json!({
            "iid": 1,
            "title": "MR",
            "author": { "username": "bob" },
            "state": "opened",
            "source_branch": "feat",
            "target_branch": "main",
            "updated_at": "2026-03-30T10:00:00Z",
            "web_url": "https://gitlab.example/mr/1",
            "head_pipeline": { "status": "success" }
        });
        assert_eq!(
            parse_mr_summary(&val_success).unwrap().checks,
            ForgeChecksRollup::Passing
        );
    }
}
