use serde::{Deserialize, Serialize};

use super::git::{GitChange, GitErrorKind, GitFileDiff};

pub const MAX_PR_FILES: usize = 3_000;
pub const MAX_FORGE_DIFF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FORGE_BODY_BYTES: usize = 16 * 1024;
pub const MAX_FORGE_DESCRIPTION_BYTES: usize = 64 * 1024;
pub const MAX_FORGE_REPLY_TEXT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeKind {
    GitHub,
    GitLab,
    Gitea,
    Bitbucket,
    AzureDevOps,
    Generic,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeScheme {
    Https,
    Http,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeMergeMethod {
    Merge,
    Squash,
    Rebase,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeCapabilities {
    pub pull_requests: bool,
    pub inline_comments: bool,
    pub multiline_comments: bool,
    pub suggestions: bool,
    pub request_changes: bool,
    pub resolve_threads: bool,
    pub reply_to_threads: bool,
    pub auto_merge: bool,
    pub drafts: bool,
    pub checks: bool,
    pub reviewers_by_login: bool,
    pub reopen: bool,
    pub ssh_key_upload: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeAccountSource {
    Cawide,
    GhCli,
    GlabCli,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeAccount {
    pub id: String,
    pub kind: ForgeKind,
    pub scheme: ForgeScheme,
    pub host: String,
    pub login: String,
    pub source: ForgeAccountSource,
    pub is_default: bool,
    pub healthy: bool,
    pub terminal_helper: bool,
    pub existing_terminal_helper: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeAccountsState {
    pub accounts: Vec<ForgeAccount>,
    pub device_sign_in_hosts: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeSignInChallenge {
    pub session_id: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in_secs: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeSignInState {
    Pending,
    Succeeded { account: ForgeAccount },
    Failed { message: String },
    Expired,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeSshKey {
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeHostKey {
    pub key_type: String,
    pub fingerprint: String,
    pub line: String,
    pub officially_known: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ForgeAccountOp {
    List,
    DetectHost {
        host: String,
        scheme: ForgeScheme,
    },
    SignInStart {
        kind: ForgeKind,
        host: String,
    },
    SignInPoll {
        session_id: String,
    },
    SignInCancel {
        session_id: String,
    },
    AddToken {
        kind: ForgeKind,
        scheme: ForgeScheme,
        host: String,
        login: Option<String>,
        token: String,
        azure_org: Option<String>,
        verify_url: Option<String>,
    },
    Remove {
        account_id: String,
    },
    SetDefault {
        account_id: String,
    },
    SetTerminalHelper {
        host: String,
        enabled: bool,
    },
    SshPublicKey,
    UploadSshKey {
        account_id: String,
        title: String,
    },
    ScanHostKey {
        host: String,
        port: u16,
    },
    TrustHostKey {
        host: String,
        port: u16,
        lines: Vec<String>,
    },
}
impl std::fmt::Debug for ForgeAccountOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::List => write!(f, "List"),
            Self::DetectHost { host, scheme } => f
                .debug_struct("DetectHost")
                .field("host", host)
                .field("scheme", scheme)
                .finish(),
            Self::SignInStart { kind, host } => f
                .debug_struct("SignInStart")
                .field("kind", kind)
                .field("host", host)
                .finish(),
            Self::SignInPoll { session_id } => f
                .debug_struct("SignInPoll")
                .field("session_id", session_id)
                .finish(),
            Self::SignInCancel { session_id } => f
                .debug_struct("SignInCancel")
                .field("session_id", session_id)
                .finish(),
            Self::AddToken {
                kind,
                scheme,
                host,
                login,
                token: _,
                azure_org,
                verify_url,
            } => f
                .debug_struct("AddToken")
                .field("kind", kind)
                .field("scheme", scheme)
                .field("host", host)
                .field("login", login)
                .field("token", &"[REDACTED]")
                .field("azure_org", azure_org)
                .field("verify_url", verify_url)
                .finish(),
            Self::Remove { account_id } => f
                .debug_struct("Remove")
                .field("account_id", account_id)
                .finish(),
            Self::SetDefault { account_id } => f
                .debug_struct("SetDefault")
                .field("account_id", account_id)
                .finish(),
            Self::SetTerminalHelper { host, enabled } => f
                .debug_struct("SetTerminalHelper")
                .field("host", host)
                .field("enabled", enabled)
                .finish(),
            Self::SshPublicKey => write!(f, "SshPublicKey"),
            Self::UploadSshKey { account_id, title } => f
                .debug_struct("UploadSshKey")
                .field("account_id", account_id)
                .field("title", title)
                .finish(),
            Self::ScanHostKey { host, port } => f
                .debug_struct("ScanHostKey")
                .field("host", host)
                .field("port", port)
                .finish(),
            Self::TrustHostKey { host, port, lines } => f
                .debug_struct("TrustHostKey")
                .field("host", host)
                .field("port", port)
                .field("lines", lines)
                .finish(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeAccountReply {
    Accounts { state: ForgeAccountsState },
    HostKind { kind: ForgeKind },
    Challenge { challenge: ForgeSignInChallenge },
    SignInState { state: ForgeSignInState },
    Account { account: ForgeAccount },
    SshKey { key: ForgeSshKey },
    HostKeys { keys: Vec<ForgeHostKey> },
    Done,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeRepoOp {
    Repository,
    CurrentPullRequest {
        branch: String,
    },
    ListPullRequests {
        filter: ForgePrFilter,
        limit: u32,
    },
    PullRequest {
        number: u64,
    },
    Checks {
        number: u64,
    },
    Files {
        number: u64,
        head_oid: String,
    },
    FileDiff {
        number: u64,
        path: String,
        head_oid: String,
    },
    ReviewThreads {
        number: u64,
    },
    SubmitReview {
        review: ForgeReviewSubmission,
    },
    ReplyToThread {
        number: u64,
        thread_id: String,
        body: String,
    },
    ResolveThread {
        number: u64,
        thread_id: String,
        resolved: bool,
    },
    Comment {
        number: u64,
        body: String,
    },
    Merge {
        request: ForgeMergeRequest,
    },
    CreateDefaults {
        head_branch: String,
        base: Option<String>,
    },
    Create {
        request: ForgeCreateRequest,
    },
    Checkout {
        number: u64,
        reset_existing: bool,
    },
    SetState {
        number: u64,
        change: ForgePrStateChange,
    },
    PullRequestWithChecks {
        number: u64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeRepoReply {
    Repository {
        repository: ForgeRepository,
    },
    CurrentPullRequest {
        pull_request: Option<ForgePrSummary>,
    },
    PullRequests {
        pull_requests: Vec<ForgePrSummary>,
    },
    PullRequest {
        detail: ForgePrDetail,
    },
    Checks {
        checks: Vec<ForgeCheck>,
    },
    Files {
        files: Vec<ForgePrFile>,
    },
    FileDiff {
        diff: GitFileDiff,
    },
    ReviewThreads {
        threads: Vec<ForgeReviewThread>,
    },
    CreateDefaults {
        defaults: ForgeCreateDefaults,
    },
    Created {
        number: u64,
        url: String,
    },
    CheckedOut {
        local_branch: String,
    },
    Done,
    PullRequestWithChecks {
        detail: ForgePrDetail,
        checks: Vec<ForgeCheck>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeError {
    pub kind: ForgeErrorKind,
    pub message: String,
    pub git_kind: Option<GitErrorKind>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeErrorKind {
    NoForgeRemote,
    NotAuthenticated,
    NotFound,
    PermissionDenied,
    RateLimited,
    AlreadyExists,
    MergeBlocked,
    Network,
    Timeout,
    InvalidArgument,
    Unsupported,
    SignInUnavailable,
    HostKeyChanged,
    GitFailed,
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeRepository {
    pub kind: ForgeKind,
    pub host: String,
    pub namespace: String,
    pub name: String,
    pub web_url: String,
    pub default_branch: String,
    pub remote_name: String,
    pub viewer_can_merge: bool,
    pub merge_methods: Vec<ForgeMergeMethod>,
    pub delete_branch_on_merge: bool,
    pub capabilities: ForgeCapabilities,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgePrFilter {
    NeedsMyReview,
    Mine,
    Open,
    Merged,
    Closed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgePrState {
    Open,
    Closed,
    Merged,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeReviewDecision {
    Approved,
    ChangesRequested,
    ReviewRequired,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeChecksRollup {
    Passing,
    Failing,
    Pending,
    NoChecks,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgePrSummary {
    pub number: u64,
    pub title: String,
    pub author: String,
    pub state: ForgePrState,
    pub is_draft: bool,
    pub head_ref: String,
    pub base_ref: String,
    pub updated_at: String,
    pub review_decision: Option<ForgeReviewDecision>,
    pub checks: ForgeChecksRollup,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeMergeable {
    Mergeable,
    Conflicting,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgePrDetail {
    pub summary: ForgePrSummary,
    pub body: String,
    pub body_truncated: bool,
    pub head_oid: String,
    pub head_owner: String,
    pub is_cross_repository: bool,
    pub additions: Option<u32>,
    pub deletions: Option<u32>,
    pub changed_files: Option<u32>,
    pub mergeable: ForgeMergeable,
    pub merge_state: ForgeMergeState,
    pub auto_merge_enabled: bool,
    pub created_at: String,
    pub commits: Vec<ForgePrCommit>,
    pub reviews: Vec<ForgeReview>,
    pub comments: Vec<ForgeComment>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeMergeState {
    Clean,
    Blocked,
    Behind,
    Conflicts,
    ChecksFailing,
    ChecksPending,
    Draft,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgePrCommit {
    pub oid: String,
    pub headline: String,
    pub author: String,
    pub authored_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeReview {
    pub author: String,
    pub state: ForgeReviewState,
    pub body: String,
    pub truncated: bool,
    pub submitted_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeReviewState {
    Approved,
    ChangesRequested,
    Commented,
    Dismissed,
    Pending,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeComment {
    pub author: String,
    pub body: String,
    pub truncated: bool,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeCheckBucket {
    Pass,
    Fail,
    Pending,
    Skipping,
    Cancel,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeCheck {
    pub name: String,
    pub group: String,
    pub bucket: ForgeCheckBucket,
    pub link: String,
    pub started_at: String,
    pub completed_at: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgePrFile {
    pub path: String,
    pub previous_path: Option<String>,
    pub change: GitChange,
    pub additions: u32,
    pub deletions: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeDiffSide {
    Left,
    Right,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeReviewThread {
    pub id: String,
    pub path: String,
    pub line: Option<u32>,
    pub start_line: Option<u32>,
    pub side: ForgeDiffSide,
    pub resolved: bool,
    pub outdated: bool,
    pub can_reply: bool,
    pub can_resolve: bool,
    pub comments: Vec<ForgeThreadComment>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeThreadComment {
    pub id: String,
    pub author: String,
    pub body: String,
    pub truncated: bool,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgeReviewEvent {
    Comment,
    Approve,
    RequestChanges,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeLineRef {
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeDraftThread {
    pub path: String,
    pub old_path: Option<String>,
    pub side: ForgeDiffSide,
    pub end: ForgeLineRef,
    pub start: Option<ForgeLineRef>,
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeReviewSubmission {
    pub number: u64,
    pub head_oid: String,
    pub event: ForgeReviewEvent,
    pub body: String,
    pub threads: Vec<ForgeDraftThread>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeMergeRequest {
    pub number: u64,
    pub method: ForgeMergeMethod,
    pub delete_branch: bool,
    pub auto: bool,
    pub head_oid: String,
    pub subject: Option<String>,
    pub body: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgePrTemplate {
    pub name: String,
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeCreateDefaults {
    pub base: String,
    pub head_branch: String,
    pub title: String,
    pub body: String,
    pub commits_ahead: u32,
    pub head_pushed: bool,
    pub templates: Vec<ForgePrTemplate>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForgeCreateRequest {
    pub title: String,
    pub body: String,
    pub base: String,
    pub head_branch: String,
    pub draft: bool,
    pub reviewers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ForgePrStateChange {
    Close,
    Reopen,
    Ready,
    ConvertToDraft,
}
