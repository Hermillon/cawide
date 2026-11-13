use serde::{Deserialize, Serialize};

use super::rpc::DiffHunk;

pub const MAX_STATUS_ENTRIES: usize = 5_000;
pub const MAX_PATHS_PER_OP: usize = 10_000;
pub const MAX_LOG_WINDOW: u32 = 2_000;
pub const LOG_PAGE_SIZE: u32 = 100;
pub const MAX_COMMIT_FILES: usize = 3_000;
pub const MAX_COMMIT_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitOp {
    Status,
    Diff {
        target: GitDiffTarget,
    },
    Stage {
        paths: Vec<String>,
    },
    Unstage {
        paths: Vec<String>,
    },
    Discard {
        paths: Vec<String>,
        scope: GitDiscardScope,
    },
    RestoreBlobs {
        items: Vec<GitUndoItem>,
    },
    ApplyPatch {
        patch: GitPatchRequest,
    },
    Commit {
        message: String,
        amend: bool,
        stage_tracked: bool,
    },
    Identity,
    SetIdentity {
        name: String,
        email: String,
        scope: GitConfigScope,
    },
    Log {
        query: GitLogQuery,
    },
    CommitDetail {
        oid: String,
    },
    Branches,
    CreateBranch {
        name: String,
        start_point: Option<String>,
        checkout: bool,
    },
    Checkout {
        target: GitCheckoutTarget,
    },
    RenameBranch {
        old_name: String,
        new_name: String,
    },
    DeleteBranch {
        name: String,
        force: bool,
    },
    Merge {
        reference: String,
    },
    Rebase {
        onto: String,
    },
    Sequencer {
        action: GitSequencerAction,
    },
    ResolveConflict {
        path: String,
        resolution: GitConflictResolution,
    },
    CherryPick {
        oid: String,
    },
    Revert {
        oid: String,
    },
    Reset {
        oid: String,
        mode: GitResetMode,
    },
    Tags,
    CreateTag {
        name: String,
        target: String,
        message: Option<String>,
    },
    DeleteTag {
        name: String,
    },
    Stashes,
    StashPush {
        message: Option<String>,
        include_untracked: bool,
    },
    StashApply {
        index: u32,
        oid: String,
        pop: bool,
    },
    StashDrop {
        index: u32,
        oid: String,
    },
    Remotes,
    AddRemote {
        name: String,
        url: String,
    },
    RemoveRemote {
        name: String,
    },
    SetRemoteUrl {
        name: String,
        url: String,
    },
    Fetch {
        remote: Option<String>,
        account: Option<String>,
    },
    Pull {
        mode: GitPullMode,
        account: Option<String>,
    },
    Push {
        remote: String,
        local_branch: String,
        remote_branch: String,
        set_upstream: bool,
        force_with_lease: bool,
        account: Option<String>,
    },
    PushTag {
        remote: String,
        name: String,
        account: Option<String>,
    },
    DeleteRemoteRef {
        remote: String,
        full_ref: String,
        account: Option<String>,
    },
}

impl GitOp {
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            GitOp::Status
                | GitOp::Diff { .. }
                | GitOp::Identity
                | GitOp::Log { .. }
                | GitOp::CommitDetail { .. }
                | GitOp::Branches
                | GitOp::Tags
                | GitOp::Stashes
                | GitOp::Remotes
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitReply {
    Status { status: GitRepoStatus },
    Diff { diff: GitFileDiff },
    Done,
    Discarded { items: Vec<GitUndoItem> },
    Committed { oid: String },
    Identity { identity: GitIdentity },
    Log { page: GitLogPage },
    CommitDetail { detail: GitCommitDetail },
    Branches { branches: Vec<GitBranch> },
    Tags { tags: Vec<GitTag> },
    Stashes { stashes: Vec<GitStashEntry> },
    Remotes { remotes: Vec<GitRemote> },
    Integrated { outcome: GitIntegrationOutcome },
    Pushed { new_remote_branch: bool },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitError {
    pub kind: GitErrorKind,
    pub message: String,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitErrorKind {
    NotARepository,
    InvalidArgument,
    AuthenticationFailed,
    PermissionDenied,
    NonFastForward,
    LocalChangesWouldBeOverwritten,
    NotFullyMerged,
    IndexLocked,
    Network,
    Timeout,
    StaleDiff,
    StaleStash,
    NothingToCommit,
    NoUpstream,
    IdentityMissing,
    UnknownHostKey,
    UnknownHostKeyCustomSsh,
    HostKeyChanged,
    LfsUnavailable,
    Unsupported,
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitRepoStatus {
    pub head: GitHead,
    pub upstream: Option<GitUpstream>,
    pub entries: Vec<GitStatusEntry>,
    pub entries_truncated: bool,
    pub total_entries: u32,
    pub operation: Option<GitOperation>,
    pub stash_count: u32,
    pub lfs: GitLfsState,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitLfsState {
    NotUsed,
    Enabled,
    Unavailable,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitHead {
    Branch { name: String, oid: Option<String> },
    Detached { oid: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitUpstream {
    pub name: String,
    pub ahead: u32,
    pub behind: u32,
    pub gone: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitStatusEntry {
    pub path: String,
    pub orig_path: Option<String>,
    pub index: GitChange,
    pub worktree: GitChange,
    pub conflict: Option<GitConflictKind>,
    pub staged_stats: Option<GitLineStats>,
    pub unstaged_stats: Option<GitLineStats>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitChange {
    Unmodified,
    Modified,
    Added,
    Deleted,
    Renamed,
    Copied,
    TypeChanged,
    Untracked,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitConflictKind {
    BothModified,
    BothAdded,
    BothDeleted,
    AddedByUs,
    AddedByThem,
    DeletedByUs,
    DeletedByThem,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitLineStats {
    pub additions: u32,
    pub deletions: u32,
    pub binary: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitOperation {
    Merge {
        message: Option<String>,
    },
    Rebase {
        step: Option<u32>,
        total: Option<u32>,
        onto: Option<String>,
    },
    CherryPick,
    Revert,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitDiffTarget {
    Unstaged {
        path: String,
    },
    Staged {
        path: String,
    },
    Untracked {
        path: String,
    },
    Commit {
        oid: String,
        path: String,
        old_path: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitFileDiff {
    pub path: String,
    pub old_path: Option<String>,
    pub binary: bool,
    pub too_large: bool,
    pub lfs: bool,
    pub total_bytes: u64,
    pub hunks: Vec<DiffHunk>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitDiscardScope {
    Unstaged,
    All,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitUndoItem {
    pub path: String,
    pub blob_oid: Option<String>,
    pub executable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitPatchRequest {
    pub path: String,
    pub source: GitPatchSource,
    pub hunk_index: u32,
    pub hunk_hash: String,
    pub line_indices: Vec<u32>,
    pub action: GitPatchAction,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitPatchSource {
    Unstaged,
    Staged,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitPatchAction {
    Stage,
    Unstage,
    Discard,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitIdentity {
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitConfigScope {
    Repository,
    Global,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitLogQuery {
    pub scope: GitLogScope,
    pub path: Option<String>,
    pub skip: u32,
    pub limit: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitLogScope {
    AllRefs,
    Head,
    Ref { name: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitLogPage {
    pub commits: Vec<GitCommitRow>,
    pub has_more: bool,
    pub max_lane: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitCommitRow {
    pub oid: String,
    pub short_oid: String,
    pub parents: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub author_time: i64,
    pub subject: String,
    pub refs: Vec<GitRefLabel>,
    pub graph: GitGraphRow,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitRefLabel {
    pub name: String,
    pub kind: GitRefKind,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitRefKind {
    CurrentBranch,
    LocalBranch,
    RemoteBranch,
    Tag,
    DetachedHead,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitGraphRow {
    pub lane: u8,
    pub color: u8,
    pub edges: Vec<GitGraphEdge>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitGraphEdge {
    pub from_lane: u8,
    pub to_lane: u8,
    pub color: u8,
    pub half: GitGraphHalf,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitGraphHalf {
    Top,
    Bottom,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitCommitDetail {
    pub oid: String,
    pub parents: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub author_time: i64,
    pub committer_name: String,
    pub committer_email: String,
    pub commit_time: i64,
    pub subject: String,
    pub body: String,
    pub refs: Vec<GitRefLabel>,
    pub files: Vec<GitCommitFile>,
    pub files_truncated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitCommitFile {
    pub path: String,
    pub old_path: Option<String>,
    pub change: GitChange,
    pub stats: GitLineStats,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitBranch {
    pub name: String,
    pub full_ref: String,
    pub kind: GitBranchKind,
    pub oid: String,
    pub is_head: bool,
    pub upstream: Option<GitUpstream>,
    pub last_commit_time: i64,
    pub subject: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitBranchKind {
    Local,
    Remote { remote: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitCheckoutTarget {
    Branch {
        name: String,
    },
    RemoteBranch {
        remote_branch: String,
        local_name: String,
    },
    Detached {
        oid: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitSequencerAction {
    Continue,
    Abort,
    Skip,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitConflictResolution {
    Ours,
    Theirs,
    MarkResolved,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitResetMode {
    Soft,
    Mixed,
    Hard,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitTag {
    pub name: String,
    pub target_oid: String,
    pub annotated: bool,
    pub time: i64,
    pub subject: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitStashEntry {
    pub index: u32,
    pub oid: String,
    pub time: i64,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitRemoteScheme {
    Https,
    Http,
    Ssh,
    Git,
    File,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitRemote {
    pub name: String,
    pub fetch_url: String,
    pub push_url: String,
    pub scheme: GitRemoteScheme,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub https_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitPullMode {
    FastForwardOnly,
    Rebase,
    Merge,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GitIntegrationOutcome {
    pub result: GitIntegrationResult,
    pub conflicted_paths: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GitIntegrationResult {
    UpToDate,
    FastForward,
    Completed,
    Conflicts,
}
