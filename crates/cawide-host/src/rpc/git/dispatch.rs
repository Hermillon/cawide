//! Git RPC operation dispatch.

use cawide_protocol::types::{GitError, GitErrorKind, GitOp, GitReply};

use super::GitEngine;
use crate::forge::credentials::ForgeCredentialSource;

pub async fn handle(
    engine: &GitEngine,
    creds: &dyn ForgeCredentialSource,
    _host_env: &crate::rpc::git::env::GitHostEnv,
    op: GitOp,
) -> Result<GitReply, GitError> {
    match op {
        GitOp::Status => {
            let status = engine.status().await.map_err(|e| GitError {
                kind: GitErrorKind::Other,
                message: e,
                host: None,
                port: None,
            })?;
            Ok(GitReply::Status { status })
        }
        GitOp::Diff { target } => {
            let diff = engine.diff_target(&target).await.map_err(|e| GitError {
                kind: GitErrorKind::Other,
                message: e,
                host: None,
                port: None,
            })?;
            Ok(GitReply::Diff { diff })
        }
        GitOp::Stage { paths } => {
            engine.stage_paths(&paths).await?;
            Ok(GitReply::Done)
        }
        GitOp::Unstage { paths } => {
            engine.unstage_paths(&paths).await?;
            Ok(GitReply::Done)
        }
        GitOp::Commit {
            message,
            amend,
            stage_tracked,
        } => {
            let oid = super::commit::commit(engine, &message, amend, stage_tracked).await?;
            Ok(GitReply::Committed { oid })
        }
        GitOp::Discard { paths, scope } => {
            let items = engine.discard(&paths, scope).await?;
            Ok(GitReply::Discarded { items })
        }
        GitOp::RestoreBlobs { items } => {
            engine.restore_blobs(&items).await?;
            Ok(GitReply::Done)
        }
        GitOp::ApplyPatch { patch } => match engine.apply_patch(patch).await? {
            Some(item) => Ok(GitReply::Discarded { items: vec![item] }),
            None => Ok(GitReply::Done),
        },
        GitOp::Identity => {
            let identity = super::identity::get_identity(engine).await?;
            Ok(GitReply::Identity { identity })
        }
        GitOp::SetIdentity { name, email, scope } => {
            super::identity::set_identity(engine, &name, &email, scope).await?;
            Ok(GitReply::Done)
        }
        GitOp::Log { query } => {
            let page = super::log::log(engine, query).await?;
            Ok(GitReply::Log { page })
        }
        GitOp::CommitDetail { oid } => {
            let detail = super::detail::commit_detail(engine, &oid).await?;
            Ok(GitReply::CommitDetail { detail })
        }
        GitOp::Branches => {
            let branches = super::branches::list_branches(engine).await?;
            Ok(GitReply::Branches { branches })
        }
        GitOp::CreateBranch {
            name,
            start_point,
            checkout,
        } => {
            super::branches::create_branch(engine, &name, start_point.as_deref(), checkout).await?;
            Ok(GitReply::Done)
        }
        GitOp::Checkout { target } => {
            super::branches::checkout(engine, target).await?;
            Ok(GitReply::Done)
        }
        GitOp::RenameBranch { old_name, new_name } => {
            super::branches::rename_branch(engine, &old_name, &new_name).await?;
            Ok(GitReply::Done)
        }
        GitOp::DeleteBranch { name, force } => {
            super::branches::delete_branch(engine, &name, force).await?;
            Ok(GitReply::Done)
        }
        GitOp::Merge { reference } => {
            let outcome = super::integrate::merge(engine, &reference).await?;
            Ok(GitReply::Integrated { outcome })
        }
        GitOp::Rebase { onto } => {
            let outcome = super::integrate::rebase(engine, &onto).await?;
            Ok(GitReply::Integrated { outcome })
        }
        GitOp::Sequencer { action } => {
            let outcome = super::integrate::sequencer(engine, action).await?;
            Ok(GitReply::Integrated { outcome })
        }
        GitOp::ResolveConflict { path, resolution } => {
            super::integrate::resolve_conflict(engine, &path, resolution).await?;
            Ok(GitReply::Done)
        }
        GitOp::CherryPick { oid } => {
            let outcome = super::integrate::cherry_pick(engine, &oid).await?;
            Ok(GitReply::Integrated { outcome })
        }
        GitOp::Revert { oid } => {
            let outcome = super::integrate::revert(engine, &oid).await?;
            Ok(GitReply::Integrated { outcome })
        }
        GitOp::Reset { oid, mode } => {
            super::integrate::reset(engine, &oid, mode).await?;
            Ok(GitReply::Done)
        }
        GitOp::Tags => {
            let tags = super::tags::list_tags(engine).await?;
            Ok(GitReply::Tags { tags })
        }
        GitOp::CreateTag {
            name,
            target,
            message,
        } => {
            super::tags::create_tag(engine, &name, &target, message.as_deref()).await?;
            Ok(GitReply::Done)
        }
        GitOp::DeleteTag { name } => {
            super::tags::delete_tag(engine, &name).await?;
            Ok(GitReply::Done)
        }
        GitOp::Stashes => {
            let stashes = super::stash::list_stashes(engine).await?;
            Ok(GitReply::Stashes { stashes })
        }
        GitOp::StashPush {
            message,
            include_untracked,
        } => {
            super::stash::stash_push(engine, message.as_deref(), include_untracked).await?;
            Ok(GitReply::Done)
        }
        GitOp::StashApply { index, oid, pop } => {
            super::stash::stash_apply(engine, index, &oid, pop).await?;
            Ok(GitReply::Done)
        }
        GitOp::StashDrop { index, oid } => {
            super::stash::stash_drop(engine, index, &oid).await?;
            Ok(GitReply::Done)
        }
        GitOp::Remotes => {
            let remotes = super::remotes::list_remotes(engine).await?;
            Ok(GitReply::Remotes { remotes })
        }
        GitOp::AddRemote { name, url } => {
            super::remotes::add_remote(engine, &name, &url).await?;
            Ok(GitReply::Done)
        }
        GitOp::RemoveRemote { name } => {
            super::remotes::remove_remote(engine, &name).await?;
            Ok(GitReply::Done)
        }
        GitOp::SetRemoteUrl { name, url } => {
            super::remotes::set_remote_url(engine, &name, &url).await?;
            Ok(GitReply::Done)
        }
        GitOp::Fetch { remote, account } => {
            super::network::fetch(engine, creds, remote.as_deref(), account.as_deref()).await?;
            Ok(GitReply::Done)
        }
        GitOp::Pull { mode, account } => {
            let outcome = super::network::pull(engine, creds, mode, account.as_deref()).await?;
            Ok(GitReply::Integrated { outcome })
        }
        GitOp::Push {
            remote,
            local_branch,
            remote_branch,
            set_upstream,
            force_with_lease,
            account,
        } => {
            let new_remote_branch = super::network::push(
                engine,
                creds,
                &remote,
                &local_branch,
                &remote_branch,
                set_upstream,
                force_with_lease,
                account.as_deref(),
            )
            .await?;
            Ok(GitReply::Pushed { new_remote_branch })
        }
        GitOp::PushTag {
            remote,
            name,
            account,
        } => {
            super::network::push_tag(engine, creds, &remote, &name, account.as_deref()).await?;
            Ok(GitReply::Done)
        }
        GitOp::DeleteRemoteRef {
            remote,
            full_ref,
            account,
        } => {
            super::network::delete_remote_ref(
                engine,
                creds,
                &remote,
                &full_ref,
                account.as_deref(),
            )
            .await?;
            Ok(GitReply::Done)
        }
    }
}
