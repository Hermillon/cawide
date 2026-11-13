//! Workspace filesystem watcher (Brick 8).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cawide_protocol::types::HostEvent;
use ignore::gitignore::Gitignore;
use notify_debouncer_full::{
    new_debouncer_opt, DebounceEventResult, DebouncedEvent, Debouncer, NoCache,
};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::warn;

use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::error::NetError;

pub struct WorkspaceWatcher {
    _debouncer: Debouncer<notify::RecommendedWatcher, NoCache>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WorkspaceWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn start(
    root: &Path,
    broadcaster: Arc<HostEventBroadcaster>,
) -> Result<WorkspaceWatcher, NetError> {
    let canonical_root = root
        .canonicalize()
        .map_err(|e| NetError::Watcher(e.to_string()))?;
    let root_label = canonical_root.display().to_string();
    let root_buf = root.to_path_buf();

    let (tx, rx) = mpsc::unbounded_channel();
    let handler = move |res: DebounceEventResult| {
        let _ = tx.send(res);
    };

    let mut debouncer = new_debouncer_opt::<_, notify::RecommendedWatcher, NoCache>(
        Duration::from_millis(250),
        None,
        handler,
        NoCache,
        notify::Config::default(),
    )
    .map_err(|e| NetError::Watcher(e.to_string()))?;

    debouncer
        .watch(&canonical_root, notify::RecursiveMode::Recursive)
        .map_err(|e| NetError::Watcher(e.to_string()))?;

    let task = tokio::spawn(async move {
        run_watcher_task(root_buf, canonical_root, root_label, broadcaster, rx).await;
    });

    Ok(WorkspaceWatcher {
        _debouncer: debouncer,
        task,
    })
}

pub fn is_excluded(root: &Path, home: Option<&Path>) -> bool {
    root == Path::new("/") || home.is_some_and(|h| h.starts_with(root))
}

pub struct RootWatchers {
    broadcaster: Arc<HostEventBroadcaster>,
    home: Option<PathBuf>,
    active: HashMap<PathBuf, WorkspaceWatcher>,
    failed: HashSet<PathBuf>,
}

impl RootWatchers {
    pub fn new(
        broadcaster: Arc<HostEventBroadcaster>,
        initial_root: &Path,
    ) -> Result<Self, NetError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|h| h.canonicalize().ok());
        let mut active = HashMap::new();
        let canonical_initial = initial_root
            .canonicalize()
            .map_err(|e| NetError::Watcher(e.to_string()))?;
        if !is_excluded(&canonical_initial, home.as_deref()) {
            let watcher = start(&canonical_initial, Arc::clone(&broadcaster))?;
            active.insert(canonical_initial, watcher);
        }
        Ok(Self {
            broadcaster,
            home,
            active,
            failed: HashSet::new(),
        })
    }

    pub fn sync(&mut self, desired: &BTreeSet<PathBuf>) {
        self.active.retain(|p, _| desired.contains(p));
        self.failed.retain(|p| desired.contains(p));

        for root in desired {
            if is_excluded(root, self.home.as_deref())
                || self.active.contains_key(root)
                || self.failed.contains(root)
            {
                continue;
            }
            match start(root, Arc::clone(&self.broadcaster)) {
                Ok(watcher) => {
                    self.active.insert(root.clone(), watcher);
                }
                Err(e) => {
                    tracing::warn!(root = %root.display(), error = %e, "failed to start root watcher");
                    self.failed.insert(root.clone());
                }
            }
        }
    }
}

#[derive(Default)]
struct WindowState {
    first_relevant: Option<Instant>,
    last_relevant: Option<Instant>,
    pending_paths: BTreeSet<String>,
    refresh_all: bool,
    git_dirty: bool,
}

impl WindowState {
    fn mark_relevant(&mut self) {
        let now = Instant::now();
        if self.first_relevant.is_none() {
            self.first_relevant = Some(now);
        }
        self.last_relevant = Some(now);
    }

    fn deadline(&self) -> Option<Instant> {
        match (self.first_relevant, self.last_relevant) {
            (Some(first), Some(last)) => {
                let by_last = last + Duration::from_millis(150);
                let by_first = first + Duration::from_millis(1000);
                Some(std::cmp::min(by_last, by_first))
            }
            _ => None,
        }
    }
}

async fn run_watcher_task(
    root: PathBuf,
    canonical_root: PathBuf,
    root_label: String,
    broadcaster: Arc<HostEventBroadcaster>,
    mut rx: mpsc::UnboundedReceiver<DebounceEventResult>,
) {
    let (mut gitignore, _) = Gitignore::new(canonical_root.join(".gitignore"));
    let mut state = WindowState::default();

    loop {
        let dl = state.deadline();
        tokio::select! {
            _ = async {
                match dl {
                    Some(inst) => tokio::time::sleep_until(inst).await,
                    None => std::future::pending().await,
                }
            } => {
                emit_window(&mut state, &root_label, &broadcaster);
            }
            batch = rx.recv() => {
                match batch {
                    Some(res) => {
                        process_batch(
                            res,
                            &root,
                            &canonical_root,
                            &mut gitignore,
                            &mut state,
                        );
                    }
                    None => {
                        emit_window(&mut state, &root_label, &broadcaster);
                        break;
                    }
                }
            }
        }
    }
}

fn emit_window(state: &mut WindowState, root_label: &str, broadcaster: &HostEventBroadcaster) {
    if state.refresh_all {
        broadcaster.broadcast(HostEvent::FsChanged {
            root: root_label.to_string(),
            paths: Vec::new(),
        });
        if state.git_dirty {
            broadcaster.broadcast(HostEvent::GitChanged {
                root: root_label.to_string(),
            });
        }
    } else if !state.pending_paths.is_empty() {
        let mut paths: Vec<String> = std::mem::take(&mut state.pending_paths)
            .into_iter()
            .collect();
        if paths.len() > 200 {
            paths.clear();
        }
        broadcaster.broadcast(HostEvent::FsChanged {
            root: root_label.to_string(),
            paths,
        });
        if state.git_dirty {
            broadcaster.broadcast(HostEvent::GitChanged {
                root: root_label.to_string(),
            });
        }
    } else if state.git_dirty {
        broadcaster.broadcast(HostEvent::GitChanged {
            root: root_label.to_string(),
        });
    }

    state.first_relevant = None;
    state.last_relevant = None;
    state.pending_paths.clear();
    state.refresh_all = false;
    state.git_dirty = false;
}

fn strip_root(path: &Path, root: &Path, canonical_root: &Path) -> Option<PathBuf> {
    if path == canonical_root || path == root {
        return Some(PathBuf::new());
    }
    if let Ok(rel) = path.strip_prefix(canonical_root) {
        return Some(rel.to_path_buf());
    }
    if let Ok(rel) = path.strip_prefix(root) {
        return Some(rel.to_path_buf());
    }
    if let Ok(canon) = path.canonicalize() {
        if canon == canonical_root || canon == root {
            return Some(PathBuf::new());
        }
        if let Ok(rel) = canon.strip_prefix(canonical_root) {
            return Some(rel.to_path_buf());
        }
        if let Ok(rel) = canon.strip_prefix(root) {
            return Some(rel.to_path_buf());
        }
    }
    None
}

fn normalize_rel_path(rel: &Path) -> (String, Vec<Component<'_>>) {
    let comps: Vec<Component<'_>> = rel
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .collect();
    let s = comps
        .iter()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    (s, comps)
}

enum PathOutcome {
    Ignore,
    RefreshAll,
    GitDirtyOnly,
    AddPath(String),
}

fn classify_path(
    clean_str: &str,
    comps: &[Component<'_>],
    canonical_root: &Path,
    gitignore: &mut Gitignore,
) -> PathOutcome {
    if clean_str.is_empty() {
        return PathOutcome::RefreshAll;
    }

    if clean_str == ".git" || clean_str.starts_with(".git/") {
        if clean_str == ".git/index"
            || clean_str == ".git/HEAD"
            || clean_str == ".git/packed-refs"
            || clean_str.starts_with(".git/refs/")
        {
            return PathOutcome::GitDirtyOnly;
        }
        return PathOutcome::Ignore;
    }

    let first = comps[0].as_os_str().to_string_lossy();
    let full = canonical_root.join(clean_str);
    let meta = full.symlink_metadata().ok();
    // Per plan: for a single component, missing path counts as a directory.
    let is_dir = if comps.len() >= 2 {
        true
    } else {
        meta.as_ref().is_none_or(|m| m.is_dir())
    };
    if crate::rpc::fs::is_skipped_dir(&first, is_dir) {
        return PathOutcome::Ignore;
    }

    if clean_str == ".gitignore" {
        let (new_gi, _) = Gitignore::new(canonical_root.join(".gitignore"));
        *gitignore = new_gi;
    }

    let is_dir_gi = meta.as_ref().is_some_and(|m| m.is_dir());
    if gitignore
        .matched_path_or_any_parents(Path::new(clean_str), is_dir_gi)
        .is_ignore()
    {
        return PathOutcome::Ignore;
    }

    PathOutcome::AddPath(clean_str.to_string())
}

fn process_event(
    event: &DebouncedEvent,
    root: &Path,
    canonical_root: &Path,
    gitignore: &mut Gitignore,
    state: &mut WindowState,
) -> bool {
    let mut relevant = false;
    if event.need_rescan() {
        state.refresh_all = true;
        state.git_dirty = true;
        relevant = true;
    }

    for p in &event.event.paths {
        let Some(rel) = strip_root(p, root, canonical_root) else {
            continue;
        };
        let (clean_str, comps) = normalize_rel_path(&rel);
        match classify_path(&clean_str, &comps, canonical_root, gitignore) {
            PathOutcome::Ignore => {}
            PathOutcome::RefreshAll => {
                state.refresh_all = true;
                state.git_dirty = true;
                relevant = true;
            }
            PathOutcome::GitDirtyOnly => {
                state.git_dirty = true;
                relevant = true;
            }
            PathOutcome::AddPath(p) => {
                state.pending_paths.insert(p);
                state.git_dirty = true;
                relevant = true;
                if state.pending_paths.len() > 200 {
                    state.refresh_all = true;
                    state.pending_paths.clear();
                }
            }
        }
    }
    relevant
}

fn process_batch(
    result: DebounceEventResult,
    root: &Path,
    canonical_root: &Path,
    gitignore: &mut Gitignore,
    state: &mut WindowState,
) {
    match result {
        Ok(events) => {
            let mut batch_relevant = false;
            for ev in &events {
                if process_event(ev, root, canonical_root, gitignore, state) {
                    batch_relevant = true;
                }
            }
            if batch_relevant {
                state.mark_relevant();
            }
        }
        Err(errors) => {
            warn!("filesystem debouncer error batch: {errors:?}");
            state.refresh_all = true;
            state.git_dirty = true;
            state.mark_relevant();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_excluded() {
        let home = Path::new("/Users/alice");
        assert!(is_excluded(Path::new("/"), Some(home)));
        assert!(is_excluded(Path::new("/Users/alice"), Some(home)));
        assert!(is_excluded(Path::new("/Users"), Some(home)));
        assert!(!is_excluded(Path::new("/Users/alice/proj"), Some(home)));
        assert!(!is_excluded(Path::new("/tmp/x"), Some(home)));

        assert!(is_excluded(Path::new("/"), None));
        assert!(!is_excluded(Path::new("/Users"), None));
        assert!(!is_excluded(Path::new("/Users/alice"), None));
    }
}
