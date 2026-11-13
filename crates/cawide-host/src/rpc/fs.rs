//! Workspace filesystem engine: listing, bounded reads, fuzzy search, uploads, remote open.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

use cawide_protocol::types::{
    FsChunk, FsEntry, FsReadResult, FsSearchResult, FS_READ_CHUNK_MAX_BYTES, FS_SEARCH_MAX_RESULTS,
    FS_SEARCH_MAX_VISITED_ENTRIES, FS_UPLOAD_MAX_BYTES, MAX_CHUNKED_FILE_SIZE, MAX_FILE_SIZE,
};
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::rpc::jail::resolve_jailed_path;

/// Opens a URL or absolute file path with the host's default handler.
pub type OpenerHook = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Directories never listed or searched (VCS internals and build output).
const SKIPPED_DIRS: [&str; 5] = [".git", "node_modules", "target", "build", "dist"];
const RECURSIVE_LIST_MAX_DEPTH: usize = 8;
const RECURSIVE_LIST_MAX_ENTRIES: usize = 2_000;
const UPLOAD_NAME_MAX_CHARS: usize = 128;
const UPLOAD_FALLBACK_NAME: &str = "upload.bin";

/// Extensions the host launcher could execute or install (compared case-insensitively).
/// Defense in depth on top of the executable-bit check.
const BLOCKED_OPEN_EXTENSIONS: [&str; 31] = [
    "app",
    "command",
    "sh",
    "bash",
    "zsh",
    "fish",
    "csh",
    "bin",
    "desktop",
    "terminal",
    "workflow",
    "action",
    "scpt",
    "applescript",
    "jar",
    "pkg",
    "mpkg",
    "dmg",
    "exe",
    "com",
    "msi",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "jse",
    "wsf",
    "lnk",
    "scr",
    "pif",
    "js",
];

pub struct FsEngine {
    upload_dir: PathBuf,
    opener: OpenerHook,
}

impl std::fmt::Debug for FsEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsEngine")
            .field("upload_dir", &self.upload_dir)
            .finish_non_exhaustive()
    }
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn is_skipped_dir(name: &str, is_dir: bool) -> bool {
    is_dir && SKIPPED_DIRS.contains(&name)
}

fn unix_secs(t: std::io::Result<SystemTime>) -> u64 {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

fn unix_nanos(t: std::io::Result<SystemTime>) -> u64 {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Walker over `root` showing everything `list()` shows (hidden and gitignored
/// files included), never following symlinks, pruning [`SKIPPED_DIRS`].
fn workspace_walker(root: &Path) -> ignore::WalkBuilder {
    let mut builder = ignore::WalkBuilder::new(root);
    builder.standard_filters(false).filter_entry(|entry| {
        let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
        !is_skipped_dir(&entry.file_name().to_string_lossy(), is_dir)
    });
    builder
}

/// Creates `dir` (mode 0700) if missing, then verifies, without following links,
/// that it is a directory owned by this user and not accessible to others. Nothing
/// is changed by path after the check, so a swapped-in symlink cannot be chmodded.
fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).map_err(|e| e.to_string())?;

    let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Err("upload directory is not a real directory".into());
    }

    #[cfg(unix)]
    {
        // SAFETY: getuid takes no arguments, cannot fail and touches no Rust memory.
        if meta.uid() != unsafe { libc::getuid() } {
            return Err("upload directory is not owned by the current user".into());
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "upload directory {} must not be accessible to other users (chmod 700)",
                dir.display()
            ));
        }
    }

    Ok(())
}

/// Reduces a client filename to `[A-Za-z0-9._-]{1,128}` with no path components.
fn sanitize_upload_name(filename: &str) -> String {
    let base = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(UPLOAD_FALLBACK_NAME);
    let sanitized: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(UPLOAD_NAME_MAX_CHARS)
        .collect();
    if sanitized.trim_matches('.').is_empty() {
        UPLOAD_FALLBACK_NAME.to_string()
    } else {
        sanitized
    }
}

pub(crate) fn join_err(e: tokio::task::JoinError) -> String {
    format!("internal task failed: {e}")
}

impl FsEngine {
    pub fn new(upload_dir: PathBuf) -> Self {
        let opener: OpenerHook = Arc::new(|target| opener::open(target).map_err(|e| e.to_string()));
        Self::new_with_opener(upload_dir, opener)
    }

    pub fn new_with_opener(upload_dir: PathBuf, opener: OpenerHook) -> Self {
        Self { upload_dir, opener }
    }

    pub async fn list(
        &self,
        root: &Path,
        path: &str,
        recursive: bool,
    ) -> Result<Vec<FsEntry>, String> {
        let target = resolve_jailed_path(root, path)?;
        if !tokio::fs::metadata(&target).await.is_ok_and(|m| m.is_dir()) {
            return Err("not a directory".into());
        }
        if recursive {
            return self.list_recursive(root, target).await;
        }

        let mut dir = tokio::fs::read_dir(&target)
            .await
            .map_err(|e| e.to_string())?;
        let mut entries = Vec::new();
        while let Some(entry) = dir.next_entry().await.map_err(|e| e.to_string())? {
            let entry_path = entry.path();
            // Follow symlinks for display; a dangling link falls back to its own metadata.
            let meta = match tokio::fs::metadata(&entry_path).await {
                Ok(m) => m,
                Err(_) => entry.metadata().await.map_err(|e| e.to_string())?,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_skipped_dir(&name, meta.is_dir()) {
                continue;
            }
            entries.push(FsEntry {
                path: relative_to(root, &entry_path),
                name,
                is_dir: meta.is_dir(),
                size: meta.len(),
                modified_ts: unix_secs(meta.modified()),
            });
        }
        entries.sort_unstable_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
        Ok(entries)
    }

    async fn list_recursive(&self, root: &Path, target: PathBuf) -> Result<Vec<FsEntry>, String> {
        let root_buf = root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut entries = Vec::new();
            let walker = workspace_walker(&target)
                .max_depth(Some(RECURSIVE_LIST_MAX_DEPTH))
                .build();
            for entry in walker.filter_map(Result::ok).filter(|e| e.depth() > 0) {
                if entries.len() >= RECURSIVE_LIST_MAX_ENTRIES {
                    break;
                }
                // Follow symlinks like `list()`; a dangling link keeps its own metadata.
                let Ok(meta) = std::fs::metadata(entry.path()).or_else(|_| entry.metadata()) else {
                    continue;
                };
                entries.push(FsEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    path: relative_to(&root_buf, entry.path()),
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                    modified_ts: unix_secs(meta.modified()),
                });
            }
            entries
        })
        .await
        .map_err(join_err)
    }

    async fn open_regular_file(
        root: &Path,
        path: &str,
    ) -> Result<(tokio::fs::File, std::fs::Metadata), String> {
        let jailed = resolve_jailed_path(root, path)?;
        let file = tokio::fs::File::open(&jailed)
            .await
            .map_err(|e| e.to_string())?;
        // Metadata from the open handle: the checks apply to exactly the bytes we read.
        let meta = file.metadata().await.map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err("target is not a regular file".into());
        }
        Ok((file, meta))
    }

    pub async fn read(
        &self,
        root: &Path,
        path: &str,
        offset: u64,
        length: u32,
    ) -> Result<FsReadResult, String> {
        let (mut file, meta) = Self::open_regular_file(root, path).await?;
        let total_size = meta.len();
        if total_size > MAX_FILE_SIZE {
            return Ok(FsReadResult {
                data: Vec::new(),
                too_large: true,
                total_size,
            });
        }
        if offset >= total_size {
            return Ok(FsReadResult {
                data: Vec::new(),
                too_large: false,
                total_size,
            });
        }
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| e.to_string())?;
        // Bounded by `total_size <= MAX_FILE_SIZE` (500 KB), so the cast is lossless.
        let read_len = u64::from(length).min(total_size - offset) as usize;
        let mut data = Vec::with_capacity(read_len);
        // `take` tolerates a file shrinking after `metadata()`.
        file.take(read_len as u64)
            .read_to_end(&mut data)
            .await
            .map_err(|e| e.to_string())?;
        Ok(FsReadResult {
            data,
            too_large: false,
            total_size,
        })
    }

    pub async fn read_chunk(
        &self,
        root: &Path,
        path: &str,
        offset: u64,
        length: u32,
    ) -> Result<FsChunk, String> {
        let (mut file, meta) = Self::open_regular_file(root, path).await?;
        let total_size = meta.len();
        let modified_unix_ns = unix_nanos(meta.modified());
        if total_size > MAX_CHUNKED_FILE_SIZE {
            return Ok(FsChunk {
                data: Vec::new(),
                too_large: true,
                total_size,
                modified_unix_ns,
            });
        }
        let length = length.min(FS_READ_CHUNK_MAX_BYTES);
        if length == 0 || offset >= total_size {
            return Ok(FsChunk {
                data: Vec::new(),
                too_large: false,
                total_size,
                modified_unix_ns,
            });
        }
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| e.to_string())?;
        // Bounded by `FS_READ_CHUNK_MAX_BYTES` (4 MB), so the cast is lossless.
        let read_len = u64::from(length).min(total_size - offset) as usize;
        let mut data = Vec::with_capacity(read_len);
        // `take` tolerates a file shrinking after `metadata()`.
        file.take(read_len as u64)
            .read_to_end(&mut data)
            .await
            .map_err(|e| e.to_string())?;
        Ok(FsChunk {
            data,
            too_large: false,
            total_size,
            modified_unix_ns,
        })
    }

    pub async fn search(&self, root: &Path, query: &str) -> Result<Vec<FsSearchResult>, String> {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let root_buf = root.to_path_buf();
        let pattern = Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart);
        tokio::task::spawn_blocking(move || {
            let mut matcher = Matcher::new(Config::DEFAULT.match_paths());
            let mut char_buf = Vec::new();
            let mut indices = Vec::new();
            let mut results = Vec::new();
            let walker = workspace_walker(&root_buf).build();
            for entry in walker
                .filter_map(Result::ok)
                .take(FS_SEARCH_MAX_VISITED_ENTRIES)
            {
                if !entry.file_type().is_some_and(|t| t.is_file()) {
                    continue;
                }
                let rel = relative_to(&root_buf, entry.path());
                let haystack = Utf32Str::new(&rel, &mut char_buf);
                if let Some(score) = pattern.indices(haystack, &mut matcher, &mut indices) {
                    indices.sort_unstable();
                    indices.dedup();
                    results.push(FsSearchResult {
                        path: rel,
                        score,
                        // Hand over the buffer; a fresh one is allocated only per hit.
                        match_indices: std::mem::take(&mut indices),
                    });
                } else {
                    indices.clear();
                }
            }
            results
                .sort_unstable_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
            results.truncate(FS_SEARCH_MAX_RESULTS);
            results
        })
        .await
        .map_err(join_err)
    }

    /// Stores `data` in the isolated upload directory (never the workspace) and
    /// returns the absolute host path.
    pub async fn upload(&self, filename: &str, data: Vec<u8>) -> Result<String, String> {
        if data.len() > FS_UPLOAD_MAX_BYTES {
            return Err(format!("upload exceeds {FS_UPLOAD_MAX_BYTES} byte limit"));
        }
        let name = format!(
            "{}_{:08x}_{}",
            unix_secs(Ok(SystemTime::now())),
            rand::random::<u32>(),
            sanitize_upload_name(filename)
        );
        let upload_dir = self.upload_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<String, String> {
            ensure_private_dir(&upload_dir)?;

            // tempfile creates 0600; persist is an atomic rename within the same dir.
            let mut temp = tempfile::Builder::new()
                .prefix(".upload_")
                .tempfile_in(&upload_dir)
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut temp, &data).map_err(|e| e.to_string())?;
            let target = upload_dir.join(name);
            temp.persist_noclobber(&target)
                .map_err(|e| e.error.to_string())?;
            Ok(target.display().to_string())
        })
        .await
        .map_err(join_err)?
    }

    /// Opens an http(s) URL or a non-executable regular file inside the jail on the host.
    pub async fn remote_open(&self, root: &Path, target: &str) -> Result<(), String> {
        if target.chars().any(char::is_control) {
            return Err("target contains control characters".into());
        }
        let lower = target.get(..8).unwrap_or(target).to_ascii_lowercase();
        let validated = if lower.starts_with("http://") || lower.starts_with("https://") {
            if target.chars().any(char::is_whitespace) {
                return Err("URL contains whitespace".into());
            }
            let url = url::Url::parse(target).map_err(|e| format!("invalid URL: {e}"))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err("prohibited URL scheme".into());
            }
            target.to_string()
        } else {
            // Anything else (including `file:`/`javascript:` URLs) must be a jailed file.
            self.validate_openable_file(root, target).await?
        };
        let opener = Arc::clone(&self.opener);
        tokio::task::spawn_blocking(move || opener(&validated))
            .await
            .map_err(join_err)?
    }

    async fn validate_openable_file(&self, root: &Path, target: &str) -> Result<String, String> {
        let jailed = resolve_jailed_path(root, target)?;
        let meta = tokio::fs::metadata(&jailed)
            .await
            .map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err("cannot open non-regular file".into());
        }
        #[cfg(unix)]
        if meta.permissions().mode() & 0o111 != 0 {
            return Err("opening executable files is prohibited".into());
        }
        #[cfg(windows)]
        {
            let ext = jailed.extension().and_then(|e| e.to_str());
            const WINDOWS_EXECUTABLE_EXTENSIONS: [&str; 10] = [
                "exe", "cmd", "bat", "ps1", "vbs", "js", "wsf", "scr", "pif", "lnk",
            ];
            if ext.is_some_and(|e| {
                WINDOWS_EXECUTABLE_EXTENSIONS
                    .iter()
                    .any(|x| e.eq_ignore_ascii_case(x))
            }) {
                return Err("opening executable files is prohibited".into());
            }
        }
        let ext = jailed.extension().and_then(|e| e.to_str());
        if ext.is_some_and(|ext| {
            BLOCKED_OPEN_EXTENSIONS
                .iter()
                .any(|b| ext.eq_ignore_ascii_case(b))
        }) {
            return Err("opening executable file type is prohibited".into());
        }
        jailed
            .into_os_string()
            .into_string()
            .map_err(|_| "path is not valid UTF-8".to_string())
    }
}
