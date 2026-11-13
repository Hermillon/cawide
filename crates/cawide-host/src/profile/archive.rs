use std::io::Read;
use std::path::{Component, Path};

use anyhow::Context;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

pub const MANIFEST_PATH: &str = "__cawide__/manifest.json";
pub const CLAUDE_FRAGMENT_PATH: &str = "__cawide__/claude-json.json";
pub const OMP_DB_PATH: &str = "__cawide__/db/omp-agent.db";
pub const OPENCODE_DB_PATH: &str = "__cawide__/db/opencode.db";
pub const ALLOWED_PREFIXES: [&str; 7] = [
    ".claude/",
    ".codex/",
    ".omp/",
    ".agents/",
    ".config/opencode/",
    ".local/share/opencode/",
    "__cawide__/",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub source_os: String,
    pub source_home: String,
    pub source_host: String,
    pub agents: Vec<String>,
    pub notices: Vec<String>,
}

pub struct ArchiveFile {
    pub path: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

pub struct ArchiveContents {
    pub manifest: Manifest,
    pub files: Vec<ArchiveFile>,
}

pub fn write_archive(staging: &Path, manifest: &Manifest) -> anyhow::Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);

    // 1. Manifest as first entry
    let manifest_bytes =
        serde_json::to_vec_pretty(manifest).context("failed to serialize manifest")?;
    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_size(manifest_bytes.len() as u64);
    manifest_header.set_mode(0o600);
    manifest_header.set_uid(0);
    manifest_header.set_gid(0);
    manifest_header.set_mtime(0);
    manifest_header.set_entry_type(tar::EntryType::Regular);
    manifest_header.set_cksum();
    builder.append_data(
        &mut manifest_header,
        MANIFEST_PATH,
        manifest_bytes.as_slice(),
    )?;

    // 2. Staged files in sorted relative path order
    let mut entries = Vec::new();
    collect_files_recursive(staging, staging, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (rel_path, abs_path, mode) in entries {
        if rel_path == MANIFEST_PATH {
            continue;
        }
        let data = std::fs::read(&abs_path)
            .with_context(|| format!("failed to read staged file {}", abs_path.display()))?;

        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(mode & 0o777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        builder.append_data(&mut header, &rel_path, data.as_slice())?;
    }

    let encoder = builder.into_inner()?;
    let out = encoder.finish()?;
    Ok(out)
}

fn collect_files_recursive(
    base: &Path,
    current: &Path,
    out: &mut Vec<(String, std::path::PathBuf, u32)>,
) -> anyhow::Result<()> {
    if !current.is_dir() {
        return Ok(());
    }

    let mut dir_entries: Vec<_> = std::fs::read_dir(current)?.filter_map(|e| e.ok()).collect();
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let path = entry.path();
        if path.is_file() {
            let rel = path
                .strip_prefix(base)?
                .to_string_lossy()
                .replace('\\', "/");
            #[cfg(unix)]
            let mode_val = {
                use std::os::unix::fs::PermissionsExt;
                entry.metadata()?.permissions().mode()
            };
            #[cfg(not(unix))]
            let mode_val = 0o644;

            out.push((rel, path, mode_val));
        } else if path.is_dir() {
            collect_files_recursive(base, &path, out)?;
        }
    }
    Ok(())
}

pub fn read_archive(bytes: &[u8]) -> anyhow::Result<ArchiveContents> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);

    let mut running_size: u64 = 0;
    const MAX_UNPACKED_SIZE: u64 = 256 * 1024 * 1024;

    let mut manifest: Option<Manifest> = None;
    let mut files = Vec::new();

    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let entry_type = entry.header().entry_type();

        if entry_type == tar::EntryType::Directory {
            continue;
        }

        let raw_path_bytes = entry.path_bytes();
        let path_str = std::str::from_utf8(&raw_path_bytes)
            .map_err(|_| anyhow::anyhow!("profile archive contains invalid UTF-8 path"))?
            .replace('\\', "/");

        if entry_type != tar::EntryType::Regular {
            anyhow::bail!("profile archive contains unsupported entry type: {path_str}");
        }

        let p = Path::new(&path_str);
        for comp in p.components() {
            if !matches!(comp, Component::Normal(_)) {
                anyhow::bail!("profile archive contains unsafe path: {path_str}");
            }
        }

        if !ALLOWED_PREFIXES
            .iter()
            .any(|prefix| path_str.starts_with(prefix))
        {
            anyhow::bail!("profile archive contains unsafe path: {path_str}");
        }

        let size = entry.header().size()?;
        running_size += size;
        if running_size > MAX_UNPACKED_SIZE {
            anyhow::bail!("profile archive is too large when unpacked");
        }

        let mut data = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut data)?;

        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;

        if path_str == MANIFEST_PATH {
            let m: Manifest =
                serde_json::from_slice(&data).context("failed to parse profile manifest")?;
            if m.format_version != 1 {
                anyhow::bail!("unsupported profile archive format");
            }
            manifest = Some(m);
        } else {
            files.push(ArchiveFile {
                path: path_str,
                mode,
                data,
            });
        }
    }

    let manifest = manifest.ok_or_else(|| anyhow::anyhow!("unsupported profile archive format"))?;

    Ok(ArchiveContents { manifest, files })
}
