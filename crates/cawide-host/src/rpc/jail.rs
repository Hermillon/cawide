//! Workspace Jail (INV-FS-001): the single path-confinement check for every RPC path.

use std::path::{Component, Path, PathBuf};

pub const ESCAPE: &str = "access denied: path escapes workspace jail";
pub const DANGLING: &str = "access denied: dangling symlink";
pub const NUL_BYTE: &str = "invalid path: contains null byte";
pub const COLON_CHAR: &str = "invalid path: contains colon";
pub const INVALID_COMPONENT: &str = "invalid path: contains illegal component";
pub const ROOT_NOT_ABSOLUTE: &str = "invalid root: must be an absolute path";
pub const ROOT_NOT_DIR: &str = "invalid root: not a directory";

/// Strips Windows verbatim (extended length) prefixes such as `\\?\` or `\\?\UNC\`.
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", stripped))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Determines whether `child` is equal to or located strictly inside `parent`.
pub fn is_subpath_of(child: &Path, parent: &Path) -> bool {
    #[cfg(unix)]
    if child.starts_with(parent) {
        return true;
    }

    let clean_child = strip_verbatim_prefix(child);
    let clean_parent = strip_verbatim_prefix(parent);

    let child_comps: Vec<_> = clean_child.components().collect();
    let parent_comps: Vec<_> = clean_parent.components().collect();

    // If on Unix but comparing Windows-style drive paths (where \ was not parsed as a separator):
    if child_comps.len() == 1 && parent_comps.len() == 1 {
        let c_str = clean_child.to_string_lossy().replace('\\', "/");
        let p_str = clean_parent.to_string_lossy().replace('\\', "/");
        if c_str.contains('/') || p_str.contains('/') {
            return is_subpath_of(Path::new(&c_str), Path::new(&p_str));
        }
    }

    if child_comps.len() < parent_comps.len() {
        return false;
    }

    for (c, p) in child_comps.iter().zip(parent_comps.iter()) {
        match (c, p) {
            (Component::Prefix(p1), Component::Prefix(p2)) => {
                let s1 = p1.as_os_str().to_string_lossy();
                let s2 = p2.as_os_str().to_string_lossy();
                if !s1.eq_ignore_ascii_case(&s2) {
                    return false;
                }
            }
            (Component::Normal(s1), Component::Normal(s2)) => {
                let str1 = s1.to_string_lossy();
                let str2 = s2.to_string_lossy();
                if !str1.eq_ignore_ascii_case(&str2) {
                    return false;
                }
            }
            (c1, c2) if c1 == c2 => {}
            _ => return false,
        }
    }
    true
}

const DOS_DEVICE_NAMES: [&str; 24] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

fn is_reserved_dos_device(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name);
    DOS_DEVICE_NAMES
        .iter()
        .any(|d| base.eq_ignore_ascii_case(d) || name.eq_ignore_ascii_case(d))
}
pub fn resolve_root(root: &str) -> Result<PathBuf, String> {
    if root.contains('\0') {
        return Err(NUL_BYTE.to_string());
    }
    let path = Path::new(root);
    if !path.is_absolute() {
        return Err(ROOT_NOT_ABSOLUTE.to_string());
    }
    match path.canonicalize() {
        Ok(p) => {
            if p.is_dir() {
                Ok(p)
            } else {
                Err(ROOT_NOT_DIR.to_string())
            }
        }
        Err(e) => Err(format!("invalid root: {e}")),
    }
}

/// Resolves a client path to a canonical path inside `workspace_root`.
///
/// `workspace_root` MUST already be canonical. A leading `/` is workspace-relative.
/// `..`/root/prefix components, null bytes and dangling symlinks (final or
/// intermediate) are rejected. A nonexistent tail is allowed only below an existing,
/// in-jail ancestor.
pub fn resolve_jailed_path(workspace_root: &Path, path_str: &str) -> Result<PathBuf, String> {
    if path_str.contains('\0') {
        return Err(NUL_BYTE.into());
    }
    if path_str.contains(':') {
        return Err(COLON_CHAR.into());
    }
    let rel = path_str.trim_start_matches(['/', '\\']);

    // Validate components for illegal chars, reserved DOS names, or trailing dots/spaces
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(os_name) => {
                let name = os_name.to_string_lossy();
                if is_reserved_dos_device(&name) {
                    return Err(INVALID_COMPONENT.into());
                }
                if name.ends_with(' ') || name.ends_with('.') {
                    return Err(INVALID_COMPONENT.into());
                }
            }
            Component::CurDir => {}
            _ => return Err(ESCAPE.into()),
        }
    }

    let candidate = workspace_root.join(rel);

    // `exists()` follows links; `symlink_metadata()` does not. A component that
    // lstat()s but does not stat() is a dangling symlink whose target is unknown.
    let mut ancestor = candidate.as_path();
    let mut missing_tail = Vec::new();
    while !ancestor.exists() {
        if ancestor.symlink_metadata().is_ok() {
            return Err(DANGLING.into());
        }
        let name = ancestor.file_name().ok_or(ESCAPE)?;
        missing_tail.push(name);
        ancestor = ancestor.parent().ok_or(ESCAPE)?;
    }
    let mut resolved = ancestor.canonicalize().map_err(|e| e.to_string())?;
    let clean_resolved = strip_verbatim_prefix(&resolved);
    let clean_root = strip_verbatim_prefix(workspace_root);
    if !is_subpath_of(&clean_resolved, &clean_root) {
        return Err(ESCAPE.into());
    }
    resolved.extend(missing_tail.into_iter().rev());
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    fn root() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        (tmp, root)
    }

    #[test]
    fn empty_and_dot_resolve_to_root() {
        let (_t, root) = root();
        for p in ["", ".", "/", "//"] {
            assert_eq!(resolve_jailed_path(&root, p), Ok(root.clone()), "{p:?}");
        }
    }

    #[test]
    fn parent_components_are_rejected_even_when_lexically_inside() {
        let (_t, root) = root();
        std::fs::create_dir(root.join("a")).unwrap();
        for p in ["..", "a/../../etc", "a/..", "../x"] {
            assert_eq!(resolve_jailed_path(&root, p), Err(ESCAPE.into()), "{p:?}");
        }
    }

    #[test]
    fn leading_slash_is_workspace_relative() {
        let (_t, root) = root();
        assert_eq!(
            resolve_jailed_path(&root, "/etc/passwd"),
            Ok(root.join("etc/passwd"))
        );
    }

    #[test]
    fn existing_paths_resolve_canonically() {
        let (_t, root) = root();
        std::fs::create_dir_all(root.join("src/sub")).unwrap();
        std::fs::write(root.join("src/sub/f.rs"), b"x").unwrap();
        assert_eq!(
            resolve_jailed_path(&root, "./src/./sub/f.rs"),
            Ok(root.join("src/sub/f.rs"))
        );
    }

    #[test]
    fn nonexistent_tail_below_existing_ancestor_is_allowed() {
        let (_t, root) = root();
        assert_eq!(
            resolve_jailed_path(&root, "new/dir/file.txt"),
            Ok(root.join("new/dir/file.txt"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_jail_is_followed() {
        let (_t, root) = root();
        std::fs::create_dir(root.join("real")).unwrap();
        std::fs::write(root.join("real/f.txt"), b"x").unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();
        assert_eq!(
            resolve_jailed_path(&root, "alias/f.txt"),
            Ok(root.join("real/f.txt"))
        );
        assert_eq!(
            resolve_jailed_path(&root, "alias/missing.txt"),
            Ok(root.join("real/missing.txt"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        let (_t, root) = root();
        symlink("/etc", root.join("out")).unwrap();
        assert_eq!(resolve_jailed_path(&root, "out/hosts"), Err(ESCAPE.into()));
        assert_eq!(resolve_jailed_path(&root, "out"), Err(ESCAPE.into()));
        assert_eq!(
            resolve_jailed_path(&root, "out/missing/x"),
            Err(ESCAPE.into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_final_and_intermediate_are_rejected() {
        let (_t, root) = root();
        symlink("/etc/cawide_missing_dir", root.join("dl")).unwrap();
        assert_eq!(resolve_jailed_path(&root, "dl"), Err(DANGLING.into()));
        assert_eq!(resolve_jailed_path(&root, "dl/sub"), Err(DANGLING.into()));
        assert_eq!(
            resolve_jailed_path(&root, "dl/sub/deeper.txt"),
            Err(DANGLING.into())
        );
    }
    #[test]
    fn null_byte_is_rejected() {
        let (_t, root) = root();
        assert_eq!(resolve_jailed_path(&root, "a\0b"), Err(NUL_BYTE.into()));
    }

    #[test]
    fn test_resolve_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let canonical_temp = temp.path().canonicalize().expect("canonical temp");

        // valid directory
        let res = resolve_root(temp.path().to_str().expect("to_str"));
        assert_eq!(res, Ok(canonical_temp.clone()));

        // relative path
        assert_eq!(
            resolve_root("relative/path"),
            Err(ROOT_NOT_ABSOLUTE.to_string())
        );

        // empty string
        assert_eq!(resolve_root(""), Err(ROOT_NOT_ABSOLUTE.to_string()));

        // NUL byte
        assert_eq!(resolve_root("/tmp/a\0b"), Err(NUL_BYTE.to_string()));

        // missing directory
        let missing = temp.path().join("does_not_exist");
        assert!(resolve_root(missing.to_str().expect("to_str")).is_err());

        // regular file
        let file_path = temp.path().join("a_file.txt");
        std::fs::write(&file_path, b"hello").expect("write file");
        assert_eq!(
            resolve_root(file_path.to_str().expect("to_str")),
            Err(ROOT_NOT_DIR.to_string())
        );

        #[cfg(unix)]
        {
            // symlinked directory resolves to canonical target
            let link_path = temp.path().join("link_dir");
            let real_dir = temp.path().join("real_dir");
            std::fs::create_dir(&real_dir).expect("create real_dir");
            symlink(&real_dir, &link_path).expect("symlink dir");
            let canonical_real = real_dir.canonicalize().expect("canonical real");
            assert_eq!(
                resolve_root(link_path.to_str().expect("to_str")),
                Ok(canonical_real)
            );
        }
    }
    #[test]
    fn test_strip_verbatim_prefix() {
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\C:\Users\User\repo")),
            PathBuf::from(r"C:\Users\User\repo")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\UNC\server\share\repo")),
            PathBuf::from(r"\\server\share\repo")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new("/var/workspace")),
            PathBuf::from("/var/workspace")
        );
    }

    #[test]
    fn test_is_subpath_of() {
        let parent = Path::new("/workspace");
        let child = Path::new("/workspace/sub/file.txt");
        assert!(is_subpath_of(child, parent));

        let outside = Path::new("/etc/passwd");
        assert!(!is_subpath_of(outside, parent));

        // Windows case-folding tests
        let win_parent = Path::new(r"C:\Workspace");
        let win_child = Path::new(r"c:\workspace\SUB\file.txt");
        let win_verbatim_child = Path::new(r"\\?\c:\workspace\SUB\file.txt");
        assert!(is_subpath_of(win_child, win_parent));
        assert!(is_subpath_of(win_verbatim_child, win_parent));

        let win_outside = Path::new(r"D:\Workspace\file.txt");
        assert!(!is_subpath_of(win_outside, win_parent));
    }

    #[test]
    fn test_dos_device_rejection() {
        let (_t, root) = root();
        for dev in [
            "CON",
            "con",
            "Prn",
            "AUX",
            "aux",
            "NUL",
            "nul",
            "CONIN$",
            "conin$",
            "CONOUT$",
            "COM1",
            "com9",
            "LPT1",
            "lpt5",
            "con.txt",
            "nul.tar.gz",
        ] {
            assert_eq!(
                resolve_jailed_path(&root, dev),
                Err(INVALID_COMPONENT.into()),
                "testing {dev}"
            );
            assert_eq!(
                resolve_jailed_path(&root, &format!("sub/{dev}")),
                Err(INVALID_COMPONENT.into()),
                "testing sub/{dev}"
            );
        }
    }

    #[test]
    fn test_colon_rejection() {
        let (_t, root) = root();
        assert_eq!(resolve_jailed_path(&root, "C:foo"), Err(COLON_CHAR.into()));
        assert_eq!(
            resolve_jailed_path(&root, "file.txt:hidden"),
            Err(COLON_CHAR.into())
        );
        assert_eq!(
            resolve_jailed_path(&root, r"C:\Windows\System32"),
            Err(COLON_CHAR.into())
        );
    }

    #[test]
    fn test_trailing_dot_and_space_rejection() {
        let (_t, root) = root();
        assert_eq!(
            resolve_jailed_path(&root, "file.txt."),
            Err(INVALID_COMPONENT.into())
        );
        assert_eq!(
            resolve_jailed_path(&root, "file.txt "),
            Err(INVALID_COMPONENT.into())
        );
        assert_eq!(
            resolve_jailed_path(&root, "dir./file.txt"),
            Err(INVALID_COMPONENT.into())
        );
        assert_eq!(
            resolve_jailed_path(&root, "dir /file.txt"),
            Err(INVALID_COMPONENT.into())
        );
    }
}
