#![cfg(unix)]

//! Property tests for workspace jail path resolution (INV-FS-001).

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use cawide_host::rpc::jail::resolve_jailed_path;
use proptest::prelude::*;

fn make_jail_env() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().canonicalize().expect("canonicalize root");

    // Structure:
    // root/
    //   a/
    //   b/
    //   link_out -> /etc
    //   link_in -> <root>/a
    //   dangling -> <root>/missing
    fs::create_dir_all(root.join("a")).expect("create dir a");
    fs::create_dir_all(root.join("b")).expect("create dir b");
    symlink("/etc", root.join("link_out")).expect("symlink link_out");
    symlink(root.join("a"), root.join("link_in")).expect("symlink link_in");
    symlink(root.join("missing"), root.join("dangling")).expect("symlink dangling");

    (tmp, root)
}

fn segment_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("a"),
        Just("b"),
        Just(".."),
        Just("."),
        Just(""),
        Just("link_out"),
        Just("link_in"),
        Just("dangling"),
        Just("\0"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    #[test]
    fn prop_resolve_jailed_path_never_escapes_or_panics(
        segments in prop::collection::vec(segment_strategy(), 0..=8)
    ) {
        use std::sync::LazyLock;
        static JAIL_ENV: LazyLock<(tempfile::TempDir, PathBuf)> = LazyLock::new(make_jail_env);
        let (_tmp, root) = (&JAIL_ENV.0, &JAIL_ENV.1);
        let path_str = segments.join("/");

        match resolve_jailed_path(root, &path_str) {
            Ok(resolved) => {
                // Resolved path must start with the canonical root
                prop_assert!(
                    resolved.starts_with(root),
                    "resolved path {:?} does not start with root {:?}",
                    resolved,
                    root
                );
            }
            Err(_) => {
                // Rejection is safe and expected for escapes/invalid paths
            }
        }
    }
}
