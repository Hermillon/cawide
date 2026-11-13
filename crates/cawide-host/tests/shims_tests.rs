#[test]
fn test_shims_generation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_dir = tmp.path();
    let bin_dir = cawide_host::net::shims::ensure_shims(config_dir).expect("ensure_shims");

    assert_eq!(bin_dir, config_dir.join("bin"));
    assert!(bin_dir.is_dir());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&bin_dir)
            .expect("bin metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    let cawide_bin = bin_dir.join("cawide");
    assert!(cawide_bin.exists());

    let cawide_open = bin_dir.join("cawide-open");
    assert!(cawide_open.is_file());
    let cawide_open_content = std::fs::read_to_string(&cawide_open).expect("read cawide-open");
    assert!(cawide_open_content.contains(r#"exec "$BIN_DIR/cawide" open "$@""#));

    let open_shim = bin_dir.join("open");
    assert!(open_shim.is_file());
    let open_content = std::fs::read_to_string(&open_shim).expect("read open");
    assert!(open_content.contains("is_url()"));
    assert!(open_content.contains("is_port()"));
    assert!(open_content.contains(r#""$CAWIDE_BIN" open "$target_url""#));

    let xdg_open = bin_dir.join("xdg-open");
    assert!(xdg_open.is_file());
    let xdg_content = std::fs::read_to_string(&xdg_open).expect("read xdg-open");
    assert!(xdg_content.contains("is_url()"));
    assert!(xdg_content.contains("is_port()"));
    assert!(xdg_content.contains(r#""$CAWIDE_BIN" open "$target_url""#));

    let codex_shim = bin_dir.join("codex");
    assert!(codex_shim.is_file());
    let codex_content = std::fs::read_to_string(&codex_shim).expect("read codex");
    assert!(codex_content.contains("--enable hooks --dangerously-bypass-hook-trust"));

    let claude_shim = bin_dir.join("claude");
    assert!(claude_shim.is_file());
    let claude_content = std::fs::read_to_string(&claude_shim).expect("read claude");
    assert!(claude_content.contains("setup claude"));

    let omp_shim = bin_dir.join("omp");
    assert!(omp_shim.is_file());
    let omp_content = std::fs::read_to_string(&omp_shim).expect("read omp");
    assert!(omp_content.contains("setup omp"));

    let opencode_shim = bin_dir.join("opencode");
    assert!(opencode_shim.is_file());
    let opencode_content = std::fs::read_to_string(&opencode_shim).expect("read opencode");
    assert!(opencode_content.contains("setup opencode"));

    let zsh_dir = config_dir.join("shell").join("zsh");
    assert!(zsh_dir.join(".zshenv").is_file());
    assert!(zsh_dir.join(".zprofile").is_file());
    assert!(zsh_dir.join(".zshrc").is_file());
    assert!(zsh_dir.join(".zlogin").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for shim in [
            &cawide_open,
            &open_shim,
            &xdg_open,
            &codex_shim,
            &claude_shim,
            &omp_shim,
            &opencode_shim,
        ] {
            let mode = std::fs::metadata(shim)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o755,
                "Shim {} must have 0o755 permissions",
                shim.display()
            );
        }
    }

    // Idempotency: running ensure_shims again should succeed without error
    let bin_dir_again =
        cawide_host::net::shims::ensure_shims(config_dir).expect("ensure_shims repeat");
    assert_eq!(bin_dir_again, bin_dir);
    assert!(bin_dir.join("cawide").exists());
    assert!(bin_dir.join("cawide-open").exists());
    assert!(bin_dir.join("open").exists());
    assert!(bin_dir.join("xdg-open").exists());
    assert!(bin_dir.join("codex").exists());
    assert!(bin_dir.join("claude").exists());
    assert!(bin_dir.join("omp").exists());
    assert!(bin_dir.join("opencode").exists());
}

#[test]
#[cfg(unix)]
fn test_shims_posix_execution() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_dir = tmp.path();
    let bin_dir = cawide_host::net::shims::ensure_shims(config_dir).expect("ensure_shims");

    let log_file = tmp.path().join("cawide_calls.log");
    // Replace cawide in bin_dir with a mock script that logs arguments
    let mock_cawide = bin_dir.join("cawide");
    if std::fs::symlink_metadata(&mock_cawide).is_ok() {
        let _ = std::fs::remove_file(&mock_cawide);
    }
    let mock_script = format!(
        "#!/bin/sh\necho \"$@\" >> \"{}\"\nexit 0\n",
        log_file.display()
    );
    std::fs::write(&mock_cawide, mock_script).expect("write mock cawide");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&mock_cawide, std::fs::Permissions::from_mode(0o755))
            .expect("chmod mock cawide");
    }

    // 1. Test cawide-open execution
    let status = std::process::Command::new(bin_dir.join("cawide-open"))
        .arg("5173")
        .status()
        .expect("failed to execute cawide-open");
    assert!(status.success());
    let log = std::fs::read_to_string(&log_file).expect("read log");
    assert!(log.contains("open 5173"));

    // 2. Test open with URL
    let status = std::process::Command::new(bin_dir.join("open"))
        .arg("http://localhost:3000")
        .status()
        .expect("failed to execute open");
    assert!(status.success());
    let log = std::fs::read_to_string(&log_file).expect("read log");
    assert!(log.contains("open http://localhost:3000"));

    // 3. Test open with Port
    let status = std::process::Command::new(bin_dir.join("open"))
        .arg("8080")
        .status()
        .expect("failed to execute open with port");
    assert!(status.success());
    let log = std::fs::read_to_string(&log_file).expect("read log");
    assert!(log.contains("open 8080"));

    // 4. Test xdg-open with URL
    let status = std::process::Command::new(bin_dir.join("xdg-open"))
        .arg("https://example.com/app?key=val")
        .status()
        .expect("failed to execute xdg-open");
    assert!(status.success());
    let log = std::fs::read_to_string(&log_file).expect("read log");
    assert!(log.contains("open https://example.com/app?key=val"));

    // 5. Test xdg-open with flags preceding URL
    let status = std::process::Command::new(bin_dir.join("xdg-open"))
        .arg("--some-flag")
        .arg("localhost:4000")
        .status()
        .expect("failed to execute xdg-open with flag");
    assert!(status.success());
    let log = std::fs::read_to_string(&log_file).expect("read log");
    assert!(log.contains("open localhost:4000"));

    // 6. Test fallback when cawide open fails or target is non-url
    let fallback_dir = tmp.path().join("fallback");
    std::fs::create_dir_all(&fallback_dir).expect("create fallback dir");
    let fallback_log = tmp.path().join("fallback.log");
    let fallback_xdg = fallback_dir.join("xdg-open");
    std::fs::write(
        &fallback_xdg,
        format!(
            "#!/bin/sh\necho \"FALLBACK:$@\" >> \"{}\"\nexit 0\n",
            fallback_log.display()
        ),
    )
    .expect("write fallback xdg-open");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fallback_xdg, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fallback xdg-open");
    }
    #[cfg(target_os = "linux")]
    {
        let existing_path = std::env::var("PATH").unwrap_or_default();
        let test_path = format!("{}:{}", fallback_dir.display(), existing_path);
        let status = std::process::Command::new(bin_dir.join("xdg-open"))
            .arg("some_document.pdf")
            .env("PATH", &test_path)
            .status()
            .expect("failed to execute fallback");
        assert!(status.success());
        let fb = std::fs::read_to_string(&fallback_log).expect("read fallback log");
        assert!(fb.contains("FALLBACK:some_document.pdf"));
    }

    #[cfg(target_os = "macos")]
    {
        // On Darwin, open with macOS flag like -h should not invoke CAWIDE_BIN
        let before_log = std::fs::read_to_string(&log_file).unwrap_or_default();
        let _ = std::process::Command::new(bin_dir.join("open"))
            .arg("-h")
            .status();
        let after_log = std::fs::read_to_string(&log_file).unwrap_or_default();
        assert_eq!(
            before_log, after_log,
            "open -h should not invoke cawide open"
        );
    }
}

#[test]
fn test_open_with_flags() {
    use cawide_host::web::{normalize_open_target, resolve_open_target};

    // Prioritized target resolution tests
    let args1 = vec!["5173".to_string()];
    let target1 = resolve_open_target(&args1).expect("resolve 5173");
    assert_eq!(target1, "5173");
    assert_eq!(
        normalize_open_target(&target1).expect("norm"),
        "http://localhost:5173/"
    );

    let args2 = vec![":3000".to_string()];
    let target2 = resolve_open_target(&args2).expect("resolve :3000");
    assert_eq!(target2, ":3000");
    assert_eq!(
        normalize_open_target(&target2).expect("norm"),
        "http://localhost:3000/"
    );

    let args3 = vec![
        "--new-window".to_string(),
        "http://127.0.0.1:8080".to_string(),
    ];
    let target3 = resolve_open_target(&args3).expect("resolve url with flag");
    assert_eq!(target3, "http://127.0.0.1:8080");
    assert_eq!(
        normalize_open_target(&target3).expect("norm"),
        "http://127.0.0.1:8080/"
    );

    // URL with query parameters and flags
    let args4 = vec![
        "-a".to_string(),
        "Google Chrome".to_string(),
        "https://www.npmjs.com/login?next=/login/cli/12345".to_string(),
    ];
    let target4 = resolve_open_target(&args4).expect("resolve full npmjs url");
    assert_eq!(target4, "https://www.npmjs.com/login?next=/login/cli/12345");
    assert_eq!(
        normalize_open_target(&target4).expect("norm"),
        "https://www.npmjs.com/login?next=/login/cli/12345"
    );

    // Port with preceding flags
    let args4b = vec!["-a".to_string(), "Safari".to_string(), "3000".to_string()];
    let target4b = resolve_open_target(&args4b).expect("resolve port with flag");
    assert_eq!(target4b, "3000");
    assert_eq!(
        normalize_open_target(&target4b).expect("norm"),
        "http://localhost:3000/"
    );

    // Quoted inputs
    let args5 = vec!["'localhost:5173/app'".to_string()];
    let target5 = resolve_open_target(&args5).expect("resolve single-quoted target");
    assert_eq!(
        normalize_open_target(&target5).expect("norm"),
        "http://localhost:5173/app"
    );

    let args6 = vec!["\"https://example.com/test?a=1&b=2\"".to_string()];
    let target6 = resolve_open_target(&args6).expect("resolve double-quoted target");
    assert_eq!(
        normalize_open_target(&target6).expect("norm"),
        "https://example.com/test?a=1&b=2"
    );

    // Missing URL or port
    let empty: Vec<String> = vec![];
    assert!(resolve_open_target(&empty).is_err());

    let flags_only = vec!["--flag1".to_string(), "-f".to_string()];
    assert!(resolve_open_target(&flags_only).is_err());

    // Test invoking the cawide CLI binary directly
    let cawide_exe = env!("CARGO_BIN_EXE_cawide");

    // cawide open with no args should fail cleanly with "missing URL or port"
    let output = std::process::Command::new(cawide_exe)
        .arg("open")
        .output()
        .expect("failed to run cawide open");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing URL or port"),
        "Expected 'missing URL or port' in stderr: {stderr}"
    );

    // cawide open with only flags
    let output = std::process::Command::new(cawide_exe)
        .arg("open")
        .arg("-a")
        .arg("-b")
        .output()
        .expect("failed to run cawide open");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing URL or port"),
        "Expected 'missing URL or port' in stderr: {stderr}"
    );

    // cawide open with invalid port
    let output = std::process::Command::new(cawide_exe)
        .arg("open")
        .arg("70000")
        .output()
        .expect("failed to run cawide open");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("port must be 1-65535"),
        "Expected 'port must be 1-65535' in stderr: {stderr}"
    );

    // cawide open with invalid scheme
    let output = std::process::Command::new(cawide_exe)
        .arg("open")
        .arg("ftp://test.com")
        .output()
        .expect("failed to run cawide open");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only http and https URLs can be opened"),
        "Expected error in stderr: {stderr}"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn test_pty_env_shims_injection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_dir = tmp.path();
    let bin_dir = cawide_host::net::shims::ensure_shims(config_dir).expect("ensure_shims");
    let cawide_open_path = bin_dir.join("cawide-open").display().to_string();
    let current_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin_dir.clone()];
    paths.extend(std::env::split_paths(&current_path));
    let prepended_path = std::env::join_paths(paths)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("{}:{}", bin_dir.display(), current_path.to_string_lossy()));
    let env = vec![
        ("PATH".to_string(), prepended_path.clone()),
        ("BROWSER".to_string(), cawide_open_path.clone()),
        ("NPM_CONFIG_BROWSER".to_string(), cawide_open_path.clone()),
        ("CAWIDE_BIN_DIR".to_string(), bin_dir.display().to_string()),
    ];

    let opts = cawide_host::pty::PtySpawnOptions {
        launch_cmd: Some("/bin/sh".to_string()),
        env,
        ..Default::default()
    };

    let session =
        cawide_host::pty::PtySession::spawn(80, 24, opts).expect("failed to spawn PTY session");

    session
        .send_input(
            b"printf 'ENV_TEST:PATH=%s|BROWSER=%s|NPM=%s|BIN=%s\\n' \"$PATH\" \"$BROWSER\" \"$NPM_CONFIG_BROWSER\" \"$CAWIDE_BIN_DIR\"\n",
        )
        .expect("send_input failed");

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    let mut found = false;
    let expected = format!(
        "ENV_TEST:PATH={}|BROWSER={}|NPM={}|BIN={}",
        prepended_path,
        cawide_open_path,
        cawide_open_path,
        bin_dir.display()
    );

    while start.elapsed() < timeout {
        let slice = session.read_slice(0);
        let text = String::from_utf8_lossy(&slice.data);
        if text.contains(&expected) {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let slice = session.read_slice(0);
    let output = String::from_utf8_lossy(&slice.data);
    assert!(
        found,
        "Expected env values not found. Buffer contained:\n{output}"
    );

    let _ = session.send_input(b"exit\n");
}
