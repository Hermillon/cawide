//! Cawide daemon lifecycle management, background process control, and log streaming.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::net::{send_ipc_request, IpcRequest, IpcResponse, NetError};

#[derive(Debug, Clone)]
pub struct DaemonPaths {
    pub config_dir: PathBuf,
    pub socket_path: PathBuf,
    pub pid_path: PathBuf,
    pub log_dir: PathBuf,
    pub log_file: PathBuf,
}

impl DaemonPaths {
    pub fn from_config_dir(config_dir: PathBuf) -> Self {
        let socket_path = crate::net::default_ipc_path(&config_dir);
        let pid_path = config_dir.join("cawide.pid");
        let log_dir = config_dir.join("logs");
        let log_file = log_dir.join("cawide.log");
        Self {
            config_dir,
            socket_path,
            pid_path,
            log_dir,
            log_file,
        }
    }
}

/// Checks if the daemon is currently running.
///
/// Returns `Ok(Some(pid))` if active, `Ok(None)` if not running (cleaning stale files).
pub async fn check_daemon_status(paths: &DaemonPaths) -> Result<Option<u32>> {
    match send_ipc_request(&paths.socket_path, &IpcRequest::Status).await {
        Ok(IpcResponse::Status { .. }) => {
            let pid = if paths.pid_path.exists() {
                match std::fs::read_to_string(&paths.pid_path) {
                    Ok(s) => s.trim().parse::<u32>().ok(),
                    Err(_) => None,
                }
            } else {
                None
            };
            Ok(Some(pid.unwrap_or(0)))
        }
        Ok(_) => Ok(None),
        Err(e) => {
            let is_stale = match &e {
                NetError::DaemonNotRunning(_) => true,
                NetError::Io(io_err) => matches!(
                    io_err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ),
                _ => false,
            };
            if is_stale {
                #[cfg(unix)]
                if paths.socket_path.exists() {
                    let _ = std::fs::remove_file(&paths.socket_path);
                }
                if paths.pid_path.exists() {
                    let _ = std::fs::remove_file(&paths.pid_path);
                }
                Ok(None)
            } else {
                // If there was an error communicating with socket, verify if PID file process is alive
                if paths.pid_path.exists() {
                    if let Ok(s) = std::fs::read_to_string(&paths.pid_path) {
                        if let Ok(pid) = s.trim().parse::<u32>() {
                            if pid > 0 {
                                #[cfg(unix)]
                                let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
                                #[cfg(windows)]
                                let alive = {
                                    use windows_sys::Win32::Foundation::{
                                        CloseHandle, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
                                    };
                                    use windows_sys::Win32::System::Threading::{
                                        OpenProcess, WaitForSingleObject,
                                        PROCESS_QUERY_LIMITED_INFORMATION,
                                    };
                                    unsafe {
                                        let h =
                                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                                        if h != 0 && h != INVALID_HANDLE_VALUE {
                                            let res = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
                                            CloseHandle(h);
                                            res
                                        } else {
                                            false
                                        }
                                    }
                                };
                                #[cfg(not(any(unix, windows)))]
                                let alive = false;

                                if alive {
                                    return Ok(Some(pid));
                                }
                            }
                        }
                    }
                    let _ = std::fs::remove_file(&paths.pid_path);
                    #[cfg(unix)]
                    if paths.socket_path.exists() {
                        let _ = std::fs::remove_file(&paths.socket_path);
                    }
                }
                Ok(None)
            }
        }
    }
}

/// Starts the cawide daemon as a background detached process.
///
/// If already running, returns the existing PID without spawning a duplicate.
pub async fn start_background(paths: &DaemonPaths, pass_args: &[String]) -> Result<u32> {
    if let Some(pid) = check_daemon_status(paths).await? {
        return Ok(pid);
    }

    if !paths.log_dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&paths.log_dir)?;
    } else {
        #[cfg(unix)]
        std::fs::set_permissions(&paths.log_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let mut log_opts = OpenOptions::new();
    log_opts.create(true).append(true);
    #[cfg(unix)]
    log_opts.mode(0o600);
    let log_file = log_opts
        .open(&paths.log_file)
        .with_context(|| format!("Failed to open log file at {}", paths.log_file.display()))?;

    let current_exe = std::env::current_exe()?;
    let mut cmd = Command::new(current_exe);
    cmd.arg("serve");
    cmd.arg("--foreground");
    cmd.arg("--no-pair");
    for arg in pass_args {
        if arg != "serve" && arg != "--foreground" && arg != "-f" && arg != "--no-pair" {
            cmd.arg(arg);
        }
    }
    cmd.env("CAWIDE_CONFIG_DIR", &paths.config_dir);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log_file.try_clone()?));
    cmd.stderr(Stdio::from(log_file));

    #[cfg(unix)]
    // SAFETY: setsid detaches the child from the controlling terminal in unix fork.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().context("Failed to spawn background daemon")?;

    let mut started = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        match child.try_wait() {
            Ok(Some(status)) => {
                let last_logs = read_last_lines(&paths.log_file, 15).unwrap_or_default();
                bail!(
                    "Daemon process exited prematurely with status {status}.\nRecent logs:\n{last_logs}"
                );
            }
            Ok(None) => {}
            Err(e) => {
                bail!("Error polling daemon process: {e}");
            }
        }

        #[cfg(unix)]
        let socket_ready = paths.socket_path.exists();
        #[cfg(not(unix))]
        let socket_ready = true;

        if socket_ready {
            if let Ok(IpcResponse::Status { .. }) =
                send_ipc_request(&paths.socket_path, &IpcRequest::Status).await
            {
                started = true;
                break;
            }
        }
    }

    if !started {
        let last_logs = read_last_lines(&paths.log_file, 15).unwrap_or_default();
        bail!(
            "Timed out waiting for cawide daemon to start after 5 seconds.\nRecent logs:\n{last_logs}"
        );
    }

    let child_pid = child.id();
    if !paths.pid_path.exists() {
        let mut pid_opts = OpenOptions::new();
        pid_opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        pid_opts.mode(0o600);
        if let Ok(mut pid_file) = pid_opts.open(&paths.pid_path) {
            let _ = writeln!(pid_file, "{child_pid}");
            let _ = pid_file.flush();
        }
    }
    Ok(child_pid)
}

/// Stops the running daemon gracefully via IPC, falling back to SIGTERM if necessary.
pub async fn stop_daemon(paths: &DaemonPaths) -> Result<()> {
    let pid_opt = check_daemon_status(paths).await?;
    let Some(pid) = pid_opt else {
        println!("No cawide daemon is currently running.");
        #[cfg(unix)]
        if paths.socket_path.exists() {
            let _ = std::fs::remove_file(&paths.socket_path);
        }
        if paths.pid_path.exists() {
            let _ = std::fs::remove_file(&paths.pid_path);
        }
        return Ok(());
    };

    let _ = send_ipc_request(&paths.socket_path, &IpcRequest::Stop).await;

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut stopped = false;
    while Instant::now() < deadline {
        #[cfg(unix)]
        let socket_gone = !paths.socket_path.exists();
        #[cfg(not(unix))]
        let socket_gone = true;

        if socket_gone && !paths.pid_path.exists() {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if !stopped && pid > 0 {
        #[cfg(unix)]
        // SAFETY: SIGTERM to terminate unresponsive process after timeout.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };
            unsafe {
                let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if h != 0 && h != INVALID_HANDLE_VALUE {
                    TerminateProcess(h, 1);
                    CloseHandle(h);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    #[cfg(unix)]
    if paths.socket_path.exists() {
        let _ = std::fs::remove_file(&paths.socket_path);
    }
    if paths.pid_path.exists() {
        let _ = std::fs::remove_file(&paths.pid_path);
    }

    println!("Cawide daemon stopped.");
    Ok(())
}

/// Reads the last `count` lines of a file.
pub fn read_last_lines(path: &Path, count: usize) -> Result<String> {
    if !path.exists() || count == 0 {
        return Ok(String::new());
    }
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let file_len = metadata.len();
    if file_len == 0 {
        return Ok(String::new());
    }

    let read_size = file_len.min(64 * 1024) as usize;
    let seek_pos = file_len.saturating_sub(read_size as u64);
    file.seek(SeekFrom::Start(seek_pos))?;
    let mut buf = vec![0u8; read_size];
    file.read_exact(&mut buf)?;

    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    if seek_pos > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    if lines.len() > count {
        lines = lines.split_off(lines.len() - count);
    }
    Ok(lines.join("\n"))
}

/// Prints recent log lines and optionally follows log output in real time.
pub async fn stream_logs(log_path: &Path, follow: bool, lines: usize) -> Result<()> {
    if !log_path.exists() {
        if !follow {
            println!("No log file found at {}", log_path.display());
            return Ok(());
        }
        println!("Waiting for log file at {}...", log_path.display());
        while !log_path.exists() {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    }

    let initial_content = read_last_lines(log_path, lines)?;
    if !initial_content.is_empty() {
        println!("{initial_content}");
    }

    if !follow {
        return Ok(());
    }

    let mut file = std::fs::File::open(log_path)?;
    file.seek(SeekFrom::End(0))?;

    let mut stdout = std::io::stdout();
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if let Ok(meta) = file.metadata() {
                    let current_pos = file.stream_position().unwrap_or(0);
                    if meta.len() < current_pos {
                        let _ = file.seek(SeekFrom::Start(0));
                    }
                }
                loop {
                    match file.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = stdout.write_all(&buf[..n]);
                            let _ = stdout.flush();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_daemon_paths() {
        let dir = PathBuf::from("/tmp/test-cawide");
        let paths = DaemonPaths::from_config_dir(dir.clone());
        assert_eq!(paths.config_dir, dir);
        assert_eq!(paths.socket_path, dir.join("cawide.sock"));
        assert_eq!(paths.pid_path, dir.join("cawide.pid"));
        assert_eq!(paths.log_dir, dir.join("logs"));
        assert_eq!(paths.log_file, dir.join("logs/cawide.log"));
    }

    #[test]
    fn test_read_last_lines() {
        let temp = tempdir().unwrap();
        let log_file = temp.path().join("test.log");

        // Non-existent
        assert_eq!(read_last_lines(&log_file, 5).unwrap(), "");

        // Empty
        std::fs::write(&log_file, "").unwrap();
        assert_eq!(read_last_lines(&log_file, 5).unwrap(), "");

        // Multiple lines
        let content = "line 1\nline 2\nline 3\nline 4\nline 5\n";
        std::fs::write(&log_file, content).unwrap();
        assert_eq!(
            read_last_lines(&log_file, 3).unwrap(),
            "line 3\nline 4\nline 5"
        );
        assert_eq!(
            read_last_lines(&log_file, 10).unwrap(),
            "line 1\nline 2\nline 3\nline 4\nline 5"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_check_daemon_status_cleans_stale_files() {
        let temp = tempdir().unwrap();
        let paths = DaemonPaths::from_config_dir(temp.path().to_path_buf());

        // Create a stale socket (Unix domain socket listener that immediately closes)
        {
            let listener = std::os::unix::net::UnixListener::bind(&paths.socket_path).unwrap();
            drop(listener);
        }
        // Create a stale pid file with a dead PID (e.g. 99999999)
        std::fs::write(&paths.pid_path, "99999999\n").unwrap();

        assert!(paths.socket_path.exists());
        assert!(paths.pid_path.exists());

        let status = check_daemon_status(&paths).await.unwrap();
        assert_eq!(status, None);
        assert!(!paths.socket_path.exists());
        assert!(!paths.pid_path.exists());
    }

    #[tokio::test]
    async fn test_stop_daemon_when_not_running() {
        let temp = tempdir().unwrap();
        let paths = DaemonPaths::from_config_dir(temp.path().to_path_buf());
        let res = stop_daemon(&paths).await;
        assert!(res.is_ok());
    }
}
