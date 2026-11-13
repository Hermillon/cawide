//! Shared hardened process runner.

use std::process::ExitStatus;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub const MAX_STDERR_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct ProcOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stdout_total: usize,
    pub stderr: Vec<u8>,
}

pub struct RunOpts<'a> {
    pub stdin: Option<&'a [u8]>,
    pub stdout_cap: usize,
    pub timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcError {
    #[error("failed to spawn process: {0}")]
    Spawn(String),
    #[error("process timed out")]
    Timeout,
    #[error("process io error: {0}")]
    Io(String),
}

fn prepare_command(cmd: &mut Command) {
    cmd.kill_on_drop(true);
    #[cfg(unix)]
    unsafe {
        cmd.as_std_mut().pre_exec(|| {
            // SAFETY: setsid runs in the child process fork before exec, creating a new session
            // and detaching from any controlling terminal.
            libc::setsid();
            Ok(())
        });
    }
    #[cfg(windows)]
    {
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
}

async fn terminate_process_group(
    mut child: tokio::process::Child,
    #[allow(unused_variables)] pid: Option<i32>,
) -> ProcError {
    #[cfg(unix)]
    if let Some(pid) = pid.filter(|&p| p > 1) {
        // SAFETY: pid was detached via setsid in child pre_exec, forming its own process group.
        unsafe {
            libc::killpg(pid, libc::SIGTERM);
        }
        tokio::select! {
            _ = child.wait() => {}
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                // SAFETY: pid was detached via setsid in child pre_exec, forming its own process group.
                unsafe {
                    libc::killpg(pid, libc::SIGKILL);
                }
                let _ = child.wait().await;
            }
        }
    } else {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    ProcError::Timeout
}

pub async fn read_capped(
    mut reader: impl AsyncRead + Unpin,
    cap: usize,
) -> std::io::Result<(Vec<u8>, usize)> {
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok((kept, total));
        }
        total = total.saturating_add(n);
        let room = cap.saturating_sub(kept.len());
        if room > 0 {
            kept.extend_from_slice(&buf[..n.min(room)]);
        }
    }
}

pub async fn run(mut cmd: Command, opts: RunOpts<'_>) -> Result<ProcOutput, ProcError> {
    cmd.stdin(if opts.stdin.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    })
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    prepare_command(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| ProcError::Spawn(e.to_string()))?;
    let pid = child.id().map(|id| id as i32);

    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(ProcError::Spawn("child stdio unavailable".into()));
    };

    let mut stdin_pipe = child.stdin.take();
    let stdin_fut = async {
        if let (Some(mut pipe), Some(bytes)) = (stdin_pipe.take(), opts.stdin) {
            pipe.write_all(bytes).await?;
            pipe.flush().await?;
            drop(pipe);
        }
        Ok::<(), std::io::Error>(())
    };

    let stdout_fut = read_capped(out, opts.stdout_cap);
    let stderr_fut = read_capped(err, MAX_STDERR_BYTES);

    let runner = async {
        let (fed, stdout_res, stderr_res) = tokio::join!(stdin_fut, stdout_fut, stderr_fut);
        let status = child.wait().await?;
        fed?;
        let (stdout, stdout_total) = stdout_res?;
        let (stderr, _) = stderr_res?;
        Ok::<_, std::io::Error>(ProcOutput {
            status,
            stdout,
            stdout_total,
            stderr,
        })
    };

    match tokio::time::timeout(opts.timeout, Box::pin(runner)).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(ProcError::Io(e.to_string())),
        Err(_) => Err(terminate_process_group(child, pid).await),
    }
}

pub async fn run_records(
    mut cmd: Command,
    stdin: Option<&[u8]>,
    sep: u8,
    timeout: Duration,
    mut on_record: impl FnMut(&[u8]),
) -> Result<ExitStatus, ProcError> {
    cmd.stdin(if stdin.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    })
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    prepare_command(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| ProcError::Spawn(e.to_string()))?;
    let pid = child.id().map(|id| id as i32);

    let (Some(mut out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(ProcError::Spawn("child stdio unavailable".into()));
    };

    let mut stdin_pipe = child.stdin.take();
    let stdin_fut = async {
        if let (Some(mut pipe), Some(bytes)) = (stdin_pipe.take(), stdin) {
            pipe.write_all(bytes).await?;
            pipe.flush().await?;
            drop(pipe);
        }
        Ok::<(), std::io::Error>(())
    };

    let stderr_fut = read_capped(err, MAX_STDERR_BYTES);

    const MAX_RECORD_BYTES: usize = 64 * 1024;

    let stdout_fut = async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = out.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);

            let mut start = 0;
            while let Some(pos) = buf[start..].iter().position(|&b| b == sep) {
                let sep_index = start + pos;
                let rec = &buf[start..sep_index];
                if rec.len() > MAX_RECORD_BYTES {
                    return Err(std::io::Error::other("record exceeded 64 KiB"));
                }
                on_record(rec);
                start = sep_index + 1;
            }
            if start > 0 {
                buf.drain(..start);
            }
            if buf.len() > MAX_RECORD_BYTES {
                return Err(std::io::Error::other("record exceeded 64 KiB"));
            }
        }
        if !buf.is_empty() {
            if buf.len() > MAX_RECORD_BYTES {
                return Err(std::io::Error::other("record exceeded 64 KiB"));
            }
            on_record(&buf);
        }
        Ok::<(), std::io::Error>(())
    };

    let runner = async {
        let (fed, stdout_res, stderr_res) = tokio::join!(stdin_fut, stdout_fut, stderr_fut);
        let status = child.wait().await?;
        fed?;
        stdout_res?;
        stderr_res?;
        Ok::<_, std::io::Error>(status)
    };

    match tokio::time::timeout(timeout, Box::pin(runner)).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => Err(ProcError::Io(e.to_string())),
        Err(_) => Err(terminate_process_group(child, pid).await),
    }
}

pub async fn run_to_writer(
    mut cmd: Command,
    sink: &mut (impl AsyncWrite + Unpin),
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>), ProcError> {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    prepare_command(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| ProcError::Spawn(e.to_string()))?;
    let pid = child.id().map(|id| id as i32);

    let (Some(mut out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(ProcError::Spawn("child stdio unavailable".into()));
    };

    let copy_fut = async {
        tokio::io::copy(&mut out, sink).await?;
        sink.flush().await?;
        Ok::<(), std::io::Error>(())
    };

    let stderr_fut = read_capped(err, MAX_STDERR_BYTES);

    let runner = async {
        let (copy_res, stderr_res) = tokio::join!(copy_fut, stderr_fut);
        let status = child.wait().await?;
        copy_res?;
        let (stderr, _) = stderr_res?;
        Ok::<_, std::io::Error>((status, stderr))
    };

    match tokio::time::timeout(timeout, Box::pin(runner)).await {
        Ok(Ok(tuple)) => Ok(tuple),
        Ok(Err(e)) => Err(ProcError::Io(e.to_string())),
        Err(_) => Err(terminate_process_group(child, pid).await),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn grandchild_killed_on_timeout() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let tmp_path = tmp.path().to_str().expect("tmp path");
        let script = format!("sleep 30 & echo $! > {}; sleep 30", tmp_path);
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&script);

        let start = std::time::Instant::now();
        let res = run(
            cmd,
            RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_millis(200),
            },
        )
        .await;

        assert!(start.elapsed() < Duration::from_secs(2));
        match res {
            Err(ProcError::Timeout) => {}
            other => panic!("expected ProcError::Timeout, got {:?}", other),
        }

        let pid_str = std::fs::read_to_string(tmp_path).expect("read pid");
        let grandchild_pid: i32 = pid_str.trim().parse().expect("parse pid");

        let mut dead = false;
        for _ in 0..20 {
            // SAFETY: Checking liveness with signal 0.
            if unsafe { libc::kill(grandchild_pid, 0) } == -1 {
                dead = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(dead, "grandchild process should be killed");
    }

    #[tokio::test]
    async fn stdout_cap_total_counted() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("printf '%010000d' 0");

        let cap = 256;
        let res = run(
            cmd,
            RunOpts {
                stdin: None,
                stdout_cap: cap,
                timeout: Duration::from_secs(5),
            },
        )
        .await
        .expect("run successful");

        assert!(res.status.success());
        assert_eq!(res.stdout.len(), cap);
        assert_eq!(res.stdout_total, 10000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_session_id_differs() {
        // SAFETY: query session id of current process (test runner).
        let runner_sid = unsafe { libc::getsid(0) };

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo $$; sleep 1");

        let mut recorded_sid = None;
        let mut child_pid_val = None;

        let res = run_records(cmd, None, b'\n', Duration::from_secs(5), |rec| {
            if child_pid_val.is_none() {
                if let Ok(s) = std::str::from_utf8(rec) {
                    if let Ok(pid) = s.trim().parse::<i32>() {
                        child_pid_val = Some(pid);
                        // SAFETY: query session id of child process while it is running.
                        let sid = unsafe { libc::getsid(pid) };
                        recorded_sid = Some(sid);
                    }
                }
            }
        })
        .await
        .expect("run_records successful");

        assert!(res.success());
        let child_pid = child_pid_val.expect("captured child pid");
        let child_sid = recorded_sid.expect("captured child sid");

        assert_ne!(
            child_sid, runner_sid,
            "child session id should differ from runner"
        );
        assert_eq!(child_sid, child_pid, "child should be session leader");
    }

    #[tokio::test]
    async fn run_records_bounded_memory() {
        let mut cmd = Command::new("python3");
        cmd.arg("-c")
            .arg("import sys; sys.stdout.buffer.write(b'a\\0' * 100000)");

        let mut count = 0usize;
        let status = run_records(cmd, None, b'\0', Duration::from_secs(10), |rec| {
            assert_eq!(rec, b"a");
            count += 1;
        })
        .await
        .expect("run_records succeeds");

        assert!(status.success());
        assert_eq!(count, 100_000);
    }

    #[tokio::test]
    async fn run_to_writer_exact_copy() {
        let mut cmd = Command::new("python3");
        cmd.arg("-c")
            .arg("import sys; sys.stdout.buffer.write(b'Z' * (20 * 1024 * 1024))");

        let mut sink = Vec::with_capacity(20 * 1024 * 1024);
        let (status, stderr) = run_to_writer(cmd, &mut sink, Duration::from_secs(15))
            .await
            .expect("run_to_writer succeeds");

        assert!(status.success());
        assert!(stderr.is_empty());
        assert_eq!(sink.len(), 20 * 1024 * 1024);
        assert!(sink.iter().all(|&b| b == b'Z'));
    }

    #[tokio::test]
    async fn core_askpass_neutralized() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).expect("create repo dir");

        let init_out = std::process::Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .expect("git init");
        assert!(init_out.status.success());

        let canary_file = tmp.path().join("canary_file.txt");
        let script_file = tmp.path().join("askpass.sh");
        let script_content = format!(
            "#!/bin/sh\ntouch {}\necho password\n",
            canary_file.display()
        );
        std::fs::write(&script_file, script_content).expect("write askpass script");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_file).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_file, perms).expect("chmod");
        }

        let cfg_out = std::process::Command::new("git")
            .current_dir(&repo_dir)
            .args([
                "config",
                "core.askPass",
                script_file.to_str().expect("script path"),
            ])
            .output()
            .expect("git config");
        assert!(cfg_out.status.success());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local_addr").port();

        let server_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Git\"\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(response).await;
            }
        });

        let engine =
            crate::rpc::git::GitEngine::new(repo_dir, std::sync::Arc::new(Default::default()));
        let ctx = engine.build_request_ctx().await.expect("request ctx");
        let url = format!("http://127.0.0.1:{}/repo.git", port);
        let cmd = engine.git_cmd(&ctx, &["fetch", &url]);
        let _ = run(
            cmd,
            RunOpts {
                stdin: None,
                stdout_cap: 1024,
                timeout: Duration::from_secs(5),
            },
        )
        .await;

        server_task.abort();
        assert!(
            !canary_file.exists(),
            "canary file should not be created by core.askPass"
        );
    }
}
