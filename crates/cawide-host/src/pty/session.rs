//! Asynchronous, thread-safe PTY session manager with UTF-8 ring buffer persistence and headless vt100 screen tracking.

use crate::pty::error::PtyError;
use crate::pty::output::{AttachStart, SessionOutput, TerminalSignals};
use crate::pty::ring_buffer::SliceResult;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "macos")]
mod libc {
    pub use ::libc::*;
    unsafe extern "C" {
        pub fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: size_t) -> c_int;
    }
}

/// Default capacity for the broadcast channel forwarding PTY output.
pub const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// Configuration options for spawning a new PTY session.
#[derive(Debug, Clone, Default)]
pub struct PtySpawnOptions {
    /// Working directory for the spawned shell or command.
    pub workdir: Option<PathBuf>,
    /// Shell command to execute (e.g., `"claude --resume"` or `"/bin/sh"`).
    pub launch_cmd: Option<String>,
    /// Extra environment variables to inject.
    pub env: Vec<(String, String)>,
}

const INHERITED_TERMINAL_IDENTITY_KEYS: &[&str] = &[
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TERM_SESSION_ID",
    "TERM_FEATURES",
    "LC_TERMINAL",
    "LC_TERMINAL_VERSION",
    "ITERM_SESSION_ID",
    "ITERM_PROFILE",
    "WT_SESSION",
    "WT_PROFILE_ID",
    "VTE_VERSION",
    "KONSOLE_VERSION",
    "TMUX",
    "TMUX_PANE",
    "STY",
    "ZELLIJ",
    "WMUX",
    "PASEO_TERMINAL_ID",
    "TERMINAL_EMULATOR",
    "COLORFGBG",
    "__CFBundleIdentifier",
];
const INHERITED_TERMINAL_IDENTITY_PREFIXES: &[&str] = &[
    "GHOSTTY_",
    "KITTY_",
    "WEZTERM_",
    "ALACRITTY_",
    "VSCODE_",
    "KONSOLE_DBUS_",
    "WARP_",
    "CMUX_",
    "HERDR_",
    "ORCA_",
    "WMUX_",
    "ZELLIJ_",
];
fn is_inherited_terminal_identity(key: &str) -> bool {
    INHERITED_TERMINAL_IDENTITY_KEYS.contains(&key)
        || INHERITED_TERMINAL_IDENTITY_PREFIXES
            .iter()
            .any(|p| key.starts_with(p))
}

/// A thread-safe, detached PTY session running an interactive child process.
///
/// Output is continuously drained in a background blocking task into an in-memory
/// UTF-8 aligned ring buffer and headless vt100 parser, broadcast to active subscribers.
pub struct PtySession {
    master: parking_lot::Mutex<Box<dyn MasterPty + Send>>,
    writer: Arc<parking_lot::Mutex<Box<dyn Write + Send>>>,
    input_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    child: parking_lot::Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
    pid: Option<i32>,
    output: parking_lot::Mutex<SessionOutput>,
    broadcast_tx: tokio::sync::broadcast::Sender<bytes::Bytes>,
    eof_tx: Arc<tokio::sync::watch::Sender<bool>>,
    exit_code: parking_lot::Mutex<Option<i32>>,
}

impl PtySession {
    /// Spawn a new shell or process inside a native pseudo-terminal.
    pub fn spawn(cols: u16, rows: u16, options: PtySpawnOptions) -> Result<Arc<Self>, PtyError> {
        let (Some(cols_nz), Some(rows_nz)) = (NonZeroU16::new(cols), NonZeroU16::new(rows)) else {
            return Err(PtyError::InvalidDimensions(cols, rows));
        };

        let pty_system = native_pty_system();
        let pty_size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = pty_system
            .openpty(pty_size)
            .map_err(|e| PtyError::OpenPty(e.to_string()))?;

        let shell = default_shell();
        let mut cmd = if let Some(launch_cmd) = &options.launch_cmd {
            let parts: Vec<&str> = launch_cmd.split_whitespace().collect();
            if parts.len() == 1 && Path::new(parts[0]).exists() {
                CommandBuilder::new(parts[0])
            } else {
                let mut c = CommandBuilder::new(&shell);
                let shell_lower = shell.to_ascii_lowercase();
                if shell_lower.ends_with("cmd.exe") || shell_lower == "cmd" {
                    c.arg("/c");
                    c.arg(launch_cmd);
                } else if shell_lower.ends_with("powershell.exe")
                    || shell_lower.ends_with("pwsh.exe")
                    || shell_lower == "powershell"
                    || shell_lower == "pwsh"
                {
                    c.arg("-NoLogo");
                    c.arg("-Command");
                    c.arg(launch_cmd);
                } else {
                    c.arg("-c");
                    c.arg(launch_cmd);
                }
                c
            }
        } else {
            let mut c = CommandBuilder::new(&shell);
            let shell_lower = shell.to_ascii_lowercase();
            if shell_lower.ends_with("cmd.exe") || shell_lower == "cmd" {
                c.arg("/k");
            } else if shell_lower.ends_with("powershell.exe")
                || shell_lower.ends_with("pwsh.exe")
                || shell_lower == "powershell"
                || shell_lower == "pwsh"
            {
                c.arg("-NoLogo");
            } else {
                c.arg("-l");
            }
            c
        };

        if let Some(dir) = &options.workdir {
            cmd.cwd(dir);
        }

        // Standard terminal environment
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");

        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(is_inherited_terminal_identity) {
                cmd.env_remove(&key);
            }
        }
        cmd.env("TERM_PROGRAM", "cawide");
        cmd.env("TERM_PROGRAM_VERSION", env!("CARGO_PKG_VERSION"));
        // OMP (pi-tui) only enables Kitty graphics and Unicode placeholders for allowlisted TERM_PROGRAM values.
        cmd.env("PI_FORCE_IMAGE_PROTOCOL", "kitty");
        cmd.env("PI_KITTY_PLACEHOLDERS", "1");
        cmd.env("PI_FORCE_SYNC_OUTPUT", "1");

        for (k, v) in &options.env {
            cmd.env(k, v);
        }

        // Spawn child process
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::SpawnProcess(e.to_string()))?;
        let pid = child.process_id().map(|p| p as i32);
        // Crucial: drop slave PTY handle immediately so reader gets clean EOF when child exits.
        drop(pair.slave);

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::OpenPty(e.to_string()))?;

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::OpenPty(e.to_string()))?;
        let writer = Arc::new(parking_lot::Mutex::new(writer));

        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(128);
        let writer_arc = Arc::clone(&writer);
        tokio::task::spawn_blocking(move || {
            while let Some(chunk) = input_rx.blocking_recv() {
                let mut guard = writer_arc.lock();
                for part in chunk.chunks(512) {
                    if guard.write_all(part).is_err() {
                        return;
                    }
                }
                if guard.flush().is_err() {
                    return;
                }
            }
        });

        let (broadcast_tx, _) = tokio::sync::broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let (eof_tx_raw, _) = tokio::sync::watch::channel(false);
        let eof_tx = Arc::new(eof_tx_raw);

        let session = Arc::new(Self {
            master: parking_lot::Mutex::new(pair.master),
            writer,
            input_tx,
            child: parking_lot::Mutex::new(child),
            pid,
            output: parking_lot::Mutex::new(SessionOutput::new(cols_nz, rows_nz)),
            broadcast_tx: broadcast_tx.clone(),
            eof_tx: Arc::clone(&eof_tx),
            exit_code: parking_lot::Mutex::new(None),
        });
        // Background reader task draining master PTY output
        let session_weak = Arc::downgrade(&session);
        let reader_eof_tx = Arc::clone(&eof_tx);
        tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        tracing::debug!("PTY master reader reached clean EOF");
                        break;
                    }
                    Ok(n) => {
                        let chunk = &buf[..n];
                        if let Some(sess) = session_weak.upgrade() {
                            sess.output.lock().write(chunk);
                            let _ = broadcast_tx.send(bytes::Bytes::copy_from_slice(chunk));
                        } else {
                            // Session was dropped
                            break;
                        }
                    }
                    Err(err) => {
                        #[cfg(unix)]
                        if err.raw_os_error() == Some(libc::EIO) {
                            tracing::debug!("PTY master reader reached EIO (clean exit on Linux)");
                            break;
                        }
                        #[cfg(windows)]
                        if err.kind() == std::io::ErrorKind::BrokenPipe
                            || err.raw_os_error() == Some(109)
                        {
                            tracing::debug!(
                                "PTY master reader reached BrokenPipe (clean exit on Windows ConPTY)"
                            );
                            break;
                        }
                        tracing::debug!("PTY reader exited with error: {err}");
                        break;
                    }
                }
            }
            let start = std::time::Instant::now();
            let mut code = None;
            while start.elapsed() < std::time::Duration::from_millis(2000) {
                if let Some(sess) = session_weak.upgrade() {
                    let mut child = sess.child.lock();
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            code = Some(status.exit_code() as i32);
                            drop(child);
                            break;
                        }
                        Ok(None) => {
                            drop(child);
                        }
                        Err(_) => {
                            drop(child);
                            break;
                        }
                    }
                } else {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if let Some(sess) = session_weak.upgrade() {
                if let Some(c) = code {
                    *sess.exit_code.lock() = Some(c);
                }
            }
            let _ = reader_eof_tx.send_replace(true);
        });

        Ok(session)
    }

    /// Write input bytes directly to the PTY master stdin.
    pub fn send_input(&self, data: &[u8]) -> Result<(), PtyError> {
        let mut writer = self.writer.lock();
        writer.write_all(data).map_err(PtyError::Io)?;
        writer.flush().map_err(PtyError::Io)?;
        Ok(())
    }

    /// Asynchronously write input bytes to the dedicated PTY input queue.
    pub async fn send_input_async(&self, data: bytes::Bytes) -> Result<(), PtyError> {
        self.input_tx.send(data).await.map_err(|_| {
            PtyError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pty input channel closed",
            ))
        })
    }

    /// Resize terminal dimensions.
    ///
    /// Sends `SIGWINCH` automatically to the foreground process group on Unix.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        let (Some(cols_nz), Some(rows_nz)) = (NonZeroU16::new(cols), NonZeroU16::new(rows)) else {
            return Err(PtyError::InvalidDimensions(cols, rows));
        };
        {
            let master = self.master.lock();
            master
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| PtyError::Resize(e.to_string()))?;
        }
        self.output.lock().resize(cols_nz, rows_nz);
        Ok(())
    }

    /// Receiver that flips to `true` once the PTY output reader has terminated (child exited).
    pub fn subscribe_eof(&self) -> tokio::sync::watch::Receiver<bool> {
        self.eof_tx.subscribe()
    }

    /// Current terminal dimensions as `(cols, rows)`.
    pub fn size(&self) -> Result<(u16, u16), PtyError> {
        let size = self
            .master
            .lock()
            .get_size()
            .map_err(|e| PtyError::Resize(e.to_string()))?;
        Ok((size.cols, size.rows))
    }

    /// Subscribe to the live broadcast output stream.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<bytes::Bytes> {
        self.broadcast_tx.subscribe()
    }

    /// Replay a slice from the retained UTF-8 ring buffer.
    pub fn read_slice(&self, from_offset: u64) -> SliceResult {
        self.output.lock().read_slice(from_offset)
    }

    /// Returns either a replay slice or a full headless screen snapshot.
    pub fn attach_start(&self, requested: u64) -> AttachStart {
        self.output.lock().attach_start(requested)
    }

    /// Returns the current terminal input mode flags (ECHO, CANONICAL), if supported.
    pub fn input_mode(&self) -> Option<u8> {
        #[cfg(unix)]
        {
            let fd = self.master.lock().as_raw_fd()?;
            // SAFETY: tcgetattr initializes the termios struct for a valid file descriptor.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            let mut res = unsafe { libc::tcgetattr(fd, &mut t) };
            if res != 0 {
                // Thread-safe fallback for platforms where tcgetattr is supported only on the slave descriptor.
                let mut name_buf = [0 as libc::c_char; 64];
                if unsafe { libc::ptsname_r(fd, name_buf.as_mut_ptr(), name_buf.len()) } == 0 {
                    let slave_fd = unsafe {
                        libc::open(
                            name_buf.as_ptr(),
                            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
                        )
                    };
                    if slave_fd >= 0 {
                        res = unsafe { libc::tcgetattr(slave_fd, &mut t) };
                        unsafe { libc::close(slave_fd) };
                    }
                }
            }
            if res != 0 {
                return None;
            }
            let mut mode = 0u8;
            if t.c_lflag & (libc::ECHO as libc::tcflag_t) != 0 {
                mode |= cawide_protocol::PTY_INPUT_MODE_ECHO;
            }
            if t.c_lflag & (libc::ICANON as libc::tcflag_t) != 0 {
                mode |= cawide_protocol::PTY_INPUT_MODE_CANONICAL;
            }
            Some(mode)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// Check if the child process is still running.
    pub fn is_alive(&self) -> bool {
        if self.exit_code.lock().is_some() {
            return false;
        }
        let mut child = self.child.lock();
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.exit_code() as i32;
                drop(child);
                *self.exit_code.lock() = Some(code);
                false
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Exit code of the child process if it has terminated.
    pub fn exit_code(&self) -> Option<i32> {
        *self.exit_code.lock()
    }

    /// Terminate the child process.
    pub fn kill(&self) -> Result<(), PtyError> {
        let mut child = self.child.lock();
        child.kill().map_err(|e| PtyError::Process(e.to_string()))?;
        Ok(())
    }

    /// Current monotonic head offset in the ring buffer.
    pub fn head_offset(&self) -> u64 {
        self.output.lock().head_offset()
    }

    /// Current monotonic tail offset in the ring buffer.
    pub fn tail_offset(&self) -> u64 {
        self.output.lock().tail_offset()
    }

    pub fn root_pid(&self) -> Option<i32> {
        self.pid
    }

    pub fn foreground_pgid(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            self.master.lock().process_group_leader()
        }
        #[cfg(windows)]
        {
            let root_pid = self.root_pid()?;
            find_active_leaf_child_pid(root_pid as u32)
                .map(|p| p as i32)
                .or(Some(root_pid))
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.root_pid()
        }
    }

    pub fn terminal_signals(&self) -> TerminalSignals {
        self.output.lock().signals()
    }

    pub fn clear_progress(&self) {
        self.output.lock().clear_progress();
    }

    pub fn take_detected_urls(&self) -> Vec<String> {
        self.output.lock().take_detected_urls()
    }
}

fn default_shell() -> String {
    #[cfg(windows)]
    {
        if let Ok(shell) = std::env::var("SHELL") {
            if !shell.trim().is_empty() && Path::new(&shell).exists() {
                return shell;
            }
        }
        // Check PATH for pwsh.exe
        if let Ok(path_val) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_val) {
                let p = dir.join("pwsh.exe");
                if p.is_file() {
                    return p.to_string_lossy().to_string();
                }
            }
        }
        // WindowsPowerShell
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let ps_path = format!("{sys_root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        if Path::new(&ps_path).is_file() {
            return ps_path;
        }
        // Git Bash
        let git_bash = Path::new("C:\\Program Files\\Git\\bin\\bash.exe");
        if git_bash.is_file() {
            return git_bash.to_string_lossy().to_string();
        }
        // COMSPEC or cmd.exe
        if let Ok(comspec) = std::env::var("COMSPEC") {
            if Path::new(&comspec).is_file() {
                return comspec;
            }
        }
        format!("{sys_root}\\System32\\cmd.exe")
    }
    #[cfg(not(windows))]
    {
        if let Ok(shell) = std::env::var("SHELL") {
            if !shell.trim().is_empty() && Path::new(&shell).exists() {
                return shell;
            }
        }
        #[cfg(target_os = "macos")]
        {
            if Path::new("/bin/zsh").exists() {
                return "/bin/zsh".to_string();
            }
        }
        if Path::new("/bin/bash").exists() {
            return "/bin/bash".to_string();
        }
        "/bin/sh".to_string()
    }
}

#[cfg(windows)]
fn find_active_leaf_child_pid(root_pid: u32) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == 0 || snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _guard = HandleGuard(snapshot);

        let mut parent_to_children: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        let mut entry = std::mem::zeroed::<PROCESSENTRY32>();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                parent_to_children
                    .entry(entry.th32ParentProcessID)
                    .or_default()
                    .push(entry.th32ProcessID);
                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        // Traverse down from root_pid to find deepest leaf descendant
        let mut current = root_pid;
        loop {
            if let Some(children) = parent_to_children.get(&current) {
                if let Some(&last_child) = children.last() {
                    current = last_child;
                    continue;
                }
            }
            break;
        }

        if current != root_pid {
            Some(current)
        } else {
            None
        }
    }
}
