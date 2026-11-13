//! `cawide` — host daemon CLI.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use cawide_host::daemon::{
    check_daemon_status, start_background, stop_daemon, stream_logs, DaemonPaths,
};
use cawide_host::net::{
    filter_direct_addrs, send_ipc_request, CawideServer, CawideServerConfig, IpcRequest,
    IpcResponse, NetworkMode,
};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cawide", version, about = "Cawide host daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct ServeArgs {
    /// Run in foreground instead of detaching as a daemon
    #[arg(short, long)]
    pub foreground: bool,
    /// Disable relays and discovery; use direct addresses only
    #[arg(long)]
    pub local_only: bool,
    /// Working directory for spawned sessions (default: $HOME)
    #[arg(long)]
    pub workdir: Option<PathBuf>,
    /// Command to run in new sessions (default: login shell)
    #[arg(long = "command")]
    pub command: Option<String>,
    /// Directory for files uploaded from devices (default: $HOME/.cache/cawide/uploads)
    #[arg(long)]
    pub upload_dir: Option<PathBuf>,
    /// Do not open a pairing window at startup
    #[arg(long)]
    pub no_pair: bool,
    /// Deterministic UDP port to bind for Iroh QUIC transport
    #[arg(long)]
    pub port: Option<u16>,
    /// Public external address to advertise in Iroh node info
    #[arg(long)]
    pub external_addr: Option<std::net::SocketAddr>,
    /// Custom relay URL to override the default relay map
    #[arg(long)]
    pub relay_url: Option<String>,
}

impl ServeArgs {
    pub fn to_pass_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.local_only {
            args.push("--local-only".into());
        }
        if let Some(w) = &self.workdir {
            args.push("--workdir".into());
            args.push(w.to_string_lossy().into_owned());
        }
        if let Some(c) = &self.command {
            args.push("--command".into());
            args.push(c.clone());
        }
        if let Some(u) = &self.upload_dir {
            args.push("--upload-dir".into());
            args.push(u.to_string_lossy().into_owned());
        }
        if self.no_pair {
            args.push("--no-pair".into());
        }
        if let Some(p) = self.port {
            args.push("--port".into());
            args.push(p.to_string());
        }
        if let Some(a) = &self.external_addr {
            args.push("--external-addr".into());
            args.push(a.to_string());
        }
        if let Some(r) = &self.relay_url {
            args.push("--relay-url".into());
            args.push(r.clone());
        }
        args
    }
}

#[derive(Subcommand)]
enum Command {
    /// Start or run the host daemon (defaults to background unless --foreground/-f)
    Serve(ServeArgs),
    /// Start the host daemon in background
    Start(ServeArgs),
    /// Restart the daemon
    Restart(ServeArgs),
    /// Stop or quit the running daemon
    #[command(alias = "quit")]
    Stop,
    /// Check for updates and upgrade to the latest version
    Update,
    /// View daemon logs
    #[command(alias = "log")]
    Logs {
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
        /// Number of lines to show (default: 50)
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
    /// Issue a fresh pairing QR from the running daemon
    Pair,
    /// Show daemon status
    Status {
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Run an agent integration hook
    Hook {
        agent: String,
        #[arg(long)]
        event: Option<String>,
        payload: Option<String>,
    },
    /// Configure shell hooks for an agent
    Setup {
        agent: String,
        #[arg(long)]
        remove: bool,
    },
    /// List authorized devices
    Devices,
    /// Revoke an authorized device
    Revoke { selector: String },
    /// Open a URL or port in the Cawide browser on your phone (e.g. cawide open 5173)
    Open {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Link this computer to your Cawide account
    Login,
    /// Unlink this computer from your Cawide account
    Logout,
    /// Sync your AI agent setup to Cawide Cloud
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    #[command(hide = true)]
    GitCredential {
        action: String,
        #[arg(long)]
        config_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// Upload your Claude Code, Codex, OMP and OpenCode setup
    Push {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, requires = "dry_run")]
        output: Option<PathBuf>,
    },
    /// Show the uploaded profile
    Status,
    /// Delete the uploaded profile
    Delete,
    /// Install a downloaded profile on this machine (used by Cawide Cloud)
    Apply {
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

fn home_dir() -> Result<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    #[cfg(windows)]
    {
        if let Some(userprofile) = std::env::var_os("USERPROFILE") {
            if !userprofile.is_empty() {
                return Ok(PathBuf::from(userprofile));
            }
        }
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let combined = format!("{}{}", drive.to_string_lossy(), path.to_string_lossy());
            if !combined.is_empty() {
                return Ok(PathBuf::from(combined));
            }
        }
    }
    bail!("HOME is not set; set CAWIDE_CONFIG_DIR")
}

fn config_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("CAWIDE_CONFIG_DIR") {
        if !d.is_empty() {
            return Ok(PathBuf::from(d));
        }
    }
    #[cfg(windows)]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            if !local_app_data.is_empty() {
                return Ok(PathBuf::from(local_app_data).join("cawide"));
            }
        }
        let legacy = home_dir()?.join(".config\\cawide");
        if legacy.exists() {
            return Ok(legacy);
        }
    }
    Ok(home_dir()?.join(".config/cawide"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(Command::Hook {
        agent,
        event,
        payload,
    }) = &cli.command
    {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            rt.block_on(cawide_host::agent::hook::run_hook(
                agent,
                event.as_deref(),
                payload.as_deref(),
            ));
        }
        std::process::exit(0);
    }
    if let Some(Command::GitCredential { action, config_dir }) = &cli.command {
        cawide_host::forge::helper::run_git_credential(action, config_dir.clone());
        std::process::exit(0);
    }

    let is_foreground_worker = match &cli.command {
        Some(Command::Serve(args)) | Some(Command::Start(args)) => args.foreground,
        _ => false,
    };

    let default_filter = if is_foreground_worker { "info" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    tokio::runtime::Runtime::new()?.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Hook { .. }) | Some(Command::GitCredential { .. }) => unreachable!(),
        Some(Command::Setup { agent, remove }) => {
            let summary = cawide_host::agent::setup::run_setup(
                &home_dir()?,
                &std::env::current_exe()?,
                &agent,
                remove,
            )?;
            println!("{summary}");
        }
        Some(Command::Devices) => {
            let config_dir = config_dir()?;
            cawide_host::devices::cli_devices(&config_dir).await?;
        }
        Some(Command::Revoke { selector }) => {
            let config_dir = config_dir()?;
            cawide_host::devices::cli_revoke(&config_dir, &selector).await?;
        }
        Some(Command::Start(args)) | Some(Command::Serve(args)) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            if args.foreground {
                if let Some(pid) = check_daemon_status(&paths).await? {
                    bail!(
                        "Cawide daemon is already running (PID: {pid}). Stop it with 'cawide stop' first."
                    );
                }
                run_serve_foreground(args).await?;
            } else {
                if let Some(pid) = check_daemon_status(&paths).await? {
                    println!("Cawide daemon is already running (PID: {pid}).");
                    if !args.no_pair {
                        show_pair(&paths, Some(pid)).await?;
                    } else {
                        show_status(&paths, Some(pid)).await?;
                    }
                } else {
                    let pass_args = args.to_pass_args();
                    let pid = start_background(&paths, &pass_args).await?;
                    if !args.no_pair {
                        show_pair(&paths, Some(pid)).await?;
                    } else {
                        println!("Cawide daemon started in background (PID: {pid}).");
                    }
                }
            }
        }
        Some(Command::Restart(args)) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            stop_daemon(&paths).await?;
            if args.foreground {
                run_serve_foreground(args).await?;
            } else {
                let pass_args = args.to_pass_args();
                let pid = start_background(&paths, &pass_args).await?;
                if !args.no_pair {
                    show_pair(&paths, Some(pid)).await?;
                } else {
                    println!("Cawide daemon started in background (PID: {pid}).");
                }
            }
        }
        Some(Command::Stop) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            stop_daemon(&paths).await?;
        }
        Some(Command::Update) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            run_update(&paths).await?;
        }
        Some(Command::Logs { follow, lines }) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            stream_logs(&paths.log_file, follow, lines).await?;
        }
        Some(Command::Pair) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            let pid = match check_daemon_status(&paths).await? {
                Some(p) => Some(p),
                None => {
                    let p = start_background(&paths, &[]).await?;
                    Some(p)
                }
            };
            show_pair(&paths, pid).await?;
        }
        Some(Command::Status { json }) => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            match check_daemon_status(&paths).await? {
                Some(pid) => {
                    if json {
                        match send_ipc_request(&paths.socket_path, &IpcRequest::Status).await? {
                            IpcResponse::Status {
                                node_id,
                                active_sessions,
                                active_connections,
                                authorized_keys,
                                pairing_active,
                                last_input_unix,
                            } => {
                                let payload = serde_json::json!({
                                    "node_id": node_id,
                                    "active_sessions": active_sessions,
                                    "active_connections": active_connections,
                                    "authorized_keys": authorized_keys,
                                    "pairing_active": pairing_active,
                                    "last_input_unix": last_input_unix,
                                });
                                println!("{payload}");
                            }
                            other => bail!("unexpected ipc response: {other:?}"),
                        }
                    } else {
                        show_status(&paths, Some(pid)).await?;
                    }
                }
                None => {
                    if json {
                        eprintln!("Cawide daemon is not running.");
                        std::process::exit(1);
                    } else {
                        println!("Cawide daemon is not running. Run 'cawide start' to start.");
                    }
                }
            }
        }
        Some(Command::Open { args }) => {
            let socket = match std::env::var_os("CAWIDE_SOCKET") {
                Some(s) if !s.is_empty() => PathBuf::from(s),
                _ => cawide_host::net::default_ipc_path(&config_dir()?),
            };
            let session_id = std::env::var("CAWIDE_SESSION_ID").ok();
            let target =
                cawide_host::web::resolve_open_target(&args).map_err(|e| anyhow::anyhow!("{e}"))?;
            let normalized = match cawide_host::web::normalize_open_target(&target) {
                Ok(url) => url,
                Err(e) => bail!("{e}"),
            };
            match send_ipc_request(
                &socket,
                &IpcRequest::OpenUrl {
                    url: normalized.clone(),
                    session_id,
                },
            )
            .await?
            {
                IpcResponse::Ok => println!("Opened {normalized} on your phone."),
                IpcResponse::Error(m) => bail!("{m}"),
                _ => bail!("unexpected response"),
            }
        }
        Some(Command::Login) => {
            let dir = config_dir()?;
            cawide_host::cloud::login::run_login(&dir).await?;
            println!("Copying your agent setup to Cawide Cloud...");
            if let Err(err) = cawide_host::profile::commands::run_push(&dir, false, None).await {
                eprintln!("could not copy your agent setup: {err:#}");
                eprintln!("Run `cawide profile push` to try again.");
            }
        }
        Some(Command::Logout) => {
            cawide_host::cloud::login::run_logout(&config_dir()?).await?;
        }
        Some(Command::Profile { command }) => match command {
            ProfileCommand::Push { dry_run, output } => {
                cawide_host::profile::commands::run_push(&config_dir()?, dry_run, output).await?;
            }
            ProfileCommand::Status => {
                cawide_host::profile::commands::run_status(&config_dir()?).await?;
            }
            ProfileCommand::Delete => {
                cawide_host::profile::commands::run_delete(&config_dir()?).await?;
            }
            ProfileCommand::Apply { file } => {
                let home = home_dir()?;
                let cfg = config_dir()?;
                cawide_host::profile::commands::run_apply(&home, &cfg, file)?;
            }
        },
        None => {
            let paths = DaemonPaths::from_config_dir(config_dir()?);
            if let Some(pid) = check_daemon_status(&paths).await? {
                show_status(&paths, Some(pid)).await?;
            } else {
                let pid = start_background(&paths, &[]).await?;
                show_pair(&paths, Some(pid)).await?;
            }
        }
    }
    Ok(())
}

async fn show_status(paths: &DaemonPaths, pid: Option<u32>) -> Result<()> {
    match send_ipc_request(&paths.socket_path, &IpcRequest::Status).await? {
        IpcResponse::Status {
            node_id,
            active_sessions,
            active_connections,
            authorized_keys,
            pairing_active,
            ..
        } => {
            println!(
                "{}",
                cawide_host::ui::render_status_card(
                    &node_id,
                    pid,
                    active_sessions,
                    active_connections,
                    authorized_keys,
                    pairing_active,
                    &paths.log_file,
                )
            );
        }
        IpcResponse::Error(e) => bail!(e),
        _ => bail!("unexpected response from daemon"),
    }
    if let Some(latest) = cawide_host::update::check_for_update_cached(&paths.config_dir) {
        let current = env!("CARGO_PKG_VERSION");
        println!();
        println!(
            "{}",
            cawide_host::ui::render_update_notice(
                current,
                &latest,
                cawide_host::ui::is_color_enabled()
            )
        );
    }
    Ok(())
}

async fn show_pair(paths: &DaemonPaths, pid: Option<u32>) -> Result<()> {
    match send_ipc_request(&paths.socket_path, &IpcRequest::Pair).await? {
        IpcResponse::PairTicket {
            uri,
            qr_text,
            expires_in_secs,
        } => {
            let node_id = match send_ipc_request(&paths.socket_path, &IpcRequest::Status).await {
                Ok(IpcResponse::Status { node_id, .. }) => node_id,
                _ => String::new(),
            };
            println!(
                "{}",
                cawide_host::ui::render_pairing_screen(
                    &uri,
                    &qr_text,
                    expires_in_secs,
                    &node_id,
                    pid,
                )
            );
        }
        IpcResponse::Error(e) => bail!(e),
        _ => bail!("unexpected response from daemon"),
    }
    if let Some(latest) = cawide_host::update::check_for_update_cached(&paths.config_dir) {
        let current = env!("CARGO_PKG_VERSION");
        println!();
        println!(
            "{}",
            cawide_host::ui::render_update_notice(
                current,
                &latest,
                cawide_host::ui::is_color_enabled()
            )
        );
    }
    Ok(())
}
async fn run_update(paths: &DaemonPaths) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("Checking for updates...");

    let latest =
        match cawide_host::update::fetch_latest_version(std::time::Duration::from_secs(5)).await {
            Ok(v) => v,
            Err(e) => {
                bail!("Failed to check for updates from npm registry: {e}");
            }
        };

    if !cawide_host::update::is_newer_version(current, &latest) {
        println!("✔ Cawide is already up to date (v{current}).");
        return Ok(());
    }

    println!("Updating Cawide from v{current} to v{latest}...");

    let npm_bin = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let npm_check = std::process::Command::new(npm_bin)
        .arg("--version")
        .output();

    let success = match npm_check {
        Ok(out) if out.status.success() => {
            println!("==> Running: {npm_bin} install -g cawide@latest");
            let mut child = std::process::Command::new(npm_bin)
                .args(["install", "-g", "cawide@latest"])
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()?;
            let status = child.wait()?;
            status.success()
        }
        _ => {
            println!("npm was not found in PATH.");
            println!("To update manually, install via npm: npm install -g cawide@latest");
            println!("Or download the latest release from: https://github.com/Hermillon/cawide/releases/tag/v{latest}");
            return Ok(());
        }
    };

    if !success {
        bail!("npm install failed. Please run 'npm install -g cawide@latest' manually.");
    }

    if let Some(_pid) = check_daemon_status(paths).await? {
        println!("Reloading background daemon...");
        stop_daemon(paths).await?;
        let new_pid = start_background(paths, &[]).await?;
        println!("✔ Background daemon reloaded (PID: {new_pid}).");
    }

    println!("✔ Successfully updated Cawide to v{latest}!");
    Ok(())
}

async fn run_serve_foreground(args: ServeArgs) -> Result<()> {
    #[cfg(unix)]
    // SAFETY: Ignore SIGHUP so terminal/tab closure never terminates the daemon.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let _power_guard = cawide_host::power::prevent_idle_sleep("cawide remote host daemon");
    let config_dir = config_dir()?;
    let paths = DaemonPaths::from_config_dir(config_dir.clone());
    let workdir = match args.workdir {
        Some(w) => w,
        None => home_dir()?,
    };
    let watch_workspace = true;

    let server = CawideServer::bind(CawideServerConfig {
        config_dir,
        network_mode: if args.local_only {
            NetworkMode::LocalOnly
        } else {
            NetworkMode::N0
        },
        workdir,
        launch_cmd: args.command,
        upload_dir: args.upload_dir,
        opener: None,
        watch_workspace,
        port: args.port,
        external_addr: args.external_addr,
        relay_url: args.relay_url,
        forge: default_forge_config(),
        git_env: Vec::new(),
    })
    .await
    .context("failed to start daemon")?;

    // Write pid file for status inspection
    let _ = std::fs::write(&paths.pid_path, format!("{}\n", std::process::id()));

    tracing::info!(
        node_id = %hex::encode(server.node_id()),
        "cawide listening"
    );
    let _lan = cawide_host::net::lan_advertise::LanAdvertiser::start(
        server.endpoint().clone(),
        cawide_host::net::dispatcher::host_display_name(),
    );

    if !args.no_pair {
        let relay = server
            .endpoint()
            .addr()
            .relay_urls()
            .next()
            .map(|u| u.to_string());
        let direct_addrs = filter_direct_addrs(server.endpoint().addr().ip_addrs().copied());
        let ticket =
            server
                .pairing_manager()
                .start_pairing(server.node_id(), relay, direct_addrs)?;
        let qr_text = ticket.render_terminal_qr()?;
        let uri = ticket.to_uri();
        let expires_in_secs = ticket
            .expires_at
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        let node_id = hex::encode(server.node_id());
        println!(
            "{}",
            cawide_host::ui::render_pairing_screen(
                &uri,
                &qr_text,
                expires_in_secs,
                &node_id,
                Some(std::process::id()),
            )
        );
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = server.wait_for_stop_request() => {}
    }
    server.shutdown().await?;
    let _ = std::fs::remove_file(&paths.pid_path);
    Ok(())
}

fn default_forge_config() -> cawide_host::forge::ForgeHostConfig {
    let mut client_ids = std::collections::HashMap::new();
    let gh_id = std::env::var("CAWIDE_GITHUB_OAUTH_CLIENT_ID")
        .ok()
        .or_else(|| option_env!("CAWIDE_GITHUB_OAUTH_CLIENT_ID").map(str::to_string))
        .unwrap_or_default();
    if !gh_id.trim().is_empty() {
        client_ids.insert("github.com".to_string(), gh_id.trim().to_string());
    }
    let gl_id = std::env::var("CAWIDE_GITLAB_OAUTH_CLIENT_ID")
        .ok()
        .or_else(|| option_env!("CAWIDE_GITLAB_OAUTH_CLIENT_ID").map(str::to_string))
        .unwrap_or_default();
    if !gl_id.trim().is_empty() {
        client_ids.insert("gitlab.com".to_string(), gl_id.trim().to_string());
    }

    cawide_host::forge::ForgeHostConfig {
        client_ids,
        helper_exe: None,
        endpoint_overrides: std::collections::HashMap::new(),
        cli_search_path: None,
    }
}
