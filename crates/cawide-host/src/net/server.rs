//! Server engine wiring identity, gate, handlers, and IPC together.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, VarInt};
use iroh::protocol::Router;

use crate::auth::{AuthorizedKeysStore, PairingManager};
use crate::cloud::client::{CloudClient, CloudConfig};
use crate::cloud::trust_sync::{AccountClaimer, TrustKick, TrustSync};
use crate::net::broadcaster::HostEventBroadcaster;
use crate::net::connections::ConnectionTracker;
use crate::net::dispatcher::{
    host_display_name, CawidePairingHandler, CawideProtocolHandler, LegacyAlpnHandler,
};
use crate::net::error::NetError;
use crate::net::hooks::CawideEndpointHooks;
use crate::net::identity::load_or_create_host_key;
use crate::net::ipc::{bind_ipc_listener, serve_ipc, IpcContext};
use crate::net::probe::SessionProbe;
use crate::net::registry::SessionRegistry;
use crate::ports::watch::PortWatcher;
use crate::rpc::{FsEngine, OpenerHook};
use crate::watch::RootWatchers;
use cawide_protocol::{ALPN_CAWIDE, ALPN_CAWIDE_LEGACY, ALPN_CAWIDE_PAIR};

/// Host events buffered per Control stream before a slow client lags.
const HOST_EVENT_CAPACITY: usize = 64;

/// `$HOME/.cache/cawide/uploads`. Never a shared temp dir, where another local
/// user could pre-create the path.
fn default_upload_dir() -> Result<PathBuf, NetError> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".cache/cawide/uploads"))
        .ok_or(NetError::UploadDirUnavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// n0 relays + DNS discovery (production).
    N0,
    /// No relay/discovery; direct addresses only (tests, LAN smoke).
    LocalOnly,
}

pub struct CawideServerConfig {
    /// Holds `host_key`, `authorized_keys`, `cawide.sock`.
    pub config_dir: PathBuf,
    pub network_mode: NetworkMode,
    /// Working directory for spawned PTYs.
    pub workdir: PathBuf,
    /// `None` = login shell.
    pub launch_cmd: Option<String>,
    /// Where `FsUpload` stores files. `None` = `$HOME/.cache/cawide/uploads`.
    pub upload_dir: Option<PathBuf>,
    /// `RemoteOpen` launcher. `None` = system default handler (`opener::open`).
    pub opener: Option<OpenerHook>,
    /// Whether to start workspace filesystem watcher.
    pub watch_workspace: bool,
    /// Deterministic UDP port to bind for Iroh QUIC transport.
    pub port: Option<u16>,
    /// Public external address to advertise in Iroh node info.
    pub external_addr: Option<std::net::SocketAddr>,
    /// Custom relay URL to override the default relay map.
    pub relay_url: Option<String>,
    pub forge: crate::forge::ForgeHostConfig,
    pub git_env: Vec<(String, String)>,
}

pub struct CawideServer {
    router: Router,
    registry: Arc<SessionRegistry>,
    auth_store: Arc<AuthorizedKeysStore>,
    pairing_manager: Arc<PairingManager>,
    connections: Arc<ConnectionTracker>,
    broadcaster: Arc<HostEventBroadcaster>,
    _probe: SessionProbe,
    _observers: Option<crate::agent::observe::ObserverHub>,
    _ports: PortWatcher,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    ipc_task: tokio::task::JoinHandle<()>,
    trust_task: Option<tokio::task::JoinHandle<()>>,
    socket_path: PathBuf,
}

impl CawideServer {
    pub async fn bind(config: CawideServerConfig) -> Result<Self, NetError> {
        let socket_path = crate::net::ipc::default_ipc_path(&config.config_dir);

        // IPC first so a second daemon fails fast before touching the network.
        let listener = bind_ipc_listener(&socket_path)?;

        match Self::bind_inner(config, listener, socket_path.clone()).await {
            Ok(server) => Ok(server),
            Err(e) => {
                #[cfg(unix)]
                let _ = std::fs::remove_file(&socket_path);
                Err(e)
            }
        }
    }

    async fn bind_inner(
        config: CawideServerConfig,
        listener: crate::net::ipc::IpcListener,
        socket_path: PathBuf,
    ) -> Result<Self, NetError> {
        let auth_store = Arc::new(AuthorizedKeysStore::open_or_create(
            config.config_dir.join("authorized_keys"),
        )?);
        let pairing_manager = Arc::new(PairingManager::default());
        let canonical_workdir = config
            .workdir
            .canonicalize()
            .map_err(|e| NetError::Workdir(config.workdir.display().to_string(), e))?;
        let upload_dir = match config.upload_dir {
            Some(dir) => dir,
            None => default_upload_dir()?,
        };
        let fs_engine = Arc::new(match config.opener {
            Some(hook) => FsEngine::new_with_opener(upload_dir, hook),
            None => FsEngine::new(upload_dir),
        });
        let connections = Arc::new(ConnectionTracker::new());
        let broadcaster = Arc::new(HostEventBroadcaster::new(HOST_EVENT_CAPACITY));
        let bin_dir = crate::net::shims::ensure_shims(&config.config_dir)
            .map_err(|e| NetError::Shims(e.to_string()))?;
        if crate::net::ipc::default_config_dir().is_ok_and(|d| d == config.config_dir) {
            if let Ok(home_path) = crate::net::ipc::home_dir() {
                for action in crate::agent::setup::remove_legacy_codex_opencode(&home_path) {
                    tracing::info!("{action}");
                }
                let exe_path = bin_dir.join("cawide");
                let _ = crate::agent::setup::auto_setup_all(&home_path, &exe_path);
            }
        }
        let cawide_open_path = bin_dir.join("cawide-open").display().to_string();
        let current_path = std::env::var_os("PATH").unwrap_or_default();
        let identity_vars: Vec<(String, std::ffi::OsString)> = std::env::vars_os()
            .filter_map(|(k, v)| {
                let ks = k.into_string().ok()?;
                crate::pty::session::is_inherited_terminal_identity(&ks).then_some((ks, v))
            })
            .collect();
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from);
        let tmpdir = std::env::var_os("TMPDIR")
            .filter(|t| !t.is_empty())
            .map(PathBuf::from);
        let sanitized_path = sanitize_inherited_path(
            &current_path,
            identity_vars
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_os_str())),
            home.as_deref(),
            tmpdir.as_deref(),
            &bin_dir,
        );
        let mut paths = vec![bin_dir.clone()];
        paths.extend(
            std::env::split_paths(&sanitized_path)
                .filter(|p| !p.as_os_str().is_empty() && p != &bin_dir),
        );
        let prepended_path = std::env::join_paths(paths)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| {
                #[cfg(windows)]
                const SEP: &str = ";";
                #[cfg(not(windows))]
                const SEP: &str = ":";
                if sanitized_path.is_empty() {
                    bin_dir.display().to_string()
                } else {
                    format!(
                        "{}{SEP}{}",
                        bin_dir.display(),
                        sanitized_path.to_string_lossy()
                    )
                }
            });
        let base_env = vec![
            (
                "CAWIDE_SOCKET".to_string(),
                socket_path.display().to_string(),
            ),
            ("CAWIDE_BIN_DIR".to_string(), bin_dir.display().to_string()),
            ("PATH".to_string(), prepended_path),
            ("BROWSER".to_string(), cawide_open_path.clone()),
            ("NPM_CONFIG_BROWSER".to_string(), cawide_open_path),
        ];
        let (alert_tx, alert_rx) = tokio::sync::mpsc::channel(64);
        let (activity_tx, activity_rx) = tokio::sync::mpsc::channel(128);
        let obs_paths = crate::agent::observe::ObserverPaths::from_env();
        let (obs_tx, obs_rx) = tokio::sync::mpsc::channel(16);
        let mut reg = SessionRegistry::new(
            canonical_workdir.clone(),
            config.launch_cmd,
            base_env,
            Arc::clone(&broadcaster),
        )
        .with_config_dir(config.config_dir.clone())
        .with_alert_sender(alert_tx)
        .with_activity_sender(activity_tx);
        if obs_paths.is_some() {
            reg = reg.with_observer_sender(obs_tx);
        }
        let registry = Arc::new(reg);
        let watchers = if config.watch_workspace {
            Some(RootWatchers::new(
                Arc::clone(&broadcaster),
                &canonical_workdir,
            )?)
        } else {
            None
        };
        let _probe = SessionProbe::spawn(Arc::clone(&registry), Arc::clone(&broadcaster), watchers);
        let _observers = obs_paths.map(|paths| {
            crate::agent::observe::ObserverHub::spawn(
                Arc::clone(&registry),
                Arc::clone(&broadcaster),
                paths,
                obs_rx,
            )
        });
        let _ports = PortWatcher::spawn(
            Arc::clone(&registry),
            Arc::clone(&broadcaster),
            Arc::clone(&connections),
        );
        let secret = load_or_create_host_key(&config.config_dir.join("host_key"))?;
        let host_secret = secret.to_bytes();
        let trust_kick = TrustKick::new(10_000);
        let relinked = TrustKick::new(5_000);

        let hooks = CawideEndpointHooks::new(
            Arc::clone(&auth_store),
            Arc::clone(&pairing_manager),
            Arc::clone(&trust_kick),
        );
        let transport_config = iroh::endpoint::QuicTransportConfig::builder()
            // Revert to noq default controller (Cubic) due to app-limited pacing collapse in BBRv3
            .initial_rtt(Duration::from_millis(100))
            .keep_alive_interval(Duration::from_secs(20))
            .max_idle_timeout(Some(
                Duration::from_secs(45)
                    .try_into()
                    .map_err(|e| NetError::Bind(format!("{e}")))?,
            ))
            .ack_frequency_config(Some(iroh::endpoint::AckFrequencyConfig::default()))
            .max_concurrent_bidi_streams(VarInt::from_u32(1024))
            .stream_receive_window(VarInt::from_u32(4 * 1024 * 1024))
            .receive_window(VarInt::from_u32(16 * 1024 * 1024))
            .send_fairness(true)
            .build();
        let mut builder = match config.network_mode {
            NetworkMode::N0 => iroh::Endpoint::builder(presets::N0),
            NetworkMode::LocalOnly => iroh::Endpoint::builder(presets::Minimal),
        };
        builder = builder
            .secret_key(secret)
            .hooks(hooks)
            .transport_config(transport_config);

        if let Some(port) = config.port {
            builder = builder
                .clear_ip_transports()
                .bind_addr((std::net::Ipv4Addr::UNSPECIFIED, port))
                .map_err(|e| NetError::Bind(e.to_string()))?;
        }
        if let Some(ext) = config.external_addr {
            builder = builder.external_addr(ext);
        }
        if let Some(relay_str) = &config.relay_url {
            let url: iroh::RelayUrl = relay_str
                .parse()
                .map_err(|e| NetError::Bind(format!("invalid relay url: {e}")))?;
            builder =
                builder.relay_mode(iroh::endpoint::RelayMode::Custom(iroh::RelayMap::from(url)));
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| NetError::Bind(e.to_string()))?;

        if config.network_mode == NetworkMode::N0 {
            if tokio::time::timeout(std::time::Duration::from_millis(3500), endpoint.online())
                .await
                .is_err()
            {
                tracing::warn!("Relay discovery timed out; continuing with direct addresses only");
            } else {
                tracing::info!("Relay discovery completed; endpoint is online");
            }
        }
        let node_id = *endpoint.id().as_bytes();
        let claimed = Arc::new(AtomicBool::new(true));
        let account = Arc::new(AccountClaimer::new(
            Arc::clone(&auth_store),
            host_secret,
            node_id,
            Arc::clone(&relinked),
            Arc::clone(&claimed),
        ));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let push = crate::push::PushService::open(
            &config.config_dir,
            Arc::clone(&auth_store),
            node_id,
            host_secret,
        );
        push.spawn_dispatcher(alert_rx);
        push.spawn_activity_dispatcher(activity_rx);
        let trust_wake = Arc::new(tokio::sync::Notify::new());
        let (trust, trust_task) = if config.network_mode == NetworkMode::N0 {
            let cfg = CloudConfig::from_env().map_err(|e| NetError::Bind(e.to_string()))?;
            let client = CloudClient::new(&cfg).map_err(|e| NetError::Bind(e.to_string()))?;
            let sync = TrustSync::new(
                client,
                Arc::clone(&auth_store),
                Arc::clone(&connections),
                Arc::clone(&push),
                {
                    let endpoint = endpoint.clone();
                    Arc::new(move || {
                        let addr = endpoint.addr();
                        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
                        let direct_addrs =
                            crate::net::ipc::filter_direct_addrs(addr.ip_addrs().copied())
                                .iter()
                                .map(ToString::to_string)
                                .collect();
                        (relay_url, direct_addrs)
                    })
                },
                host_secret,
                node_id,
                Arc::clone(&trust_kick),
                Arc::clone(&relinked),
                Arc::clone(&claimed),
                Arc::clone(&trust_wake),
            );
            let task = Arc::clone(&sync).spawn(shutdown_tx.subscribe());
            (Some(sync), Some(task))
        } else {
            (None, None)
        };
        let git_host_env = Arc::new(crate::rpc::git::env::GitHostEnv::new(config.git_env));
        let forge_service = Arc::new(crate::forge::ForgeService::new(
            config.config_dir.clone(),
            config.forge,
        ));
        let mut router_builder = Router::builder(endpoint.clone())
            .accept(
                ALPN_CAWIDE,
                CawideProtocolHandler {
                    registry: Arc::clone(&registry),
                    fs_engine,
                    broadcaster: Arc::clone(&broadcaster),
                    connections: Arc::clone(&connections),
                    forge_service,
                    git_host_env,
                    push: Arc::clone(&push),
                    account,
                    auth_store: Arc::clone(&auth_store),
                    host_secret,
                    node_id,
                    trust_wake: Arc::clone(&trust_wake),
                },
            )
            .accept(
                ALPN_CAWIDE_PAIR,
                CawidePairingHandler {
                    pairing_manager: Arc::clone(&pairing_manager),
                    auth_store: Arc::clone(&auth_store),
                    host_name: Arc::from(host_display_name()),
                    host_secret,
                    node_id,
                    trust_wake: Arc::clone(&trust_wake),
                    connections: Arc::clone(&connections),
                },
            );
        for legacy_alpn in ALPN_CAWIDE_LEGACY {
            router_builder = router_builder.accept(legacy_alpn, LegacyAlpnHandler);
        }
        let router = router_builder.spawn();

        let ctx = Arc::new(IpcContext {
            node_id,
            endpoint,
            pairing_manager: Arc::clone(&pairing_manager),
            auth_store: Arc::clone(&auth_store),
            registry: Arc::clone(&registry),
            broadcaster: Arc::clone(&broadcaster),
            connections: Arc::clone(&connections),
            trust,
            push: Arc::clone(&push),
            shutdown_tx: shutdown_tx.clone(),
        });
        let ipc_task = tokio::spawn(serve_ipc(listener, ctx, shutdown_rx));

        Ok(Self {
            router,
            registry,
            auth_store,
            pairing_manager,
            connections,
            broadcaster,
            _probe,
            _observers,
            _ports,
            shutdown_tx,
            ipc_task,
            trust_task,
            socket_path,
        })
    }

    pub fn endpoint(&self) -> &iroh::Endpoint {
        self.router.endpoint()
    }

    pub fn node_id(&self) -> [u8; 32] {
        *self.endpoint().id().as_bytes()
    }

    pub fn registry(&self) -> &Arc<SessionRegistry> {
        &self.registry
    }

    pub fn auth_store(&self) -> &Arc<AuthorizedKeysStore> {
        &self.auth_store
    }

    pub fn pairing_manager(&self) -> &Arc<PairingManager> {
        &self.pairing_manager
    }

    pub fn broadcaster(&self) -> &Arc<HostEventBroadcaster> {
        &self.broadcaster
    }

    pub fn connections(&self) -> &Arc<ConnectionTracker> {
        &self.connections
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Resolves when an IPC `Stop` was received.
    pub async fn wait_for_stop_request(&self) {
        let mut rx = self.shutdown_tx.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }

    pub async fn shutdown(self) -> Result<(), NetError> {
        self.shutdown_tx.send_replace(true);
        if let Err(e) = self.ipc_task.await {
            tracing::warn!(error = %e, "ipc task failed");
        }
        if let Some(task) = self.trust_task {
            if let Err(e) = task.await {
                tracing::warn!(error = %e, "trust sync task failed");
            }
        }
        if let Err(e) = self.router.shutdown().await {
            tracing::warn!(error = %e, "router shutdown task panicked");
        }
        self.registry.kill_all();
        #[cfg(unix)]
        match std::fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "failed to remove ipc socket"),
        }
        Ok(())
    }
}

struct NormalizedPath {
    raw: PathBuf,
    resolved: PathBuf,
}

impl NormalizedPath {
    fn new(path: &Path) -> Self {
        Self {
            raw: path.components().collect(),
            resolved: resolve_path(path),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.raw == other.raw || self.resolved == other.resolved
    }

    fn starts_with(&self, base: &Self) -> bool {
        self.raw.starts_with(&base.raw) || self.resolved.starts_with(&base.resolved)
    }
}

fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    let mut cur = path;
    let mut suffix = Vec::new();
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            suffix.push(name.to_os_string());
        }
        if let Ok(mut base) = std::fs::canonicalize(parent) {
            for part in suffix.into_iter().rev() {
                base.push(part);
            }
            return base;
        }
        cur = parent;
    }
    path.components().collect()
}

fn is_protected_dir(
    dir: &NormalizedPath,
    home: Option<&NormalizedPath>,
    tmpdir: Option<&NormalizedPath>,
) -> bool {
    if dir.raw == Path::new("/") || dir.resolved == Path::new("/") {
        return true;
    }
    if let Some(h) = home {
        if h.starts_with(dir) {
            return true;
        }
    }
    if let Some(t) = tmpdir {
        if dir.matches(t) {
            return true;
        }
    }
    false
}

/// Strips PATH entries belonging to inherited terminal wrappers (e.g. cmux, VS Code)
/// while preserving `keep` (Cawide's `bin_dir`) and never dropping `/`, `$HOME`,
/// ancestors of `$HOME`, or `$TMPDIR` itself.
pub fn sanitize_inherited_path<'a, I>(
    path: &std::ffi::OsStr,
    identity_vars: I,
    home: Option<&Path>,
    tmpdir: Option<&Path>,
    keep: &Path,
) -> std::ffi::OsString
where
    I: IntoIterator<Item = (&'a str, &'a std::ffi::OsStr)>,
{
    let home_norm = home
        .filter(|p| !p.as_os_str().is_empty())
        .map(NormalizedPath::new);
    let tmpdir_norm = tmpdir
        .filter(|p| !p.as_os_str().is_empty())
        .map(NormalizedPath::new);
    let keep_norm = NormalizedPath::new(keep);

    let mut drop_exact: Vec<NormalizedPath> = Vec::new();
    let mut drop_subtrees: Vec<NormalizedPath> = Vec::new();

    for (key, val) in identity_vars {
        if val.is_empty() || !crate::pty::session::is_inherited_terminal_identity(key) {
            continue;
        }
        let p = Path::new(val);
        let Ok(meta) = std::fs::metadata(p) else {
            continue;
        };
        if meta.is_file() {
            if let Some(parent) = p.parent() {
                let parent_norm = NormalizedPath::new(parent);
                if !is_protected_dir(&parent_norm, home_norm.as_ref(), tmpdir_norm.as_ref()) {
                    drop_exact.push(parent_norm);
                }
            }
        } else if meta.is_dir() {
            let dir_norm = NormalizedPath::new(p);
            if !is_protected_dir(&dir_norm, home_norm.as_ref(), tmpdir_norm.as_ref()) {
                drop_subtrees.push(dir_norm);
            }
        }
    }

    if drop_exact.is_empty() && drop_subtrees.is_empty() {
        return path.to_os_string();
    }

    let kept: Vec<PathBuf> = std::env::split_paths(path)
        .filter(|entry| {
            if entry.as_os_str().is_empty() {
                return false;
            }
            let entry_norm = NormalizedPath::new(entry);
            if entry_norm.matches(&keep_norm) {
                return true;
            }
            if drop_exact.iter().any(|d| entry_norm.matches(d)) {
                return false;
            }
            if drop_subtrees.iter().any(|d| entry_norm.starts_with(d)) {
                return false;
            }
            true
        })
        .collect();

    std::env::join_paths(kept).unwrap_or_else(|_| path.to_os_string())
}

#[cfg(test)]
mod tests {
    use super::sanitize_inherited_path;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[test]
    fn sanitize_inherited_path_drops_cmux_shim_root_and_bundled_cli_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tmpdir = tmp.path().join("tmp");
        let home = tmp.path().join("home");
        let cmux_root = tmpdir.join("cmux-shims-123");
        let cmux_sub = cmux_root.join("bin");
        let bundled_dir = tmp
            .path()
            .join("Applications/cmux.app/Contents/Resources/bin");
        let bundled_cli = bundled_dir.join("cmux");
        let user_bin = home.join(".local/bin");
        let keep_bin = home.join(".config/cawide/bin");

        std::fs::create_dir_all(&cmux_sub).expect("cmux_sub");
        std::fs::create_dir_all(&bundled_dir).expect("bundled_dir");
        std::fs::write(&bundled_cli, b"#!/bin/sh\n").expect("bundled_cli");
        std::fs::create_dir_all(&user_bin).expect("user_bin");
        std::fs::create_dir_all(&keep_bin).expect("keep_bin");

        let path =
            std::env::join_paths([&keep_bin, &cmux_root, &cmux_sub, &bundled_dir, &user_bin])
                .expect("join_paths");

        let vars = [
            ("CMUX_SHIM_ROOT", cmux_root.as_os_str()),
            ("CMUX_BUNDLED_CLI_PATH", bundled_cli.as_os_str()),
        ];
        let out = sanitize_inherited_path(&path, vars, Some(&home), Some(&tmpdir), &keep_bin);
        let entries: Vec<PathBuf> = std::env::split_paths(&out).collect();
        assert_eq!(entries, vec![keep_bin, user_bin]);
    }

    #[test]
    fn sanitize_inherited_path_vscode_ipc_in_tmpdir_keeps_other_tmpdir_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tmpdir = tmp.path().join("tmp");
        let home = tmp.path().join("home");
        let other_tmp_bin = tmpdir.join("my-tools/bin");
        let keep_bin = home.join(".config/cawide/bin");
        std::fs::create_dir_all(&other_tmp_bin).expect("other_tmp_bin");
        std::fs::create_dir_all(&keep_bin).expect("keep_bin");

        // Case 1: non-file / socket path (or Unix socket on unix)
        let sock_path = tmpdir.join("vscode-git.sock");
        #[cfg(unix)]
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind sock");

        let path = std::env::join_paths([&other_tmp_bin, &keep_bin]).expect("join_paths");
        let vars = [("VSCODE_GIT_IPC_HANDLE", sock_path.as_os_str())];
        let out = sanitize_inherited_path(&path, vars, Some(&home), Some(&tmpdir), &keep_bin);
        let entries: Vec<PathBuf> = std::env::split_paths(&out).collect();
        assert_eq!(entries, vec![other_tmp_bin.clone(), keep_bin.clone()]);

        // Case 2: even if VSCODE_GIT_IPC_HANDLE is a regular file in $TMPDIR, nothing else under $TMPDIR is dropped
        let file_in_tmp = tmpdir.join("vscode-ipc.file");
        std::fs::write(&file_in_tmp, b"x").expect("write file");
        let path_with_tmpdir =
            std::env::join_paths([&tmpdir, &other_tmp_bin, &keep_bin]).expect("join_paths");
        let vars2 = [("VSCODE_GIT_IPC_HANDLE", file_in_tmp.as_os_str())];
        let out2 = sanitize_inherited_path(
            &path_with_tmpdir,
            vars2,
            Some(&home),
            Some(&tmpdir),
            &keep_bin,
        );
        let entries2: Vec<PathBuf> = std::env::split_paths(&out2).collect();
        assert_eq!(entries2, vec![tmpdir, other_tmp_bin, keep_bin]);
    }

    #[test]
    fn sanitize_inherited_path_never_drops_home_ancestors_root_or_tmpdir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tmpdir = tmp.path().join("tmp");
        let home_parent = tmp.path().join("Users");
        let home = home_parent.join("alice");
        let home_bin = home.join("bin");
        let keep_bin = home.join(".config/cawide/bin");
        std::fs::create_dir_all(&tmpdir).expect("tmpdir");
        std::fs::create_dir_all(&home_bin).expect("home_bin");
        std::fs::create_dir_all(&keep_bin).expect("keep_bin");

        let path = std::env::join_paths([
            PathBuf::from("/"),
            home_parent.clone(),
            home.clone(),
            home_bin.clone(),
            tmpdir.clone(),
            keep_bin.clone(),
        ])
        .expect("join_paths");

        let vars = [
            ("CMUX_ROOT", OsStr::new("/")),
            ("WARP_ANCESTOR", home_parent.as_os_str()),
            ("KITTY_HOME", home.as_os_str()),
            ("WEZTERM_TMP", tmpdir.as_os_str()),
        ];
        let out = sanitize_inherited_path(&path, vars, Some(&home), Some(&tmpdir), &keep_bin);
        let entries: Vec<PathBuf> = std::env::split_paths(&out).collect();
        assert_eq!(
            entries,
            vec![
                PathBuf::from("/"),
                home_parent,
                home,
                home_bin,
                tmpdir,
                keep_bin
            ]
        );
    }

    #[test]
    fn sanitize_inherited_path_preserves_keep_even_under_dropped_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dropped_root = tmp.path().join("wrapper");
        let dropped_other = dropped_root.join("other");
        let keep_bin = dropped_root.join("cawide/bin");
        std::fs::create_dir_all(&dropped_other).expect("dropped_other");
        std::fs::create_dir_all(&keep_bin).expect("keep_bin");

        let path =
            std::env::join_paths([&dropped_root, &dropped_other, &keep_bin]).expect("join_paths");
        let vars = [("CMUX_WRAPPER_DIR", dropped_root.as_os_str())];
        let out = sanitize_inherited_path(&path, vars, None, None, &keep_bin);
        let entries: Vec<PathBuf> = std::env::split_paths(&out).collect();
        assert_eq!(entries, vec![keep_bin]);
    }
}
