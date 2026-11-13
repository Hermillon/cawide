//! Server engine wiring identity, gate, handlers, and IPC together.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, VarInt};
use iroh::protocol::Router;

use crate::auth::{AuthorizedKeysStore, PairingManager};
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
    _ports: PortWatcher,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    ipc_task: tokio::task::JoinHandle<()>,
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
        if let Some(home) = std::env::var_os("HOME") {
            let home_path = PathBuf::from(home);
            let exe_path = bin_dir.join("cawide");
            let _ = crate::agent::setup::auto_setup_all(&home_path, &exe_path);
        }
        let cawide_open_path = bin_dir.join("cawide-open").display().to_string();
        let current_path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![bin_dir.clone()];
        paths.extend(std::env::split_paths(&current_path));
        let prepended_path = std::env::join_paths(paths)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| {
                #[cfg(windows)]
                const SEP: &str = ";";
                #[cfg(not(windows))]
                const SEP: &str = ":";
                if current_path.is_empty() {
                    bin_dir.display().to_string()
                } else {
                    format!(
                        "{}{SEP}{}",
                        bin_dir.display(),
                        current_path.to_string_lossy()
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
        let registry = Arc::new(
            SessionRegistry::new(
                canonical_workdir.clone(),
                config.launch_cmd,
                base_env,
                Arc::clone(&broadcaster),
            )
            .with_config_dir(config.config_dir.clone())
            .with_alert_sender(alert_tx),
        );
        let watchers = if config.watch_workspace {
            Some(RootWatchers::new(
                Arc::clone(&broadcaster),
                &canonical_workdir,
            )?)
        } else {
            None
        };
        let _probe = SessionProbe::spawn(Arc::clone(&registry), Arc::clone(&broadcaster), watchers);
        let _ports = PortWatcher::spawn(
            Arc::clone(&registry),
            Arc::clone(&broadcaster),
            Arc::clone(&connections),
        );
        let secret = load_or_create_host_key(&config.config_dir.join("host_key"))?;

        let hooks = CawideEndpointHooks::new(Arc::clone(&auth_store), Arc::clone(&pairing_manager));
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
        let push =
            crate::push::PushService::open(&config.config_dir, Arc::clone(&auth_store), node_id);
        push.spawn_dispatcher(alert_rx);
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
                    push,
                },
            )
            .accept(
                ALPN_CAWIDE_PAIR,
                CawidePairingHandler {
                    pairing_manager: Arc::clone(&pairing_manager),
                    auth_store: Arc::clone(&auth_store),
                    host_name: Arc::from(host_display_name()),
                },
            );
        for legacy_alpn in ALPN_CAWIDE_LEGACY {
            router_builder = router_builder.accept(legacy_alpn, LegacyAlpnHandler);
        }
        let router = router_builder.spawn();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let ctx = Arc::new(IpcContext {
            node_id,
            endpoint,
            pairing_manager: Arc::clone(&pairing_manager),
            auth_store: Arc::clone(&auth_store),
            registry: Arc::clone(&registry),
            broadcaster: Arc::clone(&broadcaster),
            connections: Arc::clone(&connections),
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
            _ports,
            shutdown_tx,
            ipc_task,
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
