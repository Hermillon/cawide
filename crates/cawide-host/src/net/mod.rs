//! Network layer: Iroh QUIC listener, transport gate, stream dispatcher, local IPC.

pub mod broadcaster;
pub mod connections;
pub mod dispatcher;
pub mod error;
pub mod hooks;
pub mod identity;
pub mod ipc;
pub mod lan_advertise;
pub mod probe;
pub mod registry;
pub mod server;
pub mod sessions;
pub mod shims;
pub mod tunnel;

pub const HANDSHAKE_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const MAX_IPC_FRAME_SIZE: usize = 65_536;
pub const DEFAULT_COLS: u16 = 80;
pub const DEFAULT_ROWS: u16 = 24;

pub use broadcaster::HostEventBroadcaster;
pub use dispatcher::{CawidePairingHandler, CawideProtocolHandler};
pub use error::NetError;
pub use hooks::CawideEndpointHooks;
pub use identity::load_or_create_host_key;
pub use ipc::{
    bind_ipc_listener, config_dir, default_ipc_path, filter_direct_addrs, send_ipc_request,
    IpcContext, IpcListener, IpcRequest, IpcResponse, IpcStream,
};
pub use probe::SessionProbe;
pub use registry::{validate_session_id, SessionRegistry};
pub use server::{CawideServer, CawideServerConfig, NetworkMode};
