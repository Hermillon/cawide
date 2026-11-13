//! QUIC client helpers shared by the host integration test crates.
#![allow(dead_code)] // each test crate uses a different subset

pub mod http_fixture;
pub mod rpc_env;
#[allow(unused_imports)]
pub use http_fixture::{MockServer, RecordedRequest};
#[allow(unused_imports)]
pub use rpc_env::Env;

use std::future::Future;
use std::time::Duration;

use cawide_host::net::CawideServer;
use cawide_protocol::ALPN_CAWIDE;
use cawide_protocol::{write_stream_purpose, StreamPurpose};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, SecretKey};

pub const T: Duration = Duration::from_secs(10);

pub async fn within<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(T, f)
        .await
        .expect("operation timed out")
}

pub async fn client(secret: SecretKey) -> Endpoint {
    within(
        Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .bind(),
    )
    .await
    .unwrap()
}

pub async fn connect(
    ep: &Endpoint,
    server: &CawideServer,
    alpn: &[u8],
) -> Result<Connection, String> {
    match tokio::time::timeout(T, ep.connect(server.endpoint().addr(), alpn)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("connect timed out".into()),
    }
}

pub async fn open(conn: &Connection, purpose: StreamPurpose) -> (SendStream, RecvStream) {
    let (mut send, recv) = within(conn.open_bi()).await.unwrap();
    within(write_stream_purpose(&mut send, purpose))
        .await
        .unwrap();
    (send, recv)
}

pub async fn authorized_client(server: &CawideServer) -> (Endpoint, Connection) {
    let key = SecretKey::generate();
    server
        .auth_store()
        .add_key(*key.public().as_bytes(), "Test Device".into())
        .unwrap();
    let ep = client(key).await;
    let conn = connect(&ep, server, ALPN_CAWIDE)
        .await
        .expect("authorized connect");
    (ep, conn)
}
