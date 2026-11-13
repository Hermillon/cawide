use std::time::{Duration, Instant};

use cawide_host::forge::ForgeHostConfig;
use cawide_host::net::lan_advertise::LanAdvertiser;
use cawide_host::net::{filter_direct_addrs, CawideServer, CawideServerConfig, NetworkMode};

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn lan_advertise_visible_to_querier() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().canonicalize()?;
    let ws = root.join("ws");
    std::fs::create_dir(&ws)?;

    let free_port = {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        sock.local_addr()?.port()
    };

    let server = CawideServer::bind(CawideServerConfig {
        config_dir: root.join("conf"),
        network_mode: NetworkMode::LocalOnly,
        workdir: ws,
        launch_cmd: None,
        upload_dir: None,
        opener: None,
        watch_workspace: false,
        port: Some(free_port),
        external_addr: None,
        relay_url: None,
        forge: ForgeHostConfig::default(),
        git_env: Vec::new(),
    })
    .await?;

    let direct_addrs = filter_direct_addrs(server.endpoint().addr().ip_addrs().copied());
    if direct_addrs.is_empty() {
        return Ok(());
    }

    let _advertiser = match LanAdvertiser::start(
        server.endpoint().clone(),
        cawide_host::net::dispatcher::host_display_name(),
    ) {
        Some(adv) => adv,
        None => return Ok(()),
    };

    let daemon = mdns_sd::ServiceDaemon::new()?;
    let receiver = daemon.browse("_cawide._udp.local.")?;

    let expected_node_id = hex::encode(server.node_id());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found = false;

    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(resolved)) => {
                if let Some(id) = resolved.get_property_val_str("node_id") {
                    if id == expected_node_id {
                        found = true;
                        break;
                    }
                }
            }
            Ok(_) => {}
            Err(mdns_sd::RecvTimeoutError::Timeout) => {}
            Err(mdns_sd::RecvTimeoutError::Disconnected) => break,
        }
    }

    assert!(
        found,
        "timed out waiting for node_id in mDNS browse results"
    );
    Ok(())
}
