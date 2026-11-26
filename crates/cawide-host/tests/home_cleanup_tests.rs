#![cfg(unix)]

use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn test_default_config_dir_cleans_legacy_codex_and_sets_up_omp() {
    struct EnvRestore {
        home: Option<std::ffi::OsString>,
        config_dir: Option<std::ffi::OsString>,
    }
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match &self.config_dir {
                Some(v) => std::env::set_var("CAWIDE_CONFIG_DIR", v),
                None => std::env::remove_var("CAWIDE_CONFIG_DIR"),
            }
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let omp_agent = home.join(".omp/agent");
    let codex_dir = home.join(".codex");
    let workdir = tmp.path().join("workdir");
    std::fs::create_dir_all(&omp_agent).unwrap();
    std::fs::create_dir_all(&codex_dir).unwrap();
    std::fs::create_dir_all(&workdir).unwrap();

    let hooks_path = codex_dir.join("hooks.json");
    std::fs::write(
        &hooks_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "hooks": {
                "Stop": [{ "hooks": [{ "type": "command", "command": "/usr/bin/cawide hook codex --event Stop" }] }]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let _restore = EnvRestore {
        home: std::env::var_os("HOME"),
        config_dir: std::env::var_os("CAWIDE_CONFIG_DIR"),
    };
    std::env::set_var("HOME", &home);
    std::env::remove_var("CAWIDE_CONFIG_DIR");

    let config = CawideServerConfig {
        config_dir: home.join(".config/cawide"),
        network_mode: NetworkMode::LocalOnly,
        workdir,
        launch_cmd: None,
        upload_dir: Some(tmp.path().join("uploads")),
        opener: None,
        watch_workspace: false,
        port: None,
        external_addr: None,
        relay_url: None,
        forge: cawide_host::forge::ForgeHostConfig::default(),
        git_env: Vec::new(),
    };

    let server = tokio::time::timeout(Duration::from_secs(10), CawideServer::bind(config))
        .await
        .expect("bind timeout")
        .expect("bind");
    assert!(
        !hooks_path.exists(),
        "cawide-only .codex/hooks.json must be deleted"
    );
    assert!(
        omp_agent.join("extensions/cawide.js").exists(),
        "omp extension must be written when binding default config_dir"
    );
    server.shutdown().await.unwrap();
}
