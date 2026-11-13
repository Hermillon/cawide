use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use cawide_host::forge::ForgeHostConfig;
use cawide_host::net::{CawideServer, CawideServerConfig, NetworkMode};
use cawide_host::rpc::OpenerHook;
use cawide_protocol::types::{
    ForgeAccountOp, ForgeAccountReply, ForgeError, ForgeRepoOp, ForgeRepoReply, GitError, GitOp,
    GitReply, RpcRequest, RpcResponse,
};
use cawide_protocol::{read_rpc_response, write_rpc_request, StreamPurpose};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::Endpoint;
use parking_lot::Mutex;

use super::{authorized_client, open, within};

pub struct Env {
    pub server: CawideServer,
    pub ws: PathBuf,
    pub uploads: PathBuf,
    pub opened: Arc<Mutex<Vec<String>>>,
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub next_id: u32,
    pub _ep: Endpoint,
    pub _tmp: tempfile::TempDir,
}

impl Env {
    pub async fn start() -> Env {
        Self::start_with_forge(ForgeHostConfig {
            cli_search_path: Some(String::new()),
            ..ForgeHostConfig::default()
        })
        .await
    }

    pub async fn start_with_forge(forge: ForgeHostConfig) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let ws = root.join("ws");
        let uploads = root.join("uploads");
        std::fs::create_dir(&ws).unwrap();
        let opened = Arc::new(Mutex::new(Vec::<String>::new()));
        let rec = Arc::clone(&opened);
        let hook: OpenerHook = Arc::new(move |t: &str| {
            rec.lock().push(t.to_string());
            Ok(())
        });
        let server = within(CawideServer::bind(CawideServerConfig {
            config_dir: root.join("conf"),
            network_mode: NetworkMode::LocalOnly,
            workdir: ws.clone(),
            launch_cmd: None,
            upload_dir: Some(uploads.clone()),
            opener: Some(hook),
            watch_workspace: false,
            port: None,
            external_addr: None,
            relay_url: None,
            forge,
            git_env: vec![
                ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
                ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
            ],
        }))
        .await
        .unwrap();
        let (ep, conn) = authorized_client(&server).await;
        let (send, recv) = open(&conn, StreamPurpose::Rpc).await;
        Env {
            server,
            ws,
            uploads,
            opened,
            conn,
            send,
            recv,
            next_id: 0,
            _ep: ep,
            _tmp: tmp,
        }
    }

    pub fn root(&self) -> String {
        self.ws.display().to_string()
    }

    pub async fn call(&mut self, req: RpcRequest) -> RpcResponse {
        self.next_id += 1;
        within(write_rpc_request(&mut self.send, self.next_id, &req))
            .await
            .unwrap();
        let frame = within(read_rpc_response(&mut self.recv))
            .await
            .unwrap()
            .expect("rpc response");
        assert_eq!(frame.request_id, self.next_id);
        frame.payload
    }

    pub async fn git_op(&mut self, op: GitOp) -> Result<GitReply, GitError> {
        let root = self.root();
        let resp = self.call(RpcRequest::Git { root, op }).await;
        match resp {
            RpcResponse::Git { result } => result,
            other => panic!("expected RpcResponse::Git, got {:?}", other),
        }
    }

    pub async fn forge_accounts_op(
        &mut self,
        op: ForgeAccountOp,
    ) -> Result<ForgeAccountReply, ForgeError> {
        let resp = self.call(RpcRequest::ForgeAccounts { op }).await;
        match resp {
            RpcResponse::ForgeAccounts { result } => result,
            other => panic!("expected RpcResponse::ForgeAccounts, got {:?}", other),
        }
    }

    pub async fn forge_op(
        &mut self,
        account: Option<String>,
        op: ForgeRepoOp,
    ) -> Result<ForgeRepoReply, ForgeError> {
        let root = self.root();
        let resp = self.call(RpcRequest::Forge { root, account, op }).await;
        match resp {
            RpcResponse::Forge { result } => result,
            other => panic!("expected RpcResponse::Forge, got {:?}", other),
        }
    }

    pub fn write(&self, rel: &str, contents: &[u8]) {
        let p = self.ws.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contents).unwrap();
    }

    pub fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(&self.ws)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    pub fn init_repo(&self) {
        self.git(&["init", "-q", "-b", "main"]);
        self.git(&["config", "user.name", "Test User"]);
        self.git(&["config", "user.email", "test@cawide.dev"]);
        self.git(&["config", "commit.gpgSign", "false"]);
    }

    pub async fn shutdown(self) {
        self.conn.close(VarInt::from_u32(0), b"bye");
        self.server.shutdown().await.unwrap();
    }
}
