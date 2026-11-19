use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use cawide_account::{
    validate_account_id, HostClaimProof, HostSyncRequest, HostTrustSnapshot, MachineClaimBody,
    HOST_SYNC_PATH, HOST_UNLINK_PATH,
};
use cawide_protocol::CLOSE_UNAUTHORIZED;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

use crate::auth::{AuthError, AuthorizedKeysStore};
use crate::cloud::client::CloudClient;
use crate::net::connections::ConnectionTracker;
use crate::net::dispatcher::host_display_name;
use crate::net::ipc::filter_direct_addrs;

static START: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug)]
pub struct TrustKick {
    notify: Notify,
    last_ms: AtomicU64,
    window_ms: u64,
}

impl TrustKick {
    pub fn new(window_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            notify: Notify::new(),
            last_ms: AtomicU64::new(u64::MAX),
            window_ms,
        })
    }

    pub fn kick(&self) -> bool {
        let now = START.elapsed().as_millis() as u64;
        let old = self.last_ms.load(Ordering::Acquire);
        if (old == u64::MAX || now.saturating_sub(old) >= self.window_ms)
            && self
                .last_ms
                .compare_exchange(old, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.notify.notify_one();
            true
        } else {
            false
        }
    }
}

pub struct AccountClaimer {
    auth_store: Arc<AuthorizedKeysStore>,
    host_secret: [u8; 32],
    node_id: [u8; 32],
    relinked: Arc<TrustKick>,
    claimed: Arc<AtomicBool>,
}

impl std::fmt::Debug for AccountClaimer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountClaimer")
            .field("node_id", &hex::encode(self.node_id))
            .finish_non_exhaustive()
    }
}

impl AccountClaimer {
    pub fn new(
        auth_store: Arc<AuthorizedKeysStore>,
        host_secret: [u8; 32],
        node_id: [u8; 32],
        relinked: Arc<TrustKick>,
        claimed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            auth_store,
            host_secret,
            node_id,
            relinked,
            claimed,
        }
    }

    pub fn claim(
        &self,
        client: [u8; 32],
        account_id: &str,
        takeover: bool,
    ) -> Result<Vec<u8>, String> {
        validate_account_id(account_id).map_err(|_| "invalid account id".to_string())?;
        let now = now_secs();
        let changed = self
            .auth_store
            .begin_claim(&client, account_id, takeover, now)?;
        let body = MachineClaimBody {
            account_id: account_id.to_string(),
            host: self.node_id,
            claimer: client,
            issued_at: now,
        };
        let host_sig =
            cawide_account::sign(&self.host_secret, &body.host_signing_message()).to_vec();
        let proof = HostClaimProof { body, host_sig };
        let bytes = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        if changed {
            self.claimed.store(true, Ordering::Release);
            self.relinked.kick();
        }
        Ok(bytes)
    }
}

pub struct TrustSync {
    client: CloudClient,
    auth_store: Arc<AuthorizedKeysStore>,
    connections: Arc<ConnectionTracker>,
    endpoint: iroh::Endpoint,
    host_secret: [u8; 32],
    node_id: [u8; 32],
    kick: Arc<TrustKick>,
    relinked: Arc<TrustKick>,
    claimed: Arc<AtomicBool>,
    unlink_requested: Notify,
}

impl std::fmt::Debug for TrustSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustSync")
            .field("node_id", &hex::encode(self.node_id))
            .finish_non_exhaustive()
    }
}

async fn wait_shutdown(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|v| *v).await;
}

async fn drain_notify(n: &Notify) {
    tokio::select! {
        biased;
        _ = n.notified() => {},
        _ = std::future::ready(()) => {},
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SleepOutcome {
    Shutdown,
    Elapsed,
    Woken,
}

async fn sleep_or_wake(
    dur: Duration,
    shutdown: &mut watch::Receiver<bool>,
    kick: &TrustKick,
    relinked: &TrustKick,
    unlink_requested: &Notify,
) -> SleepOutcome {
    tokio::select! {
        _ = wait_shutdown(shutdown) => SleepOutcome::Shutdown,
        _ = tokio::time::sleep(dur) => SleepOutcome::Elapsed,
        _ = kick.notify.notified() => SleepOutcome::Woken,
        _ = relinked.notify.notified() => SleepOutcome::Woken,
        _ = unlink_requested.notified() => SleepOutcome::Woken,
    }
}

fn jittered_backoff(exp_backoff_secs: &mut u64) -> Duration {
    let next = if *exp_backoff_secs == 0 {
        1
    } else {
        (*exp_backoff_secs * 2).min(60)
    };
    *exp_backoff_secs = next;
    let max_jitter_ms = next * 200;
    let jitter_ms = rand::random::<u64>() % (max_jitter_ms + 1);
    Duration::from_secs(next) + Duration::from_millis(jitter_ms)
}

fn pending_backoff(pending_backoff_secs: &mut u64) -> Duration {
    let next = if *pending_backoff_secs == 0 {
        2
    } else {
        (*pending_backoff_secs * 2).min(60)
    };
    *pending_backoff_secs = next;
    Duration::from_secs(next)
}

impl TrustSync {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: CloudClient,
        auth_store: Arc<AuthorizedKeysStore>,
        connections: Arc<ConnectionTracker>,
        endpoint: iroh::Endpoint,
        host_secret: [u8; 32],
        node_id: [u8; 32],
        kick: Arc<TrustKick>,
        relinked: Arc<TrustKick>,
        claimed: Arc<AtomicBool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client,
            auth_store,
            connections,
            endpoint,
            host_secret,
            node_id,
            kick,
            relinked,
            claimed,
            unlink_requested: Notify::new(),
        })
    }

    pub fn spawn(self: Arc<Self>, shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(self.run(shutdown))
    }

    pub async fn unlink(&self) -> Result<bool, AuthError> {
        let store = Arc::clone(&self.auth_store);
        let (was_linked, removed) =
            tokio::task::spawn_blocking(move || store.mark_unlinked_local(true))
                .await
                .map_err(|e| AuthError::AccountSync(format!("unlink task failed: {e}")))??;
        for pk in removed {
            self.connections
                .close_all(pk, CLOSE_UNAUTHORIZED, b"account unlinked");
        }
        self.unlink_requested.notify_one();
        Ok(was_linked)
    }

    fn close_removed(&self, removed: Vec<[u8; 32]>) {
        for pk in removed {
            self.connections
                .close_all(pk, CLOSE_UNAUTHORIZED, b"device revoked");
        }
    }
}

impl TrustSync {
    async fn sleep_backoff(
        &self,
        dur: Duration,
        shutdown: &mut watch::Receiver<bool>,
        exp_backoff_secs: &mut u64,
        pending_backoff_secs: &mut u64,
    ) -> bool {
        match sleep_or_wake(
            dur,
            shutdown,
            &self.kick,
            &self.relinked,
            &self.unlink_requested,
        )
        .await
        {
            SleepOutcome::Shutdown => false,
            SleepOutcome::Elapsed => true,
            SleepOutcome::Woken => {
                *exp_backoff_secs = 0;
                *pending_backoff_secs = 0;
                true
            }
        }
    }

    async fn handle_pending_unlink(
        &self,
        shutdown: &mut watch::Receiver<bool>,
        exp_backoff_secs: &mut u64,
        pending_backoff_secs: &mut u64,
    ) -> bool {
        let res = tokio::select! {
            _ = wait_shutdown(shutdown) => return false,
            r = self.client.post_signed(
                HOST_UNLINK_PATH,
                b"{}".to_vec(),
                &self.host_secret,
                &self.node_id,
            ) => r,
        };
        match res {
            Ok(resp) if resp.status == 200 || resp.status == 404 => {
                let store = Arc::clone(&self.auth_store);
                match tokio::task::spawn_blocking(move || store.clear_pending_unlink()).await {
                    Ok(Ok(())) => {
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        return true;
                    }
                    Ok(Err(e)) => tracing::warn!(error = %e, "failed to clear pending unlink"),
                    Err(e) => tracing::warn!(error = %e, "clear pending unlink task failed"),
                }
                let delay = jittered_backoff(exp_backoff_secs);
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
            Ok(resp) if resp.status == 429 || resp.status >= 500 => {
                tracing::warn!(status = resp.status, "host unlink transient error");
                let delay = jittered_backoff(exp_backoff_secs);
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
            Ok(resp) => {
                tracing::warn!(status = resp.status, "host unlink unexpected status");
                *exp_backoff_secs = 0;
                *pending_backoff_secs = 0;
                self.sleep_backoff(
                    Duration::from_secs(60),
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Err(e) => {
                tracing::warn!(error = %e, "host unlink request failed");
                let delay = jittered_backoff(exp_backoff_secs);
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
        }
    }

    async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut exp_backoff_secs: u64 = 0;
        let mut pending_backoff_secs: u64 = 0;

        loop {
            if *shutdown.borrow() {
                break;
            }
            drain_notify(&self.relinked.notify).await;
            drain_notify(&self.unlink_requested).await;

            if self.auth_store.pending_unlink() {
                if !self
                    .handle_pending_unlink(
                        &mut shutdown,
                        &mut exp_backoff_secs,
                        &mut pending_backoff_secs,
                    )
                    .await
                {
                    break;
                }
                continue;
            }

            let Some((target, pending)) = self.auth_store.sync_target() else {
                exp_backoff_secs = 0;
                pending_backoff_secs = 0;
                tokio::select! {
                    _ = wait_shutdown(&mut shutdown) => break,
                    _ = self.kick.notify.notified() => {}
                    _ = self.relinked.notify.notified() => {}
                    _ = self.unlink_requested.notified() => {}
                }
                continue;
            };

            let wait = !pending && !self.claimed.swap(false, Ordering::AcqRel);
            let req_body = HostSyncRequest {
                version: self.auth_store.account_version(),
                wait,
                host_name: cawide_account::truncate_utf8(&host_display_name(), 64),
                relay_url: self
                    .endpoint
                    .addr()
                    .relay_urls()
                    .next()
                    .map(|u| u.to_string()),
                direct_addrs: filter_direct_addrs(self.endpoint.addr().ip_addrs().copied())
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            };
            let body_bytes = match serde_json::to_vec(&req_body) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize host sync request");
                    exp_backoff_secs = 0;
                    pending_backoff_secs = 0;
                    if !self
                        .sleep_backoff(
                            Duration::from_secs(60),
                            &mut shutdown,
                            &mut exp_backoff_secs,
                            &mut pending_backoff_secs,
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
            };

            let resp_res = if wait {
                tokio::select! {
                    _ = wait_shutdown(&mut shutdown) => break,
                    _ = self.relinked.notify.notified() => {
                        exp_backoff_secs = 0;
                        pending_backoff_secs = 0;
                        continue;
                    }
                    _ = self.unlink_requested.notified() => {
                        exp_backoff_secs = 0;
                        pending_backoff_secs = 0;
                        continue;
                    }
                    r = self.client.post_signed(
                        HOST_SYNC_PATH,
                        body_bytes,
                        &self.host_secret,
                        &self.node_id,
                    ) => r,
                }
            } else {
                tokio::select! {
                    _ = wait_shutdown(&mut shutdown) => break,
                    r = self.client.post_signed(
                        HOST_SYNC_PATH,
                        body_bytes,
                        &self.host_secret,
                        &self.node_id,
                    ) => r,
                }
            };

            let Some((cur_target, cur_pending)) = self.auth_store.sync_target() else {
                continue;
            };
            if self.auth_store.pending_unlink()
                || cur_target.account_id != target.account_id
                || cur_pending != pending
            {
                continue;
            }

            if !self
                .handle_sync_response(
                    resp_res,
                    &target.account_id,
                    target.claimed_at,
                    pending,
                    wait,
                    &mut shutdown,
                    &mut exp_backoff_secs,
                    &mut pending_backoff_secs,
                )
                .await
            {
                break;
            }
        }
    }
}

impl TrustSync {
    #[allow(clippy::too_many_arguments)]
    async fn handle_sync_response(
        &self,
        resp_res: anyhow::Result<crate::cloud::client::ApiResponse>,
        target_account_id: &str,
        claimed_at: u64,
        pending: bool,
        was_wait: bool,
        shutdown: &mut watch::Receiver<bool>,
        exp_backoff_secs: &mut u64,
        pending_backoff_secs: &mut u64,
    ) -> bool {
        match resp_res {
            Ok(resp) if resp.status == 200 => {
                let snap: HostTrustSnapshot = match serde_json::from_slice(&resp.body) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse host trust snapshot");
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        return self
                            .sleep_backoff(
                                Duration::from_secs(60),
                                shutdown,
                                exp_backoff_secs,
                                pending_backoff_secs,
                            )
                            .await;
                    }
                };
                let now = now_secs();
                if pending && snap.account_id != target_account_id {
                    let store = Arc::clone(&self.auth_store);
                    match tokio::task::spawn_blocking(move || store.apply_account_sync(&snap, now))
                        .await
                    {
                        Ok(Ok(removed)) => self.close_removed(removed),
                        Ok(Err(e)) => {
                            tracing::debug!(error = %e, "pending account sync mismatch");
                        }
                        Err(e) => tracing::warn!(error = %e, "apply_account_sync task failed"),
                    }
                    let delay = pending_backoff(pending_backoff_secs);
                    *exp_backoff_secs = 0;
                    return self
                        .sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                        .await;
                }
                if !pending && snap.account_id != target_account_id {
                    let store = Arc::clone(&self.auth_store);
                    let expected = target_account_id.to_string();
                    match tokio::task::spawn_blocking(move || {
                        store.clear_account_link(&expected, now)
                    })
                    .await
                    {
                        Ok(Ok((cleared, removed))) => {
                            self.close_removed(removed);
                            *exp_backoff_secs = 0;
                            *pending_backoff_secs = 0;
                            if cleared {
                                tracing::info!("machine moved to another Cawide account");
                                return true;
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "failed to clear moved account link");
                        }
                        Err(e) => tracing::warn!(error = %e, "clear_account_link task failed"),
                    }
                    *exp_backoff_secs = 0;
                    *pending_backoff_secs = 0;
                    return self
                        .sleep_backoff(
                            Duration::from_secs(60),
                            shutdown,
                            exp_backoff_secs,
                            pending_backoff_secs,
                        )
                        .await;
                }
                let store = Arc::clone(&self.auth_store);
                match tokio::task::spawn_blocking(move || store.apply_account_sync(&snap, now))
                    .await
                {
                    Ok(Ok(removed)) => {
                        self.close_removed(removed);
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        true
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "failed to apply account trust snapshot");
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        self.sleep_backoff(
                            Duration::from_secs(60),
                            shutdown,
                            exp_backoff_secs,
                            pending_backoff_secs,
                        )
                        .await
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "apply_account_sync task failed");
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        self.sleep_backoff(
                            Duration::from_secs(60),
                            shutdown,
                            exp_backoff_secs,
                            pending_backoff_secs,
                        )
                        .await
                    }
                }
            }
            Ok(resp) if resp.status == 304 => {
                if !was_wait || pending {
                    let delay = pending_backoff(pending_backoff_secs);
                    *exp_backoff_secs = 0;
                    return self
                        .sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                        .await;
                }
                *exp_backoff_secs = 0;
                *pending_backoff_secs = 0;
                true
            }
            Ok(resp) if resp.status == 404 => {
                let now = now_secs();
                if now.saturating_sub(claimed_at) < 600 {
                    let delay = pending_backoff(pending_backoff_secs);
                    *exp_backoff_secs = 0;
                    return self
                        .sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                        .await;
                }
                let store = Arc::clone(&self.auth_store);
                let expected = target_account_id.to_string();
                match tokio::task::spawn_blocking(move || store.clear_account_link(&expected, now))
                    .await
                {
                    Ok(Ok((cleared, removed))) => {
                        self.close_removed(removed);
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        if cleared {
                            tracing::info!("machine unlinked by Cawide Cloud");
                            return true;
                        }
                        if pending {
                            return true;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "failed to clear unlinked account");
                    }
                    Err(e) => tracing::warn!(error = %e, "clear_account_link task failed"),
                }
                *exp_backoff_secs = 0;
                *pending_backoff_secs = 0;
                self.sleep_backoff(
                    Duration::from_secs(60),
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Ok(resp) if resp.status == 401 => {
                tracing::warn!("host sync unauthorized (401)");
                *exp_backoff_secs = 0;
                *pending_backoff_secs = 0;
                self.sleep_backoff(
                    Duration::from_secs(60),
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Ok(resp) if resp.status == 429 || resp.status >= 500 => {
                tracing::warn!(status = resp.status, "host sync transient error");
                let delay = jittered_backoff(exp_backoff_secs);
                *pending_backoff_secs = 0;
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
            Ok(resp) => {
                tracing::warn!(status = resp.status, "host sync unexpected status");
                *exp_backoff_secs = 0;
                *pending_backoff_secs = 0;
                self.sleep_backoff(
                    Duration::from_secs(60),
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Err(e) => {
                tracing::warn!(error = %e, "host sync request failed");
                let delay = jittered_backoff(exp_backoff_secs);
                *pending_backoff_secs = 0;
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn trust_kick_debounces_within_window() {
        let kick = TrustKick::new(10_000);
        assert!(kick.kick());
        assert!(!kick.kick());
        tokio::time::timeout(Duration::from_millis(50), kick.notify.notified())
            .await
            .expect("first kick should notify");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), kick.notify.notified())
                .await
                .is_err(),
            "second kick within window must not notify"
        );
    }

    #[tokio::test]
    async fn account_claimer_notifies_relinked_at_most_once_for_same_account() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            AuthorizedKeysStore::open_or_create(tmp.path().join("authorized_keys")).unwrap(),
        );
        let client_pk = cawide_account::public_key_of(&[7u8; 32]);
        store.add_key(client_pk, "Phone".into()).unwrap();

        let host_secret = [9u8; 32];
        let node_id = cawide_account::public_key_of(&host_secret);
        let relinked = TrustKick::new(5_000);
        let claimed = Arc::new(AtomicBool::new(false));
        let claimer = AccountClaimer::new(
            Arc::clone(&store),
            host_secret,
            node_id,
            Arc::clone(&relinked),
            Arc::clone(&claimed),
        );

        for _ in 0..100 {
            let bytes = claimer.claim(client_pk, "acct-1", false).unwrap();
            let proof = HostClaimProof::from_bytes(&bytes).unwrap();
            proof.verify().unwrap();
            assert_eq!(proof.body.host, node_id);
            assert_eq!(proof.body.claimer, client_pk);
        }
        assert!(claimed.load(Ordering::Acquire));
        tokio::time::timeout(Duration::from_millis(50), relinked.notify.notified())
            .await
            .expect("first claim should notify relinked");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), relinked.notify.notified())
                .await
                .is_err(),
            "repeated claims for same account must not notify again"
        );
    }
}
