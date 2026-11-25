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
use crate::push::PushService;

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

/// Reachability hints advertised in sync requests: `(relay URL, direct address strings)`.
/// Supplied by the server from its live endpoint so this module stays free of iroh types.
pub type AddrHints = Arc<dyn Fn() -> (Option<String>, Vec<String>) + Send + Sync>;

pub struct TrustSync {
    client: CloudClient,
    auth_store: Arc<AuthorizedKeysStore>,
    connections: Arc<ConnectionTracker>,
    push: Arc<PushService>,
    addr_hints: AddrHints,
    host_secret: [u8; 32],
    node_id: [u8; 32],
    kick: Arc<TrustKick>,
    relinked: Arc<TrustKick>,
    claimed: Arc<AtomicBool>,
    unlink_requested: Notify,
    /// Wakes the loop immediately after a managed binding is established (pair or adopt).
    trust_wake: Arc<Notify>,
    /// Current authorization lease deadline; `None` means no lease (fail-closed).
    lease_tx: watch::Sender<Option<tokio::time::Instant>>,
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
    trust_wake: &Notify,
) -> SleepOutcome {
    tokio::select! {
        _ = wait_shutdown(shutdown) => SleepOutcome::Shutdown,
        _ = tokio::time::sleep(dur) => SleepOutcome::Elapsed,
        _ = kick.notify.notified() => SleepOutcome::Woken,
        _ = relinked.notify.notified() => SleepOutcome::Woken,
        _ = unlink_requested.notified() => SleepOutcome::Woken,
        _ = trust_wake.notified() => SleepOutcome::Woken,
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
        push: Arc<PushService>,
        addr_hints: AddrHints,
        host_secret: [u8; 32],
        node_id: [u8; 32],
        kick: Arc<TrustKick>,
        relinked: Arc<TrustKick>,
        claimed: Arc<AtomicBool>,
        trust_wake: Arc<Notify>,
    ) -> Arc<Self> {
        let (lease_tx, _lease_rx) = watch::channel(None);
        Arc::new(Self {
            client,
            auth_store,
            connections,
            push,
            addr_hints,
            host_secret,
            node_id,
            kick,
            relinked,
            claimed,
            unlink_requested: Notify::new(),
            trust_wake,
            lease_tx,
        })
    }

    pub fn spawn(self: Arc<Self>, shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            tokio::select! {
                _ = Arc::clone(&self).run_lease_watchdog(shutdown.clone()) => {}
                _ = self.run(shutdown) => {}
            }
        })
    }

    /// Closes all connections once the authorization lease passes its deadline without renewal.
    /// Keeps PTY and agent processes running; only transport authorization is revoked.
    async fn run_lease_watchdog(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut lease_rx = self.lease_tx.subscribe();
        loop {
            let deadline = *lease_rx.borrow_and_update();
            match deadline {
                None => {
                    tokio::select! {
                        _ = wait_shutdown(&mut shutdown) => return,
                        changed = lease_rx.changed() => {
                            if changed.is_err() { return; }
                        }
                    }
                }
                Some(until) => {
                    tokio::select! {
                        _ = wait_shutdown(&mut shutdown) => return,
                        changed = lease_rx.changed() => {
                            if changed.is_err() { return; }
                        }
                        _ = tokio::time::sleep_until(until) => {
                            if self.auth_store.expire_lease() {
                                if self.auth_store.requires_lease() {
                                    tracing::warn!("authorization lease expired; closing connections");
                                    self.connections.close_all_connections(
                                        CLOSE_UNAUTHORIZED,
                                        b"authorization lease expired",
                                    );
                                }
                                self.lease_tx.send_if_modified(|cur| {
                                    if *cur == Some(until) {
                                        *cur = None;
                                        true
                                    } else {
                                        false
                                    }
                                });
                            } else {
                                let current = self.auth_store.lease_until();
                                self.lease_tx.send_if_modified(|cur| {
                                    if *cur == Some(until) && current != Some(until) {
                                        *cur = current;
                                        true
                                    } else {
                                        false
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Relay URL and direct addresses advertised in a sync request. Shared by the managed
    /// and legacy request builders so both report the same reachability hints.
    fn addr_hints(&self) -> (Option<String>, Vec<String>) {
        (self.addr_hints)()
    }

    /// Publishes the store's current lease deadline to the watchdog. A withdrawn lease
    /// (`None` after having been active) closes transport streams immediately: a host
    /// without a current verified snapshot must not keep serving.
    fn publish_lease(&self) {
        let deadline = self.auth_store.lease_until();
        let previous = self.lease_tx.send_replace(deadline);
        if deadline.is_none() && previous.is_some() && self.auth_store.requires_lease() {
            self.connections
                .close_all_connections(CLOSE_UNAUTHORIZED, b"authorization withdrawn");
        }
    }
}

impl TrustSync {
    pub async fn unlink(&self) -> Result<bool, AuthError> {
        let was_managed = self.auth_store.is_managed();
        let store = Arc::clone(&self.auth_store);
        let res = tokio::task::spawn_blocking(move || store.mark_unlinked_local(true))
            .await
            .map_err(|e| AuthError::AccountSync(format!("unlink task failed: {e}")))?;
        match res {
            Ok((was_linked, removed)) => {
                if was_managed {
                    self.connections
                        .close_all_connections(CLOSE_UNAUTHORIZED, b"account unlinked");
                    self.auth_store.revoke_lease();
                }
                for pk in removed {
                    self.connections
                        .close_all(pk, CLOSE_UNAUTHORIZED, b"account unlinked");
                }
                self.publish_lease();
                self.push.prune_channels().await;
                self.unlink_requested.notify_one();
                Ok(was_linked)
            }
            Err(e) => {
                if was_managed {
                    // Managed revocation is already applied in memory; close transport and prune push fail-closed.
                    self.connections
                        .close_all_connections(CLOSE_UNAUTHORIZED, b"account unlinked");
                    self.auth_store.revoke_lease();
                    self.publish_lease();
                    self.push.prune_channels().await;
                    self.unlink_requested.notify_one();
                }
                Err(e)
            }
        }
    }

    fn close_removed(&self, removed: Vec<[u8; 32]>) {
        for pk in removed {
            self.connections
                .close_all(pk, CLOSE_UNAUTHORIZED, b"device revoked");
        }
    }
}

const MANAGED_SYNC_INTERVAL: Duration = Duration::from_secs(10);
const MANAGED_SYNC_TIMEOUT: Duration = Duration::from_secs(8);

impl TrustSync {
    /// Retries a revocation whose durable write failed. Denial is already in memory.
    async fn retry_pending_revocation_persist(&self) {
        if !self.auth_store.has_pending_revocation_persist() {
            return;
        }
        let store = Arc::clone(&self.auth_store);
        match tokio::task::spawn_blocking(move || store.retry_persist_trust()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "retry revocation persist failed"),
            Err(e) => tracing::warn!(error = %e, "retry revocation persist task failed"),
        }
    }

    /// Sends the epoch-gated managed unlink. Returns true once the cloud acknowledges it.
    async fn handle_managed_pending_unlink(
        &self,
        account_id: String,
        epoch: u64,
        shutdown: &mut watch::Receiver<bool>,
        exp_backoff_secs: &mut u64,
        pending_backoff_secs: &mut u64,
    ) -> bool {
        let body = match serde_json::to_vec(&cawide_account::ManagedHostUnlinkRequest {
            account_id: account_id.clone(),
            epoch,
        }) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize managed unlink");
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
        let res = tokio::select! {
            _ = wait_shutdown(shutdown) => return false,
            r = tokio::time::timeout(
                MANAGED_SYNC_TIMEOUT,
                self.client.post_signed(
                    cawide_account::MANAGED_HOST_UNLINK_PATH,
                    body,
                    &self.host_secret,
                    &self.node_id,
                ),
            ) => match r {
                Ok(inner) => inner,
                Err(_) => Err(anyhow::anyhow!("managed host unlink timed out")),
            },
        };
        match res {
            Ok(resp) if resp.status == 200 || resp.status == 404 => {
                let store = Arc::clone(&self.auth_store);
                let acct = account_id.clone();
                match tokio::task::spawn_blocking(move || {
                    store.clear_managed_pending_unlink(&acct, epoch)
                })
                .await
                {
                    Ok(Ok(())) => {
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                        true
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "failed to clear managed pending unlink");
                        self.sleep_backoff(
                            Duration::from_secs(10),
                            shutdown,
                            exp_backoff_secs,
                            pending_backoff_secs,
                        )
                        .await
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "clear managed pending unlink task failed");
                        self.sleep_backoff(
                            Duration::from_secs(10),
                            shutdown,
                            exp_backoff_secs,
                            pending_backoff_secs,
                        )
                        .await
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(status = resp.status, "managed host unlink not acknowledged");
                let delay = jittered_backoff(exp_backoff_secs);
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
            Err(e) => {
                tracing::warn!(error = %e, "managed host unlink request failed");
                let delay = jittered_backoff(exp_backoff_secs);
                self.sleep_backoff(delay, shutdown, exp_backoff_secs, pending_backoff_secs)
                    .await
            }
        }
    }

    /// One managed poll. Never renews the lease on a failed request; the watchdog enforces expiry.
    async fn handle_managed_sync(
        &self,
        account_id: String,
        epoch: u64,
        shutdown: &mut watch::Receiver<bool>,
        exp_backoff_secs: &mut u64,
        pending_backoff_secs: &mut u64,
    ) -> bool {
        let request_start = tokio::time::Instant::now();
        let addr_hints = self.addr_hints();
        let req = cawide_account::ManagedHostSyncRequest {
            account_id: account_id.clone(),
            epoch,
            sync: HostSyncRequest {
                version: self.auth_store.account_version(),
                wait: false,
                host_name: cawide_account::truncate_utf8(&host_display_name(), 64),
                relay_url: addr_hints.0,
                direct_addrs: addr_hints.1,
            },
        };
        let body = match serde_json::to_vec(&req) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize managed sync request");
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
        let res = tokio::select! {
            _ = wait_shutdown(shutdown) => return false,
            r = tokio::time::timeout(
                MANAGED_SYNC_TIMEOUT,
                self.client.post_signed(
                    cawide_account::MANAGED_HOST_SYNC_PATH,
                    body,
                    &self.host_secret,
                    &self.node_id,
                ),
            ) => match r {
                Ok(inner) => inner,
                Err(_) => Err(anyhow::anyhow!("managed sync timed out")),
            },
        };

        // The binding may have moved while the request was in flight.
        let Some((cur_account, cur_epoch)) = self.auth_store.managed_sync_target() else {
            return true;
        };
        if cur_account != account_id || cur_epoch != epoch {
            return true;
        }

        match res {
            Ok(resp) if resp.status == 200 => {
                let parsed: cawide_account::ManagedHostSyncResponse =
                    match serde_json::from_slice(&resp.body) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to parse managed sync response");
                            return self
                                .sleep_backoff(
                                    MANAGED_SYNC_INTERVAL,
                                    shutdown,
                                    exp_backoff_secs,
                                    pending_backoff_secs,
                                )
                                .await;
                        }
                    };
                let lease_until = request_start + Duration::from_secs(crate::auth::LEASE_SECS);
                let store = Arc::clone(&self.auth_store);
                let acct = account_id.clone();
                let now = now_secs();
                let outcome = tokio::task::spawn_blocking(move || {
                    store.apply_managed_sync(&acct, epoch, parsed, lease_until, now)
                })
                .await;
                match outcome {
                    Ok(Ok(crate::auth::ManagedSyncOutcome::Active { removed })) => {
                        self.close_removed(removed);
                        self.publish_lease();
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                    }
                    Ok(Ok(crate::auth::ManagedSyncOutcome::Pending)) => {
                        self.publish_lease();
                        let delay = pending_backoff(pending_backoff_secs);
                        *exp_backoff_secs = 0;
                        return self
                            .sleep_backoff(
                                delay.min(MANAGED_SYNC_INTERVAL),
                                shutdown,
                                exp_backoff_secs,
                                pending_backoff_secs,
                            )
                            .await;
                    }
                    Ok(Ok(crate::auth::ManagedSyncOutcome::Removed {
                        removed,
                        persist_failed,
                    })) => {
                        self.connections
                            .close_all_connections(CLOSE_UNAUTHORIZED, b"device revoked");
                        self.close_removed(removed);
                        self.publish_lease();
                        self.push.prune_channels().await;
                        if persist_failed {
                            tracing::warn!("managed revocation applied in memory; persist pending");
                        }
                        *exp_backoff_secs = 0;
                        *pending_backoff_secs = 0;
                    }
                    Ok(Ok(crate::auth::ManagedSyncOutcome::Stale)) => {
                        tracing::debug!("managed sync response no longer matches binding");
                        return true;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "failed to apply managed trust snapshot");
                        self.auth_store.revoke_lease();
                        self.publish_lease();
                        return self
                            .sleep_backoff(
                                MANAGED_SYNC_INTERVAL,
                                shutdown,
                                exp_backoff_secs,
                                pending_backoff_secs,
                            )
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "apply_managed_sync task failed");
                        self.auth_store.revoke_lease();
                        self.publish_lease();
                        return self
                            .sleep_backoff(
                                MANAGED_SYNC_INTERVAL,
                                shutdown,
                                exp_backoff_secs,
                                pending_backoff_secs,
                            )
                            .await;
                    }
                }
                self.sleep_backoff(
                    MANAGED_SYNC_INTERVAL,
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Ok(resp) if resp.status == 401 || resp.status == 404 => {
                // No renewal: the 120 s lease expires on its own if this stays unresolved.
                // Immediate revocation comes only from a verified `200 Removed`.
                tracing::warn!(
                    status = resp.status,
                    "managed host sync rejected; lease not renewed"
                );
                self.sleep_backoff(
                    MANAGED_SYNC_INTERVAL,
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Ok(resp) => {
                tracing::warn!(status = resp.status, "managed host sync transient error");
                self.sleep_backoff(
                    MANAGED_SYNC_INTERVAL,
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
            Err(e) => {
                tracing::warn!(error = %e, "managed host sync request failed");
                self.sleep_backoff(
                    MANAGED_SYNC_INTERVAL,
                    shutdown,
                    exp_backoff_secs,
                    pending_backoff_secs,
                )
                .await
            }
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
            &self.trust_wake,
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
            self.retry_pending_revocation_persist().await;
            drain_notify(&self.unlink_requested).await;
            drain_notify(&self.trust_wake).await;

            if let Some((account_id, epoch)) = self.auth_store.pending_managed_unlink() {
                if !self
                    .handle_managed_pending_unlink(
                        account_id,
                        epoch,
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

            if let Some((account_id, epoch)) = self.auth_store.managed_sync_target() {
                if !self
                    .handle_managed_sync(
                        account_id,
                        epoch,
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
                if self.auth_store.has_pending_revocation_persist() {
                    let delay = jittered_backoff(&mut exp_backoff_secs);
                    if !self
                        .sleep_backoff(
                            delay,
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
                exp_backoff_secs = 0;
                pending_backoff_secs = 0;
                tokio::select! {
                    _ = wait_shutdown(&mut shutdown) => break,
                    _ = self.kick.notify.notified() => {}
                    _ = self.relinked.notify.notified() => {}
                    _ = self.unlink_requested.notified() => {}
                    _ = self.trust_wake.notified() => {}
                }
                continue;
            };

            let wait = !pending && !self.claimed.swap(false, Ordering::AcqRel);
            let addr_hints = self.addr_hints();
            let req_body = HostSyncRequest {
                version: self.auth_store.account_version(),
                wait,
                host_name: cawide_account::truncate_utf8(&host_display_name(), 64),
                relay_url: addr_hints.0,
                direct_addrs: addr_hints.1,
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
                    _ = self.trust_wake.notified() => {
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
                        self.publish_lease();
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

#[cfg(test)]
mod managed_sync_tests {
    use super::*;
    use cawide_account::{HostTrustSnapshot, ManagedHostSyncResponse, SnapshotDevice};
    use cawide_protocol::types::rpc::PushChannelV2;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // ---------------------------------------------------------------------------
    // Scripted loopback HTTP/1.1 stub. Each request pops the next scripted step.
    // ---------------------------------------------------------------------------

    #[derive(Clone)]
    enum Step {
        /// Reply with `status` and `body` immediately.
        Respond(u16, Vec<u8>),
        /// Wait for `gate` before replying with `status` and `body`.
        Gate(Arc<Notify>, u16, Vec<u8>),
        /// Read the request, then keep the socket open without replying (a stalled or
        /// blocked sync request). The task is aborted when the stub is dropped.
        Hold,
    }

    #[derive(Default)]
    struct StubState {
        steps: VecDeque<Step>,
        paths: Vec<String>,
    }

    struct Stub {
        addr: SocketAddr,
        state: Arc<parking_lot::Mutex<StubState>>,
        seen: Arc<Notify>,
        accept_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            self.accept_task.abort();
        }
    }

    impl Stub {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(parking_lot::Mutex::new(StubState::default()));
            let seen = Arc::new(Notify::new());
            let server = Arc::clone(&state);
            let seen_tx = Arc::clone(&seen);
            let accept_task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(handle_conn(
                        stream,
                        Arc::clone(&server),
                        Arc::clone(&seen_tx),
                    ));
                }
            });
            Self {
                addr,
                state,
                seen,
                accept_task,
            }
        }

        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn script(&self, steps: Vec<Step>) {
            self.state.lock().steps.extend(steps);
        }

        fn paths(&self) -> Vec<String> {
            self.state.lock().paths.clone()
        }

        async fn wait_requests(&self, count: usize) {
            loop {
                let notified = self.seen.notified();
                if self.state.lock().paths.len() >= count {
                    return;
                }
                notified.await;
            }
        }
    }

    async fn handle_conn(
        mut stream: TcpStream,
        state: Arc<parking_lot::Mutex<StubState>>,
        seen: Arc<Notify>,
    ) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let header_end = loop {
            let n = match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let path = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("")
            .to_string();
        let content_len: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_len {
            let n = match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
        }
        let step = {
            let mut s = state.lock();
            s.paths.push(path);
            s.steps
                .pop_front()
                .unwrap_or(Step::Respond(500, Vec::new()))
        };
        seen.notify_waiters();
        match step {
            Step::Respond(status, body) => write_http(&mut stream, status, &body).await,
            Step::Gate(gate, status, body) => {
                gate.notified().await;
                write_http(&mut stream, status, &body).await;
            }
            Step::Hold => std::future::pending::<()>().await,
        }
    }

    async fn write_http(stream: &mut TcpStream, status: u16, body: &[u8]) {
        let resp = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.shutdown().await;
    }

    /// Keeps Tokio's paused clock from auto-advancing past `MANAGED_SYNC_TIMEOUT` while
    /// real loopback TCP I/O is in flight, without advancing `Instant::now()`.
    async fn with_inhibited_auto_advance<F: Future>(fut: F) -> F::Output {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = rx.recv();
        });
        let out = fut.await;
        drop(tx);
        let _ = blocker.await;
        out
    }

    // ---------------------------------------------------------------------------
    // Harness: real store, tracker, and push service in a tempdir. TrustSync is wired
    // through the addr_hints closure seam, so no iroh endpoint is involved.
    // ---------------------------------------------------------------------------

    const HOST_SECRET: [u8; 32] = [0x31; 32];
    const ACCOUNT: &str = "acct-1";

    fn client_pk() -> [u8; 32] {
        cawide_account::public_key_of(&[0x41; 32])
    }

    struct Harness {
        dir: tempfile::TempDir,
        stub: Stub,
        store: Arc<AuthorizedKeysStore>,
        connections: Arc<ConnectionTracker>,
        push: Arc<PushService>,
        sync: Arc<TrustSync>,
        trust_wake: Arc<Notify>,
        auth_path: std::path::PathBuf,
    }

    async fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let auth_path = dir.path().join("authorized_keys");
        let stub = Stub::start().await;
        let store = Arc::new(AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap());
        let connections = Arc::new(ConnectionTracker::new());
        let host_node_id = cawide_account::public_key_of(&HOST_SECRET);
        let push = PushService::open_with_cloud(
            dir.path(),
            Arc::clone(&store),
            host_node_id,
            HOST_SECRET,
            None,
        );
        let client = CloudClient::new_insecure_for_test(stub.url());
        let trust_wake = Arc::new(Notify::new());
        let addr_hints: AddrHints = Arc::new(|| {
            (
                Some("https://relay.example".to_string()),
                vec!["10.0.0.2:4433".to_string()],
            )
        });
        let sync = TrustSync::new(
            client,
            Arc::clone(&store),
            Arc::clone(&connections),
            Arc::clone(&push),
            addr_hints,
            HOST_SECRET,
            host_node_id,
            TrustKick::new(10_000),
            TrustKick::new(10_000),
            Arc::new(AtomicBool::new(false)),
            Arc::clone(&trust_wake),
        );
        Harness {
            dir,
            stub,
            store,
            connections,
            push,
            sync,
            trust_wake,
            auth_path,
        }
    }

    fn snapshot(devices: &[[u8; 32]]) -> HostTrustSnapshot {
        HostTrustSnapshot {
            version: 1,
            account_id: ACCOUNT.into(),
            locked: false,
            devices: devices
                .iter()
                .map(|pk| SnapshotDevice {
                    public_key: hex::encode(pk),
                    name: "Phone".into(),
                })
                .collect(),
            links: vec![],
            revoked: vec![],
        }
    }

    fn active_body(devices: &[[u8; 32]]) -> Vec<u8> {
        serde_json::to_vec(&ManagedHostSyncResponse::Active {
            snapshot: snapshot(devices),
        })
        .unwrap()
    }

    fn removed_body() -> Vec<u8> {
        serde_json::to_vec(&ManagedHostSyncResponse::Removed).unwrap()
    }

    fn pending_body() -> Vec<u8> {
        serde_json::to_vec(&ManagedHostSyncResponse::Pending).unwrap()
    }

    /// Runs one managed poll without advancing paused time: `trust_wake` wakes the
    /// trailing `sleep_backoff` immediately, and `with_inhibited_auto_advance` keeps
    /// `MANAGED_SYNC_TIMEOUT` from firing while loopback TCP connects.
    async fn one_poll(h: &Harness) {
        let (acct, epoch) = h
            .store
            .managed_sync_target()
            .expect("managed binding must be live");
        let (_tx, mut rx) = watch::channel(false);
        let mut exp = 0u64;
        let mut pend = 0u64;
        h.trust_wake.notify_one();
        with_inhibited_auto_advance(
            h.sync
                .handle_managed_sync(acct, epoch, &mut rx, &mut exp, &mut pend),
        )
        .await;
    }

    /// Enrolls the test client as a managed device at `epoch`.
    fn enroll(h: &Harness, epoch: u64) {
        h.store
            .begin_managed_pair(client_pk(), "Phone".into(), ACCOUNT, epoch, 0)
            .unwrap();
    }

    /// Lets spawned tasks (the watchdog, the sync loop) run at the current paused instant.
    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn no_lease_after_restart_until_first_active_sync() {
        let h = harness().await;
        enroll(&h, 2);
        let auth_path = h.auth_path.clone();
        let _keep_dir = h.dir;
        drop(h.sync);
        drop(h.push);
        drop(h.store);
        // Reopen from disk: the managed binding survives, but no lease is restored.
        let store = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
        assert!(store.managed_binding().is_some());
        assert!(store.lease_until().is_none());
        assert!(!store.is_session_authorized(&client_pk()));
    }

    #[tokio::test(start_paused = true)]
    async fn active_lease_holds_at_119s_and_withdraws_at_120s_even_with_stalled_sync() {
        let h = harness().await;
        enroll(&h, 2);

        // Bind a minimal loopback QUIC connection (idle timeout disabled so paused time
        // advances only test the lease watchdog) and register it in ConnectionTracker.
        let (server_ep, client_ep, server_conn, client_conn) = with_inhibited_auto_advance(async {
            let tc = iroh::endpoint::QuicTransportConfig::builder()
                .max_idle_timeout(None)
                .build();
            let server_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .alpns(vec![b"test".to_vec()])
                .transport_config(tc.clone())
                .bind()
                .await
                .unwrap();
            let client_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .transport_config(tc)
                .bind()
                .await
                .unwrap();
            let addr = server_ep.addr();
            let (server_res, client_res) = tokio::join!(
                async { server_ep.accept().await.unwrap().await },
                client_ep.connect(addr, b"test"),
            );
            (
                server_ep,
                client_ep,
                server_res.unwrap(),
                client_res.unwrap(),
            )
        })
        .await;
        h.connections.register(client_pk(), server_conn);
        assert!(h.connections.has_connections());

        // Snapshot admits the client; the next sync request is held open by the stub.
        h.stub.script(vec![
            Step::Respond(200, active_body(&[client_pk()])),
            Step::Hold,
            Step::Hold,
        ]);
        one_poll(&h).await;
        assert!(h.store.is_session_authorized(&client_pk()));

        // Start the real watchdog + sync loop and wait until the stalled request reaches the stub.
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = Arc::clone(&h.sync).spawn(shutdown_rx);
        with_inhibited_auto_advance(h.stub.wait_requests(2)).await;

        tokio::time::advance(Duration::from_secs(119)).await;
        settle().await;
        assert!(
            h.store.is_session_authorized(&client_pk()),
            "lease must still hold at +119 s"
        );
        assert!(
            h.connections.has_connections(),
            "connections must remain open at +119 s"
        );
        assert!(client_conn.close_reason().is_none());

        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert!(
            !h.store.is_session_authorized(&client_pk()),
            "lease must be withdrawn by +120 s even though a sync request is pending"
        );
        assert!(h.store.lease_until().is_none());
        assert!(
            !h.connections.has_connections(),
            "close_all_connections must clear tracked connections at +120 s"
        );
        let close_err = with_inhibited_auto_advance(client_conn.closed()).await;
        assert!(
            matches!(
                close_err,
                iroh::endpoint::ConnectionError::ApplicationClosed(ref c)
                    if c.error_code == iroh::endpoint::VarInt::from_u32(CLOSE_UNAUTHORIZED)
            ),
            "expected CLOSE_UNAUTHORIZED on expired lease, got {close_err:?}"
        );
        task.abort();
        with_inhibited_auto_advance(async {
            client_ep.close().await;
            server_ep.close().await;
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_extends_lease_to_request_start_plus_120s() {
        let h = harness().await;
        enroll(&h, 2);
        h.stub.script(vec![
            Step::Respond(200, active_body(&[client_pk()])),
            Step::Respond(200, active_body(&[client_pk()])),
        ]);
        one_poll(&h).await;
        let first = h.store.lease_until().expect("first lease");

        tokio::time::advance(Duration::from_secs(60)).await;
        let request_start = tokio::time::Instant::now();
        one_poll(&h).await;
        let renewed = h.store.lease_until().expect("renewed lease");
        assert!(renewed > first, "renewal must extend the lease");
        assert_eq!(
            renewed,
            request_start + Duration::from_secs(crate::auth::LEASE_SECS),
            "renewed lease is measured from the request start, not the response"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn removed_while_first_pending_revokes_prunes_push_and_never_resurrects() {
        let h = harness().await;
        enroll(&h, 2);
        h.push
            .set_channel_v2(
                client_pk(),
                Some(PushChannelV2 {
                    channel_id: "chan-1".into(),
                    secret: "ab".repeat(32),
                    content_key: Vec::new(),
                    caps: 0,
                }),
            )
            .await
            .unwrap();
        // Without an active lease, delivery is gated off, while the channel stays on disk.
        assert!(h.push.deliverable_channels_v2().is_empty());
        let channels_path = h.dir.path().join("push-channels.json");
        assert!(std::fs::read_to_string(&channels_path)
            .unwrap()
            .contains("chan-1"));

        // Still pending on the cloud (no snapshot yet), then the device is removed.
        h.stub.script(vec![
            Step::Respond(200, pending_body()),
            Step::Respond(200, removed_body()),
        ]);
        one_poll(&h).await;
        assert!(h.store.lease_until().is_none(), "pending grants no lease");
        assert!(std::fs::read_to_string(&channels_path)
            .unwrap()
            .contains("chan-1"));
        one_poll(&h).await;

        assert!(h.store.managed_binding().unwrap().revoked);
        assert!(!h.store.is_session_authorized(&client_pk()));
        assert!(
            h.push.deliverable_channels_v2().is_empty(),
            "push channels must be pruned on revocation"
        );
        assert!(
            !std::fs::read_to_string(&channels_path)
                .unwrap()
                .contains("chan-1"),
            "revocation must prune push-channels.json on disk"
        );
        // Reopen from disk: revocation is durable and the device is not resurrected.
        let auth_path = h.auth_path.clone();
        let _keep_dir = h.dir;
        drop(h.sync);
        drop(h.push);
        drop(h.store);
        let reopened = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
        assert!(reopened.managed_binding().unwrap().revoked);
        assert!(!reopened.is_authorized(&client_pk()));
        assert!(reopened.managed_sync_target().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stale_response_after_epoch_change_is_ignored() {
        let h = harness().await;
        enroll(&h, 2);
        let gate = Arc::new(Notify::new());
        h.stub.script(vec![Step::Gate(
            Arc::clone(&gate),
            200,
            active_body(&[client_pk()]),
        )]);

        let (acct, epoch) = h.store.managed_sync_target().unwrap();
        let sync = Arc::clone(&h.sync);
        let (_tx, mut rx) = watch::channel(false);
        h.trust_wake.notify_one();
        let poll = tokio::spawn(async move {
            let mut exp = 0u64;
            let mut pend = 0u64;
            sync.handle_managed_sync(acct, epoch, &mut rx, &mut exp, &mut pend)
                .await;
        });

        with_inhibited_auto_advance(async {
            h.stub.wait_requests(1).await;
            // Binding moves to epoch 3 while epoch 2's request is in flight.
            enroll(&h, 3);
            gate.notify_one();
            poll.await.unwrap();
        })
        .await;
        assert!(
            h.store.lease_until().is_none(),
            "in-flight response for old epoch must not grant a lease"
        );

        // Also verify the store's own Stale guard directly.
        let outcome = h
            .store
            .apply_managed_sync(
                ACCOUNT,
                2,
                ManagedHostSyncResponse::Active {
                    snapshot: snapshot(&[client_pk()]),
                },
                tokio::time::Instant::now() + Duration::from_secs(crate::auth::LEASE_SECS),
                0,
            )
            .unwrap();
        assert!(matches!(outcome, crate::auth::ManagedSyncOutcome::Stale));
        assert!(h.store.lease_until().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn unauthorized_response_does_not_renew_or_revoke_immediately() {
        let h = harness().await;
        enroll(&h, 2);
        h.stub.script(vec![
            Step::Respond(200, active_body(&[client_pk()])),
            Step::Respond(401, Vec::new()),
            Step::Respond(404, Vec::new()),
        ]);
        one_poll(&h).await;
        let before = h.store.lease_until().expect("lease from first Active");

        for status in ["401", "404"] {
            tokio::time::advance(Duration::from_secs(30)).await;
            one_poll(&h).await;
            assert_eq!(
                h.store.lease_until(),
                Some(before),
                "{status}: must not renew the lease"
            );
            assert!(
                !h.store.managed_binding().unwrap().revoked,
                "{status}: must not revoke immediately"
            );
            assert!(
                h.store.is_session_authorized(&client_pk()),
                "{status}: lease still runs until its own deadline"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn trust_wake_wakes_idle_loop_after_begin_managed_pair() {
        let h = harness().await;
        // No binding yet: the loop parks in its idle wait with no sync target.
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = Arc::clone(&h.sync).spawn(shutdown_rx);
        settle().await;

        // Enrollment fires trust_wake; the loop must start polling without any other signal.
        h.stub.script(vec![Step::Respond(200, pending_body())]);
        enroll(&h, 2);
        h.trust_wake.notify_one();
        with_inhibited_auto_advance(h.stub.wait_requests(1)).await;
        assert!(
            h.stub
                .paths()
                .iter()
                .any(|p| p == cawide_account::MANAGED_HOST_SYNC_PATH),
            "trust_wake must wake the idle loop to poll sync-managed, saw {:?}",
            h.stub.paths()
        );
        task.abort();
    }
}
