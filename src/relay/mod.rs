//! The relay engine (propose.md §3.5 / §3.6 / §3.7) — the core of the gateway.
//!
//! ## Invariants preserved here
//!
//! * **I1 (ordering)**: the server handler awaits each client→backend forward
//!   *inside* the per-packet callback. Because russh invokes those callbacks
//!   serially in arrival order, awaiting inside the callback is exactly the
//!   strict FIFO the design demands — no spawning, no aggregation.
//! * **I2 (want_reply)**: the `want_reply` flag is passed through verbatim;
//!   backend SUCCESS/FAILURE replies are routed back to the originating
//!   callback in FIFO order via [`ReplyRouter`].
//! * **I3 (execution requests)**: emitting a `shell`/`exec`/`subsystem` is the
//!   last thing forwarded; afterwards only data/eof/signal/exit/close flow. The
//!   relay never injects a request of its own.
//! * **I4 (native failures)**: denials use channel/request failure primitives;
//!   the relay never fabricates exec output or exit codes.
//!
//! ## Memory bound (§3.6)
//!
//! The authoritative uplink bound is russh's client-channel window
//! (`ChannelWriteHalf::data_bytes` blocks when the send window is exhausted —
//! the "#7 components" of `crate::relay::tests::outbound_window` cover the
//! case). [`OutboundWindow`] *Calibration-free* storm-drain: it mirrors the
//! backend's advertised send window and blocks lavishly in the `data` callback
//! before bytes ever enter the buffer, so gateway memory stays bounded even if
//! the library's internal behaviour changes.

use std::sync::Mutex;

use tokio::sync::{oneshot, Notify};

use russh::client::Msg as ClientMsg;
use russh::{ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};

use crate::audit::ByteCounters;
use crate::metrics::Metrics;
use crate::types::Grant;

/// Backend channel's writable half, used to forward client requests + data.
pub type BackendWriter = ChannelWriteHalf<ClientMsg>;
/// Backend channel's readable half, consumed by the down-pump (non-generic).
pub type BackendReader = ChannelReadHalf;

/// FIFO router matching backend SUCCESS/FAILURE replies to the `want_reply`
/// requests that produced them (I2). Only `want_reply=true` forwards enqueue a
/// slot, because only those generate a reply — so the queue stays aligned one
/// slot per outstanding reply-bearing request.
#[derive(Clone, Default)]
pub struct ReplyRouter {
    queue: std::sync::Arc<Mutex<VecDeque<oneshot::Sender<bool>>>>,
}

impl ReplyRouter {
    /// Enqueue a reply slot for a forwarded request.
    ///
    /// Returns the receiver the originating callback awaits when `want_reply` is
    /// set; returns `None` (and enqueues nothing) when `want_reply` is false, so
    /// the backend won't emit a reply.
    pub fn push(&self, want_reply: bool) -> Option<oneshot::Receiver<bool>> {
        if !want_reply {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        self.lock().push_back(tx);
        Some(rx)
    }

    /// Deliver a backend reply (`true` = SUCCESS, `false` = FAILURE) to the
    /// oldest outstanding request. Extra replies (protocol anomalies) are
    /// dropped rather than panicking.
    pub fn settle(&self, success: bool) {
        if let Some(tx) = self.lock().pop_front() {
            let _ = tx.send(success);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<oneshot::Sender<bool>>> {
        match self.queue.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Number of request slots currently outstanding (used by tests).
    pub fn pending(&self) -> usize {
        self.lock().len()
    }
}

use std::collections::VecDeque;

/// Per-channel uplink fuse mirroring the backend send window (§3.6, D5).
///
/// It starts *uncalibrated* (`u32::MAX` permits) so it never blocks before the
/// backend has told us its real window via the first `WINDOW_ADJUST`; from then
/// on it mirrors the backend's advertised available window and blocks the
/// `data` callback when the window is exhausted. Backpressure therefore never
/// regresses throughput and still guarantees a hard in-gateway ceiling.
pub struct OutboundWindow {
    available: Mutex<u32>,
    notify: Notify,
}

impl OutboundWindow {
    /// An uncalibrated window that never blocks until first calibrated.
    pub fn uncalibrated() -> Self {
        OutboundWindow {
            available: Mutex::new(u32::MAX),
            notify: Notify::new(),
        }
    }

    /// Whether a send of `n` bytes would currently exceed the available window.
    pub fn would_exhaust(&self, n: usize) -> bool {
        let available = self.load();
        (n as u64) > available as u64
    }

    /// Block until at least `n` permits are available, then consume them.
    pub async fn acquire(&self, n: usize) {
        loop {
            let notified = {
                let mut available = self.lock();
                if (n as u64) <= (*available) as u64 {
                    *available = available.saturating_sub(n as u32);
                    return;
                }
                self.notify.notified()
            };
            notified.await;
        }
    }

    /// Apply a backend `WINDOW_ADJUST` carrying the new absolute available
    /// window (russh reports the absolute size, not a delta).
    pub fn note_window(&self, new_available: u32) {
        {
            let mut available = self.lock();
            *available = new_available;
        }
        self.notify.notify_waiters();
    }

    fn load(&self) -> u32 {
        *self.lock()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, u32> {
        match self.available.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Decision returned by a [`SubsystemInterceptor`] (propose.md §3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the request unchanged (the M1 default fast path).
    Pass,
    /// Deny the request locally with this user-facing reason.
    Deny(String),
    /// Forward and additionally tap the data stream (M3 recording/audit).
    Tap,
}

/// Relay-layer hook for SFTP/subsystem inspection. The default implementation,
/// [`PassThroughInterceptor`], takes the zero-cost `Pass` fast path (no lock, no
/// allocation); the richer `Tap` implementation is an M3 deliverable.
///
/// The method returns a boxed future so the trait is object-safe and can be
/// stored as `Arc<dyn SubsystemInterceptor>`.
pub trait SubsystemInterceptor: Send + Sync {
    fn on_subsystem_request<'a>(
        &'a self,
        name: &'a str,
        grant: &'a Grant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>>;
}

/// The M1 interceptor: pass everything through with no overhead.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThroughInterceptor;

impl SubsystemInterceptor for PassThroughInterceptor {
    fn on_subsystem_request<'a>(
        &'a self,
        _name: &'a str,
        _grant: &'a Grant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move { Verdict::Pass })
    }
}

/// All per-channel relay state shared between the request path (handler
/// callbacks) and the down-pump.
pub struct ChannelRelay {
    /// Client-side channel id (the map key).
    pub client_id: ChannelId,
    /// Writable half of the backend channel (client → backend).
    pub backend: BackendWriter,
    /// FIFO router for want_reply replies (I2).
    pub router: ReplyRouter,
    /// Uplink window fuse (§3.6).
    pub window: std::sync::Arc<OutboundWindow>,
    /// Shared up/down byte counters (fed to the audit record).
    pub bytes: std::sync::Arc<ByteCounters>,
    metrics: Metrics,
}

impl ChannelRelay {
    pub fn new(
        client_id: ChannelId,
        backend: BackendWriter,
        router: ReplyRouter,
        window: std::sync::Arc<OutboundWindow>,
        bytes: std::sync::Arc<ByteCounters>,
        metrics: Metrics,
    ) -> Self {
        ChannelRelay {
            client_id,
            backend,
            router,
            window,
            bytes,
            metrics,
        }
    }

    /// Whether the fuse is currently exhausted for `n` bytes (records the
    /// `window_exhausted_total` metric as a side-channel signal).
    pub fn note_would_exhaust(&self, n: usize) {
        if self.window.would_exhaust(n) {
            self.metrics.window_exhausted();
        }
    }
}

/// The down-pump: backend → client. Runs as a detached task and is the only
/// place backend-originated messages are turned into client-originated ones.
///
/// `up` is the server session handle for the client leg, `router` routes
/// SUCCESS/FAILURE back to the originating callbacks, `window` is replenished by
/// `WINDOW_ADJUST`, and `bytes` tallies traffic for the audit record.
pub async fn pump_backend_to_client(
    mut backend: BackendReader,
    up: russh::server::Handle,
    client_id: ChannelId,
    router: ReplyRouter,
    window: std::sync::Arc<OutboundWindow>,
    bytes: std::sync::Arc<ByteCounters>,
) {
    while let Some(msg) = backend.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                let n = data.len();
                if up.data(client_id, data).await.is_err() {
                    break;
                }
                bytes.add_down(n);
            }
            ChannelMsg::ExtendedData { data, ext } => {
                let n = data.len();
                if up.extended_data(client_id, ext, data).await.is_err() {
                    break;
                }
                bytes.add_down(n);
            }
            ChannelMsg::Success => router.settle(true),
            ChannelMsg::Failure => router.settle(false),
            ChannelMsg::WindowAdjusted { new_size } => window.note_window(new_size),
            ChannelMsg::ExitStatus { exit_status } => {
                let _ = up.exit_status_request(client_id, exit_status).await;
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                let _ = up
                    .exit_signal_request(
                        client_id,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )
                    .await;
            }
            ChannelMsg::Eof => {
                let _ = up.eof(client_id).await;
            }
            ChannelMsg::Close => {
                let _ = up.close(client_id).await;
                break;
            }
            other => {
                tracing::debug!(target: "relay", ?client_id, ?other, "unhandled backend channel message");
            }
        }
    }
    // Backend channel ended: close the coupled client channel (§3.5 coupled
    // close). No fabricated exit status is injected (I4).
    let _ = up.close(client_id).await;
}

/// Forward an `exec` request (raw command bytes), enqueuing the reply slot
/// *before* the send (I2). Returns the receiver the request-path driver awaits.
pub async fn forward_exec(
    relay: &ChannelRelay,
    want_reply: bool,
    command: &[u8],
) -> Result<Option<oneshot::Receiver<bool>>, String> {
    let rx = relay.router.push(want_reply);
    relay
        .backend
        .exec(want_reply, command.to_vec())
        .await
        .map_err(|e| e.to_string())?;
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn reply_router_matches_fifo_and_drops_extras() {
        let router = ReplyRouter::default();
        let mut a = router.push(true).unwrap();
        let mut b = router.push(true).unwrap();
        let mut c = router.push(true).unwrap();
        assert_eq!(router.pending(), 3);

        // want_reply=false enqueues nothing.
        assert!(router.push(false).is_none());
        assert_eq!(router.pending(), 3);

        // Replies are delivered strictly FIFO.
        router.settle(false); // → a
        router.settle(true); // → b
        assert!(!a.try_recv().unwrap(), "first reply must be a FAILURE");
        assert!(b.try_recv().unwrap(), "second reply must be a SUCCESS");
        router.settle(true); // → c

        // A fourth reply with no matching request is dropped, not a panic.
        router.settle(true);
        assert_eq!(router.pending(), 0);
        // `c` was settled exactly once.
        assert!(c.try_recv().unwrap(), "third reply must be a SUCCESS");
    }

    #[tokio::test]
    async fn uncalibrated_window_never_blocks() {
        let w = OutboundWindow::uncalibrated();
        // An uncalibrated window must not block a large send.
        w.acquire(1_000_000).await;
        assert!(!w.would_exhaust(10));
    }

    #[tokio::test]
    async fn window_acquire_blocks_until_adjust_then_resumes() {
        let w = std::sync::Arc::new(OutboundWindow::uncalibrated());
        w.note_window(5);
        w.acquire(5).await; // drains the window
        assert!(w.would_exhaust(1));

        let probe = {
            let w = w.clone();
            tokio::spawn(async move { w.acquire(4).await })
        };
        tokio::task::yield_now().await;
        assert!(
            !probe.is_finished(),
            "acquire should block on an exhausted window"
        );

        // A WINDOW_ADJUST replenishes and unblocks.
        w.note_window(10);
        tokio::time::timeout(Duration::from_secs(1), probe)
            .await
            .expect("acquire unblocks after window adjust")
            .expect("task join");
    }

    #[tokio::test]
    async fn window_note_sets_absolute_not_incremental() {
        let w = OutboundWindow::uncalibrated();
        w.note_window(100);
        w.acquire(40).await;
        // An absolute adjust replaces our accounting with the backend's truth.
        w.note_window(7);
        assert!(!w.would_exhaust(7));
        assert!(w.would_exhaust(8));
    }

    #[tokio::test]
    async fn passthrough_interceptor_always_passes() {
        let interceptor = PassThroughInterceptor;
        let grant = crate::types::Grant {
            principal: crate::types::Principal::parse("alex_host1").unwrap(),
            fingerprint: crate::types::Fingerprint::new("SHA256:fp"),
            target: crate::types::Target {
                host: "h".into(),
                port: 22,
                user: "root".into(),
            },
            policy: crate::types::Policy::default(),
        };
        assert_eq!(
            interceptor.on_subsystem_request("sftp", &grant).await,
            Verdict::Pass
        );
    }
}
