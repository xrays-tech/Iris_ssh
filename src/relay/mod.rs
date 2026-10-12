//! The relay engine (propose.md §3.5 / §3.6 / §3.7) — the core of the gateway.
//!
//! ## Invariants preserved here
//!
//! * **I1 (ordering)**: the server handler awaits each client→backend forward
//!   *inside* the per-packet callback. Because russh invokes those callbacks
//!   serially in arrival order, awaiting inside the callback is exactly the
//!   strict FIFO the design demands — no spawning, no aggregation.
//!   Agent-passthrough mode (C2) is the one documented exception: it keeps the
//!   same FIFO by handing every op to a **single** per-session consumer, and is
//!   authorised by propose.md §3.5.1.
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
//! (`ChannelWriteHalf::data_bytes` blocks when the send window is exhausted).
//! [`OutboundWindow`] is the defense-in-depth fuse the design mandates
//! (§3.6 / D5) — it mirrors the backend's advertised send window with a
//! `tokio::sync::Semaphore` and blocks the `data` callback *before* bytes enter
//! the pipeline, so gateway memory stays bounded even if the library's internal
//! buffering behaviour changes. Because a semaphore is a *fair, wake-free-by-
//! construction* primitive — `add_permits`/`acquire` hand the waiter its permit
//! atomically rather than relying on a `Notified` that is only registered on
//! first poll — the "wake-up lost in the lock-release → first-poll window" race
//! that plagued a hand-rolled `Mutex + Notify` fuse cannot happen here.
//!
//! ## Liveness coupling (§3.5 / P0-2)
//!
//! The down-pump owns the *only* reader of the backend channel. When it ends
//! (backend died, `Close`, or the client leg broke) it calls
//! [`OutboundWindow::close`], which wakes every blocked `acquire` with an error
//! so the server's serial `data` callback can never wedge the whole session on
//! a dead backend. On an *abnormal* backend death the pump additionally sends
//! the client a protocol-level `SSH_MSG_DISCONNECT[BY_APPLICATION]` goodbye
//! (§3.8 destroy semantics) instead of a silent TCP reset.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;

use tokio::sync::{oneshot, Semaphore};

use russh::client::Msg as ClientMsg;
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf};

/// Agent-passthrough supervisor (C2): the one documented exception to the
/// "everything happens inside the serial handler callback" rule, authorised by
/// propose.md §3.5.1 and unreachable unless the agent kill-switch is on.
pub mod agent;

/// Re-exported so callers can name the type without depending on `russh`'s path.
pub use russh::ChannelId;

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

/// Returned by [`OutboundWindow::acquire`] when the window has been closed —
/// i.e. the backend connection is gone and no further uplink bytes can flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowClosed;

impl std::fmt::Display for WindowClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("uplink window closed (backend connection lost)")
    }
}

impl std::error::Error for WindowClosed {}

/// The permit ceiling an *uncalibrated* window starts with. `u32::MAX` is far
/// below tokio's `Semaphore::MAX_PERMITS` on 64-bit, and in practice a send is
/// bounded by the negotiated max packet size, so this never over-reserves.
const WINDOW_PERMIT_CEILING: u32 = u32::MAX;

/// Description advertised to the client when the backend connection is lost
/// (propose §3.8 destroy semantics).
pub const BACKEND_LOST_MESSAGE: &str = "backend connection lost, please retry";

/// Per-channel uplink fuse mirroring the backend send window (§3.6, D5).
///
/// It starts *uncalibrated* (`WINDOW_PERMIT_CEILING` permits) so it never blocks
/// before the backend has told us its real window; from then on it mirrors the
/// backend's advertised available window and blocks the `data` callback when
/// exhausted. [`close`](OutboundWindow::close) permanently unblocks and rejects
/// every waiter.
pub struct OutboundWindow {
    /// Available uplink permits, mirroring the backend send window.
    sem: Semaphore,
    /// Set once the backend is known-dead; checked before mutating the
    /// semaphore so a closed fuse never issues further `add`/`forget`.
    closed: AtomicBool,
}

impl OutboundWindow {
    /// An uncalibrated window that never blocks until first calibrated.
    pub fn uncalibrated() -> Self {
        OutboundWindow {
            sem: Semaphore::new(WINDOW_PERMIT_CEILING as usize),
            closed: AtomicBool::new(false),
        }
    }

    /// Whether a send of `n` bytes would currently exceed the available window.
    pub fn would_exhaust(&self, n: usize) -> bool {
        (n as u64) > self.sem.available_permits() as u64
    }

    /// Block until at least `n` permits are available, then consume them.
    ///
    /// Returns [`WindowClosed`] as soon as the window is closed, so a dead
    /// backend can never leave a caller awaiting forever.
    pub async fn acquire(&self, n: usize) -> Result<(), WindowClosed> {
        // Early exit: a closed window rejects immediately (no permit churn).
        if self.is_closed() {
            return Err(WindowClosed);
        }
        // An empty send needs no budget.
        if n == 0 {
            return Ok(());
        }
        let wanted = n as u32;
        match self.sem.acquire_many(wanted).await {
            // Consume the permits permanently: the window is recalibrated only
            // by an explicit `note_window`, never by the caller releasing.
            Ok(permit) => {
                permit.forget();
                if self.is_closed() {
                    // Closed while we were waiting: the permits we just took are
                    // gone for good, but the caller must not proceed.
                    return Err(WindowClosed);
                }
                Ok(())
            }
            // The semaphore was closed while we were waiting.
            Err(_) => Err(WindowClosed),
        }
    }

    /// Apply a backend `WINDOW_ADJUST`.
    ///
    /// russh reports the **absolute** remaining send window — `new_size` is the
    /// cumulative `recipient_window_size + amount`, less what was just flushed
    /// (client `encrypted.rs`) — i.e. exactly how many bytes may be sent *now*.
    /// So the fuse must **set** its free-permit count to that absolute value, not
    /// apply a delta on top of what this window already handed out. Doing the
    /// latter silently subtracts every in-flight acquisition from each report and
    /// drives the free count to zero under sustained load, wedging `data`.
    ///
    /// Permits currently held by in-flight `acquire`s are *not* part of
    /// `available_permits()`, so correcting against that value converges on the
    /// backend's truth regardless of how much is in flight. Idempotent and
    /// race-free because the semaphore — not a hand-rolled notify — holds the
    /// waiters.
    pub fn note_window(&self, new_available: u32) {
        // A closed fuse must never be replenished.
        if self.is_closed() {
            return;
        }
        let current = self.sem.available_permits() as u64;
        let target = u64::from(new_available);
        if target > current {
            self.sem.add_permits((target - current) as usize);
        } else if target < current {
            self.sem.forget_permits((current - target) as usize);
        }
    }

    /// Permanently close the window: every pending and future `acquire` returns
    /// [`WindowClosed`]. Called by the down-pump as soon as the backend channel
    /// ends, so a dead backend cannot wedge the server's serial `data` callback.
    pub fn close(&self) {
        // Ordering matters: flip our own flag first so `note_window` can never
        // touch the semaphore after it is closed.
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // already closed — idempotent
        }
        // Wakes every waiter with an `AcquireError`; subsequent acquires fail
        // fast on the `closed` flag above.
        self.sem.close();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Decision returned by a [`SubsystemInterceptor`] (propose.md §3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the request unchanged (the M1 default fast path).
    Pass,
    /// Deny the request locally with this user-facing reason.
    Deny(String),
    /// Forward and additionally observe the channel's data (M3 recording/audit).
    Tap,
}

/// Which way a captured buffer is travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client → backend.
    Up,
    /// Backend → client.
    Down,
}

/// What a [`ChannelTap`] decided to do with a captured buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataVerdict {
    /// Forward the buffer unchanged — the zero-cost fast path.
    Pass,
    /// Withhold or rewrite the buffer, optionally injecting bytes back to the
    /// *client* (e.g. a synthesized `SSH_FXP_STATUS` failure).
    Rewrite {
        /// Bytes to forward; may be empty when the whole buffer is withheld.
        forward: Vec<u8>,
        /// Bytes to send back the other way (never part of `forward`).
        inject: Vec<u8>,
        /// Why something was withheld, for logging/metrics.
        denied: Option<String>,
    },
}

/// Per-channel identity handed to tap implementations, so a recorder or
/// inspector can name and label its output without borrowing the session.
#[derive(Debug, Clone)]
pub struct ChannelCtx {
    pub session_id: String,
    pub channel_id: ChannelId,
    pub principal: String,
    pub command_class: crate::audit::CommandClass,
    /// Whether the grant asked for this session to be recorded.
    pub record: bool,
}

/// A per-channel data observer created by a [`SubsystemInterceptor`].
///
/// `on_data` is only ever called on a channel whose verdict was
/// [`Verdict::Tap`], so the pass-through path pays nothing. `flush` runs once when
/// the channel ends so a recorder can close its file deterministically rather
/// than relying on `Drop` ordering inside a spawned task.
pub trait ChannelTap: Send + Sync {
    fn on_data(&self, dir: Direction, buf: &[u8]) -> DataVerdict;
    fn flush(&self) {}
}

/// Relay-layer hook for SFTP/subsystem inspection. The default implementation,
/// [`PassThroughInterceptor`], takes the zero-cost `Pass` fast path (no lock, no
/// allocation).
///
/// The method returns a boxed future so the trait is object-safe and can be
/// stored as `Arc<dyn SubsystemInterceptor>`.
pub trait SubsystemInterceptor: Send + Sync {
    fn on_subsystem_request<'a>(
        &'a self,
        name: &'a str,
        grant: &'a Grant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>>;

    /// Create the per-channel data observer for a channel the interceptor wants
    /// to watch. The default returns `None` (no tap), which is what keeps the
    /// plain-transmission path free of both allocation and locking.
    fn observe(&self, _ctx: &ChannelCtx) -> Option<Arc<dyn ChannelTap>> {
        None
    }
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

/// Why the down-pump stopped relaying a channel.
///
/// The only distinction that drives behaviour is *backend lost vs. not*, but it
/// is expressed as an enum rather than by comparing sentinel strings. A previous
/// revision keyed the abnormal-exit decision off the fact that two near-identical
/// strings (`"backend channel closed"` and `"backend closed channel"`) did **not**
/// compare equal — a fragile coupling where any rewording silently flips a
/// normal close into (or out of) the backend-loss path. Here the normal teardown
/// case is a distinct variant, so that class of bug cannot compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The backend closed this channel normally (the command finished / the
    /// backend ended its side). Quiet: no fabricated reason, no session disconnect.
    BackendChannelClosed,
    /// The client leg broke (the `up.data(...)` write failed) — the *client*
    /// went away, so a session-wide DISCONNECT would be pointless.
    ClientWriteFailed,
    /// The backend channel stream ended without a `Close` message: the backend
    /// connection died rather than the command finishing (§3.8 loss).
    BackendLost,
}

impl StopReason {
    /// Whether this stop means the backend connection was lost — the only case
    /// that warrants the ERROR log, the reason metric and a DISCONNECT(11).
    pub fn is_backend_lost(self) -> bool {
        matches!(self, StopReason::BackendLost)
    }

    /// Stable label for logs and the audit trail.
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::BackendChannelClosed => "backend closed channel",
            StopReason::ClientWriteFailed => "client leg write failed",
            StopReason::BackendLost => "backend connection lost",
        }
    }
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The down-pump: backend → client. Runs as a detached task and is the only
/// place backend-originated messages are turned into client-originated ones.
///
/// `up` is the server session handle for the client leg, `router` routes
/// SUCCESS/FAILURE back to the originating callbacks, `window` is replenished by
/// `WINDOW_ADJUST`, and `bytes` tallies traffic for the audit record.
///
/// **Liveness coupling (P0-2 / P1-3):** this task owns the only reader of the
/// backend channel, so it is the authority on whether the backend is alive. On
/// every exit path it calls [`OutboundWindow::close`], which wakes any `data`
/// callback blocked on an exhausted window. On an *abnormal* exit — the backend
/// channel ended without a `Close` message, i.e. the connection died rather than
/// the command finishing — it additionally tells the whole client leg goodbye
/// with `SSH_MSG_DISCONNECT[BY_APPLICATION]` (§3.8 destroy semantics) and logs
/// the reason at ERROR, instead of leaving the client staring at a silent close.
#[allow(clippy::too_many_arguments)]
pub async fn pump_backend_to_client(
    mut backend: BackendReader,
    up: russh::server::Handle,
    client_id: ChannelId,
    router: ReplyRouter,
    window: std::sync::Arc<OutboundWindow>,
    bytes: std::sync::Arc<ByteCounters>,
    metrics: Metrics,
    tap: Option<Arc<dyn ChannelTap>>,
) {
    // Why we are stopping. Starts as `BackendLost`, which is exactly the case of
    // reaching the end of the loop with `wait()` having returned `None` and no
    // `Close` message having arrived: the backend *connection* died rather than
    // the command finishing. Every exit path overwrites it with the true cause.
    let mut stop_reason = StopReason::BackendLost;

    while let Some(msg) = backend.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                // B2/B3: a downlink tap may withhold or rewrite the payload
                // (e.g. an SFTP denial response injected back to the client).
                // The owned `Bytes` russh handed us is forwarded as-is whenever
                // the tap passes it through (zero-copy).
                let (payload, inject) = apply_tap_down(tap.as_ref(), data, client_id);
                let n = payload.len();
                if !inject.is_empty() && up.data(client_id, inject).await.is_err() {
                    stop_reason = StopReason::ClientWriteFailed;
                    break;
                }
                if !payload.is_empty() && up.data(client_id, payload).await.is_err() {
                    stop_reason = StopReason::ClientWriteFailed;
                    break;
                }
                bytes.add_down(n);
            }
            ChannelMsg::ExtendedData { data, ext } => {
                let (payload, inject) = apply_tap_down(tap.as_ref(), data, client_id);
                let n = payload.len();
                if !inject.is_empty() && up.extended_data(client_id, ext, inject).await.is_err() {
                    stop_reason = StopReason::ClientWriteFailed;
                    break;
                }
                if !payload.is_empty() && up.extended_data(client_id, ext, payload).await.is_err() {
                    stop_reason = StopReason::ClientWriteFailed;
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
                // Normal channel teardown (the command finished / the backend
                // closed its side): no fabricated reason, no session-wide
                // disconnect (I4).
                stop_reason = StopReason::BackendChannelClosed;
                let _ = up.close(client_id).await;
                break;
            }
            other => {
                tracing::debug!(target: "relay", ?client_id, ?other, "unhandled backend channel message");
            }
        }
    }

    if stop_reason.is_backend_lost() {
        // Audit trail + metric for the disconnect-reason histogram (§3.8).
        metrics.backend_lost();
        metrics.disconnect_reason(11); // SSH_DISCONNECT_BY_APPLICATION
        tracing::error!(
            target: "relay",
            ?client_id,
            reason = %stop_reason,
            "backend connection lost; disconnecting client leg"
        );
        // §3.8 destroy semantics: tell the client *why*, with a protocol-level
        // goodbye rather than a silent close / TCP reset.
        let _ = up
            .disconnect(
                russh::Disconnect::ByApplication,
                BACKEND_LOST_MESSAGE.to_owned(),
                "en".to_owned(),
            )
            .await;
    }

    // Always: close the coupled client channel (§3.5 coupled close) and, above
    // all, unblock any `data` callback awaiting this window (P0-2). Without the
    // close, a backend that died mid-send would wedge the server's serial event
    // loop until the (configurable) inactivity timeout fires.
    let _ = up.close(client_id).await;
    if let Some(tap) = &tap {
        // B2: flush/close the recording deterministically at channel end rather
        // than relying on Drop ordering inside this task.
        tap.flush();
    }
    window.close();
}

/// Run a downlink buffer through the channel tap, returning `(forward, inject)`.
///
/// When there is no tap (the default) or the tap verdicts `Pass`, the original
/// owned `Bytes` is forwarded unchanged with zero allocation or copy. Only a
/// `Rewrite` verdict allocates (the tap already owns its `Vec<u8>` payloads).
///
/// Takes the owned `Bytes` russh's down-pump already holds, so the untapped
/// fast path crosses to the client leg without a second buffer.
pub fn apply_tap_down(
    tap: Option<&Arc<dyn ChannelTap>>,
    data: Bytes,
    client_id: ChannelId,
) -> (Bytes, Bytes) {
    let Some(tap) = tap else {
        return (data, Bytes::new()); // zero-copy: forward the owned buffer as-is
    };
    match tap.on_data(Direction::Down, &data) {
        DataVerdict::Pass => (data, Bytes::new()),
        DataVerdict::Rewrite {
            forward,
            inject,
            denied,
        } => {
            if let Some(reason) = denied {
                tracing::info!(target: "relay", ?client_id, %reason, "downlink data withheld by tap");
            }
            (Bytes::from(forward), Bytes::from(inject))
        }
    }
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
    fn stop_reason_classifies_backend_loss_explicitly() {
        // The pump's abnormal-vs-normal decision must come from the variant, not
        // from how two similar strings happen to compare.
        assert!(
            !StopReason::BackendChannelClosed.is_backend_lost(),
            "a normal backend Close must never be treated as backend loss"
        );
        assert!(
            !StopReason::ClientWriteFailed.is_backend_lost(),
            "the client going away is not a backend loss"
        );
        assert!(
            StopReason::BackendLost.is_backend_lost(),
            "the backend connection dying must be classified as a loss"
        );
    }

    #[test]
    fn stop_reason_labels_are_all_distinct() {
        // Guards against the failure mode this enum replaced: near-identical
        // sentinel strings whose equality (or inequality) carried meaning.
        use std::collections::HashSet;
        let all = [
            StopReason::BackendChannelClosed,
            StopReason::ClientWriteFailed,
            StopReason::BackendLost,
        ];
        let labels: HashSet<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            labels.len(),
            all.len(),
            "stop reasons must have distinct labels"
        );
        for reason in all {
            assert_eq!(
                reason.to_string(),
                reason.as_str(),
                "Display must match as_str"
            );
        }
    }

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
        w.acquire(1_000_000).await.expect("uncalibrated acquire");
        assert!(!w.would_exhaust(10));
    }

    #[tokio::test]
    async fn acquire_takes_zero_bytes_without_blocking() {
        let w = OutboundWindow::uncalibrated();
        w.note_window(0); // fully exhaust it
        w.acquire(0)
            .await
            .expect("a zero-length send needs no budget");
    }

    #[tokio::test]
    async fn window_acquire_blocks_until_replenish_then_resumes() {
        let w = std::sync::Arc::new(OutboundWindow::uncalibrated());
        w.note_window(5);
        w.acquire(5).await.expect("drain the window");
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

        // A WINDOW_ADJUST replenishes the window (add-permits) and unblocks the
        // waiter — with no reliance on a `Notified` being registered in time.
        w.note_window(10);
        tokio::time::timeout(Duration::from_secs(1), probe)
            .await
            .expect("acquire unblocks after window adjust")
            .expect("task join")
            .expect("acquire succeeds once permits arrive");
    }

    #[tokio::test]
    async fn window_note_sets_absolute_remaining_window() {
        // russh reports the ABSOLUTE remaining send window, so the fuse sets its
        // free permits to that value — in-flight acquisitions must not be
        // double-subtracted (that regression wedged `data` under sustained load).
        let w = OutboundWindow::uncalibrated();
        w.note_window(2_000_000); // initial window the backend advertised
        w.acquire(40).await.expect("send 40");
        // The backend consumed and acked: it now reports 1_500_000 absolute
        // remaining. The 40 already in flight must NOT be subtracted again.
        w.note_window(1_500_000);
        w.acquire(1_499_990)
            .await
            .expect("the full remaining window is sendable");
        // 10 bytes of the reported window remain free.
        assert!(!w.would_exhaust(10));
        assert!(w.would_exhaust(11));
    }

    #[tokio::test]
    async fn window_note_can_grow_the_free_budget() {
        let w = OutboundWindow::uncalibrated();
        w.note_window(1000);
        w.acquire(900).await.expect("send 900");
        w.note_window(4000); // backend opened much more window
        assert!(!w.would_exhaust(4000));
        w.acquire(4000)
            .await
            .expect("the widened window is fully usable");
    }

    #[tokio::test]
    async fn repeated_note_window_is_idempotent_not_cumulative() {
        let w = OutboundWindow::uncalibrated();
        w.note_window(100);
        w.note_window(100); // same absolute report repeated
        w.note_window(100);
        assert!(!w.would_exhaust(100), "a repeat must not add permits again");
        assert!(w.would_exhaust(101));
    }

    #[tokio::test]
    async fn window_note_shrink_is_clamped_and_never_panics() {
        let w = OutboundWindow::uncalibrated();
        w.note_window(100);
        w.acquire(90).await.expect("send 90");
        // Real windows only grow, but a backwards report must clamp rather than
        // underflow or panic: the free count tracks the reported absolute value.
        w.note_window(5);
        assert!(!w.would_exhaust(5), "the reported 5 bytes are all sendable");
        assert!(w.would_exhaust(6));
    }

    #[tokio::test]
    async fn close_unblocks_a_waiting_acquire() {
        // P0-2 core: a backend that dies while `data()` awaits window must not
        // freeze the channel. Closing the window must wake the waiter with an
        // error, deterministically, on the first try.
        let w = std::sync::Arc::new(OutboundWindow::uncalibrated());
        w.note_window(4);
        w.acquire(4).await.expect("drain the window");

        let probe = {
            let w = w.clone();
            tokio::spawn(async move { w.acquire(1).await })
        };
        tokio::task::yield_now().await;
        assert!(!probe.is_finished(), "acquire must block while exhausted");

        // Backend died → pump closes the window.
        w.close();
        let outcome = tokio::time::timeout(Duration::from_secs(1), probe)
            .await
            .expect("close must wake the waiter")
            .expect("task join");
        assert_eq!(outcome, Err(WindowClosed));
    }

    #[tokio::test]
    async fn closed_window_rejects_new_acquires_and_ignores_windows() {
        let w = OutboundWindow::uncalibrated();
        w.close();
        assert_eq!(w.acquire(1).await, Err(WindowClosed));
        // A late WINDOW_ADJUST must not resurrect a closed window.
        w.note_window(u32::MAX);
        assert_eq!(w.acquire(1).await, Err(WindowClosed));
        // Closing twice is idempotent.
        w.close();
        assert!(w.is_closed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_blocked_waiters_are_all_woken_by_incremental_replenish() {
        // P0-1 stress: this is exactly the race the oracle flagged in the old
        // hand-rolled fuse. `N` tasks block on an exhausted window; the window is
        // then fed one permit at a time (each `WINDOW_ADJUST` adds exactly one
        // permit, so exactly one waiter must be released). If any wakeup were
        // lost between "lock released" and "first poll", the corresponding task
        // would hang forever and the timeout would fire. The semaphore hands the
        // permit to a registered waiter atomically, so it cannot be lost.
        let w = std::sync::Arc::new(OutboundWindow::uncalibrated());
        w.note_window(0); // fully exhausted

        let waiters = 50usize;
        let woken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::with_capacity(waiters);
        for _ in 0..waiters {
            let w = std::sync::Arc::clone(&w);
            let woken = std::sync::Arc::clone(&woken);
            tasks.push(tokio::spawn(async move {
                w.acquire(1).await.expect("window must not close mid-wait");
                woken.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }));
        }
        // Let every task reach the blocking `acquire` before we start feeding.
        tokio::time::sleep(Duration::from_millis(20)).await;

        for k in 1..=(waiters as u32) {
            w.note_window(k); // +1 permit → must wake exactly one waiter
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        for t in tasks {
            tokio::time::timeout(Duration::from_secs(5), t)
                .await
                .expect("a waiter was stranded — the window lost a wakeup")
                .expect("task join");
        }
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), waiters);
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
