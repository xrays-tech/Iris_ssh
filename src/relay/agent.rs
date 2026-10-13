//! Agent-passthrough supervisor (plan-agent-passthrough C2, propose.md §3.5.1).
//!
//! This is the only backend data path left: the gateway authenticates to the
//! backend as the **user**, by asking the user's own ssh-agent to sign — the
//! `ssh -A` semantic. The private key never leaves the client; the gateway only
//! relays agent messages.
//!
//! # Why this is a separate task
//!
//! Everything the agent leg needs — opening the agent channel towards the
//! client, speaking the agent protocol, and the backend handshake that asks for
//! signatures — is `await` work that must run *on top of* the client's session
//! event loop. Doing that inside a handler callback would block russh's single
//! serial loop and deadlock it (D11). So the work is lifted into one
//! **per-session supervisor task** (propose.md §3.5.1), and the handler only
//! enqueues.
//!
//! # One connection, many channels
//!
//! The supervisor owns exactly **one** authenticated backend `Handle` and a
//! `HashMap<ChannelId, Arc<ChannelRelay>>` describing every client channel that
//! has been mapped onto it. A new client channel is an [`AgentOpKind::OpenChannel`]
//! that opens a *further* session channel on the same backend connection; each
//! gets its own relay, its own uplink window and its own down-pump. I1 is
//! therefore **per-channel FIFO**: ops for one channel are applied in enqueue
//! order, cross-channel order is not an invariant.
//!
//! The four qualifiers of §3.5.1 are enforced structurally here:
//!
//! * **one FIFO consumer** — a session owns exactly one
//!   [`mpsc::Sender<AgentOp>`] and one supervisor; ops are applied strictly in
//!   enqueue order, so I1 holds per channel and no request is ever reordered or
//!   injected.
//! * **handler never blocks while dialing** — while the state is
//!   [`STATE_DIALING`] the handler uses `try_send`; a full queue fails the
//!   channel natively instead of awaiting (C5). The supervisor drains that
//!   queue *during* the dial (into [`DialStash`]) so it cannot fill under a
//!   fast producer in the first place, and `Handler::adjust_window` collapses
//!   the client's uplink window for the same reason, which is what keeps the
//!   stash itself bounded by the relay window. Once [`STATE_READY`] the
//!   handler's `send().await` is the same backpressure the inline path applies,
//!   and the queue's slot count bounds the bytes it can hold.
//! * **failures are protocol-native** — every exit path answers pending
//!   requests with `channel_failure` and closes the client channels it accepted;
//!   it never falls back to the gateway's own key or certificate (red line 3).
//! * **minimal signing surface** — the forwarded agent channel is dropped the
//!   moment the single backend signature succeeds, so the oracle window is one
//!   signature wide (red lines 4/10).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;
use russh::server::Handle as ClientHandle;
use russh::{ChannelId, Pty, Sig};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::audit::ByteCounters;
use crate::backend::{BackendDialer, SessionAgentClient};
use crate::relay::{self, ChannelRelay, ReplyRouter};
use crate::types::{Fingerprint, Grant};

/// How long the supervisor waits for the client to request agent forwarding
/// before declaring the session unusable.
///
/// `auth-agent-req@openssh.com` is only sent by clients that actually want
/// agent forwarding (`ssh -A`), and it is one round-trip behind the channel
/// open we have already answered — so a real `-A` client arrives in
/// milliseconds. The generous bound exists only so the *negative* case
/// (a client that never asks) still ends in a protocol-native channel close
/// instead of hanging: without a request there is no agent to authenticate
/// with, and there is no other credential the gateway could dial with either,
/// so a protocol-native close is the only honest outcome (red line 3).
pub const AGENT_GRANT_DEADLINE: Duration = Duration::from_secs(5);

/// Supervisor is waiting for the client's agent-forwarding request, or for the
/// backend dial to complete once it has one.
const STATE_DIALING: u8 = 0;
/// Backend session is up; the supervisor is applying queued ops.
const STATE_READY: u8 = 1;
/// The supervisor gave up; nothing more will be relayed.
const STATE_CLOSED: u8 = 2;

/// One request the serial handler hands to the supervisor instead of acting on
/// it itself (propose.md §3.5.1), tagged with the client channel it belongs to.
///
/// The channel tag is what makes the single ordered consumer safe for a
/// multi-channel session: every op names its channel, so the supervisor routes
/// each one to the right relay without the handler ever sharing a lock.
#[derive(Debug)]
pub struct AgentOp {
    pub client_id: ChannelId,
    pub kind: AgentOpKind,
}

impl AgentOp {
    pub fn new(client_id: ChannelId, kind: AgentOpKind) -> Self {
        AgentOp { client_id, kind }
    }
}

/// The payload of an [`AgentOp`]: every request a client can send on a session
/// channel, plus the channel-mapping op itself.
///
/// Exhaustive for the session-channel surface: whichever arrive before the
/// backend is up are replayed, in order, the moment it is.
pub enum AgentOpKind {
    /// Map this client channel onto a new session channel of the already
    /// authenticated backend connection, and start its down-pump.
    OpenChannel {
        /// Per-channel data tap (recording / SFTP inspection), created by the
        /// handler so `taps`/`apply_uplink_tap` stay where §3.5.1 puts them.
        tap: Option<Arc<dyn relay::ChannelTap>>,
    },
    Pty {
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: Vec<(Pty, u32)>,
        want_reply: bool,
    },
    Shell {
        want_reply: bool,
    },
    Exec {
        command: Vec<u8>,
        want_reply: bool,
    },
    Subsystem {
        name: String,
        want_reply: bool,
    },
    Env {
        name: String,
        value: String,
        want_reply: bool,
    },
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    Signal {
        signal: Sig,
    },
    Data {
        data: Bytes,
    },
    ExtendedData {
        ext: u32,
        data: Bytes,
    },
    Eof,
    Close,
}

impl std::fmt::Debug for AgentOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ChannelTap` is an object-safe trait object, not a data type: show
        // its presence rather than pretending to print it.
        match self {
            AgentOpKind::OpenChannel { tap } => f
                .debug_struct("OpenChannel")
                .field("tap", &tap.as_ref().map(|_| "<tap>"))
                .finish(),
            AgentOpKind::Pty {
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                modes,
                want_reply,
            } => f
                .debug_struct("Pty")
                .field("term", term)
                .field("want_reply", want_reply)
                .field("size", &(col_width, row_height, pix_width, pix_height))
                .field("modes", &modes.len())
                .finish(),
            AgentOpKind::Shell { want_reply } => f
                .debug_struct("Shell")
                .field("want_reply", want_reply)
                .finish(),
            AgentOpKind::Exec {
                command,
                want_reply,
            } => f
                .debug_struct("Exec")
                .field("command", &String::from_utf8_lossy(command))
                .field("want_reply", want_reply)
                .finish(),
            AgentOpKind::Subsystem { name, want_reply } => f
                .debug_struct("Subsystem")
                .field("name", name)
                .field("want_reply", want_reply)
                .finish(),
            AgentOpKind::Env {
                name,
                value,
                want_reply,
            } => f
                .debug_struct("Env")
                .field("name", name)
                .field("value", value)
                .field("want_reply", want_reply)
                .finish(),
            AgentOpKind::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            } => f
                .debug_struct("WindowChange")
                .field("size", &(col_width, row_height, pix_width, pix_height))
                .finish(),
            AgentOpKind::Signal { signal } => f.debug_tuple("Signal").field(signal).finish(),
            AgentOpKind::Data { data } => f.debug_tuple("Data").field(&data.len()).finish(),
            AgentOpKind::ExtendedData { ext, data } => f
                .debug_struct("ExtendedData")
                .field("ext", ext)
                .field("len", &data.len())
                .finish(),
            AgentOpKind::Eof => f.write_str("Eof"),
            AgentOpKind::Close => f.write_str("Close"),
        }
    }
}

impl AgentOpKind {
    /// Whether the client asked for a reply, and therefore deserves one.
    fn wants_reply(&self) -> bool {
        match self {
            AgentOpKind::Pty { want_reply, .. }
            | AgentOpKind::Shell { want_reply }
            | AgentOpKind::Exec { want_reply, .. }
            | AgentOpKind::Subsystem { want_reply, .. }
            | AgentOpKind::Env { want_reply, .. } => *want_reply,
            _ => false,
        }
    }

    /// Replay the op against the now-live backend channel, answering the client
    /// with the protocol-native SUCCESS/FAILURE when it asked for a reply.
    async fn apply(self, relay: &ChannelRelay, up: &ClientHandle, client_id: ChannelId) {
        match self {
            // OpenChannel is routed by the supervisor itself: it mutates the
            // relay map, so it cannot be applied against an existing relay.
            AgentOpKind::OpenChannel { .. } => {
                debug_assert!(false, "OpenChannel must never reach apply()");
            }
            AgentOpKind::Pty {
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                modes,
                want_reply,
            } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay
                    .backend
                    .request_pty(
                        want_reply, &term, col_width, row_height, pix_width, pix_height, &modes,
                    )
                    .await
                {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode pty request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOpKind::Shell { want_reply } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.request_shell(want_reply).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode shell request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOpKind::Exec {
                command,
                want_reply,
            } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.exec(want_reply, command).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode exec request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOpKind::Subsystem { name, want_reply } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.request_subsystem(want_reply, name).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode subsystem request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOpKind::Env {
                name,
                value,
                want_reply,
            } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.set_env(want_reply, name, value).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode env request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOpKind::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            } => {
                if let Err(e) = relay
                    .backend
                    .window_change(col_width, row_height, pix_width, pix_height)
                    .await
                {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode window-change failed");
                }
            }
            AgentOpKind::Signal { signal } => {
                if let Err(e) = relay.backend.signal(signal).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode signal failed");
                }
            }
            AgentOpKind::Data { data } => {
                relay.note_would_exhaust(data.len());
                // Same fuse as the inline path: the down-pump closes it the
                // instant the backend dies, so it cannot park this task (P0-2).
                if relay.window.acquire(data.len()).await.is_err() {
                    return;
                }
                relay.bytes.add_up(data.len());
                if let Err(e) = relay.backend.data_bytes(data).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode uplink forward failed");
                }
            }
            AgentOpKind::ExtendedData { ext, data } => {
                relay.bytes.add_up(data.len());
                if let Err(e) = relay.backend.extended_data_bytes(ext, data).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode uplink ext-data forward failed");
                }
            }
            AgentOpKind::Eof => {
                if let Err(e) = relay.backend.eof().await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode eof failed");
                }
            }
            AgentOpKind::Close => {
                if let Err(e) = relay.backend.close().await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode channel close failed");
                }
            }
        }
    }

    /// Answer a still-pending request with a protocol-native FAILURE (I4).
    async fn fail_pending(self, up: &ClientHandle, client_id: ChannelId) {
        if self.wants_reply() {
            let _ = up.channel_failure(client_id).await;
        }
    }
}

/// Await the backend's reply to one forwarded request and answer the client
/// with SUCCESS/FAILURE. A dropped receiver is FAILURE (I4), matching the
/// session's inline helper.
async fn deliver(
    up: &ClientHandle,
    client_id: ChannelId,
    want_reply: bool,
    rx: &mut Option<oneshot::Receiver<bool>>,
) {
    if !want_reply {
        return;
    }
    let Some(rx) = rx.as_mut() else { return };
    match tokio::time::timeout(Duration::from_secs(10), &mut *rx).await {
        Ok(Ok(true)) => {
            let _ = up.channel_success(client_id).await;
        }
        _ => {
            let _ = up.channel_failure(client_id).await;
        }
    }
}

/// Result of a handler-side enqueue (C5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// Queued; the supervisor owns it now.
    Accepted,
    /// Still dialing and the bounded queue is full: the caller must fail the
    /// channel natively and must **not** await (C5).
    QueueFull,
    /// The supervisor already tore this session's channel down.
    Closed,
}

/// State visible to both sides of one agent session.
///
/// Deliberately **does not own the op sender**: if it did, the supervisor's own
/// strong reference would keep the queue open forever, `rx.recv()` would never
/// return `None`, and the supervisor would never exit — which in turn would
/// leave the supervisor holding the backend connection alive after the session
/// ended. The sender lives in [`AgentHandle`], which only the handler holds.
pub struct AgentShared {
    state: AtomicU8,
    /// Set by [`AgentShared::grant_decision`] from `agent_request`; a permit is
    /// stored even if the supervisor has not started waiting yet, so the
    /// decision can never be missed.
    grant: Notify,
    /// Agent forwarding was refused, so there is no agent to authenticate with.
    denied: AtomicBool,
}

impl AgentShared {
    fn new() -> Self {
        AgentShared {
            state: AtomicU8::new(STATE_DIALING),
            grant: Notify::new(),
            denied: AtomicBool::new(false),
        }
    }

    fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_CLOSED
    }

    /// Whether the backend session is up and the supervisor is applying queued
    /// ops (as opposed to still dialing).
    pub fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_READY
    }

    fn mark_ready(&self) {
        self.state.store(STATE_READY, Ordering::Release);
    }

    fn mark_closed(&self) {
        self.state.store(STATE_CLOSED, Ordering::Release);
    }
}

/// The handler's handle for one agent session, and the only owner of the queue
/// sender.
///
/// Dropping it is the supervisor's stop signal: the drain loop ends, the
/// supervisor closes every backend channel it still owns and drops the backend
/// connection.
pub struct AgentHandle {
    shared: Arc<AgentShared>,
    tx: mpsc::Sender<AgentOp>,
}

impl AgentHandle {
    fn new(tx: mpsc::Sender<AgentOp>) -> Self {
        AgentHandle {
            shared: Arc::new(AgentShared::new()),
            tx,
        }
    }

    /// Hand an op to the supervisor.
    ///
    /// While dialing the caller is expected to use [`try_enqueue`](Self::try_enqueue)
    /// instead (C5). Once ready this awaits — exactly the backpressure the
    /// inline `data()` path applies — and holds no lock while it does (D11).
    pub async fn enqueue(&self, op: AgentOp) -> Enqueued {
        push(&self.tx, self.shared.is_closed(), op).await
    }

    /// Non-blocking enqueue, used by the handler while the backend is still
    /// dialing so the serial event loop is never parked on a full queue (C5).
    pub fn try_enqueue(&self, op: AgentOp) -> Enqueued {
        try_push(&self.tx, self.shared.is_closed(), op)
    }

    /// Report the agent-forwarding decision so the supervisor can stop waiting.
    ///
    /// `granted` is the outcome of the C1 policy check: `true` means the client
    /// may open an agent channel, `false` means the request arrived but policy
    /// refused it.
    pub fn grant_decision(&self, granted: bool) {
        self.shared.denied.store(!granted, Ordering::Release);
        self.shared.grant.notify_one();
    }

    /// Whether the backend session is up and the supervisor is applying queued
    /// ops.
    pub fn is_ready(&self) -> bool {
        self.shared.is_ready()
    }

    /// Whether the supervisor is still dialing: neither ready nor torn down.
    ///
    /// The handler uses this to collapse the uplink window for the duration of
    /// the dial (see `server::Handler::adjust_window`), so a flooding client
    /// trickles instead of streaming straight into the pre-ready backlog.
    pub fn is_dialing(&self) -> bool {
        !self.shared.is_ready() && !self.shared.is_closed()
    }
}

/// The blocking half of the enqueue contract: report a closed supervisor
/// *before* touching the queue, otherwise await the slot (D11: the caller
/// holds no lock here).
async fn push<T>(tx: &mpsc::Sender<T>, closed: bool, item: T) -> Enqueued {
    if closed {
        return Enqueued::Closed;
    }
    match tx.send(item).await {
        Ok(()) => Enqueued::Accepted,
        Err(_) => Enqueued::Closed,
    }
}

/// The non-blocking half (C5), generic over the queue item so the rules can be
/// unit-tested: russh keeps [`ChannelId`]'s constructor private, so a test
/// cannot build a real [`AgentOp`] from scratch.
fn try_push<T>(tx: &mpsc::Sender<T>, closed: bool, item: T) -> Enqueued {
    if closed {
        return Enqueued::Closed;
    }
    match tx.try_send(item) {
        Ok(()) => Enqueued::Accepted,
        Err(mpsc::error::TrySendError::Full(_)) => Enqueued::QueueFull,
        Err(mpsc::error::TrySendError::Closed(_)) => Enqueued::Closed,
    }
}

/// The client channels currently occupying a slot on one session's backend
/// connection.
///
/// `pool.channels_per_conn` caps how many channels a connection carries **at
/// once**, exactly like sshd's `MaxSessions`, so the count has to fall when a
/// channel is spent — and only the supervisor can know when that is: the
/// down-pump's completion signal is the authority on a channel's liveness, and
/// it never reaches the serial handler. A handler-side set alone therefore
/// counts channels over the *lifetime* of a connection: a ControlMaster that
/// reuses one connection for many short commands hits the cap after
/// `channels_per_conn` of them and every later channel is refused with
/// `ResourceShortage`.
///
/// Hence one set shared by the two tasks, retired from idempotently by
/// whichever side observes an end first. Plain `std::sync::Mutex`, not the
/// tokio one: every critical section is a `HashSet` insert/remove with no await
/// inside, and the handler takes it on the serial event loop.
pub type ChannelSlots = Arc<Mutex<HashSet<ChannelId>>>;

/// An empty slot set for a fresh session.
pub fn new_slots() -> ChannelSlots {
    Arc::new(Mutex::new(HashSet::new()))
}

/// Claim one slot for an accepted client channel.
///
/// The handler calls this before the `OpenChannel` op is handed over, so the
/// cap can never undercount a channel that is already on its way to the
/// supervisor.
pub fn reserve_slot(slots: &ChannelSlots, client_id: ChannelId) {
    slots
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(client_id);
}

/// Give a channel's slot back. Idempotent: both the handler (client close, or
/// an op it could not hand over) and the supervisor (backend half spent, or a
/// channel it never managed to open) can report the same end.
pub fn release_slot(slots: &ChannelSlots, client_id: ChannelId) {
    slots
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&client_id);
}

/// How many channels are live on the session's backend connection right now.
///
/// Poison recovery: a poisoned lock means some task panicked while holding it,
/// and the surviving tasks must still be able to serve and refuse channels
/// rather than deadlock on the serial event loop.
pub fn slot_count(slots: &ChannelSlots) -> usize {
    slots.lock().unwrap_or_else(PoisonError::into_inner).len()
}

/// Everything the supervisor needs, bundled once so the spawned task owns its
/// whole world and borrows nothing from the session.
///
/// No channel identity lives here: a supervisor is per *session* and serves
/// every channel on it, so each op carries its own `client_id`.
pub struct AgentSupervisorArgs {
    pub grant: Grant,
    pub up: ClientHandle,
    pub dialer: Arc<BackendDialer>,
    pub metrics: crate::metrics::Metrics,
    /// Shared up/down byte counters (the audit record's session-wide tally).
    pub bytes: Arc<ByteCounters>,
    /// Session auditor, so the agent identity actually used lands in the audit
    /// record (red line 10).
    pub auditor: Option<Arc<crate::audit::Auditor>>,
    pub session_id: String,
    /// Live-channel accounting shared with the handler (see [`ChannelSlots`]):
    /// the supervisor retires a channel's slot here the moment its backend half
    /// is spent, which is what keeps `channels_per_conn` a concurrent cap.
    pub slots: ChannelSlots,
}

/// Queue depth for one agent session's pre-ready ops.
///
/// Bounded so the bytes parked here can never exceed the relay window (I2/I3):
/// each `Data` op holds at most one max-sized packet, and the slack covers the
/// payload-free control ops (pty/shell/env) that carry none. The slack also has
/// to absorb the `OpenChannel` ops a client can pile on before it is ready,
/// which is capped separately by `channels_per_conn` on the handler side.
///
/// Nothing accumulates here for long: during the dial the supervisor pulls the
/// queue into a [`DialStash`] as fast as the handler fills it, and the client's
/// uplink window is collapsed for the same period (`Handler::adjust_window`),
/// so the slot count is a hand-off buffer rather than a backlog.
fn queue_capacity(window_size: u32, max_packet: u32) -> usize {
    let packets = u64::from(window_size.max(1)).div_ceil(u64::from(max_packet.max(1)));
    // +64 slots of slack for payload-free control ops.
    usize::try_from(packets)
        .unwrap_or(usize::MAX)
        .saturating_add(64)
}

/// Pre-ready ops the handler handed over while the backend dial is in flight.
///
/// The supervisor drains the bounded queue into this during the dial, so a fast
/// producer is absorbed here instead of filling the queue and getting its
/// channel closed with `QueueFull` (C5). Two properties make the backlog safe:
///
/// * **bounded** — the handler's uplink window is collapsed to a two-byte
///   trickle while dialing (`Handler::adjust_window`), so the client can push
///   at most one relay window plus one refill before it has to wait, and
/// * **ordered** — ops are replayed in exactly the order they were pushed (I1),
///   with consecutive `Data` ops for one channel merged into a single buffer so
///   a trickle of tiny packets costs one entry rather than one entry per
///   packet.
#[derive(Default)]
struct DialStash {
    ops: VecDeque<AgentOp>,
    /// Trailing run of `Data` ops for one channel, not yet pushed into `ops`.
    tail: Option<(ChannelId, BytesMut)>,
}

impl DialStash {
    /// Park one op, merging it into the tail when it extends the current data
    /// run and sealing that run first when it does not (order is I1).
    fn push(&mut self, op: AgentOp) {
        let AgentOp { client_id, kind } = op;
        match kind {
            AgentOpKind::Data { data } => match self.tail.take() {
                Some((id, mut buf)) if id == client_id => {
                    buf.extend_from_slice(&data);
                    self.tail = Some((id, buf));
                }
                run => {
                    if let Some((id, buf)) = run {
                        let data = buf.freeze();
                        self.ops
                            .push_back(AgentOp::new(id, AgentOpKind::Data { data }));
                    }
                    self.tail = Some((client_id, BytesMut::from(&data[..])));
                }
            },
            kind => {
                self.seal();
                self.ops.push_back(AgentOp::new(client_id, kind));
            }
        }
    }

    /// Push the in-progress data run into `ops`.
    fn seal(&mut self) {
        if let Some((client_id, buf)) = self.tail.take() {
            let data = buf.freeze();
            self.ops
                .push_back(AgentOp::new(client_id, AgentOpKind::Data { data }));
        }
    }

    /// The whole backlog, sealed and in push order, ready to replay or fail.
    fn flush(&mut self) -> VecDeque<AgentOp> {
        self.seal();
        std::mem::take(&mut self.ops)
    }
}

/// Build the handler-side handle and spawn the supervisor task.
pub fn spawn(args: AgentSupervisorArgs, window_size: u32, max_packet: u32) -> AgentHandle {
    let (tx, rx) = mpsc::channel(queue_capacity(window_size, max_packet));
    let handle = AgentHandle::new(tx.clone());
    // Every down-pump reports its channel back here so the supervisor can drop
    // the relay (and with it the backend channel's write half) the moment the
    // backend side goes away.
    let (pump_done_tx, pump_done_rx) = mpsc::unbounded_channel();
    // Detached: the task ends when the handler drops its handle, and a panic
    // inside it is already reported by tokio and surfaced by the channel close
    // the handler observes. `tx` is handed to the supervisor as a *dial guard*
    // so the queue stays open while the backend is still coming up; it is
    // dropped the moment the handler becomes the sole owner of the sender.
    tokio::spawn(run(
        args,
        Arc::clone(&handle.shared),
        tx,
        rx,
        pump_done_tx,
        pump_done_rx,
    ));
    handle
}

/// The supervisor task: wait for the grant, authenticate with the user's agent,
/// dial the backend, then apply queued ops — opening a backend session channel
/// for every `OpenChannel` and relaying the rest onto it — until the handler
/// drops its handle.
async fn run(
    args: AgentSupervisorArgs,
    shared: Arc<AgentShared>,
    dial_guard: mpsc::Sender<AgentOp>,
    mut rx: mpsc::Receiver<AgentOp>,
    pump_done_tx: mpsc::UnboundedSender<ChannelId>,
    mut pump_done_rx: mpsc::UnboundedReceiver<ChannelId>,
) {
    let AgentSupervisorArgs {
        grant,
        up,
        dialer,
        metrics,
        bytes,
        auditor,
        session_id,
        slots,
    } = args;

    // `dial_guard` keeps the queue open while we dial (the handler may be
    // enqueueing an OpenChannel plus pty/env/exec right now); it is dropped
    // below, the moment the handler becomes the sole owner of the sender.
    //
    // The dial runs *alongside* the queue instead of in front of it. Waiting
    // here would let a fast producer fill the bounded queue and have its
    // channel closed with `QueueFull`, so every op that arrives meanwhile is
    // pulled straight into a `DialStash` and replayed once the backend is up.
    let mut dial = Box::pin(establish_backend(&shared, &grant, &up, &dialer));
    let mut stash = DialStash::default();
    let mut established = None;
    let mut dial_error = None;
    loop {
        tokio::select! {
            result = &mut dial => {
                match result {
                    Ok(live) => established = Some(live),
                    Err(reason) => dial_error = Some(reason),
                }
                break;
            }
            op = rx.recv() => match op {
                Some(op) => stash.push(op),
                // Unreachable: `dial_guard` is a live sender for the whole
                // dial, so the queue cannot close under us. Handle it anyway
                // rather than spinning on a closed queue.
                None => {
                    dial_error = Some("the handler dropped the session while the backend was dialing".into());
                    break;
                }
            },
        }
    }
    // Cancels the dial if the branch above ended it early; on the normal path
    // the future has already produced its value.
    drop(dial);

    let established = match established {
        Some(established) => established,
        None => {
            let reason =
                dial_error.unwrap_or_else(|| "the backend dial ended without a session".into());
            shared.mark_closed();
            metrics.agent_backend_auth_fail();
            tracing::warn!(
                target: "relay",
                %session_id,
                target_host = %grant.target.host,
                target_port = grant.target.port,
                %reason,
                "agent-mode backend authentication failed"
            );
            // I4: every client channel the handler already accepted is closed,
            // and every request queued behind one gets a native FAILURE. Never
            // a key/cert fallback. The stashed ops are older than anything
            // still sitting in the queue, so they fail first.
            let mut backlog = stash.flush();
            while let Ok(op) = rx.try_recv() {
                backlog.push_back(op);
            }
            fail_backlog(&up, backlog, &slots).await;
            return;
        }
    };

    // The forwarded agent channel exists for exactly one signature and is
    // dropped inside `establish_backend` the moment that signature succeeds
    // (red lines 4/10). What stays alive is the backend transport task, whose
    // lifecycle is bound to `Handle` — see `Established`.
    let handle = established.handle;
    metrics.agent_backend_auth_ok();
    metrics.agent_signature();
    if let Some(auditor) = &auditor {
        auditor.set_agent_identity(established.fingerprint.as_str());
        auditor.note_agent_signature();
    }

    // Drain before the flip, not after: an empty queue at the moment the
    // handler starts reading `is_ready()` is what rules out the `QueueFull`
    // it could otherwise race into. Whatever it queued behind that drain is
    // newer than everything in `backlog`, so it stays behind it in order.
    let mut backlog = stash.flush();
    while let Ok(op) = rx.try_recv() {
        backlog.push_back(op);
    }
    let backlog_bytes: usize = backlog
        .iter()
        .map(|op| match &op.kind {
            AgentOpKind::Data { data } | AgentOpKind::ExtendedData { data, .. } => data.len(),
            _ => 0,
        })
        .sum();
    tracing::debug!(
        target: "relay",
        %session_id,
        ops = backlog.len(),
        bytes = backlog_bytes,
        "replaying the pre-ready backlog"
    );
    shared.mark_ready();
    // From here on the handler owns the only sender: once it drops its handle,
    // `rx.recv()` returns `None` and this loop ends.
    drop(dial_guard);
    tracing::info!(
        target: "relay",
        %session_id,
        agent_identity = %established.fingerprint,
        backend_user = %grant.target.user,
        backend_host = %grant.target.host,
        backend_port = grant.target.port,
        "agent-mode backend session established"
    );

    // One relay per client channel, all multiplexed onto `handle`.
    let mut relays: HashMap<ChannelId, Arc<ChannelRelay>> = HashMap::new();

    // Replay what the dial swallowed before serving anything else: the handler
    // wrote this order, so the backend sees this order (I1). Deliberately NOT
    // merging `rx` into the backlog here — doing so empties the queue faster
    // than the backend drains, so the handler stops ever parking and the
    // backlog becomes an unbounded buffer (RSS tracks volume). Letting the
    // queue fill and the handler park during the replay is exactly the
    // backpressure the main loop gives (I4).
    while let Some(op) = backlog.pop_front() {
        serve_op(
            op,
            &mut relays,
            &handle,
            &up,
            &bytes,
            &metrics,
            &pump_done_tx,
            &slots,
        )
        .await;
    }

    // Single ordered consumer: ops in enqueue order, per channel (I1).
    // The loop ends when the handler drops its handle — which is what "every
    // channel is closed and the session is over" looks like from here — or when
    // the last down-pump has reported in and there is nothing left to serve.
    loop {
        tokio::select! {
            op = rx.recv() => {
                match op {
                    None => break,
                    Some(op) => serve_op(
                        op,
                        &mut relays,
                        &handle,
                        &up,
                        &bytes,
                        &metrics,
                        &pump_done_tx,
                        &slots,
                    )
                    .await,
                }
            }
            done = pump_done_rx.recv() => {
                // The down-pump is the authority on this channel's liveness
                // (P0-2): it finished, so the backend half is spent. Drop the
                // relay — that closes the write half and, with it, the backend
                // channel — and forget the mapping.
                match done {
                    None => break,
                    Some(client_id) => {
                        // Slot released unconditionally: the relay may already
                        // be gone (a `Close` op dropped it), but the channel is
                        // spent either way and `channels_per_conn` has to stop
                        // counting it.
                        release_slot(&slots, client_id);
                        if let Some(relay) = relays.remove(&client_id) {
                            let _ = relay.backend.close().await;
                        }
                    }
                }
            }
        }
    }

    // Session over: close every backend channel still mapped, then drop `handle`
    // (implicitly) so the backend transport task stops with it.
    for (client_id, relay) in relays {
        release_slot(&slots, client_id);
        let _ = relay.backend.close().await;
    }
}

/// Apply one op from the ordered consumer: map `OpenChannel` onto a new session
/// channel of the backend connection, relay everything else onto the channel it
/// names.
///
/// Split out of the main loop so the dial-time backlog is replayed through
/// exactly the same code path as live ops — two implementations would be two
/// chances to drift.
#[allow(clippy::too_many_arguments)]
async fn serve_op(
    op: AgentOp,
    relays: &mut HashMap<ChannelId, Arc<ChannelRelay>>,
    handle: &crate::backend::BackendHandle,
    up: &ClientHandle,
    bytes: &Arc<ByteCounters>,
    metrics: &crate::metrics::Metrics,
    pump_done_tx: &mpsc::UnboundedSender<ChannelId>,
    slots: &ChannelSlots,
) {
    match op.kind {
        AgentOpKind::OpenChannel { tap } => {
            if relays.contains_key(&op.client_id) {
                tracing::debug!(
                    target: "relay",
                    client_id = %op.client_id,
                    "duplicate OpenChannel ignored"
                );
            } else {
                open_backend_channel(
                    op.client_id,
                    tap,
                    handle,
                    up,
                    bytes,
                    metrics,
                    pump_done_tx,
                    relays,
                    slots,
                )
                .await;
            }
        }
        kind => match relays.get(&op.client_id) {
            // Cloned so the borrow of `relays` never crosses the await below
            // (D11).
            Some(relay) => {
                let relay = Arc::clone(relay);
                kind.apply(&relay, up, op.client_id).await;
            }
            None => tracing::debug!(
                target: "relay",
                client_id = %op.client_id,
                ?kind,
                "dropping op for a channel that is already gone"
            ),
        },
    }
}

/// Answer a dead session's whole backlog the protocol-native way (I4): every
/// request that asked for a reply gets a FAILURE, and every client channel the
/// handler already accepted is closed. Never a key/cert fallback, never a
/// fabricated SUCCESS.
async fn fail_backlog(up: &ClientHandle, backlog: VecDeque<AgentOp>, slots: &ChannelSlots) {
    let mut accepted = Vec::new();
    for AgentOp { client_id, kind } in backlog {
        if matches!(kind, AgentOpKind::OpenChannel { .. }) {
            accepted.push(client_id);
        } else {
            kind.fail_pending(up, client_id).await;
        }
    }
    for client_id in accepted {
        // The client is about to see the close, but a close the *server*
        // initiated is not echoed back as a handler callback, so the slot has
        // to be given back here or it leaks for the rest of the connection.
        release_slot(slots, client_id);
        let _ = up.close(client_id).await;
    }
}

/// Open one more session channel on the authenticated backend connection and
/// start its down-pump, wiring the new relay into the supervisor's map.
#[allow(clippy::too_many_arguments)]
async fn open_backend_channel(
    client_id: ChannelId,
    tap: Option<Arc<dyn relay::ChannelTap>>,
    handle: &crate::backend::BackendHandle,
    up: &ClientHandle,
    bytes: &Arc<ByteCounters>,
    metrics: &crate::metrics::Metrics,
    pump_done_tx: &mpsc::UnboundedSender<ChannelId>,
    relays: &mut HashMap<ChannelId, Arc<ChannelRelay>>,
    slots: &ChannelSlots,
) {
    let opened = match handle.channel_open_session().await {
        Ok(channel) => channel,
        Err(e) => {
            // I4: the client channel was already accepted, so the only honest
            // answer left is to close it. No fabricated exec, no fallback.
            tracing::warn!(
                target: "relay",
                %client_id,
                ?e,
                "backend refused a session channel for an accepted client channel"
            );
            // No down-pump was ever spawned for this channel, so nothing else
            // will report it: hand the slot back here or the cap counts a
            // channel that never existed on the backend.
            release_slot(slots, client_id);
            let _ = up.close(client_id).await;
            return;
        }
    };

    let (backend_read, backend_write) = opened.split();
    let router = ReplyRouter::default();
    let window = Arc::new(relay::OutboundWindow::uncalibrated());
    let relay = Arc::new(ChannelRelay::new(
        client_id,
        backend_write,
        router.clone(),
        Arc::clone(&window),
        Arc::clone(bytes),
        metrics.clone(),
    ));

    // Everything the pump needs is taken *before* the task is built; the
    // completion signal is what lets the supervisor retire this channel.
    let done = pump_done_tx.clone();
    let pump_up = up.clone();
    let pump_bytes = Arc::clone(bytes);
    let pump_metrics = metrics.clone();
    tokio::spawn(async move {
        relay::pump_backend_to_client(
            backend_read,
            pump_up,
            client_id,
            router,
            window,
            pump_bytes,
            pump_metrics,
            tap,
        )
        .await;
        let _ = done.send(client_id);
    });

    // No await between the spawn above and this insert: the map is always
    // populated before the supervisor can observe the pump's completion signal.
    relays.insert(client_id, relay);
}

/// A live agent leg, reduced to the authenticated backend transport.
///
/// `handle` is not decoration: russh's client driver task is spawned by
/// `client::connect_stream` and its lifecycle is bound to the `Handle`, which
/// owns the reply stream and the command sender the run loop ends on. Dropping
/// it would stop the transport while leaving the channel objects — and every
/// later request would hang forever with no error.
///
/// The forwarded agent channel is deliberately **absent**: it is dropped the
/// instant the one signature succeeds, before this struct is ever built.
struct Established {
    handle: crate::backend::BackendHandle,
    fingerprint: Fingerprint,
}

/// Wait for the client's agent-forwarding decision.
///
/// Returns `true` only when both the client asked for forwarding **and** the
/// C1 policy check allowed it. The two failure modes (no request, refused
/// request) are both terminal: red line 3 forbids dialing with the gateway's
/// own key instead.
async fn wait_for_grant(shared: &AgentShared, deadline: Duration) -> bool {
    let notified = shared.grant.notified();
    tokio::pin!(notified);
    if shared.denied.load(Ordering::Acquire) {
        return false;
    }
    tokio::select! {
        _ = &mut notified => !shared.denied.load(Ordering::Acquire),
        () = tokio::time::sleep(deadline) => false,
    }
}

/// Open the agent channel, list identities, dial + authenticate the backend
/// with the one identity whose fingerprint matches the grant — and then close
/// the agent channel again.
///
/// The close is the whole point: the forwarded agent is a signing oracle, and
/// this session only ever needs the one signature that gets it through the
/// backend handshake. Keeping the channel open for the session's lifetime would
/// widen that window for no benefit (the user's local agent is untouched
/// either way — red lines 4/10).
async fn establish_backend(
    shared: &AgentShared,
    grant: &Grant,
    up: &ClientHandle,
    dialer: &BackendDialer,
) -> Result<Established, String> {
    if !wait_for_grant(shared, AGENT_GRANT_DEADLINE).await {
        return Err(if shared.denied.load(Ordering::Acquire) {
            "agent forwarding denied by policy".into()
        } else {
            "client never requested agent forwarding".into()
        });
    }

    let agent_channel = up
        .channel_open_agent()
        .await
        .map_err(|e| format!("client refused the agent channel: {e}"))?;
    let mut agent = SessionAgentClient::connect(agent_channel.into_stream());

    let identities = agent
        .request_identities()
        .await
        .map_err(|e| format!("agent returned no identities: {e}"))?;

    // Red line 4: only the identity whose fingerprint the control plane already
    // authorized is ever offered to the backend. A missing match is an error,
    // never an invitation to try another credential.
    let wanted = grant.fingerprint.as_str();
    let matched = identities
        .iter()
        .position(|identity| agent_identity_fingerprint(identity).as_str() == wanted);
    let Some(index) = matched else {
        let offered: Vec<String> = identities
            .iter()
            .take(8)
            .map(|identity| agent_identity_fingerprint(identity).as_str().to_owned())
            .collect();
        return Err(format!(
            "no agent identity matches the authorized fingerprint {wanted} \
             (agent offers {} identities: {offered:?})",
            identities.len()
        ));
    };
    let fingerprint = agent_identity_fingerprint(&identities[index]);

    let public_key = identities[index].public_key().into_owned();
    let backend = dialer
        .connect(grant, public_key, &mut agent)
        .await
        .map_err(|e| format!("backend rejected the agent signature: {e}"))?;

    // Red lines 4/10: the oracle has served its one purpose. Dropping the
    // agent client drops its `ChannelStream`, whose reader half carries
    // russh's `ChannelCloseOnDrop` — so the forwarded agent channel really is
    // closed on the wire, not merely forgotten locally.
    drop(agent);

    Ok(Established {
        handle: backend,
        fingerprint,
    })
}

/// The canonical `SHA256:` fingerprint of an agent identity.
fn agent_identity_fingerprint(identity: &AgentIdentity) -> Fingerprint {
    Fingerprint::new(
        identity
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_capacity_scales_with_the_relay_window_and_never_hits_zero() {
        // 1 MiB window / 32 KiB packet = 32 payload slots + control-op slack.
        assert_eq!(queue_capacity(1 << 20, 32 << 10), 32 + 64);
        // Degenerate config values must still yield a usable queue.
        assert!(queue_capacity(0, 0) > 0);
        assert!(queue_capacity(1, u32::MAX) > 0);
    }

    #[test]
    fn slots_track_live_channels_and_are_released_idempotently() {
        // The per-connection cap counts *concurrent* channels (sshd MaxSessions
        // semantics), so a spent channel has to give its slot back. Handler and
        // supervisor can both observe the same channel ending — a client close
        // and the backend half's end are two observations of one event — and
        // the second release must be a no-op rather than free a stranger's
        // slot.
        let slots = new_slots();
        assert_eq!(slot_count(&slots), 0);
        for n in 1..=3 {
            reserve_slot(&slots, channel_id(n));
        }
        assert_eq!(slot_count(&slots), 3);
        release_slot(&slots, channel_id(2));
        release_slot(&slots, channel_id(2));
        assert_eq!(
            slot_count(&slots),
            2,
            "releasing the same channel twice must not release two slots"
        );
        release_slot(&slots, channel_id(1));
        release_slot(&slots, channel_id(3));
        assert_eq!(slot_count(&slots), 0);
    }

    #[tokio::test]
    async fn grant_decision_wakes_a_supervisor_that_has_not_started_waiting_yet() {
        // `Notify::notify_one` stores a permit, so a decision taken *before* the
        // supervisor calls `wait_for_grant` is still observed. Losing that
        // decision would turn every `-A` session into a 5s timeout.
        let (tx, _rx) = mpsc::channel(4);
        let handle = AgentHandle::new(tx);
        handle.grant_decision(true);
        let waited = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_grant(&handle.shared, Duration::from_secs(30)),
        )
        .await
        .expect("a recorded grant must not wait for the deadline");
        assert!(waited);
    }

    #[tokio::test]
    async fn a_denied_grant_is_terminal_even_if_a_permit_is_pending() {
        let (tx, _rx) = mpsc::channel(4);
        let handle = AgentHandle::new(tx);
        handle.grant_decision(true);
        handle.grant_decision(false); // policy refused it after all
        let waited = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_grant(&handle.shared, Duration::from_secs(30)),
        )
        .await
        .expect("a recorded decision must not wait for the deadline");
        assert!(!waited);
    }

    #[tokio::test]
    async fn waiting_for_the_client_to_ask_expires_at_the_deadline() {
        let (tx, _rx) = mpsc::channel(4);
        let handle = AgentHandle::new(tx);
        let started = std::time::Instant::now();
        assert!(
            !wait_for_grant(&handle.shared, Duration::from_millis(50)).await,
            "a client that never asks for agent forwarding must not be dialed"
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn try_push_never_blocks_and_reports_the_bounded_queue() {
        // C5 is a red line: a full queue must be *reported*, never awaited,
        // because the caller is the session's serial event loop.
        let (tx, mut rx) = mpsc::channel(2);
        assert_eq!(try_push(&tx, false, ()), Enqueued::Accepted);
        assert_eq!(try_push(&tx, false, ()), Enqueued::Accepted);
        assert_eq!(try_push(&tx, false, ()), Enqueued::QueueFull);
        rx.recv().await.expect("one item must drain");
        assert_eq!(try_push(&tx, false, ()), Enqueued::Accepted);
    }

    #[tokio::test]
    async fn a_closed_supervisor_is_reported_before_the_queue_is_touched() {
        // `Closed` must win over `QueueFull`: once the supervisor is gone the
        // caller has to tear the channel down, not retry the send.
        let (tx, _rx) = mpsc::channel(1);
        assert_eq!(try_push(&tx, true, ()), Enqueued::Closed);
        assert_eq!(push(&tx, true, ()).await, Enqueued::Closed);
    }

    #[tokio::test]
    async fn push_preserves_fifo_order() {
        // I1: the supervisor applies ops in enqueue order. Nothing here may
        // reorder them.
        let (tx, mut rx) = mpsc::channel(8);
        for i in 0..4u8 {
            assert_eq!(push(&tx, false, i).await, Enqueued::Accepted);
        }
        for i in 0..4u8 {
            assert_eq!(rx.recv().await, Some(i), "items must come back in order");
        }
    }

    #[tokio::test]
    async fn a_dropped_receiver_is_reported_as_closed_not_as_a_full_queue() {
        let (tx, _rx) = mpsc::channel::<()>(4);
        drop(_rx);
        assert_eq!(try_push(&tx, false, ()), Enqueued::Closed);
        assert_eq!(push(&tx, false, ()).await, Enqueued::Closed);
    }

    #[test]
    fn only_requests_that_asked_for_a_reply_get_one() {
        // An unsolicited CHANNEL_FAILURE would desynchronise the client, so the
        // failure path must key off the client's own want_reply flag.
        assert!(AgentOpKind::Shell { want_reply: true }.wants_reply());
        assert!(!AgentOpKind::Shell { want_reply: false }.wants_reply());
        assert!(AgentOpKind::Exec {
            command: b"true".to_vec(),
            want_reply: true
        }
        .wants_reply());
        assert!(!AgentOpKind::Data {
            data: Bytes::from_static(b"x")
        }
        .wants_reply());
        assert!(!AgentOpKind::Close.wants_reply());
        assert!(!AgentOpKind::OpenChannel { tap: None }.wants_reply());
    }

    // --- DialStash: the pre-ready backlog -----------------------------------

    /// `ChannelId`'s constructor is private to russh, so a test builds one the
    /// way the library itself does — by decoding it from the wire. Same
    /// technique as `record::tests::placeholder_channel_id`.
    fn channel_id(n: u32) -> ChannelId {
        let bytes = n.to_be_bytes();
        let mut cursor = &bytes[..];
        ssh_encoding::Decode::decode(&mut cursor).expect("decode a channel id")
    }

    fn data_op(id: ChannelId, payload: &[u8]) -> AgentOp {
        AgentOp::new(
            id,
            AgentOpKind::Data {
                data: Bytes::copy_from_slice(payload),
            },
        )
    }

    fn data_payload(op: &AgentOp) -> &[u8] {
        match &op.kind {
            AgentOpKind::Data { data } => data,
            other => panic!("expected a Data op, got {other:?}"),
        }
    }

    #[test]
    fn the_stash_coalesces_a_run_of_data_on_one_channel() {
        // The coalescing is the exception granted by propose.md 3.5.1
        // qualifier 2: a client trickling one keystroke at a time during the
        // dial must not cost one backlog entry per packet, or the stash stops
        // being bounded by the relay window.
        let a = channel_id(1);
        let mut stash = DialStash::default();
        stash.push(data_op(a, b"abc"));
        stash.push(data_op(a, b"de"));

        let ops = stash.flush();
        assert_eq!(ops.len(), 1, "one run must collapse into one buffer");
        assert_eq!(ops[0].client_id, a);
        assert_eq!(data_payload(&ops[0]), b"abcde");
        assert!(
            stash.flush().is_empty(),
            "flush takes the whole backlog, it does not leave a tail"
        );
    }

    #[test]
    fn the_stash_never_merges_across_channels_and_keeps_push_order() {
        // I1 is per channel, but the replay is global: Data(A), Data(B),
        // Data(A) must come back as three ops in exactly that order, each
        // carrying only its own channel's bytes.
        let a = channel_id(1);
        let b = channel_id(2);
        let mut stash = DialStash::default();
        stash.push(data_op(a, b"a1"));
        stash.push(data_op(b, b"b1"));
        stash.push(data_op(a, b"a2"));

        let ops = stash.flush();
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].client_id, a);
        assert_eq!(data_payload(&ops[0]), b"a1");
        assert_eq!(ops[1].client_id, b);
        assert_eq!(data_payload(&ops[1]), b"b1");
        assert_eq!(ops[2].client_id, a);
        assert_eq!(data_payload(&ops[2]), b"a2");
    }

    #[test]
    fn a_control_op_is_never_merged_and_seals_the_run_before_it() {
        // Data(A), Close(A), Data(A): the Close is a barrier, not part of the
        // byte stream, so it must land between the two buffers in order. The
        // same barrier applies when the control op is for another channel.
        let a = channel_id(1);
        let b = channel_id(2);
        let mut stash = DialStash::default();
        stash.push(data_op(a, b"x"));
        stash.push(AgentOp::new(a, AgentOpKind::Close));
        stash.push(data_op(a, b"y"));
        stash.push(AgentOp::new(b, AgentOpKind::Eof));
        stash.push(data_op(b, b"z"));

        let ops = stash.flush();
        assert_eq!(ops.len(), 5, "control ops must never be folded away");
        assert_eq!((ops[0].client_id, ops[2].client_id), (a, a));
        assert_eq!(data_payload(&ops[0]), b"x");
        assert!(matches!(ops[1].kind, AgentOpKind::Close));
        assert_eq!(data_payload(&ops[2]), b"y");
        assert!(matches!(ops[3].kind, AgentOpKind::Eof));
        assert_eq!(ops[4].client_id, b);
        assert_eq!(data_payload(&ops[4]), b"z");
    }
}
