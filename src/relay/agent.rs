//! Agent-passthrough supervisor (plan-agent-passthrough C2, propose.md §3.5.1).
//!
//! With `backend_auth = "agent"`, the gateway authenticates to the backend as
//! the **user**, by asking the user's own ssh-agent to sign — the `ssh -A`
//! semantic. The private key never leaves the client; the gateway only relays
//! agent messages.
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
//! The four qualifiers of §3.5.1 are enforced structurally here:
//!
//! * **agent mode only** — a supervisor is only ever spawned after
//!   [`ensure_agent_backend_auth`](crate::backend::ensure_agent_backend_auth)
//!   passed, i.e. the kill-switch is on *and* the grant resolved to `agent`.
//!   The key/cert path never constructs one.
//! * **one FIFO consumer** — a session owns exactly one
//!   [`mpsc::Sender<AgentOp>`] and one supervisor; ops are applied strictly in
//!   enqueue order, so I1 (channel ↔ backend 1:1) holds and no request is ever
//!   reordered or injected.
//! * **handler never blocks while dialing** — while the state is
//!   [`STATE_DIALING`] the handler uses `try_send`; a full queue fails the
//!   channel natively instead of awaiting (C5). Once [`STATE_READY`] the
//!   handler's `send().await` is the same backpressure it applies inline today,
//!   and the queue's slot count bounds the bytes it can hold.
//! * **failures are protocol-native** — every exit path answers pending
//!   requests with `channel_failure` and then closes the channel; it never
//!   falls back to the gateway's own key or certificate (red line 3).

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;
use russh::server::Handle as ClientHandle;
use russh::{Pty, Sig};
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
/// with, and silently dialing with the gateway's own key would be exactly the
/// credential downgrade red line 3 forbids.
pub const AGENT_GRANT_DEADLINE: Duration = Duration::from_secs(5);

/// Supervisor is waiting for the client's agent-forwarding request, or for the
/// backend dial to complete once it has one.
const STATE_DIALING: u8 = 0;
/// Backend session is up; the supervisor is applying queued ops.
const STATE_READY: u8 = 1;
/// The supervisor gave up; nothing more will be relayed.
const STATE_CLOSED: u8 = 2;

/// What the serial handler hands to the supervisor instead of acting on it
/// itself (propose.md §3.5.1).
///
/// Exhaustive for the requests a client can send on a session channel:
/// whichever arrive before the backend is up are replayed, in order, the moment
/// it is.
#[derive(Debug)]
pub enum AgentOp {
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

impl AgentOp {
    /// Whether the client asked for a reply, and therefore deserves one.
    fn wants_reply(&self) -> bool {
        match self {
            AgentOp::Pty { want_reply, .. }
            | AgentOp::Shell { want_reply }
            | AgentOp::Exec { want_reply, .. }
            | AgentOp::Subsystem { want_reply, .. }
            | AgentOp::Env { want_reply, .. } => *want_reply,
            _ => false,
        }
    }

    /// Replay the op against the now-live backend channel, answering the client
    /// with the protocol-native SUCCESS/FAILURE when it asked for a reply.
    async fn apply(self, relay: &ChannelRelay, up: &ClientHandle, client_id: russh::ChannelId) {
        match self {
            AgentOp::Pty {
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
            AgentOp::Shell { want_reply } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.request_shell(want_reply).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode shell request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOp::Exec {
                command,
                want_reply,
            } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.exec(want_reply, command).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode exec request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOp::Subsystem { name, want_reply } => {
                let mut rx = relay.router.push(want_reply);
                if let Err(e) = relay.backend.request_subsystem(want_reply, name).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode subsystem request failed");
                }
                deliver(up, client_id, want_reply, &mut rx).await;
            }
            AgentOp::Env {
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
            AgentOp::WindowChange {
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
            AgentOp::Signal { signal } => {
                if let Err(e) = relay.backend.signal(signal).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode signal failed");
                }
            }
            AgentOp::Data { data } => {
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
            AgentOp::ExtendedData { ext, data } => {
                relay.bytes.add_up(data.len());
                if let Err(e) = relay.backend.extended_data_bytes(ext, data).await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode uplink ext-data forward failed");
                }
            }
            AgentOp::Eof => {
                if let Err(e) = relay.backend.eof().await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode eof failed");
                }
            }
            AgentOp::Close => {
                if let Err(e) = relay.backend.close().await {
                    tracing::debug!(target: "relay", %client_id, ?e, "agent-mode channel close failed");
                }
            }
        }
    }

    /// Answer a still-pending request with a protocol-native FAILURE (I4).
    async fn fail_pending(self, up: &ClientHandle, client_id: russh::ChannelId) {
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
    client_id: russh::ChannelId,
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
/// leave the agent-forwarding channel open and pin the client's connection
/// alive after the session ended. The sender lives in [`AgentHandle`], which
/// only the handler holds.
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
/// supervisor drops the forwarded agent channel, and the client's connection is
/// free to close.
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
    /// inline `data()` path applies today — and holds no lock while it does
    /// (D11).
    pub async fn enqueue(&self, op: AgentOp) -> Enqueued {
        if self.shared.is_closed() {
            return Enqueued::Closed;
        }
        match self.tx.send(op).await {
            Ok(()) => Enqueued::Accepted,
            Err(_) => Enqueued::Closed,
        }
    }

    /// Non-blocking enqueue, used by the handler while the backend is still
    /// dialing so the serial event loop is never parked on a full queue (C5).
    pub fn try_enqueue(&self, op: AgentOp) -> Enqueued {
        if self.shared.is_closed() {
            return Enqueued::Closed;
        }
        match self.tx.try_send(op) {
            Ok(()) => Enqueued::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => Enqueued::QueueFull,
            Err(mpsc::error::TrySendError::Closed(_)) => Enqueued::Closed,
        }
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
}

/// Everything the supervisor needs, bundled once so the spawned task owns its
/// whole world and borrows nothing from the session.
pub struct AgentSupervisorArgs {
    pub grant: Grant,
    pub client_id: russh::ChannelId,
    pub up: ClientHandle,
    pub dialer: Arc<BackendDialer>,
    pub metrics: crate::metrics::Metrics,
    /// Per-channel data tap (recording / SFTP inspection), already created by
    /// the handler so the fast path stays allocation-free.
    pub tap: Option<Arc<dyn relay::ChannelTap>>,
    pub bytes: Arc<ByteCounters>,
    /// Session auditor, so the agent identity actually used lands in the audit
    /// record (red line 10).
    pub auditor: Option<Arc<crate::audit::Auditor>>,
    pub session_id: String,
}

/// Queue depth for one agent session's pre-ready ops.
///
/// Bounded so the bytes parked here can never exceed the relay window (I2/I3):
/// each `Data` op holds at most one max-sized packet, and the slack covers the
/// payload-free control ops (pty/shell/env) that carry none.
fn queue_capacity(window_size: u32, max_packet: u32) -> usize {
    let packets = u64::from(window_size.max(1)).div_ceil(u64::from(max_packet.max(1)));
    // +64 slots of slack for payload-free control ops.
    usize::try_from(packets)
        .unwrap_or(usize::MAX)
        .saturating_add(64)
}

/// Build the handler-side handle and spawn the supervisor task.
pub fn spawn(args: AgentSupervisorArgs, window_size: u32, max_packet: u32) -> AgentHandle {
    let (tx, rx) = mpsc::channel(queue_capacity(window_size, max_packet));
    let handle = AgentHandle::new(tx.clone());
    // Detached: the task ends when the handler drops its handle, and a panic
    // inside it is already reported by tokio and surfaced by the channel close
    // the handler observes. `tx` is handed to the supervisor as a *dial guard*
    // so the queue stays open while the backend is still coming up; it is
    // dropped the moment the handler becomes the sole owner of the sender.
    tokio::spawn(run(args, Arc::clone(&handle.shared), tx, rx));
    handle
}

/// The supervisor task: wait for the grant, authenticate with the user's agent,
/// dial the backend, then replay the queue and keep draining it until the
/// handler drops its handle.
async fn run(
    args: AgentSupervisorArgs,
    shared: Arc<AgentShared>,
    dial_guard: mpsc::Sender<AgentOp>,
    mut rx: mpsc::Receiver<AgentOp>,
) {
    let AgentSupervisorArgs {
        grant,
        client_id,
        up,
        dialer,
        metrics,
        tap,
        bytes,
        auditor,
        session_id,
    } = args;

    // `dial_guard` keeps the queue open while we dial (the handler may be
    // enqueueing pty/env/exec right now); it is dropped below, the moment the
    // handler becomes the sole owner of the sender.
    let established = match establish_backend(&shared, &grant, &up, &dialer).await {
        Ok(established) => established,
        Err(reason) => {
            shared.mark_closed();
            metrics.agent_backend_auth_fail();
            tracing::warn!(
                target: "relay",
                %session_id,
                %client_id,
                target_host = %grant.target.host,
                target_port = grant.target.port,
                %reason,
                "agent-mode backend authentication failed"
            );
            // I4: every request the client already queued gets a native
            // FAILURE, then the channel closes. Never a key/cert fallback.
            while let Ok(op) = rx.try_recv() {
                op.fail_pending(&up, client_id).await;
            }
            let _ = up.close(client_id).await;
            return;
        }
    };

    // Keep the agent channel open for as long as the session lives: closing it
    // would tell the client its forwarding channel is gone.
    let _agent = established.agent;
    // ...and keep the backend transport task alive for the same reason (see
    // `Established`). Both are deliberately bound to underscore names so they
    // live until `run` returns.
    let _handle = established.handle;
    let backend_channel = established.backend_channel;
    metrics.agent_backend_auth_ok();
    metrics.agent_signature();
    if let Some(auditor) = &auditor {
        auditor.set_agent_identity(established.fingerprint.as_str());
        auditor.note_agent_signature();
    }

    let (backend_read, backend_write) = backend_channel.split();
    let router = ReplyRouter::default();
    let window = Arc::new(relay::OutboundWindow::uncalibrated());
    let relay = Arc::new(ChannelRelay::new(
        client_id,
        backend_write,
        router,
        Arc::clone(&window),
        Arc::clone(&bytes),
        metrics.clone(),
    ));

    // The down-pump is the only reader of the backend channel and the authority
    // on its liveness (P0-2): it closes the window the instant the backend dies.
    // Its completion is also what ends this supervisor, so the forwarded agent
    // channel can never outlive the session it authenticates — a channel left
    // open would keep the client's connection (and its agent) alive forever.
    let (relay_done_tx, relay_done_rx) = oneshot::channel::<()>();
    // Everything the pump needs is taken *before* the task is built: capturing
    // `relay` or `up` itself would move them out from under the drain loop.
    let pump_up = up.clone();
    let pump_router = relay.router.clone();
    let pump_window = Arc::clone(&window);
    let pump_bytes = Arc::clone(&bytes);
    let pump_metrics = metrics.clone();
    tokio::spawn(async move {
        relay::pump_backend_to_client(
            backend_read,
            pump_up,
            client_id,
            pump_router,
            pump_window,
            pump_bytes,
            pump_metrics,
            tap,
        )
        .await;
        let _ = relay_done_tx.send(());
    });

    // From here on the handler owns the only sender: once it drops its handle,
    // `rx.recv()` returns `None` and this loop ends.
    drop(dial_guard);

    shared.mark_ready();
    tracing::info!(
        target: "relay",
        %session_id,
        %client_id,
        agent_identity = %established.fingerprint,
        backend_user = %grant.target.user,
        backend_host = %grant.target.host,
        backend_port = grant.target.port,
        "agent-mode backend session established"
    );

    // Drain whatever the client queued while we were dialing, then keep draining
    // until either the handler drops its handle (which closes the sender) or the
    // relayed session ends. Single consumer, FIFO — the ordering guarantee
    // §3.5.1 qualifier 2 asks for.
    let mut relay_done = relay_done_rx;
    loop {
        let op = tokio::select! {
            op = rx.recv() => op,
            _ = &mut relay_done => break,
        };
        let Some(op) = op else { break };
        if relay.window.is_closed() {
            // The backend is gone; the down-pump has already closed the client
            // channel, so replaying further ops would only write into a void.
            break;
        }
        op.apply(&relay, &up, client_id).await;
    }

    let _ = relay.backend.close().await;
}

/// A live agent leg plus the backend channel it authenticated.
///
/// `handle` is not decoration: russh's client driver task is spawned by
/// `client::connect_stream` and its lifecycle is bound to the `Handle`, which
/// owns the reply stream and the command sender the run loop ends on. Dropping
/// it would stop the transport while leaving the channel object — and every
/// later request would hang forever with no error. The inline relay path keeps
/// its handle in the session registry for exactly the same reason.
struct Established {
    backend_channel: russh::Channel<russh::client::Msg>,
    agent: SessionAgentClient,
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

/// Open the agent channel, list identities, and dial + authenticate the backend
/// with the one identity whose fingerprint matches the grant.
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
        .connect_agent(grant, public_key, &mut agent)
        .await
        .map_err(|e| format!("backend rejected the agent signature: {e}"))?;

    let backend_channel = backend
        .channel_open_session()
        .await
        .map_err(|e| format!("backend refused a session channel: {e}"))?;

    Ok(Established {
        backend_channel,
        agent,
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
    async fn try_enqueue_never_blocks_and_reports_the_bounded_queue() {
        let (tx, mut rx) = mpsc::channel(2);
        let handle = AgentHandle::new(tx);
        assert_eq!(handle.try_enqueue(AgentOp::Eof), Enqueued::Accepted);
        assert_eq!(handle.try_enqueue(AgentOp::Eof), Enqueued::Accepted);
        // Full: C5 says fail the channel, never await.
        assert_eq!(handle.try_enqueue(AgentOp::Eof), Enqueued::QueueFull);
        rx.recv().await.expect("one op must drain");
        assert_eq!(handle.try_enqueue(AgentOp::Eof), Enqueued::Accepted);
    }

    #[tokio::test]
    async fn a_closed_supervisor_rejects_further_ops_instead_of_buffering_them() {
        let (tx, _rx) = mpsc::channel(4);
        let handle = AgentHandle::new(tx);
        handle.shared.mark_closed();
        assert_eq!(handle.try_enqueue(AgentOp::Eof), Enqueued::Closed);
        assert_eq!(handle.enqueue(AgentOp::Eof).await, Enqueued::Closed);
    }

    #[tokio::test]
    async fn ready_state_delivers_ops_to_the_supervisor_in_order() {
        let (tx, mut rx) = mpsc::channel(8);
        let handle = AgentHandle::new(tx);
        handle.shared.mark_ready();
        assert_eq!(handle.enqueue(AgentOp::Eof).await, Enqueued::Accepted);
        assert_eq!(
            handle.enqueue(AgentOp::Shell { want_reply: false }).await,
            Enqueued::Accepted
        );
        assert!(matches!(rx.recv().await, Some(AgentOp::Eof)));
        assert!(matches!(
            rx.recv().await,
            Some(AgentOp::Shell { want_reply: false })
        ));
    }

    #[test]
    fn only_requests_that_asked_for_a_reply_get_one() {
        // An unsolicited CHANNEL_FAILURE would desynchronise the client, so the
        // failure path must key off the client's own want_reply flag.
        assert!(AgentOp::Shell { want_reply: true }.wants_reply());
        assert!(!AgentOp::Shell { want_reply: false }.wants_reply());
        assert!(AgentOp::Exec {
            command: b"true".to_vec(),
            want_reply: true
        }
        .wants_reply());
        assert!(!AgentOp::Data {
            data: Bytes::from_static(b"x")
        }
        .wants_reply());
        assert!(!AgentOp::Close.wants_reply());
    }
}
