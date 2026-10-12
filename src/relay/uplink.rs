//! The up-pump: client → backend (route 1 C3).
//!
//! Mirror image of [`pump_backend_to_client`](super::pump_backend_to_client):
//! this task owns the *client* channel's [`ChannelReadHalf`], the only reader
//! of that ordered stream, and forwards every message to the backend channel.
//!
//! Why a pump rather than the old serial `Handler` callbacks:
//!
//! * **I1 constructively** — data, requests, `eof` and `close` all arrive on
//!   one cursor, so "await each forward before consuming the next message" is
//!   strict FIFO by construction (same shape as the down-pump).
//! * **uplink zero-copy** — russh hands the read half *owned* `Bytes`, so the
//!   untapped fast path crosses to `backend.data_bytes` without the old
//!   `&[u8] -> to_vec()` allocation the handler API forced.
//! * **read-ahead** — the session read loop can run ahead into russh's bounded
//!   per-channel mpsc (`channel_buffer_size` × `max_packet`) while this task
//!   awaits the backend, instead of parking the whole session's serial event
//!   loop on one channel's forward.
//!
//! Invariants: I2 (replies routed via [`ReplyRouter`], answered with the
//! protocol-native success/failure), I3 (pass-through only — a tap `inject`
//! is client-bound *data*, never a request), I4 (denials use channel failure),
//! §3.6 (no unbounded buffering; the [`OutboundWindow`] fuse is applied before
//! bytes enter the pipeline). `agent`/`x11` requests stay on the handler
//! (local default-deny); this pump ignores their read-half echoes.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use russh::server;
use russh::{ChannelId, ChannelMsg, ChannelReadHalf};

use crate::audit::{ByteCounters, CommandInfo};
use crate::config::GatewayConfig;
use crate::metrics::Metrics;
use crate::server::SessionEntry;
use crate::types::Grant;

use super::{
    apply_tap_up, BackendWriter, ChannelTap, OutboundWindow, ReplyRouter, SubsystemInterceptor,
    Verdict, WindowClosed,
};

/// How long the up-pump waits for the backend's SUCCESS/FAILURE before
/// answering the client with a native failure (same budget the serial handler
/// path used).
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything the up-pump needs for one channel — the state the old per-packet
/// handler callbacks re-looked up in `self.relays` on every message.
pub struct RelayUpstream {
    /// Client-side channel id.
    pub client_id: ChannelId,
    /// Writable half of the backend channel (client → backend).
    pub backend: BackendWriter,
    /// Server session handle for the client leg (replies, tap inject).
    pub up: server::Handle,
    /// FIFO router for want_reply replies (I2), shared with the down-pump.
    pub router: ReplyRouter,
    /// Uplink window fuse (§3.6), closed by the down-pump on backend loss.
    pub window: Arc<OutboundWindow>,
    /// Shared up/down byte counters (fed to the audit record).
    pub bytes: Arc<ByteCounters>,
    /// Metrics handle (window exhaustion counter etc.).
    pub metrics: Metrics,
    /// B2/B3 per-channel tap (recording / SFTP inspection), if any.
    pub tap: Option<Arc<dyn ChannelTap>>,
    /// Gateway config (env allowlist, outbound guard, …).
    pub config: Arc<GatewayConfig>,
    /// Subsystem interceptor (SFTP deny etc.), consulted on RequestSubsystem.
    pub interceptor: Arc<dyn SubsystemInterceptor>,
    /// The authorized grant, handed to the interceptor.
    pub grant: Option<Grant>,
    /// Session registry entry (per-channel command class, drain awareness).
    pub entry: Option<Arc<SessionEntry>>,
    /// Shared audit sink (first command wins, `&self` recording).
    pub auditor: Option<Arc<crate::audit::Auditor>>,
}

impl RelayUpstream {
    /// Record what this channel is running (drain/D10 bookkeeping).
    fn set_channel_class(&self, class: crate::audit::CommandClass) {
        if let Some(entry) = &self.entry {
            entry.set_channel_class(self.client_id, class);
        }
    }

    /// Record the session's audit subject (first command wins).
    fn record_command(&self, info: CommandInfo) {
        if let Some(auditor) = &self.auditor {
            auditor.set_command(info);
        }
    }
}

/// Forward one reply-bearing request (I2): enqueue the reply slot *before* the
/// send, forward to the backend, then answer the client with the protocol
/// native SUCCESS/FAILURE routed back through the down-pump. A dropped or
/// timed-out receiver is reported as FAILURE (I4).
///
/// Returns `false` when the backend send itself failed (the backend channel is
/// gone) so the caller can stop pumping.
async fn forward_request(
    st: &RelayUpstream,
    want_reply: bool,
    send: impl std::future::Future<Output = Result<(), russh::Error>>,
) -> bool {
    let mut rx = st.router.push(want_reply);
    if let Err(e) = send.await {
        tracing::debug!(target: "relay", client_id = %st.client_id, %e, "uplink forward failed");
        return false;
    }
    if let Some(rx) = rx.as_mut() {
        match tokio::time::timeout(REPLY_TIMEOUT, &mut *rx).await {
            Ok(Ok(true)) => {
                let _ = st.up.channel_success(st.client_id).await;
            }
            _ => {
                let _ = st.up.channel_failure(st.client_id).await;
            }
        }
    }
    true
}

/// The up-pump: client → backend. The only reader of the client channel's
/// ordered stream, forwarding strictly in arrival order (I1).
///
/// Exit paths: the client sent `Close`, or the client channel stream ended
/// (`None` — the client leg died). Either way the backend channel is closed
/// (§3.5 coupled close). This pump deliberately does **not** close the
/// [`OutboundWindow`]: that stays the down-pump's job, so a closed window
/// always means "the backend is gone" and the client channel is always closed
/// exactly once (P0-2).
pub async fn pump_client_to_backend(mut client: ChannelReadHalf, st: RelayUpstream) {
    let mut saw_close = false;

    while let Some(msg) = client.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                if !pump_data(&st, data).await {
                    break;
                }
            }
            ChannelMsg::ExtendedData { data, ext } => {
                // Small, infrequent streams (stderr): no window fuse, exactly as
                // the old handler path — only the byte tally feeds the audit.
                let n = data.len();
                st.bytes.add_up(n);
                if let Err(e) = st.backend.extended_data_bytes(ext, data).await {
                    tracing::debug!(target: "relay", client_id = %st.client_id, %e, "uplink ext-data forward failed");
                    break;
                }
            }
            ChannelMsg::RequestPty {
                want_reply,
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes,
            } => {
                let ok = forward_request(
                    &st,
                    want_reply,
                    st.backend.request_pty(
                        want_reply,
                        &term,
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        &terminal_modes,
                    ),
                )
                .await;
                if !ok {
                    break;
                }
            }
            ChannelMsg::RequestShell { want_reply } => {
                st.set_channel_class(crate::audit::CommandClass::Interactive);
                let ok =
                    forward_request(&st, want_reply, st.backend.request_shell(want_reply)).await;
                if !ok {
                    break;
                }
            }
            ChannelMsg::Exec {
                want_reply,
                command,
            } => {
                st.set_channel_class(crate::audit::classify_exec_bytes(&command));
                st.record_command(CommandInfo::Exec(
                    String::from_utf8_lossy(&command).into_owned(),
                ));
                let ok =
                    forward_request(&st, want_reply, st.backend.exec(want_reply, command)).await;
                if !ok {
                    break;
                }
            }
            ChannelMsg::RequestSubsystem { want_reply, name } => {
                if !subsystem_request(&st, want_reply, &name).await {
                    break;
                }
            }
            ChannelMsg::SetEnv {
                want_reply,
                variable_name,
                variable_value,
            } => {
                // M1: pass-through unless an allowlist is configured (§3.4).
                let allowed =
                    crate::policy::env_allowed(&variable_name, &st.config.relay.env_allowlist);
                if matches!(allowed, crate::policy::ForwardDecision::DenyLocally { .. }) {
                    // Destined for a filtered-out env: drop silently (the client
                    // rarely asked for a reply anyway).
                    continue;
                }
                let ok = forward_request(
                    &st,
                    want_reply,
                    st.backend
                        .set_env(want_reply, &variable_name, &variable_value),
                )
                .await;
                if !ok {
                    break;
                }
            }
            ChannelMsg::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            } => {
                // No reply per RFC 4254 — never enqueues a router slot.
                if let Err(e) = st
                    .backend
                    .window_change(col_width, row_height, pix_width, pix_height)
                    .await
                {
                    tracing::debug!(target: "relay", client_id = %st.client_id, %e, "uplink window-change forward failed");
                    break;
                }
            }
            ChannelMsg::Signal { signal } => {
                // No reply per RFC 4254 — never enqueues a router slot.
                if let Err(e) = st.backend.signal(signal).await {
                    tracing::debug!(target: "relay", client_id = %st.client_id, %e, "uplink signal forward failed");
                    break;
                }
            }
            ChannelMsg::Eof => {
                if let Err(e) = st.backend.eof().await {
                    tracing::debug!(target: "relay", client_id = %st.client_id, %e, "uplink eof forward failed");
                    break;
                }
            }
            ChannelMsg::Close => {
                // §3.5 coupled close: the client finished, tell the backend.
                let _ = st.backend.close().await;
                saw_close = true;
                break;
            }
            // `AgentForward`/`RequestX11` are refused by the serial handler
            // (D6 default-deny) — never forwarded, and never replied to here:
            // the handler owns the single native failure for both. Everything
            // else is server-only traffic that cannot arrive on this half.
            other => {
                tracing::debug!(target: "relay", client_id = %st.client_id, ?other, "ignored client channel message");
            }
        }
    }

    if !saw_close {
        // The client leg vanished without a Close (session teardown): close the
        // backend half so the channel does not leak on the backend connection.
        let _ = st.backend.close().await;
    }
}

/// One uplink data packet: window fuse → tap → backend write.
///
/// Returns `false` when the pump must stop (window closed = backend gone, or
/// the backend write failed).
async fn pump_data(st: &RelayUpstream, data: Bytes) -> bool {
    if !charge_uplink_window(
        &st.window,
        &st.metrics,
        st.config.relay.outbound_guard,
        data.len(),
    )
    .await
    {
        tracing::info!(
            target: "relay",
            client_id = %st.client_id,
            "uplink window closed (backend gone); stopping up-pump"
        );
        return false;
    }

    // B2/B3: the channel tap may withhold part of the payload and answer the
    // client directly (e.g. a synthesized SFTP permission-denied status). The
    // owned `Bytes` is forwarded as-is whenever the tap passes it (zero-copy).
    let (payload, inject) = apply_tap_up(st.tap.as_ref(), data, st.client_id);
    let n = payload.len();
    // The refusal answer goes on the same channel-data stream the request
    // arrived on; writing it to stderr instead would strand the client.
    if !inject.is_empty() && st.up.data(st.client_id, inject).await.is_err() {
        tracing::debug!(target: "relay", client_id = %st.client_id, "could not deliver tap response to client");
        return false;
    }
    if payload.is_empty() {
        return true; // fully withheld (or an empty packet): nothing to forward
    }
    st.bytes.add_up(n);
    if let Err(e) = st.backend.data_bytes(payload).await {
        tracing::debug!(target: "relay", client_id = %st.client_id, %e, "uplink forward failed");
        return false;
    }
    true
}

/// Charge one packet against the §3.6 uplink fuse. Returns `false` when the
/// window is closed (the backend is gone) and the pump must stop.
///
/// The fuse is only applied when `guard` is on; the fast path is
/// [`OutboundWindow::try_acquire`], which never yields. `window_exhausted` is
/// recorded on the genuinely-blocking path only (the old per-packet probe
/// moved here with the pump).
async fn charge_uplink_window(
    window: &OutboundWindow,
    metrics: &Metrics,
    guard: bool,
    n: usize,
) -> bool {
    if !guard {
        return true;
    }
    match window.try_acquire(n) {
        Ok(true) => true,
        Ok(false) => {
            // Slow path: this send actually blocks — record the exhaustion and
            // wait for the backend's WINDOW_ADJUST. P0-2: the down-pump closes
            // the window the instant the backend dies, so this can never wedge.
            metrics.window_exhausted();
            window.acquire(n).await.is_ok()
        }
        Err(WindowClosed) => false,
    }
}

/// One subsystem request: interceptor first (§3.7), then classify + forward.
///
/// Returns `false` when the pump must stop (backend send failed). A local
/// denial answers the client with a native channel failure and keeps pumping
/// (I4) — the channel stays open for a possible retry.
async fn subsystem_request(st: &RelayUpstream, want_reply: bool, name: &str) -> bool {
    // Audit subject first (first command on the session wins), matching the
    // old serial path's ordering.
    st.record_command(CommandInfo::Subsystem(name.to_owned()));

    // Interceptor hook (default: zero-cost Pass). A Deny short-circuits with a
    // native failure; never fabricate output (I4).
    let Some(grant) = st.grant.clone() else {
        let _ = st.up.channel_failure(st.client_id).await;
        return true;
    };
    let verdict = st.interceptor.on_subsystem_request(name, &grant).await;
    if let Verdict::Deny(reason) = verdict {
        tracing::info!(target: "relay", client_id = %st.client_id, %reason, %name, "subsystem request denied by interceptor");
        let _ = st.up.channel_failure(st.client_id).await;
        return true;
    }

    st.set_channel_class(CommandInfo::Subsystem(name.to_owned()).classify());
    forward_request(
        st,
        want_reply,
        st.backend.request_subsystem(want_reply, name),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn charge_window_passes_through_when_guard_is_off() {
        let window = OutboundWindow::uncalibrated();
        window.note_window(0); // would exhaust everything…
                               // …but the fuse is disabled, so traffic flows untouched.
        assert!(charge_uplink_window(&window, &Metrics::default(), false, 1_000_000).await);
        assert!(
            window.would_exhaust(1),
            "the guard-off path must not consume any permits"
        );
    }

    #[tokio::test]
    async fn charge_window_rejects_a_closed_window() {
        // P0-2: a dead backend closes the window; the pump must stop cleanly.
        let window = OutboundWindow::uncalibrated();
        window.close();
        assert!(
            !charge_uplink_window(&window, &Metrics::default(), true, 1).await,
            "a closed window must stop the pump, not wedge it"
        );
    }

    #[tokio::test]
    async fn charge_window_blocks_then_resumes_on_adjust() {
        let window = Arc::new(OutboundWindow::uncalibrated());
        window.note_window(4);
        let metrics = Metrics::default();

        // Room for the first packet: fast path, no blocking.
        assert!(charge_uplink_window(&window, &metrics, true, 4).await);

        // Second packet exhausts the window: the slow path parks until the
        // backend's WINDOW_ADJUST arrives.
        let probe = {
            let window = Arc::clone(&window);
            let metrics = metrics.clone();
            tokio::spawn(async move { charge_uplink_window(&window, &metrics, true, 3).await })
        };
        tokio::task::yield_now().await;
        assert!(
            !probe.is_finished(),
            "the slow path must block on an empty window"
        );
        window.note_window(3);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), probe)
                .await
                .expect("the parked send must resume after the adjust")
                .expect("task join"),
            "the resumed send must charge the window and proceed"
        );
    }
}
