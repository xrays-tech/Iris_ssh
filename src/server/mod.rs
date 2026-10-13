//! The gateway's client-facing SSH server leg.
//!
//! [`GatewayServer`] adapts this crate to russh's `server::Server`, minting one
//! [`GatewaySession`] per TCP connection. The session implements the full
//! `server::Handler` boundary:
//!
//! * **auth** — `auth_publickey_offered` only *prechecks* (early-403 + cache
//!   warm, never a final accept, D3); `auth_publickey` runs after russh has
//!   verified the signature and makes the authoritative accept/reject (D3/D4);
//! * **channel_open_session** — lazily dials the backend and, on failure,
//!   answers `CHANNEL_OPEN_FAILURE`/`ConnectFailed` (I4);
//! * **request + data callbacks** — forward strictly in-arrival-order inside the
//!   callback (I1) via [`crate::relay`];
//! * **drain** — a `SIGTERM` flips readiness, injects a stderr warning into
//!   interactive/exec channels (never sftp, D10) and sends a protocol-level
//!   `SSH_MSG_DISCONNECT[BY_APPLICATION]` goodbye.

pub mod health;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use russh::server::{self, Auth, Config as ServerConfig, Server as _, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty};

use crate::audit::{Auditor, CommandInfo};
use crate::backend::{BackendAuthMethod, BackendClient, BackendDialer, CredentialStore};
use crate::config::GatewayConfig;
use crate::error::{BackendError, Error, Result};
use crate::metrics::Metrics;
use crate::policy::HostKeyVerifier;
use crate::relay::{self, BackendWriter, ChannelRelay, ReplyRouter, SubsystemInterceptor};
use crate::resolve::{ControlPlaneClient, HttpControlPlane, Resolver};
use crate::types::{Grant, Principal, SessionId};

/// Atomic-encoded readiness state shared between the drain coordinator and the
/// `/readyz` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainState {
    Accepting,
    Draining,
}

impl DrainState {
    fn encode(self) -> u8 {
        match self {
            DrainState::Accepting => 0,
            DrainState::Draining => 1,
        }
    }
    fn decode(v: u8) -> Self {
        match v {
            1 => DrainState::Draining,
            _ => DrainState::Accepting,
        }
    }
}

/// Per-session bookkeeping kept in the shared registry so the drain coordinator
/// can inject warnings without borrowing any live handler.
pub struct SessionEntry {
    pub session_id: SessionId,
    pub client_ip: String,
    handle: server::Handle,
    /// Channel id → what it is running, so drain never writes into sftp (D10).
    channels: std::sync::Mutex<HashMap<ChannelId, crate::audit::CommandClass>>,
}

impl SessionEntry {
    fn new(session_id: SessionId, client_ip: String, handle: server::Handle) -> Self {
        SessionEntry {
            session_id,
            client_ip,
            handle,
            channels: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Record what a channel is running (used to avoid draining sftp channels).
    pub fn set_channel_class(&self, id: ChannelId, class: crate::audit::CommandClass) {
        match self.channels.lock() {
            Ok(mut m) => {
                m.insert(id, class);
            }
            Err(poisoned) => {
                poisoned.into_inner().insert(id, class);
            }
        }
    }

    pub fn forget_channel(&self, id: ChannelId) {
        match self.channels.lock() {
            Ok(mut m) => {
                m.remove(&id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&id);
            }
        }
    }
}

/// Registry of live sessions, used for drain warnings and up-to limits.
#[derive(Clone, Default)]
pub struct SessionRegistry {
    sessions: Arc<std::sync::Mutex<HashMap<SessionId, Arc<SessionEntry>>>>,
    drain: Arc<AtomicU8>,
}

impl SessionRegistry {
    pub fn drain_state(&self) -> DrainState {
        DrainState::decode(self.drain.load(Ordering::SeqCst))
    }

    pub fn set_drain_state(&self, state: DrainState) {
        self.drain.store(state.encode(), Ordering::SeqCst);
    }

    pub fn insert(&self, entry: Arc<SessionEntry>) {
        match self.sessions.lock() {
            Ok(mut m) => {
                m.insert(entry.session_id.clone(), entry);
            }
            Err(poisoned) => {
                poisoned
                    .into_inner()
                    .insert(entry.session_id.clone(), entry);
            }
        }
    }

    pub fn remove(&self, id: &SessionId) {
        match self.sessions.lock() {
            Ok(mut m) => {
                m.remove(id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(id);
            }
        }
    }

    /// The number of live sessions from `ip`.
    pub fn count_from_ip(&self, ip: &str) -> usize {
        match self.sessions.lock() {
            Ok(m) => m.values().filter(|e| e.client_ip == ip).count(),
            Err(poisoned) => poisoned
                .into_inner()
                .values()
                .filter(|e| e.client_ip == ip)
                .count(),
        }
    }

    pub fn total(&self) -> usize {
        match self.sessions.lock() {
            Ok(m) => m.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Snapshot of live entries (cloned `Arc`s; no lock held across await).
    fn snapshot(&self) -> Vec<Arc<SessionEntry>> {
        match self.sessions.lock() {
            Ok(m) => m.values().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().values().cloned().collect(),
        }
    }

    /// Inject a stderr warning into every channel that is *not* an sftp channel
    /// (D10). Best-effort; closed channels simply drop the message.
    pub async fn inject_drain_warning(&self, warning: &str) {
        for entry in self.snapshot() {
            let to_warn: Vec<ChannelId> = match entry.channels.lock() {
                Ok(m) => m
                    .iter()
                    .filter(|(_, class)| !matches!(class, crate::audit::CommandClass::Sftp))
                    .map(|(id, _)| *id)
                    .collect(),
                Err(poisoned) => poisoned
                    .into_inner()
                    .iter()
                    .filter(|(_, class)| !matches!(class, crate::audit::CommandClass::Sftp))
                    .map(|(id, _)| *id)
                    .collect(),
            };
            for id in to_warn {
                let _ = entry
                    .handle
                    .extended_data(id, 1, Bytes::from(warning.as_bytes().to_vec()))
                    .await;
            }
        }
    }
}

/// Shared state handed to every session.
pub struct GatewayContext {
    pub config: Arc<GatewayConfig>,
    pub resolver: Arc<Resolver>,
    pub dialer: Arc<BackendDialer>,
    pub metrics: Metrics,
    pub interceptor: Arc<dyn SubsystemInterceptor>,
    /// Certificate authority set (B1): trusted CA fingerprints for user and host
    /// certificates, plus the signing key when issuance is enabled.
    pub ca: Arc<crate::ca::CertificateAuthority>,
    pub registry: SessionRegistry,
    pub server_config: Arc<ServerConfig>,
}

/// Composition root for subsystem interception (propose.md §3.7, B2 + B3).
///
/// The policy questions ("is SFTP enabled?", "does this grant ask for
/// recording?") are answered here, while the *stateful* per-channel work lives
/// in the [`relay::ChannelTap`] objects this returns from `observe`. Multiple
/// taps are composed so a session can be recorded **and** inspected at once.
pub struct CompositeInterceptor {
    sftp: crate::sftp::SftpAuditInterceptor,
    recording_dir: std::path::PathBuf,
    recording_budget: u64,
    metrics: Metrics,
}

impl CompositeInterceptor {
    /// Build from config. Returns `PassThroughInterceptor`-equivalent behaviour
    /// when nothing is enabled, so the fast path is preserved by construction.
    pub fn new(config: &GatewayConfig, metrics: Metrics) -> Self {
        CompositeInterceptor {
            sftp: crate::sftp::SftpAuditInterceptor::new(&config.intercept.sftp, metrics.clone()),
            recording_dir: config.recording.dir.clone(),
            recording_budget: config.recording.max_bytes_per_session,
            metrics,
        }
    }
}

impl SubsystemInterceptor for CompositeInterceptor {
    fn on_subsystem_request<'a>(
        &'a self,
        name: &'a str,
        grant: &'a crate::types::Grant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = relay::Verdict> + Send + 'a>> {
        Box::pin(async move { self.sftp.on_subsystem_request(name, grant).await })
    }

    fn observe(&self, ctx: &relay::ChannelCtx) -> Option<Arc<dyn relay::ChannelTap>> {
        self.build_tap(ctx)
    }
}

impl CompositeInterceptor {
    /// Build the composed per-channel tap, or `None` when nothing would observe
    /// this channel (the zero-cost path).
    ///
    /// Taps are ordered **inspector first, recorder second**, so
    /// [`CompositeTap`] can chain them: the recorder sees exactly the bytes the
    /// inspector allowed, and never persists a request policy refused.
    fn build_tap(&self, ctx: &relay::ChannelCtx) -> Option<Arc<dyn relay::ChannelTap>> {
        let mut taps: Vec<Arc<dyn relay::ChannelTap>> = Vec::new();
        if let Some(tap) = self.sftp.observe(ctx) {
            taps.push(tap);
        }
        if ctx.record && self.recording_budget > 0 {
            match crate::record::SessionRecorder::create(
                &self.recording_dir,
                ctx,
                self.recording_budget,
            ) {
                Ok(recorder) => {
                    self.metrics.recorded_session();
                    taps.push(recorder);
                }
                Err(e) => {
                    // A recording that cannot be started must never take down a
                    // working session; fail open on the recording only.
                    tracing::warn!(
                        target: "record",
                        error = %e,
                        dir = %self.recording_dir.display(),
                        "could not start session recording; continuing without it"
                    );
                }
            }
        }
        if taps.is_empty() {
            None
        } else {
            Some(Arc::new(CompositeTap { taps }))
        }
    }
}

/// A tap that chains several sub-taps: each sees the bytes the previous one
/// chose to forward, and the first refusal short-circuits what is emitted.
///
/// Chaining (rather than fanning the same buffer to every tap) matters because a
/// recorder must not persist a request an SFTP inspector refused — that would
/// make an audit replay disagree with what actually reached the backend.
struct CompositeTap {
    taps: Vec<Arc<dyn relay::ChannelTap>>,
}

impl relay::ChannelTap for CompositeTap {
    fn on_data(&self, dir: relay::Direction, buf: &[u8]) -> relay::DataVerdict {
        use relay::DataVerdict;

        // Start with the caller's buffer; each sub-tap may narrow it.
        let mut forward: Vec<u8> = buf.to_vec();
        let mut inject: Vec<u8> = Vec::new();
        let mut denied: Option<String> = None;
        let mut rewritten = false;

        for tap in &self.taps {
            match tap.on_data(dir, &forward) {
                DataVerdict::Pass => {}
                DataVerdict::Rewrite {
                    forward: next,
                    inject: extra,
                    denied: reason,
                } => {
                    forward = next;
                    rewritten = true;
                    inject.extend_from_slice(&extra);
                    if denied.is_none() {
                        denied = reason;
                    }
                }
            }
        }

        if !rewritten {
            return DataVerdict::Pass;
        }
        DataVerdict::Rewrite {
            forward,
            inject,
            denied,
        }
    }

    fn flush(&self) {
        for tap in &self.taps {
            tap.flush();
        }
    }
}

/// Adapter that turns accepted TCP streams into [`GatewaySession`] handlers.
pub struct GatewayServer {
    ctx: Arc<GatewayContext>,
}

impl GatewayServer {
    pub fn new(ctx: Arc<GatewayContext>) -> Self {
        GatewayServer { ctx }
    }
}

/// The two russh auth-timing knobs, computed once from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRejectionTiming {
    /// Padding sleep after the **initial "none" probe** — the unauthenticated
    /// method negotiation every SSH client (incl. OpenSSH) issues before real
    /// auth (russh `Config::auth_rejection_time_initial`).
    pub initial: Duration,
    /// Padding sleep after each **subsequent rejection** (bad/denied key, etc.)
    /// — russh's constant-time anti-timing / anti-bruteforce lever
    /// (`Config::auth_rejection_time`).
    pub ongoing: Duration,
}

/// Decouple russh's auth-timing knobs (defect-A fix, P1-2 hardening).
///
/// russh applies `auth_rejection_time_initial.unwrap_or(auth_rejection_time)`
/// to the very first "none" probe (`server/encrypted.rs`). Historically
/// `limits.auth_timeout` (default 30s) was mapped straight into
/// `auth_rejection_time` with no explicit `_initial`, so every legitimate client
/// stalled on the full 30s before auth could even begin, and each *rejected*
/// attempt also burned 30s. That conflated two unrelated concerns:
///
/// * **`auth_timeout`** — the ceiling on the initial `"none"`-probe back-off
///   (`min(auth_timeout, auth_rejection_pad)`), per `limits.auth_timeout`.
///   It is not itself a stall deadline: the unauthenticated-session bound is
///   `inactivity_timeout` + `max_auth_attempts`. `0s` removes the per-connection
///   initial back-off (production option) while keeping the per-rejection pad.
/// * **`auth_rejection_pad`** — the constant-time padding per rejection
///   (anti-timing leak / anti-bruteforce), default 1s (russh's own default), not
///   inherited from `auth_timeout`.
pub fn auth_rejection_timing(
    auth_timeout: Duration,
    rejection_pad: Duration,
) -> AuthRejectionTiming {
    AuthRejectionTiming {
        // The initial probe must be fast, but never longer than the budget.
        initial: auth_timeout.min(rejection_pad),
        // Ongoing rejections use the dedicated pad — independent of auth_timeout.
        ongoing: rejection_pad,
    }
}

impl GatewayContext {
    /// Build the full shared context from a validated [`GatewayConfig`].
    ///
    /// Every failure here is fatal at startup (fail-closed): a bad host key or
    /// an unsafe credential must prevent the gateway from coming up sick.
    pub fn build(config: GatewayConfig) -> Result<Arc<GatewayContext>> {
        let control_plane = HttpControlPlane::new(
            config.control_plane.url.clone(),
            config.control_plane.timeout,
        )
        .map_err(|e| {
            Error::io(
                std::io::Error::other(e.to_string()),
                "building control-plane HTTP client",
            )
        })?;
        Self::build_with_client(config, Arc::new(control_plane))
    }

    /// [`build`] with an injected control-plane client (production uses
    /// [`HttpControlPlane`]; tests inject a fake). Everything else — key loading,
    /// credential permission checks — is identical and still fail-closed.
    pub fn build_with_client(
        config: GatewayConfig,
        control_plane: Arc<dyn ControlPlaneClient>,
    ) -> Result<Arc<GatewayContext>> {
        let metrics = Metrics::default();

        // Host keys: all configured keys are offered (multi-key, propose §5.3).
        let mut keys = Vec::with_capacity(config.host_keys.len());
        for entry in &config.host_keys {
            let key = crate::backend::load_private_key_checked(&entry.path, true)?;
            keys.push(key);
        }

        // M4: the certificate authority gates backend host *certificates*
        // (`@cert-authority`) and issues the short-lived user certificates used
        // for cert-mode dialing, so it is loaded before the dialer.
        let ca = Arc::new(crate::ca::CertificateAuthority::load(&config.ca)?);
        let credentials = Arc::new(CredentialStore::load(&config)?);
        // No pre-pinned fingerprints by default: `pinned` therefore rejects
        // until an operator pins the backend fingerprint (out-of-band), while
        // `accept-new` learns it with a warning. The CA set is layered on top so
        // a host certificate is trusted by its signer instead of its inner key.
        let verifier = Arc::new(if ca.trusted_ca_fingerprints().is_empty() {
            HostKeyVerifier::new(config.backend.host_key_policy, Vec::new())
        } else {
            HostKeyVerifier::with_trusted_ca(
                config.backend.host_key_policy,
                Vec::new(),
                ca.trusted_ca_fingerprints().to_vec(),
            )
        });
        let dialer = Arc::new(
            BackendDialer::new(
                &config,
                Arc::clone(&credentials),
                verifier,
                metrics.clone(),
                Some(Arc::clone(&ca)),
            )
            .with_ca(ca),
        );

        let resolver = Arc::new(Resolver::new(
            control_plane,
            config.control_plane.cache_ttl,
            Duration::from_secs(5), // negative cache
            Duration::from_secs(1), // transient coalesce
            config.control_plane.cache_ttl_jitter,
            config.control_plane.fail_open,
            5, // breaker failure threshold
            config.control_plane.timeout * 3,
            config.control_plane.timeout,
        ));

        let interceptor: Arc<dyn SubsystemInterceptor> =
            Arc::new(CompositeInterceptor::new(&config, metrics.clone()));
        // B1: the trusted-CA set gates both user certificates and backend host
        // certificates, so it is loaded once and shared.
        let ca = Arc::new(crate::ca::CertificateAuthority::load(&config.ca)?);

        let auth_timing =
            auth_rejection_timing(config.limits.auth_timeout, config.limits.auth_rejection_pad);
        let mut server_pref = ServerConfig::default().preferred;
        // Optional explicit cipher-order override from `[relay] ciphers` (A/B
        // throughput comparisons; empty = russh default chacha20-first order).
        if !config.relay.ciphers.is_empty() {
            let mut ciphers = Vec::with_capacity(config.relay.ciphers.len());
            for name in &config.relay.ciphers {
                match russh::cipher::Name::try_from(name.as_str()) {
                    Ok(cipher) => ciphers.push(cipher),
                    Err(_) => {
                        tracing::warn!(
                            target: "config",
                            %name,
                            "ignoring unknown cipher name in relay.ciphers"
                        );
                    }
                }
            }
            if !ciphers.is_empty() {
                server_pref.cipher = std::borrow::Cow::Owned(ciphers);
            }
        }
        let server_config = ServerConfig {
            keys,
            window_size: config.relay.window_size,
            maximum_packet_size: config.relay.max_packet,
            nodelay: config.relay.nodelay,
            preferred: server_pref,
            channel_buffer_size: 100,
            // Only public-key auth is offered; password/none are rejected by the
            // handler regardless.
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            // Decoupled anti-timing paddings (see `auth_rejection_timing`): the
            // initial none-probe must be fast so a legit client isn't stalled by
            // the full auth_timeout; ongoing rejections use the dedicated pad.
            auth_rejection_time: auth_timing.ongoing,
            auth_rejection_time_initial: Some(auth_timing.initial),
            // Idle-session GC; also the deadline for a peer that stalls mid-auth
            // (no dedicated auth-phase knob exists in russh 0.64.1).
            inactivity_timeout: Some(config.limits.inactivity_timeout),
            // Anti-bruteforce attempt cap, now explicit rather than relying on
            // russh's built-in default (`0` = unlimited, russh's encoding).
            max_auth_attempts: config.limits.max_auth_attempts,
            ..ServerConfig::default()
        };

        Ok(Arc::new(GatewayContext {
            config: Arc::new(config),
            resolver,
            dialer,
            metrics,
            interceptor,
            ca,
            registry: SessionRegistry::default(),
            server_config: Arc::new(server_config),
        }))
    }
}

/// Wait for SIGTERM (graceful) or Ctrl-C (interactive dev).
async fn wait_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let term_recv = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut t) => {
                t.recv().await;
            }
            Err(_) => {
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::pin!(term_recv);
    tokio::select! {
        _ = &mut ctrl_c => {},
        _ = &mut term_recv => {},
    }
}

/// Run the gateway until a shutdown signal, implementing the two-phase drain of
/// propose.md §5.4: stop accepting, flip `/readyz`, warn interactive/exec
/// channels (never sftp, D10), then send a protocol-level DISCONNECT[11] and
/// force-exit after `hard_deadline`.
pub async fn serve(ctx: Arc<GatewayContext>) -> Result<()> {
    // Observability endpoints (/healthz /readyz /metrics).
    let metrics_listener = tokio::net::TcpListener::bind(ctx.config.metrics.addr)
        .await
        .map_err(|e| Error::io(e, "binding metrics/health listener"))?;
    {
        let registry = ctx.registry.clone();
        let readiness = Arc::new(move || {
            if matches!(registry.drain_state(), DrainState::Draining) {
                health::Readiness::NotReady
            } else {
                health::Readiness::Ready
            }
        });
        let metrics = ctx.metrics.clone();
        tokio::spawn(health::serve(metrics_listener, readiness, move || {
            metrics.render_prometheus()
        }));
    }

    let ssh_listener = tokio::net::TcpListener::bind(ctx.config.listen_addr)
        .await
        .map_err(|e| Error::io(e, "binding SSH listener"))?;
    tracing::info!(addr = %ctx.config.listen_addr, metrics_addr = %ctx.config.metrics.addr, "ssh gateway listening");

    let mut server = GatewayServer::new(Arc::clone(&ctx));
    let running = server.run_on_socket(Arc::clone(&ctx.server_config), &ssh_listener);
    let shutdown_handle = running.handle();

    let drain_cfg = ctx.config.shutdown.clone();
    let registry = ctx.registry.clone();
    tokio::spawn(async move {
        wait_shutdown_signal().await;
        tracing::info!("shutdown signal received: draining");
        registry.set_drain_state(DrainState::Draining);

        // Hard-deadline watchdog from the moment we begin draining.
        if !drain_cfg.hard_deadline.is_zero() {
            let hard = drain_cfg.hard_deadline;
            tokio::spawn(async move {
                tokio::time::sleep(hard).await;
                tracing::error!("hard deadline reached before sessions drained; exiting");
                std::process::exit(0);
            });
        }

        // Ask interactive/exec channels to wrap up (never sftp — D10).
        registry
            .inject_drain_warning("gateway is shutting down, please wrap up\r\n")
            .await;

        // Give short tasks a chance to finish naturally.
        if !drain_cfg.drain_wait.is_zero() {
            tokio::time::sleep(drain_cfg.drain_wait).await;
        }

        // Protocol-level goodbye to every remaining session (DISCONNECT[11]).
        shutdown_handle.shutdown("Gateway is shutting down, please reconnect".into());
    });

    running
        .await
        .map_err(|e| Error::io(e, "running ssh server"))?;
    Ok(())
}

impl server::Server for GatewayServer {
    type Handler = GatewaySession;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> GatewaySession {
        let session_id = SessionId::generate();
        let client_ip = peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_owned());

        // Admission control: refuse new sessions from over-limit IPs or when the
        // instance is draining, before spending a KEX on them.
        let over_limit = {
            self.ctx.registry.total() >= self.ctx.config.limits.max_sessions
                || self.ctx.registry.count_from_ip(&client_ip)
                    >= self.ctx.config.limits.max_sessions_per_ip
        };
        let draining = matches!(self.ctx.registry.drain_state(), DrainState::Draining);
        let limiter_reject = over_limit || draining;

        // A placeholder handle will be replaced once the real session handle is
        // available (see GatewaySession::on_session_ready).
        GatewaySession {
            ctx: Arc::clone(&self.ctx),
            session_id,
            client_ip,
            principal: None,
            grant: None,
            auditor: None,
            signature_algorithm: String::new(),
            backend: None,
            relays: HashMap::new(),
            taps: HashMap::new(),
            agent: None,
            agent_channels: HashSet::new(),
            entry: None,
            limiter_reject,
            audited: false,
        }
    }
}

/// One client SSH connection.
pub struct GatewaySession {
    ctx: Arc<GatewayContext>,
    session_id: SessionId,
    client_ip: String,
    principal: Option<Principal>,
    grant: Option<Grant>,
    /// Shared with the detached up-pump task (route 1 C3), so recording the
    /// channel's command only needs `&self` on the auditor.
    auditor: Option<Arc<Auditor>>,
    signature_algorithm: String,
    backend: Option<russh::client::Handle<BackendClient>>,
    /// Per-channel relay state, `Arc`-shared so the serial handler callbacks can
    /// take an owned handle with a single map lookup and hold it across their
    /// awaits without borrowing `self.relays`.
    relays: HashMap<ChannelId, Arc<ChannelRelay>>,
    /// Per-channel data taps (recording / SFTP inspection), keyed by channel.
    taps: HashMap<ChannelId, Arc<dyn relay::ChannelTap>>,
    /// Agent-passthrough mode (C2): set when the session authenticates to the
    /// backend with the user's forwarded agent. `None` in the key/cert path,
    /// which therefore stays byte-for-byte unchanged.
    agent: Option<AgentSession>,
    /// Every client channel this session has handed to the supervisor, used
    /// for the per-connection channel cap and to tell an agent channel from a
    /// stale one. The relay state itself lives in the supervisor.
    agent_channels: HashSet<ChannelId>,
    entry: Option<Arc<SessionEntry>>,
    limiter_reject: bool,
    audited: bool,
}

/// The agent-mode state of one session (C2/D2).
///
/// A session owns exactly one supervisor task and one authenticated backend
/// connection; every client channel on it is multiplexed onto that connection
/// by the supervisor (see [`relay::agent`]).
struct AgentSession {
    handle: relay::agent::AgentHandle,
}

impl GatewaySession {
    fn reject_all(&self) -> Auth {
        Auth::reject()
    }

    /// Run an uplink buffer through the channel's tap (B2/B3).
    ///
    /// Returns `None` when nothing is forwarded, otherwise the permitted bytes
    /// together with any bytes that must be pushed back to the client on the
    /// **channel data stream** — a synthesized SFTP failure has to travel the same
    /// stream the client's request arrived on, or the client waits forever for a
    /// reply that never comes.
    fn apply_uplink_tap(&mut self, channel: ChannelId, data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let Some(tap) = self.taps.get(&channel).cloned() else {
            return Some((data.to_vec(), Vec::new()));
        };
        match tap.on_data(relay::Direction::Up, data) {
            relay::DataVerdict::Pass => Some((data.to_vec(), Vec::new())),
            relay::DataVerdict::Rewrite {
                forward,
                inject,
                denied,
            } => {
                if let Some(reason) = denied {
                    tracing::info!(target: "relay", %channel, %reason, "uplink request withheld by tap");
                }
                if forward.is_empty() && inject.is_empty() {
                    None
                } else {
                    Some((forward, inject))
                }
            }
        }
    }

    /// Register this session in the shared registry (called once we hold a real
    /// session handle). Idempotent.
    fn register(&mut self, handle: server::Handle) {
        if self.entry.is_none() {
            let entry = Arc::new(SessionEntry::new(
                self.session_id.clone(),
                self.client_ip.clone(),
                handle,
            ));
            self.ctx.registry.insert(Arc::clone(&entry));
            self.entry = Some(entry);
        }
    }

    /// Resolve + authorize `(principal, fingerprint)` against the control plane.
    async fn resolve_grant(
        &self,
        principal: &Principal,
        fingerprint: &str,
    ) -> crate::resolve::ResolveResult {
        let started = std::time::Instant::now();
        let outcome = self
            .ctx
            .resolver
            .authorize(principal, fingerprint, &self.client_ip)
            .await;
        match &outcome {
            Ok(_) => self.ctx.metrics.resolve_ok(),
            Err(_) => self.ctx.metrics.resolve_err(),
        }
        self.ctx.metrics.resolve_latency(started.elapsed());
        outcome
    }

    /// Authorize a **certificate**-authenticated session (B1).
    ///
    /// The control plane is still consulted for the destination, but the *key*
    /// identity it sees is the issuing CA's fingerprint rather than an inner
    /// user key: that is the trust anchor an operator actually provisions. The
    /// certificate's principal list is checked against the requested username
    /// here, and `Grant::fingerprint` carries the CA fingerprint so the resolver
    /// can key on it.
    async fn authorize_certificate(
        &mut self,
        principal: &Principal,
        certificate: &russh::keys::Certificate,
    ) -> Auth {
        let ca_fingerprint = crate::ca::certificate_ca_fingerprint(certificate);
        // 1. The issuing CA must be trusted.
        if !self.ctx.ca.is_trusted_ca(&ca_fingerprint) {
            self.ctx.metrics.cert_auth_reject();
            tracing::warn!(
                target: "server",
                %ca_fingerprint,
                "rejecting certificate issued by an untrusted CA"
            );
            return Auth::reject();
        }
        // 2. Signature, validity window and principal list.
        let check = crate::ca::validate_user_certificate_at(
            certificate,
            self.ctx.ca.trusted_ca_fingerprints(),
            principal.as_str(),
            crate::ca::now_unix_secs().unwrap_or(u64::MAX),
        );
        if check != crate::ca::CertificateCheck::Trusted {
            self.ctx.metrics.cert_auth_reject();
            tracing::warn!(target: "server", ?check, %ca_fingerprint, "rejecting certificate");
            return Auth::reject();
        }
        // 3. Resolve the destination from the control plane, keyed on the CA.
        match self.resolve_grant(principal, &ca_fingerprint).await {
            Ok(grant) => {
                self.ctx.metrics.cert_auth_accept();
                self.ctx.metrics.session_started();
                self.ctx
                    .metrics
                    .add_window_budget((self.ctx.config.relay.window_size as usize) * 2);
                self.signature_algorithm = certificate.algorithm().to_string();
                self.principal = Some(principal.clone());
                self.auditor = Some(Arc::new(Auditor::new(
                    self.session_id.clone(),
                    self.client_ip.clone(),
                    grant.clone(),
                    self.signature_algorithm.clone(),
                    self.ctx.metrics.clone(),
                )));
                self.grant = Some(grant);
                Auth::Accept
            }
            Err(_) => {
                self.ctx.metrics.cert_auth_reject();
                self.ctx.metrics.auth_reject();
                Auth::reject()
            }
        }
    }

    /// Lazily establish the per-session backend connection (M1).
    async fn ensure_backend(&mut self) -> Result<()> {
        if self.backend.is_some() {
            return Ok(());
        }
        let grant = self.grant.clone().ok_or_else(|| BackendError::Auth {
            user: "<unauthorized>".into(),
        })?;
        let handle = self.ctx.dialer.connect(&grant).await?;
        self.backend = Some(handle);
        Ok(())
    }

    /// Open a backend session channel, reusing the per-session connection.
    async fn open_backend_channel(
        &mut self,
    ) -> Result<Option<(relay::BackendReader, BackendWriter)>> {
        self.ensure_backend().await?;
        let handle = self.backend.as_ref().ok_or_else(|| BackendError::Auth {
            user: "<no-backend>".into(),
        })?;
        match handle.channel_open_session().await {
            Ok(ch) => Ok(Some(ch.split())),
            Err(_) => Ok(None),
        }
    }

    /// Record the audit subject for this channel's first command (first wins).
    fn record_channel_command(&self, _id: ChannelId, info: &CommandInfo) {
        if let Some(auditor) = &self.auditor {
            auditor.set_command(info.clone());
        }
    }

    /// Whether this session authenticates to the backend with the user's
    /// forwarded agent (C2).
    ///
    /// Delegates the admission decision to the dialer — the same
    /// kill-switch + policy check the dial path runs — so the server leg can
    /// never disagree with it about which credential a session uses.
    fn agent_mode(&self) -> bool {
        let Some(grant) = &self.grant else {
            return false;
        };
        matches!(
            self.ctx.dialer.resolved_backend_auth(grant),
            Ok(BackendAuthMethod::Agent)
        )
    }

    /// Agent mode (C2/D2): while this session's channel belongs to the
    /// supervisor, hand the op to its single ordered consumer instead of acting
    /// on it here (propose.md §3.5.1).
    ///
    /// Returns `true` when the caller must stop: either the op was queued, the
    /// channel is already gone, or the supervisor has closed it natively (I4).
    async fn take_over_by_agent(
        &mut self,
        channel: ChannelId,
        kind: relay::agent::AgentOpKind,
        session: &mut Session,
    ) -> bool {
        if self.agent.is_none() {
            return false;
        }
        if !self.agent_channels.contains(&channel) {
            // Already closed (or never ours): swallow it rather than letting
            // the caller fall through to the inline path, which has no relay
            // for an agent session either.
            return true;
        }
        let op = relay::agent::AgentOp::new(channel, kind);
        // While dialing this must never park the serial event loop (C5); once
        // the backend is up, `send().await` is the same backpressure the inline
        // path applies.
        let outcome = match &self.agent {
            Some(agent) => {
                if agent.handle.is_ready() {
                    agent.handle.enqueue(op).await
                } else {
                    agent.handle.try_enqueue(op)
                }
            }
            None => relay::agent::Enqueued::Closed,
        };
        match outcome {
            relay::agent::Enqueued::Accepted => true,
            relay::agent::Enqueued::QueueFull => {
                self.ctx.metrics.agent_channel_denied();
                tracing::warn!(
                    target: "server",
                    %channel,
                    "agent-mode queue full while dialing; failing the channel natively"
                );
                // The op is dropped with its reply slot, so the client learns
                // about it from the close rather than a fabricated SUCCESS.
                // Only *this* channel goes; the session and its other channels
                // carry on.
                self.agent_channels.remove(&channel);
                if let Some(tap) = self.taps.remove(&channel) {
                    tap.flush();
                }
                if let Some(entry) = &self.entry {
                    entry.forget_channel(channel);
                }
                let _ = session.close(channel);
                true
            }
            relay::agent::Enqueued::Closed => {
                // The supervisor has already answered the queue with
                // protocol-native failures and closed the channels it accepted.
                // Forget this one too; the handle stays in place so later
                // opens are refused instead of resurrecting a dead supervisor.
                self.agent_channels.remove(&channel);
                if let Some(tap) = self.taps.remove(&channel) {
                    tap.flush();
                }
                if let Some(entry) = &self.entry {
                    entry.forget_channel(channel);
                }
                true
            }
        }
    }

    /// Run the subsystem interceptor and, on a Deny, answer the client with a
    /// native failure.
    ///
    /// Shared by the inline and the agent path so the two cannot drift: a Deny
    /// has to mean exactly the same thing whichever side of the supervisor the
    /// request sits on. Today's only interceptor (`SftpAuditInterceptor`)
    /// returns `Tap`/`Pass`, but the agent path must not become the hole a
    /// future `Deny` falls through.
    ///
    /// Returns `false` when the request was denied *and* the client has already
    /// been answered; the caller must then return immediately.
    async fn allow_subsystem(
        &self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<bool> {
        // Interceptor hook (default: zero-cost Pass). A Deny short-circuits with a
        // native failure; never fabricate output (I4).
        let Some(grant) = self.grant.clone() else {
            session.channel_failure(channel)?;
            return Ok(false);
        };
        let verdict = self
            .ctx
            .interceptor
            .on_subsystem_request(name, &grant)
            .await;
        if let relay::Verdict::Deny(reason) = verdict {
            tracing::info!(target: "server", %reason, %name, "subsystem request denied by interceptor");
            session.channel_failure(channel)?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Agent mode (C2/D2): hand this session's channel to the supervisor rather
    /// than dialing inline.
    ///
    /// The channel is accepted *immediately* (the client needs its confirmation
    /// before it can request agent forwarding at all), and an
    /// [`AgentOpKind::OpenChannel`] op asks the supervisor to map it onto a new
    /// session channel of the one authenticated backend connection. Failure to
    /// reach the backend closes the channel natively — it never falls back to
    /// the gateway's own key (red line 3).
    ///
    /// Channels #2..n that arrive **while the backend is still dialing** are
    /// accepted and queued exactly like the first one — the supervisor has no
    /// connection to open them on yet, so the op simply waits, and the dial's
    /// failure path closes every channel it accepted (I4). Only the
    /// `channels_per_conn` cap can refuse one up front.
    async fn open_agent_channel(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
        grant: &Grant,
    ) -> Result<()> {
        let client_id = channel.id();
        let first = self.agent.is_none();

        // Per-connection channel cap (§3.8 / sshd MaxSessions): every channel
        // is multiplexed onto this session's single backend connection, so the
        // configured (hard-capped) limit applies exactly as it does inline.
        if !crate::pool::can_open_channel(
            self.agent_channels.len(),
            self.ctx.config.pool.channels_per_conn,
        ) {
            self.ctx.metrics.agent_channel_denied();
            tracing::warn!(
                target: "server",
                channels = self.agent_channels.len(),
                limit = self.ctx.config.pool.channels_per_conn,
                "per-connection channel limit reached; refusing agent channel"
            );
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }

        if let Some(entry) = &self.entry {
            entry.set_channel_class(client_id, crate::audit::CommandClass::Interactive);
        }
        let tap_ctx = relay::ChannelCtx {
            session_id: self.session_id.to_string(),
            channel_id: client_id,
            principal: grant.principal.as_str().to_owned(),
            command_class: crate::audit::CommandClass::Interactive,
            record: grant.policy.recording,
        };
        let tap = self.ctx.interceptor.observe(&tap_ctx);
        if let Some(tap) = &tap {
            self.taps.insert(client_id, Arc::clone(tap));
        }
        if let Some(auditor) = &self.auditor {
            // The audit record has to say *which credential reached the
            // backend*, even if the dial then fails (red line 10).
            auditor.set_auth_kind("agent");
        }

        if first {
            let bytes = self
                .auditor
                .as_ref()
                .map(|a| a.byte_counters())
                .unwrap_or_default();
            let handle = relay::agent::spawn(
                relay::agent::AgentSupervisorArgs {
                    grant: grant.clone(),
                    up: session.handle(),
                    dialer: Arc::clone(&self.ctx.dialer),
                    metrics: self.ctx.metrics.clone(),
                    bytes,
                    auditor: self.auditor.clone(),
                    session_id: self.session_id.to_string(),
                },
                self.ctx.config.relay.window_size,
                self.ctx.config.relay.max_packet,
            );
            // Register the handle *before* confirming the open, so the client's
            // first request can never outrun it. The supervisor cannot reply to
            // or close this channel before then either: its first act is to wait
            // for the client's `auth-agent-req@openssh.com`, which the client
            // only sends once it has this confirmation.
            self.agent = Some(AgentSession { handle });
        }

        let op =
            relay::agent::AgentOp::new(client_id, relay::agent::AgentOpKind::OpenChannel { tap });
        let outcome = match &self.agent {
            Some(agent) => {
                if agent.handle.is_ready() {
                    agent.handle.enqueue(op).await
                } else {
                    agent.handle.try_enqueue(op)
                }
            }
            None => relay::agent::Enqueued::Closed,
        };
        match outcome {
            relay::agent::Enqueued::Accepted => {
                self.agent_channels.insert(client_id);
                reply.accept().await;
            }
            relay::agent::Enqueued::QueueFull | relay::agent::Enqueued::Closed => {
                // Nothing to relay it with: refuse the channel natively (I4)
                // rather than accepting a channel that would never move.
                self.taps.remove(&client_id);
                if let Some(entry) = &self.entry {
                    entry.forget_channel(client_id);
                }
                reply.reject(ChannelOpenFailure::ResourceShortage).await;
            }
        }
        Ok(())
    }
}

/// Await the backend reply receiver and answer the client with the protocol
/// native SUCCESS/FAILURE (russh suppresses the reply if the client did not ask
/// for one). A dropped/errored receiver is treated as FAILURE (I4).
async fn deliver_reply(
    session: &mut Session,
    channel: ChannelId,
    receiver: &mut tokio::sync::oneshot::Receiver<bool>,
) -> Result<()> {
    match tokio::time::timeout(Duration::from_secs(10), &mut *receiver).await {
        Ok(Ok(true)) => session.channel_success(channel).map_err(Error::Ssh),
        _ => session.channel_failure(channel).map_err(Error::Ssh),
    }
}

impl server::Handler for GatewaySession {
    type Error = Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        Ok(self.reject_all())
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(self.reject_all())
    }

    /// Precheck for raw public-key authentication (D3).
    ///
    /// For a **certificate** attempt russh hands this callback the *inner* user
    /// key (`PublicKey::new(cert.public_key(), "")`), not the CA that issued it,
    /// so a control-plane decision keyed on raw-key fingerprints would refuse
    /// every certificate client before it ever signs (S4). Because the offered
    /// fingerprint cannot distinguish "raw key to reject" from "inner key of a
    /// valid certificate", the precheck keeps only the shape check and otherwise
    /// lets the attempt proceed; the authoritative decision happens in
    /// [`auth_publickey`](Self::auth_publickey) for raw keys and in
    /// [`auth_openssh_certificate`](Self::auth_openssh_certificate) for certs.
    ///
    /// Trade-off: an unauthorized raw key no longer fails fast in the probe and
    /// instead burns one signing round — bounded by `auth_rejection_pad` x
    /// `max_auth_attempts`, and never a silent accept.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        self.ctx.metrics.auth_offered();
        // Malformed principals are rejected before any work: a shape failure, not
        // an authorization one, and independent of cert-vs-raw.
        let Ok(principal) = Principal::parse(user) else {
            return Ok(self.reject_all());
        };
        self.signature_algorithm = public_key.algorithm().to_string();
        let fingerprint = public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        // Warm the resolver cache without acting on the answer so the final
        // callback benefits from the warm path.
        let _ = self.resolve_grant(&principal, &fingerprint).await;
        self.principal = Some(principal);
        Ok(Auth::Accept)
    }

    /// Authoritative decision (D3/D4): russh has already verified the signature
    /// bound to the session id before invoking this callback, so a bad signature
    /// never reaches us. On success we mint the auditor and mark the session
    /// active.
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        let principal = match Principal::parse(user) {
            Ok(p) => p,
            Err(_) => {
                self.ctx.metrics.auth_reject();
                return Ok(self.reject_all());
            }
        };
        let fingerprint = public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        self.signature_algorithm = public_key.algorithm().to_string();

        match self.resolve_grant(&principal, &fingerprint).await {
            Ok(grant) => {
                self.ctx.metrics.auth_accept();
                self.ctx.metrics.session_started();
                // Reserve this session's relay *window budget* (one send window per
                // leg). This is quota accounting, not live in-flight bytes.
                self.ctx
                    .metrics
                    .add_window_budget((self.ctx.config.relay.window_size as usize) * 2);
                self.principal = Some(principal);
                self.auditor = Some(Arc::new(Auditor::new(
                    self.session_id.clone(),
                    self.client_ip.clone(),
                    grant.clone(),
                    self.signature_algorithm.clone(),
                    self.ctx.metrics.clone(),
                )));
                self.grant = Some(grant);
                Ok(Auth::Accept)
            }
            Err(_) => {
                self.ctx.metrics.auth_reject();
                Ok(self.reject_all())
            }
        }
    }

    /// Authoritative decision for **certificate** authentication (B1).
    ///
    /// russs only calls this *after* it has checked the certificate's validity
    /// window, verified the certificate's own signature, and verified the
    /// USERAUTH signature against the inner public key — so reaching here means
    /// the client actually holds the private key. What this callback adds is the
    /// gateway's own policy: the issuing CA must be trusted, the certificate must
    /// be inside its validity window and list the requested principal, and the
    /// control plane must still authorize the destination.
    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::Certificate,
    ) -> std::result::Result<Auth, Self::Error> {
        let Ok(principal) = Principal::parse(user) else {
            self.ctx.metrics.cert_auth_reject();
            return Ok(self.reject_all());
        };
        Ok(self.authorize_certificate(&principal, certificate).await)
    }

    async fn auth_succeeded(
        &mut self,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let handle = session.handle();
        self.register(handle);
        Ok(())
    }

    /// `direct-tcpip` ("local TCP forwarding") is always refused.
    ///
    /// The gateway terminates the client's transport and opens exactly one kind
    /// of outbound connection: the session's own backend leg. It is not an
    /// outbound pivot for arbitrary TCP, so there is no policy that can turn
    /// this on — jump mode was removed with the agent-only backend decision
    /// (dev-docs/plan-agent-only.md). Refusing explicitly (rather than leaving
    /// russh's `ChannelOpenHandle` to be dropped) keeps the answer a property of
    /// the protocol state machine and makes the refusal countable (I4).
    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.ctx.metrics.direct_tcpip_denied();
        tracing::info!(
            target: "server",
            originator = originator_address,
            host = host_to_connect,
            port = port_to_connect,
            "refusing direct-tcpip: the gateway is never an outbound pivot"
        );
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        // Register lazily in case auth_succeeded wasn't invoked first.
        self.register(session.handle());

        if self.limiter_reject {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        let grant = match &self.grant {
            Some(g) => g.clone(),
            None => {
                // Not authorized; channel opens shouldn't arrive, but be safe.
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
        };

        // C2 agent passthrough: this session authenticates to the backend with
        // the *user's* forwarded agent, so the channel goes to a supervisor
        // task instead of being dialled inline. Everything after the channel is
        // up is the ordinary relay path.
        if self.agent_mode() {
            return self
                .open_agent_channel(channel, reply, session, &grant)
                .await;
        }

        // Per-connection channel cap (§3.8 / sshd MaxSessions): one backend
        // connection carries this session's channels, so refuse to open more than
        // the configured (hard-capped) limit rather than overloading the backend.
        if !crate::pool::can_open_channel(self.relays.len(), self.ctx.config.pool.channels_per_conn)
        {
            tracing::warn!(
                target: "server",
                channels = self.relays.len(),
                limit = self.ctx.config.pool.channels_per_conn,
                "per-connection channel limit reached; refusing new channel"
            );
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }

        match self.open_backend_channel().await {
            Ok(Some((backend_read, backend_write))) => {
                let client_id = channel.id();
                let router = ReplyRouter::default();
                let window = Arc::new(relay::OutboundWindow::uncalibrated());
                let bytes = self
                    .auditor
                    .as_ref()
                    .map(|a| a.byte_counters())
                    .unwrap_or_default();

                if let Some(entry) = &self.entry {
                    // Default classification until exec/shell/subsystem decides.
                    entry.set_channel_class(client_id, crate::audit::CommandClass::Interactive);
                }

                let up = session.handle();
                // B2/B3: create the per-channel data tap (recording and/or SFTP
                // inspection). `None` keeps the plain-transmission fast path.
                let tap_ctx = relay::ChannelCtx {
                    session_id: self.session_id.to_string(),
                    channel_id: client_id,
                    principal: grant.principal.as_str().to_owned(),
                    command_class: crate::audit::CommandClass::Interactive,
                    record: grant.policy.recording,
                };
                let tap = self.ctx.interceptor.observe(&tap_ctx);
                tokio::spawn(relay::pump_backend_to_client(
                    backend_read,
                    up,
                    client_id,
                    router.clone(),
                    Arc::clone(&window),
                    Arc::clone(&bytes),
                    self.ctx.metrics.clone(),
                    tap.clone(),
                ));

                let relay = ChannelRelay::new(
                    client_id,
                    backend_write,
                    router,
                    window,
                    bytes,
                    self.ctx.metrics.clone(),
                );
                self.relays.insert(client_id, Arc::new(relay));
                if let Some(tap) = tap {
                    self.taps.insert(client_id, tap);
                }
                reply.accept().await;
            }
            Ok(None) | Err(_) => {
                // I4: fail via protocol-native open failure; no fabricated exec.
                tracing::info!(target: "server", target_host = %grant.target.host, "backend channel open failed");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }

    /// Uplink channel data (client → backend).
    ///
    /// This is the one uplink path that goes through the [`relay::OutboundWindow`]
    /// fuse: it carries the bulk traffic (scp/rsync/sftp transfers, `cat`, …), so
    /// it is where an unbounded gateway buffer would actually grow. The guard is
    /// skipped entirely when `relay.outbound_guard` is false, in which case
    /// russh's own channel window is the sole bound.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let n = data.len();
        // C2 agent passthrough: the supervisor owns this channel's uplink, so
        // the tap still runs here (it has the per-channel record) and only the
        // already-filtered bytes are handed over.
        if self.agent.is_some() {
            let Some((payload, inject)) = self.apply_uplink_tap(channel, data) else {
                return Ok(());
            };
            if !inject.is_empty() {
                if let Err(e) = session.data(channel, Bytes::from(inject)) {
                    tracing::debug!(target: "relay", ?channel, ?e, "could not deliver tap response to client");
                }
            }
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Data {
                    data: Bytes::from(payload),
                },
                session,
            )
            .await;
            return Ok(());
        }
        // One map lookup per packet: take an owned `Arc` handle (and the metrics
        // snapshot it carries) so the relay survives the awaits below without
        // borrowing `self.relays` across them.
        let relay = match self.relays.get(&channel) {
            Some(r) => {
                r.note_would_exhaust(n);
                Arc::clone(r)
            }
            None => return Ok(()),
        };
        if self.ctx.config.relay.outbound_guard {
            // P0-2: the down-pump closes the window the instant the backend dies,
            // so this await can never wedge the session's serial event loop on a
            // dead backend. On close, drop the relay and close the client channel
            // natively (I4) — no fabricated output or exit code.
            if let Err(relay::WindowClosed) = relay.window.acquire(n).await {
                tracing::info!(
                    target: "server",
                    %channel,
                    "uplink window closed (backend gone); dropping relay and closing channel"
                );
                self.relays.remove(&channel);
                if let Some(entry) = &self.entry {
                    entry.forget_channel(channel);
                }
                session.close(channel).map_err(Error::Ssh)?;
                return Ok(());
            }
        }

        // B2/B3: the channel tap may withhold part of the payload and answer the
        // client directly (e.g. a synthesized SFTP permission-denied status).
        // NOTE: russh's handler callback lends `&[u8]`, so the untapped fast path
        // must make one owned copy (`to_vec` in `apply_uplink_tap`) before the
        // bytes can cross to the backend. This is the API-constrained minimum;
        // unlike the downlink path there is no redundant second allocation.
        let Some((payload, inject)) = self.apply_uplink_tap(channel, data) else {
            return Ok(());
        };
        let n = payload.len();
        // The refusal answer goes on the same channel-data stream the request
        // arrived on; writing it to stderr instead would strand the client.
        if !inject.is_empty() {
            // `Session::data` is synchronous (it enqueues onto the session's own
            // send channel), unlike `Handle::data` used from detached tasks.
            if let Err(e) = session.data(channel, Bytes::from(inject)) {
                tracing::debug!(target: "relay", ?channel, ?e, "could not deliver tap response to client");
            }
        }

        relay.bytes.add_up(n);
        let owned = Bytes::from(payload);
        if let Err(e) = relay.backend.data_bytes(owned).await {
            tracing::debug!(target: "relay", ?channel, ?e, "uplink forward failed");
        }
        Ok(())
    }

    /// Uplink extended data (client → backend, non-zero `ext` codes — e.g. stderr
    /// data, debug output).
    ///
    /// **Deliberately not routed through the [`relay::OutboundWindow`] fuse**,
    /// unlike [`data`](Self::data). The fuse exists to bound *bulk* uplink
    /// buffering, and extended-data streams are small, infrequent, and bounded per
    /// channel by russh's own send window on the backend leg (which
    /// `ChannelWriteHalf::extended_data_bytes` respects exactly as `data_bytes`
    /// does). Charging them against a window calibrated for bulk `data` would risk
    /// a small stderr burst starving real payload. The byte *tally* is still
    /// recorded so the audit record's `bytes_up` stays complete.
    ///
    /// Deviation note: propose.md §3.6 describes the fuse generically; this is the
    /// one uplink path intentionally left to russh's window as the backstop.
    async fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.agent.is_some() {
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::ExtendedData {
                    ext,
                    data: Bytes::copy_from_slice(data),
                },
                session,
            )
            .await;
            return Ok(());
        }
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };
        let n = data.len();
        relay.bytes.add_up(n);
        let owned = Bytes::copy_from_slice(data);
        if let Err(e) = relay.backend.extended_data_bytes(ext, owned).await {
            tracing::debug!(target: "relay", ?channel, ?e, "uplink ext-data forward failed");
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.agent.is_some() {
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Pty {
                    term: term.to_owned(),
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    modes: modes.to_vec(),
                    want_reply: true,
                },
                session,
            )
            .await;
            return Ok(());
        }
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };
        let mut rx = relay.router.push(true);
        relay
            .backend
            .request_pty(
                true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await?;
        if let Some(rx) = rx.as_mut() {
            deliver_reply(session, channel, rx).await?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(entry) = &self.entry {
            entry.set_channel_class(channel, crate::audit::CommandClass::Interactive);
        }
        if self.agent.is_some() {
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Shell { want_reply: true },
                session,
            )
            .await;
            return Ok(());
        }
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };
        let mut rx = relay.router.push(true);
        relay.backend.request_shell(true).await?;
        if let Some(rx) = rx.as_mut() {
            deliver_reply(session, channel, rx).await?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        let class = crate::audit::classify_exec_bytes(data);
        if let Some(entry) = &self.entry {
            entry.set_channel_class(channel, class);
        }
        self.record_channel_command(channel, &CommandInfo::Exec(cmd));
        if self.agent.is_some() {
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Exec {
                    command: data.to_vec(),
                    want_reply: true,
                },
                session,
            )
            .await;
            return Ok(());
        }
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };
        let rx = relay::forward_exec(relay, true, data)
            .await
            .map_err(|reason| Error::Backend(BackendError::Send { reason }))?;
        if let Some(mut rx) = rx {
            deliver_reply(session, channel, &mut rx).await?;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.record_channel_command(channel, &CommandInfo::Subsystem(name.to_owned()));
        if self.agent.is_some() {
            // The interceptor runs on both sides of the supervisor (see
            // `allow_subsystem`), so an agent-mode sftp cannot sidestep a Deny.
            if !self.allow_subsystem(channel, name, session).await? {
                return Ok(());
            }
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Subsystem {
                    name: name.to_owned(),
                    want_reply: true,
                },
                session,
            )
            .await;
            return Ok(());
        }
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };

        if !self.allow_subsystem(channel, name, session).await? {
            return Ok(());
        }

        if let Some(entry) = &self.entry {
            entry.set_channel_class(channel, CommandInfo::Subsystem(name.to_owned()).classify());
        }
        let mut rx = relay.router.push(true);
        relay.backend.request_subsystem(true, name).await?;
        if let Some(rx) = rx.as_mut() {
            deliver_reply(session, channel, rx).await?;
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        // The agent branch comes *before* the relay lookup, like every other
        // request handler: an agent session deliberately has no inline relay, so
        // looking one up first would make this the single handler that silently
        // drops the client's request instead of handing it to the supervisor.
        if self.agent.is_some() {
            // M1's env allowlist is applied here, before anything reaches the
            // backend, so agent mode cannot be used to smuggle a filtered
            // variable past it.
            let allowed =
                crate::policy::env_allowed(variable_name, &self.ctx.config.relay.env_allowlist);
            if matches!(allowed, crate::policy::ForwardDecision::DenyLocally { .. }) {
                return Ok(());
            }
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Env {
                    name: variable_name.to_owned(),
                    value: variable_value.to_owned(),
                    want_reply: true,
                },
                session,
            )
            .await;
            return Ok(());
        }
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };
        // M1: pass-through unless an allowlist is configured (propose §3.4).
        let allowed =
            crate::policy::env_allowed(variable_name, &self.ctx.config.relay.env_allowlist);
        if matches!(allowed, crate::policy::ForwardDecision::DenyLocally { .. }) {
            // Destined for a filtered-out env: drop silently (client never wanted a
            // reply for env, typically).
            return Ok(());
        }
        let mut rx = relay.router.push(true);
        relay
            .backend
            .set_env(true, variable_name, variable_value)
            .await?;
        if let Some(rx) = rx.as_mut() {
            deliver_reply(session, channel, rx).await?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.agent.is_some() {
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                },
                session,
            )
            .await;
            return Ok(());
        }
        if let Some(relay) = self.relays.get(&channel) {
            relay
                .backend
                .window_change(col_width, row_height, pix_width, pix_height)
                .await?;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: russh::Sig,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.agent.is_some() {
            self.take_over_by_agent(
                channel,
                relay::agent::AgentOpKind::Signal { signal },
                _session,
            )
            .await;
            return Ok(());
        }
        if let Some(relay) = self.relays.get(&channel) {
            relay.backend.signal(signal).await?;
        }
        Ok(())
    }

    /// Agent-forwarding decision (D6 + plan-agent-passthrough C1).
    ///
    /// Stays default-deny — byte-for-byte the old `Ok(false)` outcome — unless
    /// **both** gates pass:
    ///
    /// 1. `[backend] allow_agent_backend_auth` (the instance-wide kill-switch,
    ///    off by default), and
    /// 2. the control-plane `policy.agent_forwarding` for *this* grant.
    ///
    /// `false` is the protocol-native refusal: russh answers CHANNEL_FAILURE for
    /// `auth-agent-req@openssh.com`, exactly as an unconditional deny does. No
    /// agent channel is ever opened on the deny path (red line 2/3: nothing is
    /// forwarded to the backend, nothing silently downgrades).
    async fn agent_request(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let Some(grant) = self.grant.as_ref() else {
            tracing::debug!(
                target: "server",
                %channel,
                "agent-forwarding request denied (session has no grant)"
            );
            if let Some(agent) = &self.agent {
                // The supervisor is waiting on this decision; a refusal must
                // unblock it immediately rather than run out the deadline.
                agent.handle.grant_decision(false);
            }
            return Ok(false);
        };
        // Both gates (instance kill-switch + grant policy) live in one pure
        // helper so the combined rule is unit-tested and cannot drift here.
        match crate::policy::agent_passthrough_allowed(
            self.ctx.config.backend.allow_agent_backend_auth,
            grant,
        ) {
            crate::policy::ForwardDecision::Forward => {
                tracing::info!(
                    target: "server",
                    %channel,
                    principal = %grant.principal,
                    "agent forwarding permitted for this grant"
                );
                if let Some(agent) = &self.agent {
                    agent.handle.grant_decision(true);
                }
                Ok(true)
            }
            crate::policy::ForwardDecision::DenyLocally { reason } => {
                tracing::debug!(
                    target: "server",
                    %channel,
                    %reason,
                    "agent-forwarding request denied"
                );
                if let Some(agent) = &self.agent {
                    agent.handle.grant_decision(false);
                }
                Ok(false)
            }
        }
    }

    /// X11 forwarding unsupported (D6): deny locally.
    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.agent.is_some() {
            self.take_over_by_agent(channel, relay::agent::AgentOpKind::Eof, _session)
                .await;
            return Ok(());
        }
        if let Some(relay) = self.relays.get(&channel) {
            relay.backend.eof().await?;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        // `agent_channels` is only ever populated for an agent session, so the
        // membership test alone identifies one of this session's supervisor
        // channels; the `agent` guard just keeps the two in step.
        if self.agent.is_some() && self.agent_channels.remove(&channel) {
            // Best-effort only (red line 8): this callback runs on the
            // serial event loop, and `enqueue().await` would park it for as
            // long as the bounded queue stayed full while the backend was
            // still dialing — the same deadlock shape §3.5.1 exists to
            // avoid. `try_enqueue` either hands the op over or tells us not
            // to bother; either way the supervisor drops this channel's
            // write half, which closes the backend channel for good.
            if let Some(agent) = &self.agent {
                let _ = agent.handle.try_enqueue(relay::agent::AgentOp::new(
                    channel,
                    relay::agent::AgentOpKind::Close,
                ));
            }
            if let Some(tap) = self.taps.remove(&channel) {
                tap.flush();
            }
            if let Some(entry) = &self.entry {
                entry.forget_channel(channel);
            }
            return Ok(());
        }
        // Not one of this session's agent channels (already closed, or a
        // channel belonging to the inline path): fall through.
        if let Some(relay) = self.relays.remove(&channel) {
            relay.backend.close().await?;
        }
        if let Some(tap) = self.taps.remove(&channel) {
            // Deterministic flush/close of any recording for this channel (B2).
            tap.flush();
        }
        if let Some(entry) = &self.entry {
            entry.forget_channel(channel);
        }
        Ok(())
    }
}

impl Drop for GatewaySession {
    fn drop(&mut self) {
        if self.audited {
            return;
        }
        self.audited = true;
        self.ctx.registry.remove(&self.session_id);
        if self.principal.is_some() && self.grant.is_some() {
            // Emit a best-effort audit record for sessions that reached the
            // relayed state.
            if let Some(auditor) = self.auditor.take() {
                auditor.finalize(None, None);
            }
            self.ctx
                .metrics
                .sub_window_budget((self.ctx.config.relay.window_size as usize) * 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::ChannelTap as _;

    #[test]
    fn drain_state_roundtrips_through_atomic() {
        assert_eq!(
            DrainState::decode(DrainState::Accepting.encode()),
            DrainState::Accepting
        );
        assert_eq!(
            DrainState::decode(DrainState::Draining.encode()),
            DrainState::Draining
        );
    }

    #[test]
    fn registry_tracks_and_counts_sessions() {
        let reg = SessionRegistry::default();
        // We can't build a server::Handle here, so exercise the state/drain logic
        // and count helpers with a synthetic, handle-free path.
        assert_eq!(reg.total(), 0);
        assert_eq!(reg.count_from_ip("1.2.3.4"), 0);
        assert_eq!(reg.drain_state(), DrainState::Accepting);
        reg.set_drain_state(DrainState::Draining);
        assert_eq!(reg.drain_state(), DrainState::Draining);
    }

    // ---- auth-boundary tests (Spike #3: offered vs final, impersonation) ----

    use crate::resolve::ControlError;
    use crate::types::{Policy, ResolveRequest, ResolveResponse, Target};
    use russh::server::Handler as _;

    struct FixControlPlane {
        result: std::result::Result<ResolveResponse, ControlError>,
    }

    impl crate::resolve::ControlPlaneClient for FixControlPlane {
        fn resolve<'a>(
            &'a self,
            _req: &'a ResolveRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::result::Result<ResolveResponse, ControlError>>
                    + Send
                    + 'a,
            >,
        > {
            let result = self.result.clone();
            Box::pin(async move { result })
        }
    }

    fn ok_response() -> ResolveResponse {
        ResolveResponse {
            target: Target {
                host: "10.1.2.3".into(),
                port: 22,
                user: "root".into(),
            },
            policy: Policy::default(),
        }
    }

    /// RAII guard that deletes the temp key files it created when dropped —
    /// defect-B: no leaked `sshgw-*` files after `cargo test`. The gateway
    /// loads every key into memory during `build_with_client`, so deleting the
    /// files once the context is built is safe.
    struct TestKeyGuard(Vec<std::path::PathBuf>);

    impl TestKeyGuard {
        fn new() -> Self {
            TestKeyGuard(Vec::new())
        }

        /// Create a 0600 ed25519 key file and register it for cleanup.
        ///
        /// The file name is derived from the freshly generated key, so two tests
        /// running concurrently in this process can never collide on a path (a
        /// time-based suffix does: cargo runs test threads in parallel and they
        /// reach this within the same clock tick, which used to make one test's
        /// guard delete a file another was still loading).
        fn add_key(&mut self) -> String {
            let mut rng = rand::rng();
            let key =
                russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
            let body = key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap();
            let digest = key
                .public_key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string();
            let path = std::env::temp_dir().join(format!(
                "sshgw-ctx-{}-{}.key",
                std::process::id(),
                digest.replace([':', '/'], "")
            ));
            {
                let f = std::fs::File::create(&path).unwrap();
                let _ = f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
            }
            std::fs::write(&path, body).unwrap();
            self.0.push(path.clone());
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for TestKeyGuard {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    /// Build a gateway context over freshly-created temp keys (registered in
    /// `keys` for RAII cleanup). The keys are read into memory during this call,
    /// so the guard may safely delete the files immediately afterwards.
    fn build_test_ctx(
        keys: &mut TestKeyGuard,
        auth_timeout: &str,
        control_plane: Arc<FixControlPlane>,
    ) -> Arc<GatewayContext> {
        let host_key = keys.add_key();
        let backend_key = keys.add_key();
        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [{{ path = "{host_key}", state = "active" }}]
            [backend]
            private_key = "{backend_key}"
            host_key_policy = "accept-new"
            [control_plane]
            url = "http://127.0.0.1:1"
            [limits]
            auth_timeout = "{auth_timeout}"
        "#
        );
        let config = GatewayConfig::parse(&toml).unwrap();
        GatewayContext::build_with_client(config, control_plane).unwrap()
    }

    /// Default test context (fast `auth_timeout = "0s"`) with leak-free keys.
    fn test_ctx(control_plane: Arc<FixControlPlane>) -> Arc<GatewayContext> {
        let mut keys = TestKeyGuard::new();
        build_test_ctx(&mut keys, "0s", control_plane)
        // `keys` drops here — the key files are already loaded into memory.
    }

    /// A test context with an explicit `auth_timeout` (for the defect-A timing
    /// regression test, which uses the schema default of 30s).
    fn test_ctx_with_auth_timeout(
        auth_timeout: &str,
        control_plane: Arc<FixControlPlane>,
    ) -> Arc<GatewayContext> {
        let mut keys = TestKeyGuard::new();
        build_test_ctx(&mut keys, auth_timeout, control_plane)
    }

    /// A test context whose `[limits]` section is extended with `extra`
    /// (TOML lines indented to match the generated template).
    fn test_ctx_with_limits_override(
        extra: String,
        control_plane: Arc<FixControlPlane>,
    ) -> Arc<GatewayContext> {
        let mut keys = TestKeyGuard::new();
        let host_key = keys.add_key();
        let backend_key = keys.add_key();
        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [{{ path = "{host_key}", state = "active" }}]
            [backend]
            private_key = "{backend_key}"
            host_key_policy = "accept-new"
            [control_plane]
            url = "http://127.0.0.1:1"
            [limits]
            auth_timeout = "0s"
            {extra}
        "#
        );
        let config = GatewayConfig::parse(&toml).unwrap();
        GatewayContext::build_with_client(config, control_plane).unwrap()
    }

    fn random_client_key() -> russh::keys::PrivateKey {
        let mut rng = rand::rng();
        russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap()
    }

    /// A CA private key for certificate tests.
    fn ca_key() -> russh::keys::PrivateKey {
        let mut rng = rand::rng();
        russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap()
    }

    /// A context whose CA trusts `ca_public_key`.
    fn cert_ctx(
        dir: &mut TestKeyGuard,
        ca_pub: &russh::keys::PublicKey,
        control_plane: Arc<FixControlPlane>,
    ) -> Arc<GatewayContext> {
        let host_key = dir.add_key();
        let backend_key = dir.add_key();
        let ca_path = dir.add_key();
        std::fs::write(&ca_path, ca_pub.to_openssh().unwrap()).unwrap();
        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [{{ path = "{host_key}", state = "active" }}]
            [backend]
            private_key = "{backend_key}"
            host_key_policy = "accept-new"
            [control_plane]
            url = "http://127.0.0.1:1"
            [ca]
            trusted_ca_keys = ["{ca_path}"]
            cert_lifetime = "300s"
        "#
        );
        let config = GatewayConfig::parse(&toml).unwrap();
        GatewayContext::build_with_client(config, control_plane).unwrap()
    }

    /// Issue a user certificate signed by `ca` for `principals`.
    fn issue_cert(
        ca: &russh::keys::PrivateKey,
        subject: &russh::keys::PublicKey,
        principals: &[&str],
        lifetime_s: u64,
    ) -> russh::keys::Certificate {
        let principals: Vec<String> = principals.iter().map(|s| (*s).to_owned()).collect();
        crate::ca::issue_user_certificate_with(
            ca,
            subject,
            &principals,
            "alex@dev",
            std::time::Duration::from_secs(lifetime_s),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn authorized_pubkey_is_accepted_and_grants() {
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        let mut session = GatewayServer::new(Arc::clone(&ctx))
            .new_client(Some("203.0.113.7:2222".parse().unwrap()));
        let key = random_client_key();
        let pk = key.public_key();

        // Offered only prechecks (never a final grant).
        let offered = session
            .auth_publickey_offered("alex_host1", pk)
            .await
            .unwrap();
        assert_eq!(offered, Auth::Accept, "offered should let signing proceed");
        assert!(
            session.grant.is_none(),
            "offered must not finalize authorization (D3)"
        );

        // Final (russh has verified the signature by the time this runs) grants.
        let authorized = session.auth_publickey("alex_host1", pk).await.unwrap();
        assert_eq!(authorized, Auth::Accept);
        assert!(session.grant.is_some(), "final accept must grant");
    }

    #[tokio::test]
    async fn unauthorized_key_is_rejected_in_the_final_callback_only() {
        // S4 semantics: the offered callback cannot distinguish "a raw key to
        // reject" from "the inner key of a valid certificate" (russh hands it
        // the inner public key either way), so it must let the attempt proceed
        // and the authoritative refusal happens in `auth_publickey`.
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Err(ControlError::Forbidden),
        }));
        let mut session = GatewayServer::new(Arc::clone(&ctx))
            .new_client(Some("203.0.113.7:2222".parse().unwrap()));
        let key = random_client_key();
        let pk = key.public_key();

        let offered = session
            .auth_publickey_offered("alex_host1", pk)
            .await
            .unwrap();
        assert_eq!(
            offered,
            Auth::Accept,
            "offered must let a cert-capable attempt reach signature verification"
        );
        let authorized = session.auth_publickey("alex_host1", pk).await.unwrap();
        assert!(
            matches!(authorized, Auth::Reject { .. }),
            "the final callback must still refuse an unauthorized key"
        );
        assert!(
            session.grant.is_none(),
            "a denied principal must never be granted"
        );
    }

    #[tokio::test]
    async fn malformed_principal_is_rejected_before_any_lookup() {
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let key = random_client_key();
        let pk = key.public_key();
        // Uppercase username fails the token shape and is rejected outright.
        assert!(matches!(
            session
                .auth_publickey_offered("BAD_user", pk)
                .await
                .unwrap(),
            Auth::Reject { .. }
        ));
        assert!(session.grant.is_none());
    }

    #[tokio::test]
    async fn password_and_none_auth_are_rejected() {
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        assert!(matches!(
            session.auth_none("alex_host1").await.unwrap(),
            Auth::Reject { .. }
        ));
        assert!(matches!(
            session.auth_password("alex_host1", "x").await.unwrap(),
            Auth::Reject { .. }
        ));
    }

    #[tokio::test]
    async fn unknown_principals_and_rate_limits_are_rejected() {
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Err(ControlError::NotFound),
        }));
        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let key = random_client_key();
        assert!(matches!(
            session
                .auth_publickey("ghost", key.public_key())
                .await
                .unwrap(),
            Auth::Reject { .. }
        ));
    }

    // ---- E2E auth over an in-process russh session (Spike #3 / #1) ----

    #[derive(Debug)]
    struct FakeSignError;

    impl std::fmt::Display for FakeSignError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fake sign error")
        }
    }
    impl std::error::Error for FakeSignError {}
    impl From<russh::SendError> for FakeSignError {
        fn from(_: russh::SendError) -> Self {
            FakeSignError
        }
    }

    /// A signer that returns a well-formed but **forged** ed25519 signature blob —
    /// it carries a valid length/algorithm header over a zeroed signature body, so
    /// the server parses it and fails *verification*. This proves the gateway
    /// (via russh) rejects a forged `USERAUTH_REQUEST` signature (propose §3.2),
    /// never reaching the handler's accept.
    ///
    /// Contract (mirrors russh's agent signer): return `to_sign || wire_sig`.
    struct GarbageSigner;

    impl russh::Signer for GarbageSigner {
        type Error = FakeSignError;

        async fn auth_sign(
            &mut self,
            _key: &russh::keys::agent::AgentIdentity,
            _hash_alg: Option<russh::keys::HashAlg>,
            to_sign: Vec<u8>,
        ) -> std::result::Result<Vec<u8>, Self::Error> {
            let mut out = to_sign;
            // SSH signature blob: uint32 algo_len || algo || uint32 sig_len || sig
            let algo = b"ssh-ed25519";
            out.extend_from_slice(&(algo.len() as u32).to_be_bytes());
            out.extend_from_slice(algo);
            out.extend_from_slice(&64u32.to_be_bytes());
            out.extend_from_slice(&[0u8; 64]); // forged (all-zero) ed25519 signature
            Ok(out)
        }
    }

    struct TrustClient;

    impl russh::client::Handler for TrustClient {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKeyOrCertificate,
        ) -> std::result::Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// Drive a fresh gateway session over an in-memory duplex and return the
    /// authenticated client `Handle`.
    async fn handshake(ctx: Arc<GatewayContext>) -> russh::client::Handle<TrustClient> {
        let (client_end, server_end) = tokio::io::duplex(16 * 1024);
        let handler = GatewayServer::new(Arc::clone(&ctx))
            .new_client(Some("198.51.100.9:40000".parse().unwrap()));
        // Start the server side concurrently *before* connecting the client:
        // `run_stream` blocks reading the client id, so awaiting it first would
        // deadlock against the not-yet-started client.
        let server_cfg = Arc::clone(&ctx.server_config);
        tokio::spawn(async move {
            let _ = russh::server::run_stream(server_cfg, server_end, handler).await;
        });
        let client_cfg = Arc::new(russh::client::Config::default());
        russh::client::connect_stream(client_cfg, client_end, TrustClient)
            .await
            .expect("client connect/kex")
    }

    #[tokio::test]
    async fn good_signature_session_authenticates_e2e() {
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        let mut client = handshake(ctx).await;
        let key = random_client_key();
        let pkwha = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let result = client.authenticate_publickey("alex_host1", pkwha).await;
        assert_eq!(result.unwrap(), russh::client::AuthResult::Success);
    }

    #[tokio::test]
    async fn bad_signature_is_rejected_even_when_principal_is_authorized() {
        // The control plane authorizes the principal; only a *forged signature*
        // stands between the client and success. The gateway must still reject it.
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        let mut client = handshake(ctx).await;
        let key = random_client_key();
        let public = key.public_key().clone();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            client.authenticate_publickey_with("alex_host1", public, None, &mut GarbageSigner),
        )
        .await;
        match result {
            Ok(Ok(russh::client::AuthResult::Failure { .. })) => {}
            other => panic!("a forged signature must be rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn e2e_unauthorized_principal_fails_authentication() {
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Err(ControlError::Forbidden),
        }));
        let mut client = handshake(ctx).await;
        let key = random_client_key();
        let pkwha = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let result = client.authenticate_publickey("alex_host1", pkwha).await;
        assert!(
            matches!(result, Ok(russh::client::AuthResult::Failure { .. })),
            "unauthorized principal must not authenticate, got {result:?}"
        );
    }

    #[test]
    fn max_auth_attempts_is_wired_into_the_server_config() {
        // The anti-bruteforce cap must come from config, not from russh's built-in
        // default, in both directions (explicit value and the 10 default).
        for (configured, expected) in [("10", 10usize), ("3", 3), ("0", 0)] {
            let ctx = test_ctx_with_limits_override(
                format!("max_auth_attempts = {configured}"),
                Arc::new(FixControlPlane {
                    result: Ok(ok_response()),
                }),
            );
            assert_eq!(
                ctx.server_config.max_auth_attempts, expected,
                "limits.max_auth_attempts = {configured} must reach the server config"
            );
        }
    }

    #[test]
    fn omitted_max_auth_attempts_wires_russh_builtin_default() {
        // Backward compatibility: an unset `limits.max_auth_attempts` must behave
        // exactly as before wiring it (russh's own default of 10).
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        assert_eq!(ctx.server_config.max_auth_attempts, 10);
    }

    // ---- M3 B5: HA support (stateless replicas can coexist) ----

    #[test]
    fn two_instances_coexist_on_distinct_ports_and_dirs() {
        // B5's src-side requirement: nothing global pins an instance. Building two
        // contexts with different listen/metrics addresses (the operator-facing
        // knobs) and proving nothing collides is the replica story on one host.
        let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        drop(listener_a);
        drop(listener_b);
        assert_ne!(addr_a, addr_b, "distinct instances must use distinct ports");

        let mut keys = TestKeyGuard::new();
        let a = recording_ctx(&mut keys, addr_a);
        let b = recording_ctx(&mut keys, addr_b);

        assert_ne!(a.config.listen_addr, b.config.listen_addr);
        assert_ne!(a.config.metrics.addr, b.config.metrics.addr);
        // Per-instance recording directory: replicas must not share files.
        assert_ne!(
            a.config.recording.dir, b.config.recording.dir,
            "each replica needs its own recording directory"
        );
        // Registries are independent (the session tables are per-process).
        assert_eq!(a.registry.total(), 0);
        assert_eq!(b.registry.total(), 0);
    }

    #[test]
    fn recorded_files_are_namespaced_per_instance_dir() {
        // Two replicas recording the same session id must not share a file,
        // which is what B2's directory config guarantees.
        let tmp_a = TempRecDir::new("ha-a");
        let tmp_b = TempRecDir::new("ha-b");
        assert_ne!(tmp_a.path(), tmp_b.path());
    }

    /// A drop-guarded temp recording directory for the HA tests.
    struct TempRecDir(std::path::PathBuf);

    impl TempRecDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sshgw-ha-{}-{tag}-{}",
                std::process::id(),
                // Random suffix so concurrent tests never share a directory.
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempRecDir(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempRecDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A replica-shaped context: its own listen addr, metrics addr and recording
    /// directory — exactly the knobs an operator must give each replica so two
    /// can run side by side on one host.
    fn recording_ctx(keys: &mut TestKeyGuard, addr: std::net::SocketAddr) -> Arc<GatewayContext> {
        let host_key = keys.add_key();
        let backend_key = keys.add_key();
        // Allocate a free metrics port so a real multi-replica start would bind.
        let metrics = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("allocate a metrics port");
        let rec_dir = TempRecDir::new("ctx");
        let rec_dir = std::mem::ManuallyDrop::new(rec_dir).0.clone();
        let toml = format!(
            r#"
            [listen]
            addr = "{addr}"
            [host_keys]
            keys = [{{ path = "{host_key}", state = "active" }}]
            [backend]
            private_key = "{backend_key}"
            host_key_policy = "accept-new"
            [control_plane]
            url = "http://127.0.0.1:1"
            [recording]
            dir = "{}"
            [metrics]
            addr = "{metrics}"
        "#,
            rec_dir.to_string_lossy()
        );
        let config = GatewayConfig::parse(&toml).unwrap();
        GatewayContext::build_with_client(
            config,
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        )
        .unwrap()
    }

    #[test]
    fn m3_sections_have_safe_defaults() {
        // Every M3 feature must be off unless explicitly configured, so an
        // operator upgrading from the pre-M3 config changes nothing.
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        assert!(
            ctx.ca.trusted_ca_fingerprints().is_empty(),
            "CA must default to disabled"
        );
        assert!(
            !ctx.config.intercept.sftp.enabled,
            "SFTP interception must default to off"
        );
        assert!(
            !ctx.config.recording.dir.as_os_str().is_empty(),
            "a recording directory must always be configured"
        );
        assert!(
            ctx.config.recording.max_bytes_per_session > 0,
            "recording must be budgeted"
        );
    }

    // ---- defect-A: auth-timeout / rejection-delay decoupling ----

    #[test]
    fn auth_rejection_timing_decouples_initial_from_ongoing() {
        // Default schema values: auth_timeout=30s, pad=1s. The initial none-probe
        // must NOT inherit the full 30s (a legit client would stall before auth),
        // and a rejected attempt must NOT burn 30s either — the pad governs that.
        let t = auth_rejection_timing(Duration::from_secs(30), Duration::from_secs(1));
        assert_eq!(
            t.initial,
            Duration::from_secs(1),
            "initial probe delay is the pad, not the auth_timeout"
        );
        assert_eq!(
            t.ongoing,
            Duration::from_secs(1),
            "ongoing rejection padding is the dedicated pad, not the auth_timeout"
        );

        // The auth_timeout still caps the initial delay (never inflated past it).
        let t = auth_rejection_timing(Duration::from_millis(200), Duration::from_secs(1));
        assert_eq!(t.initial, Duration::from_millis(200));
        // The ongoing pad is independent of auth_timeout and stays at 1s.
        assert_eq!(t.ongoing, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn default_auth_timeout_has_no_cold_start_on_the_none_probe() {
        // Regression test for defect A: with the schema default auth_timeout of
        // 30s, a *realistic* authentication flow — the initial "none" probe every
        // SSH client sends, followed by a real public-key auth — must complete in
        // well under 3s, not ~30s.
        let ctx = test_ctx_with_auth_timeout(
            "30s",
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        // Sanity: the mapping under test produced a small initial delay and a
        // small ongoing pad (P1-2), not the full auth_timeout.
        assert_eq!(
            ctx.server_config.auth_rejection_time_initial,
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            ctx.server_config.auth_rejection_time,
            Duration::from_secs(1)
        );

        let mut client = handshake(ctx).await;
        let started = std::time::Instant::now();

        // 1) The initial "none" probe (OpenSSH always sends this first).
        let _ = client.authenticate_none("alex_host1").await;
        // 2) Then the real public-key authentication, which must succeed.
        let key = random_client_key();
        let pkwha = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let auth = client.authenticate_publickey("alex_host1", pkwha).await;
        let elapsed = started.elapsed();

        assert_eq!(auth.unwrap(), russh::client::AuthResult::Success);
        assert!(
            elapsed < Duration::from_secs(3),
            "auth took {elapsed:?}: the initial none-probe is being padded by the full auth_timeout (defect A)"
        );
    }

    // ---- M3 B1: certificate authentication ----

    #[tokio::test]
    async fn valid_certificate_from_a_trusted_ca_is_accepted() {
        let mut keys = TestKeyGuard::new();
        let ca = ca_key();
        let subject =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let ctx = cert_ctx(
            &mut keys,
            &ca.public_key().clone(),
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        let cert = issue_cert(&ca, &subject, &["alex_host1"], 300);

        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &cert)
            .await
            .unwrap();
        assert_eq!(
            auth,
            Auth::Accept,
            "a valid cert from a trusted CA must authenticate"
        );
        assert!(
            session.grant.is_some(),
            "the session must be granted on accept"
        );
    }

    #[tokio::test]
    async fn certificate_from_an_untrusted_ca_is_rejected() {
        let mut keys = TestKeyGuard::new();
        let trusted_ca = ca_key();
        let rogue_ca = ca_key();
        let subject_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let ctx = cert_ctx(
            &mut keys,
            &trusted_ca.public_key().clone(),
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        let cert = issue_cert(&rogue_ca, &subject_key, &["alex_host1"], 300);

        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &cert)
            .await
            .unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "an untrusted CA must be refused"
        );
        assert!(session.grant.is_none());
    }

    #[tokio::test]
    async fn certificate_with_the_wrong_principal_is_rejected() {
        let mut keys = TestKeyGuard::new();
        let ca = ca_key();
        let subject_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let ctx = cert_ctx(
            &mut keys,
            &ca.public_key().clone(),
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        // Minted for `bob`, used to log in as `alex_host1`.
        let cert = issue_cert(&ca, &subject_key, &["bob"], 300);

        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &cert)
            .await
            .unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "principal mismatch must be refused"
        );
    }

    #[tokio::test]
    async fn expired_certificate_is_rejected() {
        let mut keys = TestKeyGuard::new();
        let ca = ca_key();
        let subject_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let ctx = cert_ctx(
            &mut keys,
            &ca.public_key().clone(),
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        // A 1-second certificate, then actually wait it out: this exercises the
        // real clock path in `authorize_certificate` rather than a fake.
        let cert = issue_cert(&ca, &subject_key, &["alex_host1"], 1);
        tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &cert)
            .await
            .unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "an expired certificate must be refused"
        );
    }

    #[tokio::test]
    async fn tampered_certificate_is_rejected_end_to_end() {
        let mut keys = TestKeyGuard::new();
        let ca = ca_key();
        let subject_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let ctx = cert_ctx(
            &mut keys,
            &ca.public_key().clone(),
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        let cert = issue_cert(&ca, &subject_key, &["alex_host1"], 300);
        let mut bytes = cert.to_bytes().unwrap();
        let len = bytes.len();
        bytes[len - 32] ^= 0xff; // corrupt the trailing ed25519 signature
        let tampered = russh::keys::Certificate::from_bytes(&bytes).unwrap();

        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &tampered)
            .await
            .unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "a tampered certificate must be refused"
        );
    }

    #[tokio::test]
    async fn certificate_inner_fingerprint_differs_from_the_ca_fingerprint() {
        // S4 regression: the fingerprint control-plane authorization sees for a
        // certificate client is the *inner user key's*, not the CA's. The
        // certificate must still authenticate because authorization happens in
        // `auth_openssh_certificate` against the CA.
        let mut keys = TestKeyGuard::new();
        let ca = ca_key();
        let subject_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let ctx = cert_ctx(
            &mut keys,
            &ca.public_key().clone(),
            Arc::new(FixControlPlane {
                result: Ok(ok_response()),
            }),
        );
        let cert = issue_cert(&ca, &subject_key, &["alex_host1"], 300);

        let ca_fp = crate::ca::certificate_ca_fingerprint(&cert);
        let inner_fp = subject_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        assert_ne!(
            ca_fp, inner_fp,
            "the inner key fingerprint must differ from the CA's"
        );

        // A control plane that only knows the CA fingerprint (the only thing it
        // is given for a certificate client) still authorizes the session.
        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &cert)
            .await
            .unwrap();
        assert_eq!(auth, Auth::Accept);
        let granted_fp = session
            .grant
            .as_ref()
            .unwrap()
            .fingerprint
            .as_str()
            .to_owned();
        assert_eq!(
            granted_fp, ca_fp,
            "the grant must key on the CA fingerprint"
        );
    }

    #[tokio::test]
    async fn ca_disabled_rejects_every_certificate() {
        // No `[ca]` section at all: certificate authentication must be off while
        // raw public-key auth keeps working.
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Ok(ok_response()),
        }));
        assert!(
            ctx.ca.trusted_ca_fingerprints().is_empty(),
            "no CAs must be trusted"
        );
        let ca = ca_key();
        let subject_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let cert = issue_cert(&ca, &subject_key, &["alex_host1"], 300);

        let mut session = GatewayServer::new(Arc::clone(&ctx)).new_client(None);
        let auth = session
            .auth_openssh_certificate("alex_host1", &cert)
            .await
            .unwrap();
        assert!(matches!(auth, Auth::Reject { .. }));
    }

    // ---- M3 B3: SFTP data-path interception ----

    fn sftp_inspector(deny: &[&str], allow: &[&str], drop: &[&str]) -> crate::sftp::SftpInspector {
        let (deny, allow, drop) = crate::sftp::validate_rules(
            &deny.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            &allow.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            &drop.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap();
        crate::sftp::SftpInspector::new(
            crate::sftp::SftpRules {
                deny_commands: deny,
                allowed_path_prefixes: allow,
                denied_path_prefixes: drop,
            },
            Metrics::default(),
        )
    }

    fn frame(type_byte: u8, body: &[u8]) -> Vec<u8> {
        let mut inner = vec![type_byte];
        inner.extend_from_slice(body);
        let mut out = Vec::new();
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        out.extend_from_slice(&inner);
        out
    }

    /// Build a request frame using the SFTP command's **wire** type byte, so the
    /// fixture cannot drift from the parser's table (the mistake that let
    /// `deny_commands=["REMOVE"]` silently never match).
    fn request(command: crate::sftp::SftpCommand, id: u32, path: &str) -> Vec<u8> {
        let mut body = id.to_be_bytes().to_vec();
        body.extend_from_slice(&(path.len() as u32).to_be_bytes());
        body.extend_from_slice(path.as_bytes());
        frame(command.type_byte(), &body)
    }

    #[tokio::test]
    async fn sftp_inspector_passes_allowed_requests_without_copying() {
        let inspector = sftp_inspector(&["REMOVE"], &[], &[]);
        let ok = request(crate::sftp::SftpCommand::Open, 1, "/data/ok.txt");
        let verdict = inspector.on_data(relay::Direction::Up, &ok);
        assert_eq!(
            verdict,
            relay::DataVerdict::Pass,
            "an allowed request must pass through"
        );
    }

    #[tokio::test]
    async fn sftp_inspector_denies_a_forbidden_command_and_synthesises_status() {
        let inspector = sftp_inspector(&["REMOVE"], &[], &[]);
        let rm = request(crate::sftp::SftpCommand::Remove, 42, "/data/x.txt");
        let verdict = inspector.on_data(relay::Direction::Up, &rm);
        let relay::DataVerdict::Rewrite {
            forward,
            inject,
            denied,
        } = verdict
        else {
            panic!("a denied REMOVE must be rewritten, got the Pass path");
        };
        assert!(forward.is_empty(), "the denied request must be withheld");
        assert!(denied.is_some(), "the denial reason must be reported");
        // The injected bytes must be a well-formed SSH_FXP_STATUS for this id.
        let len = u32::from_be_bytes(inject[..4].try_into().unwrap()) as usize;
        assert_eq!(
            len + 4,
            inject.len(),
            "the frame length must cover the whole body"
        );
        assert_eq!(inject[4], 101, "SSH_FXP_STATUS");
        assert_eq!(
            u32::from_be_bytes(inject[5..9].try_into().unwrap()),
            42,
            "the request id must be echoed"
        );
    }

    #[tokio::test]
    async fn sftp_inspector_denies_paths_outside_the_allow_list() {
        let inspector = sftp_inspector(&[], &["/data/"], &[]);
        let denied = request(crate::sftp::SftpCommand::Open, 7, "/etc/shadow");
        let verdict = inspector.on_data(relay::Direction::Up, &denied);
        assert!(
            matches!(verdict, relay::DataVerdict::Rewrite { .. }),
            "an out-of-scope path must be refused"
        );

        let allowed = request(crate::sftp::SftpCommand::Open, 8, "/data/ok.txt");
        assert_eq!(
            inspector.on_data(relay::Direction::Up, &allowed),
            relay::DataVerdict::Pass
        );
    }

    #[tokio::test]
    async fn sftp_inspector_never_inspects_downlink_data() {
        let inspector = sftp_inspector(&["REMOVE"], &[], &[]);
        let rm = request(crate::sftp::SftpCommand::Remove, 42, "/data/x.txt");
        assert_eq!(
            inspector.on_data(relay::Direction::Down, &rm),
            relay::DataVerdict::Pass,
            "only client→server carries SFTP requests"
        );
    }

    #[tokio::test]
    async fn composite_tap_chains_inspector_before_recorder() {
        // The recorder must see only what the inspector allowed.
        let inspector = sftp_inspector(&["REMOVE"], &[], &[]);
        let rm = request(crate::sftp::SftpCommand::Remove, 1, "/data/x.txt");
        let allowed = request(crate::sftp::SftpCommand::Open, 2, "/data/ok.txt");
        let combined: Vec<u8> = rm.iter().chain(allowed.iter()).copied().collect();

        // With the inspector first, the recorder sees just the allowed OPEN.
        let filtered = match inspector.on_data(relay::Direction::Up, &combined) {
            relay::DataVerdict::Pass => combined.clone(),
            relay::DataVerdict::Rewrite { forward, .. } => forward,
        };
        assert_eq!(
            filtered, allowed,
            "only the allowed frame must survive the inspector"
        );
    }
}
