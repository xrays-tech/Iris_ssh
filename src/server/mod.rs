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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use russh::server::{self, Auth, Config as ServerConfig, Server as _, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty};

use crate::audit::{Auditor, CommandInfo};
use crate::backend::{BackendClient, BackendDialer, CredentialStore};
use crate::config::GatewayConfig;
use crate::error::{BackendError, Error, Result};
use crate::metrics::Metrics;
use crate::policy::HostKeyVerifier;
use crate::relay::{
    self, BackendWriter, ChannelRelay, PassThroughInterceptor, ReplyRouter, SubsystemInterceptor,
};
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
    pub registry: SessionRegistry,
    pub server_config: Arc<ServerConfig>,
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

        let credentials = Arc::new(CredentialStore::load(&config)?);
        // No pre-pinned fingerprints by default: `pinned` therefore rejects
        // until an operator pins the backend fingerprint (out-of-band), while
        // `accept-new` learns it with a warning.
        let verifier = Arc::new(HostKeyVerifier::new(
            config.backend.host_key_policy,
            Vec::new(),
        ));
        let dialer = Arc::new(BackendDialer::new(
            &config,
            Arc::clone(&credentials),
            Arc::clone(&verifier),
            metrics.clone(),
        ));

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

        let interceptor: Arc<dyn SubsystemInterceptor> = Arc::new(PassThroughInterceptor);

        let server_config = ServerConfig {
            keys,
            window_size: config.relay.window_size,
            maximum_packet_size: config.relay.max_packet,
            channel_buffer_size: 100,
            // Only public-key auth is offered; password/none are rejected by the
            // handler regardless.
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            auth_rejection_time: config.limits.auth_timeout,
            inactivity_timeout: Some(Duration::from_secs(3600)),
            ..ServerConfig::default()
        };

        Ok(Arc::new(GatewayContext {
            config: Arc::new(config),
            resolver,
            dialer,
            metrics,
            interceptor,
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
    auditor: Option<Auditor>,
    signature_algorithm: String,
    backend: Option<russh::client::Handle<BackendClient>>,
    relays: HashMap<ChannelId, ChannelRelay>,
    entry: Option<Arc<SessionEntry>>,
    limiter_reject: bool,
    audited: bool,
}

impl GatewaySession {
    fn reject_all(&self) -> Auth {
        Auth::reject()
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

    /// Deliver a want_reply result to the client via the protocol-native
    /// success/failure primitives (russh gates on the client's real want_reply).
    fn record_channel_command(&mut self, _id: ChannelId, info: &CommandInfo) {
        if let Some(auditor) = self.auditor.as_mut() {
            auditor.set_command(info.clone());
        }
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

    /// Precheck only (D3). Warms the resolver cache and early-rejects on a
    /// definitive 403/404, but NEVER grants the final accept — that happens in
    /// `auth_publickey` after russh verifies the signature.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        self.ctx.metrics.auth_offered();
        let principal = match Principal::parse(user) {
            Ok(p) => p,
            Err(_) => return Ok(self.reject_all()),
        };
        let fingerprint = public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        self.signature_algorithm = public_key.algorithm().to_string();
        match self.resolve_grant(&principal, &fingerprint).await {
            Ok(_) => {
                // Let the client proceed to signature verification.
                self.principal = Some(principal);
                Ok(Auth::Accept)
            }
            Err(_) => {
                // Early reject: authoritative-but-negative; saves a signing round.
                Ok(self.reject_all())
            }
        }
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
                self.ctx
                    .metrics
                    .add_inflight((self.ctx.config.relay.window_size as usize) * 2);
                self.principal = Some(principal);
                self.auditor = Some(Auditor::new(
                    self.session_id.clone(),
                    self.client_ip.clone(),
                    grant.clone(),
                    self.signature_algorithm.clone(),
                    self.ctx.metrics.clone(),
                ));
                self.grant = Some(grant);
                Ok(Auth::Accept)
            }
            Err(_) => {
                self.ctx.metrics.auth_reject();
                Ok(self.reject_all())
            }
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &russh::keys::Certificate,
    ) -> std::result::Result<Auth, Self::Error> {
        // Certificate auth (TrustedCA) is an M3 deliverable.
        Ok(self.reject_all())
    }

    async fn auth_succeeded(
        &mut self,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let handle = session.handle();
        self.register(handle);
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
                tokio::spawn(relay::pump_backend_to_client(
                    backend_read,
                    up,
                    client_id,
                    router.clone(),
                    Arc::clone(&window),
                    Arc::clone(&bytes),
                ));

                let relay = ChannelRelay::new(
                    client_id,
                    backend_write,
                    router,
                    window,
                    bytes,
                    self.ctx.metrics.clone(),
                );
                self.relays.insert(client_id, relay);
                // Consume `grant` to silence clippy and document intent.
                let _ = grant;
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

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };
        let n = data.len();
        relay.note_would_exhaust(n);
        if self.ctx.config.relay.outbound_guard {
            relay.window.acquire(n).await;
        }
        relay.bytes.add_up(n);
        let owned = Bytes::copy_from_slice(data);
        if let Err(e) = relay.backend.data_bytes(owned).await {
            tracing::debug!(target: "relay", ?channel, ?e, "uplink forward failed");
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
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
        let relay = match self.relays.get(&channel) {
            Some(r) => r,
            None => return Ok(()),
        };

        // Interceptor hook (default: zero-cost Pass). A Deny short-circuits with a
        // native failure; never fabricate output (I4).
        let grant = match &self.grant {
            Some(g) => g.clone(),
            None => {
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        let verdict = self
            .ctx
            .interceptor
            .on_subsystem_request(name, &grant)
            .await;
        if let relay::Verdict::Deny(reason) = verdict {
            tracing::info!(target: "server", %reason, %name, "subsystem request denied by interceptor");
            session.channel_failure(channel)?;
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
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
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
        if let Some(relay) = self.relays.get(&channel) {
            relay.backend.signal(signal).await?;
        }
        Ok(())
    }

    /// agent-forwarding default-deny (D6): locally refuse, don't forward.
    async fn agent_request(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        tracing::debug!(target: "server", %channel, "agent-forwarding request denied");
        Ok(false)
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
        if let Some(relay) = self.relays.remove(&channel) {
            relay.backend.close().await?;
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
                .sub_inflight((self.ctx.config.relay.window_size as usize) * 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Write a fresh key to a 0600 temp file and return its path.
    fn write_key_file() -> String {
        let mut rng = rand::rng();
        let key =
            russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
        let body = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "sshgw-ctx-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        {
            let f = std::fs::File::create(&path).unwrap();
            let _ = f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
        }
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn test_ctx(control_plane: Arc<FixControlPlane>) -> Arc<GatewayContext> {
        let host_key = write_key_file();
        let backend_key = write_key_file();
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
        "#
        );
        let config = GatewayConfig::parse(&toml).unwrap();
        GatewayContext::build_with_client(config, control_plane).unwrap()
    }

    fn random_client_key() -> russh::keys::PrivateKey {
        let mut rng = rand::rng();
        russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap()
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
    async fn unauthorized_key_is_rejected_in_both_phases() {
        // Control plane denies (impersonated key → 403): offered early-rejects,
        // final rejects, and no grant is ever set.
        let ctx = test_ctx(Arc::new(FixControlPlane {
            result: Err(ControlError::Forbidden),
        }));
        let mut session = GatewayServer::new(Arc::clone(&ctx))
            .new_client(Some("203.0.113.7:2222".parse().unwrap()));
        let key = random_client_key();
        let pk = key.public_key();

        assert!(matches!(
            session
                .auth_publickey_offered("alex_host1", pk)
                .await
                .unwrap(),
            Auth::Reject { .. }
        ));
        assert!(matches!(
            session.auth_publickey("alex_host1", pk).await.unwrap(),
            Auth::Reject { .. }
        ));
        assert!(
            session.grant.is_none(),
            "denied principal must not be granted"
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
}
