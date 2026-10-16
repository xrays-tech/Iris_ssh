//! Backend leg: dialing + host-key verification.
//!
//! The gateway authenticates to the backend `sshd` as a russh *client*
//! (propose.md §3.3). This module owns:
//!
//! * **Host-key trust**: [`BackendClient::check_server_key`] computes the
//!   backend's SHA256 fingerprint and defers to the [`HostKeyVerifier`], so a
//!   `pinned` policy rejects an unexpected backend before userauth.
//! * **Dialing/auth** ([`BackendDialer::connect`]): TCP + KEX + publickey auth
//!   driven by the **user's forwarded agent**. There is no gateway-owned
//!   credential any more — no `CredentialStore`, no `BackendAuthMethod`, no
//!   cert-dial (plan-agent-only D3) — so the dial path has exactly one shape.
//!
//! Private-key loading survives only for the gateway's own **host keys**
//! ([`load_private_key_checked`]), whose file permissions are still enforced
//! fail-closed at boot.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Handle};
use russh::keys::{HashAlg, PrivateKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure};

use crate::error::{BackendError, Result};
use crate::metrics::Metrics;
use crate::policy::HostKeyVerifier;
use crate::pool::DialCircuitBreaker;
use crate::types::Grant;

/// Unix file mode bit that must be clear for a private key to be considered
/// safe: group and other must have no access.
const KEY_UNSAFE_MODE_MASK: u32 = 0o077;

/// The agent transport for one user session: the channel *we* opened towards
/// the client with `channel_open_agent()`, wrapped for the SSH-agent protocol.
pub type AgentChannelStream = russh::ChannelStream<russh::server::Msg>;

/// This session's forwarded agent, as an SSH-agent client speaking over that
/// channel.
///
/// The concrete type is deliberate, and it is a **design** choice rather than a
/// language limitation. For the record: russh 0.64.1 keeps its `auth` module
/// private (`mod auth;` in `lib_inner.rs`), so `russh::auth::Signer` is not a
/// path one can write — but `Signer` itself *is* re-exported publicly as
/// `russh::Signer` (`pub use auth::{... Signer}`), so a generic
/// `SG: russh::Signer` bound is expressible and is used elsewhere in this repo
/// (see the `GarbageSigner` test double in `server/mod.rs`).
///
/// We freeze the surface to exactly this one type anyway because red line 4
/// asks for it: the smallest signing surface is one that cannot be pointed at
/// anything but the user's own agent, reached through this session's own agent
/// channel. A generic `Signer` would widen the set of things [`BackendDialer::connect`]
/// could be handed in a future refactor; this alias makes that a compile error.
pub type SessionAgentClient = russh::keys::agent::client::AgentClient<AgentChannelStream>;

/// A live backend transport, as returned by [`BackendDialer::connect`].
///
/// Carrying this type explicitly matters for agent mode: russh's client driver
/// task is spawned by `client::connect_stream` and ends when the `Handle` is
/// dropped, so a caller that dials a backend must keep the handle for as long
/// as it intends to use the channel it opened on it. The relayed path stores it
/// beside the channel for exactly that reason.
pub type BackendHandle = Handle<BackendClient>;

/// Read a private key from `path`, refusing to load keys that are readable by
/// group/other (propose.md §3.3: 0600 required).
///
/// Only the gateway's own **host keys** are still loaded this way; backend
/// credentials went away with the agent-only rework (plan-agent-only D3), so the
/// error is unconditionally the host-key one.
pub(crate) fn load_private_key_checked(path: &std::path::Path) -> Result<PrivateKey> {
    #[cfg(unix)]
    check_key_permissions(path)?;
    russh::keys::load_secret_key(path, None)
        .map_err(|source| BackendError::LoadHostKey {
            path: path.to_owned(),
            source,
        })
        .map_err(Into::into)
}

/// Enforce that `path` is not accessible by group or other (0600-style).
///
/// A key readable beyond its owner would let any local user impersonate the
/// gateway, so this is a hard startup gate (fail-closed).
#[cfg(unix)]
fn check_key_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .map_err(|source| crate::error::Error::io(source, "reading private key file metadata"))?;
    let mode = metadata.permissions().mode();
    if mode & KEY_UNSAFE_MODE_MASK != 0 {
        return Err(BackendError::UnsafeHostKeyPermissions {
            path: path.to_owned(),
            perms: mode & 0o777,
        }
        .into());
    }
    Ok(())
}

/// Compute the canonical `SHA256:` fingerprint of a backend host key. Exposed as
/// a pure helper so the pinning value can be logged/asserted.
///
/// For a `Certificate` this returns the **inner key's** fingerprint, which is
/// what the pre-M4 `pinned`/`accept-new` policies (and an unconfigured CA set)
/// match on. The M4 `@cert-authority` path does *not* use it: a trusted-CA host
/// certificate is verified by
/// [`HostKeyVerifier::verify_host_certificate`] instead, because the inner key
/// rotates with every backend re-issue while the CA stays put.
///
/// `host_key_description` is the audit-friendly way to report either kind.
pub fn host_key_fingerprint(key: &PublicKeyOrCertificate) -> String {
    let public = match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
        PublicKeyOrCertificate::Certificate(cert) => {
            russh::keys::PublicKey::from(cert.public_key().clone())
        }
    };
    public.fingerprint(HashAlg::Sha256).to_string()
}

/// An operator-readable description of what the backend presented during KEX.
///
/// For a host certificate this deliberately names **both** the signing CA's
/// fingerprint (the actual trust anchor) and the inner key's, so an operator
/// reading a log line can tell a CA-signed host key apart from a bare one that
/// merely happens to match a pinned fingerprint — the two are not
/// interchangeable, and conflating them is exactly the confusion that
/// `docs/known-limitations.md` #1 warns about.
pub fn host_key_description(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { .. } => {
            format!("hostkey {}", host_key_fingerprint(key))
        }
        PublicKeyOrCertificate::Certificate(cert) => format!(
            "host-cert (ca {} / key {})",
            crate::ca::certificate_ca_fingerprint(cert),
            host_key_fingerprint(key)
        ),
    }
}

/// Client-leg handler: verifies the backend host key against the policy and
/// records the last rejection reason so `connect` can surface a clear error.
///
/// russh hands the handler whatever the KEX produced — a bare public key *or* a
/// host certificate — with **no** prior validation of its own, so the whole
/// trust decision (including the `@cert-authority` chain) lives here.
pub struct BackendClient {
    verifier: Arc<HostKeyVerifier>,
    last_rejection: Arc<Mutex<Option<String>>>,
    /// The host name this dial set out to reach. A host certificate must name it
    /// among its valid principals, or a certificate minted for a *different*
    /// backend would be accepted here (M4-T1, plan risk "principals 越权").
    expected_host: String,
}

impl BackendClient {
    fn new(
        verifier: Arc<HostKeyVerifier>,
        last_rejection: Arc<Mutex<Option<String>>>,
        expected_host: String,
    ) -> Self {
        BackendClient {
            verifier,
            last_rejection,
            expected_host,
        }
    }
}

impl client::Handler for BackendClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let described = host_key_description(server_public_key);

        // M4-T1: a host certificate goes through the four-step
        // `@cert-authority` chain when trusted CAs are configured. With no CA
        // configured it falls back to the legacy inner-fingerprint path so an
        // operator who has not adopted certificates sees no behaviour change.
        let verdict = match server_public_key {
            PublicKeyOrCertificate::Certificate(cert) if self.verifier.has_trusted_ca() => {
                let now = crate::ca::now_unix_secs()
                    .unwrap_or_else(|e| {
                        // A clock we cannot read is not a reason to trust
                        // anything: refuse, and say why.
                        tracing::warn!(target: "backend", %e, "cannot read the clock for host-cert validation");
                        u64::MAX
                    });
                // u64::MAX is in the future, so every real certificate reads as
                // expired — fail closed.
                self.verifier
                    .verify_host_certificate(cert, &self.expected_host, now)
            }
            _ => self
                .verifier
                .verify(&host_key_fingerprint(server_public_key)),
        };

        match verdict {
            crate::policy::HostKeyVerdict::Trusted => {
                if matches!(server_public_key, PublicKeyOrCertificate::Certificate(_)) {
                    tracing::info!(target: "backend", host = %described, "trusted backend host certificate via @cert-authority");
                }
                Ok(true)
            }
            crate::policy::HostKeyVerdict::TrustFirstUse => {
                tracing::warn!(target: "backend", host = %described, "trusted backend host key on first use; pin it for production");
                Ok(true)
            }
            crate::policy::HostKeyVerdict::Rejected { reason } => {
                if let Ok(mut slot) = self.last_rejection.lock() {
                    *slot = Some(format!("{reason} ({described})"));
                }
                tracing::warn!(target: "backend", host = %described, %reason, "rejected backend host key");
                Ok(false)
            }
        }
    }

    /// Red line 2, second layer: never act as the *target* of agent forwarding.
    ///
    /// The gateway is the party that *asks* a client for its agent
    /// (`channel_open_agent`), never the party that accepts one back. russh's
    /// default implementation of this hook accepts, so "we never request it" is
    /// the only thing standing between a misbehaving peer and a channel the
    /// gateway would then have to service. Rejecting explicitly turns the rule
    /// from a property of our own behaviour into a property of the protocol
    /// state machine, which is where a defence belongs.
    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        tracing::warn!(
            target: "backend",
            "refusing an inbound agent-forward channel: the gateway is never an agent forward target"
        );
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }
}

/// Dials and authenticates backend sshd on behalf of a resolved [`Grant`].
pub struct BackendDialer {
    verifier: Arc<HostKeyVerifier>,
    client_config: Arc<client::Config>,
    metrics: Metrics,
    dial_timeout: Duration,
    /// The RSA signature hash the forwarded agent is asked to sign with.
    /// `HashAlg::Sha512` (plan-openstack E.1); non-RSA keys ignore it (see
    /// [`signature_hash_alg`]).
    rsa_signature_hash: HashAlg,
    /// Per-target dial circuit breaker (§3.8): after `threshold` consecutive
    /// dial failures a target is short-circuited so repeated channel opens don't
    /// pile onto a dead backend.
    dial_breaker: DialCircuitBreaker,
}

impl BackendDialer {
    pub fn new(
        config: &crate::config::GatewayConfig,
        verifier: Arc<HostKeyVerifier>,
        metrics: Metrics,
        ca: Option<Arc<crate::ca::CertificateAuthority>>,
    ) -> Self {
        let mut preferred = client::Config::default().preferred;
        // russh's client default advertises **no** host-certificate algorithms,
        // so a backend that only offers a host certificate is negotiated down to
        // its bare key and the `@cert-authority` chain would never run. Advertising
        // the certificate types our trusted CAs can actually verify closes that
        // gap (plan-m4 M4-T1's missing wire half).
        if let Some(ca) = &ca {
            let algos = ca.trusted_cert_algorithms();
            if !algos.is_empty() {
                preferred.host_key_certificates = std::borrow::Cow::Owned(algos);
            }
        }
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
                preferred.cipher = std::borrow::Cow::Owned(ciphers);
            }
        }
        let client_config = client::Config {
            preferred,
            window_size: config.relay.window_size,
            maximum_packet_size: config.relay.max_packet,
            nodelay: config.relay.nodelay,
            // The gateway drives liveness itself; don't let russh's own timeout
            // GC an otherwise healthy long-lived backend session.
            inactivity_timeout: None,
            // §3.8 health: russh emits `keepalive@openssh.com` at this cadence and
            // closes the connection after `keepalive_max` unanswered probes, giving
            // dead-backend detection for both pooled and per-session connections.
            keepalive_interval: if config.pool.keepalive_interval.is_zero() {
                None
            } else {
                Some(config.pool.keepalive_interval)
            },
            keepalive_max: if config.pool.keepalive_interval.is_zero() {
                3
            } else {
                config.pool.keepalive_max_miss as usize
            },
            ..client::Config::default()
        };
        BackendDialer {
            verifier,
            client_config: Arc::new(client_config),
            metrics,
            rsa_signature_hash: HashAlg::Sha512,
            // A control plane's timeout doubles as the dial deadline; in
            // OpenStack pure mode there is no control plane, so fall back to
            // the OpenStack request timeout and finally the 2s default.
            dial_timeout: config
                .control_plane
                .as_ref()
                .map(|cp| cp.timeout)
                .or_else(|| config.openstack.as_ref().map(|os| os.timeout))
                .unwrap_or(Duration::from_secs(2)),
            dial_breaker: DialCircuitBreaker::new(
                config.pool.circuit_failure_threshold,
                config.pool.circuit_reset_timeout,
            ),
        }
    }

    /// The breaker key for a grant's target (one breaker per `host:port`).
    fn breaker_key(grant: &Grant) -> String {
        format!("{}:{}", grant.target.host, grant.target.port)
    }

    /// Enter the dial gate: return the breaker key, or fail fast on an open
    /// breaker without touching the network (so a dead backend can't stall every
    /// channel open). The first thing every dial does.
    fn enter_dial_gate(&self, grant: &Grant) -> Result<String> {
        let key = Self::breaker_key(grant);
        if !self.dial_breaker.allows(&key) {
            self.metrics.backend_dial_fail();
            return Err(BackendError::CircuitOpen { target: key }.into());
        }
        Ok(key)
    }

    /// TCP connect + KEX + host-key verification, **before** any user
    /// authentication. Records breaker/metric failures exactly as before; the
    /// caller authenticates with the forwarded agent once this returns.
    async fn connect_inner(&self, grant: &Grant, key: &str) -> Result<Handle<BackendClient>> {
        let addr = (grant.target.host.as_str(), grant.target.port);
        let last_rejection: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let handler = BackendClient::new(
            Arc::clone(&self.verifier),
            Arc::clone(&last_rejection),
            // Host-certificate validation must check the certificate names *this*
            // host, so the handler needs the name we set out to reach.
            grant.target.host.clone(),
        );

        let connect_fut =
            client::connect::<BackendClient, _>(Arc::clone(&self.client_config), addr, handler);
        tokio::time::timeout(self.dial_timeout, connect_fut)
            .await
            .map_err(|_| {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(key);
                BackendError::Dial {
                    addr: format!("{}:{}", grant.target.host, grant.target.port),
                    source: Box::new(crate::error::Error::Invariant(
                        "backend dial timed out".into(),
                    )),
                }
            })?
            .map_err(|e| {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(key);
                self.dial_error(grant, last_rejection, e)
            })
            .map_err(Into::into)
    }

    /// Fold a completed authentication attempt into breaker + metrics + result.
    fn settle_auth(
        &self,
        key: &str,
        started: std::time::Instant,
        handle: Handle<BackendClient>,
        user: &str,
        outcome: std::result::Result<AuthResult, BackendError>,
    ) -> Result<Handle<BackendClient>> {
        match outcome {
            Err(e) => {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(key);
                Err(e.into())
            }
            Ok(AuthResult::Success) => {
                self.metrics.backend_dial_ok();
                self.metrics.backend_dial_latency(started.elapsed());
                // A full handshake succeeded: the target is healthy again.
                self.dial_breaker.record_success(key);
                Ok(handle)
            }
            Ok(_) => {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(key);
                Err(BackendError::Auth {
                    user: user.to_owned(),
                }
                .into())
            }
        }
    }

    /// Establish an authenticated backend session using the **user's forwarded
    /// agent** as the signing credential — the only credential the gateway has
    /// (plan-agent-only D3).
    ///
    /// `public_key` / `signer` describe the *one* identity the supervisor
    /// already matched against `grant.fingerprint`; the agent is only ever asked
    /// to sign for a key **we offered** (`auth::Method::FuturePublicKey`), so it
    /// never signs under another identity on our behalf (red line 4).
    pub async fn connect(
        &self,
        grant: &Grant,
        public_key: russh::keys::PublicKey,
        signer: &mut SessionAgentClient,
    ) -> Result<Handle<BackendClient>> {
        let key = self.enter_dial_gate(grant)?;
        let started = std::time::Instant::now();
        let mut handle = self.connect_inner(grant, &key).await?;

        // RSA needs an explicit rsa-sha2 hash: passing `None` makes russh emit
        // the legacy SHA-1 `ssh-rsa` signature, which OpenSSH >= 8.8 rejects by
        // default. Non-RSA keys ignore the argument entirely, so they see no
        // behaviour change at all (plan-openstack E.1).
        let hash_alg = signature_hash_alg(&public_key, self.rsa_signature_hash);
        tracing::debug!(
            target: "backend",
            user = %grant.target.user,
            key_type = %public_key.algorithm(),
            ?hash_alg,
            "backend publickey auth"
        );

        let outcome = handle
            .authenticate_publickey_with(&grant.target.user, public_key, hash_alg, signer)
            .await
            .map_err(|e| BackendError::Auth {
                // The hash goes in the context, not as a retry: a backend that
                // rejects rsa-sha2-512 fails here, loudly, rather than being
                // retried with a weaker algorithm (red line 1).
                user: format!("{} ({e}, rsa_hash={:?})", grant.target.user, hash_alg),
            });

        self.settle_auth(&key, started, handle, &grant.target.user, outcome)
    }

    fn dial_error(
        &self,
        grant: &Grant,
        last_rejection: Arc<Mutex<Option<String>>>,
        err: russh::Error,
    ) -> BackendError {
        let addr = format!("{}:{}", grant.target.host, grant.target.port);
        // If the host-key callback recorded a rejection, it is a host-key
        // (MITM / wrong backend) failure; otherwise it is a transport failure.
        let rejection = last_rejection.lock().ok().and_then(|slot| slot.clone());
        match rejection {
            Some(reason) => BackendError::HostKeyRejected { addr, reason },
            None => BackendError::Dial {
                addr,
                source: Box::new(crate::error::Error::Ssh(err)),
            },
        }
    }
}

/// The RSA signature hash this gateway uses when the end-user's forwarded
/// agent signs for the backend.
///
/// RSA keys get `rsa_hash` (default `HashAlg::Sha512`, plan-openstack E.1).
/// Everything else gets `None`: their signature scheme is fixed by the key
/// type, and russh ignores the argument entirely for non-RSA keys — so passing
/// `None` here is byte-for-byte the pre-E.1 behaviour for ed25519/ecdsa/sk-*
/// (red line 2).
///
/// The match deliberately names no non-RSA variant: `None` is the answer for
/// every key type other than RSA, including ones this build does not know
/// about. RSA never reaches that arm, so SHA-1 (`ssh-rsa`) is unreachable on
/// the backend leg (red line 1) — there is no fallback path to fall back to.
pub fn signature_hash_alg(key: &russh::keys::PublicKey, rsa_hash: HashAlg) -> Option<HashAlg> {
    match key.algorithm() {
        russh::keys::Algorithm::Rsa { .. } => Some(rsa_hash),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HostKeyVerdict;
    use crate::types::HostKeyPolicy;
    use std::io::Write;

    /// A temp key file that deletes itself on drop (defect-B: no leaked
    /// `sshgw-test-key-*` files after `cargo test`).
    struct TempKeyPath(std::path::PathBuf);

    impl std::ops::Deref for TempKeyPath {
        type Target = std::path::PathBuf;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TempKeyPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write_temp_key(perms: u32, content: &str) -> TempKeyPath {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sshgw-test-key-{}-{}",
            std::process::id(),
            unique_nonce(content)
        ));
        {
            let file = std::fs::File::create(&path).unwrap();
            let _ = file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(perms));
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();
        TempKeyPath(path)
    }

    fn unique_nonce(seed: &str) -> u64 {
        // Simple, deterministic-enough nonce for unique temp paths in tests.
        seed.len() as u64
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0)
    }

    #[test]
    fn rejects_key_with_group_or_other_permissions() {
        // A syntactically valid but world-readable key must be refused.
        let content = format!("nonsense-{}-perms-test\n", unique_nonce("x"));
        let temp = write_temp_key(0o644, &content);
        let err = load_private_key_checked(&temp).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Backend(BackendError::UnsafeHostKeyPermissions { .. })
            ),
            "expected unsafe-permissions rejection, got {err:?}"
        );
    }

    #[test]
    fn loads_a_0600_key_generated_on_the_fly() {
        let mut rng = rand::rng();
        let key =
            PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).expect("random key");
        let openssh = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encode");
        let temp = write_temp_key(0o600, &openssh);
        let loaded = load_private_key_checked(&temp).expect("0600 key loads");
        assert_eq!(loaded.algorithm(), key.algorithm());
    }

    #[test]
    fn missing_key_file_is_a_load_error_not_panic() {
        let path = std::path::Path::new("/nonexistent/definitely/not/here/key");
        let err = load_private_key_checked(path).unwrap_err();
        // Fails at the permission/metadata step with a context-rich i/o error.
        assert!(
            matches!(err, crate::error::Error::Io { .. }),
            "expected an i/o error for a missing key, got {err:?}"
        );
    }

    #[test]
    fn verifier_rejects_unpinned_under_pinned_policy() {
        let v = HostKeyVerifier::new(HostKeyPolicy::Pinned, Vec::new());
        assert!(matches!(
            v.verify("SHA256:whatever"),
            HostKeyVerdict::Rejected { .. }
        ));
    }

    // ---- P1-1: dial circuit-breaker wiring ----

    fn test_grant(host: &str) -> Grant {
        Grant {
            principal: crate::types::Principal::parse("alex_host1").unwrap(),
            fingerprint: crate::types::Fingerprint::new("SHA256:fp"),
            agent_fingerprint: crate::types::Fingerprint::new("SHA256:fp"),
            target: crate::types::Target {
                host: host.to_owned(),
                port: 22,
                user: "root".to_owned(),
            },
            policy: crate::types::Policy::default(),
            resolve_source: crate::types::ResolveSource::default(),
        }
    }

    /// Build a dialer whose breaker trips after `fail_threshold` failures with a
    /// `reset` window, using a throwaway local config.
    fn dialer_with(fail_threshold: u32, reset: Duration) -> BackendDialer {
        let assets = std::env::temp_dir().join(format!(
            "sshgw-dialer-{}-{}",
            std::process::id(),
            unique_nonce("d")
        ));
        std::fs::create_dir_all(&assets).unwrap();
        let host = assets.join("host");
        let mut rng = rand::rng();
        let key = PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
        let body = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        {
            let f = std::fs::File::create(&host).unwrap();
            let _ = f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
        }
        std::fs::write(&host, body).unwrap();
        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [ {{ path = "{}", state = "active" }} ]
            [backend]
            host_key_policy = "accept-new"
            [control_plane]
            url = "http://127.0.0.1:1"
            [pool]
            circuit_failure_threshold = {fail_threshold}
            circuit_reset_timeout = "{}s"
        "#,
            host.to_string_lossy(),
            reset.as_secs(),
        );
        let config = crate::config::GatewayConfig::parse(&toml).unwrap();
        let verifier = Arc::new(HostKeyVerifier::new(HostKeyPolicy::AcceptNew, Vec::new()));
        let dialer = BackendDialer::new(&config, verifier, Metrics::default(), None);
        drop(std::fs::remove_dir_all(&assets));
        dialer
    }

    #[test]
    fn breaker_key_is_host_and_port() {
        let g = test_grant("10.1.2.3");
        assert_eq!(BackendDialer::breaker_key(&g), "10.1.2.3:22");
    }

    #[test]
    fn open_breaker_makes_the_dial_gate_fail_fast_without_network() {
        // P1-1: once the per-target breaker has tripped, `connect` must fail with
        // `CircuitOpen` *before* any socket work. `enter_dial_gate` is the first
        // statement of `connect`, so asserting it covers the ordering; a real
        // dial would return Dial/Timeout, not CircuitOpen.
        let dialer = dialer_with(2, Duration::from_secs(60));
        let grant = test_grant("10.1.2.3");
        dialer
            .dial_breaker
            .record_failure(&BackendDialer::breaker_key(&grant));
        dialer
            .dial_breaker
            .record_failure(&BackendDialer::breaker_key(&grant));

        let err = dialer
            .enter_dial_gate(&grant)
            .expect_err("gate must refuse");
        assert!(
            matches!(
                err,
                crate::error::Error::Backend(BackendError::CircuitOpen { .. })
            ),
            "expected a fast CircuitOpen, got {err:?}"
        );
    }

    #[test]
    fn breaker_is_per_target_not_global() {
        let dialer = dialer_with(1, Duration::from_secs(60));
        let key_a = BackendDialer::breaker_key(&test_grant("10.0.0.1"));
        let key_b = BackendDialer::breaker_key(&test_grant("10.0.0.2"));
        dialer.dial_breaker.record_failure(&key_a);
        assert!(!dialer.dial_breaker.allows(&key_a), "A's breaker is open");
        assert!(dialer.dial_breaker.allows(&key_b), "B is unaffected by A");
    }

    // --- backend RSA signature hash (plan-openstack E.1 / E.5.1) -----------

    /// One OpenSSH public-key line per key type, the same way a forwarded
    /// identity reaches the gateway. The sk-* keys are hand-built (they are not
    /// supported by `ssh-keygen`); everything else is a `ssh-keygen` line.
    const TEST_PUBKEYS: &[(&str, Option<HashAlg>)] = &[
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB0tNwSXLXP/LrkgydkuUqloGCMgC0MOK1L4KvP7wPH",
            None,
        ),
        (
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIyYs/0Zbpv7DjpHAtlPr1uWWx4PiMKe7biy6XS682Nd/Dens6Cqq/SY59CtGrinJE+9Dtc2gs6EwfNdzZf5VLo=",
            None,
        ),
        (
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBB58K459l2kZDIvIPuTRXrR7zo+ecwkR7x3hewafoc2D8oIa0wLddu78keUzjhCPj38HrzmmhKyVawaxt5xG8Ob8v31MsJZazzp3fqCHeRUKUqVzhuJojoPF+7zn+UGxVQ==",
            None,
        ),
        (
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFW1nLAF/0/zEk9viLls9GJwrfsTeoWtEiCupNJxGHpOHZAhheKJ/ydWcdxq87W7XrchkHuFCCosmFl+Ki/RzDQGAGweg3ad+iQad4ai9PgzweniMnP1ZzG90CmQ7Cgq5r9gha1H5R3kX1dMy2ZXVfcmOK44KGclcl7RYSuEBE8DU1YyQ==",
            None,
        ),
        (
            "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAAAAAA==",
            None,
        ),
        (
            "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8AAAAA",
            None,
        ),
        // The bare `ssh-rsa` key type is the *key's* encoding (an RSA public
        // key carries no hash); the *signature* hash is what we decide here.
        (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6ouMQLXfiHJC8huDR9xNFTZ4dh+z4ToDijR7zqXENLC83hOkkM4c9TK4cKCmIG76RZ2xa+l29TdaYvjf78ihdNIJU7tElPcZTRVmwkPRJ4+m6N8bVBQNcthCjn5usOAhC/QQYxe/UpSu2v/k8/yX/LpCaEtC++aIzwDCJqN2tO0mwsKXBehG7M9OmMHkosZ5/m+zaz3ESNhmhvU4OhbNb2x5auMQYljZyn2Ho0TDSrlk8BPyLKCVPakMZjP927UO189C1GBbZFIqaMEjTvlM+A/4hIWz64OYBFfs1uoR6fsqZLHYxUefCQmDp6PPOrbbEX6kgzy8qxuJs4QAX7+55",
            Some(HashAlg::Sha512),
        ),
    ];

    fn pubkey(openssh: &str) -> russh::keys::PublicKey {
        russh::keys::PublicKey::from_openssh(openssh).expect("valid public key")
    }

    /// RSA keys ask for the configured rsa-sha2 hash; everything else gets
    /// `None` so russh's per-key-type default is untouched (red line 2).
    #[test]
    fn signature_hash_alg_table() {
        for (openssh, expected) in TEST_PUBKEYS {
            let key = pubkey(openssh);
            assert_eq!(
                signature_hash_alg(&key, HashAlg::Sha512),
                *expected,
                "for {}",
                key.algorithm()
            );
        }
    }
}
