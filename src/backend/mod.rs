//! Backend leg: credential loading + dialing + host-key verification.
//!
//! The gateway authenticates to the backend `sshd` as a russh *client*
//! (propose.md §3.3). This module owns:
//!
//! * **Credential loading** ([`CredentialStore`]): backend private keys are
//!   loaded at startup and their file permissions are enforced (fail-closed if a
//!   key is readable by group/other — a sick credential must prevent boot).
//! * **Host-key trust**: [`BackendClient::check_server_key`] computes the
//!   backend's SHA256 fingerprint and defers to the [`HostKeyVerifier`], so a
//!   `pinned` policy rejects an unexpected backend before userauth.
//! * **Dialing/auth** ([`BackendDialer::connect`]): TCP + KEX + publickey auth.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Handle};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};

use crate::error::{BackendError, Result};
use crate::metrics::Metrics;
use crate::policy::HostKeyVerifier;
use crate::pool::DialCircuitBreaker;
use crate::types::Grant;

/// Unix file mode bit that must be clear for a private key to be considered
/// safe: group and other must have no access.
const KEY_UNSAFE_MODE_MASK: u32 = 0o077;

/// How the gateway authenticates itself to the backend (propose §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendAuthMethod {
    /// A backend private key, with its public key in the backend's
    /// `authorized_keys` — the default, unchanged path.
    Key,
    /// A short-lived user certificate issued by the gateway's CA, accepted by the
    /// backend's `TrustedUserCAKeys`.
    Cert,
}

impl BackendAuthMethod {
    /// Parse the textual config / policy value.
    pub fn parse(field: &str, value: &str) -> std::result::Result<Self, crate::error::ConfigError> {
        match value.trim() {
            "key" => Ok(BackendAuthMethod::Key),
            "cert" => Ok(BackendAuthMethod::Cert),
            other => Err(crate::error::ConfigError::Invalid {
                field: field.to_owned(),
                reason: format!("unknown backend_auth {other:?} (expected \"key\" or \"cert\")"),
            }),
        }
    }

    /// The canonical string form (round-trips through [`parse`](Self::parse)).
    pub fn as_str(self) -> &'static str {
        match self {
            BackendAuthMethod::Key => "key",
            BackendAuthMethod::Cert => "cert",
        }
    }
}

/// Resolve which credential the gateway presents to a backend.
///
/// `instance_default` is `[backend] backend_auth` (always set — it defaults to
/// `key`), and `grant_override` is the optional per-resolve `policy.backend_auth`.
/// The grant wins when present, which lets one control plane steer a single
/// backend onto certificates while every other target keeps using keys.
///
/// Pure by design (plan S3): no I/O, no clock, no locks — so the routing rules
/// are directly unit-testable.
pub fn resolve_backend_auth(
    instance_default: BackendAuthMethod,
    grant_override: Option<BackendAuthMethod>,
) -> BackendAuthMethod {
    grant_override.unwrap_or(instance_default)
}

/// Loads and holds the backend private keys, keyed by backend username, plus an
/// optional default key for users without an explicit mapping.
#[derive(Debug, Default)]
pub struct CredentialStore {
    by_user: HashMap<String, Arc<PrivateKey>>,
    default: Option<Arc<PrivateKey>>,
}

impl CredentialStore {
    /// Load every configured credential, enforcing that each key file is not
    /// group/world-accessible. Any failure is fatal at startup.
    pub fn load(config: &crate::config::GatewayConfig) -> Result<Self> {
        let mut by_user = HashMap::new();
        let mut default = None;

        for (user, path) in &config.backend.credential_map {
            let key = load_private_key_checked(path, false)?;
            by_user.insert(user.clone(), Arc::new(key));
        }
        if let Some(path) = &config.backend.private_key {
            default = Some(Arc::new(load_private_key_checked(path, false)?));
        }

        if by_user.is_empty() && default.is_none() {
            return Err(BackendError::ChannelOpen {
                reason: "no backend credentials configured".into(),
            }
            .into());
        }
        Ok(CredentialStore { by_user, default })
    }

    /// The key to authenticate with for a given backend user.
    pub fn for_user(&self, user: &str) -> Option<Arc<PrivateKey>> {
        self.by_user
            .get(user)
            .cloned()
            .or_else(|| self.default.clone())
    }
}

/// Read a private key from `path`, refusing to load keys that are readable by
/// Read a private key from `path`, refusing to load keys that are readable by
/// group/other (propose.md §3.3: 0600 required). Shared by backend credentials
/// and host keys; the `is_host_key` flag only selects the clearer error message.
pub(crate) fn load_private_key_checked(
    path: &std::path::Path,
    is_host_key: bool,
) -> Result<PrivateKey> {
    #[cfg(unix)]
    check_key_permissions(path, is_host_key)?;
    russh::keys::load_secret_key(path, None)
        .map_err(|source| {
            if is_host_key {
                BackendError::LoadHostKey {
                    path: path.to_owned(),
                    source,
                }
            } else {
                BackendError::LoadKey {
                    path: path.to_owned(),
                    source,
                }
            }
        })
        .map_err(Into::into)
}

/// Enforce that `path` is not accessible by group or other (0600-style).
///
/// A key readable beyond its owner would let any local user impersonate the
/// gateway to the backend, so this is a hard startup gate (fail-closed).
#[cfg(unix)]
fn check_key_permissions(path: &std::path::Path, is_host_key: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .map_err(|source| crate::error::Error::io(source, "reading private key file metadata"))?;
    let mode = metadata.permissions().mode();
    if mode & KEY_UNSAFE_MODE_MASK != 0 {
        return Err(if is_host_key {
            BackendError::UnsafeHostKeyPermissions {
                path: path.to_owned(),
                perms: mode & 0o777,
            }
        } else {
            BackendError::UnsafeKeyPermissions {
                path: path.to_owned(),
                perms: mode & 0o777,
            }
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
}

/// Dials and authenticates backend sshd on behalf of a resolved [`Grant`].
pub struct BackendDialer {
    credentials: Arc<CredentialStore>,
    verifier: Arc<HostKeyVerifier>,
    client_config: Arc<client::Config>,
    metrics: Metrics,
    dial_timeout: Duration,
    /// The gateway's CA: signs a fresh short-lived user certificate per dial in
    /// cert mode. Absent means cert mode is unavailable and dialing fails loudly.
    ca: Option<Arc<crate::ca::CertificateAuthority>>,
    /// `[backend] backend_auth`: the default credential for grants that do not
    /// carry their own override.
    backend_auth: BackendAuthMethod,
    /// Per-target dial circuit breaker (§3.8): after `threshold` consecutive
    /// dial failures a target is short-circuited so repeated channel opens don't
    /// pile onto a dead backend.
    dial_breaker: DialCircuitBreaker,
    /// Process-wide ephemeral identity reused for cert-dial when the operator did
    /// not provision a per-user key (M4 P2-2). The *certificate* is still minted
    /// fresh per dial — this only avoids `PrivateKey::random` on every connect;
    /// the backend trusts the CA, not this throwaway identity key. The `Result`
    /// outer layer preserves a collection error instead of panicking on first use.
    ephemeral_identity: std::sync::OnceLock<std::result::Result<Arc<PrivateKey>, String>>,
}

impl BackendDialer {
    pub fn new(
        config: &crate::config::GatewayConfig,
        credentials: Arc<CredentialStore>,
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
            credentials,
            verifier,
            client_config: Arc::new(client_config),
            metrics,
            dial_timeout: config.control_plane.timeout,
            ca,
            backend_auth: config.backend.backend_auth,
            dial_breaker: DialCircuitBreaker::new(
                config.pool.circuit_failure_threshold,
                config.pool.circuit_reset_timeout,
            ),
            ephemeral_identity: std::sync::OnceLock::new(),
        }
    }

    /// Attach the certificate authority, enabling cert-mode dialing and the
    /// host-certificate trust path (M4-T1/T2). Without it the dialer keeps the
    /// pre-M4 private-key behaviour exactly.
    pub fn with_ca(mut self, ca: Arc<crate::ca::CertificateAuthority>) -> Self {
        self.ca = Some(ca);
        self
    }

    /// The routing default this dialer was built with (exposed for introspection
    /// and tests).
    pub fn backend_auth_method(&self) -> BackendAuthMethod {
        self.backend_auth
    }

    /// The breaker key for a grant's target (one breaker per `host:port`).
    fn breaker_key(grant: &Grant) -> String {
        format!("{}:{}", grant.target.host, grant.target.port)
    }

    /// Establish an authenticated backend session for the grant's target.
    ///
    /// Fail-fast gate: if the per-target dial breaker is open, this returns
    /// [`BackendError::CircuitOpen`] without touching the network, so a dead
    /// backend can't stall every channel open. Every outcome feeds the breaker.
    pub async fn connect(&self, grant: &Grant) -> Result<Handle<BackendClient>> {
        let key = Self::breaker_key(grant);
        if !self.dial_breaker.allows(&key) {
            self.metrics.backend_dial_fail();
            return Err(BackendError::CircuitOpen { target: key }.into());
        }

        let started = std::time::Instant::now();
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
        let mut handle = tokio::time::timeout(self.dial_timeout, connect_fut)
            .await
            .map_err(|_| {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(&key);
                BackendError::Dial {
                    addr: format!("{}:{}", grant.target.host, grant.target.port),
                    source: Box::new(crate::error::Error::Invariant(
                        "backend dial timed out".into(),
                    )),
                }
            })?
            .map_err(|e| {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(&key);
                self.dial_error(grant, last_rejection, e)
            })?;

        // Authenticate with the credential the routed method selects (M4-T2/T3).
        // A per-grant override wins over `[backend] backend_auth`; a malformed
        // policy value is a resolve error, not a silent downgrade to `key`.
        let method = match grant.policy.backend_auth_method() {
            Some(Ok(override_method)) => override_method,
            Some(Err(e)) => {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(&key);
                return Err(e.into());
            }
            None => self.backend_auth,
        };
        let outcome = match method {
            BackendAuthMethod::Key => {
                let key_for_user =
                    self.credentials
                        .for_user(&grant.target.user)
                        .ok_or_else(|| BackendError::Auth {
                            user: grant.target.user.clone(),
                        })?;
                let pkwha = PrivateKeyWithHashAlg::new(key_for_user, None);
                handle
                    .authenticate_publickey(&grant.target.user, pkwha)
                    .await
                    .map_err(|e| BackendError::Auth {
                        user: format!("{} ({e})", grant.target.user),
                    })
            }
            BackendAuthMethod::Cert => self.authenticate_with_certificate(&mut handle, grant).await,
        };

        match outcome {
            Err(e) => {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(&key);
                Err(e.into())
            }
            Ok(AuthResult::Success) => {
                self.metrics.backend_dial_ok();
                self.metrics.backend_dial_latency(started.elapsed());
                // A full handshake succeeded: the target is healthy again.
                self.dial_breaker.record_success(&key);
                Ok(handle)
            }
            Ok(_) => {
                self.metrics.backend_dial_fail();
                self.dial_breaker.record_failure(&key);
                Err(BackendError::Auth {
                    user: grant.target.user.clone(),
                }
                .into())
            }
        }
    }

    /// Authenticate to the backend with a **freshly issued** short-lived user
    /// certificate (M4-T2).
    ///
    /// The certificate is minted at dial time and never cached or reused:
    ///
    /// * **stateless** — nothing to persist, so an HA fleet of replicas needs no
    ///   shared cert store and no coordination;
    /// * **auditable** — every connection issues exactly one certificate, so the
    ///   audit trail lines up one-to-one with dials;
    /// * **rotation-safe for new connections** — a CA signing-key rotation takes
    ///   effect on the next dial, not on a schedule.
    ///
    /// The deliberate trade-off (recorded here per plan-m4 M4-T2): a connection
    /// that is *already established* keeps its certificate for the life of the
    /// SSH session. SSH never re-authenticates inside a session, so rotating the
    /// CA cannot revoke a live connection; it only stops the next one. Revoking
    /// an established session is the backend's job (`ssh-keygen -R` on the user
    /// side, or killing the session).
    ///
    /// The *inner* key is the configured backend credential when one exists, and
    /// an ephemeral keypair otherwise — which is what lets `private_key` /
    /// `credential_map` be omitted in cert mode, since the backend trusts the CA
    /// rather than a specific gateway key.
    async fn authenticate_with_certificate(
        &self,
        handle: &mut Handle<BackendClient>,
        grant: &Grant,
    ) -> std::result::Result<AuthResult, BackendError> {
        let user = &grant.target.user;
        let ca = self.ca.as_ref().ok_or_else(|| BackendError::IssueCert {
            user: user.clone(),
            reason: "no CA is loaded; cert mode needs [ca] signing_key".into(),
        })?;

        // Prefer the operator-provisioned identity; otherwise reuse a single
        // process-wide throwaway keypair (safe because the backend trusts the
        // issuing CA, not this identity key — see M4 P2-2). The certificate is
        // still minted fresh per dial below.
        let inner_key = match self.credentials.for_user(user) {
            Some(key) => key,
            None => match self.ephemeral_identity.get_or_init(|| {
                PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                    .map(Arc::new)
                    .map_err(|e| format!("generating an ephemeral identity key: {e}"))
            }) {
                Ok(key) => key.clone(),
                Err(reason) => {
                    return Err(BackendError::IssueCert {
                        user: user.clone(),
                        reason: reason.clone(),
                    })
                }
            },
        };

        // One certificate per dial: principals = the backend user, lifetime =
        // `[ca].cert_lifetime`, key_id = what the backend's logs will show.
        let principals = vec![user.clone()];
        let key_id = format!("sshgw-dial-{}@{}", grant.principal.as_str(), user);
        let cert = ca
            .issue_user_certificate(inner_key.public_key(), &principals, &key_id)
            .map_err(|e| BackendError::IssueCert {
                user: user.clone(),
                reason: e.to_string(),
            })?;

        tracing::debug!(
            target: "backend",
            user = %user,
            key_id = %key_id,
            "authenticating to the backend with a short-lived user certificate"
        );

        handle
            .authenticate_openssh_cert(user, inner_key, cert)
            .await
            .map_err(|e| BackendError::IssueCert {
                user: user.clone(),
                reason: e.to_string(),
            })
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
        let err = load_private_key_checked(&temp, false).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Backend(BackendError::UnsafeKeyPermissions { .. })
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
        let loaded = load_private_key_checked(&temp, false).expect("0600 key loads");
        assert_eq!(loaded.algorithm(), key.algorithm());
    }

    #[test]
    fn missing_key_file_is_a_load_error_not_panic() {
        let path = std::path::Path::new("/nonexistent/definitely/not/here/key");
        let err = load_private_key_checked(path, false).unwrap_err();
        // Fails at the permission/metadata step with a context-rich i/o error.
        assert!(
            matches!(err, crate::error::Error::Io { .. }),
            "expected an i/o error for a missing key, got {err:?}"
        );
    }

    // ---- M4-T2/T3: backend credential routing + config ----

    #[test]
    fn routing_prefers_the_grant_override_then_the_instance_default() {
        use crate::backend::{resolve_backend_auth, BackendAuthMethod};
        // No override -> the instance default.
        assert_eq!(
            resolve_backend_auth(BackendAuthMethod::Key, None),
            BackendAuthMethod::Key
        );
        assert_eq!(
            resolve_backend_auth(BackendAuthMethod::Cert, None),
            BackendAuthMethod::Cert
        );
        // The grant wins when present, in both directions.
        assert_eq!(
            resolve_backend_auth(BackendAuthMethod::Key, Some(BackendAuthMethod::Cert)),
            BackendAuthMethod::Cert
        );
        assert_eq!(
            resolve_backend_auth(BackendAuthMethod::Cert, Some(BackendAuthMethod::Key)),
            BackendAuthMethod::Key
        );
    }

    #[test]
    fn backend_auth_method_parses_and_round_trips() {
        use crate::backend::BackendAuthMethod;
        assert_eq!(
            BackendAuthMethod::parse("f", "key").unwrap(),
            BackendAuthMethod::Key
        );
        assert_eq!(
            BackendAuthMethod::parse("f", " cert ").unwrap(),
            BackendAuthMethod::Cert
        );
        assert_eq!(BackendAuthMethod::Key.as_str(), "key");
        assert_eq!(BackendAuthMethod::Cert.as_str(), "cert");
        assert!(BackendAuthMethod::parse("f", "token").is_err());
    }

    #[test]
    fn policy_backend_auth_absent_means_no_override() {
        // A control plane that predates the field must not change behaviour.
        let policy = crate::types::Policy {
            tcp_forwarding: true,
            ..Default::default()
        };
        assert_eq!(policy.backend_auth, None);
        assert!(policy.backend_auth_method().is_none());
    }

    #[test]
    fn policy_backend_auth_reports_a_malformed_value_instead_of_defaulting() {
        // An unreadable policy must not silently downgrade the credential to a
        // key: that would quietly weaken authentication.
        let policy = crate::types::Policy {
            backend_auth: Some("token".to_owned()),
            ..Default::default()
        };
        match policy.backend_auth_method() {
            Some(Err(e)) => assert!(!e.to_string().is_empty()),
            other => panic!("a malformed backend_auth must be an error, got {other:?}"),
        }
    }

    #[test]
    fn cert_mode_without_a_ca_loaded_fails_loudly() {
        // A dialer built without a CA must refuse rather than fall back to keys.
        use crate::backend::BackendAuthMethod;
        let grant = crate::types::Grant {
            principal: crate::types::Principal::parse("alex_host1").unwrap(),
            fingerprint: crate::types::Fingerprint::new("SHA256:fp"),
            target: crate::types::Target {
                host: "127.0.0.1".into(),
                port: 22,
                user: "root".into(),
            },
            policy: crate::types::Policy {
                backend_auth: Some("cert".to_owned()),
                ..Default::default()
            },
        };
        let assets = std::env::temp_dir().join(format!(
            "sshgw-m4-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&assets).unwrap();
        let host = assets.join("host");
        let backend = assets.join("backend");
        for p in [&host, &backend] {
            let mut rng = rand::rng();
            let body = PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
                .unwrap()
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap();
            {
                let f = std::fs::File::create(p).unwrap();
                let _ = f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
            }
            std::fs::write(p, body).unwrap();
        }
        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [ {{ path = "{}", state = "active" }} ]
            [backend]
            private_key = "{}"
            host_key_policy = "accept-new"
            backend_auth = "cert"
            [control_plane]
            url = "http://127.0.0.1:1"
            [ca]
            trusted_ca_keys = []
        "#,
            host.to_string_lossy(),
            backend.to_string_lossy(),
        );
        drop(std::fs::remove_dir_all(&assets));

        // The config layer catches the contradictory combination first (cert mode
        // needs a signing key), so this never reaches the dialer.
        let err = crate::config::GatewayConfig::parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("signing_key"),
            "cert mode without a signing key must be rejected at config time, got: {msg}"
        );
        let _ = (grant, BackendAuthMethod::Cert);
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
            target: crate::types::Target {
                host: host.to_owned(),
                port: 22,
                user: "root".to_owned(),
            },
            policy: crate::types::Policy::default(),
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
        let backend = assets.join("backend");
        for p in [&host, &backend] {
            let mut rng = rand::rng();
            let key = PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
            let body = key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap();
            {
                let f = std::fs::File::create(p).unwrap();
                let _ = f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
            }
            std::fs::write(p, body).unwrap();
        }
        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [ {{ path = "{}", state = "active" }} ]
            [backend]
            private_key = "{}"
            host_key_policy = "accept-new"
            [control_plane]
            url = "http://127.0.0.1:1"
            [pool]
            circuit_failure_threshold = {fail_threshold}
            circuit_reset_timeout = "{}s"
        "#,
            host.to_string_lossy(),
            backend.to_string_lossy(),
            reset.as_secs(),
        );
        let config = crate::config::GatewayConfig::parse(&toml).unwrap();
        let credentials = Arc::new(CredentialStore::load(&config).unwrap());
        let verifier = Arc::new(HostKeyVerifier::new(HostKeyPolicy::AcceptNew, Vec::new()));
        let dialer = BackendDialer::new(&config, credentials, verifier, Metrics::default(), None);
        drop(std::fs::remove_dir_all(&assets));
        dialer
    }

    #[test]
    fn breaker_key_is_host_and_port() {
        let g = test_grant("10.1.2.3");
        assert_eq!(BackendDialer::breaker_key(&g), "10.1.2.3:22");
    }

    #[test]
    fn open_breaker_makes_connect_fail_fast_without_network() {
        // P1-1: once the per-target breaker has tripped, `connect` must fail with
        // `CircuitOpen` *before* any socket work. A closed/refused port proves we
        // never dialled (a real dial would return Dial/Timeout, not CircuitOpen).
        let dialer = dialer_with(2, Duration::from_secs(60));
        let grant = test_grant("10.1.2.3");
        dialer
            .dial_breaker
            .record_failure(&BackendDialer::breaker_key(&grant));
        dialer
            .dial_breaker
            .record_failure(&BackendDialer::breaker_key(&grant));

        let outcome = futures_now_block_on(dialer.connect(&grant));
        let err = match outcome {
            Ok(_) => panic!("connect must not dial a target with an open breaker"),
            Err(e) => e,
        };
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

    /// Minimal blocking bridge for the (non-async) failure-path assertions above.
    fn futures_now_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn ephemeral_identity_is_generated_once_and_reused_across_dials() {
        // M4 P2-2: without an operator-provisioned key, cert mode reuses one
        // process-wide throwaway identity key instead of PrivateKey::random per
        // dial; the certificate is still minted fresh each time.
        let dialer = dialer_with(1, Duration::from_secs(60));
        let key1 = {
            let slot = dialer
                .ephemeral_identity
                .get_or_init(|| {
                    PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                        .map(Arc::new)
                        .map_err(|e| e.to_string())
                })
                .clone()
                .expect("ephemeral key generation must not fail");
            key1_fingerprint(&slot)
        };
        let key2 = {
            let slot = dialer
                .ephemeral_identity
                .get_or_init(|| {
                    // A second init must not happen; if it did, the fingerprint
                    // would differ and the assert below would fail.
                    PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                        .map(Arc::new)
                        .map_err(|e| e.to_string())
                })
                .clone()
                .expect("ephemeral key generation must not fail");
            key1_fingerprint(&slot)
        };
        assert_eq!(
            key1, key2,
            "ephemeral identity must be generated once and reused across dials"
        );
        assert!(!key1.is_empty());
    }

    fn key1_fingerprint(k: &Arc<PrivateKey>) -> String {
        k.public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string()
    }
}
