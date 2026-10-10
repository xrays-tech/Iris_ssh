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
use crate::types::Grant;

/// Unix file mode bit that must be clear for a private key to be considered
/// safe: group and other must have no access.
const KEY_UNSAFE_MODE_MASK: u32 = 0o077;

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
pub fn host_key_fingerprint(key: &PublicKeyOrCertificate) -> String {
    let public = match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
        PublicKeyOrCertificate::Certificate(cert) => {
            russh::keys::PublicKey::from(cert.public_key().clone())
        }
    };
    public.fingerprint(HashAlg::Sha256).to_string()
}

/// Client-leg handler: verifies the backend host key against the policy and
/// records the last rejection reason so `connect` can surface a clear error.
pub struct BackendClient {
    verifier: Arc<HostKeyVerifier>,
    last_rejection: Arc<Mutex<Option<String>>>,
}

impl BackendClient {
    fn new(verifier: Arc<HostKeyVerifier>, last_rejection: Arc<Mutex<Option<String>>>) -> Self {
        BackendClient {
            verifier,
            last_rejection,
        }
    }
}

impl client::Handler for BackendClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let fp = host_key_fingerprint(server_public_key);
        match self.verifier.verify(&fp) {
            crate::policy::HostKeyVerdict::Trusted => Ok(true),
            crate::policy::HostKeyVerdict::TrustFirstUse => {
                tracing::warn!(target: "backend", %fp, "trusted backend host key on first use; pin it for production");
                Ok(true)
            }
            crate::policy::HostKeyVerdict::Rejected { reason } => {
                if let Ok(mut slot) = self.last_rejection.lock() {
                    *slot = Some(format!("{reason} (fingerprint {fp})"));
                }
                tracing::warn!(target: "backend", %fp, %reason, "rejected backend host key");
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
}

impl BackendDialer {
    pub fn new(
        config: &crate::config::GatewayConfig,
        credentials: Arc<CredentialStore>,
        verifier: Arc<HostKeyVerifier>,
        metrics: Metrics,
    ) -> Self {
        let client_config = client::Config {
            window_size: config.relay.window_size,
            maximum_packet_size: config.relay.max_packet,
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
        }
    }

    /// Establish an authenticated backend session for the grant's target.
    pub async fn connect(&self, grant: &Grant) -> Result<Handle<BackendClient>> {
        let started = std::time::Instant::now();
        let addr = (grant.target.host.as_str(), grant.target.port);
        let last_rejection: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let handler = BackendClient::new(Arc::clone(&self.verifier), Arc::clone(&last_rejection));

        let connect_fut =
            client::connect::<BackendClient, _>(Arc::clone(&self.client_config), addr, handler);
        let handle = tokio::time::timeout(self.dial_timeout, connect_fut)
            .await
            .map_err(|_| {
                self.metrics.backend_dial_fail();
                BackendError::Dial {
                    addr: format!("{}:{}", grant.target.host, grant.target.port),
                    source: Box::new(crate::error::Error::Invariant(
                        "backend dial timed out".into(),
                    )),
                }
            })?
            .map_err(|e| {
                self.metrics.backend_dial_fail();
                self.dial_error(grant, last_rejection, e)
            })?;

        // Authenticate with the backend key for the target user.
        let key = self
            .credentials
            .for_user(&grant.target.user)
            .ok_or_else(|| {
                self.metrics.backend_dial_fail();
                BackendError::Auth {
                    user: grant.target.user.clone(),
                }
            })?;
        let pkwha = PrivateKeyWithHashAlg::new(key, None);

        let mut handle = handle;
        match handle
            .authenticate_publickey(&grant.target.user, pkwha)
            .await
        {
            Ok(AuthResult::Success) => {
                self.metrics.backend_dial_ok();
                self.metrics.backend_dial_latency(started.elapsed());
                Ok(handle)
            }
            Ok(_) => {
                self.metrics.backend_dial_fail();
                Err(BackendError::Auth {
                    user: grant.target.user.clone(),
                }
                .into())
            }
            Err(e) => {
                self.metrics.backend_dial_fail();
                Err(BackendError::Auth {
                    user: format!("{} ({e})", grant.target.user),
                }
                .into())
            }
        }
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

    fn write_temp_key(perms: u32, content: &str) -> std::path::PathBuf {
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
        path
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
        let path = write_temp_key(0o644, &content);
        let err = load_private_key_checked(&path, false).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Backend(BackendError::UnsafeKeyPermissions { .. })
            ),
            "expected unsafe-permissions rejection, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loads_a_0600_key_generated_on_the_fly() {
        let mut rng = rand::rng();
        let key =
            PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).expect("random key");
        let openssh = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encode");
        let path = write_temp_key(0o600, &openssh);
        let loaded = load_private_key_checked(&path, false).expect("0600 key loads");
        assert_eq!(loaded.algorithm(), key.algorithm());
        let _ = std::fs::remove_file(&path);
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

    #[test]
    fn verifier_rejects_unpinned_under_pinned_policy() {
        let v = HostKeyVerifier::new(HostKeyPolicy::Pinned, Vec::new());
        assert!(matches!(
            v.verify("SHA256:whatever"),
            HostKeyVerdict::Rejected { .. }
        ));
    }
}
