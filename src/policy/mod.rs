//! Authorization-time policy decisions.
//!
//! Two concerns live here:
//!
//! 1. **Backend host-key trust** (propose.md §3.3, D8). [`HostKeyVerifier`]
//!    decides, purely from a fingerprint string, whether the backend the gateway
//!    dialed may be trusted under the configured [`HostKeyPolicy`].
//! 2. **Per-request forwarding decisions** (propose.md §3.4, D6). Pure helpers
//!    decide whether `env`, agent-forwarding, X11 and TCP-forwarding requests
//!    are forwarded to the backend or denied locally.
//!
//! Keeping these as small, side-effect-free functions (rather than inline
//! `if`s buried in the handler) makes the security-relevant rules unit-testable.

use std::collections::BTreeSet;

use crate::ca::{self, CertificateCheck};
use crate::types::{Grant, HostKeyPolicy};

/// Outcome of verifying a backend host key against the configured policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// The key is trusted.
    Trusted,
    /// Trust on first use: accept and record (caller should warn).
    TrustFirstUse,
    /// Reject the connection.
    Rejected { reason: String },
}

impl HostKeyVerdict {
    /// Whether the verdict permits the connection.
    pub fn is_trusted(&self) -> bool {
        matches!(self, HostKeyVerdict::Trusted)
    }

    /// Whether the verdict rejects the connection.
    pub fn is_rejected(&self) -> bool {
        matches!(self, HostKeyVerdict::Rejected { .. })
    }
}

/// Verifies backend host keys against a pinned set under a [`HostKeyPolicy`],
/// and — when trusted CAs are configured — against a CA set for *certificates*
/// (propose §3.3, `@cert-authority`).
#[derive(Debug, Clone)]
pub struct HostKeyVerifier {
    policy: HostKeyPolicy,
    /// Pinned `SHA256:...` fingerprints learned out-of-band.
    pinned: BTreeSet<String>,
    /// Set of fingerprints already seen under `accept-new` (trust-on-first-use).
    known: std::sync::Arc<std::sync::Mutex<BTreeSet<String>>>,
    /// `SHA256:` fingerprints of trusted CA *signing* keys. When non-empty a
    /// presented **host certificate** is trusted through the four-step
    /// `@cert-authority` chain instead of by its inner-key fingerprint.
    trusted_ca: BTreeSet<String>,
}

impl HostKeyVerifier {
    /// Construct a verifier. `pinned` fingerprints are only meaningful for the
    /// [`HostKeyPolicy::Pinned`] policy; under `accept-new` they act as a
    /// pre-seeded allow-list.
    pub fn new(policy: HostKeyPolicy, pinned: impl IntoIterator<Item = String>) -> Self {
        HostKeyVerifier {
            policy,
            pinned: pinned.into_iter().collect(),
            known: std::sync::Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            trusted_ca: BTreeSet::new(),
        }
    }

    /// Same as [`new`](Self::new) plus a trusted CA set, which enables the
    /// `@cert-authority` path for host certificates (M4-T1).
    pub fn with_trusted_ca(
        policy: HostKeyPolicy,
        pinned: impl IntoIterator<Item = String>,
        trusted_ca: impl IntoIterator<Item = String>,
    ) -> Self {
        HostKeyVerifier {
            trusted_ca: trusted_ca.into_iter().collect(),
            ..Self::new(policy, pinned)
        }
    }

    /// Whether any trusted CA is configured, i.e. whether host certificates are
    /// verified by the `@cert-authority` chain at all.
    pub fn has_trusted_ca(&self) -> bool {
        !self.trusted_ca.is_empty()
    }

    /// Decide whether a backend host **certificate** may be trusted (M4-T1).
    ///
    /// `expected_host` is the host name the gateway set out to reach; the
    /// certificate must list it among its valid principals, or a certificate
    /// minted for a different backend would be accepted here. `now_unix` is the
    /// injected clock (seconds since the epoch).
    ///
    /// When no CA is configured this is never called — a presented certificate
    /// then keeps the pre-M4 inner-fingerprint behaviour (see
    /// [`crate::backend::host_key_fingerprint`]), preserving backward
    /// compatibility.
    pub fn verify_host_certificate(
        &self,
        cert: &russh::keys::Certificate,
        expected_host: &str,
        now_unix: u64,
    ) -> HostKeyVerdict {
        let ca_fingerprints: Vec<String> = self.trusted_ca.iter().cloned().collect();
        match ca::validate_host_certificate_at(cert, &ca_fingerprints, expected_host, now_unix) {
            CertificateCheck::Trusted => HostKeyVerdict::Trusted,
            CertificateCheck::WrongCertType { expected } => HostKeyVerdict::Rejected {
                reason: format!("host certificate of the wrong type (expected {expected})"),
            },
            CertificateCheck::UnknownCa => HostKeyVerdict::Rejected {
                reason: "host certificate signed by an untrusted CA".into(),
            },
            CertificateCheck::BadSignature => HostKeyVerdict::Rejected {
                reason: "host certificate signature is invalid".into(),
            },
            CertificateCheck::Expired => HostKeyVerdict::Rejected {
                reason: "host certificate is outside its validity window".into(),
            },
            CertificateCheck::PrincipalMismatch { expected } => HostKeyVerdict::Rejected {
                reason: format!(
                    "host certificate does not name this host (expected principal {expected})"
                ),
            },
        }
    }

    /// Decide whether a backend host key fingerprint may be trusted.
    pub fn verify(&self, fingerprint: &str) -> HostKeyVerdict {
        match self.policy {
            HostKeyPolicy::Pinned => {
                if self.pinned.contains(fingerprint) {
                    HostKeyVerdict::Trusted
                } else {
                    HostKeyVerdict::Rejected {
                        reason: format!("host key {fingerprint} is not in the pinned set"),
                    }
                }
            }
            HostKeyPolicy::AcceptNew => {
                if self.pinned.contains(fingerprint) {
                    HostKeyVerdict::Trusted
                } else {
                    // Record the fingerprint as now-known; the caller arms a
                    // warning that it should be pinned for production.
                    match self.known.lock() {
                        Ok(mut known) => {
                            if known.insert(fingerprint.to_owned()) {
                                HostKeyVerdict::TrustFirstUse
                            } else {
                                HostKeyVerdict::Trusted
                            }
                        }
                        Err(poisoned) => {
                            let mut known = poisoned.into_inner();
                            if known.insert(fingerprint.to_owned()) {
                                HostKeyVerdict::TrustFirstUse
                            } else {
                                HostKeyVerdict::Trusted
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Decision for a forwardable channel request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// Forward the request to the backend, optionally filtered.
    Forward,
    /// Deny the request locally (protocol-native failure), with a reason.
    DenyLocally { reason: String },
}

/// Whether an `env` request for `variable_name` may be forwarded.
///
/// An empty `allowlist` means pass-through (M1 behaviour, propose.md §3.4).
pub fn env_allowed(variable_name: &str, allowlist: &[String]) -> ForwardDecision {
    if allowlist.is_empty() || allowlist.iter().any(|n| n == variable_name) {
        ForwardDecision::Forward
    } else {
        ForwardDecision::DenyLocally {
            reason: format!("env {variable_name:?} not in allowlist"),
        }
    }
}

/// The gate for an incoming `auth-agent-req@openssh.com`.
///
/// Default-deny unless the control-plane policy explicitly allows agent
/// forwarding (D6). This is the **only** admission rule left: the instance
/// kill-switch `[backend] allow_agent_backend_auth` went away with the key/cert
/// credential (plan-agent-only D3), so the grant is the whole answer. Denying it
/// means the supervisor never dials at all — there is no other credential it
/// could fall back to (red line 3).
pub fn agent_passthrough_allowed(grant: &Grant) -> ForwardDecision {
    if grant.policy.agent_forwarding {
        ForwardDecision::Forward
    } else {
        ForwardDecision::DenyLocally {
            reason: "agent forwarding is not permitted".into(),
        }
    }
}

/// X11 forwarding is unsupported by the gateway (M1); it is always denied
/// locally. Jump/X11 becomes a policy option only in M3.
pub fn x11_allowed() -> ForwardDecision {
    ForwardDecision::DenyLocally {
        reason: "X11 forwarding is not supported".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Fingerprint, Policy, Principal, Target};

    fn grant_with(policy: Policy) -> Grant {
        Grant {
            principal: Principal::parse("alex_host1").unwrap(),
            fingerprint: Fingerprint::new("SHA256:fp"),
            agent_fingerprint: Fingerprint::new("SHA256:fp"),
            target: Target {
                host: "10.0.0.1".into(),
                port: 22,
                user: "root".into(),
            },
            policy,
        }
    }

    const FP: &str = "SHA256:abc123";

    #[test]
    fn pinned_policy_trusts_only_listed_fingerprints() {
        let v = HostKeyVerifier::new(HostKeyPolicy::Pinned, [FP.to_owned()]);
        assert_eq!(v.verify(FP), HostKeyVerdict::Trusted);
        assert!(matches!(
            v.verify("SHA256:other"),
            HostKeyVerdict::Rejected { .. }
        ));
    }

    #[test]
    fn accept_new_trusts_first_then_remembers() {
        let v = HostKeyVerifier::new(HostKeyPolicy::AcceptNew, Vec::new());
        assert_eq!(v.verify(FP), HostKeyVerdict::TrustFirstUse);
        // Second sighting is trusted without re-warning.
        assert_eq!(v.verify(FP), HostKeyVerdict::Trusted);
    }

    #[test]
    fn env_allowlist_empty_passes_all() {
        assert_eq!(env_allowed("LC_ALL", &[]), ForwardDecision::Forward);
    }

    #[test]
    fn env_allowlist_filters_unknown_names() {
        let allow = vec!["LANG".to_owned()];
        assert_eq!(env_allowed("LANG", &allow), ForwardDecision::Forward);
        assert!(matches!(
            env_allowed("SECRET", &allow),
            ForwardDecision::DenyLocally { .. }
        ));
    }

    #[test]
    fn agent_forwarding_is_default_deny() {
        let g = grant_with(Policy::default());
        assert!(matches!(
            agent_passthrough_allowed(&g),
            ForwardDecision::DenyLocally { .. }
        ));
        let g = grant_with(Policy {
            agent_forwarding: true,
            ..Default::default()
        });
        assert_eq!(agent_passthrough_allowed(&g), ForwardDecision::Forward);
    }

    #[test]
    fn agent_passthrough_is_decided_by_the_grant_alone() {
        // No kill-switch any more: the control-plane grant is the whole rule.
        let no_grant = grant_with(Policy::default());
        assert!(matches!(
            agent_passthrough_allowed(&no_grant),
            ForwardDecision::DenyLocally { .. }
        ));

        let allowed = grant_with(Policy {
            agent_forwarding: true,
            ..Default::default()
        });
        assert_eq!(
            agent_passthrough_allowed(&allowed),
            ForwardDecision::Forward
        );
    }

    // ---- M4-T1: host-certificate `@cert-authority` chain ----

    fn ca_privkey() -> russh::keys::PrivateKey {
        let mut rng = rand::rng();
        russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap()
    }

    fn ca_pub(ca: &russh::keys::PrivateKey) -> russh::keys::PublicKey {
        ca.public_key().clone()
    }

    fn ca_fp(ca: &russh::keys::PrivateKey) -> String {
        crate::ca::sha256_fingerprint(&ca_pub(ca))
    }

    /// A host certificate naming `host`, signed by `ca`.
    fn host_cert(ca: &russh::keys::PrivateKey, host: &str) -> russh::keys::Certificate {
        let inner = ca_privkey().public_key().clone();
        crate::ca::issuing::issue_host_certificate_with(
            ca,
            &inner,
            &[host.to_owned()],
            "backend-host",
            std::time::Duration::from_secs(300),
        )
        .unwrap()
    }

    #[test]
    fn host_certificate_from_a_trusted_ca_is_accepted() {
        let ca = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&ca)]);
        let cert = host_cert(&ca, "db.example.com");
        assert_eq!(
            verifier.verify_host_certificate(
                &cert,
                "db.example.com",
                crate::ca::now_unix_secs().unwrap()
            ),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn host_certificate_from_an_untrusted_ca_is_refused() {
        let trusted = ca_privkey();
        let rogue = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&trusted)]);
        let cert = host_cert(&rogue, "db.example.com");
        match verifier.verify_host_certificate(
            &cert,
            "db.example.com",
            crate::ca::now_unix_secs().unwrap(),
        ) {
            HostKeyVerdict::Rejected { reason } => {
                assert!(reason.contains("untrusted CA"), "{reason}")
            }
            other => panic!("an untrusted CA must be refused, got {other:?}"),
        }
    }

    #[test]
    fn expired_host_certificate_is_refused() {
        let ca = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&ca)]);
        let cert = host_cert(&ca, "db.example.com");
        // The injected clock is far in the future: outside the validity window.
        let far_future = cert.valid_before().saturating_add(60);
        assert!(verifier
            .verify_host_certificate(&cert, "db.example.com", far_future)
            .is_rejected());
    }

    #[test]
    fn tampered_host_certificate_is_refused() {
        let ca = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&ca)]);
        // A tamper is detected *after* the CA check, so the CA must be trusted —
        // that is what makes the signature step meaningful rather than masked.
        let cert = host_cert(&ca, "db.example.com");
        let mut bytes = cert.to_bytes().unwrap();
        let len = bytes.len();
        bytes[len - 32] ^= 0xff;
        let tampered = russh::keys::Certificate::from_bytes(&bytes).unwrap();
        assert!(verifier
            .verify_host_certificate(
                &tampered,
                "db.example.com",
                crate::ca::now_unix_secs().unwrap()
            )
            .is_rejected());
    }

    #[test]
    fn host_certificate_for_another_host_is_refused() {
        // M4-T1's P0: a CA-signed certificate naming a *different* backend must
        // not be trusted just because the CA is shared.
        let ca = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&ca)]);
        let cert = host_cert(&ca, "payroll.example.com");
        let verdict = verifier.verify_host_certificate(
            &cert,
            "db.example.com",
            crate::ca::now_unix_secs().unwrap(),
        );
        match verdict {
            HostKeyVerdict::Rejected { reason } => {
                assert!(reason.contains("does not name this host"), "{reason}")
            }
            other => panic!("a certificate for another host must be refused, got {other:?}"),
        }
    }

    #[test]
    fn host_certificate_principal_match_is_case_insensitive() {
        // Host names are not case significant; refusing `DB.Example.COM` because
        // the certificate says `db.example.com` would be an outage, not security.
        let ca = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&ca)]);
        let cert = host_cert(&ca, "db.example.com");
        assert!(verifier
            .verify_host_certificate(
                &cert,
                "DB.Example.COM.",
                crate::ca::now_unix_secs().unwrap()
            )
            .is_trusted());
    }

    #[test]
    fn user_certificate_is_not_accepted_as_a_host_certificate() {
        // The M4 chain also checks the certificate *type*: an ordinary user
        // certificate must not satisfy the KEX host-key check.
        let ca = ca_privkey();
        let verifier =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, Vec::new(), [ca_fp(&ca)]);
        let inner = ca_privkey().public_key().clone();
        let user_cert = crate::ca::issuing::issue_user_certificate_with(
            &ca,
            &inner,
            &["db.example.com".to_owned()],
            "a-user",
            std::time::Duration::from_secs(300),
        )
        .unwrap();
        match verifier.verify_host_certificate(
            &user_cert,
            "db.example.com",
            crate::ca::now_unix_secs().unwrap(),
        ) {
            HostKeyVerdict::Rejected { reason } => {
                assert!(reason.contains("wrong type"), "{reason}")
            }
            other => panic!("a user certificate must not pass the host check, got {other:?}"),
        }
    }

    #[test]
    fn raw_public_key_policy_is_unchanged_with_or_without_a_ca() {
        // Backward compatibility: the certificate path must not disturb the
        // existing pinned / accept-new behaviour for bare public keys.
        let ca = ca_privkey();
        let with_ca =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::Pinned, [FP.to_owned()], [ca_fp(&ca)]);
        let without_ca = HostKeyVerifier::new(HostKeyPolicy::Pinned, [FP.to_owned()]);
        assert_eq!(with_ca.verify(FP), without_ca.verify(FP));
        assert_eq!(
            with_ca.verify("SHA256:other"),
            without_ca.verify("SHA256:other")
        );

        let tofu_a =
            HostKeyVerifier::with_trusted_ca(HostKeyPolicy::AcceptNew, Vec::new(), [ca_fp(&ca)]);
        let tofu_b = HostKeyVerifier::new(HostKeyPolicy::AcceptNew, Vec::new());
        assert_eq!(tofu_a.verify(FP), tofu_b.verify(FP));
    }

    #[test]
    fn verifier_without_a_trusted_ca_reports_that_host_certs_are_off() {
        let verifier = HostKeyVerifier::new(HostKeyPolicy::AcceptNew, Vec::new());
        assert!(!verifier.has_trusted_ca());
        let with_ca = HostKeyVerifier::with_trusted_ca(
            HostKeyPolicy::AcceptNew,
            Vec::new(),
            [ca_fp(&ca_privkey())],
        );
        assert!(with_ca.has_trusted_ca());
    }

    #[test]
    fn x11_is_always_denied() {
        assert!(matches!(x11_allowed(), ForwardDecision::DenyLocally { .. }));
    }
}
