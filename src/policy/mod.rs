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

/// Verifies backend host keys against a pinned set under a [`HostKeyPolicy`].
#[derive(Debug, Clone)]
pub struct HostKeyVerifier {
    policy: HostKeyPolicy,
    /// Pinned `SHA256:...` fingerprints learned out-of-band.
    pinned: BTreeSet<String>,
    /// Set of fingerprints already seen under `accept-new` (trust-on-first-use).
    known: std::sync::Arc<std::sync::Mutex<BTreeSet<String>>>,
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

/// Whether agent forwarding may be enabled for this grant.
///
/// Default-deny unless the control-plane policy explicitly allows it (D6). Note
/// propose.md §3.8 additionally forbids agent forwarding on *pooled* connections
/// because of channel-routing ambiguity — that restriction is enforced in the
/// pool, not here.
pub fn agent_forwarding_allowed(grant: &Grant) -> ForwardDecision {
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

/// Whether a direct/forwarded TCP channel may be opened.
///
/// Default-deny unless the grant's policy allows TCP forwarding (jump mode is
/// M3; when opened up there, the target must additionally be validated).
pub fn tcp_forwarding_allowed(grant: &Grant) -> ForwardDecision {
    if grant.policy.tcp_forwarding {
        ForwardDecision::Forward
    } else {
        ForwardDecision::DenyLocally {
            reason: "TCP forwarding is not permitted".into(),
        }
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
            agent_forwarding_allowed(&g),
            ForwardDecision::DenyLocally { .. }
        ));
        let g = grant_with(Policy {
            agent_forwarding: true,
            ..Default::default()
        });
        assert_eq!(agent_forwarding_allowed(&g), ForwardDecision::Forward);
    }

    #[test]
    fn tcp_forwarding_follows_grant_policy() {
        assert!(matches!(
            tcp_forwarding_allowed(&grant_with(Policy::default())),
            ForwardDecision::DenyLocally { .. }
        ));
        let g = grant_with(Policy {
            tcp_forwarding: true,
            ..Default::default()
        });
        assert_eq!(tcp_forwarding_allowed(&g), ForwardDecision::Forward);
    }

    #[test]
    fn x11_is_always_denied() {
        assert!(matches!(x11_allowed(), ForwardDecision::DenyLocally { .. }));
    }
}
