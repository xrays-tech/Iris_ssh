//! Shared domain types parsed at trust boundaries.
//!
//! Rule of *parse, don't validate*: anything crossing a trust boundary (config
//! file, control-plane response, SSH username) is converted here into a typed
//! value whose invariants the rest of the crate can rely on without re-checking.
//! [`Principal`] is the canonical example — it is impossible to construct one
//! that fails the opaque-token regex, so the resolver and auditor never have to
//! defensively re-validate it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A validated SSH username, treated as an opaque routing token.
///
/// Constructed only via [`Principal::parse`], which enforces the
/// `^[a-z0-9][a-z0-9_-]{0,62}$` shape from propose.md §3.1. Once you hold a
/// `Principal`, its shape is guaranteed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Principal(String);

/// Maximum length of a principal token (1 + 62).
const PRINCIPAL_MAX_LEN: usize = 63;

/// Attempt to parse a raw username into a [`Principal`].
///
/// Returns [`crate::error::ResolveError::InvalidPrincipal`] with a specific
/// reason so misconfigured clients fail loudly at the boundary instead of
/// silently misrouting.
pub fn parse_principal(raw: &str) -> Result<Principal, crate::error::ResolveError> {
    fn invalid(raw: &str, reason: &str) -> crate::error::ResolveError {
        crate::error::ResolveError::InvalidPrincipal {
            principal: raw.to_owned(),
            reason: reason.to_owned(),
        }
    }

    if raw.is_empty() {
        return Err(invalid(raw, "must not be empty"));
    }
    if raw.len() > PRINCIPAL_MAX_LEN {
        return Err(invalid(raw, "longer than 63 bytes"));
    }
    let mut chars = raw.chars();
    // The first character must be an ASCII lowercase letter or digit.
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => {
            return Err(invalid(
                raw,
                "must start with an ASCII lowercase letter or digit",
            ));
        }
    }
    if let Some(bad) = chars.find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-')) {
        return Err(invalid(
            raw,
            &format!("contains a disallowed character {bad:?}"),
        ));
    }
    Ok(Principal(raw.to_owned()))
}

impl Principal {
    /// Parse a raw username into a validated [`Principal`].
    pub fn parse(raw: &str) -> Result<Principal, crate::error::ResolveError> {
        parse_principal(raw)
    }

    /// The raw username bytes.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A SHA256 key fingerprint, rendered canonically as `SHA256:<base64>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn new(raw: impl Into<String>) -> Self {
        Fingerprint(raw.into())
    }

    /// Canonical string form (e.g. `SHA256:abcd...`).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `(principal, fingerprint)` key used to cache and reuse an authorization
/// decision across the two-phase authentication callbacks (propose.md §3.2, D4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthKey {
    pub principal: Principal,
    pub fingerprint: Fingerprint,
}

/// Backend connection coordinates resolved by the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
}

/// Authorization flags attached to a [`Grant`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub agent_forwarding: bool,
    #[serde(default)]
    pub tcp_forwarding: bool,
    #[serde(default)]
    pub recording: bool,
    #[serde(default)]
    pub ttl: u32,
}

/// A resolved + authorized destination for one client session.
///
/// Produced by the resolver and consumed by the dialer and relay; it is the
/// authoritative "who am I allowed to reach, and how".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub principal: Principal,
    pub fingerprint: Fingerprint,
    pub target: Target,
    pub policy: Policy,
}

/// The control-plane `POST /api/v1/resolve` request body (propose.md §3.1).
#[derive(Debug, Clone, Serialize)]
pub struct ResolveRequest {
    pub principal: String,
    pub client_ip: String,
    pub key_fp: String,
}

/// The control-plane `POST /api/v1/resolve` 200 response body (propose.md §3.1).
///
/// Serde derives make unknown future fields non-fatal (they are ignored), so
/// the control plane can evolve without breaking the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ResolveResponse {
    pub target: Target,
    #[serde(default)]
    pub policy: Policy,
}

/// A backend credential: the SSH private key the gateway authenticates with,
/// paired with the backend username it is valid for (`credential_map`).
#[derive(Debug, Clone)]
pub struct Credential {
    pub user: String,
    pub key_path: PathBuf,
}

/// How the gateway treats the backend's host key (propose.md §3.3, D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Trust only pinned fingerprints learned out-of-band; reject anything
    /// else. Required in production.
    Pinned,
    /// Trust on first use and emit a warning. Non-production only.
    AcceptNew,
}

impl HostKeyPolicy {
    /// Parse the textual config value.
    pub fn parse(value: &str) -> Result<Self, crate::error::ConfigError> {
        match value {
            "pinned" => Ok(HostKeyPolicy::Pinned),
            "accept-new" => Ok(HostKeyPolicy::AcceptNew),
            other => Err(crate::error::ConfigError::Invalid {
                field: "backend.host_key_policy".into(),
                reason: format!("unknown policy {other:?} (expected \"pinned\" or \"accept-new\")"),
            }),
        }
    }
}

/// A monotonic, time-ordered session identifier (UUIDv7) that ties the client
/// leg and backend leg audit/log lines together.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Mint a fresh v7 identifier (time-ordered, globally unique).
    pub fn generate() -> Self {
        SessionId(uuid::Uuid::now_v7().to_string())
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_principals() {
        for good in ["alex_host1", "a", "host-1", "under_score", "x9y8", "0start"] {
            assert!(parse_principal(good).is_ok(), "{good} should be valid");
        }
    }

    #[test]
    fn rejects_malformed_principals_with_specific_reason() {
        assert!(parse_principal("").is_err());
        assert!(parse_principal("Bad").is_err()); // uppercase first char
        assert!(parse_principal("-lead").is_err()); // leading dash
        assert!(parse_principal("_lead").is_err()); // leading underscore
        assert!(parse_principal("has space").is_err());
        assert!(parse_principal("dot.name").is_err());
        assert!(matches!(
            parse_principal("-lead"),
            Err(crate::error::ResolveError::InvalidPrincipal { .. })
        ));
    }

    #[test]
    fn rejects_overlong_principal() {
        let long = "a".repeat(64);
        assert!(parse_principal(&long).is_err());
        let ok = "a".repeat(63);
        assert!(parse_principal(&ok).is_ok());
    }

    #[test]
    fn principal_roundtrips_display() {
        let p = parse_principal("alex_host1").expect("valid");
        assert_eq!(p.as_str(), "alex_host1");
        assert_eq!(p.to_string(), "alex_host1");
    }

    #[test]
    fn host_key_policy_parse_accepts_known_values() {
        assert_eq!(HostKeyPolicy::parse("pinned").unwrap(), HostKeyPolicy::Pinned);
        assert_eq!(
            HostKeyPolicy::parse("accept-new").unwrap(),
            HostKeyPolicy::AcceptNew
        );
        assert!(HostKeyPolicy::parse("trust-everything").is_err());
    }

    #[test]
    fn resolve_response_tolerates_missing_optional_policy_fields() {
        let json = r#"{"target":{"host":"10.1.2.3","port":22,"user":"root"}}"#;
        let resp: ResolveResponse = serde_json::from_str(json).expect("parses");
        assert_eq!(resp.target.host, "10.1.2.3");
        assert!(!resp.policy.agent_forwarding);
        assert_eq!(resp.policy.ttl, 0);
    }

    #[test]
    fn session_ids_are_time_ordered_and_unique() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a, b);
        assert!(a.to_string().len() == 36);
    }
}
