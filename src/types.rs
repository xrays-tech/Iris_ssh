//! Shared domain types parsed at trust boundaries.
//!
//! Rule of *parse, don't validate*: anything crossing a trust boundary (config
//! file, control-plane response, SSH username) is converted here into a typed
//! value whose invariants the rest of the crate can rely on without re-checking.
//! [`Principal`] is the canonical example — it is impossible to construct one
//! that fails the opaque-token regex, so the resolver and auditor never have to
//! defensively re-validate it.

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
    if let Some(bad) =
        chars.find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-'))
    {
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

/// Whether `raw` is a **canonical, lowercase UUID** (8-4-4-4-12 hyphens).
///
/// This is the route predicate for OpenStack instance-UUID routing
/// (plan-openstack §0/F1): a username shaped like a UUID is treated as an
/// OpenStack instance id, anything else is not.
///
/// Deliberately *not* restricted to version 4: OpenStack overwhelmingly emits
/// UUIDv4, but historical instances can be UUIDv1 or otherwise, and refusing
/// them would silently un-route live machines (R10). The check is on the
/// canonical hyphenated shape only, so the 32-hex "simple" form, the `urn:uuid:`
/// form and the braced form are all rejected — this predicate is about "does the
/// username *look* like an instance id", not about general UUID parsing.
///
/// Lowercase is required: [`Principal`] rejects uppercase outright, and every
/// cloud prints ids in lowercase (`uuidgen | tr A-Z a-z`, or as Nova returns
/// them), so accepting `550E8400-...` would only widen the predicate for values
/// no OpenStack emits.
///
/// Callers are exactly two: [`crate::resolve::route_for`] (which resolver a
/// username is sent to) and the Nova URL guard in
/// [`crate::openstack::OpenStackClient`] (defense in depth before any request
/// is built). It is deliberately **not** consulted for operator configuration.
///
/// Pure: no configuration, no I/O.
pub fn is_instance_uuid(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    if raw.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    uuid::Uuid::parse_str(raw).is_ok()
}

/// A guard for the instance-**name** route: non-empty, ≤255 bytes (Nova's name
/// limit), no ASCII control characters.
///
/// It is deliberately *not* a grammar. By the time a name reaches routing it
/// has already been through [`Principal::parse`]
/// (`^[a-z0-9][a-z0-9_-]{0,62}$`), which is the real gate — a name containing
/// a space, a dot or an uppercase letter is rejected at the front leg and never
/// arrives here (plan-openstack appendix A.1). This predicate is only a
/// defence-in-depth bound on the string that is about to become a Nova query
/// parameter value.
///
/// Callers: [`crate::resolve::route_for`] (is this principal eligible for the
/// name route at all?) and the Nova name lookup in
/// [`crate::openstack::OpenStackClient`] (belt and braces before the request is
/// built). [`is_instance_uuid`] always wins: a UUID-shaped principal is never
/// treated as a name, even when both routes are enabled.
///
/// Pure: no configuration, no I/O.
pub fn is_instance_name(raw: &str) -> bool {
    !raw.is_empty() && raw.len() <= 255 && !raw.chars().any(char::is_control)
}

/// Which resolver produced a [`Grant`] (observability only: it never changes
/// what the grant authorizes).
///
/// Recorded in the audit record as `resolve_source` so an auditor can tell a
/// control-plane grant from an OpenStack UUID-route grant without guessing
/// from the target host (plan-openstack §3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ResolveSource {
    /// Resolved (and authorized) by the external control plane.
    #[default]
    ControlPlane,
    /// Resolved from OpenStack Nova (instance UUID → IP); authorization is the
    /// gateway's own `allow_any_authenticated_key` lab mode (scheme B).
    OpenStack,
}

impl ResolveSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolveSource::ControlPlane => "control_plane",
            ResolveSource::OpenStack => "openstack",
        }
    }
}

impl std::fmt::Display for ResolveSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    /// The fingerprint used to match a forwarded agent identity when dialing the
    /// backend. For raw public-key auth this equals `fingerprint`; for
    /// certificate auth this is the certificate's subject key fingerprint (the
    /// user's actual key), while `fingerprint` remains the CA fingerprint for
    /// control-plane authorization.
    pub agent_fingerprint: Fingerprint,
    pub target: Target,
    pub policy: Policy,
    /// Which resolver produced this grant. Stamped by the `ResolveRouter` after
    /// a successful authorization — the router is the only component that knows
    /// the route — and surfaced in the audit record as `resolve_source`. Purely
    /// informational: it never changes what the grant authorizes.
    pub resolve_source: ResolveSource,
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
        assert_eq!(
            HostKeyPolicy::parse("pinned").unwrap(),
            HostKeyPolicy::Pinned
        );
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

    #[test]
    fn instance_uuid_predicate_accepts_canonical_lowercase_uuids() {
        // Whatever version the runtime clock produces (v7 here): the predicate
        // must not care about the version nibble.
        let runtime = uuid::Uuid::now_v7().to_string();
        let cases = [
            "00000000-0000-0000-0000-000000000000",
            "4710fd67-1d3c-4c3e-9d35-6a5c0a9f7d1b",
            "123e4567-e89b-12d3-a456-426614174000",
            runtime.as_str(),
        ];
        for good in cases {
            assert!(is_instance_uuid(good), "{good} should route as a UUID");
        }
    }

    #[test]
    fn instance_uuid_predicate_is_not_version_restricted() {
        // v1 (time-based) and nil must still route: refusing them silently
        // un-routes live machines.
        assert!(is_instance_uuid("00000001-0000-1000-8000-00805f9b34fb"));
        assert!(is_instance_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
    }

    #[test]
    fn instance_uuid_predicate_rejects_near_misses() {
        let bad = [
            "",                                      // empty
            "not-a-uuid-at-all",                     // not hex
            "alex_host1",                            // normal principal
            "4710fd671d3c4c3e9d356a5c0a9f7d1b",      // 32-hex simple form
            "4710fd67-1d3c-4c3e-9d35-6a5c0a9f7d1b0", // 37 chars
            "4710fd67-1d3c-4c3e-9d35-6a5c0a9f7d1",   // 35 chars
            "4710fd67_1d3c_4c3e_9d35_6a5c0a9f7d1b",  // wrong separators
            "4710FD67-1D3C-4C3E-9D35-6A5C0A9F7D1B",  // uppercase (Principal rejects)
            "4710fd67-1d3c-4c3e-9d35-6a5c0a9f7d1g",  // non-hex digit
            "urn:uuid:4710fd67-1d3c-4c3e-9d35-6a5c0a9f7d1b",
            "{4710fd67-1d3c-4c3e-9d35-6a5c0a9f7d1b}",
        ];
        for bad in bad {
            assert!(!is_instance_uuid(bad), "{bad:?} must NOT route as a UUID");
        }
    }

    #[test]
    fn instance_uuid_predicate_has_no_separator_misreads() {
        // Hyphen counts match but positions are wrong.
        assert!(!is_instance_uuid("-4710fd67-1d3c-4c3e-9d35-6a5c0a9f"));
        // A 36-char string that is all hex but for the dash positions.
        assert!(!is_instance_uuid("4710fd671d3c4-c3e9d35-6a5c0a9f7d1b"));
    }

    #[test]
    fn instance_name_predicate_is_only_a_bound_not_a_grammar() {
        // Real instance names from the lab, plus the shapes the front-leg
        // grammar already admits.
        for good in ["yunqing_dev", "inst-1", "a", "x9y8", "0start", "a_b-c"] {
            assert!(is_instance_name(good), "{good:?} must be name-shaped");
        }
        // The bounds this predicate actually owns.
        assert!(!is_instance_name(""), "empty is never a name");
        assert!(
            !is_instance_name(&"a".repeat(256)),
            "beyond Nova's 255 limit"
        );
        assert!(is_instance_name(&"a".repeat(255)), "exactly 255 is fine");
        assert!(
            !is_instance_name("bad\nname"),
            "no ASCII control characters"
        );
        assert!(!is_instance_name("bad\0name"), "NUL included");
        assert!(!is_instance_name("bad\rname"));
        // Not a grammar: characters the Principal grammar would already have
        // rejected are *this* predicate's business only if they are control
        // characters or the string is empty. A space is not a control char, so
        // the bound accepts it — the front leg is what refuses it, and that
        // is by design (plan-openstack appendix A.1).
        assert!(
            is_instance_name("has space"),
            "a space is not a control char"
        );
    }

    #[test]
    fn resolve_source_default_is_control_plane() {
        assert_eq!(ResolveSource::default(), ResolveSource::ControlPlane);
        assert_eq!(ResolveSource::ControlPlane.as_str(), "control_plane");
        assert_eq!(ResolveSource::OpenStack.as_str(), "openstack");
        assert_eq!(ResolveSource::OpenStack.to_string(), "openstack");
    }
}
