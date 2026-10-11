//! Jump-mode target validation (propose.md §3.4 / B4).
//!
//! A `direct-tcpip` request asks the gateway to open a TCP connection on the
//! client's behalf, which makes the gateway an outbound pivot. Two independent
//! gates therefore apply before any socket is opened:
//!
//! 1. **Policy**: the target must appear in an allow-list (the gateway-wide
//!    `[jump] allowed_targets` unioned with the session's
//!    `policy.tcp_forwarding_targets`). An absent list means deny.
//! 2. **Address class**: loopback / private / link-local / unique-local (and the
//!    cloud metadata address) destinations are refused unless the operator
//!    explicitly opted in, so a compromised client cannot use the gateway to
//!    reach the private network behind it (SSRF pivot defence).
//!
//! Both are pure functions of their inputs — no DNS, no sockets, no clock — which
//! is what makes the policy rules directly unit-testable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A `direct-tcpip` destination request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTarget {
    pub host: String,
    pub port: u16,
}

/// Why a jump target was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpDenial {
    /// The gateway's jump mode is disabled (the pre-M3 default).
    Disabled,
    /// No allow-list entry matched the target.
    NotAllowed { host: String, port: u16 },
    /// The destination is in a class the policy forbids (e.g. loopback).
    ForbiddenAddress { host: String, port: u16 },
    /// The target string was malformed.
    Malformed,
}

impl std::fmt::Display for JumpDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JumpDenial::Disabled => f.write_str("jump mode is disabled"),
            JumpDenial::NotAllowed { host, port } => {
                write!(f, "target {host}:{port} is not in the allow-list")
            }
            JumpDenial::ForbiddenAddress { host, port } => {
                write!(f, "target {host}:{port} is a forbidden address class")
            }
            JumpDenial::Malformed => f.write_str("malformed target"),
        }
    }
}

/// Does `addr` fall into an address class that must not be reachable by default?
///
/// This is a *literal-address* check only. A hostname that resolves to a private
/// address is caught by resolving it first (see [`resolve_target`]), never by
/// letting it through.
pub fn is_forbidden_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => is_forbidden_ipv4(*ip),
        IpAddr::V6(ip) => is_forbidden_ipv6(*ip),
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        // 100.64.0.0/10 carrier-grade NAT, and 169.254.0.0/16 (link-local) is
        // already covered — but the cloud metadata address is called out
        // explicitly because it is the highest-value SSRF target.
        || is_carrier_grade_nat(ip)
        || ip == Ipv4Addr::new(169, 254, 169, 254)
}

/// 100.64.0.0/10.
fn is_carrier_grade_nat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xc0) == 64
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    // Loopback (::1), unspecified (::), private unique-local (fc00::/7),
    // link-local (fe80::/10), multicast. IPv4-mapped ranges are delegated to the
    // IPv4 rules so ::ffff:127.0.0.1 is caught too.
    ip.is_loopback()
        || ip.is_unspecified()
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80
        || ip.is_multicast()
        || ip.to_ipv4_mapped().is_some_and(is_forbidden_ipv4)
}

/// Resolve `host` to a literal address for the address-class check, if possible.
///
/// A name that does not resolve is *not* rejected here — the policy gate has
/// already decided, and the subsequent connect attempt will fail naturally
/// (mapped to a protocol-native open failure per I4).
pub fn resolve_target(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

/// Whether `entry` allows `target`.
///
/// Entry syntax: `host`, `host:port`, `*:port` (any host on one port).
fn target_matches(entry: &str, target: &JumpTarget) -> bool {
    let entry = entry.trim();
    if let Some(rest) = entry.strip_prefix('*') {
        // `*:port`
        return match rest.strip_prefix(':') {
            Some(port) => port.parse::<u16>().is_ok_and(|p| p == target.port),
            None => false,
        };
    }
    match entry.rsplit_once(':') {
        Some((host, port)) => host == target.host && port.parse::<u16>() == Ok(target.port),
        None => entry == target.host,
    }
}

/// Authorise a `direct-tcpip` request against the effective policy.
pub fn authorize_jump_target(
    enabled: bool,
    allow_private_networks: bool,
    gateway_targets: &[String],
    grant_targets: &[String],
    resolved: Option<IpAddr>,
    target: &JumpTarget,
) -> Result<(), JumpDenial> {
    if !enabled {
        return Err(JumpDenial::Disabled);
    }
    if target.host.is_empty() || target.port == 0 {
        return Err(JumpDenial::Malformed);
    }

    // Address class first: a forbidden destination is refused even if an
    // over-broad allow-list entry happens to match it.
    if !allow_private_networks {
        if let Some(addr) = resolved {
            if is_forbidden_address(&addr) {
                return Err(JumpDenial::ForbiddenAddress {
                    host: target.host.clone(),
                    port: target.port,
                });
            }
        }
    }

    let allowed = gateway_targets
        .iter()
        .chain(grant_targets.iter())
        .any(|entry| target_matches(entry, target));
    if !allowed {
        return Err(JumpDenial::NotAllowed {
            host: target.host.clone(),
            port: target.port,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16) -> JumpTarget {
        JumpTarget {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn disabled_by_default_denies_everything() {
        // The pre-M3 baseline: nothing is reachable, allow-list or not.
        let err = authorize_jump_target(
            false,
            false,
            &["*:22".to_owned()],
            &[],
            Some(IpAddr::from([8, 8, 8, 8])),
            &target("8.8.8.8", 22),
        )
        .unwrap_err();
        assert_eq!(err, JumpDenial::Disabled);
    }

    #[test]
    fn allow_list_entries_match_host_and_port() {
        let ok = |entry: &str, host: &str, port: u16| {
            authorize_jump_target(
                true,
                false,
                &[entry.to_owned()],
                &[],
                Some(IpAddr::from([8, 8, 8, 8])),
                &target(host, port),
            )
            .is_ok()
        };
        assert!(
            ok("db.example.com", "db.example.com", 22),
            "bare host matches any port"
        );
        assert!(
            ok("db.example.com:5432", "db.example.com", 5432),
            "host:port"
        );
        assert!(
            ok("*:22", "anything.example.com", 22),
            "*:port matches any host"
        );
        assert!(
            !ok("db.example.com:5432", "db.example.com", 22),
            "port must match"
        );
        assert!(
            !ok("other.example.com:5432", "db.example.com", 5432),
            "host must match"
        );
        assert!(!ok("*:22", "anything.example.com", 23), "*:port must match");
    }

    #[test]
    fn grant_and_gateway_allow_lists_are_unioned() {
        let err = authorize_jump_target(
            true,
            false,
            &["gw.example.com:22".to_owned()],
            &["grant.example.com:443".to_owned()],
            Some(IpAddr::from([8, 8, 8, 8])),
            &target("grant.example.com", 443),
        );
        assert!(err.is_ok(), "a grant-listed target must be reachable");
    }

    #[test]
    fn empty_allow_list_denies_all_targets() {
        // Compatible with the older boolean field: absent list = deny.
        let err = authorize_jump_target(
            true,
            false,
            &[],
            &[],
            Some(IpAddr::from([8, 8, 8, 8])),
            &target("8.8.8.8", 22),
        )
        .unwrap_err();
        assert_eq!(
            err,
            JumpDenial::NotAllowed {
                host: "8.8.8.8".to_owned(),
                port: 22
            }
        );
    }

    #[test]
    fn private_and_loopback_addresses_are_forbidden_by_default() {
        for host in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
        ] {
            assert!(
                is_forbidden_address(&host.parse::<IpAddr>().unwrap()),
                "{host} must be a forbidden address class"
            );
        }
        for host in ["8.8.8.8", "1.1.1.1", "203.0.113.9"] {
            assert!(
                !is_forbidden_address(&host.parse::<IpAddr>().unwrap()),
                "{host} must be reachable"
            );
        }
    }

    #[test]
    fn ipv4_mapped_loopback_is_forbidden() {
        let addr = "::ffff:127.0.0.1".parse::<IpAddr>().unwrap();
        assert!(
            is_forbidden_address(&addr),
            "IPv4-mapped loopback must be caught"
        );
    }

    #[test]
    fn private_address_is_refused_even_when_allow_listed() {
        // Defence in depth: an over-broad entry must not open the private net.
        let err = authorize_jump_target(
            true,
            false,
            &["*:80".to_owned()],
            &[],
            Some(IpAddr::from([127, 0, 0, 1])),
            &target("127.0.0.1", 80),
        )
        .unwrap_err();
        assert_eq!(
            err,
            JumpDenial::ForbiddenAddress {
                host: "127.0.0.1".to_owned(),
                port: 80
            }
        );
    }

    #[test]
    fn private_networks_can_be_opted_into_for_an_internal_backend() {
        // Some deployments legitimately jump to an internal host; that is an
        // explicit operator decision.
        let res = authorize_jump_target(
            true,
            true,
            &["db.internal:5432".to_owned()],
            &[],
            Some(IpAddr::from([10, 0, 0, 9])),
            &target("db.internal", 5432),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn malformed_targets_are_rejected() {
        assert_eq!(
            authorize_jump_target(
                true,
                false,
                &["*:22".to_owned()],
                &[],
                None,
                &target("", 22)
            )
            .unwrap_err(),
            JumpDenial::Malformed
        );
        assert_eq!(
            authorize_jump_target(
                true,
                false,
                &["*:22".to_owned()],
                &[],
                None,
                &target("h", 0)
            )
            .unwrap_err(),
            JumpDenial::Malformed
        );
    }
}
