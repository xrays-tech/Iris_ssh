//! Principal → resolver routing (plan-openstack §3.1 / F2).
//!
//! The route is decided by a **pure function on the principal's shape**: a
//! canonical instance UUID goes to OpenStack, anything else to the control
//! plane (or nowhere, in pure mode). Nothing here performs I/O, so the whole
//! decision table is unit-testable without a network or a config file.
//!
//! `ResolveRouter` — the stateful wrapper that actually dispatches and
//! authorizes — lives here too, assembled from the two independent `Resolver`s
//! so a dead OpenStack can never open the control plane's circuit breaker
//! (plan-openstack §0-3, failure-domain isolation).

use crate::config::OpenStackRouting;
use crate::types::is_instance_uuid;

/// Which resolver a principal is sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveRoute {
    /// The existing external control plane (unchanged behaviour).
    ControlPlane,
    /// OpenStack Nova, keyed by the instance UUID in the username.
    OpenStack,
    /// No route at all: reject before any network call is made.
    Reject,
}

/// Decide where `principal` resolves.
///
/// `openstack_enabled` is `false` whenever the `[openstack]` section is absent
/// or `enabled = false`; in that case the answer is *always* the control plane,
/// which is how "default off" stays byte-for-byte compatible with the previous
/// behaviour (plan-openstack §5.2 red line 8).
pub fn route_for(
    principal: &str,
    routing: OpenStackRouting,
    openstack_enabled: bool,
) -> ResolveRoute {
    if !openstack_enabled {
        return ResolveRoute::ControlPlane;
    }
    let is_uuid = is_instance_uuid(principal);
    match routing {
        OpenStackRouting::Hybrid => {
            if is_uuid {
                ResolveRoute::OpenStack
            } else {
                ResolveRoute::ControlPlane
            }
        }
        OpenStackRouting::OpenStackOnly => {
            if is_uuid {
                ResolveRoute::OpenStack
            } else {
                ResolveRoute::Reject
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn disabled_feature_always_routes_to_the_control_plane() {
        // Even a UUID-shaped principal must not move while the feature is off.
        for routing in [OpenStackRouting::Hybrid, OpenStackRouting::OpenStackOnly] {
            assert_eq!(route_for(UUID, routing, false), ResolveRoute::ControlPlane);
            assert_eq!(
                route_for("alex_host1", routing, false),
                ResolveRoute::ControlPlane
            );
        }
    }

    #[test]
    fn hybrid_splits_by_shape() {
        assert_eq!(
            route_for(UUID, OpenStackRouting::Hybrid, true),
            ResolveRoute::OpenStack
        );
        assert_eq!(
            route_for("alex_host1", OpenStackRouting::Hybrid, true),
            ResolveRoute::ControlPlane
        );
        // Near-misses stay on the control plane.
        assert_eq!(
            route_for("550e8400-e29b-41d4-a716", OpenStackRouting::Hybrid, true),
            ResolveRoute::ControlPlane
        );
    }

    #[test]
    fn openstack_only_rejects_non_uuids_without_falling_back() {
        assert_eq!(
            route_for(UUID, OpenStackRouting::OpenStackOnly, true),
            ResolveRoute::OpenStack
        );
        for principal in [
            "alex_host1",
            "",
            "550e8400-e29b-41d4-a716-446655440000-extra",
        ] {
            assert_eq!(
                route_for(principal, OpenStackRouting::OpenStackOnly, true),
                ResolveRoute::Reject,
                "{principal:?} must not fall back to the control plane"
            );
        }
    }
}
