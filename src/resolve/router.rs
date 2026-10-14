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

use std::sync::Arc;
use std::time::Instant;

use crate::config::OpenStackRouting;
use crate::error::ResolveError;
use crate::metrics::Metrics;
use crate::resolve::{ResolveResult, Resolver};
use crate::types::{is_instance_uuid, Principal, ResolveSource};

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

// --------------------------------------------------------------------------
// ResolveRouter: the stateful dispatcher (plan-openstack §3.1).
// --------------------------------------------------------------------------

/// The per-gateway dispatcher: it picks a route with [`route_for`] (a pure
/// function on the principal's shape), forwards to **that source's own**
/// [`Resolver`], and stamps the resulting [`crate::types::Grant`] with the
/// source that produced it.
///
/// The two resolvers are deliberately *separate objects*: each owns its own
/// cache, single-flight coalescing and circuit breaker, so an OpenStack outage
/// can never open the control plane's breaker (or the reverse). That is the
/// failure-domain isolation plan-openstack §0-3 requires, and it is asserted
/// in `a_tripped_openstack_breaker_leaves_the_control_plane_alone`.
pub struct ResolveRouter {
    routing: OpenStackRouting,
    openstack_enabled: bool,
    control_plane: Option<Arc<Resolver>>,
    openstack: Option<Arc<Resolver>>,
    metrics: Metrics,
}

impl ResolveRouter {
    /// Assemble the router. `control_plane` is `None` only in OpenStack pure
    /// mode, `openstack` only when `[openstack]` is absent or disabled.
    pub fn new(
        routing: OpenStackRouting,
        openstack_enabled: bool,
        control_plane: Option<Arc<Resolver>>,
        openstack: Option<Arc<Resolver>>,
        metrics: Metrics,
    ) -> Self {
        ResolveRouter {
            routing,
            openstack_enabled,
            control_plane,
            openstack,
            metrics,
        }
    }

    /// The route `principal` would take. Pure: no I/O, safe to call from the
    /// pre-authentication `auth_publickey_offered` probe (MUST: that phase
    /// must never reach the network).
    pub fn route(&self, principal: &str) -> ResolveRoute {
        route_for(principal, self.routing, self.openstack_enabled)
    }

    /// Whether `route` can be served by the resolvers actually configured.
    ///
    /// The configuration layer already rejects every impossible combination;
    /// this is the belt-and-braces check at the only place that could otherwise
    /// panic (a route pointing at a resolver that was never built).
    pub fn can_serve(&self, route: ResolveRoute) -> bool {
        match route {
            ResolveRoute::ControlPlane => self.control_plane.is_some(),
            ResolveRoute::OpenStack | ResolveRoute::Reject => {
                // `Reject` is served *by* refusing: it needs no upstream at all.
                route == ResolveRoute::Reject || self.openstack.is_some()
            }
        }
    }

    /// Resolve + authorize, then stamp `grant.resolve_source`.
    ///
    /// Every upstream failure stays uniform for the client (the caller maps any
    /// error to a protocol-native `Auth::reject()`); detail goes to the
    /// `resolve` tracing target with `source=` and `reason=` so an operator can
    /// still tell the two apart (plan-openstack §3.7).
    pub async fn authorize(
        &self,
        principal: &Principal,
        fingerprint: &str,
        client_ip: &str,
    ) -> ResolveResult {
        let route = self.route(principal.as_str());
        let source = match route {
            // A refused principal in `openstack_only` mode is the OpenStack
            // route declining: it belongs to that source's counters and logs.
            ResolveRoute::OpenStack | ResolveRoute::Reject => ResolveSource::OpenStack,
            ResolveRoute::ControlPlane => ResolveSource::ControlPlane,
        };
        let started = Instant::now();

        let outcome = match route {
            ResolveRoute::ControlPlane => match &self.control_plane {
                Some(resolver) => resolver.authorize(principal, fingerprint, client_ip).await,
                None => Err(ResolveError::Unavailable {
                    principal: principal.as_str().to_owned(),
                }),
            },
            ResolveRoute::OpenStack => match &self.openstack {
                Some(resolver) => resolver.authorize(principal, fingerprint, client_ip).await,
                None => Err(ResolveError::Unavailable {
                    principal: principal.as_str().to_owned(),
                }),
            },
            ResolveRoute::Reject => Err(ResolveError::Unrouted {
                principal: principal.as_str().to_owned(),
                reason: if self.openstack_enabled {
                    "openstack_only routing accepts canonical instance UUIDs only"
                } else {
                    "no route configured for this principal"
                }
                .to_owned(),
            }),
        };

        if source == ResolveSource::OpenStack {
            self.metrics.openstack_resolve_latency(started.elapsed());
            match &outcome {
                Ok(_) => self.metrics.openstack_resolve_ok(),
                Err(err) => {
                    self.metrics.openstack_resolve_err();
                    // Pre-auth resolve failures have no session, hence no
                    // AuditRecord; this structured line is where they live.
                    tracing::warn!(
                        target: "resolve",
                        %principal,
                        %client_ip,
                        source = source.as_str(),
                        reason = reason_of(err),
                        error = %err,
                        "openstack resolve failed before authentication completed"
                    );
                }
            }
        }

        match outcome {
            Ok(mut grant) => {
                // The router is the only component that knows which resolver
                // answered, so the stamp happens here and only here.
                grant.resolve_source = source;
                Ok(grant)
            }
            Err(err) => Err(err),
        }
    }
}

/// A stable, low-cardinality reason token for a [`ResolveError`].
///
/// Deliberately separate from `ResolveError`'s `Display`: the client-facing
/// wording must not change (plan-openstack red line), while logs and dashboards
/// key on these short tokens.
fn reason_of(err: &ResolveError) -> &'static str {
    match err {
        ResolveError::InvalidPrincipal { .. } => "invalid_principal",
        ResolveError::NotFound { .. } => "not_found",
        ResolveError::Forbidden { .. } => "forbidden",
        ResolveError::RateLimited { .. } => "rate_limited",
        ResolveError::Unavailable { .. } => "unavailable",
        ResolveError::CircuitOpen { .. } => "circuit_open",
        ResolveError::Unrouted { .. } => "unrouted",
    }
}

#[cfg(test)]
mod router_dispatch_tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use crate::resolve::{ControlError, ControlPlaneClient, ResolveRequest, ResolveResponse};
    use crate::types::{Policy, Target};

    use super::*;

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// A control-plane client that counts its calls and can be told to fail.
    struct CountingClient {
        calls: Arc<AtomicU64>,
        healthy: bool,
    }

    impl CountingClient {
        fn new(healthy: bool) -> (Self, Arc<AtomicU64>) {
            let calls = Arc::new(AtomicU64::new(0));
            (
                CountingClient {
                    calls: Arc::clone(&calls),
                    healthy,
                },
                calls,
            )
        }
    }

    impl ControlPlaneClient for CountingClient {
        fn resolve<'a>(
            &'a self,
            _req: &'a ResolveRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ResolveResponse, ControlError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.healthy {
                    Ok(ResolveResponse {
                        target: Target {
                            host: "10.0.0.7".into(),
                            port: 22,
                            user: "alice".into(),
                        },
                        policy: Policy {
                            agent_forwarding: true,
                            ..Policy::default()
                        },
                    })
                } else {
                    Err(ControlError::Transport)
                }
            })
        }
    }

    fn resolver(
        client: (CountingClient, Arc<AtomicU64>),
        threshold: u32,
    ) -> (Arc<Resolver>, Arc<AtomicU64>) {
        let (client, calls) = client;
        (
            Arc::new(Resolver::new(
                Arc::new(client),
                Duration::from_secs(30),
                Duration::from_secs(5),
                Duration::from_secs(1),
                Duration::from_secs(1),
                false, // fail-closed
                threshold,
                Duration::from_secs(60),
                Duration::from_secs(3),
            )),
            calls,
        )
    }

    fn router(
        routing: OpenStackRouting,
        enabled: bool,
        cp: Option<Arc<Resolver>>,
        os: Option<Arc<Resolver>>,
    ) -> ResolveRouter {
        ResolveRouter::new(routing, enabled, cp, os, Metrics::default())
    }

    #[tokio::test]
    async fn a_refused_principal_reaches_no_upstream_at_all() {
        // MUST1 in router form: the `Reject` answer is produced before any
        // resolver — and therefore before any socket — is touched.
        let (os, os_calls) = resolver(CountingClient::new(true), 5);
        let (cp, cp_calls) = resolver(CountingClient::new(true), 5);
        let router = router(OpenStackRouting::OpenStackOnly, true, Some(cp), Some(os));

        let err = router
            .authorize(
                &Principal::parse("alex_host1").unwrap(),
                "SHA256:fp",
                "127.0.0.1",
            )
            .await
            .expect_err("non-UUID must not resolve in openstack_only mode");

        assert!(matches!(err, ResolveError::Unrouted { .. }));
        assert_eq!(os_calls.load(Ordering::SeqCst), 0, "OpenStack untouched");
        assert_eq!(
            cp_calls.load(Ordering::SeqCst),
            0,
            "control plane untouched"
        );
    }

    #[tokio::test]
    async fn a_uuid_resolves_through_openstack_and_is_stamped() {
        let (os, os_calls) = resolver(CountingClient::new(true), 5);
        let (cp, cp_calls) = resolver(CountingClient::new(true), 5);
        let router = router(OpenStackRouting::OpenStackOnly, true, Some(cp), Some(os));

        let grant = router
            .authorize(&Principal::parse(UUID).unwrap(), "SHA256:fp", "127.0.0.1")
            .await
            .expect("resolves");

        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(grant.resolve_source, ResolveSource::OpenStack);
        assert!(
            grant.policy.agent_forwarding,
            "synthesized for the agent leg"
        );
        assert_eq!(os_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            cp_calls.load(Ordering::SeqCst),
            0,
            "the control plane must not see OpenStack traffic"
        );
    }

    #[tokio::test]
    async fn a_tripped_openstack_breaker_leaves_the_control_plane_alone() {
        // Failure-domain isolation (plan-openstack §0-3): one breaker per
        // source. Threshold 1 => the very first Nova failure opens the
        // OpenStack breaker, while the control-plane route keeps working with
        // its own cache and its own breaker.
        let (broken_os, os_calls) = resolver(CountingClient::new(false), 1);
        let (cp, cp_calls) = resolver(CountingClient::new(true), 1);
        let router = router(OpenStackRouting::Hybrid, true, Some(cp), Some(broken_os));

        for _ in 0..3 {
            let err = router
                .authorize(&Principal::parse(UUID).unwrap(), "SHA256:fp", "127.0.0.1")
                .await
                .expect_err("Nova is down and the policy is fail-closed");
            assert!(matches!(err, ResolveError::Unavailable { .. }), "{err:?}");
        }
        // Only the first attempt reached Nova; the open breaker fast-fails the
        // rest, and none of that leaked into the other resolver.
        assert_eq!(os_calls.load(Ordering::SeqCst), 1);

        let grant = router
            .authorize(
                &Principal::parse("alex_host1").unwrap(),
                "SHA256:fp",
                "127.0.0.1",
            )
            .await
            .expect("the control-plane route still resolves");
        assert_eq!(grant.resolve_source, ResolveSource::ControlPlane);
        assert_eq!(cp_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hybrid_sends_each_principal_to_its_own_resolver() {
        let (os, os_calls) = resolver(CountingClient::new(true), 5);
        let (cp, cp_calls) = resolver(CountingClient::new(true), 5);
        let router = router(OpenStackRouting::Hybrid, true, Some(cp), Some(os));

        let via_cp = router
            .authorize(
                &Principal::parse("alex_host1").unwrap(),
                "SHA256:fp",
                "127.0.0.1",
            )
            .await
            .expect("control plane route");
        assert_eq!(via_cp.resolve_source, ResolveSource::ControlPlane);
        assert_eq!(via_cp.target.host, "10.0.0.7");

        let via_os = router
            .authorize(&Principal::parse(UUID).unwrap(), "SHA256:fp", "127.0.0.1")
            .await
            .expect("openstack route");
        assert_eq!(via_os.resolve_source, ResolveSource::OpenStack);

        assert_eq!(cp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(os_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn can_serve_reflects_the_resolvers_that_were_built() {
        let (cp, _) = resolver(CountingClient::new(true), 5);
        let pure = router(OpenStackRouting::OpenStackOnly, true, None, None);
        assert!(!pure.can_serve(ResolveRoute::OpenStack));
        assert!(pure.can_serve(ResolveRoute::Reject), "refusing is free");

        let hybrid = router(OpenStackRouting::Hybrid, true, Some(cp), None);
        assert!(hybrid.can_serve(ResolveRoute::ControlPlane));
        assert!(!hybrid.can_serve(ResolveRoute::OpenStack));
    }
}
