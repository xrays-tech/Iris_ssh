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

use crate::config::{OpenStackRouting, RouteKind};
use crate::error::ResolveError;
use crate::metrics::Metrics;
use crate::resolve::{ResolveResult, Resolver};
use crate::types::{is_instance_name, is_instance_uuid, Principal, ResolveSource};

/// Which resolver a principal is sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveRoute {
    /// The existing external control plane (unchanged behaviour).
    ControlPlane,
    /// OpenStack Nova, keyed by the instance UUID (or, when the name route is
    /// enabled, the instance name) in the username.
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
///
/// `route_by` is the validated `[openstack] route_by` list; its default
/// `["uuid"]` reproduces the pre-name-routing behaviour exactly
/// (plan-openstack appendix A.1). Two rules govern the name route:
///
/// 1. **UUID shape always wins.** A canonical UUID is never considered as a
///    name, so an instance whose name happens to look like an id cannot create
///    ambiguity.
/// 2. **Name is opt-in.** Without `RouteKind::Name` in `route_by`, a
///    non-UUID principal takes the routing mode's ordinary answer
///    (`ControlPlane` in hybrid, `Reject` in `openstack_only`) and no request
///    is ever made.
pub fn route_for(
    principal: &str,
    routing: OpenStackRouting,
    openstack_enabled: bool,
    route_by: &[RouteKind],
) -> ResolveRoute {
    if !openstack_enabled {
        return ResolveRoute::ControlPlane;
    }
    let fallthrough = match routing {
        OpenStackRouting::Hybrid => ResolveRoute::ControlPlane,
        OpenStackRouting::OpenStackOnly => ResolveRoute::Reject,
    };
    if is_instance_uuid(principal) {
        return if route_by.contains(&RouteKind::Uuid) {
            ResolveRoute::OpenStack
        } else {
            fallthrough
        };
    }
    if route_by.contains(&RouteKind::Name) && is_instance_name(principal) {
        return ResolveRoute::OpenStack;
    }
    fallthrough
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
    /// The `[openstack] route_by` default: only the UUID route exists.
    const UUID_ONLY: &[RouteKind] = &[RouteKind::Uuid];
    /// `route_by = ["uuid", "name"]`.
    const BOTH: &[RouteKind] = &[RouteKind::Uuid, RouteKind::Name];
    /// `route_by = ["name"]` (unusual, but legal).
    const NAME_ONLY: &[RouteKind] = &[RouteKind::Name];

    #[test]
    fn disabled_feature_always_routes_to_the_control_plane() {
        // Even a UUID-shaped principal must not move while the feature is off.
        for routing in [OpenStackRouting::Hybrid, OpenStackRouting::OpenStackOnly] {
            for route_by in [UUID_ONLY, BOTH] {
                assert_eq!(
                    route_for(UUID, routing, false, route_by),
                    ResolveRoute::ControlPlane
                );
                assert_eq!(
                    route_for("alex_host1", routing, false, route_by),
                    ResolveRoute::ControlPlane
                );
            }
        }
    }

    #[test]
    fn hybrid_splits_by_shape() {
        assert_eq!(
            route_for(UUID, OpenStackRouting::Hybrid, true, UUID_ONLY),
            ResolveRoute::OpenStack
        );
        assert_eq!(
            route_for("alex_host1", OpenStackRouting::Hybrid, true, UUID_ONLY),
            ResolveRoute::ControlPlane
        );
        // Near-misses stay on the control plane.
        assert_eq!(
            route_for(
                "550e8400-e29b-41d4-a716",
                OpenStackRouting::Hybrid,
                true,
                UUID_ONLY
            ),
            ResolveRoute::ControlPlane
        );
    }

    #[test]
    fn openstack_only_rejects_non_uuids_without_falling_back() {
        assert_eq!(
            route_for(UUID, OpenStackRouting::OpenStackOnly, true, UUID_ONLY),
            ResolveRoute::OpenStack
        );
        for principal in [
            "alex_host1",
            "",
            "550e8400-e29b-41d4-a716-446655440000-extra",
        ] {
            assert_eq!(
                route_for(principal, OpenStackRouting::OpenStackOnly, true, UUID_ONLY),
                ResolveRoute::Reject,
                "{principal:?} must not fall back to the control plane"
            );
        }
    }

    #[test]
    fn the_default_route_by_is_uuid_only_so_names_stay_unrouted() {
        // Red line 1: with the default, a name principal must behave exactly
        // as it did before the name route existed.
        assert_eq!(
            route_for(
                "yunqing_dev",
                OpenStackRouting::OpenStackOnly,
                true,
                UUID_ONLY
            ),
            ResolveRoute::Reject
        );
        assert_eq!(
            route_for("yunqing_dev", OpenStackRouting::Hybrid, true, UUID_ONLY),
            ResolveRoute::ControlPlane
        );
        // Explicit `route_by = ["name"]` alone also routes a UUID nowhere.
        assert_eq!(
            route_for(UUID, OpenStackRouting::OpenStackOnly, true, NAME_ONLY),
            ResolveRoute::Reject
        );
    }

    #[test]
    fn enabling_the_name_route_covers_names_but_never_changes_the_uuid_arm() {
        for routing in [OpenStackRouting::Hybrid, OpenStackRouting::OpenStackOnly] {
            for name in ["yunqing_dev", "inst-1", "a"] {
                assert_eq!(
                    route_for(name, routing, true, BOTH),
                    ResolveRoute::OpenStack,
                    "{name:?} must route to OpenStack when the name route is on"
                );
            }
            // UUID shape still wins and still needs the uuid arm.
            assert_eq!(
                route_for(UUID, routing, true, BOTH),
                ResolveRoute::OpenStack
            );
            assert_eq!(
                route_for(UUID, routing, true, NAME_ONLY),
                match routing {
                    OpenStackRouting::Hybrid => ResolveRoute::ControlPlane,
                    OpenStackRouting::OpenStackOnly => ResolveRoute::Reject,
                },
                "a UUID must never be treated as a name"
            );
            // Nothing else sneaks through: the front-leg grammar would have
            // refused these, but the predicate is the second gate.
            assert_eq!(
                route_for("", routing, true, BOTH),
                match routing {
                    OpenStackRouting::Hybrid => ResolveRoute::ControlPlane,
                    OpenStackRouting::OpenStackOnly => ResolveRoute::Reject,
                }
            );
            assert_eq!(
                route_for("bad\nname", routing, true, BOTH),
                match routing {
                    OpenStackRouting::Hybrid => ResolveRoute::ControlPlane,
                    OpenStackRouting::OpenStackOnly => ResolveRoute::Reject,
                },
                "control characters are never a name"
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
    /// `[openstack] route_by`: which principal shapes the OpenStack route
    /// accepts (default `["uuid"]`, plan-openstack appendix A.1).
    route_by: Vec<RouteKind>,
    control_plane: Option<Arc<Resolver>>,
    openstack: Option<Arc<Resolver>>,
    metrics: Metrics,
}

impl ResolveRouter {
    /// Assemble the router. `control_plane` is `None` only in OpenStack pure
    /// mode, `openstack` only when `[openstack]` is absent or disabled.
    ///
    /// `route_by` is the validated `[openstack] route_by`; the gateway passes
    /// the configured list (which defaults to `["uuid"]`), tests may pass
    /// whatever they are asserting.
    pub fn new(
        routing: OpenStackRouting,
        openstack_enabled: bool,
        route_by: Vec<RouteKind>,
        control_plane: Option<Arc<Resolver>>,
        openstack: Option<Arc<Resolver>>,
        metrics: Metrics,
    ) -> Self {
        ResolveRouter {
            routing,
            openstack_enabled,
            route_by,
            control_plane,
            openstack,
            metrics,
        }
    }

    /// The route `principal` would take. Pure: no I/O, safe to call from the
    /// pre-authentication `auth_publickey_offered` probe (MUST: that phase
    /// must never reach the network).
    pub fn route(&self, principal: &str) -> ResolveRoute {
        route_for(
            principal,
            self.routing,
            self.openstack_enabled,
            &self.route_by,
        )
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
                    let routes: Vec<&str> = self.route_by.iter().map(|k| k.as_str()).collect();
                    format!(
                        "openstack_only routing accepts {} principals only",
                        routes.join("/")
                    )
                } else {
                    "no route configured for this principal".to_owned()
                },
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
                if source == ResolveSource::OpenStack {
                    // Appendix A.4: which principal shape the OpenStack route
                    // actually served, so the name route's hit rate is visible
                    // without touching the audit record's format.
                    if is_instance_uuid(principal.as_str()) {
                        self.metrics.openstack_resolve_by_uuid();
                    } else {
                        self.metrics.openstack_resolve_by_name();
                    }
                }
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
        // Every existing router test asserts the UUID route; the name route
        // gets its own test with its own router.
        ResolveRouter::new(
            routing,
            enabled,
            vec![RouteKind::Uuid],
            cp,
            os,
            Metrics::default(),
        )
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
    async fn a_name_resolves_through_openstack_only_when_the_name_route_is_on() {
        // Appendix A.1: the name route is opt-in, and opting in must not
        // change the UUID arm or the control-plane arm.
        let (os, os_calls) = resolver(CountingClient::new(true), 5);
        let (cp, cp_calls) = resolver(CountingClient::new(true), 5);
        let metrics = Metrics::default();
        let both = ResolveRouter::new(
            OpenStackRouting::OpenStackOnly,
            true,
            vec![RouteKind::Uuid, RouteKind::Name],
            Some(cp),
            Some(os),
            metrics.clone(),
        );

        let grant = both
            .authorize(
                &Principal::parse("yunqing_dev").unwrap(),
                "SHA256:fp",
                "127.0.0.1",
            )
            .await
            .expect("a name resolves when the route is enabled");
        assert_eq!(grant.resolve_source, ResolveSource::OpenStack);
        assert_eq!(os_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cp_calls.load(Ordering::SeqCst), 0);

        // Appendix A.4: the by-route counters expose which arm served the
        // lookup, without touching AuditRecord's shape.
        let text = metrics.render_prometheus();
        assert!(
            text.contains("sshgw_openstack_resolve_by_name_total 1"),
            "exactly the name arm fired:\n{text}"
        );
        assert!(
            text.contains("sshgw_openstack_resolve_by_uuid_total 0"),
            "the uuid arm did not:\n{text}"
        );

        // The default router (uuid only) refuses the same name with zero
        // upstream traffic — MUST1 holds for names too.
        let (os2, os2_calls) = resolver(CountingClient::new(true), 5);
        let (cp2, cp2_calls) = resolver(CountingClient::new(true), 5);
        let uuid_only = router(OpenStackRouting::OpenStackOnly, true, Some(cp2), Some(os2));
        let err = uuid_only
            .authorize(
                &Principal::parse("yunqing_dev").unwrap(),
                "SHA256:fp",
                "127.0.0.1",
            )
            .await
            .expect_err("name routing is off by default");
        assert!(matches!(err, ResolveError::Unrouted { .. }));
        assert_eq!(os2_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cp2_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_uuid_resolves_through_openstack_and_is_stamped() {
        let (os, os_calls) = resolver(CountingClient::new(true), 5);
        let (cp, cp_calls) = resolver(CountingClient::new(true), 5);
        let metrics = Metrics::default();
        let router = ResolveRouter::new(
            OpenStackRouting::OpenStackOnly,
            true,
            vec![RouteKind::Uuid, RouteKind::Name],
            Some(cp),
            Some(os),
            metrics.clone(),
        );

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

        // UUID shape still takes the uuid arm even with the name route on.
        let text = metrics.render_prometheus();
        assert!(
            text.contains("sshgw_openstack_resolve_by_uuid_total 1"),
            "the uuid arm fired:\n{text}"
        );
        assert!(
            text.contains("sshgw_openstack_resolve_by_name_total 0"),
            "a UUID is never treated as a name:\n{text}"
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
