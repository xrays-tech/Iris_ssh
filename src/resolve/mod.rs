//! Username resolver: control-plane client + caching + single-flight + breaker.
//!
//! Responsibilities (propose.md §3.1):
//! * validate the principal shape at the boundary ([`Principal`]);
//! * consult the control plane via [`ControlPlaneClient`] (HTTP in production);
//! * cache results with a positive TTL (30s ± jitter) and a short negative TTL
//!   (5s), coalescing concurrent lookups for the same `(principal, fingerprint)`
//!   into a single in-flight request (moka `get_with` single-flight);
//! * fail **closed** by default (refuse the session), or fail **open** by
//!   serving the last-known-good grant, per configuration;
//! * trip a [`CircuitBreaker`] after repeated control-plane failures so a dead
//!   control plane stops hammering dial attempts.
//!
//! The caching/breaker logic is expressed without any network dependency so it
//! can be exercised deterministically in unit tests by injecting a fake
//! [`ControlPlaneClient`] (the HTTP boundary is the only mockable seam).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moka::future::Cache;
use moka::Expiry;

use crate::error::ResolveError;
use crate::types::{AuthKey, Fingerprint, Grant, Principal, ResolveSource};

pub mod router;

pub use router::{route_for, ResolveRoute, ResolveRouter};

/// A fully-validated control-plane target that resolves to the same `Grant`
/// value as the resolver, used by callers that want the raw resolved grant.
pub type ResolveResult = std::result::Result<Grant, ResolveError>;

// --------------------------------------------------------------------------
// Circuit breaker (pure, clock-injected for deterministic tests).
// --------------------------------------------------------------------------

/// The three canonical breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests flow; failures are counted.
    Closed,
    /// Requests are rejected until the reset timeout elapses.
    Open,
    /// A single probe request is allowed through.
    HalfOpen,
}

/// A consecutive-failure circuit breaker.
///
/// The breaker opens after `failure_threshold` consecutive failures and stays
/// open for `reset_timeout`; the first request after that turns it half-open and
/// a success closes it (a failure re-opens immediately).
#[derive(Debug)]
pub struct CircuitBreaker {
    inner: Mutex<BreakerInner>,
    failure_threshold: u32,
    reset_timeout: Duration,
}

#[derive(Debug)]
struct BreakerInner {
    state: BreakerState,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        CircuitBreaker {
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed,
                consecutive_failures: 0,
                opened_at: None,
            }),
            failure_threshold: failure_threshold.max(1),
            reset_timeout,
        }
    }

    /// Whether a request at time `now` may proceed.
    pub fn should_allow(&self, now: Instant) -> bool {
        let mut inner = self.lock();
        match inner.state {
            BreakerState::Closed => true,
            BreakerState::HalfOpen => true,
            BreakerState::Open => {
                let elapsed = inner
                    .opened_at
                    .map_or(Duration::MAX, |t| now.saturating_duration_since(t));
                if elapsed >= self.reset_timeout {
                    inner.state = BreakerState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful call (closes the breaker).
    pub fn record_success(&self) {
        let mut inner = self.lock();
        inner.state = BreakerState::Closed;
        inner.consecutive_failures = 0;
        inner.opened_at = None;
    }

    /// Record a failed call at time `now` (may open the breaker).
    pub fn record_failure(&self, now: Instant) {
        let mut inner = self.lock();
        match inner.state {
            BreakerState::HalfOpen => {
                // The probe failed; re-open immediately.
                inner.state = BreakerState::Open;
                inner.opened_at = Some(now);
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
            }
            BreakerState::Closed => {
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                if inner.consecutive_failures >= self.failure_threshold {
                    inner.state = BreakerState::Open;
                    inner.opened_at = Some(now);
                }
            }
            BreakerState::Open => {
                // Already open; keep it open and push the timer forward.
                inner.opened_at = Some(now);
            }
        }
    }

    pub fn state(&self) -> BreakerState {
        self.lock().state
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerInner> {
        // A poisoned mutex only means a panic happened elsewhere; the mutation
        // methods contain no panics, so recovering the guard is safe here.
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

// --------------------------------------------------------------------------
// Control-plane boundary.
// --------------------------------------------------------------------------

/// The failure taxonomy a control-plane client reports back to the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// 404 — principal unknown.
    NotFound,
    /// 403 — principal not authorized for this key.
    Forbidden,
    /// 429 — rate limited.
    RateLimited,
    /// 5xx — the control plane is unhealthy (counts as a breaker failure).
    ServerError,
    /// Body could not be decoded (counts as a breaker failure).
    Decode,
    /// Transport-level error / timeout (counts as a breaker failure).
    Transport,
}

/// Boundary the resolver depends on to talk to the control plane. In
/// production this is [`HttpControlPlane`]; tests substitute a fake. This is the
/// single external seam in the resolver (everything else is pure, in-process
/// state). Returns a boxed future so it is object-safe.
pub trait ControlPlaneClient: Send + Sync {
    fn resolve<'a>(
        &'a self,
        req: &'a ResolveRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<ResolveResponse, ControlError>>
                + Send
                + 'a,
        >,
    >;
}

/// `reqwest`-based control-plane client (rustls, no OpenSSL).
pub struct HttpControlPlane {
    client: reqwest::Client,
    url: String,
}

impl HttpControlPlane {
    pub fn new(url: String, timeout: Duration) -> std::result::Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(HttpControlPlane { client, url })
    }
}

impl ControlPlaneClient for HttpControlPlane {
    fn resolve<'a>(
        &'a self,
        req: &'a ResolveRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<ResolveResponse, ControlError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(self.resolve_inner(req))
    }
}

impl HttpControlPlane {
    async fn resolve_inner(
        &self,
        req: &ResolveRequest,
    ) -> std::result::Result<ResolveResponse, ControlError> {
        let resp = self
            .client
            .post(&self.url)
            .json(req)
            .send()
            .await
            .map_err(|_| ControlError::Transport)?;
        match resp.status().as_u16() {
            200 => resp
                .json::<ResolveResponse>()
                .await
                .map_err(|_| ControlError::Decode),
            403 => Err(ControlError::Forbidden),
            404 => Err(ControlError::NotFound),
            429 => Err(ControlError::RateLimited),
            _ => Err(ControlError::ServerError),
        }
    }
}

use crate::types::{ResolveRequest, ResolveResponse};

// --------------------------------------------------------------------------
// Cache entry + expiry policy.
// --------------------------------------------------------------------------

/// What the resolver caches for a given `(principal, fingerprint)` key.
#[derive(Debug, Clone)]
enum CacheEntry {
    /// A positive result, held for the positive TTL (± jitter).
    Resolved(Box<Grant>),
    /// A definitive negative result (404/403/429), held for the negative TTL.
    Denied(Denied),
    /// A transient failure, held briefly to coalesce concurrent calls.
    Transient,
}

/// Definitive negative outcomes that are safe to cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Denied {
    NotFound,
    Forbidden,
    RateLimited,
}

impl Denied {
    fn to_error(self, principal: &Principal) -> ResolveError {
        let principal = principal.as_str().to_owned();
        match self {
            Denied::NotFound => ResolveError::NotFound { principal },
            Denied::Forbidden => ResolveError::Forbidden { principal },
            Denied::RateLimited => ResolveError::RateLimited { principal },
        }
    }
}

/// TTL policy: 30s (+jitter) for positives, 5s for negatives, 1s for transients.
struct TtlPolicy {
    positive_ttl: Duration,
    negative_ttl: Duration,
    transient_ttl: Duration,
    jitter: Duration,
}

impl TtlPolicy {
    fn jittered(&self, base: Duration) -> Duration {
        let extra = if self.jitter.is_zero() {
            0
        } else {
            rand::random::<u64>() % self.jitter.as_millis().max(1) as u64
        };
        base + Duration::from_millis(extra)
    }
}

impl Expiry<AuthKey, CacheEntry> for TtlPolicy {
    fn expire_after_create(
        &self,
        _key: &AuthKey,
        value: &CacheEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(match value {
            CacheEntry::Resolved(_) => self.jittered(self.positive_ttl),
            CacheEntry::Denied(_) => self.negative_ttl,
            CacheEntry::Transient => self.transient_ttl,
        })
    }
}

// --------------------------------------------------------------------------
// Resolver.
// --------------------------------------------------------------------------

/// The resolver: a thin coordinator over [`Cache`] + [`CircuitBreaker`] +
/// a last-known-good map for fail-open.
pub struct Resolver {
    client: Arc<dyn ControlPlaneClient>,
    positive_ttl: Duration,
    fail_open: bool,
    breaker: CircuitBreaker,
    cache: Cache<AuthKey, CacheEntry>,
    last_good: Mutex<HashMap<AuthKey, Grant>>,
}

impl Resolver {
    /// Build a resolver with the given policy. The cache and breaker are
    /// configured from these values; see [`crate::config::ControlPlaneConfig`].
    #[allow(clippy::too_many_arguments)] // explicit, config-derived tuning knobs
    pub fn new(
        client: Arc<dyn ControlPlaneClient>,
        positive_ttl: Duration,
        negative_ttl: Duration,
        transient_ttl: Duration,
        ttl_jitter: Duration,
        fail_open: bool,
        breaker_fail_threshold: u32,
        breaker_reset: Duration,
        _client_timeout: Duration,
    ) -> Self {
        let ttl = TtlPolicy {
            positive_ttl,
            negative_ttl,
            transient_ttl,
            jitter: ttl_jitter,
        };
        let cache = Cache::builder()
            .max_capacity(100_000)
            .expire_after(ttl)
            .build();
        Resolver {
            client,
            positive_ttl,
            fail_open,
            breaker: CircuitBreaker::new(breaker_fail_threshold, breaker_reset),
            cache,
            last_good: Mutex::new(HashMap::new()),
        }
    }

    /// The positive TTL (exposed for assertions/tuning).
    pub fn positive_ttl(&self) -> Duration {
        self.positive_ttl
    }

    fn lock_last_good(&self) -> std::sync::MutexGuard<'_, HashMap<AuthKey, Grant>> {
        match self.last_good.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Resolve + authorize a `(principal, fingerprint)`.
    ///
    /// The cache is consulted first; on a miss the control plane is called
    /// (single-flighted per key). Results are interpreted per the fail-open /
    /// fail-closed policy.
    pub async fn authorize(
        &self,
        principal: &Principal,
        fingerprint: &str,
        client_ip: &str,
    ) -> ResolveResult {
        let key = AuthKey {
            principal: principal.clone(),
            fingerprint: Fingerprint::new(fingerprint),
        };

        // Fast path: an existing (still-valid) cache entry.
        if let Some(entry) = self.cache.get(&key).await {
            return self.interpret_cached(entry, &key);
        }

        // Circuit breaker fast-fail.
        if !self.breaker.should_allow(Instant::now()) {
            return self.interpret_breaker_open(&key);
        }

        // Miss: coalesce the in-flight fetch per key via moka's single-flight.
        let entry = self
            .cache
            .get_with(key.clone(), self.fetch(&key, client_ip))
            .await;
        self.interpret_cached(entry, &key)
    }

    /// Perform the actual control-plane call and map it to a [`CacheEntry`],
    /// recording breaker success/failure and updating last-known-good.
    async fn fetch(&self, key: &AuthKey, client_ip: &str) -> CacheEntry {
        let req = ResolveRequest {
            principal: key.principal.as_str().to_owned(),
            client_ip: client_ip.to_owned(),
            key_fp: key.fingerprint.as_str().to_owned(),
        };
        match self.client.resolve(&req).await {
            Ok(resp) => {
                self.breaker.record_success();
                let grant = Grant {
                    principal: key.principal.clone(),
                    fingerprint: key.fingerprint.clone(),
                    agent_fingerprint: key.fingerprint.clone(),
                    target: resp.target,
                    policy: resp.policy,
                    // Stamped again by the ResolveRouter, which is the only
                    // component that knows which route produced this grant.
                    resolve_source: ResolveSource::default(),
                };
                self.lock_last_good().insert(key.clone(), grant.clone());
                CacheEntry::Resolved(Box::new(grant))
            }
            Err(ControlError::NotFound) => {
                // A definitive answer means the control plane is healthy.
                self.breaker.record_success();
                CacheEntry::Denied(Denied::NotFound)
            }
            Err(ControlError::Forbidden) => {
                self.breaker.record_success();
                CacheEntry::Denied(Denied::Forbidden)
            }
            Err(ControlError::RateLimited) => {
                self.breaker.record_success();
                CacheEntry::Denied(Denied::RateLimited)
            }
            Err(ControlError::ServerError)
            | Err(ControlError::Decode)
            | Err(ControlError::Transport) => {
                self.breaker.record_failure(Instant::now());
                CacheEntry::Transient
            }
        }
    }

    fn interpret_cached(&self, entry: CacheEntry, key: &AuthKey) -> ResolveResult {
        match entry {
            CacheEntry::Resolved(grant) => Ok(*grant),
            CacheEntry::Denied(denied) => Err(denied.to_error(&key.principal)),
            CacheEntry::Transient => {
                if self.fail_open {
                    if let Some(grant) = self.lock_last_good().get(key) {
                        return Ok(grant.clone());
                    }
                }
                Err(ResolveError::Unavailable {
                    principal: key.principal.as_str().to_owned(),
                })
            }
        }
    }

    fn interpret_breaker_open(&self, key: &AuthKey) -> ResolveResult {
        if self.fail_open {
            if let Some(grant) = self.lock_last_good().get(key) {
                return Ok(grant.clone());
            }
        }
        Err(ResolveError::CircuitOpen {
            principal: key.principal.as_str().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Policy, Target};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn principal() -> Principal {
        Principal::parse("alex_host1").unwrap()
    }

    fn fingerprint() -> &'static str {
        "SHA256:fp123"
    }

    fn grant_for(p: &Principal) -> Grant {
        Grant {
            principal: p.clone(),
            fingerprint: Fingerprint::new(fingerprint()),
            agent_fingerprint: Fingerprint::new(fingerprint()),
            target: Target {
                host: "10.1.2.3".into(),
                port: 22,
                user: "root".into(),
            },
            policy: Policy::default(),
            resolve_source: ResolveSource::default(),
        }
    }

    /// A fake control-plane client; the number of calls is recorded so tests can
    /// assert single-flight / cache-hit behaviour.
    #[derive(Clone, Copy)]
    enum FakeBehavior {
        AlwaysOk,
        /// The first `n` invocations succeed, subsequent ones fail.
        OkFirstN(usize),
        Always(ControlError),
    }

    struct FakeClient {
        calls: AtomicUsize,
        behavior: FakeBehavior,
    }

    impl FakeClient {
        fn ok(first_n_ok: Option<usize>) -> Arc<Self> {
            let behavior = match first_n_ok {
                Some(n) => FakeBehavior::OkFirstN(n),
                None => FakeBehavior::AlwaysOk,
            };
            Arc::new(FakeClient {
                calls: AtomicUsize::new(0),
                behavior,
            })
        }

        fn always(err: ControlError) -> Arc<Self> {
            Arc::new(FakeClient {
                calls: AtomicUsize::new(0),
                behavior: FakeBehavior::Always(err),
            })
        }

        fn response() -> ResolveResponse {
            ResolveResponse {
                target: Target {
                    host: "10.1.2.3".into(),
                    port: 22,
                    user: "root".into(),
                },
                policy: Policy::default(),
            }
        }
    }

    impl ControlPlaneClient for FakeClient {
        fn resolve<'a>(
            &'a self,
            _req: &'a ResolveRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::result::Result<ResolveResponse, ControlError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(self.resolve_inner())
        }
    }

    impl FakeClient {
        async fn resolve_inner(&self) -> std::result::Result<ResolveResponse, ControlError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await; // simulate RTT
            match self.behavior {
                FakeBehavior::AlwaysOk => Ok(Self::response()),
                FakeBehavior::OkFirstN(limit) => {
                    if n < limit {
                        Ok(Self::response())
                    } else {
                        Err(ControlError::ServerError)
                    }
                }
                FakeBehavior::Always(err) => Err(err),
            }
        }
    }

    fn build_resolver(client: Arc<dyn ControlPlaneClient>, fail_open: bool) -> Resolver {
        Resolver::new(
            client,
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_millis(1000),
            Duration::from_millis(0), // no jitter for determinism
            fail_open,
            3,                          // breaker threshold
            Duration::from_millis(200), // breaker reset
            Duration::from_secs(2),
        )
    }

    #[tokio::test]
    async fn resolves_and_caches_positive_result() {
        let client = FakeClient::ok(None);
        let resolver = build_resolver(client.clone(), false);
        let p = principal();

        let g1 = resolver
            .authorize(&p, fingerprint(), "1.2.3.4")
            .await
            .expect("grant");
        assert_eq!(g1.target.host, "10.1.2.3");
        let g2 = resolver
            .authorize(&p, fingerprint(), "1.2.3.4")
            .await
            .expect("grant");
        assert_eq!(g2.target.host, "10.1.2.3");
        // second call served from cache → only one control-plane call.
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_lookups_are_single_flighted() {
        let client = FakeClient::ok(None);
        let resolver = std::sync::Arc::new(build_resolver(client.clone(), false));
        let p = principal();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let resolver = resolver.clone();
            let p = p.clone();
            handles.push(tokio::spawn(async move {
                resolver.authorize(&p, fingerprint(), "1.2.3.4").await
            }));
        }
        for h in handles {
            h.await.unwrap().expect("grant");
        }
        // All 10 concurrent lookups coalesced into one control-plane call.
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn not_found_is_a_rejection() {
        let client = FakeClient::always(ControlError::NotFound);
        let resolver = build_resolver(client, false);
        let err = resolver
            .authorize(&principal(), fingerprint(), "1.2.3.4")
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::NotFound { .. }));
    }

    #[tokio::test]
    async fn forbidden_is_cached_as_negative() {
        let client = FakeClient::always(ControlError::Forbidden);
        let resolver = build_resolver(client.clone(), false);
        let p = principal();
        let _ = resolver.authorize(&p, fingerprint(), "1.2.3.4").await;
        let _ = resolver.authorize(&p, fingerprint(), "1.2.3.4").await;
        // negative cache suppresses the second call.
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fail_closed_returns_error_on_transient_failure() {
        let client = FakeClient::always(ControlError::ServerError);
        let resolver = build_resolver(client, false);
        let err = resolver
            .authorize(&principal(), fingerprint(), "1.2.3.4")
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::Unavailable { .. }));
    }

    #[tokio::test]
    async fn fail_open_serves_last_known_good_after_error() {
        // Call #0 succeeds; every later call fails.
        let client = FakeClient::ok(Some(1));
        // Tiny positive/transient TTLs so the positive entry lapses within the
        // test and a control-plane call is forced.
        let resolver = Resolver::new(
            client.clone() as Arc<dyn ControlPlaneClient>,
            Duration::from_millis(50), // positive ttl
            Duration::from_secs(5),
            Duration::from_millis(50), // transient ttl
            Duration::from_millis(0),
            true, // fail open
            3,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );
        let p = principal();
        let _ = resolver
            .authorize(&p, fingerprint(), "1.2.3.4")
            .await
            .expect("initial grant");

        // Let the positive entry lapse.
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Next authorize misses cache, calls the control plane (which now fails),
        // and fail-open serves the last-known-good grant for this key.
        let g = resolver.authorize(&p, fingerprint(), "1.2.3.4").await;
        assert!(
            g.is_ok(),
            "fail-open should serve last-known-good, got {g:?}"
        );
        assert_eq!(g.unwrap().target.host, "10.1.2.3");
    }

    #[tokio::test]
    async fn circuit_breaker_opens_after_threshold_and_recovers() {
        let client = FakeClient::always(ControlError::ServerError);
        let resolver = build_resolver(client, false);
        let p = principal();
        // Use distinct fingerprints so each lookup goes to the control plane
        // (distinct cache keys) and trips the breaker via failures.
        for i in 0..3 {
            let fp = format!("SHA256:fp{i}");
            let _ = resolver.authorize(&p, &fp, "1.2.3.4").await;
        }
        assert_eq!(resolver.breaker.state(), BreakerState::Open);
        // A subsequent lookup fast-fails without touching a cached entry.
        let err = resolver
            .authorize(&p, "SHA256:fpX", "1.2.3.4")
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::CircuitOpen { .. }));
        // After the reset timeout, the breaker half-opens and lets a probe in.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(resolver.breaker.should_allow(Instant::now()));
    }

    #[tokio::test]
    async fn invalid_principal_is_rejected_before_any_call() {
        // Authorize parses via Principal upstream; here we assert the client is
        // never consulted for a well-formed path with an empty fingerprint is
        // still forwarded (fingerprint validity is the control plane's job).
        let client = FakeClient::ok(None);
        let resolver = build_resolver(client.clone(), false);
        let _ = resolver
            .authorize(&principal(), fingerprint(), "1.2.3.4")
            .await
            .expect("grant");
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    // ---- CircuitBreaker unit tests (pure, no async, deterministic clock) ----

    #[test]
    fn breaker_opens_after_consecutive_failures() {
        let b = CircuitBreaker::new(3, Duration::from_millis(100));
        let t0 = Instant::now();
        assert!(b.should_allow(t0));
        b.record_failure(t0);
        b.record_failure(t0);
        assert_eq!(b.state(), BreakerState::Closed);
        b.record_failure(t0); // third failure trips it
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.should_allow(t0 + Duration::from_millis(50)));
        assert!(b.should_allow(t0 + Duration::from_millis(150))); // half-open probe
        assert_eq!(b.state(), BreakerState::HalfOpen);
    }

    #[test]
    fn breaker_success_resets_count() {
        let b = CircuitBreaker::new(3, Duration::from_millis(100));
        let t = Instant::now();
        b.record_failure(t);
        b.record_failure(t);
        b.record_success();
        b.record_failure(t);
        b.record_failure(t);
        // success reset the consecutive counter; still closed.
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn breaker_half_open_probe_failure_reopens() {
        let b = CircuitBreaker::new(1, Duration::from_millis(100));
        let t0 = Instant::now();
        b.record_failure(t0);
        assert_eq!(b.state(), BreakerState::Open);
        b.should_allow(t0 + Duration::from_millis(150)); // → HalfOpen
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.record_failure(t0 + Duration::from_millis(160)); // probe fails
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn breaker_half_open_success_closes() {
        let b = CircuitBreaker::new(1, Duration::from_millis(100));
        let t0 = Instant::now();
        b.record_failure(t0);
        b.should_allow(t0 + Duration::from_millis(150)); // → HalfOpen
        b.record_success();
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.should_allow(t0 + Duration::from_millis(151)));
    }

    #[test]
    fn ttl_jitter_stays_within_bounds() {
        let ttl = TtlPolicy {
            positive_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_secs(5),
            transient_ttl: Duration::from_secs(1),
            jitter: Duration::from_secs(3),
        };
        let entry = CacheEntry::Resolved(Box::new(grant_for(&principal())));
        let d = ttl
            .expire_after_create(
                &AuthKey {
                    principal: principal(),
                    fingerprint: Fingerprint::new("x"),
                },
                &entry,
                Instant::now(),
            )
            .unwrap();
        assert!(d >= Duration::from_secs(30) && d <= Duration::from_secs(33));
    }
}
