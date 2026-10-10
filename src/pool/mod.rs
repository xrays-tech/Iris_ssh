//! Backend connection pool capabilities (propose.md §3.8, M2) — wired into the
//! per-session dial path, opt-in reuse off by default (D9).
//!
//! ## Scope note (russh reality vs. design)
//!
//! russh's `client::Handle` is `Send` but **not `Sync`** (it owns a `Receiver`),
//! so a single backend connection cannot be shared across live client sessions
//! via `Arc`/`Mutex` without serialising channel opens behind a lock held across
//! an `await` (forbidden by D11). The default mode is therefore **one backend
//! connection per client session, reused across that session's channels** — which
//! is exactly what `server`'s `ensure_backend` does and covers the ControlMaster
//! (scp/rsync) reuse case.
//!
//! What is **wired into production paths** today:
//!
//! * **Dial circuit breaker** — [`DialCircuitBreaker`] gates
//!   [`crate::backend::BackendDialer::connect`]:
//!   a target with `pool.circuit_failure_threshold` consecutive dial failures is
//!   short-circuited for `pool.circuit_reset_timeout`, so channel opens fail fast
//!   instead of piling onto a dead backend. This is the MS2 "熔断生效" gate for
//!   the backend dial path (the control-plane path has its own breaker in
//!   [`crate::resolve`]).
//! * **Per-connection channel limit** — [`can_open_channel`] guards
//!   `server::channel_open_session`: a session whose backend connection already
//!   carries `pool.channels_per_conn` channels (capped at
//!   [`MAX_CHANNELS_PER_CONN_HARD_LIMIT`], the sshd `MaxSessions`-safe bound)
//!   fails further opens with `ResourceShortage`.
//! * **Health / liveness** — the client leg sets `keepalive_interval` +
//!   `keepalive_max` (see `BackendDialer`), so russh emits
//!   `keepalive@openssh.com` and closes a dead connection on its own;
//!   [`Liveness`] models the same consecutive-miss bookkeeping for a custom
//!   transport or richer metrics.
//!
//! [`should_ping_before_reuse`] remains a *policy* helper for the idle-reuse
//! path (§3.8); with cross-session reuse disabled it is exercised by tests
//! rather than the runtime, and is kept so enabling reuse later needs no new
//! logic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::resolve::CircuitBreaker;

/// The maximum channels a single backend connection may carry (sshd default
/// `MaxSessions` is 10; we keep a conservative margin). Use `1..=8`.
pub const MAX_CHANNELS_PER_CONN_HARD_LIMIT: usize = 8;

/// Whether one more channel may be opened on a connection already carrying
/// `current` channels. Pure decision used to enforce the sshd-safe bound.
pub fn can_open_channel(current: usize, limit: usize) -> bool {
    let effective = limit.clamp(1, MAX_CHANNELS_PER_CONN_HARD_LIMIT);
    current < effective
}

/// Whether a pooled connection idle for `idle_for` must be probed before reuse
/// (§3.8: idle > 30s → ping first).
pub fn should_ping_before_reuse(idle_for: Duration, threshold: Duration) -> bool {
    idle_for >= threshold
}

/// Tracks backend keepalive liveness for one connection (§3.8): after
/// `max_miss` consecutive misses the connection is considered dead.
#[derive(Debug, Clone)]
pub struct Liveness {
    max_miss: u32,
    consecutive_miss: u32,
    dead: bool,
}

impl Liveness {
    pub fn new(max_miss: u32) -> Self {
        Liveness {
            max_miss: max_miss.max(1),
            consecutive_miss: 0,
            dead: false,
        }
    }

    /// A keepalive round-trip succeeded.
    pub fn on_pong(&mut self) {
        self.consecutive_miss = 0;
    }

    /// A keepalive timed out. Returns `true` if this miss crosses the threshold
    /// and the connection is now considered dead (should be destroyed).
    pub fn on_timeout(&mut self) -> bool {
        self.consecutive_miss = self.consecutive_miss.saturating_add(1);
        if self.consecutive_miss >= self.max_miss && !self.dead {
            self.dead = true;
            true
        } else {
            false
        }
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    pub fn consecutive_miss(&self) -> u32 {
        self.consecutive_miss
    }
}

/// A per-target circuit breaker for backend dial failures / dead connections
/// (§3.8): after `failure_threshold` consecutive failures the target is short-
/// circuited for `reset_timeout`.
#[derive(Debug)]
pub struct DialCircuitBreaker {
    breakers: std::sync::Mutex<std::collections::HashMap<String, Arc<CircuitBreaker>>>,
    failure_threshold: u32,
    reset_timeout: Duration,
}

impl DialCircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        DialCircuitBreaker {
            breakers: std::sync::Mutex::new(std::collections::HashMap::new()),
            failure_threshold: failure_threshold.max(1),
            reset_timeout,
        }
    }

    fn breaker_for(&self, target: &str) -> Arc<CircuitBreaker> {
        let mut breakers = match self.breakers.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(breakers.entry(target.to_owned()).or_insert_with(|| {
            Arc::new(CircuitBreaker::new(
                self.failure_threshold,
                self.reset_timeout,
            ))
        }))
    }

    /// Whether a dial to `target` may proceed right now.
    pub fn allows(&self, target: &str) -> bool {
        self.breaker_for(target).should_allow(Instant::now())
    }

    pub fn record_success(&self, target: &str) {
        self.breaker_for(target).record_success();
    }

    pub fn record_failure(&self, target: &str) {
        self.breaker_for(target).record_failure(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_limit_enforced_and_clamped_to_hard_limit() {
        assert!(can_open_channel(0, 8));
        assert!(can_open_channel(7, 8));
        assert!(!can_open_channel(8, 8));
        // A config that exceeds the hard cap is clamped to 8.
        assert!(!can_open_channel(8, 100));
        // A zero/degenerate limit still allows at least one channel.
        assert!(can_open_channel(0, 0));
    }

    #[test]
    fn idle_connections_ping_only_after_threshold() {
        assert!(!should_ping_before_reuse(
            Duration::from_secs(10),
            Duration::from_secs(30)
        ));
        assert!(should_ping_before_reuse(
            Duration::from_secs(30),
            Duration::from_secs(30)
        ));
        assert!(should_ping_before_reuse(
            Duration::from_secs(31),
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn liveness_marks_dead_after_consecutive_misses() {
        let mut l = Liveness::new(2);
        assert!(!l.on_timeout()); // 1 miss, not yet dead
        assert!(!l.is_dead());
        assert!(l.on_timeout()); // 2nd miss → dead
        assert!(l.is_dead());

        // A pong resets the counter on a still-alive connection.
        let mut l2 = Liveness::new(2);
        l2.on_timeout();
        l2.on_pong();
        assert!(!l2.on_timeout());
        assert!(!l2.is_dead());
        assert_eq!(l2.consecutive_miss(), 1);
    }

    #[test]
    fn dial_breaker_opens_per_target_and_recovers() {
        let b = DialCircuitBreaker::new(2, Duration::from_millis(100));
        assert!(b.allows("10.0.0.1:22"));
        b.record_failure("10.0.0.1:22");
        b.record_failure("10.0.0.1:22");
        // now open for this target
        assert!(!b.allows("10.0.0.1:22"));
        // a different target is unaffected
        assert!(b.allows("10.0.0.2:22"));
        // recovers after the reset window
        let t = Instant::now() + Duration::from_millis(150);
        assert!(b.breaker_for("10.0.0.1:22").should_allow(t));
    }
}
