//! In-process metrics registry.
//!
//! A self-contained, lock-free registry: atomic counters, up/down gauges and
//! fixed-bucket latency histograms rendered on demand into the Prometheus text
//! exposition format. Keeping it in-crate (rather than pulling an exporter with
//! a build dependency) makes the accounting logic directly unit-testable and
//! keeps the binary lean. A [`Metrics`] handle is cheap to clone (it wraps an
//! [`Arc`]) and is shared across all legs.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// A [`Metrics`] handle shared by every session and background task.
#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    // gauges
    active_sessions: AtomicUsize,
    /// Total relay *window budget* currently reserved by live sessions
    /// (`config.relay.window_size * 2` per session: one send window for each
    /// leg). This is a **quota reservation**, not live in-flight bytes — it is a
    /// capacity-planning gauge (a derived ceiling of
    /// `active_sessions * window_size * 2`), so a threshold on it means "the
    /// gateway is about to run out of window budget", never "this many bytes are
    /// buffered right now".
    ///
    /// Renamed from `relay_inflight_bytes` (exposed as
    /// `sshgw_relay_window_budget_bytes`) because the old name suggested live
    /// byte accounting and invited mis-set alerts. Old-name mapping for existing
    /// dashboards/alerts: `sshgw_relay_inflight_bytes` -> `sshgw_relay_window_budget_bytes`.
    relay_window_budget_bytes: AtomicUsize,

    // auth counters (two-phase, propose.md §3.2)
    auth_offered_total: AtomicU64,
    auth_accept_total: AtomicU64,
    auth_reject_total: AtomicU64,

    // resolve counters
    resolve_ok_total: AtomicU64,
    resolve_err_total: AtomicU64,
    resolve_cache_hit_total: AtomicU64,
    resolve_cache_miss_total: AtomicU64,
    resolve_circuit_open_total: AtomicU64,

    // relay / flow-control
    window_exhausted_total: AtomicU64,
    backend_dial_ok_total: AtomicU64,
    backend_dial_fail_total: AtomicU64,
    /// Backend connections lost mid-session (coupled-close / DISCONNECT[11]).
    backend_lost_total: AtomicU64,

    // pool health
    pool_dead_detected_total: AtomicU64,
    pool_tracked_conns: AtomicUsize,

    // M3: certificate auth (B1)
    cert_auth_accept_total: AtomicU64,
    cert_auth_reject_total: AtomicU64,

    // M3: SFTP interception (B3)
    sftp_requests_seen_total: AtomicU64,
    sftp_requests_denied_total: AtomicU64,

    /// A `direct-tcpip` ("local TCP forwarding") channel open was refused.
    /// The gateway is never an outbound pivot, so this fires for every such
    /// request; a rising counter means someone is probing for forwarding.
    direct_tcpip_denied_total: AtomicU64,

    // M3: session recording (B2)
    recorded_bytes_total: AtomicU64,
    recorded_sessions_total: AtomicU64,

    // C2: agent passthrough (plan-agent-passthrough)
    /// Agent-mode sessions whose backend handshake succeeded.
    agent_backend_auth_ok_total: AtomicU64,
    /// Agent-mode sessions that could not authenticate to the backend. Every
    /// one of these ends in a protocol-native channel close — never in a
    /// fallback to another credential, because the gateway holds none (D3).
    agent_backend_auth_fail_total: AtomicU64,
    /// Signature operations the gateway relayed to the user's agent. Bounded by
    /// one per agent-mode session (we offer exactly one authorized identity).
    agent_signatures_total: AtomicU64,
    /// Channel opens refused because the session's per-connection channel cap
    /// (`pool.channels_per_conn`) would be exceeded.
    agent_channel_denied_total: AtomicU64,

    // disconnect reason histogram, indexed by SSH reason code (0..=15).
    disconnect_reason: [AtomicU64; 16],

    // latency histograms
    resolve_latency_us: Histogram,
    backend_dial_latency_us: Histogram,
}

/// Fixed-bucket, cumulative histogram (Prometheus `le` semantics).
struct Histogram {
    /// Upper bounds in microseconds; the implicit final bucket is `+Inf`.
    bucket_bounds_us: &'static [u64],
    /// `bucket_counts[i]` = observations with value `<= bucket_bounds_us[i]`.
    bucket_counts: Vec<AtomicU64>,
    inf_count: AtomicU64,
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl Histogram {
    /// Buckets suited to sub-millisecond-to-seconds latencies.
    const BOUNDS: &'static [u64] = &[
        500,       // 0.5ms
        1_000,     // 1ms
        5_000,     // 5ms
        10_000,    // 10ms
        50_000,    // 50ms
        100_000,   // 100ms
        500_000,   // 500ms
        1_000_000, // 1s
        5_000_000, // 5s
    ];

    fn new() -> Self {
        Histogram {
            bucket_bounds_us: Histogram::BOUNDS,
            bucket_counts: Histogram::BOUNDS
                .iter()
                .map(|_| AtomicU64::new(0))
                .collect(),
            inf_count: AtomicU64::new(0),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    fn observe_us(&self, micros: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(micros, Ordering::Relaxed);
        let mut placed = false;
        for (i, bound) in self.bucket_bounds_us.iter().enumerate() {
            if micros <= *bound {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
                placed = true;
                break;
            }
        }
        if !placed {
            self.inf_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render Prometheus `_bucket`, `_sum` and `_count` lines for a named metric.
    fn render(&self, name: &str, out: &mut String) {
        let mut cumulative = 0u64;
        for (i, bound) in self.bucket_bounds_us.iter().enumerate() {
            cumulative += self.bucket_counts[i].load(Ordering::Relaxed);
            let le = *bound as f64 / 1_000_000.0;
            out.push_str(&format!("{name}_bucket{{le=\"{le}\"}} {cumulative}\n"));
        }
        let inf = self.inf_count.load(Ordering::Relaxed);
        out.push_str(&format!(
            "{name}_bucket{{le=\"+Inf\"}} {}\n",
            cumulative + inf
        ));
        out.push_str(&format!(
            "{name}_sum {}\n",
            self.sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0
        ));
        out.push_str(&format!(
            "{name}_count {}\n",
            self.count.load(Ordering::Relaxed)
        ));
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram::new()
    }
}

impl Metrics {
    /// Record a newly accepted session (increments the active-session gauge).
    pub fn session_started(&self) {
        self.inner.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a session that has fully terminated.
    pub fn session_ended(&self) {
        // Guard against underflow if `session_ended` is ever mis-paired.
        let _ =
            self.inner
                .active_sessions
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
    }

    /// Reserve `bytes` of relay window budget for a newly-active session.
    pub fn add_window_budget(&self, bytes: usize) {
        self.inner
            .relay_window_budget_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Release a previously reserved relay window allocation.
    pub fn sub_window_budget(&self, bytes: usize) {
        let _ = self.inner.relay_window_budget_bytes.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(bytes)),
        );
    }

    pub fn auth_offered(&self) {
        self.inner
            .auth_offered_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn auth_accept(&self) {
        self.inner.auth_accept_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn auth_reject(&self) {
        self.inner.auth_reject_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_ok(&self) {
        self.inner.resolve_ok_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_err(&self) {
        self.inner.resolve_err_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_cache_hit(&self) {
        self.inner
            .resolve_cache_hit_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_cache_miss(&self) {
        self.inner
            .resolve_cache_miss_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_circuit_open(&self) {
        self.inner
            .resolve_circuit_open_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_latency(&self, latency: std::time::Duration) {
        self.inner
            .resolve_latency_us
            .observe_us(latency.as_micros() as u64);
    }

    pub fn window_exhausted(&self) {
        self.inner
            .window_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn backend_dial_ok(&self) {
        self.inner
            .backend_dial_ok_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn backend_dial_fail(&self) {
        self.inner
            .backend_dial_fail_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A backend connection died while relays were still attached to it.
    pub fn backend_lost(&self) {
        self.inner
            .backend_lost_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn backend_dial_latency(&self, latency: std::time::Duration) {
        self.inner
            .backend_dial_latency_us
            .observe_us(latency.as_micros() as u64);
    }

    pub fn pool_dead_detected(&self) {
        self.inner
            .pool_dead_detected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A certificate-authenticated session was accepted (B1).
    pub fn cert_auth_accept(&self) {
        self.inner
            .cert_auth_accept_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A certificate authentication attempt was refused (B1).
    pub fn cert_auth_reject(&self) {
        self.inner
            .cert_auth_reject_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// An SFTP request was decoded and inspected (B3).
    pub fn sftp_request_seen(&self) {
        self.inner
            .sftp_requests_seen_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// An SFTP request was refused by policy (B3).
    pub fn sftp_request_denied(&self) {
        self.inner
            .sftp_requests_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A `direct-tcpip` channel open was refused (the gateway is never an
    /// outbound pivot; there is no policy that can turn this on).
    pub fn direct_tcpip_denied(&self) {
        self.inner
            .direct_tcpip_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bytes written to the session recording (B2).
    pub fn recorded_bytes(&self, bytes: usize) {
        self.inner
            .recorded_bytes_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// A session recording was started (B2).
    pub fn recorded_session(&self) {
        self.inner
            .recorded_sessions_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn pool_conn_tracked(&self) {
        self.inner
            .pool_tracked_conns
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn pool_conn_released(&self) {
        let _ =
            self.inner
                .pool_tracked_conns
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
    }

    /// Record a session termination by SSH disconnect reason code.
    pub fn disconnect_reason(&self, code: u32) {
        if let Some(slot) = self.inner.disconnect_reason.get(code as usize) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An agent-mode session authenticated to the backend with the user's
    /// forwarded agent (C2).
    pub fn agent_backend_auth_ok(&self) {
        self.inner
            .agent_backend_auth_ok_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// An agent-mode session could **not** authenticate to the backend. The
    /// channel is closed natively; no other credential is ever tried.
    pub fn agent_backend_auth_fail(&self) {
        self.inner
            .agent_backend_auth_fail_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// One signature request was relayed to the user's agent. We offer exactly
    /// one authorized identity per session, so this is one per successful
    /// agent-mode dial.
    pub fn agent_signature(&self) {
        self.inner
            .agent_signatures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A channel open was refused because it would exceed the session's
    /// per-connection channel cap.
    pub fn agent_channel_denied(&self) {
        self.inner
            .agent_channel_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Current active session count (for readiness / assertions in tests).
    pub fn active_sessions(&self) -> usize {
        self.inner.active_sessions.load(Ordering::Relaxed)
    }

    /// Render all metrics into the Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        push_gauge(
            &mut out,
            "sshgw_active_sessions",
            self.inner.active_sessions.load(Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "sshgw_relay_window_budget_bytes",
            self.inner.relay_window_budget_bytes.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "sshgw_auth_offered_total",
            &self.inner.auth_offered_total,
        );
        push_counter(
            &mut out,
            "sshgw_auth_accept_total",
            &self.inner.auth_accept_total,
        );
        push_counter(
            &mut out,
            "sshgw_auth_reject_total",
            &self.inner.auth_reject_total,
        );
        push_counter(
            &mut out,
            "sshgw_resolve_ok_total",
            &self.inner.resolve_ok_total,
        );
        push_counter(
            &mut out,
            "sshgw_resolve_err_total",
            &self.inner.resolve_err_total,
        );
        push_counter(
            &mut out,
            "sshgw_resolve_cache_hit_total",
            &self.inner.resolve_cache_hit_total,
        );
        push_counter(
            &mut out,
            "sshgw_resolve_cache_miss_total",
            &self.inner.resolve_cache_miss_total,
        );
        push_counter(
            &mut out,
            "sshgw_resolve_circuit_open_total",
            &self.inner.resolve_circuit_open_total,
        );
        push_counter(
            &mut out,
            "sshgw_window_exhausted_total",
            &self.inner.window_exhausted_total,
        );
        push_counter(
            &mut out,
            "sshgw_backend_dial_ok_total",
            &self.inner.backend_dial_ok_total,
        );
        push_counter(
            &mut out,
            "sshgw_backend_dial_fail_total",
            &self.inner.backend_dial_fail_total,
        );
        push_counter(
            &mut out,
            "sshgw_backend_lost_total",
            &self.inner.backend_lost_total,
        );
        push_counter(
            &mut out,
            "sshgw_pool_dead_detected_total",
            &self.inner.pool_dead_detected_total,
        );
        push_gauge(
            &mut out,
            "sshgw_pool_tracked_conns",
            self.inner.pool_tracked_conns.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "sshgw_cert_auth_accept_total",
            &self.inner.cert_auth_accept_total,
        );
        push_counter(
            &mut out,
            "sshgw_cert_auth_reject_total",
            &self.inner.cert_auth_reject_total,
        );
        push_counter(
            &mut out,
            "sshgw_sftp_requests_seen_total",
            &self.inner.sftp_requests_seen_total,
        );
        push_counter(
            &mut out,
            "sshgw_sftp_requests_denied_total",
            &self.inner.sftp_requests_denied_total,
        );
        push_counter(
            &mut out,
            "sshgw_direct_tcpip_denied_total",
            &self.inner.direct_tcpip_denied_total,
        );
        push_counter(
            &mut out,
            "sshgw_recorded_bytes_total",
            &self.inner.recorded_bytes_total,
        );
        push_counter(
            &mut out,
            "sshgw_recorded_sessions_total",
            &self.inner.recorded_sessions_total,
        );
        push_counter(
            &mut out,
            "sshgw_agent_backend_auth_ok_total",
            &self.inner.agent_backend_auth_ok_total,
        );
        push_counter(
            &mut out,
            "sshgw_agent_backend_auth_fail_total",
            &self.inner.agent_backend_auth_fail_total,
        );
        push_counter(
            &mut out,
            "sshgw_agent_signatures_total",
            &self.inner.agent_signatures_total,
        );
        push_counter(
            &mut out,
            "sshgw_agent_channel_denied_total",
            &self.inner.agent_channel_denied_total,
        );

        for (code, counter) in self.inner.disconnect_reason.iter().enumerate().skip(1) {
            let v = counter.load(Ordering::Relaxed);
            if v > 0 {
                out.push_str(&format!(
                    "sshgw_disconnect_reason_total{{reason=\"{code}\"}} {v}\n"
                ));
            }
        }

        self.inner
            .resolve_latency_us
            .render("sshgw_resolve_latency_seconds", &mut out);
        self.inner
            .backend_dial_latency_us
            .render("sshgw_backend_dial_latency_seconds", &mut out);

        out
    }
}

fn push_gauge(out: &mut String, name: &str, value: usize) {
    out.push_str(&format!("{name} {value}\n"));
}

fn push_counter(out: &mut String, name: &str, value: &AtomicU64) {
    out.push_str(&format!("{name} {}\n", value.load(Ordering::Relaxed)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_gauge_tracks_up_and_down_without_underflow() {
        let m = Metrics::default();
        m.session_started();
        m.session_started();
        m.session_started();
        assert_eq!(m.active_sessions(), 3);
        m.session_ended();
        m.session_ended();
        assert_eq!(m.active_sessions(), 1);
        // Extra `ended` must not underflow to a huge number.
        m.session_ended();
        m.session_ended();
        assert_eq!(m.active_sessions(), 0);
    }

    #[test]
    fn window_budget_gauge_never_underflows() {
        let m = Metrics::default();
        m.add_window_budget(100);
        m.add_window_budget(50);
        assert_eq!(
            m.inner.relay_window_budget_bytes.load(Ordering::Relaxed),
            150
        );
        m.sub_window_budget(120);
        assert_eq!(
            m.inner.relay_window_budget_bytes.load(Ordering::Relaxed),
            30
        );
        m.sub_window_budget(999); // oversubscribe
        assert_eq!(m.inner.relay_window_budget_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_count_insertions() {
        let m = Metrics::default();
        m.backend_dial_latency(std::time::Duration::from_micros(300));
        m.backend_dial_latency(std::time::Duration::from_millis(2));
        m.backend_dial_latency(std::time::Duration::from_secs(10)); // +Inf bucket
        let text = m.render_prometheus();
        // three observations total
        assert!(text.contains("sshgw_backend_dial_latency_seconds_count 3"));
        // the 0.5ms bucket should hold the 300us observation only
        assert!(text.contains("sshgw_backend_dial_latency_seconds_bucket{le=\"0.0005\"} 1"));
        // the 5ms bucket holds the 300us + 2ms = 2
        assert!(text.contains("sshgw_backend_dial_latency_seconds_bucket{le=\"0.005\"} 2"));
    }

    #[test]
    fn disconnect_reason_histogram_ignores_out_of_range() {
        let m = Metrics::default();
        m.disconnect_reason(11); // ByApplication
        m.disconnect_reason(11);
        m.disconnect_reason(14);
        m.disconnect_reason(999); // ignored
        let text = m.render_prometheus();
        assert!(text.contains("sshgw_disconnect_reason_total{reason=\"11\"} 2"));
        assert!(text.contains("sshgw_disconnect_reason_total{reason=\"14\"} 1"));
        assert!(!text.contains("reason=\"999\""));
    }

    #[test]
    fn prometheus_render_is_valid_text_exposition() {
        let m = Metrics::default();
        // The renamed gauge must be exposed under its new name, and the old name
        // must not linger (stale series mislead dashboards).
        m.add_window_budget(7);
        m.auth_offered();
        m.auth_accept();
        m.resolve_ok();
        let text = m.render_prometheus();
        assert!(text.contains("sshgw_relay_window_budget_bytes 7"));
        assert!(!text.contains("sshgw_relay_inflight_bytes"));
        assert!(text.contains("sshgw_active_sessions 0"));
        assert!(text.contains("sshgw_auth_offered_total 1"));
        assert!(text.contains("sshgw_auth_accept_total 1"));
        assert!(text.contains("sshgw_resolve_ok_total 1"));
        // every non-empty line is `name ... value`
        for line in text.lines() {
            assert!(line.contains(' '), "line malformed: {line:?}");
        }
    }
}
