//! Configuration: TOML parsing + validation into a trusted runtime config.
//!
//! The config file is an untrusted input, so it is first deserialized into
//! `Raw*` structs whose human-facing fields (sizes, durations, socket addrs)
//! are still plain strings, then validated field-by-field into [`GatewayConfig`]
//! whose fields are already typed (`u32` bytes, [`Duration`], [`HostKeyPolicy`]).
//! Validation is a set of small pure functions so each rule is unit-testable and
//! reports the offending field name (fail fast, fail loud).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{ConfigError, Error, Result};
use crate::types::HostKeyPolicy;

/// Fully validated, ready-to-use gateway configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen_addr: SocketAddr,
    pub host_keys: Vec<HostKeyEntry>,
    pub relay: RelayConfig,
    pub backend: BackendConfig,
    pub pool: PoolConfig,
    pub control_plane: ControlPlaneConfig,
    pub limits: LimitsConfig,
    /// Certificate authority (B1: host/user CA).
    pub ca: CaConfig,
    /// SFTP command-level interception (B3).
    pub intercept: InterceptConfig,
    /// Jump mode / direct-tcpip policy (B4).
    pub jump: JumpConfig,
    /// Session recording (B2).
    pub recording: RecordingConfig,
    pub shutdown: ShutdownConfig,
    pub metrics: MetricsConfig,
}

/// One host key file the gateway offers during KEX.
#[derive(Debug, Clone)]
pub struct HostKeyEntry {
    pub path: PathBuf,
    pub state: HostKeyState,
}

/// The lifecycle state of a host key, used to model rotation (propose.md §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyState {
    /// Currently used to sign NEWKEYS.
    Active,
    /// Offered via `hostkeys-00` and accepted for verification but not used to
    /// sign — the "introduction"/"retirement" windows of a rotation.
    Passive,
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Initial channel window size in bytes (both legs).
    pub window_size: u32,
    /// Max single SSH packet payload in bytes.
    pub max_packet: u32,
    /// Enable the per-channel outbound [`crate::relay`] semaphore fuse.
    pub outbound_guard: bool,
    /// If non-empty, `env` requests are forwarded only for names in this set.
    /// Empty means pass all `env` unchanged (M1 behaviour; propose.md §3.4).
    pub env_allowlist: Vec<String>,
    /// Disable Nagle's algorithm (`TCP_NODELAY`) on both SSH legs. Defaults to
    /// false (russh default; Nagle on). For throughput tests set true — a
    /// dual-hop relay under full-duplex traffic is the classic case where
    /// Nagle + delayed-ACK otherwise adds micro-stalls.
    pub nodelay: bool,
    /// Optional explicit symmetric-cipher preference order (names like
    /// `"chacha20-poly1305"`, `"aes256-gcm"`, `"aes128-gcm"`) applied to both
    /// legs. Empty = russh default order (chacha20 first). Used for A/B
    /// throughput comparisons; see docs/perf-report.md.
    pub ciphers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// Default backend key used when the target user has no `credential_map`
    /// entry.
    pub private_key: Option<PathBuf>,
    /// Maps a backend username to the key file the gateway authenticates with.
    pub credential_map: BTreeMap<String, PathBuf>,
    pub host_key_policy: HostKeyPolicy,
    /// Which credential the gateway presents: a private key (the default, and the
    /// only mode that works without a configured CA), a short-lived user
    /// certificate issued on the fly (propose §3.3, M4-T3), or the end user's
    /// forwarded ssh-agent identity (`"agent"`, plan-agent-passthrough).
    pub backend_auth: crate::backend::BackendAuthMethod,
    /// Global kill-switch for agent-mode backend auth (default **off**).
    ///
    /// A one-vote *veto*: `backend_auth = "agent"` (instance default or a
    /// per-grant `policy.backend_auth` override) is refused unless this is true.
    /// Enabling it is an explicit statement that the gateway may authenticate to
    /// backends as whatever identity the end user's agent holds.
    pub allow_agent_backend_auth: bool,
}

impl BackendConfig {
    /// Resolve which private key file to use for a given backend user.
    ///
    /// `credential_map` takes precedence over the single `private_key`.
    pub fn key_for_user(&self, user: &str) -> Option<&PathBuf> {
        self.credential_map.get(user).or(self.private_key.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub enabled: bool,
    pub channels_per_conn: usize,
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
    pub keepalive_max_miss: u32,
    /// Number of consecutive dial failures that trips the per-target breaker.
    pub circuit_failure_threshold: u32,
    /// How long an open circuit stays open before a probe is allowed through.
    pub circuit_reset_timeout: Duration,
    /// Idle connections older than this are pinged before reuse.
    pub idle_ping_threshold: Duration,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub url: String,
    pub cache_ttl: Duration,
    pub timeout: Duration,
    /// Serve stale cache on control-plane failure (fail-open) instead of
    /// refusing the session (fail-closed, the default).
    pub fail_open: bool,
    /// Extra jitter applied to `cache_ttl` to avoid thundering-herd expiry.
    pub cache_ttl_jitter: Duration,
}

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub max_sessions: usize,
    pub max_sessions_per_ip: usize,
    /// Ceiling on the initial-probe back-off: the first `"none"` authentication
    /// probe every SSH client sends is delayed by `min(auth_timeout,
    /// auth_rejection_pad)` (russh `auth_rejection_time_initial`). It is NOT
    /// the whole auth-phase deadline — that is `inactivity_timeout` +
    /// `max_auth_attempts`. `0s` removes the per-connection initial back-off
    /// (production option for latency-sensitive pubkey deployments; the
    /// per-rejection pad is retained).
    pub auth_timeout: Duration,
    /// Constant-time padding applied on each auth rejection (russh
    /// `auth_rejection_time`), so a rejected key's latency doesn't leak *why* it
    /// was rejected. Independent of `auth_timeout`: default 1s, not 30s.
    pub auth_rejection_pad: Duration,
    /// Idle-connection garbage-collection timeout (russh `inactivity_timeout`).
    /// Also the effective deadline for a peer that stalls mid-authentication.
    pub inactivity_timeout: Duration,
    /// Maximal number of allowed authentication attempts (russh
    /// `server::Config::max_auth_attempts`). `0` means unlimited, matching
    /// russh's own encoding; the default mirrors russh's built-in default of 10.
    pub max_auth_attempts: usize,
}

#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    pub drain_wait: Duration,
    pub disconnect_flush: Duration,
    pub hard_deadline: Duration,
}

/// Address the read-only `/healthz`, `/readyz` and `/metrics` server binds to.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub addr: std::net::SocketAddr,
}

/// Certificate-authority configuration (propose.md §八 / B1).
///
/// Both the user-certificate path (`auth_openssh_certificate`) and the backend
/// host-certificate path (`@cert-authority`) trust CAs by the fingerprint of
/// their **signing** key, so one list serves both.
#[derive(Debug, Clone, Default)]
pub struct CaConfig {
    /// Paths to trusted CA public keys (OpenSSH format). Empty disables
    /// certificate authentication entirely.
    pub trusted_ca_keys: Vec<std::path::PathBuf>,
    /// Optional CA private key. When present the gateway can *issue* short-lived
    /// user certificates; absent means verify-only.
    pub signing_key: Option<std::path::PathBuf>,
    /// Lifetime of issued certificates (seconds).
    pub cert_lifetime: Duration,
}

/// Session recording configuration (B2).
#[derive(Debug, Clone)]
pub struct RecordingConfig {
    /// Directory for recording files. Must be per-instance private (0600 dir,
    /// 0600 files) so multiple gateway replicas can coexist without collisions.
    pub dir: std::path::PathBuf,
    /// Hard cap on recorded bytes per channel; recording stops (and the session
    /// is audited as truncated) once reached, bounding disk use.
    pub max_bytes_per_session: u64,
}

/// SFTP interception configuration (B3).
#[derive(Debug, Clone)]
pub struct InterceptConfig {
    pub sftp: SftpInterceptConfig,
}

/// SFTP command-level interception policy.
#[derive(Debug, Clone, Default)]
pub struct SftpInterceptConfig {
    pub enabled: bool,
    /// SFTP command names to refuse outright (e.g. `["REMOVE", "RENAME"]`).
    pub deny_commands: Vec<String>,
    /// Path prefixes that may be reached; empty means "allow all" (only
    /// `deny_commands` applies).
    pub allowed_path_prefixes: Vec<String>,
    /// Path prefixes that are always refused, evaluated after the allow-list.
    pub denied_path_prefixes: Vec<String>,
}

/// Jump-mode (direct-tcpip) configuration (B4).
#[derive(Debug, Clone)]
pub struct JumpConfig {
    /// Master switch. Off = every direct-tcpip request is rejected locally,
    /// which is the pre-M3 baseline.
    pub enabled: bool,
    /// Additional gateway-wide target allow-list (`host`, `host:port`,
    /// `*:port`). Merged with the per-grant `policy.tcp_forwarding_targets`.
    pub allowed_targets: Vec<String>,
    /// Whether loopback/private/link-local destinations may be reached. Off by
    /// default: the gateway must not become an SSRF pivot into the private net.
    pub allow_private_networks: bool,
}

// --------------------------------------------------------------------------
// Raw TOML structures (fields still strings, validated afterwards).
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawConfig {
    listen: RawListen,
    host_keys: RawHostKeys,
    #[serde(default)]
    relay: RawRelay,
    backend: RawBackend,
    #[serde(default)]
    pool: RawPool,
    control_plane: RawControlPlane,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    shutdown: RawShutdown,
    #[serde(default)]
    metrics: RawMetrics,
    #[serde(default)]
    ca: RawCa,
    #[serde(default)]
    intercept: RawIntercept,
    #[serde(default)]
    jump: RawJump,
    #[serde(default)]
    recording: RawRecording,
}

#[derive(Debug, Deserialize)]
struct RawCa {
    #[serde(default)]
    trusted_ca_keys: Vec<String>,
    #[serde(default)]
    signing_key: Option<String>,
    #[serde(default = "default_cert_lifetime")]
    cert_lifetime: String,
}

impl Default for RawCa {
    fn default() -> Self {
        RawCa {
            trusted_ca_keys: Vec::new(),
            signing_key: None,
            // Must match `default_cert_lifetime`: a derived `Default` would give
            // an empty string and then fail duration parsing for an absent
            // `[ca]` section.
            cert_lifetime: default_cert_lifetime(),
        }
    }
}

fn default_cert_lifetime() -> String {
    "300s".to_owned()
}

#[derive(Debug, Deserialize, Default)]
struct RawIntercept {
    #[serde(default)]
    sftp: RawSftpIntercept,
}

#[derive(Debug, Deserialize, Default)]
struct RawSftpIntercept {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    deny_commands: Vec<String>,
    #[serde(default)]
    allowed_path_prefixes: Vec<String>,
    #[serde(default)]
    denied_path_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawJump {
    #[serde(default = "default_jump_enabled")]
    enabled: bool,
    #[serde(default)]
    allowed_targets: Vec<String>,
    #[serde(default = "default_allow_private_networks")]
    allow_private_networks: bool,
}

impl Default for RawJump {
    fn default() -> Self {
        RawJump {
            enabled: default_jump_enabled(),
            allowed_targets: Vec::new(),
            allow_private_networks: default_allow_private_networks(),
        }
    }
}

fn default_jump_enabled() -> bool {
    false
}
fn default_allow_private_networks() -> bool {
    false
}

#[derive(Debug, Deserialize)]
struct RawRecording {
    #[serde(default = "default_recording_dir")]
    dir: String,
    #[serde(default = "default_max_bytes_per_session")]
    max_bytes_per_session: u64,
}

impl Default for RawRecording {
    fn default() -> Self {
        RawRecording {
            dir: default_recording_dir(),
            max_bytes_per_session: default_max_bytes_per_session(),
        }
    }
}

fn default_recording_dir() -> String {
    "/var/lib/ssh-gateway/recordings".to_owned()
}
fn default_max_bytes_per_session() -> u64 {
    64 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
struct RawMetrics {
    #[serde(default = "default_metrics_addr")]
    addr: String,
}

fn default_metrics_addr() -> String {
    "127.0.0.1:9090".to_owned()
}

#[derive(Debug, Deserialize)]
struct RawListen {
    addr: String,
}

#[derive(Debug, Deserialize)]
struct RawHostKeys {
    keys: Vec<RawHostKey>,
}

#[derive(Debug, Deserialize)]
struct RawHostKey {
    path: String,
    #[serde(default = "default_host_key_state")]
    state: String,
}

fn default_host_key_state() -> String {
    "active".to_owned()
}

#[derive(Debug, Deserialize, Default)]
struct RawRelay {
    window_size: Option<String>,
    max_packet: Option<String>,
    outbound_guard: Option<bool>,
    #[serde(default)]
    env_allowlist: Vec<String>,
    #[serde(default)]
    nodelay: Option<bool>,
    #[serde(default)]
    ciphers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawBackend {
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    credential_map: BTreeMap<String, String>,
    host_key_policy: String,
    /// `"key"` (default), `"cert"` or `"agent"`.
    #[serde(default = "default_backend_auth")]
    backend_auth: String,
    /// Global kill-switch for `backend_auth = "agent"` (default off; a veto —
    /// see [`crate::backend::ensure_agent_backend_auth`]).
    #[serde(default)]
    allow_agent_backend_auth: bool,
}

fn default_backend_auth() -> String {
    "key".to_owned()
}

#[derive(Debug, Deserialize)]
struct RawPool {
    #[serde(default = "default_pool_enabled")]
    enabled: bool,
    #[serde(default = "default_channels_per_conn")]
    channels_per_conn: usize,
    #[serde(default = "default_keepalive_interval")]
    keepalive_interval: String,
    #[serde(default = "default_keepalive_timeout")]
    keepalive_timeout: String,
    #[serde(default = "default_keepalive_max_miss")]
    keepalive_max_miss: u32,
    #[serde(default = "default_circuit_failure_threshold")]
    circuit_failure_threshold: u32,
    #[serde(default = "default_circuit_reset_timeout")]
    circuit_reset_timeout: String,
}

fn default_pool_enabled() -> bool {
    false
}
fn default_channels_per_conn() -> usize {
    8
}
fn default_keepalive_interval() -> String {
    "15s".to_owned()
}
fn default_keepalive_timeout() -> String {
    "5s".to_owned()
}
fn default_keepalive_max_miss() -> u32 {
    2
}
fn default_circuit_failure_threshold() -> u32 {
    5
}
fn default_circuit_reset_timeout() -> String {
    "30s".to_owned()
}

#[derive(Debug, Deserialize)]
struct RawControlPlane {
    url: String,
    #[serde(default = "default_cache_ttl")]
    cache_ttl: String,
    #[serde(default = "default_cp_timeout")]
    timeout: String,
    #[serde(default)]
    fail_open: bool,
    #[serde(default = "default_cache_ttl_jitter")]
    cache_ttl_jitter: String,
}

fn default_cache_ttl() -> String {
    "30s".to_owned()
}
fn default_cp_timeout() -> String {
    "2s".to_owned()
}
fn default_cache_ttl_jitter() -> String {
    "3s".to_owned()
}

#[derive(Debug, Deserialize)]
struct RawLimits {
    #[serde(default = "default_max_sessions")]
    max_sessions: usize,
    #[serde(default = "default_max_sessions_per_ip")]
    max_sessions_per_ip: usize,
    #[serde(default = "default_auth_timeout")]
    auth_timeout: String,
    #[serde(default = "default_auth_rejection_pad")]
    auth_rejection_pad: String,
    #[serde(default = "default_inactivity_timeout")]
    inactivity_timeout: String,
    #[serde(default = "default_max_auth_attempts")]
    max_auth_attempts: usize,
}

fn default_max_sessions() -> usize {
    10_000
}
fn default_max_sessions_per_ip() -> usize {
    20
}
fn default_auth_timeout() -> String {
    "30s".to_owned()
}
fn default_auth_rejection_pad() -> String {
    "1s".to_owned()
}
fn default_inactivity_timeout() -> String {
    "600s".to_owned()
}
fn default_max_auth_attempts() -> usize {
    10
}

#[derive(Debug, Deserialize)]
struct RawShutdown {
    #[serde(default = "default_drain_wait")]
    drain_wait: String,
    #[serde(default = "default_disconnect_flush")]
    disconnect_flush: String,
    #[serde(default = "default_hard_deadline")]
    hard_deadline: String,
}

fn default_drain_wait() -> String {
    "60s".to_owned()
}
fn default_disconnect_flush() -> String {
    "3s".to_owned()
}
fn default_hard_deadline() -> String {
    "30s".to_owned()
}

impl Default for RawMetrics {
    fn default() -> Self {
        RawMetrics {
            addr: default_metrics_addr(),
        }
    }
}

// Manual `Default` impls so an entirely-absent `[pool]` / `[limits]` /
// `[shutdown]` section yields the documented legal defaults (a derived
// `Default` would produce empty strings / zeros that then fail validation).
impl Default for RawPool {
    fn default() -> Self {
        RawPool {
            enabled: default_pool_enabled(),
            channels_per_conn: default_channels_per_conn(),
            keepalive_interval: default_keepalive_interval(),
            keepalive_timeout: default_keepalive_timeout(),
            keepalive_max_miss: default_keepalive_max_miss(),
            circuit_failure_threshold: default_circuit_failure_threshold(),
            circuit_reset_timeout: default_circuit_reset_timeout(),
        }
    }
}

impl Default for RawLimits {
    fn default() -> Self {
        RawLimits {
            max_sessions: default_max_sessions(),
            max_sessions_per_ip: default_max_sessions_per_ip(),
            auth_timeout: default_auth_timeout(),
            auth_rejection_pad: default_auth_rejection_pad(),
            inactivity_timeout: default_inactivity_timeout(),
            max_auth_attempts: default_max_auth_attempts(),
        }
    }
}

impl Default for RawShutdown {
    fn default() -> Self {
        RawShutdown {
            drain_wait: default_drain_wait(),
            disconnect_flush: default_disconnect_flush(),
            hard_deadline: default_hard_deadline(),
        }
    }
}

/// Parse a human byte size like `32KB`, `1MB`, `256KB`, `1GB`, or a bare byte
/// count `1048576`. Suffixes are binary multiples (KB = 1024).
pub fn parse_bytes(field: &str, value: &str) -> std::result::Result<u32, ConfigError> {
    let invalid = || ConfigError::Invalid {
        field: field.to_owned(),
        reason: format!("cannot parse byte size {value:?} (expected e.g. \"32KB\", \"1MB\")"),
    };

    let trimmed = value.trim();
    let upper = trimmed.to_ascii_uppercase();
    let (num_part, multiplier): (&str, u64) = if let Some(rest) = upper.strip_suffix("KB") {
        (rest, 1024)
    } else if let Some(rest) = upper.strip_suffix("MB") {
        (rest, 1024 * 1024)
    } else if let Some(rest) = upper.strip_suffix("GB") {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = upper.strip_suffix('B') {
        (rest, 1)
    } else {
        (trimmed, 1)
    };

    let num_part = num_part.trim();
    let base: u64 = num_part.parse().map_err(|_| invalid())?;
    let total = base.checked_mul(multiplier).ok_or_else(invalid)?;
    u32::try_from(total).map_err(|_| ConfigError::Invalid {
        field: field.to_owned(),
        reason: format!("byte size {value:?} exceeds u32 range"),
    })
}

/// Parse a human duration like `30s`, `1500ms`, `5m`, `2h`, or a bare number of
/// seconds. Units: `ms`, `s`, `m`, `h` (case-insensitive).
pub fn parse_duration(field: &str, value: &str) -> std::result::Result<Duration, ConfigError> {
    let invalid = || ConfigError::Invalid {
        field: field.to_owned(),
        reason: format!(
            "cannot parse duration {value:?} (expected e.g. \"30s\", \"1500ms\", \"5m\")"
        ),
    };

    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (num_part, unit_multiplier_ms): (String, u64) = if let Some(rest) = lower.strip_suffix("ms")
    {
        (rest.to_owned(), 1)
    } else if let Some(rest) = lower.strip_suffix('s') {
        (rest.to_owned(), 1000)
    } else if let Some(rest) = lower.strip_suffix('m') {
        (rest.to_owned(), 60_000)
    } else if let Some(rest) = lower.strip_suffix('h') {
        (rest.to_owned(), 3_600_000)
    } else {
        // Bare number = seconds.
        (lower.clone(), 1000)
    };

    let num_part = num_part.trim();
    let base: u64 = num_part.parse().map_err(|_| invalid())?;
    let total_ms = base.checked_mul(unit_multiplier_ms).ok_or_else(invalid)?;
    Ok(Duration::from_millis(total_ms))
}

impl GatewayConfig {
    /// Parse and validate a configuration from its TOML text.
    pub fn parse(toml_text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(toml_text).map_err(|source| ConfigError::Parse {
            path: std::path::PathBuf::from("<inline>"),
            source,
        })?;
        Self::from_raw(raw)
    }

    /// Load and validate a configuration file from disk.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
            path: path.to_owned(),
            source,
        })?;
        let raw: RawConfig = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self> {
        Self::validate(raw).map_err(Error::from)
    }

    /// The validation core, expressed purely in terms of [`ConfigError`] so every
    /// rule can be exercised in isolation and reports the offending field.
    fn validate(raw: RawConfig) -> std::result::Result<Self, ConfigError> {
        let listen_addr =
            SocketAddr::from_str(raw.listen.addr.trim()).map_err(|_| ConfigError::Invalid {
                field: "listen.addr".into(),
                reason: format!("not a valid socket address: {:?}", raw.listen.addr),
            })?;

        if raw.host_keys.keys.is_empty() {
            return Err(ConfigError::Invalid {
                field: "host_keys.keys".into(),
                reason: "at least one host key must be configured".into(),
            });
        }
        let mut host_keys = Vec::with_capacity(raw.host_keys.keys.len());
        for (idx, entry) in raw.host_keys.keys.into_iter().enumerate() {
            let field = format!("host_keys.keys[{idx}]");
            if entry.path.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field,
                    reason: "path must not be empty".into(),
                });
            }
            let state = match entry.state.as_str() {
                "active" => HostKeyState::Active,
                "passive" => HostKeyState::Passive,
                other => {
                    return Err(ConfigError::Invalid {
                        field: format!("{field}.state"),
                        reason: format!(
                            "unknown state {other:?} (expected \"active\" or \"passive\")"
                        ),
                    });
                }
            };
            host_keys.push(HostKeyEntry {
                path: PathBuf::from(entry.path),
                state,
            });
        }

        let window_size = parse_bytes(
            "relay.window_size",
            raw.relay.window_size.as_deref().unwrap_or("1MB"),
        )?;
        if !(256 * 1024..=8 * 1024 * 1024).contains(&window_size) {
            return Err(ConfigError::Invalid {
                field: "relay.window_size".into(),
                reason: "must be within [256KB, 8MB]".into(),
            });
        }
        let max_packet = parse_bytes(
            "relay.max_packet",
            raw.relay.max_packet.as_deref().unwrap_or("32KB"),
        )?;
        if max_packet == 0 || max_packet > 65535 {
            return Err(ConfigError::Invalid {
                field: "relay.max_packet".into(),
                reason: "must be within (0, 65535]".into(),
            });
        }
        let relay = RelayConfig {
            window_size,
            max_packet,
            outbound_guard: raw.relay.outbound_guard.unwrap_or(true),
            env_allowlist: raw.relay.env_allowlist,
            nodelay: raw.relay.nodelay.unwrap_or(false),
            ciphers: raw.relay.ciphers,
        };

        let host_key_policy = HostKeyPolicy::parse(raw.backend.host_key_policy.trim())?;
        // Credential rules per selected backend auth mode (M4-T3):
        // * `key`  — a private key is mandatory (the backend's authorized_keys
        //   carries its public key), so the existing error stands.
        // * `cert` — the inner key is optional: the backend trusts the issuing CA
        //   (`TrustedUserCAKeys`), so the gateway may present an ephemeral
        //   keypair. A configured key is still honoured as a stable identity.
        let backend_auth = crate::backend::BackendAuthMethod::parse(
            "backend.backend_auth",
            &raw.backend.backend_auth,
        )?;
        let has_key_material =
            raw.backend.private_key.is_some() || !raw.backend.credential_map.is_empty();
        if matches!(backend_auth, crate::backend::BackendAuthMethod::Key) && !has_key_material {
            return Err(ConfigError::Invalid {
                field: "backend".into(),
                reason:
                    "either private_key or credential_map must be provided (backend_auth = \"key\")"
                        .into(),
            });
        }
        if matches!(backend_auth, crate::backend::BackendAuthMethod::Cert)
            && raw.ca.signing_key.is_none()
        {
            return Err(ConfigError::Invalid {
                field: "backend.backend_auth".into(),
                reason: "backend_auth = \"cert\" requires [ca] signing_key (the gateway must be able to issue)".into(),
            });
        }
        // Agent-mode rules (plan-agent-passthrough C1). No key and no CA is
        // required — the credential is the end user's, reached through the
        // forwarded agent — but two hard gates apply:
        //  * the kill-switch is a veto: `backend_auth = "agent"` while it is off
        //    is a boot error, never a silent downgrade to `key`/`cert`;
        //  * pooling and agent mode are mutually exclusive (propose §3.8): a
        //    shared pooled connection cannot carry a per-session agent identity.
        crate::backend::ensure_agent_backend_auth(
            backend_auth,
            raw.backend.allow_agent_backend_auth,
        )?;
        if matches!(backend_auth, crate::backend::BackendAuthMethod::Agent) && raw.pool.enabled {
            return Err(ConfigError::Invalid {
                field: "pool.enabled".into(),
                reason: "must be false while [backend] backend_auth = \"agent\" \
                         (agent forwarding needs a per-session connection; propose §3.8)"
                    .into(),
            });
        }
        for (user, path) in &raw.backend.credential_map {
            if path.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field: format!("backend.credential_map.{user}"),
                    reason: "key path must not be empty".into(),
                });
            }
        }
        let backend = BackendConfig {
            private_key: raw.backend.private_key.map(PathBuf::from),
            credential_map: raw
                .backend
                .credential_map
                .into_iter()
                .map(|(u, p)| (u, PathBuf::from(p)))
                .collect(),
            host_key_policy,
            backend_auth,
            allow_agent_backend_auth: raw.backend.allow_agent_backend_auth,
        };

        if raw.pool.channels_per_conn == 0 || raw.pool.channels_per_conn > 8 {
            return Err(ConfigError::Invalid {
                field: "pool.channels_per_conn".into(),
                reason: "must be within [1, 8] (sshd MaxSessions constraint)".into(),
            });
        }
        if raw.pool.circuit_failure_threshold == 0 {
            return Err(ConfigError::Invalid {
                field: "pool.circuit_failure_threshold".into(),
                reason: "must be >= 1".into(),
            });
        }
        let pool = PoolConfig {
            enabled: raw.pool.enabled,
            channels_per_conn: raw.pool.channels_per_conn,
            keepalive_interval: parse_duration(
                "pool.keepalive_interval",
                &raw.pool.keepalive_interval,
            )?,
            keepalive_timeout: parse_duration(
                "pool.keepalive_timeout",
                &raw.pool.keepalive_timeout,
            )?,
            keepalive_max_miss: raw.pool.keepalive_max_miss,
            circuit_failure_threshold: raw.pool.circuit_failure_threshold,
            circuit_reset_timeout: parse_duration(
                "pool.circuit_reset_timeout",
                &raw.pool.circuit_reset_timeout,
            )?,
            idle_ping_threshold: Duration::from_secs(30),
        };

        if raw.control_plane.url.trim().is_empty() {
            return Err(ConfigError::Invalid {
                field: "control_plane.url".into(),
                reason: "must not be empty".into(),
            });
        }
        let control_plane = ControlPlaneConfig {
            url: raw.control_plane.url.trim().to_owned(),
            cache_ttl: parse_duration("control_plane.cache_ttl", &raw.control_plane.cache_ttl)?,
            timeout: parse_duration("control_plane.timeout", &raw.control_plane.timeout)?,
            fail_open: raw.control_plane.fail_open,
            cache_ttl_jitter: parse_duration(
                "control_plane.cache_ttl_jitter",
                &raw.control_plane.cache_ttl_jitter,
            )?,
        };

        let limits = LimitsConfig {
            max_sessions: raw.limits.max_sessions,
            max_sessions_per_ip: raw.limits.max_sessions_per_ip,
            auth_timeout: parse_duration("limits.auth_timeout", &raw.limits.auth_timeout)?,
            auth_rejection_pad: parse_duration(
                "limits.auth_rejection_pad",
                &raw.limits.auth_rejection_pad,
            )?,
            inactivity_timeout: parse_duration(
                "limits.inactivity_timeout",
                &raw.limits.inactivity_timeout,
            )?,
            max_auth_attempts: raw.limits.max_auth_attempts,
        };
        if limits.max_sessions == 0 || limits.max_sessions_per_ip == 0 {
            return Err(ConfigError::Invalid {
                field: "limits".into(),
                reason: "max_sessions and max_sessions_per_ip must be >= 1".into(),
            });
        }

        let shutdown = ShutdownConfig {
            drain_wait: parse_duration("shutdown.drain_wait", &raw.shutdown.drain_wait)?,
            disconnect_flush: parse_duration(
                "shutdown.disconnect_flush",
                &raw.shutdown.disconnect_flush,
            )?,
            hard_deadline: parse_duration("shutdown.hard_deadline", &raw.shutdown.hard_deadline)?,
        };

        let metrics_addr =
            SocketAddr::from_str(raw.metrics.addr.trim()).map_err(|_| ConfigError::Invalid {
                field: "metrics.addr".into(),
                reason: format!("not a valid socket address: {:?}", raw.metrics.addr),
            })?;

        // --- M3: certificate authority (B1) ---------------------------------
        // An absent `[ca]` section (hence no CAs and no signing key) is a valid,
        // fully-opt-in "CA disabled" configuration: nothing must require it.
        // A signing key alone, however, would mint certificates the gateway
        // trusts for nobody, so refuse that half-configured state.
        if raw.ca.signing_key.is_some() && raw.ca.trusted_ca_keys.is_empty() {
            return Err(ConfigError::Invalid {
                field: "ca".into(),
                reason: "a signing_key requires at least one trusted_ca_keys entry".into(),
            });
        }
        let ca = CaConfig {
            trusted_ca_keys: raw
                .ca
                .trusted_ca_keys
                .iter()
                .map(|p| PathBuf::from(p.trim()))
                .collect(),
            signing_key: raw.ca.signing_key.as_ref().map(|p| PathBuf::from(p.trim())),
            cert_lifetime: parse_duration("ca.cert_lifetime", &raw.ca.cert_lifetime)?,
        };

        // --- M3: SFTP interception (B3) -------------------------------------
        let sftp_rules = crate::sftp::validate_rules(
            &raw.intercept.sftp.deny_commands,
            &raw.intercept.sftp.allowed_path_prefixes,
            &raw.intercept.sftp.denied_path_prefixes,
        )?;
        let intercept = InterceptConfig {
            sftp: SftpInterceptConfig {
                enabled: raw.intercept.sftp.enabled,
                deny_commands: sftp_rules.0,
                allowed_path_prefixes: sftp_rules.1,
                denied_path_prefixes: sftp_rules.2,
            },
        };

        // --- M3: jump mode (B4) ---------------------------------------------
        let jump = JumpConfig {
            enabled: raw.jump.enabled,
            allowed_targets: raw.jump.allowed_targets.clone(),
            allow_private_networks: raw.jump.allow_private_networks,
        };

        // --- M3: session recording (B2 / B5) --------------------------------
        let recording_dir = PathBuf::from(raw.recording.dir.trim());
        if recording_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid {
                field: "recording.dir".into(),
                reason: "must not be empty".into(),
            });
        }
        let recording = RecordingConfig {
            dir: recording_dir,
            // 0 means "unbounded"; anything else must be a positive budget.
            max_bytes_per_session: raw.recording.max_bytes_per_session,
        };

        Ok(GatewayConfig {
            listen_addr,
            host_keys,
            relay,
            backend,
            pool,
            control_plane,
            limits,
            ca,
            intercept,
            jump,
            recording,
            shutdown,
            metrics: MetricsConfig { addr: metrics_addr },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml() -> String {
        r#"
            [listen]
            addr = "127.0.0.1:2222"

            [host_keys]
            keys = [
                { path = "/etc/ssh-gw/host_ed25519", state = "active" },
                { path = "/etc/ssh-gw/host_rsa", state = "active" },
            ]

            [relay]
            window_size = "1MB"
            max_packet = "32KB"
            outbound_guard = true

            [backend]
            private_key = "/etc/ssh-gw/backend_root_ed25519"
            host_key_policy = "pinned"

            [control_plane]
            url = "https://cp.internal"

            [pool]
            enabled = false
            channels_per_conn = 8

            [limits]
            max_sessions = 10000
            max_sessions_per_ip = 20

            [shutdown]
            drain_wait = "60s"
        "#
        .to_owned()
    }

    #[test]
    fn parses_full_config_with_defaults() {
        let cfg = GatewayConfig::parse(&minimal_toml()).expect("valid config");
        assert_eq!(cfg.listen_addr, "127.0.0.1:2222".parse().unwrap());
        assert_eq!(cfg.relay.window_size, 1024 * 1024);
        assert_eq!(cfg.relay.max_packet, 32 * 1024);
        assert!(cfg.relay.outbound_guard);
        assert_eq!(cfg.host_keys.len(), 2);
        assert_eq!(cfg.host_keys[0].state, HostKeyState::Active);
        assert_eq!(cfg.backend.host_key_policy, HostKeyPolicy::Pinned);
        assert!(!cfg.pool.enabled);
        assert_eq!(cfg.pool.channels_per_conn, 8);
        assert_eq!(cfg.control_plane.cache_ttl, Duration::from_secs(30));
        assert_eq!(cfg.limits.max_sessions, 10_000);
        assert_eq!(cfg.shutdown.drain_wait, Duration::from_secs(60));
        // Unspecified fields take documented defaults:
        assert_eq!(cfg.shutdown.disconnect_flush, Duration::from_secs(3));
        assert_eq!(cfg.shutdown.hard_deadline, Duration::from_secs(30));
        assert_eq!(cfg.limits.auth_timeout, Duration::from_secs(30));
        assert_eq!(cfg.pool.keepalive_interval, Duration::from_secs(15));
        // P1-2 / P1-1 defaults: the auth rejection pad is deliberately NOT the
        // auth_timeout, and the dial breaker has its own knobs.
        assert_eq!(cfg.limits.auth_rejection_pad, Duration::from_secs(1));
        assert_eq!(cfg.limits.inactivity_timeout, Duration::from_secs(600));
        assert_eq!(cfg.limits.max_auth_attempts, 10);
        assert_eq!(cfg.pool.circuit_failure_threshold, 5);
        assert_eq!(cfg.pool.circuit_reset_timeout, Duration::from_secs(30));
    }

    #[test]
    fn max_auth_attempts_defaults_match_russh_builtin() {
        // The pre-config default was russh's own built-in (10); the config must
        // resolve to the same value when omitted.
        assert_eq!(default_max_auth_attempts(), 10);
        let cfg = GatewayConfig::parse(&minimal_toml()).expect("valid config");
        assert_eq!(cfg.limits.max_auth_attempts, 10);
    }

    #[test]
    fn max_auth_attempts_is_overridable_including_zero() {
        // `0` means "no attempt cap", which is russh's own encoding, so it must
        // be accepted rather than rejected by validation.
        let toml = minimal_toml().replace(
            "max_sessions_per_ip = 20",
            "max_sessions_per_ip = 20\n            max_auth_attempts = 0",
        );
        let cfg = GatewayConfig::parse(&toml).expect("valid config");
        assert_eq!(cfg.limits.max_auth_attempts, 0);

        let toml = minimal_toml().replace(
            "max_sessions_per_ip = 20",
            "max_sessions_per_ip = 20\n            max_auth_attempts = 3",
        );
        let cfg = GatewayConfig::parse(&toml).expect("valid config");
        assert_eq!(cfg.limits.max_auth_attempts, 3);
    }

    #[test]
    fn auth_rejection_pad_and_inactivity_timeout_are_overridable() {
        let toml = minimal_toml().replace(
            "max_sessions_per_ip = 20",
            "max_sessions_per_ip = 20\n            auth_timeout = \"0s\"\n            auth_rejection_pad = \"250ms\"\n            inactivity_timeout = \"120s\"",
        );
        let cfg = GatewayConfig::parse(&toml).expect("valid config");
        assert_eq!(cfg.limits.auth_timeout, Duration::ZERO);
        assert_eq!(cfg.limits.auth_rejection_pad, Duration::from_millis(250));
        assert_eq!(cfg.limits.inactivity_timeout, Duration::from_secs(120));
    }

    #[test]
    fn backend_auth_defaults_to_key_which_changes_nothing() {
        let cfg = GatewayConfig::parse(&minimal_toml()).expect("valid config");
        assert_eq!(
            cfg.backend.backend_auth,
            crate::backend::BackendAuthMethod::Key,
            "the default credential must be the existing private-key path"
        );
    }

    #[test]
    fn backend_auth_cert_requires_a_signing_key() {
        // A gateway told to present certificates it cannot mint must refuse to
        // boot: silently falling back to keys would look like a working cert
        // deployment while authenticating with something else.
        let bad = minimal_toml().replace(
            "host_key_policy = \"pinned\"",
            "host_key_policy = \"pinned\"\n            backend_auth = \"cert\"",
        );
        let err = GatewayConfig::parse(&bad).unwrap_err();
        assert!(
            err.to_string().contains("signing_key"),
            "expected a signing_key requirement, got: {err}"
        );
    }

    #[test]
    fn backend_auth_cert_allows_omitting_the_private_key() {
        // With a CA able to issue, the backend trusts the CA rather than a
        // specific gateway key, so an ephemeral inner keypair is acceptable.
        let assets = std::env::temp_dir().join(format!(
            "sshgw-cfg-ca-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&assets).unwrap();
        let host = assets.join("host");
        let ca_priv = assets.join("ca");
        let ca_pub = assets.join("ca.pub");
        {
            for p in [&host, &ca_priv] {
                let mut rng = rand::rng();
                let body =
                    russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
                        .unwrap()
                        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                        .unwrap();
                let f = std::fs::File::create(p).unwrap();
                let _ = f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
                std::fs::write(p, body).unwrap();
            }
        }
        std::fs::write(
            &ca_pub,
            russh::keys::load_secret_key(&ca_priv, None)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
        )
        .unwrap();

        let toml = format!(
            r#"
            [listen]
            addr = "127.0.0.1:0"
            [host_keys]
            keys = [ {{ path = "{}", state = "active" }} ]
            [backend]
            host_key_policy = "accept-new"
            backend_auth = "cert"
            [control_plane]
            url = "http://127.0.0.1:1"
            [ca]
            trusted_ca_keys = ["{}"]
            signing_key = "{}"
        "#,
            host.to_string_lossy(),
            ca_pub.to_string_lossy(),
            ca_priv.to_string_lossy(),
        );
        drop(std::fs::remove_dir_all(&assets));

        let cfg = GatewayConfig::parse(&toml).expect("cert mode without a private key is valid");
        assert_eq!(
            cfg.backend.backend_auth,
            crate::backend::BackendAuthMethod::Cert
        );
        assert!(cfg.backend.private_key.is_none());
        assert!(cfg.backend.credential_map.is_empty());
        assert_eq!(cfg.ca.trusted_ca_keys.len(), 1);
        assert!(cfg.ca.signing_key.is_some());
    }

    #[test]
    fn backend_auth_rejects_an_unknown_value() {
        let bad = minimal_toml().replace(
            "host_key_policy = \"pinned\"",
            "host_key_policy = \"pinned\"\n            backend_auth = \"token\"",
        );
        let err = GatewayConfig::parse(&bad).unwrap_err();
        assert!(err.to_string().contains("backend_auth"), "{err}");
    }

    // ---- plan-agent-passthrough C1: agent mode + kill-switch ----

    /// `minimal_toml` with the backend private key stripped and `[backend]`
    /// overrides appended — agent mode must not require key material.
    fn agent_toml(extra: &str) -> String {
        minimal_toml()
            .replace("private_key = \"/etc/ssh-gw/backend_root_ed25519\"\n", "")
            .replace("[backend]", &format!("[backend]\n{extra}"))
    }

    #[test]
    fn allow_agent_backend_auth_defaults_to_false() {
        let cfg = GatewayConfig::parse(&minimal_toml()).expect("valid config");
        assert!(
            !cfg.backend.allow_agent_backend_auth,
            "the kill-switch must default OFF so an upgrade changes nothing"
        );
    }

    #[test]
    fn agent_backend_auth_requires_the_kill_switch() {
        // backend_auth="agent" with the switch off: boot error, never a silent
        // downgrade to `key`/`cert`.
        let bad = agent_toml("backend_auth = \"agent\"\n");
        let err = GatewayConfig::parse(&bad).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("allow_agent_backend_auth"), "{msg}");
        assert!(msg.contains("downgrad"), "{msg}");
    }

    #[test]
    fn agent_mode_needs_neither_a_private_key_nor_a_ca() {
        // The credential is the end user's, reached through the forwarded agent.
        let good = agent_toml("backend_auth = \"agent\"\nallow_agent_backend_auth = true\n");
        let cfg = GatewayConfig::parse(&good).expect("agent mode without key/CA is valid");
        assert_eq!(
            cfg.backend.backend_auth,
            crate::backend::BackendAuthMethod::Agent
        );
        assert!(cfg.backend.allow_agent_backend_auth);
        assert!(cfg.backend.private_key.is_none());
        assert!(cfg.backend.credential_map.is_empty());
        assert!(
            cfg.ca.signing_key.is_none(),
            "agent mode must not need a CA"
        );
    }

    #[test]
    fn agent_backend_auth_is_incompatible_with_pooling() {
        // propose §3.8: a pooled connection cannot carry a per-session agent
        // identity — config-time error, not a runtime surprise.
        let bad = agent_toml("backend_auth = \"agent\"\nallow_agent_backend_auth = true\n")
            .replace("enabled = false", "enabled = true");
        assert!(bad.contains("enabled = true"), "precondition of the test");
        let err = GatewayConfig::parse(&bad).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pool.enabled"), "{msg}");
        assert!(msg.contains("agent"), "{msg}");
    }

    #[test]
    fn the_agent_kill_switch_alone_changes_nothing_for_key_auth() {
        // It is a veto, not an enabler: turning it on with the default `key`
        // credential (and its required key material) is a no-op.
        let toml =
            minimal_toml().replace("[backend]", "[backend]\nallow_agent_backend_auth = true");
        let cfg = GatewayConfig::parse(&toml).expect("switch on + key auth is valid");
        assert_eq!(
            cfg.backend.backend_auth,
            crate::backend::BackendAuthMethod::Key
        );
        assert!(cfg.backend.allow_agent_backend_auth);
        assert!(cfg.backend.private_key.is_some());
    }

    #[test]
    fn zero_circuit_failure_threshold_is_rejected() {
        let bad = minimal_toml().replace(
            "channels_per_conn = 8",
            "channels_per_conn = 8\n            circuit_failure_threshold = 0",
        );
        assert!(GatewayConfig::parse(&bad).is_err());
    }

    #[test]
    fn byte_size_parsing_handles_suffixes() {
        assert_eq!(parse_bytes("f", "32KB").unwrap(), 32 * 1024);
        assert_eq!(parse_bytes("f", "1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_bytes("f", "256KB").unwrap(), 256 * 1024);
        assert_eq!(parse_bytes("f", "8MB").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_bytes("f", "1024B").unwrap(), 1024);
        assert_eq!(parse_bytes("f", "2048").unwrap(), 2048);
        assert!(parse_bytes("f", "garbage").is_err());
        assert!(parse_bytes("f", "1TB").is_err()); // unknown suffix
    }

    #[test]
    fn duration_parsing_handles_units() {
        assert_eq!(parse_duration("f", "15s").unwrap(), Duration::from_secs(15));
        assert_eq!(
            parse_duration("f", "1500ms").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(parse_duration("f", "5m").unwrap(), Duration::from_secs(300));
        assert_eq!(
            parse_duration("f", "2h").unwrap(),
            Duration::from_secs(7200)
        );
        assert_eq!(parse_duration("f", "30").unwrap(), Duration::from_secs(30));
        assert!(parse_duration("f", "nope").is_err());
    }

    #[test]
    fn missing_required_section_is_a_clear_error() {
        let bad = "[listen]\naddr=\"127.0.0.1:2222\"\n";
        let err = GatewayConfig::parse(bad).unwrap_err();
        // toml fails to deserialize before our validation; still an error.
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn invalid_socket_addr_reports_field() {
        let bad = r#"
            [listen]
            addr = "not-an-addr"
            [host_keys]
            keys = [{ path = "/x" }]
            [backend]
            private_key = "/k"
            host_key_policy = "pinned"
            [control_plane]
            url = "https://cp.internal"
        "#;
        let err = GatewayConfig::parse(bad).unwrap_err();
        match err {
            Error::Config(ConfigError::Invalid { field, .. }) => assert_eq!(field, "listen.addr"),
            _ => panic!("expected invalid listen.addr, got {err:?}"),
        }
    }

    #[test]
    fn empty_host_keys_rejected() {
        let bad = r#"
            [listen]
            addr = "127.0.0.1:2222"
            [host_keys]
            keys = []
            [backend]
            private_key = "/k"
            host_key_policy = "pinned"
            [control_plane]
            url = "https://cp.internal"
        "#;
        assert!(GatewayConfig::parse(bad).is_err());
    }

    #[test]
    fn window_size_out_of_range_rejected() {
        let bad = minimal_toml().replace("window_size = \"1MB\"", "window_size = \"128KB\"");
        let err = GatewayConfig::parse(&bad).unwrap_err();
        match err {
            Error::Config(ConfigError::Invalid { field, .. }) => {
                assert_eq!(field, "relay.window_size")
            }
            _ => panic!("expected relay.window_size error, got {err:?}"),
        }
    }

    #[test]
    fn bad_host_key_policy_rejected() {
        let bad = minimal_toml().replace(
            "host_key_policy = \"pinned\"",
            "host_key_policy = \"trust\"",
        );
        assert!(GatewayConfig::parse(&bad).is_err());
    }

    #[test]
    fn channels_per_conn_over_eight_rejected() {
        let bad = minimal_toml().replace("channels_per_conn = 8", "channels_per_conn = 16");
        assert!(GatewayConfig::parse(&bad).is_err());
    }

    #[test]
    fn credential_map_resolves_key_for_user() {
        let toml = r#"
            [listen]
            addr = "127.0.0.1:2222"
            [host_keys]
            keys = [{ path = "/h" }]
            [backend]
            credential_map = { root = "/keys/root_ed", deploy = "/keys/deploy_ed" }
            host_key_policy = "accept-new"
            [control_plane]
            url = "https://cp"
        "#;
        let cfg = GatewayConfig::parse(toml).expect("valid");
        assert_eq!(
            cfg.backend.key_for_user("root"),
            Some(&PathBuf::from("/keys/root_ed"))
        );
        assert_eq!(
            cfg.backend.key_for_user("deploy"),
            Some(&PathBuf::from("/keys/deploy_ed"))
        );
        assert_eq!(cfg.backend.key_for_user("other"), None);
    }
}
